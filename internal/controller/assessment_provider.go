package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/external"
)

// Registered external assessment providers (add-external-assessment-providers
// 2.2). With ExternalProviders configured, the controller probes every
// AssessmentProvider's endpoint with Describe over mutual TLS, records its
// availability and compatibility as status Conditions and identity, and
// selects registrations for new work through ProviderCatalog. Without it
// (the default) nothing here is set up: registrations are neither watched
// nor contacted, and only built-in providers are selectable, exactly as
// before.

const (
	// DefaultProviderProbeInterval is how often each registration is
	// re-probed while nothing changes. A rotated trust ConfigMap is used
	// from the next probe.
	DefaultProviderProbeInterval = time.Minute
	// DefaultProviderProbeTimeout bounds one probe, connection and
	// handshake included.
	DefaultProviderProbeTimeout = 10 * time.Second
	// providerProbeWorkers bounds concurrent probes, so a slow endpoint
	// holds one worker for at most the probe timeout and never delays the
	// others.
	providerProbeWorkers = 4
)

// ExternalProviders configures registered external assessment providers.
// The zero value is disabled.
type ExternalProviders struct {
	// ClientCertDir holds tls.crt and tls.key, the controller's client
	// certificate and key for provider endpoints, as a mounted
	// kubernetes.io/tls Secret (--external-provider-client-cert-dir). They
	// are read at each connection, so a rotation is used without a
	// restart. Empty disables external providers.
	ClientCertDir string
	// ProbeInterval and ProbeTimeout default to DefaultProviderProbeInterval
	// and DefaultProviderProbeTimeout. MaxStatusAge, the age of the last
	// compatible observation new work may rely on, defaults to
	// external.DefaultMaxStatusAge and must exceed ProbeInterval.
	ProbeInterval, ProbeTimeout, MaxStatusAge time.Duration
	// address overrides the address dialed for an endpoint (tests).
	address func(external.Endpoint) string
}

// Enabled reports whether external providers are configured.
func (e ExternalProviders) Enabled() bool { return e.ClientCertDir != "" }

func (e ExternalProviders) withDefaults() ExternalProviders {
	if e.ProbeInterval == 0 {
		e.ProbeInterval = DefaultProviderProbeInterval
	}
	if e.ProbeTimeout == 0 {
		e.ProbeTimeout = DefaultProviderProbeTimeout
	}
	if e.MaxStatusAge == 0 {
		e.MaxStatusAge = external.DefaultMaxStatusAge
	}
	return e
}

// Validate checks an enabled configuration: positive durations, a status
// age that outlasts a probe interval, and client credentials that pass the
// kit's checks now.
func (e ExternalProviders) Validate() error {
	if !e.Enabled() {
		return nil
	}
	e = e.withDefaults()
	switch {
	case e.ProbeInterval < 0 || e.ProbeTimeout < 0 || e.MaxStatusAge < 0:
		return errors.New("external provider probe durations must be positive")
	case e.ProbeTimeout >= e.ProbeInterval:
		return fmt.Errorf("external provider probe timeout %s must be shorter than the probe interval %s", e.ProbeTimeout, e.ProbeInterval)
	case e.MaxStatusAge <= e.ProbeInterval+e.ProbeTimeout:
		return fmt.Errorf("external provider status age %s must exceed the probe interval and timeout", e.MaxStatusAge)
	}
	return external.CredentialsDir(e.ClientCertDir).Check()
}

// ProviderCatalog is the host's provider selection: the built-in registry
// and, when external providers are enabled, the AssessmentProviders read
// through Reader. New work resolves its provider contract with Resolve
// and records the frozen identity; existing work checks its frozen
// identity with Continue.
type ProviderCatalog struct {
	Reader   client.Reader
	BuiltIn  *provider.Registry
	External bool
	// MaxStatusAge bounds the age of the observation a selection relies on.
	MaxStatusAge time.Duration
	Now          func() time.Time
}

// Catalog lists the registrations, when enabled, and builds the catalog.
func (p *ProviderCatalog) Catalog(ctx context.Context) (*external.Catalog, error) {
	o := external.CatalogOptions{BuiltIn: p.BuiltIn, External: p.External, MaxStatusAge: p.MaxStatusAge, Now: time.Now()}
	if p.Now != nil {
		o.Now = p.Now()
	}
	if p.External {
		list := &v1alpha1.AssessmentProviderList{}
		if err := p.Reader.List(ctx, list); err != nil {
			return nil, fmt.Errorf("list assessment providers: %w", err)
		}
		o.Registrations = list.Items
	}
	return external.NewCatalog(o)
}

// Resolve selects the provider of contract for new work (Catalog.Resolve).
// The error is a failure to read registrations; a rejected selection is
// the SelectionError.
func (p *ProviderCatalog) Resolve(ctx context.Context, contract string, need ...v1alpha1.AssessmentProviderCapability) (external.Selected, *provider.SelectionError, error) {
	c, err := p.Catalog(ctx)
	if err != nil {
		return external.Selected{}, nil, err
	}
	sel, serr := c.Resolve(contract, need...)
	return sel, serr, nil
}

// Continue checks that work frozen to f may continue with the registration
// as it is now (external.Frozen.Continue). Reading a registration that is
// gone is FrozenRegistrationRemoved; any other read error is returned as
// is, for a retry.
func (p *ProviderCatalog) Continue(ctx context.Context, f external.Frozen, need v1alpha1.AssessmentProviderCapability) error {
	if !p.External {
		return &external.FrozenError{Reason: external.FrozenRegistrationRemoved, Message: "registered external providers are not enabled on this controller"}
	}
	ap := &v1alpha1.AssessmentProvider{}
	switch err := p.Reader.Get(ctx, client.ObjectKey{Name: f.Registration}, ap); {
	case apierrors.IsNotFound(err):
		ap = nil
	case err != nil:
		return err
	}
	return f.Continue(ap, need)
}

// AssessmentProviderReconciler probes each registration's endpoint and
// records its status. It only describes endpoints: no assessment payload,
// collection, scan or evaluation is sent.
type AssessmentProviderReconciler struct {
	Client  client.Client
	Catalog *ProviderCatalog
	Dialer  *external.Dialer
	// Interval and Timeout are the probe interval and timeout.
	Interval, Timeout time.Duration
	Now               func() time.Time
}

func (r *AssessmentProviderReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Reconcile probes one registration and writes its status.
func (r *AssessmentProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ap := &v1alpha1.AssessmentProvider{}
	if err := r.Client.Get(ctx, req.NamespacedName, ap); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if ap.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}
	cat, err := r.Catalog.Catalog(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	var obs external.Observation
	if cat.BuiltIn(ap.Spec.Provider.Name) {
		obs = external.BuiltInObservation(ap, r.now())
	} else {
		pctx, cancel := context.WithTimeout(ctx, r.Timeout)
		obs = r.Dialer.Probe(pctx, ap, r.now)
		cancel()
	}
	status := external.Status(ap, obs, cat.Conflicts(ap))
	if !equality.Semantic.DeepEqual(ap.Status, status) {
		ap.Status = status
		switch err := r.Client.Status().Update(ctx, ap); {
		case apierrors.IsConflict(err):
			// A newer revision or a concurrent write: probe again.
			return ctrl.Result{RequeueAfter: time.Second}, nil
		case err != nil:
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		if obs.Problem != nil {
			log.FromContext(ctx).Info("assessment provider is not usable", "registration", ap.Name, "condition", obs.Problem.Condition, "reason", obs.Problem.Reason)
		}
	}
	return ctrl.Result{RequeueAfter: r.Interval}, nil
}

// trustReader reads serverTrust ConfigMaps in the controller namespace
// through the uncached reader, so a rotation is seen at the next probe.
// Errors name the ConfigMap and key, never its data.
func trustReader(r client.Reader, namespace string) external.TrustReader {
	return func(ctx context.Context, name, key string) ([]byte, error) {
		cm := &corev1.ConfigMap{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: controllerNamespace(namespace), Name: name}, cm); err != nil {
			return nil, fmt.Errorf("serverTrust ConfigMap %s: %w", name, err)
		}
		if key == "" {
			key = external.DefaultTrustKey
		}
		pem, ok := cm.Data[key]
		if !ok || pem == "" {
			return nil, fmt.Errorf("serverTrust ConfigMap %s has no key %s", name, key)
		}
		return []byte(pem), nil
	}
}

// sameProvider requeues every registration naming the same provider as the
// changed one, whose Ready condition may change with it (ambiguity).
func sameProvider(c client.Client) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		changed, ok := o.(*v1alpha1.AssessmentProvider)
		if !ok {
			return nil
		}
		list := &v1alpha1.AssessmentProviderList{}
		if err := c.List(ctx, list); err != nil {
			return nil
		}
		var out []reconcile.Request
		for _, ap := range list.Items {
			if ap.Name != changed.Name && ap.Spec.Provider.Name == changed.Spec.Provider.Name {
				out = append(out, reconcile.Request{NamespacedName: client.ObjectKey{Name: ap.Name}})
			}
		}
		return out
	})
}

// setupExternalProviders starts the registration reconciler with the
// host's ProviderCatalog over the manager's cache. It is called only when
// external providers are enabled, so a default installation neither
// watches registrations nor needs their CRD to be served.
func setupExternalProviders(mgr manager.Manager, e ExternalProviders, builtIn *provider.Registry, namespace string) error {
	e = e.withDefaults()
	catalog := &ProviderCatalog{Reader: mgr.GetClient(), BuiltIn: builtIn, External: true, MaxStatusAge: e.MaxStatusAge}
	r := &AssessmentProviderReconciler{Client: mgr.GetClient(), Catalog: catalog, Interval: e.ProbeInterval, Timeout: e.ProbeTimeout,
		Dialer: &external.Dialer{Credentials: external.CredentialsDir(e.ClientCertDir), Trust: trustReader(mgr.GetAPIReader(), namespace), Address: e.address}}
	return builder.ControllerManagedBy(mgr).Named("assessmentprovider").
		For(&v1alpha1.AssessmentProvider{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&v1alpha1.AssessmentProvider{}, sameProvider(mgr.GetClient()), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		WithOptions(controller.Options{MaxConcurrentReconciles: providerProbeWorkers}).
		Complete(r)
}
