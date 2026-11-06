package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/exception"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Leader election and its events live in the controller's namespace.
// +kubebuilder:rbac:groups=coordination.k8s.io,namespace=konstapel-system,resources=leases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",namespace=konstapel-system,resources=events,verbs=create;patch

// ProfileRefIndex indexes ComplianceBindings by spec.profileRef.name.
const ProfileRefIndex = "spec.profileRef.name"

// LeaderElectionID is the Lease name the controller uses.
const LeaderElectionID = "konstapel-targeting.compliance.erenius.io"

// Options configure the targeting manager.
type Options struct {
	Content                 targeting.ContentSource
	MetricsAddr             string
	ProbeAddr               string
	LeaderElection          bool
	LeaderElectionNamespace string
	// SkipControllerNameValidation allows a second manager in the same
	// process. Only tests that restart the manager in-process set it.
	SkipControllerNameValidation bool
	// EnginePoll is how often discovery is retried until the engine API is
	// served, and how long an availability answer is cached.
	EnginePoll time.Duration
	// WebhookCertDir holds tls.crt and tls.key for the exception admission
	// webhooks. Empty serves no webhooks and starts no webhook server.
	WebhookCertDir string
	// WebhookPort is the webhook server's port; 0 means 9443.
	WebhookPort int
}

// Scheme returns the scheme the manager uses.
func Scheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilMust(clientgoscheme.AddToScheme(s))
	utilMust(v1alpha1.AddToScheme(s))
	return s
}

// NewManager builds the targeting manager. It does not need the engine to
// be installed: the engine API is discovered while running, and the
// owned-policy watch starts once it is served.
func NewManager(cfg *rest.Config, opts Options) (manager.Manager, error) {
	if opts.EnginePoll == 0 {
		opts.EnginePoll = 15 * time.Second
	}
	mopts := ctrl.Options{
		Scheme:                  Scheme(),
		Metrics:                 metricsserver.Options{BindAddress: opts.MetricsAddr},
		HealthProbeBindAddress:  opts.ProbeAddr,
		LeaderElection:          opts.LeaderElection,
		LeaderElectionID:        LeaderElectionID,
		LeaderElectionNamespace: opts.LeaderElectionNamespace,
		Controller:              config.Controller{SkipNameValidation: &opts.SkipControllerNameValidation},
	}
	if opts.WebhookCertDir != "" {
		mopts.WebhookServer = webhook.NewServer(webhook.Options{Port: opts.WebhookPort, CertDir: opts.WebhookCertDir, CertName: "tls.crt", KeyName: "tls.key"})
	}
	mgr, err := ctrl.NewManager(cfg, mopts)
	if err != nil {
		return nil, err
	}
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return nil, err
	}
	if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
		return nil, err
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.ComplianceBinding{}, ProfileRefIndex, func(o client.Object) []string {
		return []string{o.(*v1alpha1.ComplianceBinding).Spec.ProfileRef.Name}
	}); err != nil {
		return nil, err
	}

	// The cluster identity is the assessment loop's: kube-system's UID.
	ks := &corev1.Namespace{}
	if err := mgr.GetAPIReader().Get(context.Background(), client.ObjectKey{Name: "kube-system"}, ks); err != nil {
		return nil, fmt.Errorf("read cluster identity: %w", err)
	}
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, err
	}
	engine := cachedEngine(DiscoverEngine(dc), opts.EnginePoll)

	br := &BindingReconciler{Client: mgr.GetClient(), Reader: mgr.GetAPIReader(), Content: opts.Content, Engine: engine, Cluster: "kube-system:" + string(ks.UID)}
	bc, err := builder.ControllerManagedBy(mgr).
		Named("compliancebinding").
		For(&v1alpha1.ComplianceBinding{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&v1alpha1.ComplianceProfile{}, handler.EnqueueRequestsFromMapFunc(bindingsForProfile(mgr.GetClient())), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.Namespace{}, namespaceHandler(mgr.GetClient())).
		Build(br)
	if err != nil {
		return nil, err
	}
	if err := builder.ControllerManagedBy(mgr).Named("complianceprofile").
		For(&v1alpha1.ComplianceProfile{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(&ProfileReconciler{Client: mgr.GetClient(), Content: opts.Content}); err != nil {
		return nil, err
	}
	if err := mgr.Add(&ownedPolicyWatch{mgr: mgr, ctrl: bc, engine: engine, poll: opts.EnginePoll}); err != nil {
		return nil, err
	}
	if err := setupAssessments(mgr, opts.Content, engine, br.Cluster, opts.EnginePoll); err != nil {
		return nil, err
	}
	if opts.WebhookCertDir != "" {
		// Admission runs on every replica; the server needs no leader. It
		// reads through the API reader so acceptance sees current configuration.
		m, v := exception.NewHandlers(mgr.GetScheme(), mgr.GetAPIReader(), opts.Content, br.Cluster)
		exception.Register(mgr.GetWebhookServer(), m, v)
	}
	return mgr, nil
}

// DiscoverEngine checks that the cluster serves policies.kyverno.io/v1
// validatingpolicies. A missing group/version is "not available", not an error.
func DiscoverEngine(dc discovery.DiscoveryInterface) EngineAvailable {
	return func(context.Context) (bool, error) {
		gv := targeting.ValidatingPolicyGVK.GroupVersion().String()
		list, err := dc.ServerResourcesForGroupVersion(gv)
		if err != nil {
			if isNotFound(err) {
				return false, nil
			}
			return false, fmt.Errorf("discover %s: %w", gv, err)
		}
		for _, r := range list.APIResources {
			if r.Name == "validatingpolicies" && !r.Namespaced {
				return true, nil
			}
		}
		return false, nil
	}
}

func cachedEngine(f EngineAvailable, ttl time.Duration) EngineAvailable {
	var mu sync.Mutex
	var at time.Time
	var ok bool
	return func(ctx context.Context) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		if ok && time.Since(at) < ttl {
			return true, nil
		}
		avail, err := f(ctx)
		ok, at = avail && err == nil, time.Now()
		return avail, err
	}
}

// ownedPolicyWatch starts the watch on owned engine policies once the engine
// API is served, so the manager starts and reports EngineUnavailable when
// Kyverno is absent. add-helm-oci-distribution's capability monitor
// generalises this (re-registration after API removal, authorization checks).
type ownedPolicyWatch struct {
	mgr    manager.Manager
	ctrl   controller.Controller
	engine EngineAvailable
	poll   time.Duration
}

func (w *ownedPolicyWatch) NeedLeaderElection() bool { return true }

func (w *ownedPolicyWatch) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("owned-policy-watch")
	t := time.NewTicker(w.poll)
	defer t.Stop()
	for {
		if ok, err := w.engine(ctx); err != nil {
			logger.Info("engine discovery failed; retrying", "error", err.Error())
		} else if ok {
			obj := &unstructured.Unstructured{}
			obj.SetGroupVersionKind(targeting.ValidatingPolicyGVK)
			// Only engine policies Konstapel manages are cached.
			managed := predicate.NewPredicateFuncs(func(o client.Object) bool {
				return o.GetLabels()[targeting.LabelManagedBy] == targeting.ManagedByValue
			})
			src := source.Kind(w.mgr.GetCache(), client.Object(obj),
				handler.EnqueueRequestForOwner(w.mgr.GetScheme(), w.mgr.GetRESTMapper(), &v1alpha1.ComplianceBinding{}, handler.OnlyControllerOwner()),
				managed)
			if err := w.ctrl.Watch(src); err != nil {
				logger.Info("could not start owned-policy watch; retrying", "error", err.Error())
			} else {
				logger.Info("watching owned engine policies")
				<-ctx.Done()
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func bindingsForProfile(c client.Client) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		var list v1alpha1.ComplianceBindingList
		if err := c.List(ctx, &list, client.MatchingFields{ProfileRefIndex: o.GetName()}); err != nil {
			return nil
		}
		return requests(list.Items)
	}
}

// namespaceHandler enqueues only bindings whose selector matches the
// namespace's old or new labels. Namespace events never change engine
// policies (the selector is rendered, not expanded), only status.
func namespaceHandler(c client.Client) handler.EventHandler {
	enqueue := func(ctx context.Context, q workqueue.TypedRateLimitingInterface[reconcile.Request], sets ...labels.Set) {
		var list v1alpha1.ComplianceBindingList
		if err := c.List(ctx, &list); err != nil {
			return
		}
		var hit []v1alpha1.ComplianceBinding
		for _, b := range list.Items {
			sel, err := b.Spec.NamespaceSelector.AsSelector()
			if err != nil {
				hit = append(hit, b) // let the reconciler report the invalid selector
				continue
			}
			for _, s := range sets {
				if sel.Matches(s) {
					hit = append(hit, b)
					break
				}
			}
		}
		for _, r := range requests(hit) {
			q.Add(r)
		}
	}
	return handler.Funcs{
		CreateFunc: func(ctx context.Context, e event.CreateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			enqueue(ctx, q, e.Object.GetLabels())
		},
		UpdateFunc: func(ctx context.Context, e event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			if labels.Equals(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels()) &&
				e.ObjectOld.GetDeletionTimestamp().IsZero() == e.ObjectNew.GetDeletionTimestamp().IsZero() {
				return
			}
			enqueue(ctx, q, e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels())
		},
		DeleteFunc: func(ctx context.Context, e event.DeleteEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			enqueue(ctx, q, e.Object.GetLabels())
		},
	}
}

func requests(bs []v1alpha1.ComplianceBinding) []reconcile.Request {
	out := make([]reconcile.Request, 0, len(bs))
	for _, b := range bs {
		out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: b.Name}})
	}
	return out
}

func utilMust(err error) {
	if err != nil {
		panic(err)
	}
}

func isNotFound(err error) bool {
	return apierrors.IsNotFound(err) || discovery.IsGroupDiscoveryFailedError(err)
}
