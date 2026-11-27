package controller

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/crdtest"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/external"
	"github.com/backend-bunny/Konstapel/internal/provider/external/externaltest"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
)

// The registration reconciler against real provider endpoints: providerkit
// servers over mutual TLS 1.3 on loopback with in-memory CAs, the
// controller's client certificate in a mounted-Secret directory and trust
// ConfigMaps in the controller namespace. Only the Service address is
// redirected to loopback; the authenticated server name is the
// registration's.

const providerTestNamespace = "konstapel-system"

type providerEnv struct {
	t      *testing.T
	c      client.Client
	ca     *externaltest.CA
	client string
	mu     sync.Mutex
	addrs  map[string]string // "<namespace>/<service>:<port>" -> loopback
	r      *AssessmentProviderReconciler
	crd    *crdtest.Validator
}

func newProviderEnv(t *testing.T, objs ...client.Object) *providerEnv {
	ca := externaltest.NewCA(t)
	trust := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: providerTestNamespace, Name: externaltest.TrustConfig}, Data: map[string]string{"ca.crt": string(ca.PEM)}}
	c := fake.NewClientBuilder().WithScheme(Scheme()).WithObjects(append(objs, trust)...).
		WithStatusSubresource(&v1alpha1.AssessmentProvider{}).Build()
	e := &providerEnv{t: t, c: c, ca: ca, client: externaltest.ClientDir(t, ca), addrs: map[string]string{},
		crd: crdtest.Load(t, "../../config/crd/bases")["AssessmentProvider"]}
	catalog := &ProviderCatalog{Reader: c, BuiltIn: installed.Registry(), External: true, MaxStatusAge: external.DefaultMaxStatusAge}
	e.r = &AssessmentProviderReconciler{Client: c, Catalog: catalog, Interval: time.Minute, Timeout: 2 * time.Second,
		Dialer: &external.Dialer{Credentials: external.CredentialsDir(e.client), Trust: trustReader(c, providerTestNamespace), Address: e.address}}
	return e
}

func (e *providerEnv) address(ep external.Endpoint) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.addrs[ep.Address()]
}

// route makes both endpoints of registration ap's current revision listen
// at addr: one process serving both server names.
func (e *providerEnv) route(ap *v1alpha1.AssessmentProvider, addr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f := external.Expected(ap)
	for _, ep := range []*external.Endpoint{f.Endpoint, f.EvaluatorEndpoint} {
		if ep != nil {
			e.addrs[ep.Address()] = addr
		}
	}
}

func (e *providerEnv) serve(ap *v1alpha1.AssessmentProvider, o externaltest.ServerOptions) *externaltest.Server {
	if o.CA == nil {
		o.CA = e.ca
	}
	s := externaltest.Serve(e.t, o)
	e.route(ap, s.Addr)
	return s
}

func (e *providerEnv) reconcile(name string) ctrl.Result {
	e.t.Helper()
	res, err := e.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}})
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

func (e *providerEnv) get(name string) *v1alpha1.AssessmentProvider {
	e.t.Helper()
	ap := &v1alpha1.AssessmentProvider{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, ap); err != nil {
		e.t.Fatal(err)
	}
	return ap
}

// update changes a registration's spec as the API server would: a new
// generation.
func (e *providerEnv) update(name string, mutate func(*v1alpha1.AssessmentProvider)) *v1alpha1.AssessmentProvider {
	e.t.Helper()
	ap := e.get(name)
	mutate(ap)
	ap.Generation++
	if err := e.c.Update(context.Background(), ap); err != nil {
		e.t.Fatal(err)
	}
	return e.get(name)
}

func (e *providerEnv) setTrust(pem []byte) {
	e.t.Helper()
	cm := &corev1.ConfigMap{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Namespace: providerTestNamespace, Name: externaltest.TrustConfig}, cm); err != nil {
		e.t.Fatal(err)
	}
	cm.Data["ca.crt"] = string(pem)
	if err := e.c.Update(context.Background(), cm); err != nil {
		e.t.Fatal(err)
	}
}

// ready asserts a registration's Ready condition and that the status the
// controller wrote is valid for the generated CRD.
func (e *providerEnv) ready(name string, status metav1.ConditionStatus, reason string) *v1alpha1.AssessmentProvider {
	e.t.Helper()
	ap := e.get(name)
	c := meta.FindStatusCondition(ap.Status.Conditions, v1alpha1.ProviderConditionReady)
	if c == nil || c.Status != status || c.Reason != reason || c.ObservedGeneration != ap.Generation || ap.Status.ObservedGeneration != ap.Generation {
		e.t.Fatalf("%s Ready %+v at generation %d, want %s %s", name, c, ap.Generation, status, reason)
	}
	typed := ap.DeepCopy()
	typed.APIVersion, typed.Kind = v1alpha1.GroupVersion.String(), "AssessmentProvider"
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(typed)
	if err != nil {
		e.t.Fatal(err)
	}
	old := typed.DeepCopy()
	old.Status = v1alpha1.AssessmentProviderStatus{}
	prev, err := runtime.DefaultUnstructuredConverter.ToUnstructured(old)
	if err != nil {
		e.t.Fatal(err)
	}
	if errs := e.crd.ValidateUpdate(obj, prev); len(errs) > 0 {
		e.t.Fatalf("the controller wrote status the CRD rejects: %v", errs.ToAggregate())
	}
	for _, c := range ap.Status.Conditions {
		if strings.Contains(c.Message, "BEGIN") || strings.Contains(c.Message, "PRIVATE") {
			e.t.Fatalf("status carries PEM material: %s", c.Message)
		}
	}
	return ap
}

func (e *providerEnv) resolve(contract string, need ...v1alpha1.AssessmentProviderCapability) (external.Selected, *provider.SelectionError) {
	e.t.Helper()
	sel, serr, err := e.r.Catalog.Resolve(context.Background(), contract, need...)
	if err != nil {
		e.t.Fatal(err)
	}
	return sel, serr
}

const externalContract = externaltest.Provider + "/v1"

// A healthy registration is probed over mutual TLS, reported Ready with
// its observed identity, re-probed every interval and selected for new
// work, frozen to its UID, revision and release.
func TestAssessmentProviderProbeSelectsHealthyRegistrations(t *testing.T) {
	ap := externaltest.Registration("reporting")
	e := newProviderEnv(t, ap)
	s := e.serve(ap, externaltest.ServerOptions{})
	if _, serr := e.resolve(externalContract); serr == nil || serr.Reason != provider.ReasonProviderUnavailable {
		t.Fatalf("an unprobed registration: %v", serr)
	}
	if res := e.reconcile("reporting"); res.RequeueAfter != time.Minute {
		t.Fatalf("requeue %v", res)
	}
	got := e.ready("reporting", metav1.ConditionTrue, v1alpha1.ProviderReasonReady)
	if id := got.Status.Identity; id == nil || id.ReleaseDigest != externaltest.Release || id.Name != externaltest.Provider {
		t.Fatalf("identity %+v", id)
	}
	// One Describe per endpoint (the source and the evaluator endpoint,
	// both served here by one process), nothing else.
	if s.Calls.Load() != 2 || s.Describes.Load() != 2 {
		t.Fatalf("the probe sent %d calls, %d of them Describe", s.Calls.Load(), s.Describes.Load())
	}
	sel, serr := e.resolve(externalContract, v1alpha1.ProviderCapabilityCollect)
	if serr != nil || sel.External == nil {
		t.Fatalf("resolve: %v", serr)
	}
	if f := sel.External; f.UID != "uid-reporting" || f.Revision != 1 || f.ReleaseDigest != externaltest.Release || f.Endpoint.ServerName != externaltest.ServerName {
		t.Fatalf("frozen %+v", f)
	}
	if sel, serr := e.resolve(kyverno.Contract); serr != nil || sel.BuiltIn == nil {
		t.Fatalf("built-in: %v", serr)
	}
}

// A rotated provider CA is unauthenticated until the trust ConfigMap holds
// the new roots; the next probe after that uses them, without a restart.
func TestAssessmentProviderProbePicksUpTrustRotation(t *testing.T) {
	ap := externaltest.Registration("reporting")
	e := newProviderEnv(t, ap)
	ca2 := externaltest.NewCA(t)
	s := e.serve(ap, externaltest.ServerOptions{ClientTrust: append(append([]byte(nil), e.ca.PEM...), ca2.PEM...)})
	e.reconcile("reporting")
	e.ready("reporting", metav1.ConditionTrue, v1alpha1.ProviderReasonReady)

	s.Rotate(ca2)
	calls := s.Calls.Load()
	e.reconcile("reporting")
	got := e.ready("reporting", metav1.ConditionFalse, v1alpha1.ProviderReasonUnavailable)
	if c := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ProviderConditionAvailable); c.Reason != v1alpha1.ProviderReasonAuthenticationFailed {
		t.Fatalf("Available %+v", c)
	}
	if got.Status.Identity != nil || s.Calls.Load() != calls {
		t.Fatalf("an unauthenticated endpoint kept its identity or received %d calls", s.Calls.Load()-calls)
	}
	if _, serr := e.resolve(externalContract); serr == nil || serr.Reason != provider.ReasonProviderUnavailable {
		t.Fatalf("an unauthenticated registration was selectable: %v", serr)
	}

	e.setTrust(ca2.PEM)
	e.reconcile("reporting")
	e.ready("reporting", metav1.ConditionTrue, v1alpha1.ProviderReasonReady)

	e.setTrust([]byte("garbage"))
	e.reconcile("reporting")
	got = e.ready("reporting", metav1.ConditionFalse, v1alpha1.ProviderReasonUnavailable)
	if c := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ProviderConditionAvailable); c.Reason != v1alpha1.ProviderReasonTrustUnavailable {
		t.Fatalf("Available %+v", c)
	}
}

// newRequests Disabled blocks new starts at once, while work frozen to an
// earlier revision continues with that revision's configuration. A changed
// endpoint is used only by new work; removing or replacing the
// registration ends frozen work explicitly.
func TestAssessmentProviderDisabledAndChangedRegistrations(t *testing.T) {
	ap := externaltest.Registration("reporting")
	e := newProviderEnv(t, ap)
	e.serve(ap, externaltest.ServerOptions{})
	e.reconcile("reporting")
	sel, serr := e.resolve(externalContract)
	if serr != nil {
		t.Fatal(serr)
	}
	frozen := *sel.External

	// Revision 2 moves the Service to another port, where a new endpoint
	// of the same release listens.
	moved := e.update("reporting", func(ap *v1alpha1.AssessmentProvider) { ap.Spec.Endpoint.Service.Port = 9443 })
	if _, serr := e.resolve(externalContract); serr == nil || serr.Reason != provider.ReasonProviderUnavailable {
		t.Fatalf("revision 2 was selectable before it was probed: %v", serr)
	}
	e.serve(moved, externaltest.ServerOptions{})
	e.reconcile("reporting")
	e.ready("reporting", metav1.ConditionTrue, v1alpha1.ProviderReasonReady)
	sel, serr = e.resolve(externalContract)
	if serr != nil || sel.External.Revision != 2 || sel.External.Endpoint.Port != 9443 {
		t.Fatalf("new work: %+v %v", sel.External, serr)
	}
	if err := e.r.Catalog.Continue(context.Background(), frozen, v1alpha1.ProviderCapabilityCollect); err != nil {
		t.Fatalf("frozen work stopped on revision 2: %v", err)
	}
	if frozen.Revision != 1 || frozen.Endpoint.Port != externaltest.ServicePort {
		t.Fatalf("the frozen revision changed: %+v", frozen)
	}
	// Frozen work still reaches its own revision's endpoint.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := e.r.Dialer.Connect(ctx, frozen)
	if err != nil {
		t.Fatalf("frozen work could not reach its endpoint: %v", err)
	}
	_ = conn.Close()

	// Revision 3 drains new work.
	e.update("reporting", func(ap *v1alpha1.AssessmentProvider) { ap.Spec.NewRequests = v1alpha1.ProviderNewRequestsDisabled })
	e.reconcile("reporting")
	got := e.ready("reporting", metav1.ConditionFalse, v1alpha1.ProviderReasonNewRequestsDisabled)
	if got.Status.Identity == nil {
		t.Fatal("a draining but healthy registration lost its identity")
	}
	if _, serr := e.resolve(externalContract); serr == nil || serr.Reason != provider.ReasonProviderDisabled {
		t.Fatalf("a disabled registration was selected: %v", serr)
	}
	if err := e.r.Catalog.Continue(context.Background(), frozen, v1alpha1.ProviderCapabilityCollect); err != nil {
		t.Fatalf("draining blocked frozen work: %v", err)
	}
	if err := e.r.Catalog.Continue(context.Background(), frozen, v1alpha1.ProviderCapabilityScan); !frozenIs(err, external.FrozenCapabilityNotFrozen) {
		t.Fatalf("frozen work widened: %v", err)
	}

	// Replaced under the same name, then removed.
	old := e.get("reporting")
	if err := e.c.Delete(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := e.r.Catalog.Continue(context.Background(), frozen, v1alpha1.ProviderCapabilityCollect); !frozenIs(err, external.FrozenRegistrationRemoved) {
		t.Fatalf("removed: %v", err)
	}
	recreated := externaltest.Registration("reporting")
	recreated.UID = "uid-recreated"
	if err := e.c.Create(context.Background(), recreated); err != nil {
		t.Fatal(err)
	}
	if err := e.r.Catalog.Continue(context.Background(), frozen, v1alpha1.ProviderCapabilityCollect); !frozenIs(err, external.FrozenRegistrationReplaced) {
		t.Fatalf("replaced: %v", err)
	}
}

func frozenIs(err error, reason external.FrozenReason) bool {
	var fe *external.FrozenError
	return errors.As(err, &fe) && fe.Reason == reason
}

// A release upgrade is a second registration. While both are Enabled
// neither is selected and both say why; disabling the old release selects
// the new one. Changes to one requeue the other.
func TestAssessmentProviderAmbiguousRegistrations(t *testing.T) {
	a := externaltest.Registration("reporting-a")
	b := externaltest.Registration("reporting-b", func(ap *v1alpha1.AssessmentProvider) {
		ap.Spec.Provider.ReleaseDigest = externaltest.OtherRelease
		ap.Spec.Endpoint.Service.Name = "example-reporting-next"
		ap.Spec.EvaluatorEndpoint.Service.Name = "example-reporting-next-evaluator"
	})
	e := newProviderEnv(t, a, b)
	e.serve(a, externaltest.ServerOptions{})
	next := externaltest.Description()
	next.Implementation = externaltest.OtherRelease
	e.serve(b, externaltest.ServerOptions{Description: next})
	e.reconcile("reporting-a")
	e.reconcile("reporting-b")
	e.ready("reporting-a", metav1.ConditionFalse, v1alpha1.ProviderReasonAmbiguousRegistration)
	e.ready("reporting-b", metav1.ConditionFalse, v1alpha1.ProviderReasonAmbiguousRegistration)
	if _, serr := e.resolve(externalContract); serr == nil || serr.Reason != provider.ReasonAmbiguousProvider {
		t.Fatalf("an ambiguous contract: %v", serr)
	}
	q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer q.ShutDown()
	sameProvider(e.c).Update(context.Background(), event.UpdateEvent{ObjectOld: a, ObjectNew: a}, q)
	if r, _ := q.Get(); q.Len() != 0 || r.Name != "reporting-b" {
		t.Fatalf("a change to reporting-a requeues %v and %d more", r, q.Len())
	}

	e.update("reporting-a", func(ap *v1alpha1.AssessmentProvider) { ap.Spec.NewRequests = v1alpha1.ProviderNewRequestsDisabled })
	e.reconcile("reporting-a")
	e.reconcile("reporting-b")
	e.ready("reporting-a", metav1.ConditionFalse, v1alpha1.ProviderReasonNewRequestsDisabled)
	e.ready("reporting-b", metav1.ConditionTrue, v1alpha1.ProviderReasonReady)
	sel, serr := e.resolve(externalContract)
	if serr != nil || sel.External.Registration != "reporting-b" || sel.External.ReleaseDigest != externaltest.OtherRelease {
		t.Fatalf("after draining the old release: %+v %v", sel.External, serr)
	}
}

// An unavailable, hanging or incompatible provider is reported on its own
// registration only. Probes run concurrently and each is bounded, so a
// hanging endpoint never delays a healthy one, and neither affects
// selection of the healthy provider or of the built-in Kyverno provider.
func TestAssessmentProviderHealthyProvidersAreIndependent(t *testing.T) {
	named := func(name, provider string) *v1alpha1.AssessmentProvider {
		return externaltest.Registration(name, func(ap *v1alpha1.AssessmentProvider) {
			ap.Spec.Provider.Name = provider
			ap.Spec.Endpoint.Service.Name = provider
			ap.Spec.EvaluatorEndpoint.Service.Name = provider + "-evaluator"
		})
	}
	healthy, hanging, closed, wrong := externaltest.Registration("reporting"), named("hanging", "hanging-reporting"), named("closed", "closed-reporting"), named("wrong", "wrong-reporting")
	e := newProviderEnv(t, healthy, hanging, closed, wrong)
	e.serve(healthy, externaltest.ServerOptions{})
	e.route(hanging, externaltest.Hang(t))
	e.route(closed, externaltest.Closed(t))
	e.serve(wrong, externaltest.ServerOptions{}) // serves example-reporting, not wrong-reporting

	var wg sync.WaitGroup
	done := map[string]time.Duration{}
	var mu sync.Mutex
	start := time.Now()
	for _, name := range []string{"hanging", "closed", "wrong", "reporting"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
				t.Error(err)
			}
			mu.Lock()
			done[name] = time.Since(start)
			mu.Unlock()
		}()
	}
	wg.Wait()
	if done["reporting"] >= e.r.Timeout || done["hanging"] > e.r.Timeout+2*time.Second {
		t.Fatalf("probe durations %v with a %s timeout", done, e.r.Timeout)
	}
	e.ready("reporting", metav1.ConditionTrue, v1alpha1.ProviderReasonReady)
	for name, reason := range map[string]string{"hanging": v1alpha1.ProviderReasonUnavailable, "closed": v1alpha1.ProviderReasonUnavailable, "wrong": v1alpha1.ProviderReasonIncompatible} {
		e.ready(name, metav1.ConditionFalse, reason)
	}
	if c := meta.FindStatusCondition(e.get("wrong").Status.Conditions, v1alpha1.ProviderConditionCompatible); c.Reason != v1alpha1.ProviderReasonProviderMismatch {
		t.Fatalf("wrong provider: %+v", c)
	}
	if sel, serr := e.resolve(externalContract); serr != nil || sel.External.Registration != "reporting" {
		t.Fatalf("the healthy provider: %v", serr)
	}
	if sel, serr := e.resolve(kyverno.Contract); serr != nil || sel.BuiltIn == nil {
		t.Fatalf("the built-in provider: %v", serr)
	}
	for _, c := range []string{"hanging-reporting/v1", "closed-reporting/v1", "wrong-reporting/v1"} {
		if _, serr := e.resolve(c); serr == nil || serr.Reason != provider.ReasonProviderUnavailable {
			t.Fatalf("%s: %v", c, serr)
		}
	}
}

// A registration naming a built-in provider, which the API rejects, is
// never contacted by the controller nor selected.
func TestAssessmentProviderNeverContactsBuiltInNames(t *testing.T) {
	ap := externaltest.Registration("shadow", func(ap *v1alpha1.AssessmentProvider) { ap.Spec.Provider.Name = "konstapel-kyverno" })
	e := newProviderEnv(t, ap)
	s := e.serve(ap, externaltest.ServerOptions{})
	e.reconcile("shadow")
	got := e.get("shadow")
	if c := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ProviderConditionCompatible); c == nil || c.Reason != v1alpha1.ProviderReasonBuiltInProvider {
		t.Fatalf("Compatible %+v", c)
	}
	if s.Calls.Load() != 0 {
		t.Fatal("the controller contacted a registration naming a built-in provider")
	}
	if sel, serr := e.resolve(kyverno.Contract); serr != nil || sel.BuiltIn == nil {
		t.Fatalf("the built-in provider was shadowed: %+v %v", sel, serr)
	}
}

// Disabled by default: an external contract is unknown, as before, and no
// registration is read at all.
func TestExternalProvidersAreOffByDefault(t *testing.T) {
	var opts Options
	if opts.ExternalProviders.Enabled() || opts.ExternalProviders.Validate() != nil {
		t.Fatal("external providers are not off by default")
	}
	c := fake.NewClientBuilder().WithScheme(Scheme()).WithInterceptorFuncs(interceptor.Funcs{
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return errors.New("registrations were listed")
		},
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return errors.New("a registration was read")
		},
	}).Build()
	p := &ProviderCatalog{Reader: c, BuiltIn: installed.Registry()}
	sel, serr, err := p.Resolve(context.Background(), externalContract)
	if err != nil || serr == nil || serr.Reason != provider.ReasonUnknownProvider || sel.External != nil {
		t.Fatalf("an external contract with external providers off: %+v %v %v", sel, serr, err)
	}
	if sel, serr, err := p.Resolve(context.Background(), ""); err != nil || serr != nil || sel.BuiltIn == nil || sel.Contract != kyverno.Contract {
		t.Fatalf("the default contract: %+v %v %v", sel, serr, err)
	}
	if err := p.Continue(context.Background(), external.Frozen{Registration: "reporting"}, v1alpha1.ProviderCapabilityCollect); !frozenIs(err, external.FrozenRegistrationRemoved) {
		t.Fatalf("frozen work with external providers off: %v", err)
	}
}

func TestExternalProvidersValidate(t *testing.T) {
	ca := externaltest.NewCA(t)
	dir := externaltest.ClientDir(t, ca)
	if err := (ExternalProviders{ClientCertDir: dir}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		e    ExternalProviders
		want string
	}{
		{"missing credentials", ExternalProviders{ClientCertDir: t.TempDir()}, "client credentials"},
		{"timeout not below the interval", ExternalProviders{ClientCertDir: dir, ProbeInterval: time.Second, ProbeTimeout: time.Second}, "shorter than the probe interval"},
		{"status age within an interval", ExternalProviders{ClientCertDir: dir, ProbeInterval: time.Minute, MaxStatusAge: time.Minute}, "must exceed"},
		{"negative", ExternalProviders{ClientCertDir: dir, ProbeTimeout: -time.Second}, "positive"},
	} {
		if err := tc.e.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	if _, err := NewManager(nil, Options{ExternalProviders: ExternalProviders{ClientCertDir: t.TempDir()}}); err == nil || !strings.Contains(err.Error(), "client credentials") {
		t.Fatalf("a manager with invalid client credentials: %v", err)
	}
}
