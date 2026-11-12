package stack_test

import (
	"context"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	bundlecontent "github.com/backend-bunny/Konstapel/internal/bundle/content"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/controller"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// cluster is a fake API server with the profile and binding reconcilers
// wired to the router over the real bundle stack, as NewManager wires them.
type cluster struct {
	t       *testing.T
	w       *stack.World
	c       client.Client
	router  *stack.Router
	profile *controller.ProfileReconciler
	binding *controller.BindingReconciler
	// onBindingRead runs once on the binding reconciler's next uncached
	// read of a binding (the snapshot check right before applying).
	onBindingRead atomic.Pointer[func()]
	policy        string
	// engine is what the binding reconciler's engine check reports; nil
	// means available.
	engine atomic.Pointer[engineState]
	// writes records every write the reconcilers make, as "verb Kind".
	writes writeLog
}

type engineState struct {
	available bool
	err       error
}

func newCluster(t *testing.T) *cluster {
	w := stack.NewWorld(t)
	return newClusterOver(t, w, w.Stack.Router(stack.LocalContent(), stack.VendoredName), w.Ref(), nil)
}

// newClusterOver wires the reconcilers to router and creates the profile
// "org" pinning ref (with the given policies, or the bundle's first policy
// when nil) and the audit binding "org" selecting namespace app.
func newClusterOver(t *testing.T, w *stack.World, router *stack.Router, ref v1alpha1.BundleReference, policies []v1alpha1.ProfilePolicy) *cluster {
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(targeting.ValidatingPolicyGVK, meta.RESTScopeRoot)
	for _, k := range []string{"ComplianceBinding", "ComplianceProfile"} {
		mapper.Add(v1alpha1.GroupVersion.WithKind(k), meta.RESTScopeRoot)
	}
	mapper.Add(schema.GroupVersionKind{Version: "v1", Kind: "Namespace"}, meta.RESTScopeRoot)
	c := fake.NewClientBuilder().WithScheme(controller.Scheme()).WithRESTMapper(mapper).
		WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app", UID: "uid-app", Labels: map[string]string{"team": "a"}}}).
		WithStatusSubresource(&v1alpha1.ComplianceBinding{}, &v1alpha1.ComplianceProfile{}).
		WithIndex(&v1alpha1.ComplianceBinding{}, controller.ProfileRefIndex, func(o client.Object) []string {
			return []string{o.(*v1alpha1.ComplianceBinding).Spec.ProfileRef.Name}
		}).Build()
	cl := &cluster{t: t, w: w, c: c, router: router}
	reader := interceptor.NewClient(c.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, cw client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*v1alpha1.ComplianceBinding); ok {
				if f := cl.onBindingRead.Swap(nil); f != nil {
					(*f)()
				}
			}
			return cw.Get(ctx, key, obj, opts...)
		}})
	writer := cl.writes.client(c.(client.WithWatch))
	cl.profile = &controller.ProfileReconciler{Client: writer, ValidateParameters: bundlecontent.ValidateParameters}
	cl.binding = &controller.BindingReconciler{Client: writer, Reader: reader, Cluster: "kube-system:test",
		Engine: func(context.Context) (bool, error) {
			if e := cl.engine.Load(); e != nil {
				return e.available, e.err
			}
			return true, nil
		}, Ready: func(*unstructured.Unstructured) bool { return true },
		ValidateParameters: bundlecontent.ValidateParameters}
	cl.setRouter(router)
	if policies == nil {
		content, err := cl.router.Content(context.Background(), ref)
		if err != nil {
			t.Fatal(err)
		}
		cl.policy = content.Bundle.Policies[0].Name
		policies = []v1alpha1.ProfilePolicy{{Name: cl.policy}}
	}
	for _, o := range []client.Object{
		&v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "org", UID: "uid-org", Generation: 1},
			Spec: v1alpha1.ComplianceProfileSpec{Bundle: ref, Policies: policies}},
		&v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "org", UID: "uid-binding", Generation: 1},
			Spec: v1alpha1.ComplianceBindingSpec{ProfileRef: v1alpha1.ProfileReference{Name: "org"}, Mode: v1alpha1.ModeAudit,
				NamespaceSelector: &v1alpha1.NamespaceSelector{MatchLabels: map[string]v1alpha1.LabelValue{"team": "a"}}}},
	} {
		if err := c.Create(context.Background(), o); err != nil {
			t.Fatal(err)
		}
	}
	return cl
}

// setRouter points both reconcilers at router (after a restart builds a
// new stack, as a restarted controller would).
func (cl *cluster) setRouter(router *stack.Router) {
	cl.router = router
	cl.profile.Content = router
	cl.binding.Content = router
}

func (cl *cluster) reconcile() ctrl.Result {
	cl.t.Helper()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "org"}}
	if _, err := cl.profile.Reconcile(context.Background(), req); err != nil {
		cl.t.Fatal(err)
	}
	res, err := cl.binding.Reconcile(context.Background(), req)
	if err != nil {
		cl.t.Fatal(err)
	}
	return res
}

func (cl *cluster) conditions() (profile, resolved, engine metav1.Condition) {
	cl.t.Helper()
	p := &v1alpha1.ComplianceProfile{}
	b := &v1alpha1.ComplianceBinding{}
	if err := cl.c.Get(context.Background(), client.ObjectKey{Name: "org"}, p); err != nil {
		cl.t.Fatal(err)
	}
	if err := cl.c.Get(context.Background(), client.ObjectKey{Name: "org"}, b); err != nil {
		cl.t.Fatal(err)
	}
	get := func(cs []metav1.Condition, typ string) metav1.Condition {
		if c := meta.FindStatusCondition(cs, typ); c != nil {
			return *c
		}
		return metav1.Condition{}
	}
	return get(p.Status.Conditions, v1alpha1.ConditionResolved), get(b.Status.Conditions, v1alpha1.ConditionResolved), get(b.Status.Conditions, v1alpha1.ConditionEngineReady)
}

func (cl *cluster) policies() []unstructured.Unstructured {
	cl.t.Helper()
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(targeting.ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
	if err := cl.c.List(context.Background(), list); err != nil {
		cl.t.Fatal(err)
	}
	return list.Items
}

// A profile pinning an OCI bundle resolves and renders through the wired
// stack; a trust change invalidates it and keeps the applied policies; the
// restored rule recovers without duplicates.
func TestWiredStackEndToEnd(t *testing.T) {
	cl := newCluster(t)
	cl.reconcile()
	p, r, e := cl.conditions()
	if p.Status != metav1.ConditionTrue || r.Status != metav1.ConditionTrue || e.Status != metav1.ConditionTrue {
		t.Fatalf("initial: profile %+v, resolved %+v, engine %+v", p, r, e)
	}
	applied := cl.policies()
	if len(applied) != 1 || applied[0].GetAnnotations()[targeting.AnnotationBundleDigest] != cl.w.Fix.Subject ||
		applied[0].GetAnnotations()[targeting.AnnotationBundle] != stack.FixtureName {
		t.Fatalf("applied %d policies: %v", len(applied), applied)
	}
	if cl.w.Leases() != 0 {
		t.Fatalf("%d leases after reconciles", cl.w.Leases())
	}

	// Trust revoked: the rule now names another key.
	cl.w.SetSources(cl.w.OtherSource())
	cl.w.Sync()
	cl.reconcile()
	p, r, e = cl.conditions()
	if p.Reason != v1alpha1.ReasonContentUnavailable || r.Reason != v1alpha1.ReasonContentUnavailable || e.Status != metav1.ConditionFalse {
		t.Fatalf("revoked: profile %+v, resolved %+v, engine %+v", p, r, e)
	}
	if got := cl.policies(); len(got) != 1 || got[0].GetName() != applied[0].GetName() {
		t.Fatalf("revocation changed the applied policies: %v", got)
	}

	// Recovery.
	cl.w.SetSources(cl.w.OrgSource())
	cl.w.Sync()
	cl.reconcile()
	p, r, e = cl.conditions()
	if p.Status != metav1.ConditionTrue || r.Status != metav1.ConditionTrue || e.Status != metav1.ConditionTrue {
		t.Fatalf("recovered: profile %+v, resolved %+v, engine %+v", p, r, e)
	}
	if got := cl.policies(); len(got) != 1 || got[0].GetName() != applied[0].GetName() {
		t.Fatalf("recovery duplicated or replaced policies: %v", got)
	}
}

// The TOCTOU window between reading content for rendering and applying it:
// trust is revoked after desired() read the content and before Delivery
// writes. The adoption guard refuses the apply: nothing is created and the
// binding resolves again.
func TestRevocationBeforeApplyIsRefused(t *testing.T) {
	cl := newCluster(t)
	revoke := func() {
		cl.w.SetSources(cl.w.OtherSource())
		cl.w.Sync()
	}
	cl.onBindingRead.Store(&revoke)
	res := cl.reconcile()
	if cl.onBindingRead.Load() != nil {
		t.Fatal("the snapshot check did not run")
	}
	if got := cl.policies(); len(got) != 0 {
		t.Fatalf("applied content revoked before the write: %v", got)
	}
	if res.RequeueAfter == 0 {
		t.Fatal("a refused apply must resolve again")
	}
	if err := cl.router.Confirm(context.Background(), cl.w.Ref()); err == nil {
		t.Fatal("confirmed revoked content")
	}
	// The next reconcile reads the revoked content and applies nothing.
	cl.reconcile()
	if _, r, _ := cl.conditions(); r.Reason != v1alpha1.ReasonContentUnavailable {
		t.Fatalf("after revocation: %+v", r)
	}
}

// Pins: a Pinner over the wired stack pins the profile's and the applied
// bundle, keeps them across the reconciles, and a restarted process (new
// stack, no leases) re-pins them from cluster state.
func TestPinsFromClusterStateAcrossRestart(t *testing.T) {
	cl := newCluster(t)
	cl.reconcile()
	pins := func() *stack.Pinner {
		return &stack.Pinner{Pin: cl.w.Stack.Pin, Desired: stack.ClusterState{Client: cl.c, Engine: cl.c, Local: stack.VendoredName}.Desired}
	}
	p := pins()
	if err := p.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	holders := map[string]bool{}
	for _, k := range p.Held() {
		holders[k.Holder] = true
	}
	if !holders[bundle.HolderProfile] || !holders[bundle.HolderApplied] || cl.w.Leases() != 2 {
		t.Fatalf("pins %v, %d leases", p.Held(), cl.w.Leases())
	}
	cl.reconcile()
	if cl.w.Leases() != 2 {
		t.Fatalf("reconciles changed the pins: %d leases", cl.w.Leases())
	}

	// Restart with the registry down: the retained evidence re-pins offline.
	cl.w.Fetch.Down.Store(true)
	cl.w.Restart()
	if cl.w.Leases() != 0 {
		t.Fatal("leases survived a restart")
	}
	p2 := pins()
	if err := p2.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cl.w.Leases() != 2 || len(p2.Held()) != 2 {
		t.Fatalf("re-pinned %v, %d leases", p2.Held(), cl.w.Leases())
	}

	// Profile deleted and its policies withdrawn: every pin is released.
	if err := cl.c.Delete(context.Background(), &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "org"}}); err != nil {
		t.Fatal(err)
	}
	for _, o := range cl.policies() {
		if err := cl.c.Delete(context.Background(), &o); err != nil {
			t.Fatal(err)
		}
	}
	if err := p2.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cl.w.Leases() != 0 || len(p2.Held()) != 0 {
		t.Fatalf("stale pins %v, %d leases", p2.Held(), cl.w.Leases())
	}
}
