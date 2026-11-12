package controller

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	bundlecontent "github.com/backend-bunny/Konstapel/internal/bundle/content"
	"github.com/backend-bunny/Konstapel/internal/exception"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// bundlecontent.ValidateParameters is the validator the manager wires.
var _ ParameterValidator = bundlecontent.ValidateParameters

const plantedSecret = "PLANTED-password-hunter2"

// switchContent serves the vendored content unless a failure is set; fail
// can be limited to one call (failAt), and edit adjusts served content.
type switchContent struct {
	mu     sync.Mutex
	inner  targeting.ContentSource
	err    error
	failAt int // 1-based call number to fail at; 0: every call while err is set
	calls  int
	edit   func(*targeting.Content)
}

func (s *switchContent) set(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err, s.failAt, s.calls = err, 0, 0
}

func (s *switchContent) Content(ctx context.Context, ref v1alpha1.BundleReference) (*targeting.Content, error) {
	s.mu.Lock()
	s.calls++
	err, fail, edit := s.err, s.err != nil && (s.failAt == 0 || s.failAt == s.calls), s.edit
	s.mu.Unlock()
	if fail {
		return nil, err
	}
	c, cerr := s.inner.Content(ctx, ref)
	if cerr == nil && edit != nil {
		edit(c)
	}
	return c, cerr
}

func classErr(class targeting.ContentErrorClass, detail string) error {
	// Err is the classification sentinel; a planted secret there must never
	// reach status.
	return &targeting.ContentError{Class: class, Detail: detail, Err: errors.New(plantedSecret)}
}

var allClasses = []struct {
	class   targeting.ContentErrorClass
	requeue time.Duration
}{
	{targeting.ContentErrorStale, StaleContentRequeue},
	{targeting.ContentErrorContentUnavailable, TransientContentRequeue},
	{targeting.ContentErrorProofUnavailable, TransientContentRequeue},
	{targeting.ContentErrorCapacity, TransientContentRequeue},
	{targeting.ContentErrorUnresolved, TransientContentRequeue},
	{targeting.ContentErrorUntrusted, UntrustedContentRequeue},
	{targeting.ContentErrorConfig, 0},
	{targeting.ContentErrorIncompatible, 0},
	{targeting.ContentErrorDigestMismatch, 0},
	{targeting.ContentErrorMalformed, 0},
}

func TestContentRequeuePolicy(t *testing.T) {
	for _, c := range allClasses {
		if got := ContentRequeue(classErr(c.class, "x")); got != c.requeue {
			t.Errorf("%s: requeue %s, want %s", c.class, got, c.requeue)
		}
	}
	for _, err := range []error{nil, targeting.ErrContentUnavailable, errors.New("other")} {
		if got := ContentRequeue(err); got != 0 {
			t.Errorf("%v: requeue %s", err, got)
		}
	}
}

func (e *env) profileCond(name string) (metav1.Condition, *v1alpha1.ComplianceProfile) {
	e.t.Helper()
	p := &v1alpha1.ComplianceProfile{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, p); err != nil {
		e.t.Fatal(err)
	}
	c := meta.FindStatusCondition(p.Status.Conditions, v1alpha1.ConditionResolved)
	if c == nil {
		e.t.Fatalf("%s has no Resolved condition", name)
	}
	return *c, p
}

func reconcileProfile(t *testing.T, pr *ProfileReconciler, name string) ctrl.Result {
	t.Helper()
	res, err := pr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// Every content error class is Resolved=False/ContentUnavailable with the
// class and bounded detail in the message, the current observed generation
// and the class's requeue; recovery returns to Resolved.
func TestProfileConditionPerContentClass(t *testing.T) {
	long := strings.Repeat("d", 3*maxMessage)
	for _, c := range allClasses {
		t.Run(string(c.class), func(t *testing.T) {
			p := profileObj(t, "baseline", pol)
			p.Generation = 3
			e := newEnv(t, p)
			sc := &switchContent{inner: content}
			pr := &ProfileReconciler{Client: e.c, Content: sc}

			sc.set(classErr(c.class, "konstapel-vendored@sha256:x: "+string(c.class)+" detail"))
			for range 2 { // the second reconcile writes nothing but requeues the same way
				if res := reconcileProfile(t, pr, "baseline"); res.RequeueAfter != c.requeue {
					t.Fatalf("requeue %s, want %s", res.RequeueAfter, c.requeue)
				}
			}
			cond, got := e.profileCond("baseline")
			if cond.Status != metav1.ConditionFalse || cond.Reason != v1alpha1.ReasonContentUnavailable ||
				!strings.Contains(cond.Message, "("+string(c.class)+")") || !strings.Contains(cond.Message, string(c.class)+" detail") ||
				cond.ObservedGeneration != 3 || got.Status.ObservedGeneration != 3 {
				t.Fatalf("condition %+v", cond)
			}
			if strings.Contains(cond.Message, plantedSecret) {
				t.Fatal("secret in status")
			}

			sc.set(classErr(c.class, long))
			reconcileProfile(t, pr, "baseline")
			if cond, _ := e.profileCond("baseline"); len(cond.Message) > maxMessage {
				t.Fatalf("message is %d bytes", len(cond.Message))
			}

			sc.set(nil)
			if res := reconcileProfile(t, pr, "baseline"); res.RequeueAfter != 0 {
				t.Fatalf("resolved profile requeued: %+v", res)
			}
			cond, _ = e.profileCond("baseline")
			if cond.Status != metav1.ConditionTrue || cond.Reason != v1alpha1.ReasonResolutionSucceeded || cond.ObservedGeneration != 3 ||
				!strings.Contains(cond.Message, "policies resolve in") {
				t.Fatalf("recovery %+v", cond)
			}
		})
	}
}

// LocalContent errors are reported exactly as before: the error text, no
// timed retry.
func TestProfileLocalContentErrorUnchanged(t *testing.T) {
	p := profileObj(t, "missing", pol)
	p.Spec.Bundle.Digest = "sha256:" + strings.Repeat("1", 64)
	e := newEnv(t, p)
	pr := &ProfileReconciler{Client: e.c, Content: content}
	if res := reconcileProfile(t, pr, "missing"); res.RequeueAfter != 0 {
		t.Fatalf("requeue %+v", res)
	}
	_, want := content.Content(context.Background(), p.Spec.Bundle)
	if cond, _ := e.profileCond("missing"); cond.Message != want.Error() || cond.Reason != v1alpha1.ReasonContentUnavailable {
		t.Fatalf("condition %+v, want message %q", cond, want)
	}
}

func appliedNames(e *env) []string {
	var out []string
	for _, p := range e.policies() {
		out = append(out, p.GetName()+"@"+p.GetResourceVersion())
	}
	return out
}

func bindingResult(t *testing.T, e *env, name string) (ctrl.Result, error) {
	t.Helper()
	return e.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}})
}

// Initial failure: nothing is applied, the binding is unresolved with the
// detailed class, and it is retried per class.
func TestBindingInitialContentFailure(t *testing.T) {
	e := newEnv(t, nsObj("prod"), profileObj(t, "baseline", pol), bindingObj("all", "baseline", v1alpha1.ModeAudit, nil))
	sc := &switchContent{inner: content}
	e.r.Content = sc
	sc.set(classErr(targeting.ContentErrorContentUnavailable, "registry outage"))
	if res := e.reconcile("all"); res.RequeueAfter != TransientContentRequeue {
		t.Fatalf("requeue %+v", res)
	}
	b := e.binding("all")
	requireObserved(t, b)
	if c := cond(b, v1alpha1.ConditionResolved); c.Status != metav1.ConditionFalse || c.Reason != v1alpha1.ReasonContentUnavailable ||
		!strings.Contains(c.Message, "(ContentUnavailable): registry outage") || strings.Contains(c.Message, plantedSecret) {
		t.Fatalf("Resolved %+v", c)
	}
	requireNotCurrent(t, b, v1alpha1.ReasonStaleRevision)
	if len(e.policies()) != 0 || b.Status.ConfigurationRevision != "" {
		t.Fatalf("unresolved content applied something: %v %q", e.policies(), b.Status.ConfigurationRevision)
	}
	// Persistent configuration failures are not retried on a timer.
	sc.set(classErr(targeting.ContentErrorConfig, "no source"))
	if res := e.reconcile("all"); res.RequeueAfter != 0 {
		t.Fatalf("config failure requeued: %+v", res)
	}
	sc.set(nil)
	e.reconcile("all")
	if len(e.policies()) != 1 {
		t.Fatal("recovery did not deliver")
	}
}

// Failed update, trust revocation and recovery: applied owned policies are
// retained and reported stale, no new revision is installed or reapplied,
// no exception can be authorized meanwhile, and recovery duplicates nothing.
func TestBindingKeepsAppliedOwnershipOnContentFailure(t *testing.T) {
	p := profileObj(t, "baseline", pol)
	p.Spec.Policies[0].Exceptions = v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: time.Hour}}
	e := newEnv(t, nsObj("prod"), p, bindingObj("all", "baseline", v1alpha1.ModeAudit, nil))
	sc := &switchContent{inner: content}
	e.r.Content = sc
	e.reconcile("all")
	e.markAllReady()
	e.reconcile("all")
	applied := appliedNames(e)
	revision := e.binding("all").Status.ConfigurationRevision
	if len(applied) != 1 || revision == "" {
		t.Fatalf("applied %v %q", applied, revision)
	}
	ns := nsObj("prod")
	resolver := &exception.ClusterResolver{Reader: e.c, Content: sc, Cluster: e.r.Cluster}
	eligibility := func() v1alpha1.ExceptionEligibility {
		t.Helper()
		res, err := resolver.Resolve(context.Background(), targeting.NamespaceRef{Name: ns.Name, UID: ns.UID}, pol)
		if err != nil {
			t.Fatal(err)
		}
		if res.Eligibility == nil {
			return ""
		}
		return res.Eligibility.Effective
	}
	if got := eligibility(); got != v1alpha1.ExceptionsSelfService {
		t.Fatalf("resolved eligibility %q", got)
	}

	expectRetained := func(step string, b *v1alpha1.ComplianceBinding) {
		t.Helper()
		requireObserved(t, b)
		if c := cond(b, v1alpha1.ConditionResolved); c.Status != metav1.ConditionFalse || c.Reason != v1alpha1.ReasonContentUnavailable ||
			!strings.Contains(c.Message, "(Untrusted)") {
			t.Fatalf("%s: Resolved %+v", step, c)
		}
		requireNotCurrent(t, b, v1alpha1.ReasonStaleRevision)
		if c := cond(b, v1alpha1.ConditionEngineReady); !strings.Contains(c.Message, "last applied policies kept") {
			t.Fatalf("%s: EngineReady %+v", step, c)
		}
		if got := appliedNames(e); !slices.Equal(got, applied) {
			t.Fatalf("%s: applied policies changed: %v -> %v", step, applied, got)
		}
		if got := eligibility(); got != v1alpha1.ExceptionsForbidden {
			t.Fatalf("%s: exceptions are %q while content is untrusted", step, got)
		}
	}

	// Trust revocation: the same profile's content becomes untrusted.
	sc.set(classErr(targeting.ContentErrorUntrusted, "signature no longer trusted"))
	if res := e.reconcile("all"); res.RequeueAfter != UntrustedContentRequeue {
		t.Fatalf("requeue %+v", res)
	}
	expectRetained("revocation", e.binding("all"))
	// Even if the applied policy disappears meanwhile, rejected content is
	// never reapplied.
	saved := e.policies()[0]
	if err := e.c.Delete(context.Background(), &saved); err != nil {
		t.Fatal(err)
	}
	e.reconcile("all")
	if len(e.policies()) != 0 {
		t.Fatal("untrusted content was reapplied")
	}
	saved.SetResourceVersion("")
	if err := e.c.Create(context.Background(), &saved); err != nil {
		t.Fatal(err)
	}
	applied = appliedNames(e)

	// Failed update: a profile edit that would create a new revision, while
	// the content is untrusted. Nothing of the new revision is installed.
	_ = e.c.Get(context.Background(), client.ObjectKeyFromObject(p), p)
	p.Spec.Policies[0].Exceptions.MaxLifetime = &metav1.Duration{Duration: 2 * time.Hour}
	p.Generation++
	if err := e.c.Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	e.reconcile("all")
	b := e.binding("all")
	expectRetained("failed update", b)
	if b.Status.Profile == nil || b.Status.Profile.Generation != p.Generation {
		t.Fatalf("status must report the desired profile generation: %+v", b.Status.Profile)
	}

	// Recovery: the new revision is delivered alongside, the old retired
	// once ready; never duplicated.
	sc.set(nil)
	e.reconcile("all")
	e.markAllReady()
	if res := e.reconcile("all"); res.RequeueAfter != 0 {
		t.Fatalf("recovered binding requeued: %+v", res)
	}
	b = e.binding("all")
	requireObserved(t, b)
	if c := cond(b, v1alpha1.ConditionResolved); c.Status != metav1.ConditionTrue {
		t.Fatalf("recovery Resolved %+v", c)
	}
	if c := cond(b, v1alpha1.ConditionEngineReady); c.Status != metav1.ConditionTrue {
		t.Fatalf("recovery EngineReady %+v", c)
	}
	if got := e.policies(); len(got) != 1 || got[0].GetAnnotations()[targeting.AnnotationRevision] != b.Status.ConfigurationRevision || b.Status.ConfigurationRevision == revision {
		t.Fatalf("after recovery %v (revision %q, was %q)", got, b.Status.ConfigurationRevision, revision)
	}
	e.reconcile("all")
	if len(e.policies()) != 1 {
		t.Fatal("recovery duplicated policies")
	}
	if got := eligibility(); got != v1alpha1.ExceptionsSelfService {
		t.Fatalf("eligibility after recovery %q", got)
	}
}

// Content that resolved for the snapshot but not when it is read for
// rendering (trust revoked in between) is ContentUnavailable, holds what is
// applied and renders nothing new.
func TestBindingContentRevokedBetweenResolveAndRender(t *testing.T) {
	p := profileObj(t, "baseline", pol)
	e := newEnv(t, nsObj("prod"), p, bindingObj("all", "baseline", v1alpha1.ModeAudit, nil))
	sc := &switchContent{inner: content}
	e.r.Content = sc
	e.reconcile("all")
	e.markAllReady()
	e.reconcile("all")
	applied := appliedNames(e)

	_ = e.c.Get(context.Background(), client.ObjectKeyFromObject(p), p)
	p.Spec.Policies[0].Exceptions = v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: time.Hour}}
	p.Generation++
	if err := e.c.Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	sc.mu.Lock()
	sc.err, sc.failAt, sc.calls = classErr(targeting.ContentErrorUntrusted, "revoked during reconcile"), 2, 0
	sc.mu.Unlock()
	if res := e.reconcile("all"); res.RequeueAfter != UntrustedContentRequeue {
		t.Fatalf("requeue %+v", res)
	}
	b := e.binding("all")
	if c := cond(b, v1alpha1.ConditionResolved); c.Status != metav1.ConditionFalse || c.Reason != v1alpha1.ReasonContentUnavailable || !strings.Contains(c.Message, "revoked during reconcile") {
		t.Fatalf("Resolved %+v", c)
	}
	requireNotCurrent(t, b, v1alpha1.ReasonStaleRevision)
	if got := appliedNames(e); !slices.Equal(got, applied) {
		t.Fatalf("applied changed: %v -> %v", applied, got)
	}
}

// failOnceList fails the first List of engine policies, as a transient API
// error would.
type failOnceList struct {
	client.Reader
	mu     sync.Mutex
	failed bool
}

func (f *failOnceList) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*unstructured.UnstructuredList); ok {
		f.mu.Lock()
		first := !f.failed
		f.failed = true
		f.mu.Unlock()
		if first {
			return errors.New("transient list failure")
		}
	}
	return f.Reader.List(ctx, list, opts...)
}

// If what a binding owns cannot be listed while its content does not
// resolve, the reconcile fails instead of holding nothing: holding nothing
// would let delivery delete the applied policies.
func TestBindingHoldsAppliedWhenOwnedListFails(t *testing.T) {
	e := newEnv(t, nsObj("prod"), profileObj(t, "baseline", pol), bindingObj("all", "baseline", v1alpha1.ModeAudit, nil))
	sc := &switchContent{inner: content}
	e.r.Content = sc
	e.reconcile("all")
	e.markAllReady()
	e.reconcile("all")
	applied := appliedNames(e)

	sc.set(classErr(targeting.ContentErrorUntrusted, "revoked"))
	e.r.Reader = &failOnceList{Reader: e.c}
	if _, err := bindingResult(t, e, "all"); err == nil {
		t.Fatal("a failed list of owned policies was ignored")
	}
	if got := appliedNames(e); !slices.Equal(got, applied) {
		t.Fatalf("applied policies removed: %v -> %v", applied, got)
	}
	e.reconcile("all") // the retry lists successfully and keeps them
	if got := appliedNames(e); !slices.Equal(got, applied) {
		t.Fatalf("applied policies removed on retry: %v -> %v", applied, got)
	}
}

// Parameters of content that declares a parameter contract are rejected with
// a precise message; content without one (LocalContent) is unchanged.
func TestParameterValidationHook(t *testing.T) {
	schema := []byte(`{"type":"object","properties":{"limit":{"type":"integer"}},"additionalProperties":false}`)
	cases := []struct {
		name      string
		params    string
		schema    []byte
		validated bool
		profile   string // substring of the profile message; "" means Resolved=True
		binding   string // substring of the binding message
	}{
		{name: "unknown property", params: `{"other":1}`, schema: schema, validated: true, profile: "additional", binding: "additional"},
		{name: "wrong type", params: `{"limit":"x"}`, schema: schema, validated: true, profile: "limit", binding: "limit"},
		{name: "schemaless policy", params: `{"limit":1}`, validated: true, profile: "declares no parameters", binding: "declares no parameters"},
		{name: "valid but not rendered", params: `{"limit":1}`, schema: schema, validated: true, profile: "not rendered", binding: "not rendered"},
		{name: "local content", params: `{"limit":1}`, schema: schema, binding: `does not accept parameters`},
		{name: "empty object", params: `{}`, schema: schema, validated: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := profileObj(t, "baseline", pol)
			p.Spec.Policies[0].Parameters = &apiextensionsv1.JSON{Raw: []byte(tc.params)}
			e := newEnv(t, nsObj("prod"), p, bindingObj("all", "baseline", v1alpha1.ModeAudit, nil))
			sc := &switchContent{inner: content, edit: func(c *targeting.Content) {
				src := c.Policies[pol]
				src.ParametersValidated, src.ParameterSchema = tc.validated, tc.schema
				c.Policies[pol] = src
			}}
			e.r.Content, e.r.ValidateParameters = sc, bundlecontent.ValidateParameters
			pr := &ProfileReconciler{Client: e.c, Content: sc, ValidateParameters: bundlecontent.ValidateParameters}
			reconcileProfile(t, pr, "baseline")
			pc, _ := e.profileCond("baseline")
			if tc.profile == "" {
				if pc.Status != metav1.ConditionTrue {
					t.Fatalf("profile %+v", pc)
				}
			} else if pc.Status != metav1.ConditionFalse || pc.Reason != v1alpha1.ReasonInvalidConfiguration || !strings.Contains(pc.Message, tc.profile) {
				t.Fatalf("profile %+v, want %q", pc, tc.profile)
			}
			e.reconcile("all")
			bc := cond(e.binding("all"), v1alpha1.ConditionResolved)
			if tc.binding == "" {
				if bc.Status != metav1.ConditionTrue {
					t.Fatalf("binding %+v", bc)
				}
				return
			}
			if bc.Status != metav1.ConditionFalse || bc.Reason != v1alpha1.ReasonInvalidConfiguration || !strings.Contains(bc.Message, tc.binding) {
				t.Fatalf("binding %+v, want %q", bc, tc.binding)
			}
			if len(e.policies()) != 0 {
				t.Fatal("rejected parameters were applied")
			}
		})
	}
}
