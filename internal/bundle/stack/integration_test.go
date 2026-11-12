package stack_test

// Task 5.2: resolved OCI bundle content reaches the existing profile and
// binding reconcilers (provider and contribution resolver) through the
// controller's Router, and every content-level rejection, engine outage and
// recovery keeps the platform's governance. Nothing here installs a fixture
// resource anywhere: the cluster is a fake API server, and every write the
// reconcilers make is recorded and checked.
//
// Two content paths are used:
//
//   - the real, Cosign-signed official bundle through the real stack
//     (fetcher, verifier, cache, acceptances, Watcher, resolver, OCIContent,
//     Router), for everything that bundle can express;
//   - crafted bundles (shapes no signed fixture carries: another provider,
//     another OS, unsupported policy kinds and APIs, parameter schemas,
//     policy-looking test fixtures) stored in a real cache and served by the
//     real OCIContent and Router, with the production compatibility check
//     (content.Compatibility.Check) standing in only for signature and
//     provenance verification, which needs private keys the repository does
//     not hold.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/cache"
	bundlecontent "github.com/backend-bunny/Konstapel/internal/bundle/content"
	"github.com/backend-bunny/Konstapel/internal/bundle/internal/provfixture"
	"github.com/backend-bunny/Konstapel/internal/bundle/resolve"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/capability"
	"github.com/backend-bunny/Konstapel/internal/controller"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// --- write recording --------------------------------------------------------

// writeLog records the reconcilers' writes as "verb Kind" (status writes
// as "status Kind").
type writeLog struct {
	mu      sync.Mutex
	entries []string
}

func (l *writeLog) add(verb string, obj client.Object) {
	gvk := obj.GetObjectKind().GroupVersionKind()
	if gvk.Kind == "" {
		gvk, _ = apiutil.GVKForObject(obj, controller.Scheme())
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, verb+" "+gvk.Kind)
}

// take returns and clears the recorded writes.
func (l *writeLog) take() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.entries
	l.entries = nil
	return out
}

func (l *writeLog) client(c client.WithWatch) client.WithWatch {
	return interceptor.NewClient(c, interceptor.Funcs{
		Create: func(ctx context.Context, cw client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			l.add("create", obj)
			return cw.Create(ctx, obj, opts...)
		},
		Update: func(ctx context.Context, cw client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			l.add("update", obj)
			return cw.Update(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, cw client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			l.add("patch", obj)
			return cw.Patch(ctx, obj, patch, opts...)
		},
		Delete: func(ctx context.Context, cw client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			l.add("delete", obj)
			return cw.Delete(ctx, obj, opts...)
		},
		DeleteAllOf: func(ctx context.Context, cw client.WithWatch, obj client.Object, opts ...client.DeleteAllOfOption) error {
			l.add("deleteall", obj)
			return cw.DeleteAllOf(ctx, obj, opts...)
		},
		SubResourceCreate: func(ctx context.Context, cw client.Client, sub string, obj, subObj client.Object, opts ...client.SubResourceCreateOption) error {
			l.add(sub+"-create", obj)
			return cw.SubResource(sub).Create(ctx, obj, subObj, opts...)
		},
		SubResourceUpdate: func(ctx context.Context, cw client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			l.add(sub, obj)
			return cw.SubResource(sub).Update(ctx, obj, opts...)
		},
		SubResourcePatch: func(ctx context.Context, cw client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			l.add(sub, obj)
			return cw.SubResource(sub).Patch(ctx, obj, patch, opts...)
		},
	})
}

// requireOnlyStatusWrites fails unless every write is a status write.
func requireOnlyStatusWrites(t *testing.T, writes []string, what string) {
	t.Helper()
	for _, w := range writes {
		if !strings.HasPrefix(w, "status ") {
			t.Fatalf("%s: wrote %v; only status writes are allowed", what, writes)
		}
	}
}

// requireOnlyPolicyAndStatusWrites fails on any write other than a status
// write or a ValidatingPolicy create: content never installs anything else
// (no fixture Pod, PolicyException, RBAC, legacy ClusterPolicy).
func requireOnlyPolicyAndStatusWrites(t *testing.T, writes []string) {
	t.Helper()
	for _, w := range writes {
		if !strings.HasPrefix(w, "status ") && w != "create "+targeting.ValidatingPolicyGVK.Kind {
			t.Fatalf("wrote %v; content may only create ValidatingPolicies", writes)
		}
	}
}

// --- cluster state ----------------------------------------------------------

type snapshot struct {
	profileRV, bindingRV string
	policies             map[string]string // name -> resourceVersion
	owners               map[string]string // name -> owner reference UIDs
}

func (cl *cluster) snapshot() snapshot {
	cl.t.Helper()
	p := &v1alpha1.ComplianceProfile{}
	b := &v1alpha1.ComplianceBinding{}
	if err := cl.c.Get(context.Background(), client.ObjectKey{Name: "org"}, p); err != nil {
		cl.t.Fatal(err)
	}
	if err := cl.c.Get(context.Background(), client.ObjectKey{Name: "org"}, b); err != nil {
		cl.t.Fatal(err)
	}
	s := snapshot{profileRV: p.ResourceVersion, bindingRV: b.ResourceVersion, policies: map[string]string{}, owners: map[string]string{}}
	for _, o := range cl.policies() {
		s.policies[o.GetName()] = o.GetResourceVersion()
		var uids []string
		for _, r := range o.GetOwnerReferences() {
			uids = append(uids, string(r.UID))
		}
		s.owners[o.GetName()] = strings.Join(uids, ",")
	}
	return s
}

func (cl *cluster) bindingStatus() v1alpha1.ComplianceBindingStatus {
	cl.t.Helper()
	b := &v1alpha1.ComplianceBinding{}
	if err := cl.c.Get(context.Background(), client.ObjectKey{Name: "org"}, b); err != nil {
		cl.t.Fatal(err)
	}
	return b.Status
}

// editProfile replaces the profile's policies as a new generation.
func (cl *cluster) editProfile(policies ...v1alpha1.ProfilePolicy) {
	cl.t.Helper()
	p := &v1alpha1.ComplianceProfile{}
	if err := cl.c.Get(context.Background(), client.ObjectKey{Name: "org"}, p); err != nil {
		cl.t.Fatal(err)
	}
	p.Spec.Policies = policies
	p.Generation++
	if err := cl.c.Update(context.Background(), p); err != nil {
		cl.t.Fatal(err)
	}
}

// applyOnce reconciles to the applied, ready state and returns it.
func (cl *cluster) applyOnce() snapshot {
	cl.t.Helper()
	cl.reconcile()
	p, r, e := cl.conditions()
	if p.Status != metav1.ConditionTrue || r.Status != metav1.ConditionTrue || e.Status != metav1.ConditionTrue {
		cl.t.Fatalf("not applied: profile %+v, resolved %+v, engine %+v", p, r, e)
	}
	s := cl.snapshot()
	if len(s.policies) != 1 {
		cl.t.Fatalf("applied %v", s.policies)
	}
	cl.writes.take()
	return s
}

// requirePreserved checks that the applied policies are exactly as before
// (same names, resource versions and owners) and that a second reconcile
// in the same state writes nothing at all: no status or ownership churn.
func (cl *cluster) requirePreserved(before snapshot, what string) {
	cl.t.Helper()
	after := cl.snapshot()
	if !mapsEqual(after.policies, before.policies) || !mapsEqual(after.owners, before.owners) {
		cl.t.Fatalf("%s changed the applied policies: %v (owners %v), was %v (owners %v)", what, after.policies, after.owners, before.policies, before.owners)
	}
	cl.writes.take()
	cl.reconcile()
	if w := cl.writes.take(); len(w) != 0 {
		cl.t.Fatalf("%s: a repeated reconcile wrote %v", what, w)
	}
	if again := cl.snapshot(); again.profileRV != after.profileRV || again.bindingRV != after.bindingRV || !mapsEqual(again.policies, after.policies) {
		cl.t.Fatalf("%s: a repeated reconcile changed status or policies", what)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// --- signed content through the real stack ---------------------------------

// Unknown policy names in a profile pinning a verified OCI bundle: the
// profile and binding report UnknownPolicy, nothing is applied for an
// initial profile, and an edit naming an unknown policy keeps what is
// applied without churn. A name that only exists as an upstream test
// fixture inside the signed bundle (an upstream test policy, a Pod, a
// PolicyException) is unknown too.
func TestOCIUnknownPolicies(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"no-such-policy", "disallow-privileged-containers-controllers", "badpod01", "whole"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := stack.NewWorld(t)
			cl := newClusterOver(t, w, w.Stack.Router(stack.LocalContent(), stack.VendoredName), w.Ref(), []v1alpha1.ProfilePolicy{{Name: name}})
			cl.reconcile()
			p, r, _ := cl.conditions()
			if p.Reason != v1alpha1.ReasonUnknownPolicy || r.Reason != v1alpha1.ReasonUnknownPolicy || !strings.Contains(p.Message, name) {
				t.Fatalf("profile %+v, resolved %+v", p, r)
			}
			if got := cl.policies(); len(got) != 0 {
				t.Fatalf("applied %v for an unknown policy", got)
			}
			requireOnlyStatusWrites(t, cl.writes.take(), "unknown policy")
		})
	}

	// Per-policy semantics, as for vendored content: an edit adding an
	// unknown name reports it, the known policy moves to the new profile
	// generation through the normal revision (create, then retire), and
	// nothing else is written.
	t.Run("edit reports per policy", func(t *testing.T) {
		cl := newCluster(t)
		before := cl.applyOnce()
		cl.editProfile(v1alpha1.ProfilePolicy{Name: cl.policy}, v1alpha1.ProfilePolicy{Name: "no-such-policy"})
		cl.reconcile()
		p, r, _ := cl.conditions()
		if p.Reason != v1alpha1.ReasonUnknownPolicy || r.Reason != v1alpha1.ReasonUnknownPolicy || !strings.Contains(r.Message, "no-such-policy") {
			t.Fatalf("profile %+v, resolved %+v", p, r)
		}
		for _, w := range cl.writes.take() {
			if !strings.HasPrefix(w, "status ") && w != "create ValidatingPolicy" && w != "delete ValidatingPolicy" {
				t.Fatalf("wrote %s", w)
			}
		}
		got := cl.policies()
		if len(got) != 1 || got[0].GetAnnotations()[targeting.AnnotationPolicy] != cl.policy || got[0].GetAnnotations()[targeting.AnnotationProfileGen] != "2" {
			t.Fatalf("applied %v", got)
		}
		if _, ok := before.policies[got[0].GetName()]; ok {
			t.Fatal("a new profile generation kept the old revision's name")
		}
		cl.requirePreserved(cl.snapshot(), "a reported unknown policy")
	})
}

// Parameters for an OCI policy that declares no parameter contract are
// rejected with the contract's reason (content.ValidateParameters through
// the reconcilers' ValidateParameters hook), never rendered, and keep what
// is applied.
func TestOCIInvalidParameters(t *testing.T) {
	t.Parallel()
	cl := newCluster(t)
	before := cl.applyOnce()
	cl.editProfile(v1alpha1.ProfilePolicy{Name: cl.policy, Parameters: &apiextensionsv1.JSON{Raw: []byte(`{"allowPrivileged":true}`)}})
	cl.reconcile()
	p, r, _ := cl.conditions()
	if p.Reason != v1alpha1.ReasonInvalidConfiguration || r.Reason != v1alpha1.ReasonInvalidConfiguration {
		t.Fatalf("profile %+v, resolved %+v", p, r)
	}
	want := bundle.ValidatePolicyParameters(cl.policy, nil, []byte(`{"allowPrivileged":true}`))
	if want == nil {
		t.Fatal("the bundle contract accepts parameters for a schemaless policy")
	}
	for _, c := range []metav1.Condition{p, r} {
		if !strings.Contains(c.Message, "accepts no parameters") && !strings.Contains(c.Message, want.Error()) {
			t.Fatalf("message %q does not carry the contract's reason %q", c.Message, want)
		}
	}
	requireOnlyStatusWrites(t, cl.writes.take(), "invalid parameters")
	cl.requirePreserved(before, "invalid parameters")
}

// The installed provider allowlist is enforced on verified OCI content:
// after a restart whose allowlist no longer contains the bundle's provider
// contract, the same pinned, signed bundle is Incompatible, never adopted,
// and what is applied stays; vendored content keeps reconciling; restoring
// the allowlist recovers without a refetch or duplicates.
func TestOCIProviderAllowlist(t *testing.T) {
	t.Parallel()
	cl := newCluster(t)
	before := cl.applyOnce()

	base := cl.w.Deps
	cl.w.Deps = stack.WithTestProviders(base, "other-provider/v1")
	cl.w.Restart()
	cl.setRouter(cl.w.Stack.Router(stack.LocalContent(), stack.VendoredName))
	cl.reconcile()
	p, r, e := cl.conditions()
	for _, c := range []metav1.Condition{p, r} {
		if c.Reason != v1alpha1.ReasonContentUnavailable || !strings.Contains(c.Message, string(targeting.ContentErrorIncompatible)) ||
			!strings.Contains(c.Message, fmt.Sprintf("provider contract %q is not installed", bundlecontent.DefaultProvider)) {
			t.Fatalf("condition %+v", c)
		}
	}
	if e.Status != metav1.ConditionFalse {
		t.Fatalf("engine %+v", e)
	}
	requireOnlyStatusWrites(t, cl.writes.take(), "provider not allowlisted")
	cl.requirePreserved(before, "a provider allowlist change")
	if err := cl.router.Confirm(context.Background(), cl.w.Ref()); err == nil {
		t.Fatal("confirmed content whose provider is not installed")
	}

	// The controller still reconciles supported (vendored) configuration.
	requireVendoredStillServed(t, cl)

	// Restored allowlist: the same cached, verified content recovers, offline.
	cl.w.Fetch.Down.Store(true)
	calls := cl.w.Fetch.Calls.Load()
	cl.w.Deps = base
	cl.w.Restart()
	cl.setRouter(cl.w.Stack.Router(stack.LocalContent(), stack.VendoredName))
	cl.reconcile()
	p, r, e = cl.conditions()
	if p.Status != metav1.ConditionTrue || r.Status != metav1.ConditionTrue || e.Status != metav1.ConditionTrue {
		t.Fatalf("recovered: profile %+v, resolved %+v, engine %+v", p, r, e)
	}
	if got := cl.snapshot(); !mapsEqual(got.policies, before.policies) {
		t.Fatalf("recovery changed the applied policies: %v, was %v", got.policies, before.policies)
	}
	if cl.w.Fetch.Calls.Load() != calls {
		t.Fatal("recovery fetched the bundle again")
	}
}

// requireVendoredStillServed checks that a profile and binding using the
// vendored bundle resolve and apply in the same cluster and controller.
func requireVendoredStillServed(t *testing.T, cl *cluster) {
	t.Helper()
	sums, err := os.ReadFile(filepath.Join(stack.RepoRoot, "content", "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(sums)
	ref := v1alpha1.BundleReference{Name: stack.VendoredName, Digest: "sha256:" + hex.EncodeToString(sum[:])}
	ctx := context.Background()
	for _, o := range []client.Object{
		&v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "vendored", UID: "uid-vendored", Generation: 1},
			Spec: v1alpha1.ComplianceProfileSpec{Bundle: ref, Policies: []v1alpha1.ProfilePolicy{{Name: assessment.PolicyName}}}},
		&v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "vendored", UID: "uid-vendored-binding", Generation: 1},
			Spec: v1alpha1.ComplianceBindingSpec{ProfileRef: v1alpha1.ProfileReference{Name: "vendored"}, Mode: v1alpha1.ModeAudit,
				NamespaceSelector: &v1alpha1.NamespaceSelector{MatchLabels: map[string]v1alpha1.LabelValue{"team": "a"}}}},
	} {
		if err := cl.c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	req := reqFor("vendored")
	if _, err := cl.profile.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.binding.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	b := &v1alpha1.ComplianceBinding{}
	if err := cl.c.Get(ctx, client.ObjectKey{Name: "vendored"}, b); err != nil {
		t.Fatal(err)
	}
	for _, c := range b.Status.Conditions {
		if (c.Type == v1alpha1.ConditionResolved || c.Type == v1alpha1.ConditionEngineReady) && c.Status != metav1.ConditionTrue {
			t.Fatalf("vendored binding %+v", c)
		}
	}
	n := 0
	for _, o := range cl.policies() {
		if o.GetAnnotations()[targeting.AnnotationBundle] == stack.VendoredName {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d vendored policies applied", n)
	}
	requireOnlyPolicyAndStatusWrites(t, cl.writes.take())
	// Clean up so the caller's "org" checks are unaffected.
	for _, o := range cl.policies() {
		if o.GetAnnotations()[targeting.AnnotationBundle] == stack.VendoredName {
			if err := cl.c.Delete(ctx, &o); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, o := range []client.Object{&v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "vendored"}}, &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "vendored"}}} {
		if err := cl.c.Delete(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
}

// A missing engine API (the ValidatingPolicy CRD not served, or another
// capability failure): verified OCI content still resolves, nothing is
// written, the binding reports the engine reason and keeps retrying; when
// the engine becomes available the same pinned content is delivered with
// no manual action and no refetch, even with the registry down. An engine
// that disappears after delivery leaves the applied policies alone.
func TestOCIEngineRecovery(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		available bool
		err       error
		reason    string
	}{
		"api not served":    {false, &capability.Error{Result: capability.Result{Reason: capability.APINotServed, Message: "policies.kyverno.io/v1 is not served"}}, controller.ReasonEngineAPINotServed},
		"resource missing":  {false, &capability.Error{Result: capability.Result{Reason: capability.ResourceMissing, Message: "validatingpolicies is missing"}}, controller.ReasonEngineResourceMissing},
		"engine not served": {false, nil, controller.ReasonEngineUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cl := newCluster(t)
			cl.engine.Store(&engineState{available: tc.available, err: tc.err})
			res := cl.reconcile()
			p, r, e := cl.conditions()
			if p.Status != metav1.ConditionTrue || r.Status != metav1.ConditionTrue {
				t.Fatalf("content must resolve without the engine: profile %+v, resolved %+v", p, r)
			}
			if e.Status != metav1.ConditionFalse || e.Reason != tc.reason {
				t.Fatalf("engine %+v, want %s", e, tc.reason)
			}
			if res.RequeueAfter == 0 {
				t.Fatal("a missing engine must be retried")
			}
			if got := cl.policies(); len(got) != 0 {
				t.Fatalf("applied %v without the engine", got)
			}
			requireOnlyStatusWrites(t, cl.writes.take(), "engine missing")

			// The engine arrives; the registry is gone. The retry delivers
			// the same pinned content without a refetch.
			cl.w.Fetch.Down.Store(true)
			calls := cl.w.Fetch.Calls.Load()
			cl.engine.Store(nil)
			before := cl.applyOnce()
			if cl.w.Fetch.Calls.Load() != calls {
				t.Fatal("engine recovery fetched the bundle again")
			}
			for _, o := range cl.policies() {
				if o.GetAnnotations()[targeting.AnnotationBundleDigest] != cl.w.Fix.Subject {
					t.Fatalf("delivered %s", o.GetAnnotations()[targeting.AnnotationBundleDigest])
				}
			}

			// The engine goes away again: applied policies stay, untouched.
			cl.engine.Store(&engineState{available: tc.available, err: tc.err})
			cl.reconcile()
			if _, _, e := cl.conditions(); e.Reason != tc.reason {
				t.Fatalf("engine %+v", e)
			}
			requireOnlyStatusWrites(t, cl.writes.take(), "engine lost")
			cl.requirePreserved(before, "an engine outage")
		})
	}
}

// Governance of applied OCI content: every way the pinned content becomes
// unusable after delivery (trust revoked, source removed, cache lost with
// the registry down, controller too old after a restart) reports
// ContentUnavailable on the profile and binding, keeps the applied policy
// with its name, resource version and owners, makes no status or ownership
// churn on repeated reconciles, and recovers to the same policy.
func TestOCIGovernancePreserved(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		break_, fix func(cl *cluster)
		// retry: the class is retried on a timer; the others are
		// re-triggered by the configuration or trust change that fixes them.
		retry bool
	}{
		"trust revoked": {
			retry:  true,
			break_: func(cl *cluster) { cl.w.SetSources(cl.w.OtherSource()); cl.w.Sync() },
			fix:    func(cl *cluster) { cl.w.SetSources(cl.w.OrgSource()); cl.w.Sync() },
		},
		"source removed": {
			break_: func(cl *cluster) { cl.w.SetSources(); cl.w.Sync() },
			fix:    func(cl *cluster) { cl.w.SetSources(cl.w.OrgSource()); cl.w.Sync() },
		},
		"cache lost, registry down": {
			retry: true,
			break_: func(cl *cluster) {
				cl.w.Fetch.Down.Store(true)
				if err := cl.w.Stack.Close(); err != nil {
					cl.t.Fatal(err)
				}
				if err := os.RemoveAll(cl.w.Opts.CacheDir); err != nil {
					cl.t.Fatal(err)
				}
				cl.w.Open()
				cl.setRouter(cl.w.Stack.Router(stack.LocalContent(), stack.VendoredName))
			},
			fix: func(cl *cluster) { cl.w.Fetch.Down.Store(false) },
		},
		"controller too old": {
			break_: func(cl *cluster) {
				cl.w.Opts.ControllerVersion = "0.0.9"
				cl.w.Restart()
				cl.setRouter(cl.w.Stack.Router(stack.LocalContent(), stack.VendoredName))
			},
			fix: func(cl *cluster) {
				cl.w.Opts.ControllerVersion = "0.1.0"
				cl.w.Restart()
				cl.setRouter(cl.w.Stack.Router(stack.LocalContent(), stack.VendoredName))
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cl := newCluster(t)
			before := cl.applyOnce()
			status := cl.bindingStatus()

			tc.break_(cl)
			res := cl.reconcile()
			p, r, e := cl.conditions()
			if p.Reason != v1alpha1.ReasonContentUnavailable || r.Reason != v1alpha1.ReasonContentUnavailable || e.Status != metav1.ConditionFalse {
				t.Fatalf("profile %+v, resolved %+v, engine %+v", p, r, e)
			}
			if tc.retry && res.RequeueAfter == 0 {
				t.Fatal("unavailable content must be retried")
			}
			requireOnlyStatusWrites(t, cl.writes.take(), name)
			cl.requirePreserved(before, name)
			// The applied revision stays identifiable: the binding reports
			// it stale by name, and the kept policy carries the revision
			// the binding last reported as current.
			if e.Reason != v1alpha1.ReasonStaleRevision {
				t.Fatalf("engine %+v, want %s", e, v1alpha1.ReasonStaleRevision)
			}
			for n := range before.policies {
				if !strings.Contains(e.Message, n) {
					t.Fatalf("engine message %q does not name the kept policy %s", e.Message, n)
				}
			}
			for _, o := range cl.policies() {
				if o.GetAnnotations()[targeting.AnnotationRevision] != status.ConfigurationRevision {
					t.Fatalf("kept policy revision %s, last current %s", o.GetAnnotations()[targeting.AnnotationRevision], status.ConfigurationRevision)
				}
			}
			if got := cl.bindingStatus(); got.Profile == nil || got.Profile.BundleDigest != status.Profile.BundleDigest {
				t.Fatalf("status lost the pinned digest: %+v", got.Profile)
			}

			tc.fix(cl)
			cl.reconcile()
			p, r, e = cl.conditions()
			if p.Status != metav1.ConditionTrue || r.Status != metav1.ConditionTrue || e.Status != metav1.ConditionTrue {
				t.Fatalf("recovered: profile %+v, resolved %+v, engine %+v", p, r, e)
			}
			requireOnlyStatusWrites(t, cl.writes.take(), name+" recovery")
			if got := cl.snapshot(); !mapsEqual(got.policies, before.policies) || !mapsEqual(got.owners, before.owners) {
				t.Fatalf("recovery replaced the applied policy: %v, was %v", got.policies, before.policies)
			}
		})
	}
}

func reqFor(name string) ctrl.Request {
	return ctrl.Request{NamespacedName: client.ObjectKey{Name: name}}
}

// --- crafted content: shapes the signed fixtures cannot carry ---------------

// craftedResolver serves bundles stored in a real cache under real leases,
// judging each with the production compatibility check exactly as the
// resolver does; only signature and provenance verification is skipped.
type craftedResolver struct {
	c      *cache.Cache
	compat bundlecontent.Compatibility
}

func (r *craftedResolver) judge(ctx context.Context, name, digest string) error {
	e, err := r.c.Get(ctx, digest)
	if err != nil {
		return fmt.Errorf("%w: %w", resolve.ErrContentUnavailable, err)
	}
	if e.Descriptor.Name != name {
		return fmt.Errorf("%w: %s is %s", resolve.ErrConfig, digest, e.Descriptor.Name)
	}
	// As resolve.Resolver reports an incompatible verdict.
	if v := r.compat.Check(e.Descriptor); !v.Compatible {
		return fmt.Errorf("%w: %s@%s: %v", resolve.ErrIncompatible, e.Descriptor.Name, e.Descriptor.Version, v.Reasons)
	}
	return nil
}

func (r *craftedResolver) Resolve(ctx context.Context, req resolve.Request) (bundle.ResolvedContent, error) {
	if err := r.judge(ctx, req.Name, req.Digest); err != nil {
		return bundle.ResolvedContent{}, err
	}
	l, err := r.c.Acquire(req.Digest, req.Holder, req.Owner)
	if err != nil {
		return bundle.ResolvedContent{}, fmt.Errorf("%w: %w", resolve.ErrContentUnavailable, err)
	}
	return bundle.ResolvedContent{Name: req.Name, Digests: bundle.Digests{OCI: req.Digest}, Lease: l}, nil
}

func (r *craftedResolver) Release(h bundle.ResolvedContent) error { return r.c.Release(h.Lease) }

// crafted is a bundle around the official policy file (real path and
// bytes) with extra policies and files and descriptor edits.
type crafted struct {
	version  string
	provider string
	os       []string
	policies []bundle.Policy
	files    map[string]string // archive path -> body
	roles    map[string]string // archive path -> role
}

func buildCrafted(t *testing.T, c crafted) *bundle.Archive {
	t.Helper()
	official, err := os.ReadFile(filepath.Join(stack.RepoRoot, assessment.SourcePolicy))
	if err != nil {
		t.Fatal(err)
	}
	src := fstest.MapFS{
		"policy.yaml": {Data: official},
		"cd.json":     {Data: []byte(`{"component-definition":{}}`)},
		"prov.json":   {Data: []byte(`{}`)},
		"LICENSE":     {Data: []byte("license\n")},
	}
	provider := c.provider
	if provider == "" {
		provider = bundlecontent.DefaultProvider
	}
	osList := c.os
	if osList == nil {
		osList = []string{"linux"}
	}
	def := bundle.Definition{
		Name: provfixture.Name, Version: c.version,
		Source:        bundle.Source{Repository: provfixture.SourceRepository, Revision: strings.Repeat("c", 40)},
		Policies:      append([]bundle.Policy{craftedPolicy(assessment.PolicyName, assessment.SourcePolicy, "")}, c.policies...),
		Scope:         bundle.Scope{Workloads: []string{"Pod"}, OS: osList},
		Compatibility: bundle.Compatibility{Provider: provider, Konstapel: "0.1.0"},
		OSCAL:         []bundle.OSCALDocument{{Path: "content/component-definition.json", Version: "1.1.3"}},
		Include: []bundle.Include{
			{From: "policy.yaml", To: assessment.SourcePolicy, Role: bundle.RolePolicy},
			{From: "cd.json", To: "content/component-definition.json", Role: bundle.RoleComponentDefinition},
			{From: "prov.json", To: "content/provenance.json", Role: bundle.RoleProvenance},
			{Generate: bundle.GenerateSHA256Sums, To: "content/SHA256SUMS", Role: bundle.RoleChecksums},
			{From: "LICENSE", To: "LICENSE", Role: bundle.RoleLicense},
		},
	}
	for _, to := range slices.Sorted(func(yield func(string) bool) {
		for k := range c.files {
			if !yield(k) {
				return
			}
		}
	}) {
		from := "crafted/" + to
		src[from] = &fstest.MapFile{Data: []byte(c.files[to])}
		def.Include = append(def.Include, bundle.Include{From: from, To: to, Role: c.roles[to]})
	}
	a, err := bundle.Build(def, src, time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func craftedPolicy(name, path, schema string) bundle.Policy {
	return bundle.Policy{Name: name, Path: path, ParameterSchema: schema, Checks: []bundle.Check{{RuleID: name, CheckID: name}}}
}

const craftedPolicyTemplate = `apiVersion: %s
kind: %s
metadata:
  name: %s
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: [%q]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: [%q]
  validations:
    - expression: "true"
`

func craftedPolicyYAML(apiVersion, kind, name, group, resource string) string {
	return fmt.Sprintf(craftedPolicyTemplate, apiVersion, kind, name, group, resource)
}

// newCraftedCluster stores the archive in a real cache (storage checks
// only) and wires the reconcilers to a Router over the real OCIContent.
func newCraftedCluster(t *testing.T, a *bundle.Archive, policies []v1alpha1.ProfilePolicy) *cluster {
	t.Helper()
	c, err := cache.Open(t.TempDir(), cache.Config{CheckContent: func(*bundle.Descriptor, string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err := c.Put(context.Background(), a.Manifest, a.Layer); err != nil {
		t.Fatal(err)
	}
	r := &craftedResolver{c: c, compat: bundlecontent.Compatibility{Controller: "0.1.0"}}
	oci, err := bundlecontent.New(bundlecontent.Config{Resolver: r, Entries: c})
	if err != nil {
		t.Fatal(err)
	}
	router := stack.NewTestRouter(stack.LocalContent(), stack.VendoredName, oci, func(name, digest string) error {
		if err := r.judge(context.Background(), name, digest); err != nil {
			return fmt.Errorf("%w: %w", resolve.ErrStale, err)
		}
		return nil
	})
	ref := v1alpha1.BundleReference{Name: a.Descriptor.Name, Digest: a.ManifestDigest}
	cl := newClusterOver(t, nil, router, ref, policies)
	t.Cleanup(func() {
		if n := c.Stats().Leases; n != 0 {
			t.Errorf("%d leases held after the test", n)
		}
	})
	return cl
}

// Content that claims an unsupported workload OS or names a provider
// contract Konstapel does not install is Incompatible: the profile and
// binding report it, nothing is adopted or installed, and the controller
// keeps reconciling supported (vendored) configuration.
func TestOCIUnsupportedRequirementsAreNotAdopted(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		c      crafted
		reason string
	}{
		"provider not allowlisted": {crafted{version: "0.5.0", provider: "evil-exec/v1"}, `provider contract "evil-exec/v1" is not installed`},
		"provider version":         {crafted{version: "0.5.1", provider: "konstapel-kyverno/v2"}, `provider contract "konstapel-kyverno/v2" is not installed`},
		"windows workloads":        {crafted{version: "0.5.2", os: []string{"windows"}}, "only linux workloads are supported"},
		"linux and windows":        {crafted{version: "0.5.3", os: []string{"linux", "windows"}}, "only linux workloads are supported"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cl := newCraftedCluster(t, buildCrafted(t, tc.c), []v1alpha1.ProfilePolicy{{Name: assessment.PolicyName}})
			cl.reconcile()
			p, r, e := cl.conditions()
			for _, c := range []metav1.Condition{p, r} {
				if c.Reason != v1alpha1.ReasonContentUnavailable || !strings.Contains(c.Message, string(targeting.ContentErrorIncompatible)) || !strings.Contains(c.Message, tc.reason) {
					t.Fatalf("condition %+v, want %q", c, tc.reason)
				}
			}
			if e.Status != metav1.ConditionFalse {
				t.Fatalf("engine %+v", e)
			}
			if got := cl.policies(); len(got) != 0 {
				t.Fatalf("adopted incompatible content: %v", got)
			}
			requireOnlyStatusWrites(t, cl.writes.take(), name)
			requireVendoredStillServed(t, cl)
		})
	}
}

// Per policy: cluster-scoped workload targeting, an API outside the
// standard namespaced workloads, and a non-ValidatingPolicy (legacy) kind
// are UnsupportedScope; files that are not named policy sources (upstream
// test fixtures that look like policies, a Pod, a PolicyException) are
// unknown policies and never installed. The supported policies of the same
// bundle still resolve and are the only resources created.
func TestOCIPolicyScopesAndFixtures(t *testing.T) {
	t.Parallel()
	a := buildCrafted(t, crafted{
		version: "0.6.0",
		policies: []bundle.Policy{
			craftedPolicy("cluster-scoped", "content/policies/cluster-scoped.yaml", ""),
			craftedPolicy("unknown-resource", "content/policies/unknown-resource.yaml", ""),
			craftedPolicy("not-validating", "content/policies/not-validating.yaml", ""),
			craftedPolicy("another-namespaced", "content/policies/another-namespaced.yaml", ""),
		},
		files: map[string]string{
			"content/policies/cluster-scoped.yaml":     craftedPolicyYAML("policies.kyverno.io/v1", "ValidatingPolicy", "cluster-scoped", "", "namespaces"),
			"content/policies/unknown-resource.yaml":   craftedPolicyYAML("policies.kyverno.io/v1", "ValidatingPolicy", "unknown-resource", "example.com", "widgets"),
			"content/policies/not-validating.yaml":     craftedPolicyYAML("kyverno.io/v1", "ClusterPolicy", "not-validating", "", "pods"),
			"content/policies/another-namespaced.yaml": craftedPolicyYAML("policies.kyverno.io/v1", "ValidatingPolicy", "another-namespaced", "apps", "deployments"),
			"tests/fixture-policy.yaml":                craftedPolicyYAML("policies.kyverno.io/v1", "ValidatingPolicy", "fixture-policy", "", "pods"),
			"tests/fixture-pod.yaml":                   "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\n",
			"tests/fixture-exception.yaml":             "apiVersion: policies.kyverno.io/v1\nkind: PolicyException\nmetadata:\n  name: allow-all\nspec: {}\n",
		},
		roles: map[string]string{
			"content/policies/cluster-scoped.yaml": bundle.RolePolicy, "content/policies/unknown-resource.yaml": bundle.RolePolicy,
			"content/policies/not-validating.yaml": bundle.RolePolicy, "content/policies/another-namespaced.yaml": bundle.RolePolicy,
			"tests/fixture-policy.yaml": bundle.RoleTest, "tests/fixture-pod.yaml": bundle.RoleTest, "tests/fixture-exception.yaml": bundle.RoleTest,
		},
	})

	t.Run("unsupported scope", func(t *testing.T) {
		for _, name := range []string{"cluster-scoped", "unknown-resource", "not-validating"} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				cl := newCraftedCluster(t, a, []v1alpha1.ProfilePolicy{{Name: assessment.PolicyName}, {Name: name}})
				cl.reconcile()
				p, r, _ := cl.conditions()
				if p.Reason != v1alpha1.ReasonUnsupportedScope || r.Reason != v1alpha1.ReasonUnsupportedScope || !strings.Contains(p.Message, name) {
					t.Fatalf("profile %+v, resolved %+v", p, r)
				}
				for _, o := range cl.policies() {
					if o.GetAnnotations()[targeting.AnnotationPolicy] == name {
						t.Fatalf("rendered unsupported %s", name)
					}
				}
				requireOnlyPolicyAndStatusWrites(t, cl.writes.take())
			})
		}
	})

	t.Run("fixtures are unknown and never installed", func(t *testing.T) {
		for _, name := range []string{"fixture-policy", "bad", "allow-all", "tests/fixture-pod.yaml"} {
			t.Run(strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
				cl := newCraftedCluster(t, a, []v1alpha1.ProfilePolicy{{Name: name}})
				cl.reconcile()
				p, r, _ := cl.conditions()
				if p.Reason != v1alpha1.ReasonUnknownPolicy || r.Reason != v1alpha1.ReasonUnknownPolicy {
					t.Fatalf("profile %+v, resolved %+v", p, r)
				}
				if got := cl.policies(); len(got) != 0 {
					t.Fatalf("installed %v", got)
				}
				requireOnlyStatusWrites(t, cl.writes.take(), name)
			})
		}
	})

	t.Run("supported policies are the only resources", func(t *testing.T) {
		cl := newCraftedCluster(t, a, []v1alpha1.ProfilePolicy{{Name: assessment.PolicyName}, {Name: "another-namespaced"}})
		cl.reconcile()
		p, r, e := cl.conditions()
		if p.Status != metav1.ConditionTrue || r.Status != metav1.ConditionTrue || e.Status != metav1.ConditionTrue {
			t.Fatalf("profile %+v, resolved %+v, engine %+v", p, r, e)
		}
		writes := cl.writes.take()
		requireOnlyPolicyAndStatusWrites(t, writes)
		got := map[string]bool{}
		for _, o := range cl.policies() {
			got[o.GetAnnotations()[targeting.AnnotationPolicy]] = true
			// Governance comes from the binding, not the bundle.
			if o.GetLabels()[targeting.LabelBindingUID] != "uid-binding" {
				t.Fatalf("policy %s carries no binding ownership", o.GetName())
			}
			for _, ref := range o.GetOwnerReferences() {
				if ref.UID != "uid-binding" {
					t.Fatalf("policy %s owned by %s", o.GetName(), ref.UID)
				}
			}
		}
		if len(got) != 2 || !got[assessment.PolicyName] || !got["another-namespaced"] {
			t.Fatalf("applied %v", got)
		}
	})
}

// Parameters against a declared parameter contract: invalid parameters are
// rejected with the schema's reason, and valid ones are still rejected
// because the renderer does not render parameters (never silently dropped).
// Nothing is applied either way.
func TestOCIParameterContract(t *testing.T) {
	t.Parallel()
	schema := `{"type":"object","properties":{"maxContainers":{"type":"integer","minimum":1}},"additionalProperties":false}`
	a := buildCrafted(t, crafted{
		version:  "0.7.0",
		policies: []bundle.Policy{craftedPolicy("with-params", "content/policies/with-params.yaml", "content/schemas/with-params.json")},
		files: map[string]string{
			"content/policies/with-params.yaml": craftedPolicyYAML("policies.kyverno.io/v1", "ValidatingPolicy", "with-params", "", "pods"),
			"content/schemas/with-params.json":  schema,
		},
		roles: map[string]string{"content/policies/with-params.yaml": bundle.RolePolicy, "content/schemas/with-params.json": bundle.RoleSchema},
	})
	for name, tc := range map[string]struct {
		params, contains string
	}{
		"unknown parameter": {`{"unknown":1}`, "unknown"},
		"wrong type":        {`{"maxContainers":"3"}`, "maxContainers"},
		"below minimum":     {`{"maxContainers":0}`, "maxContainers"},
		"valid, unrendered": {`{"maxContainers":3}`, "with-params"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cl := newCraftedCluster(t, a, []v1alpha1.ProfilePolicy{{Name: "with-params", Parameters: &apiextensionsv1.JSON{Raw: []byte(tc.params)}}})
			cl.reconcile()
			p, r, _ := cl.conditions()
			for _, c := range []metav1.Condition{p, r} {
				if c.Reason != v1alpha1.ReasonInvalidConfiguration || !strings.Contains(c.Message, tc.contains) {
					t.Fatalf("condition %+v, want InvalidConfiguration mentioning %q", c, tc.contains)
				}
			}
			if contractErr := bundle.ValidatePolicyParameters("with-params", []byte(schema), []byte(tc.params)); contractErr != nil {
				for _, c := range []metav1.Condition{p, r} {
					if !strings.Contains(c.Message, contractErr.Error()) {
						t.Fatalf("message %q does not carry the schema's reason %q", c.Message, contractErr)
					}
				}
			}
			if got := cl.policies(); len(got) != 0 {
				t.Fatalf("applied %v", got)
			}
			requireOnlyStatusWrites(t, cl.writes.take(), name)
		})
	}
	t.Run("no parameters", func(t *testing.T) {
		cl := newCraftedCluster(t, a, []v1alpha1.ProfilePolicy{{Name: "with-params"}})
		cl.reconcile()
		if p, r, e := cl.conditions(); p.Status != metav1.ConditionTrue || r.Status != metav1.ConditionTrue || e.Status != metav1.ConditionTrue {
			t.Fatalf("profile %+v, resolved %+v, engine %+v", p, r, e)
		}
	})
}
