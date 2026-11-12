package stack_test

// Profile digest upgrades and rollbacks of signed OCI bundles
// (add-policy-bundle-distribution 5.4) through the real stack (verifier,
// acceptances, Watcher, resolver, cache, OCIContent, Router) and the real
// profile and binding reconcilers: the replacement-readiness and revision
// contracts of targeting decide what is applied, and nothing else.
//
// Three revisions of the official bundle are built from the repository's
// definition at test time and signed with disposable in-memory keys
// (bundletest.Signer; no private key is ever written anywhere):
//
//   - A: the official content, signed by the publisher key;
//   - B: A with a semantic rule change (bundletest.TightenPolicy), signed by
//     the same publisher key;
//   - C: B under another version, signed only by a rotated publisher key.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/bundletest"
	"github.com/backend-bunny/Konstapel/internal/bundle/internal/provfixture"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/controller"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const (
	upgradeRepo = "registry.example.test/org/konstapel-privileged-containers"
	mirrorRepo  = "mirror.example.test/org/konstapel-privileged-containers"
	// builderRevision is the test organization builder's own revision.
	builderRevision = "4b1d3f0e9c2a7b6d5e8f1a2b3c4d5e6f7a8b9c0d"
)

// revisions are the three signed bundles, built once per test binary.
type revisions struct {
	a, b, c          *bundle.Archive
	key, rotated     *bundletest.Signer
	resA, resB, resC *registry.Result
}

var (
	revOnce sync.Once
	revs    revisions
	revErr  error
)

func signedRevisions(t testing.TB) revisions {
	t.Helper()
	revOnce.Do(func() {
		build := func(version string, tighten bool) *bundle.Archive {
			o := bundletest.OfficialOptions{Version: version}
			if tighten {
				o.Edit = map[string]func([]byte) ([]byte, error){bundletest.OfficialPolicy: bundletest.TightenPolicy}
			}
			a, err := bundletest.Official(stack.RepoRoot, o)
			if err != nil && revErr == nil {
				revErr = err
			}
			return a
		}
		revs.a, revs.b, revs.c = build("0.1.0", false), build("0.1.1", true), build("0.1.2", true)
		if revErr != nil {
			return
		}
		if revs.key, revErr = bundletest.NewSigner(); revErr != nil {
			return
		}
		if revs.rotated, revErr = bundletest.NewSigner(); revErr != nil {
			return
		}
		sign := func(s *bundletest.Signer, a *bundle.Archive) *registry.Result {
			r, err := s.Result(a, upgradeRepo, provfixture.Builder, builderRevision)
			if err != nil && revErr == nil {
				revErr = err
			}
			return r
		}
		revs.resA, revs.resB, revs.resC = sign(revs.key, revs.a), sign(revs.key, revs.b), sign(revs.rotated, revs.c)
	})
	if revErr != nil {
		t.Fatal(revErr)
	}
	return revs
}

// fetchCall is one registry retrieval the resolver asked for.
type fetchCall struct{ repository, digest, credential string }

// multiFetcher is a fake registry serving signed subjects by repository
// and digest; it records every retrieval with the credential the source
// rule named.
type multiFetcher struct {
	mu    sync.Mutex
	repos map[string]map[string]*registry.Result
	calls []fetchCall
	down  atomic.Bool
}

func (f *multiFetcher) serve(repo string, res ...*registry.Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.repos == nil {
		f.repos = map[string]map[string]*registry.Result{}
	}
	m := map[string]*registry.Result{}
	for _, r := range res {
		m[r.Digest] = r
	}
	f.repos[repo] = m
}

func (f *multiFetcher) Fetch(_ context.Context, src bundle.BundleSource, digest string) (*registry.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cred := ""
	if src.CredentialSecret != nil {
		cred = src.CredentialSecret.Name
	}
	f.calls = append(f.calls, fetchCall{src.Repository, digest, cred})
	if f.down.Load() {
		return nil, fmt.Errorf("%w: connection refused", registry.ErrUnavailable)
	}
	r, ok := f.repos[src.Repository][digest]
	if !ok {
		return nil, registry.ErrNotFound
	}
	c := *r
	c.Repository = src.Repository
	return &c, nil
}

func (f *multiFetcher) take() []fetchCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.calls
	f.calls = nil
	return out
}

// upgradeWorld is a stack.World over the multi-subject registry, with the
// publisher key as Secret/publisher and the rotated key as Secret/rotated.
type upgradeWorld struct {
	*stack.World
	revisions
	fetch *multiFetcher
}

func newUpgradeWorld(t *testing.T) *upgradeWorld {
	t.Helper()
	r := signedRevisions(t)
	c := fake.NewClientBuilder().WithScheme(stack.SchemeForTests()).WithObjects(
		pubKeySecret("publisher", r.key.PublicKey), pubKeySecret("rotated", r.rotated.PublicKey),
		pullSecret("pull-a", upgradeRepo, "token-1"), pullSecret("pull-b", upgradeRepo, "token-b")).Build()
	f := &multiFetcher{}
	f.serve(upgradeRepo, r.resA, r.resB, r.resC)
	w := &stack.World{T: t, Client: c, Opts: stack.Options{SourcesConfigMap: stack.TestConfigMap, Namespace: stack.TestNamespace,
		CacheDir: t.TempDir() + "/cache", ControllerVersion: "0.1.0"}}
	w.Deps = stack.WithTestClock(stack.WithTestFetcher(stack.Deps{APIReader: c, Config: c}, f), func() time.Time { return stack.TestT0 })
	u := &upgradeWorld{World: w, revisions: r, fetch: f}
	w.SetSources(u.source(upgradeRepo, "publisher", nil))
	w.Open()
	return u
}

func pubKeySecret(name string, pub []byte) *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: stack.TestNamespace, Name: name},
		Data: map[string][]byte{bundle.DefaultPublicKey: pub}}
}

func pullSecret(name, repo, token string) *corev1.Secret {
	host, _, _ := strings.Cut(repo, "/")
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: stack.TestNamespace, Name: name}, Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{corev1.DockerConfigJsonKey: fmt.Appendf(nil, `{"auths":{%q:{"username":"bot","password":%q}}}`, host, token)}}
}

// source is the publisher rule for the official bundle name at repo,
// trusting the key in Secret keySecret ("publisher" or "rotated").
func (u *upgradeWorld) source(repo, keySecret string, cred *bundle.ObjectRef) bundle.BundleSource {
	fp := u.key.Fingerprint
	if keySecret == "rotated" {
		fp = u.rotated.Fingerprint
	}
	return bundle.BundleSource{Name: bundletest.OfficialName, Repository: repo, CredentialSecret: cred,
		Publisher: bundle.Publisher{Type: bundle.SignerPublicKey, PublicKey: &bundle.ObjectRef{Kind: bundle.KindSecret, Name: keySecret},
			KeyFingerprint: fp, Provenance: bundle.ProvenanceRule{SourceRepository: provfixture.SourceRepository, Builder: provfixture.Builder}}}
}

func ref(a *bundle.Archive) v1alpha1.BundleReference {
	return v1alpha1.BundleReference{Name: a.Descriptor.Name, Digest: a.ManifestDigest}
}

func (u *upgradeWorld) router() *stack.Router {
	return u.Stack.Router(stack.LocalContent(), stack.VendoredName)
}

// coldRestart restarts the controller with an empty cache, so content must
// come from the registry under the rule configured now.
func (u *upgradeWorld) coldRestart(set func(*stack.Router)) {
	u.T.Helper()
	if err := u.Stack.Close(); err != nil {
		u.T.Fatal(err)
	}
	if err := os.RemoveAll(u.Opts.CacheDir); err != nil {
		u.T.Fatal(err)
	}
	u.Open()
	set(u.router())
}

// --- cluster helpers --------------------------------------------------------

// editBundle pins the profile to r as a new generation.
func (cl *cluster) editBundle(r v1alpha1.BundleReference) {
	cl.t.Helper()
	p := &v1alpha1.ComplianceProfile{}
	if err := cl.c.Get(context.Background(), client.ObjectKey{Name: "org"}, p); err != nil {
		cl.t.Fatal(err)
	}
	p.Spec.Bundle = r
	p.Generation++
	if err := cl.c.Update(context.Background(), p); err != nil {
		cl.t.Fatal(err)
	}
}

// readyOnly makes only the named policies engine-ready (nil: all).
func (cl *cluster) readyOnly(names ...string) {
	if names == nil {
		cl.ready.Store(nil)
		return
	}
	f := func(o *unstructured.Unstructured) bool { return slices.Contains(names, o.GetName()) }
	cl.ready.Store(&f)
}

// appliedPolicy is what an engine policy says about its contribution.
type appliedPolicy struct {
	name, revision, digest, bundle, rv string
	owners                             []string
	spec                               map[string]any
}

func (cl *cluster) applied() map[string]appliedPolicy {
	cl.t.Helper()
	out := map[string]appliedPolicy{}
	for _, o := range cl.policies() {
		a := o.GetAnnotations()
		p := appliedPolicy{name: o.GetName(), revision: a[targeting.AnnotationRevision], digest: a[targeting.AnnotationBundleDigest],
			bundle: a[targeting.AnnotationBundle], rv: o.GetResourceVersion()}
		for _, r := range o.GetOwnerReferences() {
			p.owners = append(p.owners, string(r.UID))
		}
		p.spec, _ = o.Object["spec"].(map[string]any)
		out[o.GetName()] = p
	}
	return out
}

// only returns the single applied policy, failing otherwise.
func (cl *cluster) only(what string) appliedPolicy {
	cl.t.Helper()
	got := cl.applied()
	if len(got) != 1 {
		cl.t.Fatalf("%s: want exactly one engine policy, have %v", what, slices.Sorted(maps.Keys(got)))
	}
	for _, p := range got {
		if !slices.Equal(p.owners, []string{"uid-binding"}) || p.bundle != bundletest.OfficialName {
			cl.t.Fatalf("%s: %s is owned by %v for bundle %q", what, p.name, p.owners, p.bundle)
		}
		return p
	}
	return appliedPolicy{}
}

func specJSON(t *testing.T, spec map[string]any) string {
	t.Helper()
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// requireRules checks which revision's rules a rendered policy carries.
func requireRules(t *testing.T, p appliedPolicy, tightened bool, what string) {
	t.Helper()
	if strings.Contains(specJSON(t, p.spec), bundletest.TightenedMarker) != tightened {
		t.Fatalf("%s: %s carries the wrong revision's rules (tightened=%v): %s", what, p.name, !tightened, specJSON(t, p.spec))
	}
}

// --- tests ------------------------------------------------------------------

// A profile digest upgrade A→B to a semantically changed bundle signed by
// the same publisher advances the enforcement revision; A's policy keeps
// enforcing until B's is engine-ready and is removed only then. The
// rollback B→A is a new profile generation, so it gets a fresh revision
// (the revision contract never reuses one, so exceptions and engine names
// bound to earlier revisions cannot carry over), restores A's rules exactly
// and leaves nothing behind.
func TestOCIProfileDigestUpgradeAndRollback(t *testing.T) {
	u := newUpgradeWorld(t)
	if u.a.Descriptor.ContentDigest() == u.b.Descriptor.ContentDigest() || u.a.ManifestDigest == u.b.ManifestDigest {
		t.Fatal("A and B are not different content")
	}
	cl := newClusterOver(t, u.World, u.router(), ref(u.a), nil)
	cl.applyOnce()
	pa := cl.only("initial")
	if pa.digest != u.a.ManifestDigest {
		t.Fatalf("initial: applied digest %s, want A %s", pa.digest, u.a.ManifestDigest)
	}
	requireRules(t, pa, false, "initial")
	revA := cl.bindingStatus().ConfigurationRevision

	// Upgrade A→B while B's policy is not engine-ready.
	cl.readyOnly(pa.name)
	cl.editBundle(ref(u.b))
	cl.reconcile()
	got := cl.applied()
	if len(got) != 2 || got[pa.name].rv != pa.rv {
		t.Fatalf("pending upgrade: want A's policy unchanged plus B's, have %v", got)
	}
	var pb appliedPolicy
	for n, p := range got {
		if n != pa.name {
			pb = p
		}
	}
	if pb.digest != u.b.ManifestDigest || pb.revision == pa.revision || pb.name == pa.name || !slices.Equal(pb.owners, []string{"uid-binding"}) {
		t.Fatalf("pending upgrade: B's policy %+v, A's revision %s", pb, pa.revision)
	}
	requireRules(t, pb, true, "pending upgrade")
	_, r, e := cl.conditions()
	if r.Status != metav1.ConditionTrue || e.Status != metav1.ConditionFalse {
		t.Fatalf("pending upgrade: resolved %+v, engine %+v", r, e)
	}
	st := cl.bindingStatus()
	if st.Profile == nil || st.Profile.BundleDigest != u.b.ManifestDigest || st.ConfigurationRevision == revA {
		t.Fatalf("pending upgrade: binding status %+v (revision was %s)", st, revA)
	}

	// B ready: A's policy is withdrawn.
	cl.readyOnly()
	cl.reconcile()
	pbUpgraded := cl.only("upgraded")
	if pbUpgraded.name != pb.name || pbUpgraded.digest != u.b.ManifestDigest {
		t.Fatalf("upgraded: %+v", pbUpgraded)
	}
	if _, _, e := cl.conditions(); e.Status != metav1.ConditionTrue {
		t.Fatalf("upgraded: engine %+v", e)
	}

	// Rollback B→A while the new A policy is not ready.
	cl.readyOnly(pb.name)
	cl.editBundle(ref(u.a))
	cl.reconcile()
	got = cl.applied()
	if len(got) != 2 || got[pb.name].rv != pbUpgraded.rv {
		t.Fatalf("pending rollback: want B's policy kept plus A's, have %v", got)
	}
	var pa2 appliedPolicy
	for n, p := range got {
		if n != pb.name {
			pa2 = p
		}
	}
	if pa2.digest != u.a.ManifestDigest || slices.Contains([]string{pa.revision, pb.revision}, pa2.revision) || pa2.name == pa.name {
		t.Fatalf("pending rollback: A's new policy %+v (A was %s, B %s)", pa2, pa.revision, pb.revision)
	}
	if specJSON(t, pa2.spec) != specJSON(t, pa.spec) {
		t.Fatalf("rollback did not restore A's rules:\n%s\nwas\n%s", specJSON(t, pa2.spec), specJSON(t, pa.spec))
	}
	cl.readyOnly()
	cl.reconcile()
	final := cl.only("rolled back")
	if final.name != pa2.name || final.digest != u.a.ManifestDigest {
		t.Fatalf("rolled back: %+v", final)
	}
	if st := cl.bindingStatus(); st.Profile.BundleDigest != u.a.ManifestDigest || slices.Contains([]string{revA}, st.ConfigurationRevision) {
		t.Fatalf("rolled back: binding status %+v", st)
	}
	cl.requirePreserved(cl.snapshot(), "rolled back")
}

// A mirror move (the same digest from another repository) and credential
// rotation change neither the enforcement revision nor any engine policy,
// with a warm cache and after a cold restart that must fetch through the
// changed rule.
func TestOCISourceChangesKeepRevisions(t *testing.T) {
	u := newUpgradeWorld(t)
	cl := newClusterOver(t, u.World, u.router(), ref(u.a), nil)
	before := cl.applyOnce()
	pa := cl.only("initial")
	revision := cl.bindingStatus().ConfigurationRevision
	u.fetch.take()

	check := func(what string, wantFetch *fetchCall) {
		t.Helper()
		cl.reconcile()
		for _, w := range cl.writes.take() {
			if !strings.HasPrefix(w, "status ") {
				t.Fatalf("%s: wrote %s; a source change must not write engine policies or specs", what, w)
			}
		}
		cl.requirePreserved(before, what)
		if got := cl.only(what); got.revision != pa.revision || got.name != pa.name || got.rv != pa.rv {
			t.Fatalf("%s: applied %+v, was %+v", what, got, pa)
		}
		if got := cl.bindingStatus().ConfigurationRevision; got != revision {
			t.Fatalf("%s: configuration revision %s, was %s", what, got, revision)
		}
		calls := u.fetch.take()
		if wantFetch != nil && !slices.Contains(calls, *wantFetch) {
			t.Fatalf("%s: fetches %v, want %v", what, calls, *wantFetch)
		}
		p, r, e := cl.conditions()
		if p.Status != metav1.ConditionTrue || r.Status != metav1.ConditionTrue || e.Status != metav1.ConditionTrue {
			t.Fatalf("%s: profile %+v, resolved %+v, engine %+v", what, p, r, e)
		}
	}

	// Mirror: the subject now lives only at the mirror.
	u.fetch.serve(mirrorRepo, u.resA)
	u.fetch.serve(upgradeRepo)
	u.SetSources(u.source(mirrorRepo, "publisher", nil))
	u.Sync()
	check("mirror move (warm cache)", nil)
	u.coldRestart(cl.setRouter)
	check("mirror move (cold cache)", &fetchCall{mirrorRepo, u.a.ManifestDigest, ""})

	// Credentials: added, rotated in place, then replaced by another Secret.
	u.fetch.serve(upgradeRepo, u.resA)
	u.SetSources(u.source(upgradeRepo, "publisher", &bundle.ObjectRef{Kind: bundle.KindSecret, Name: "pull-a"}))
	u.Sync()
	check("credential added (warm cache)", nil)
	u.coldRestart(cl.setRouter)
	check("credential added (cold cache)", &fetchCall{upgradeRepo, u.a.ManifestDigest, "pull-a"})

	sec := pullSecret("pull-a", upgradeRepo, "token-2")
	if err := u.Client.Update(context.Background(), sec); err != nil {
		t.Fatal(err)
	}
	if ch := u.Sync(); !slices.Contains(ch.Objects, "Secret/pull-a") {
		t.Fatalf("the Watcher did not see the rotation: %+v", ch)
	}
	check("credential rotated (warm cache)", nil)
	u.coldRestart(cl.setRouter)
	check("credential rotated (cold cache)", &fetchCall{upgradeRepo, u.a.ManifestDigest, "pull-a"})

	u.SetSources(u.source(upgradeRepo, "publisher", &bundle.ObjectRef{Kind: bundle.KindSecret, Name: "pull-b"}))
	u.Sync()
	check("credential replaced (warm cache)", nil)
	u.coldRestart(cl.setRouter)
	check("credential replaced (cold cache)", &fetchCall{upgradeRepo, u.a.ManifestDigest, "pull-b"})
}

// Publisher rotation: content signed by another key than the configured
// rule's is rejected as Untrusted while the applied policies keep
// enforcing unchanged; once the rule names the new key, that content is
// accepted and replaces them, and content signed only by the old key is no
// longer trusted.
func TestOCIPublisherRotation(t *testing.T) {
	u := newUpgradeWorld(t)
	cl := newClusterOver(t, u.World, u.router(), ref(u.a), nil)
	cl.applyOnce()
	pa := cl.only("initial")

	// Upgrade to C, signed only by the rotated key: refused.
	cl.editBundle(ref(u.c))
	before := cl.snapshot()
	cl.reconcile()
	p, r, _ := cl.conditions()
	for _, c := range []metav1.Condition{p, r} {
		if c.Status != metav1.ConditionFalse || c.Reason != v1alpha1.ReasonContentUnavailable || !strings.Contains(c.Message, "("+string(targeting.ContentErrorUntrusted)+")") {
			t.Fatalf("other key: condition %+v", c)
		}
	}
	if _, err := cl.router.Content(context.Background(), ref(u.c)); targeting.ContentErrorClassOf(err) != targeting.ContentErrorUntrusted {
		t.Fatalf("other key: content error %v", err)
	}
	requireOnlyStatusWrites(t, cl.writes.take(), "other key")
	cl.requirePreserved(before, "other key")
	if got := cl.only("other key"); got.name != pa.name || got.digest != u.a.ManifestDigest {
		t.Fatalf("other key: applied %+v", got)
	}

	// The rule rotates to the new key.
	u.SetSources(u.source(upgradeRepo, "rotated", nil))
	u.Sync()
	cl.reconcile()
	pc := cl.only("rotated")
	if pc.digest != u.c.ManifestDigest || pc.revision == pa.revision {
		t.Fatalf("rotated: applied %+v", pc)
	}
	requireRules(t, pc, true, "rotated")
	if p, r, e := cl.conditions(); p.Status != metav1.ConditionTrue || r.Status != metav1.ConditionTrue || e.Status != metav1.ConditionTrue {
		t.Fatalf("rotated: profile %+v, resolved %+v, engine %+v", p, r, e)
	}
	if _, err := cl.router.Content(context.Background(), ref(u.a)); targeting.ContentErrorClassOf(err) != targeting.ContentErrorUntrusted {
		t.Fatalf("content signed by the old key after rotation: %v", err)
	}
}

// add-policy-bundle-distribution 7.2: a run captured while the profile
// already pins B but B's replacement is not engine-ready (A's policy is
// still the one enforcing) is exported from B's frozen bundle, keeps the
// enforcing A policy in its evidence, and reports B's not-yet-ready
// subject's evidence as missing rather than attributing A's report to it.
// The export is replayed after the cache is evicted and the registry lost,
// from the frozen copy alone.
func TestOCIRunDesiredDiffersFromApplied(t *testing.T) {
	u := newUpgradeWorld(t)
	rc := newRunCluster(t, u.router(), ref(u.a))
	rc.deliver()
	pa := rc.policyNames()
	if len(pa) != 1 {
		t.Fatalf("initial: %v", pa)
	}
	f := func(o *unstructured.Unstructured) bool { return o.GetName() == pa[0] }
	rc.ready.Store(&f)
	p := &v1alpha1.ComplianceProfile{}
	rc.must(rc.c.Get(context.Background(), client.ObjectKey{Name: "org"}, p))
	p.Spec.Bundle = ref(u.b)
	p.Generation++
	rc.must(rc.c.Update(context.Background(), p))
	rc.ref = ref(u.b)
	rc.deliver()
	names := rc.policyNames()
	if len(names) != 2 || !slices.Contains(names, pa[0]) {
		t.Fatalf("replacement: %v", names)
	}
	pb := names[0]
	if pb == pa[0] {
		pb = names[1]
	}
	run := rc.start()
	rc.reportFor(pa[0], runT0.Add(time.Minute))

	// The window closes and the package is exported, but the closure is not
	// recorded; then the cache is evicted and the registry lost, and the
	// replayed export must come from the frozen copy alone.
	rc.failNext.Store(true)
	rc.now = runT0.Add(6 * time.Minute)
	if err := rc.reconcile(rc.runs, run.Name); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("closure was not interrupted: %v", err)
	}
	u.fetch.down.Store(true)
	u.coldRestart(rc.setRouter)
	if _, err := rc.assess.Content.Content(context.Background(), ref(u.b)); err == nil {
		t.Fatal("B is still resolvable; the loss did not take effect")
	}
	run = rc.finish(run.Name)
	dir, d := rc.pkg(run)
	fz := requireBundleExport(t, dir, d, ref(u.b))
	if fz.Identity.Receipt.Signer.KeyFingerprint != u.key.Fingerprint || d.Revisions.Content.ContentDigest != u.b.Descriptor.ContentDigest() {
		t.Fatalf("frozen identity %+v, content revision %+v", fz.Identity, d.Revisions.Content)
	}
	// The run is of the desired revision B: its subject is B's policy, and
	// the report of A's still-enforcing policy is never attributed to it.
	if d.Evidence.Expected != 1 || d.Evidence.Attributable != 0 || d.Evidence.Missing != 1 || d.Evidence.Unresolved != 0 || d.Outcomes.Fail != 0 ||
		d.Evidence.Completeness != publication.Incomplete {
		t.Fatalf("evidence %+v outcomes %+v", d.Evidence, d.Outcomes)
	}
	// The difference is preserved in the packaged capture: both engine
	// policies with their own bundle digests and revisions, and A's report.
	var capture collector.CaptureV2
	raw, err := os.ReadFile(filepath.Join(dir, "capture.json"))
	rc.must(err)
	rc.must(json.Unmarshal(raw, &capture))
	digests := map[string]string{}
	revisionsOf := map[string]string{}
	for _, o := range capture.EnginePolicies {
		md, _ := o["metadata"].(map[string]any)
		ann, _ := md["annotations"].(map[string]any)
		name, _ := md["name"].(string)
		digests[name], _ = ann[targeting.AnnotationBundleDigest].(string)
		revisionsOf[name], _ = ann[targeting.AnnotationRevision].(string)
	}
	if !maps.Equal(digests, map[string]string{pa[0]: u.a.ManifestDigest, pb: u.b.ManifestDigest}) {
		t.Fatalf("captured engine policies %v", digests)
	}
	if len(capture.Subjects) != 1 || capture.Subjects[0].EnginePolicy != pb || capture.Subjects[0].BundleDigest != u.b.ManifestDigest ||
		!slices.Equal(d.Revisions.Enforcement, []string{revisionsOf[pb]}) || revisionsOf[pa[0]] == revisionsOf[pb] {
		t.Fatalf("subjects %+v, enforcement revisions %v, engine revisions %v", capture.Subjects, d.Revisions.Enforcement, revisionsOf)
	}
	reported, err := json.Marshal(capture.Reports)
	rc.must(err)
	if !bytes.Contains(reported, []byte(`"policy":"`+pa[0]+`"`)) {
		t.Fatalf("the enforcing policy's report is not retained: %s", reported)
	}
	// The exported OSCAL is B's (tightened) content, not A's.
	results, err := os.ReadFile(filepath.Join(dir, "assessment-results.json"))
	rc.must(err)
	if bytes.Contains(results, []byte(u.a.ManifestDigest)) {
		t.Fatal("the results attribute the run to the applied, not the desired, bundle")
	}
	pol, err := os.ReadFile(filepath.Join(dir, bundletest.OfficialPolicy))
	rc.must(err)
	if !bytes.Contains(pol, []byte(bundletest.TightenedMarker)) {
		t.Fatal("the packaged policy is not B's")
	}
}

func (rc *runCluster) policyNames() []string {
	rc.t.Helper()
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(targeting.ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
	rc.must(rc.c.List(context.Background(), list))
	var out []string
	for _, o := range list.Items {
		out = append(out, o.GetName())
	}
	slices.Sort(out)
	return out
}

// reportFor records a failure for the pod from the named engine policy.
func (rc *runCluster) reportFor(policy string, at time.Time) {
	rc.t.Helper()
	r := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "r-pod-1", "namespace": "app"},
		"scope":    map[string]any{"apiVersion": "v1", "kind": "Pod", "namespace": "app", "name": "web", "uid": "pod-1"},
		"results": []any{map[string]any{"policy": policy, "result": "fail", "source": "KyvernoValidatingPolicy",
			"properties": map[string]any{"cel.validationIndex": "0"},
			"timestamp":  map[string]any{"seconds": at.Unix(), "nanos": int64(0)}}},
	}}
	r.SetGroupVersionKind(controller.PolicyReportGVK)
	r.SetUID("report-pod-1")
	rc.must(rc.c.Create(context.Background(), r))
}
