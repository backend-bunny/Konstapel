package preview

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// fakeContent is a verified-content seam double: it serves exactly the
// pinned name and digest and reports everything else as unavailable.
type fakeContent map[v1alpha1.BundleReference]*targeting.Content

func (f fakeContent) Content(_ context.Context, ref v1alpha1.BundleReference) (*targeting.Content, error) {
	if c := f[ref]; c != nil {
		return c, nil
	}
	return nil, &targeting.ContentError{Class: targeting.ContentErrorUntrusted, Detail: "not served by the test source"}
}

func policyManifest(scope targeting.PolicyScope) map[string]any {
	rule := map[string]any{"apiGroups": []any{""}, "apiVersions": []any{"v1"}, "operations": []any{"CREATE"}, "resources": []any{"pods"}}
	if scope != targeting.ScopeNamespaced {
		rule = map[string]any{"apiGroups": []any{"rbac.authorization.k8s.io"}, "apiVersions": []any{"v1"}, "operations": []any{"CREATE"}, "resources": []any{"clusterrolebindings"}}
	}
	return map[string]any{"apiVersion": "policies.kyverno.io/v1", "kind": "ValidatingPolicy", "metadata": map[string]any{"name": "src"},
		"spec": map[string]any{"matchConstraints": map[string]any{"resourceRules": []any{rule}}, "validations": []any{map[string]any{"expression": "true"}}}}
}

func (f fakeContent) add(b targeting.Bundle) {
	c := &targeting.Content{Bundle: b, Policies: map[string]targeting.PolicySource{}}
	for _, p := range b.Policies {
		c.Policies[p.Name] = targeting.PolicySource{Manifest: policyManifest(p.Scope), SourceDigest: digestB}
	}
	f[b.Ref()] = c
}

// world is an observed cluster for comparison tests.
type world struct {
	t       *testing.T
	snap    *Snapshot
	content fakeContent
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, content: fakeContent{}, snap: &Snapshot{Complete: true, Cluster: clusterID, Contracts: map[string]int{},
		Live: Live{StoredSpecs: map[Identity]map[string]any{}}}}
	w.content.add(targeting.Bundle{Name: "hardening", Digest: digestA, Policies: []targeting.BundlePolicy{
		{Name: "run-as-non-root", Scope: targeting.ScopeNamespaced, Parameters: true}, {Name: "privileged", Scope: targeting.ScopeNamespaced},
		{Name: "cluster-rbac", Scope: targeting.ScopeCluster}}})
	w.content.add(targeting.Bundle{Name: "hardening", Digest: digestB, Policies: []targeting.BundlePolicy{
		{Name: "run-as-non-root", Scope: targeting.ScopeNamespaced, Parameters: true}, {Name: "privileged", Scope: targeting.ScopeNamespaced}}})
	return w
}

func (w *world) ns(name, uid string, labels map[string]string) *world {
	if labels == nil {
		labels = map[string]string{}
	}
	w.snap.Namespaces = append(w.snap.Namespaces, ObservedNamespace{Name: name, UID: types.UID(uid), Labels: labels})
	return w
}

// live adds an object as the API server stores it: defaulted spec, the
// stored spec kept as written, a UID and generation, and for bindings an
// enforcement epoch (0 for none).
func (w *world) live(doc, uid string, gen, epoch int64) *world {
	w.t.Helper()
	o := mustSet(w.t, doc).Objects[0]
	stored := storedForm(o.Identity.Kind, o.Spec)
	switch {
	case o.Profile != nil:
		p := o.Profile.DeepCopy()
		p.UID, p.Generation = types.UID(uid), gen
		w.snap.Live.Profiles = append(w.snap.Live.Profiles, *p)
	default:
		b := o.Binding.DeepCopy()
		b.UID, b.Generation, b.Spec.EnforcementEpoch = types.UID(uid), gen, epoch
		if epoch > 0 {
			stored["enforcementEpoch"] = epoch
		}
		w.snap.Live.Bindings = append(w.snap.Live.Bindings, *b)
	}
	w.snap.Live.StoredSpecs[o.Identity] = stored
	return w
}

// apply delivers engine policies for the live configuration as the
// controller renders them and records them as observed applied state.
func (w *world) apply(ready bool) *world {
	w.t.Helper()
	a := newAdapter(w.snap, &Candidate{Profiles: w.snap.Live.Profiles, Bindings: w.snap.Live.Bindings})
	if err := a.resolve(context.Background(), w.content); err != nil {
		w.t.Fatal(err)
	}
	for _, br := range a.base.res.Bindings {
		for _, c := range br.Contributions {
			w.applyContribution(c, ready)
		}
	}
	return w
}

func (w *world) applyContribution(c targeting.Contribution, ready bool) {
	w.t.Helper()
	ct := w.content[v1alpha1.BundleReference{Name: c.BundleName, Digest: c.BundleDigest}]
	obj, err := targeting.Render(c, ct.Policies[c.Policy])
	if err != nil {
		w.t.Fatal(err)
	}
	got, err := targeting.AppliedContribution(obj.Object)
	if err != nil {
		w.t.Fatal(err)
	}
	w.snap.Applied = append(w.snap.Applied, AppliedPolicy{ObjectRef: ObjectRef{Resource: resourceString(gvrEnginePolicy), Name: obj.GetName(), UID: types.UID("uid-" + obj.GetName())},
		Ownership: Owned, BindingUID: c.Binding.UID, Ready: ready, Contribution: &got})
}

func (w *world) compare(proposed, before *Set) *Comparison {
	w.t.Helper()
	c, err := Compare(context.Background(), CompareInput{Snapshot: w.snap, Proposed: proposed, Before: before, Content: w.content})
	if err != nil {
		w.t.Fatal(err)
	}
	// Whatever the scenario, a comparison never leaks provisional values.
	assertNoProvisionalValues(w.t, w, proposed, before, c)
	return c
}

// assertNoProvisionalValues checks that no provisional UID, generation,
// revision or engine policy name of the candidate reaches the comparison.
func assertNoProvisionalValues(t *testing.T, w *world, proposed, before *Set, c *Comparison) {
	t.Helper()
	cand, err := BuildCandidate(w.snap.Live, proposed, before)
	if err != nil {
		t.Fatal(err)
	}
	a := newAdapter(w.snap, cand)
	if err := a.resolve(context.Background(), w.content); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(c)
	text := string(raw)
	if strings.Contains(text, "preview-pending") {
		t.Errorf("a provisional UID leaked: %s", text)
	}
	baseRevs := map[string]bool{}
	for _, bc := range a.base.contribs {
		baseRevs[bc.Revision] = true
	}
	for _, nc := range a.next.contribs {
		if baseRevs[nc.Revision] {
			continue
		}
		if strings.Contains(text, nc.Revision) || strings.Contains(text, targeting.PolicyName(*nc)) {
			t.Errorf("a provisional revision or engine name of %s/%s leaked", nc.Binding.Name, nc.Policy)
		}
	}
	for _, r := range c.Contributions {
		if r.After != nil && (r.After.ProfileUID != "" || r.After.ProfileGeneration != 0 || r.After.DesiredRevision != "") {
			t.Errorf("proposed side carries server identity: %+v", r.After)
		}
	}
}

func profileWith(name, digest, policies string) string {
	return "apiVersion: compliance.erenius.io/v1alpha1\nkind: ComplianceProfile\nmetadata:\n  name: " + name +
		"\nspec:\n  bundle: {name: hardening, digest: " + digest + "}\n  policies:\n" + policies
}

func bindingWith(name, profile, mode, selector string) string {
	return "apiVersion: compliance.erenius.io/v1alpha1\nkind: ComplianceBinding\nmetadata:\n  name: " + name +
		"\nspec:\n  profileRef: {name: " + profile + "}\n  mode: " + mode + "\n  namespaceSelector: " + selector + "\n"
}

const polRun = "    - name: run-as-non-root\n"

func categories(r ContributionChange) []string {
	var out []string
	for _, i := range r.Impacts {
		out = append(out, string(i.Category))
	}
	return out
}

func rowFor(t *testing.T, c *Comparison, binding, policy string) ContributionChange {
	t.Helper()
	for _, r := range c.Contributions {
		if r.Key.Binding == binding && r.Key.Policy == policy {
			return r
		}
	}
	t.Fatalf("no row for %s/%s in %+v", binding, policy, c.Contributions)
	return ContributionChange{}
}

func errorCodes(ds []Diagnostic) []string {
	var out []string
	for _, d := range ds {
		out = append(out, string(d.Code)+":"+d.Name)
	}
	return out
}

// --- 3.1: shared resolution through the targeting resolver and content seam ---

type resolverFixture struct {
	Input struct {
		Cluster    string                       `json:"cluster"`
		Bundles    []targeting.Bundle           `json:"bundles"`
		Profiles   []v1alpha1.ComplianceProfile `json:"profiles"`
		Bindings   []v1alpha1.ComplianceBinding `json:"bindings"`
		Namespaces []targeting.Namespace        `json:"namespaces"`
	} `json:"input"`
}

// fixtureWorld observes the input of a targeting resolver fixture.
func fixtureWorld(t *testing.T, path string) (*world, resolverFixture) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fx resolverFixture
	if err := yaml.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	var generic struct {
		Input struct {
			Profiles []map[string]any `json:"profiles"`
			Bindings []map[string]any `json:"bindings"`
		} `json:"input"`
	}
	if err := yaml.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, content: fakeContent{}, snap: &Snapshot{Complete: true, Cluster: fx.Input.Cluster, Contracts: map[string]int{},
		Live: Live{Profiles: fx.Input.Profiles, Bindings: fx.Input.Bindings, StoredSpecs: map[Identity]map[string]any{}}}}
	for _, b := range fx.Input.Bundles {
		w.content.add(b)
	}
	for _, n := range fx.Input.Namespaces {
		w.ns(n.Name, string(n.UID), n.Labels)
	}
	for i, p := range generic.Input.Profiles {
		w.snap.Live.StoredSpecs[Identity{v1alpha1.GroupVersion.Group, KindProfile, fx.Input.Profiles[i].Name}] = storedForm(KindProfile, p["spec"].(map[string]any))
	}
	for i, b := range generic.Input.Bindings {
		w.snap.Live.StoredSpecs[Identity{v1alpha1.GroupVersion.Group, KindBinding, fx.Input.Bindings[i].Name}] = storedForm(KindBinding, b["spec"].(map[string]any))
	}
	return w, fx
}

// The baseline is exactly what the controller's resolver computes for the
// observed configuration, for every targeting resolver fixture, and an empty
// proposal is complete and impact-free even where the baseline itself does
// not resolve (that is a limitation, not an impact).
func TestCompareBaselineIsTheTargetingResolverOnEveryFixture(t *testing.T) {
	files, _ := filepath.Glob("../../testdata/targeting/resolver/*.yaml")
	if len(files) == 0 {
		t.Fatal("no targeting fixtures")
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			w, fx := fixtureWorld(t, f)
			a := newAdapter(w.snap, &Candidate{Profiles: w.snap.Live.Profiles, Bindings: w.snap.Live.Bindings})
			if err := a.resolve(context.Background(), w.content); err != nil {
				t.Fatal(err)
			}
			want := targeting.Resolve(targeting.Input{Cluster: fx.Input.Cluster, Bundles: fx.Input.Bundles, Profiles: fx.Input.Profiles,
				Bindings: fx.Input.Bindings, Namespaces: fx.Input.Namespaces})
			gotJSON, _ := json.Marshal(a.base.res)
			wantJSON, _ := json.Marshal(want)
			if string(gotJSON) != string(wantJSON) {
				t.Fatalf("baseline differs from targeting.Resolve:\n got %s\nwant %s", gotJSON, wantJSON)
			}
			c := w.compare(&Set{}, nil)
			if !c.Complete || c.ImpactCount != 0 || len(c.Contributions) != 0 || len(c.Namespaces) != 0 || len(c.Objects) != 0 {
				t.Fatalf("empty proposal: %+v", c)
			}
		})
	}
}

// A shared profile update reaches every live consumer, including bindings
// that are not in the files, with cumulative Audit and Deny contributions
// kept apart and Forbidden precedence and the shortest lifetime retained.
func TestCompareSharedProfileAndOverlapFollowTheResolver(t *testing.T) {
	w, _ := fixtureWorld(t, "../../testdata/targeting/resolver/restrictive-eligibility.yaml")
	// Shorten the self-service lifetime of the profile behind deny-selfservice.
	proposed := mustSet(t, `apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceProfile
metadata: {name: self-service}
spec:
  bundle: {name: example-workload-hardening, digest: sha256:1111111111111111111111111111111111111111111111111111111111111111}
  policies:
    - {name: disallow-privileged-containers, exceptions: {eligibility: SelfService, maxLifetime: 168h}}
`)
	c := w.compare(proposed, nil)
	if !c.Complete || c.ImpactCount == 0 {
		t.Fatalf("%+v", c)
	}
	r := rowFor(t, c, "deny-selfservice", "disallow-privileged-containers")
	if r.RevisionEffect != RevisionReplacement || !slices.Contains(categories(r), string(CategoryExceptionRule)) || r.After.Mode != v1alpha1.ModeDeny {
		t.Fatalf("%+v", r)
	}
	// The Audit/Forbidden binding is not touched; in production it keeps
	// eligibility Forbidden although the Deny contribution changes.
	for _, n := range c.Namespaces {
		switch n.Namespace.Name {
		case "shop-prod":
			if n.Before.Effective != v1alpha1.ExceptionsForbidden || n.After.Effective != v1alpha1.ExceptionsForbidden || len(n.Impacts) != 0 ||
				len(n.Remaining) != 1 || n.Remaining[0].Binding != "audit-forbidden-production" || n.Remaining[0].Mode != v1alpha1.ModeAudit ||
				len(n.Replaced) != 1 || n.Replaced[0].Mode != v1alpha1.ModeDeny {
				t.Fatalf("production: %+v", n)
			}
		default:
			if len(n.Impacts) != 1 || n.Impacts[0].Category != CategoryEligibility || n.Impacts[0].Before != "SelfService (maxLifetime 720h0m0s)" || n.Impacts[0].After != "SelfService (maxLifetime 168h0m0s)" {
				t.Fatalf("%s: %+v", n.Namespace.Name, n)
			}
		}
	}

	// A second, overlapping SelfService binding with a shorter lifetime: the
	// shortest applicable lifetime wins where both apply.
	w2, _ := fixtureWorld(t, "../../testdata/targeting/resolver/restrictive-eligibility.yaml")
	c2 := w2.compare(mustSet(t, `apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceProfile
metadata: {name: short}
spec:
  bundle: {name: example-workload-hardening, digest: sha256:1111111111111111111111111111111111111111111111111111111111111111}
  policies:
    - {name: disallow-privileged-containers, exceptions: {eligibility: SelfService, maxLifetime: 24h}}
---
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata: {name: audit-short}
spec: {profileRef: {name: short}, namespaceSelector: {matchLabels: {environment: development}}, mode: Audit}
`), nil)
	for _, n := range c2.Namespaces {
		if n.Namespace.Name != "shop-dev" {
			t.Fatalf("only shop-dev gains a contribution: %+v", n)
		}
		if len(n.Added) != 1 || n.Added[0].Binding != "audit-short" || n.Added[0].RevisionEffect != RevisionNew || n.Added[0].BindingUID != "" ||
			n.After.MaxLifetime.Duration.String() != "24h0m0s" || n.After.Effective != v1alpha1.ExceptionsSelfService || len(n.Remaining) != 1 {
			t.Fatalf("%+v", n)
		}
	}
}

// An unsupported policy scope and unavailable content in an affected
// binding make the comparison incomplete; an untouched broken binding is a
// limitation; and unresolved overlap forbids exceptions instead of permitting them.
func TestCompareUnresolvedConfigurationIsIncomplete(t *testing.T) {
	newW := func() *world {
		return newWorld(t).ns("prod", "prod-uid", map[string]string{"env": "production"}).
			live(profileWith("base", digestA, polRun), "p-base", 1, 0).
			live(bindingWith("deny-all", "base", "Deny", "{}"), "b-deny", 1, 1)
	}
	// The candidate adds a cluster-scoped policy to the shared profile.
	c := newW().compare(mustSet(t, profileWith("base", digestA, polRun+"    - name: cluster-rbac\n")), nil)
	if c.Complete || !slices.Contains(errorCodes(c.Errors), "unresolved-candidate:deny-all") || !strings.Contains(c.Errors[0].Message, "UnsupportedScope") {
		t.Fatalf("%+v", c.Errors)
	}
	// The candidate pins content that is not available (or not trusted). An
	// overlapping SelfService contribution of another, untouched binding
	// does not make exceptions possible: unresolved overlap forbids them.
	ss := "    - {name: run-as-non-root, exceptions: {eligibility: SelfService, maxLifetime: 720h}}\n"
	w0 := newWorld(t).ns("prod", "prod-uid", map[string]string{"env": "production"}).
		live(profileWith("base", digestA, ss), "p-base", 1, 0).live(profileWith("other", digestA, ss), "p-other", 1, 0).
		live(bindingWith("deny-all", "base", "Deny", "{}"), "b-deny", 1, 1).live(bindingWith("audit-other", "other", "Audit", "{}"), "b-other", 1, 1)
	unpinned := strings.Replace(profileWith("base", digestA, ss), digestA, "sha256:"+strings.Repeat("9", 64), 1)
	c = w0.compare(mustSet(t, unpinned), nil)
	if c.Complete || len(c.Errors) != 1 || !strings.Contains(c.Errors[0].Message, "ContentUnavailable") || !strings.Contains(c.Errors[0].Message, "(Untrusted)") {
		t.Fatalf("%+v", c.Errors)
	}
	if n := c.Namespaces; len(n) != 1 || n[0].Before.Effective != v1alpha1.ExceptionsSelfService || n[0].After.Effective != v1alpha1.ExceptionsForbidden ||
		!slices.Contains(n[0].After.Errors, targeting.ReasonContentUnavailable) || len(n[0].Removed) != 1 || n[0].Removed[0].Binding != "deny-all" {
		t.Fatalf("%+v", c.Namespaces)
	}
	// A broken live binding that the proposal does not touch is a limitation.
	w := newW().live(bindingWith("dangling", "ghost", "Audit", "{}"), "b-dangling", 1, 1)
	c = w.compare(mustSet(t, bindingWith("deny-all", "base", "Audit", "{}")), nil)
	if !c.Complete {
		t.Fatalf("%+v", c.Errors)
	}
	found := false
	for _, l := range c.Limitations {
		found = found || (l.Code == LimitBaselineUnresolved && l.Name == "dangling")
	}
	if !found {
		t.Fatalf("%+v", c.Limitations)
	}
	// A content source failure that is not "unavailable" is incomplete too.
	w = newW()
	w.content = fakeContent{}
	cmp, err := Compare(context.Background(), CompareInput{Snapshot: w.snap, Proposed: &Set{}, Content: failingContent{}})
	if err != nil || cmp.Complete || !slices.Contains(errorCodes(cmp.Errors), "content-failed:hardening@"+digestA) {
		t.Fatalf("%v %+v", err, cmp)
	}
	// Substituted content is refused.
	w = newW()
	cmp, _ = Compare(context.Background(), CompareInput{Snapshot: w.snap, Proposed: &Set{}, Content: substituting{newWorld(t).content}})
	if cmp.Complete || !slices.Contains(errorCodes(cmp.Errors), "content-mismatch:hardening@"+digestA) {
		t.Fatalf("%+v", cmp.Errors)
	}
}

type failingContent struct{}

func (failingContent) Content(context.Context, v1alpha1.BundleReference) (*targeting.Content, error) {
	return nil, os.ErrPermission
}

type substituting struct{ f fakeContent }

func (s substituting) Content(_ context.Context, ref v1alpha1.BundleReference) (*targeting.Content, error) {
	return s.f[v1alpha1.BundleReference{Name: ref.Name, Digest: digestB}], nil
}

// The adapter takes content only through targeting.ContentSource, so the
// controller's own verified vendored source plugs in unchanged: content is
// resolved by exact name and digest, and a pin it does not serve leaves the
// affected binding unresolved and the comparison incomplete.
func TestCompareThroughTheVendoredContentSource(t *testing.T) {
	src := targeting.LocalContent{Root: "../../content", Name: "konstapel-vendored",
		Policies: map[string]string{"disallow-privilege-escalation": "content/linux-hardening/variants/disallow-privilege-escalation.yaml"}}
	sums, err := os.ReadFile("../../content/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	vendored, err := src.Content(context.Background(), v1alpha1.BundleReference{Name: src.Name, Digest: "sha256:" + sha256Hex(sums)})
	if err != nil {
		t.Fatal(err)
	}
	profile := func(digest string) string {
		return "apiVersion: compliance.erenius.io/v1alpha1\nkind: ComplianceProfile\nmetadata:\n  name: vendored\nspec:\n  bundle: {name: konstapel-vendored, digest: " +
			digest + "}\n  policies:\n    - name: disallow-privilege-escalation\n"
	}
	w := newWorld(t).ns("prod", "prod-uid", map[string]string{"env": "production"}).
		live(profile(vendored.Bundle.Digest), "p-vendored", 1, 0).
		live(bindingWith("deny", "vendored", "Deny", "{}"), "b-deny", 1, 1)
	run := func(doc string) *Comparison {
		t.Helper()
		c, err := Compare(context.Background(), CompareInput{Snapshot: w.snap, Proposed: mustSet(t, doc), Content: src})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := run(bindingWith("deny", "vendored", "Audit", "{}"))
	if !c.Complete || !slices.Equal(categories(rowFor(t, c, "deny", "disallow-privilege-escalation")), []string{"mode-changed", "revision-replaced"}) {
		t.Fatalf("%+v", c)
	}
	c = run(profile("sha256:" + strings.Repeat("0", 64)))
	if c.Complete || !slices.Contains(errorCodes(c.Errors), "unresolved-candidate:deny") || !strings.Contains(c.Errors[0].Message, "ContentUnavailable") {
		t.Fatalf("%+v", c.Errors)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestCompareRequiresCompleteObservationAndContent(t *testing.T) {
	w := newWorld(t)
	if _, err := Compare(context.Background(), CompareInput{Snapshot: &Snapshot{}, Proposed: &Set{}, Content: w.content}); err == nil {
		t.Fatal("an incomplete observation was compared")
	}
	if _, err := Compare(context.Background(), CompareInput{Snapshot: w.snap, Proposed: &Set{}}); err == nil {
		t.Fatal("compared without a content source")
	}
}

// The adapter consumes a real observation: stored specs come from the API
// responses, so a restatement is a server no-op while a reorder-only edit of
// the same object is a revision replacement.
func TestCompareOnAnObservedSnapshot(t *testing.T) {
	f := baseline(t)
	snap, err := observe(t, f, nil)
	mustComplete(t, snap, err)
	if len(snap.Live.StoredSpecs) != 3 {
		t.Fatalf("stored specs: %v", snap.Live.StoredSpecs)
	}
	content := newWorld(t).content
	run := func(doc string) *Comparison {
		t.Helper()
		c, err := Compare(context.Background(), CompareInput{Snapshot: snap, Proposed: mustSet(t, doc), Content: content})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := run(bindingWith("b-prod", "shared", "Deny", "{matchLabels: {env: production}}"))
	if !c.Complete || c.ImpactCount != 0 || c.Objects[0].StoredSpec != StoredSpecEqual {
		t.Fatalf("%+v", c)
	}
	// The observed engine policy enforces a logical policy the live profile
	// no longer selects: not desired, and its removal is only requested.
	// The orphaned one is not attributable to the candidate.
	for _, p := range c.Applied.Policies {
		switch {
		case p.Binding == "b-prod" && (p.Condition != AppliedNotDesired || p.Proposed != OutcomeWithdrawalRequested):
			t.Fatalf("%+v", p)
		case p.Binding == "b-gone" && (p.Condition != AppliedOrphaned || p.Proposed != OutcomeNotAttributable):
			t.Fatalf("%+v", p)
		}
	}
	c = run(bindingWith("b-prod", "shared", "Deny", "{matchLabels: {env: production}, matchExpressions: [{key: a, operator: Exists}, {key: b, operator: Exists}]}"))
	if rowFor(t, c, "b-prod", "run-as-non-root").RevisionEffect != RevisionReplacement {
		t.Fatal("selector change")
	}
}

func TestStoredFormMirrorsServerDefaultsAndPruning(t *testing.T) {
	p := map[string]any{"bundle": map[string]any{"name": "h", "digest": digestA}, "policies": []any{
		map[string]any{"name": "a", "parameters": map[string]any{"k": nil}},
		map[string]any{"name": "b", "parameters": nil, "exceptions": map[string]any{}},
		map[string]any{"name": "c", "exceptions": nil}}}
	got := storedForm(KindProfile, p)
	pols := got["policies"].([]any)
	if v := pols[0].(map[string]any)["parameters"].(map[string]any); len(v) != 1 {
		t.Fatalf("nulls inside preserved parameters are kept: %v", v)
	}
	if _, has := pols[1].(map[string]any)["parameters"]; has {
		t.Fatal("a null parameters field is pruned")
	}
	for _, e := range pols {
		if e.(map[string]any)["exceptions"].(map[string]any)["eligibility"] != "Forbidden" {
			t.Fatalf("eligibility default: %v", e)
		}
	}
	if p["policies"].([]any)[2].(map[string]any)["exceptions"] != nil {
		t.Fatal("storedForm must not modify its input")
	}
	b := storedForm(KindBinding, map[string]any{"enforcementEpoch": int64(3), "mode": "Audit"})
	if _, has := b["enforcementEpoch"]; has || b["assessment"].(map[string]any)["interval"] != defaultInterval {
		t.Fatalf("%v", b)
	}
	if compareStored(KindBinding, nil, b) != StoredSpecUnknown || !enforcementFieldsChanged(nil, b) {
		t.Fatal("unknown live specs are never equal")
	}
}
