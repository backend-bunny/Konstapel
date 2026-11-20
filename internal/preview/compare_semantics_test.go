package preview

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"slices"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

var update = flag.Bool("update", false, "rewrite the comparison report fixtures in testdata/preview/compare")

// golden compares a comparison with its report fixture. The fixtures are
// the reviewed contract of the comparison model (the report schema itself
// is defined later, task 6.2).
func golden(t *testing.T, name string, c *Comparison) {
	t.Helper()
	got, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := "../../testdata/preview/compare/" + name + ".json"
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if string(got) != string(want) {
		t.Errorf("%s differs from the comparison; run with -update and review the diff\n%s", path, got)
	}
}

// overlapWorld: production and staging namespaces, one shared profile used
// by an Audit binding for every namespace and a Deny binding for production.
func overlapWorld(t *testing.T) *world {
	return newWorld(t).
		ns("prod", "prod-uid", map[string]string{"env": "production"}).
		ns("staging", "staging-uid", map[string]string{"env": "staging"}).
		ns("dev", "dev-uid", map[string]string{"env": "development"}).
		live(profileWith("shared", digestA, polRun+"      parameters: {runAsUser: 1000}\n    - name: privileged\n"), "p-shared", 3, 0).
		live(bindingWith("audit-all", "shared", "Audit", "{}"), "b-audit", 2, 2).
		live(bindingWith("deny-prod", "shared", "Deny", "{matchLabels: {env: production}}"), "b-deny", 5, 4)
}

// --- 3.2: stable comparisons and framework-neutral impact categories ---

// A selector that adds one observed namespace and removes another names both
// instances by name and UID with the affected binding and policies, and keeps
// the remaining overlapping contribution visible.
func TestCompareSelectorChangeNamesNamespacesAndRemainingOverlap(t *testing.T) {
	w := overlapWorld(t)
	c := w.compare(mustSet(t, bindingWith("deny-prod", "shared", "Deny", "{matchLabels: {env: staging}}")), nil)
	if !c.Complete {
		t.Fatal(c.Errors)
	}
	r := rowFor(t, c, "deny-prod", "run-as-non-root")
	if got := categories(r); !slices.Equal(got, []string{"selector-changed", "namespace-added", "namespace-removed", "revision-replaced"}) {
		t.Fatalf("categories %v", got)
	}
	if r.Key.BindingUID != "b-deny" || r.NamespacesAdded[0] != (targeting.NamespaceRef{Name: "staging", UID: "staging-uid"}) ||
		r.NamespacesRemoved[0] != (targeting.NamespaceRef{Name: "prod", UID: "prod-uid"}) || r.Responsible[0].Identity != "ComplianceBinding/deny-prod" {
		t.Fatalf("%+v", r)
	}
	for _, n := range c.Namespaces {
		if len(n.Remaining) != 1 || n.Remaining[0].Binding != "audit-all" || n.Remaining[0].RevisionEffect != RevisionUnchanged {
			t.Fatalf("remaining overlap: %+v", n)
		}
	}
	// Two policies x two rows, plus four namespace rows without eligibility impact.
	if c.ImpactCount != 2 || len(c.Namespaces) != 4 {
		t.Fatalf("impactCount %d, namespaces %+v", c.ImpactCount, c.Namespaces)
	}
	golden(t, "selector-change", c)
}

// Parameters, bundle pins, enforcement mode, exception rules and an added
// policy each have their own category, including on a binding that selects
// no namespace today.
func TestCompareCategoriesIncludingZeroTargets(t *testing.T) {
	w := overlapWorld(t).live(bindingWith("deny-none", "shared", "Deny", "{matchLabels: {env: nowhere}}"), "b-none", 1, 1)
	cases := []struct {
		name, doc, binding, policy string
		want                       []string
	}{
		{"parameters", profileWith("shared", digestA, polRun+"      parameters: {runAsUser: 2000}\n    - name: privileged\n"), "deny-none", "run-as-non-root",
			[]string{"parameters-changed", "revision-replaced"}},
		{"bundle-pin", profileWith("shared", digestB, polRun+"      parameters: {runAsUser: 1000}\n    - name: privileged\n"), "deny-none", "privileged",
			[]string{"bundle-pin-changed", "revision-replaced"}},
		{"exception-rule", profileWith("shared", digestA, polRun+"      parameters: {runAsUser: 1000}\n    - {name: privileged, exceptions: {eligibility: SelfService, maxLifetime: 24h}}\n"), "deny-none", "privileged",
			[]string{"exception-rule-changed", "revision-replaced"}},
		{"mode", bindingWith("deny-none", "shared", "Audit", "{matchLabels: {env: nowhere}}"), "deny-none", "privileged",
			[]string{"mode-changed", "revision-replaced"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := w.compare(mustSet(t, tc.doc), nil)
			r := rowFor(t, c, tc.binding, tc.policy)
			if got := categories(r); !slices.Equal(got, tc.want) || r.Before.TargetCount != 0 || r.After.TargetCount != 0 || !c.Complete || c.ImpactCount == 0 {
				t.Fatalf("%v %+v", got, r)
			}
		})
	}
	// Audit to Deny on a zero-target binding is reported with direction.
	c := w.compare(mustSet(t, bindingWith("deny-none", "shared", "Audit", "{matchLabels: {env: nowhere}}")), nil)
	if i := rowFor(t, c, "deny-none", "privileged").Impacts[0]; i.Before != "Deny" || i.After != "Audit" || i.Area != AreaEnforcement {
		t.Fatalf("%+v", i)
	}
	// A profile gaining a policy adds a contribution for every consumer.
	c = w.compare(mustSet(t, profileWith("shared", digestB, polRun+"      parameters: {runAsUser: 1000}\n    - name: privileged\n")), nil)
	if len(c.Contributions) != 6 {
		t.Fatalf("%d rows", len(c.Contributions))
	}
	golden(t, "zero-target-bundle-pin", c)
}

// Formatting, key order, written-out defaults, exported server metadata and
// status are no impact at all: not a configuration change and not stored
// differently.
func TestCompareMetadataAndOrderOnlyAreNoOps(t *testing.T) {
	w := overlapWorld(t)
	exported := `apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: deny-prod
  uid: copied-from-another-cluster
  generation: 99
  labels: {team: platform}
  annotations: {note: "reformatted"}
spec:
  namespaceSelector:
    matchLabels: {env: production}
  enforcementEpoch: 77
  assessment: {retention: 2160h, interval: 24h}
  mode: Deny
  profileRef: {name: shared}
status:
  observedGeneration: 99
---
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceProfile
metadata: {name: shared}
spec:
  policies:
    - parameters: {runAsUser: 1000}
      exceptions: {eligibility: Forbidden}
      name: run-as-non-root
    - {name: privileged, exceptions: {}}
  bundle: {digest: ` + digestA + `, name: hardening}
`
	c := w.compare(mustSet(t, exported), nil)
	if !c.Complete || c.ImpactCount != 0 || len(c.Contributions) != 0 || len(c.Namespaces) != 0 {
		t.Fatalf("%+v", c)
	}
	for _, o := range c.Objects {
		if o.Disposition != Unchanged || o.StoredSpec != StoredSpecEqual || o.ConfigurationChanged || o.PendingIdentity {
			t.Fatalf("%+v", o)
		}
	}
	if c.Objects[0].Observed.UID != "b-deny" || c.Objects[0].Observed.Generation != 5 {
		t.Fatalf("observed identity must come from the cluster: %+v", c.Objects[0].Observed)
	}
}

// --- 3.3: observed identity versus provisional resolver inputs (owner item A) ---

// serverApply applies a proposal the way the API server and the
// konstapel-binding-enforcement-epoch policy would: generation +1 when the
// stored spec changes, epoch +1 when the enforcement fields differ as
// written. Resolving the result with the real resolver gives the revisions
// the controller would compute after application.
func serverApply(t *testing.T, w *world, doc string) map[[2]string]string {
	t.Helper()
	o := mustSet(t, doc).Objects[0]
	live := *w.snap
	live.Live.Profiles = slices.Clone(w.snap.Live.Profiles)
	live.Live.Bindings = slices.Clone(w.snap.Live.Bindings)
	stored := w.snap.Live.StoredSpecs[o.Identity]
	if o.Profile != nil {
		for i, p := range live.Live.Profiles {
			if p.Name == o.Identity.Name {
				np := *o.Profile.DeepCopy()
				np.UID, np.Generation = p.UID, p.Generation
				if compareStored(KindProfile, stored, o.Spec) != StoredSpecEqual {
					np.Generation++
				}
				live.Live.Profiles[i] = np
			}
		}
	} else {
		for i, b := range live.Live.Bindings {
			if b.Name == o.Identity.Name {
				nb := *o.Binding.DeepCopy()
				nb.UID, nb.Generation, nb.Spec.EnforcementEpoch = b.UID, b.Generation, b.Spec.EnforcementEpoch
				if compareStored(KindBinding, stored, o.Spec) != StoredSpecEqual {
					nb.Generation++
				}
				if enforcementFieldsChanged(stored, o.Spec) {
					nb.Spec.EnforcementEpoch++
				}
				live.Live.Bindings[i] = nb
			}
		}
	}
	res := targeting.Resolve(targeting.Input{Cluster: live.Cluster, Bundles: []targeting.Bundle{w.content[v1alpha1.BundleReference{Name: "hardening", Digest: digestA}].Bundle,
		w.content[v1alpha1.BundleReference{Name: "hardening", Digest: digestB}].Bundle}, Profiles: live.Live.Profiles, Bindings: live.Live.Bindings, Namespaces: (&live).TargetingNamespaces()})
	out := map[[2]string]string{}
	for _, br := range res.Bindings {
		for _, c := range br.Contributions {
			out[[2]string{br.Binding.Name, c.Policy}] = c.Revision
		}
	}
	return out
}

func provisional(t *testing.T, w *world, doc string) map[[2]string]string {
	t.Helper()
	cand, err := BuildCandidate(w.snap.Live, mustSet(t, doc), nil)
	if err != nil {
		t.Fatal(err)
	}
	a := newAdapter(w.snap, cand)
	if err := a.resolve(context.Background(), w.content); err != nil {
		t.Fatal(err)
	}
	out := map[[2]string]string{}
	for k, c := range a.next.contribs {
		out[k] = c.Revision
	}
	return out
}

// The hazard behind item A, pinned: the configuration fingerprint ignores
// selector-expression order, but EnforcementRevision hashes the selector as
// written, so a reorder-only edit rotates the revision even at the same epoch.
func TestEnforcementRevisionSeesSelectorOrderThatTheFingerprintIgnores(t *testing.T) {
	a := bindingWith("b", "p", "Deny", "{matchExpressions: [{key: a, operator: Exists}, {key: b, operator: In, values: [p, q]}]}")
	b := bindingWith("b", "p", "Deny", "{matchExpressions: [{key: b, operator: In, values: [q, p]}, {key: a, operator: Exists}]}")
	oa, ob := mustSet(t, a).Objects[0], mustSet(t, b).Objects[0]
	if oa.Fingerprint != ob.Fingerprint {
		t.Fatal("the fingerprint is expected to treat these as equivalent")
	}
	in := func(s *v1alpha1.NamespaceSelector) string {
		return targeting.EnforcementRevision(targeting.EnforcementInput{Cluster: clusterID, BindingUID: "u", BindingEpoch: 3, ProfileUID: "p", ProfileGeneration: 1,
			Policy: "x", BundleDigest: digestA, ConfigurationDigest: digestB, Mode: v1alpha1.ModeDeny, NamespaceSelector: *s})
	}
	if in(oa.Binding.Spec.NamespaceSelector) == in(ob.Binding.Spec.NamespaceSelector) {
		t.Fatal("EnforcementRevision no longer hashes the selector as written; revisit RevisionEffect")
	}
	if !enforcementFieldsChanged(oa.Spec, ob.Spec) {
		t.Fatal("the epoch policy compares atomic lists in order")
	}
}

// Each case states whether the controller would rotate revisions after
// application; the preview must agree, using the real revision function with
// the server's generation and epoch rules, and never claim "unchanged" where
// the controller would replace a policy.
// revisionSelector is the live selector of revisionWorld's deny binding.
const revisionSelector = "{matchExpressions: [{key: env, operator: In, values: [production, staging]}, {key: tier, operator: Exists}]}"

// revisionWorld: one shared profile used by a Deny binding with a
// multi-expression selector, an Audit binding with an epoch, and a legacy
// Audit binding written before the enforcement-epoch policy existed.
func revisionWorld(t *testing.T) *world {
	return newWorld(t).ns("prod", "prod-uid", map[string]string{"env": "production", "tier": "web"}).
		live(profileWith("shared", digestA, polRun+"    - {name: privileged, exceptions: {eligibility: SelfService, maxLifetime: 1h}}\n"), "p-shared", 3, 0).
		live(bindingWith("deny", "shared", "Deny", revisionSelector), "b-deny", 4, 4).
		live(bindingWith("audit", "shared", "Audit", "{}"), "b-audit", 1, 1).
		live(bindingWith("legacy", "shared", "Audit", "{matchLabels: {env: production}}"), "b-legacy", 6, 0)
}

func TestRevisionEffectAgreesWithTheController(t *testing.T) {
	sel := revisionSelector
	base := func() *world { return revisionWorld(t) }
	cases := []struct {
		name string
		doc  string
		// want maps binding/policy rows to their effect; unlisted rows have none.
		want       map[string]RevisionEffect
		equivalent bool
		limitation bool
	}{
		{name: "reordered-selector-expressions",
			doc:  bindingWith("deny", "shared", "Deny", "{matchExpressions: [{key: tier, operator: Exists}, {key: env, operator: In, values: [production, staging]}]}"),
			want: map[string]RevisionEffect{"deny/privileged": RevisionReplacement, "deny/run-as-non-root": RevisionReplacement}, equivalent: true},
		{name: "reordered-selector-values",
			doc:  bindingWith("deny", "shared", "Deny", "{matchExpressions: [{key: env, operator: In, values: [staging, production]}, {key: tier, operator: Exists}]}"),
			want: map[string]RevisionEffect{"deny/privileged": RevisionReplacement, "deny/run-as-non-root": RevisionReplacement}, equivalent: true},
		{name: "default-equivalent-binding",
			doc: bindingWith("deny", "shared", "Deny", sel) + "  assessment: {interval: 24h, maxEvidenceAge: 2h}\n", want: map[string]RevisionEffect{}},
		{name: "default-equivalent-profile",
			doc:  profileWith("shared", digestA, "    - {name: run-as-non-root, exceptions: {eligibility: Forbidden}}\n    - {name: privileged, exceptions: {eligibility: SelfService, maxLifetime: 1h}}\n"),
			want: map[string]RevisionEffect{}},
		{name: "respelled-lifetime-shared-profile",
			doc: profileWith("shared", digestA, polRun+"    - {name: privileged, exceptions: {eligibility: SelfService, maxLifetime: 60m}}\n"),
			want: map[string]RevisionEffect{"deny/privileged": RevisionReplacement, "deny/run-as-non-root": RevisionReplacement, "audit/privileged": RevisionReplacement,
				"audit/run-as-non-root": RevisionReplacement, "legacy/privileged": RevisionReplacement, "legacy/run-as-non-root": RevisionReplacement}, equivalent: true},
		{name: "reordered-profile-policies",
			doc: profileWith("shared", digestA, "    - {name: privileged, exceptions: {eligibility: SelfService, maxLifetime: 1h}}\n"+polRun),
			want: map[string]RevisionEffect{"deny/privileged": RevisionReplacement, "deny/run-as-non-root": RevisionReplacement, "audit/privileged": RevisionReplacement,
				"audit/run-as-non-root": RevisionReplacement, "legacy/privileged": RevisionReplacement, "legacy/run-as-non-root": RevisionReplacement}, equivalent: true},
		{name: "reporting-only-with-epoch",
			doc: bindingWith("audit", "shared", "Audit", "{}") + "  assessment: {interval: 12h}\n", want: map[string]RevisionEffect{}},
		{name: "reporting-only-without-epoch",
			doc:  bindingWith("legacy", "shared", "Audit", "{matchLabels: {env: production}}") + "  assessment: {interval: 12h}\n",
			want: map[string]RevisionEffect{"legacy/privileged": RevisionReplacement, "legacy/run-as-non-root": RevisionReplacement}, equivalent: true, limitation: true},
		{name: "mode-change",
			doc:  bindingWith("audit", "shared", "Deny", "{}"),
			want: map[string]RevisionEffect{"audit/privileged": RevisionReplacement, "audit/run-as-non-root": RevisionReplacement}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := base()
			c := w.compare(mustSet(t, tc.doc), nil)
			if !c.Complete {
				t.Fatal(c.Errors)
			}
			got := map[string]RevisionEffect{}
			for _, r := range c.Contributions {
				got[r.Key.Binding+"/"+r.Key.Policy] = r.RevisionEffect
				if r.SemanticallyEquivalent != tc.equivalent || !slices.Contains(categories(r), string(CategoryRevision)) {
					t.Errorf("%s/%s: equivalent=%v categories=%v", r.Key.Binding, r.Key.Policy, r.SemanticallyEquivalent, categories(r))
				}
			}
			if len(got) != len(tc.want) {
				t.Fatalf("rows %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("%s: %s, want %s", k, got[k], v)
				}
			}
			if (c.ImpactCount > 0) != (len(tc.want) > 0) {
				t.Fatalf("impactCount %d", c.ImpactCount)
			}
			hasLimit := slices.ContainsFunc(c.Limitations, func(d Diagnostic) bool { return d.Code == LimitEpochUnavailable })
			if hasLimit != tc.limitation {
				t.Fatalf("epoch limitation %v", hasLimit)
			}
			// Where the epoch is observed, the provisional revisions equal what
			// the controller computes after the server applies the change.
			if !tc.limitation {
				after, prov := serverApply(t, w, tc.doc), provisional(t, w, tc.doc)
				for k, rev := range after {
					if prov[k] != rev {
						t.Errorf("%v: provisional revision differs from the controller's after application", k)
					}
				}
			}
		})
	}
}

// A rollback to earlier values replaces the revision although an older
// policy with those values is still applied, and does not revive it.
func TestRollbackRequiresANewRevision(t *testing.T) {
	w := newWorld(t).ns("prod", "prod-uid", map[string]string{"env": "production"}).
		live(profileWith("shared", digestA, polRun), "p-shared", 1, 0)
	// Epoch 1 was Audit; it was retained while the Deny replacement at epoch 2
	// is not ready yet.
	w.live(bindingWith("b", "shared", "Audit", "{}"), "b-uid", 1, 1).apply(true)
	old := w.snap.Applied[0]
	w.snap.Live.Bindings, w.snap.Applied = nil, nil
	w.live(bindingWith("b", "shared", "Deny", "{}"), "b-uid", 2, 2).apply(false)
	w.snap.Applied = append(w.snap.Applied, old)

	c := w.compare(mustSet(t, bindingWith("b", "shared", "Audit", "{}")), nil)
	r := rowFor(t, c, "b", "run-as-non-root")
	if r.RevisionEffect != RevisionReplacement || r.SemanticallyEquivalent || categories(r)[0] != string(CategoryMode) {
		t.Fatalf("%+v", r)
	}
	for _, p := range c.Applied.Policies {
		if p.Revision == old.Contribution.Revision && (p.Condition != AppliedSuperseded || p.Proposed != OutcomeReplaced) {
			t.Fatalf("the earlier Audit revision is not revived: %+v", p)
		}
		if p.Proposed == OutcomeKept {
			t.Fatalf("nothing is kept by a rollback: %+v", p)
		}
	}
}

// New objects report effects with pending identities only.
func TestNewObjectsHavePendingIdentity(t *testing.T) {
	w := newWorld(t).ns("prod", "prod-uid", map[string]string{"env": "production"})
	c := w.compare(mustSet(t, profileWith("fresh", digestA, polRun), bindingWith("fresh-b", "fresh", "Deny", "{}")), nil)
	r := rowFor(t, c, "fresh-b", "run-as-non-root")
	if r.Change != ChangeAdded || r.RevisionEffect != RevisionNew || r.Key.BindingUID != "" || r.After.TargetCount != 1 || r.Before != nil {
		t.Fatalf("%+v", r)
	}
	for _, o := range c.Objects {
		if o.Observed != nil || !o.PendingIdentity || o.Disposition != Created {
			t.Fatalf("%+v", o)
		}
	}
	if n := c.Namespaces[0]; n.Added[0].BindingUID != "" || n.Added[0].RevisionEffect != RevisionNew || n.Before != nil {
		t.Fatalf("%+v", n)
	}
	golden(t, "new-objects", c)
}

// --- 3.4: observed applied policies versus desired contributions ---

func appliedBy(t *testing.T, c *Comparison, binding string) []AppliedEntry {
	t.Helper()
	var out []AppliedEntry
	for _, p := range c.Applied.Policies {
		if p.Binding == binding {
			out = append(out, p)
		}
	}
	return out
}

func TestAppliedStateIsCorrelatedNotAssumed(t *testing.T) {
	w := overlapWorld(t).apply(true)
	// A retained earlier revision of deny-prod (an older selector, so a stale
	// scope), an orphaned policy, and a policy whose provenance is unreadable.
	stale := *w.snap.Applied[2].Contribution
	stale.Revision, stale.NamespaceSelector = "sha256:"+strings.Repeat("e", 64), v1alpha1.NamespaceSelector{MatchLabels: map[string]v1alpha1.LabelValue{"env": "staging"}}
	w.applyContribution(stale, true)
	gone := stale
	gone.Binding = targeting.ObjectRevision{Name: "deleted", UID: "b-deleted"}
	w.applyContribution(gone, true)
	w.snap.Applied[len(w.snap.Applied)-1].Ownership = Orphaned
	w.snap.Applied = append(w.snap.Applied, AppliedPolicy{ObjectRef: ObjectRef{Resource: resourceString(gvrEnginePolicy), Name: "konstapel-unreadable"}, BindingUID: "b-audit", Ownership: Owned, ProvenanceError: "missing annotations"})
	// audit-all's privileged policy is not ready yet: pending delivery.
	for i := range w.snap.Applied {
		if c := w.snap.Applied[i].Contribution; c != nil && c.Binding.Name == "audit-all" && c.Policy == "privileged" {
			w.snap.Applied[i].Ready = false
		}
	}

	// The proposal changes deny-prod's mode and removes audit-all.
	c := w.compare(mustSet(t, bindingWith("deny-prod", "shared", "Audit", "{matchLabels: {env: production}}")),
		mustSet(t, bindingWith("audit-all", "shared", "Audit", "{}"), bindingWith("deny-prod", "shared", "Deny", "{matchLabels: {env: production}}")))
	if !c.Complete {
		t.Fatal(c.Errors)
	}
	conds := map[string]string{}
	for _, p := range c.Applied.Policies {
		conds[p.Binding+"/"+p.Logical+"@"+p.Revision[:min(len(p.Revision), 12)]] = string(p.Condition) + "->" + string(p.Proposed)
		if p.Logical == "" && (p.Condition != AppliedUnknown || p.Proposed != OutcomeNotAttributable) {
			t.Fatalf("unreadable policy: %+v", p)
		}
		if p.Binding == "deleted" && (p.Condition != AppliedOrphaned || p.Proposed != OutcomeNotAttributable) {
			t.Fatalf("orphaned policy: %+v", p)
		}
	}
	for _, p := range appliedBy(t, c, "audit-all") {
		if p.Condition != AppliedCurrent || p.Proposed != OutcomeWithdrawalRequested {
			t.Fatalf("binding removal requests withdrawal: %+v", p)
		}
	}
	var superseded, current int
	for _, p := range appliedBy(t, c, "deny-prod") {
		switch p.Condition {
		case AppliedCurrent:
			current++
			if p.Proposed != OutcomeReplaced || p.Scope[0].Name != "prod" {
				t.Fatalf("pending replacement keeps the current policy enforcing: %+v", p)
			}
		case AppliedSuperseded:
			superseded++
			if p.Proposed != OutcomeReplaced || len(p.Scope) != 1 || p.Scope[0].Name != "staging" {
				t.Fatalf("retained revision and its stale scope: %+v", p)
			}
		default:
			t.Fatalf("%+v", p)
		}
	}
	if current != 2 || superseded != 1 {
		t.Fatalf("current %d superseded %d: %v", current, superseded, conds)
	}
	if len(c.Applied.Pending) != 1 || c.Applied.Pending[0].Key.Binding != "audit-all" || c.Applied.Pending[0].Key.Policy != "privileged" || !c.Applied.Pending[0].Applied {
		t.Fatalf("pending: %+v", c.Applied.Pending)
	}
	// The removal rows are withdrawal requests, never immediate absence.
	r := rowFor(t, c, "audit-all", "privileged")
	if r.Change != ChangeRemoved || !strings.Contains(r.Impacts[0].Reason, "not immediately") {
		t.Fatalf("%+v", r)
	}
	// Reconciliation lag (pending, superseded) adds no impact of its own:
	// only the configuration rows count.
	if c.ImpactCount != 4+countEligibilityRows(c) {
		t.Fatalf("impactCount %d", c.ImpactCount)
	}
	golden(t, "applied-state", c)
}

func countEligibilityRows(c *Comparison) int {
	n := 0
	for _, r := range c.Namespaces {
		if len(r.Impacts) > 0 {
			n++
		}
	}
	return n
}

// A live binding whose profile is gone holds its policies; removing a
// profile that a surviving binding references is refused before comparison,
// with the warning that applied policies may remain enforcing.
func TestUnresolvedProfileRemovalIsNotWithdrawal(t *testing.T) {
	w := overlapWorld(t).apply(true)
	_, err := Compare(context.Background(), CompareInput{Snapshot: w.snap, Proposed: &Set{}, Before: mustSet(t, profileWith("shared", digestA, polRun)), Content: w.content})
	ie, ok := err.(InputErrors)
	if !ok || ie[0].Code != CodeProfileRemoved || !strings.Contains(ie[0].Message, "may remain enforcing") {
		t.Fatalf("%v", err)
	}

	// Observed dangling profile: the controller holds what it applied. An
	// untouched dangling binding is a limitation of a complete comparison.
	w = overlapWorld(t).apply(true)
	w.snap.Live.Profiles = nil
	c := w.compare(&Set{}, nil)
	if !c.Complete || c.ImpactCount != 0 || !slices.ContainsFunc(c.Limitations, func(d Diagnostic) bool { return d.Code == LimitBaselineUnresolved && d.Name == "deny-prod" }) {
		t.Fatalf("%+v", c)
	}
	for _, p := range c.Applied.Policies {
		if p.Condition != AppliedHeld || p.Proposed != OutcomeHeld {
			t.Fatalf("%+v", p)
		}
	}
	if len(c.Applied.Pending) != 0 {
		t.Fatalf("unresolved desired state is not pending delivery: %+v", c.Applied.Pending)
	}
	// Restoring the profile affects bindings whose live contributions cannot
	// be determined: incomplete, and the held policies are replaced, not kept.
	c = w.compare(mustSet(t, profileWith("shared", digestA, polRun+"      parameters: {runAsUser: 1000}\n    - name: privileged\n")), nil)
	if c.Complete || !slices.Contains(errorCodes(c.Errors), "unresolved-baseline:deny-prod") {
		t.Fatalf("%+v", c.Errors)
	}
	for _, p := range c.Applied.Policies {
		if p.Condition != AppliedHeld || p.Proposed != OutcomeReplaced {
			t.Fatalf("%+v", p)
		}
	}
}

// Terminating bindings and namespaces are not part of the resolution, as in
// the controller; their policies are being withdrawn by garbage collection.
func TestTerminatingObjectsFollowTheController(t *testing.T) {
	w := overlapWorld(t).apply(true)
	w.snap.Namespaces[1].Terminating = true // staging
	now := w.snap.Live.Bindings[0].CreationTimestamp
	w.snap.Live.Bindings[0].DeletionTimestamp = &now // audit-all
	c := w.compare(&Set{}, nil)
	if !c.Complete || c.ImpactCount != 0 {
		t.Fatalf("%+v", c)
	}
	for _, p := range appliedBy(t, c, "audit-all") {
		if p.Condition != AppliedWithdrawing || p.Proposed != OutcomeNotAttributable {
			t.Fatalf("%+v", p)
		}
		for _, s := range p.Scope {
			if s.UID == types.UID("staging-uid") {
				t.Fatal("terminating namespaces are not in scope")
			}
		}
	}
}
