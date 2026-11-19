package preview

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func mustSet(t *testing.T, docs ...string) *Set {
	t.Helper()
	objs, errs := Parse("set.yaml", []byte(strings.Join(docs, "---\n")), Limits{})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	return newSet(objs)
}

func liveProfile(t *testing.T, name string, uid string, gen int64) v1alpha1.ComplianceProfile {
	t.Helper()
	p := mustSet(t, profileYAML(name)).Objects[0].Profile.DeepCopy()
	p.UID, p.Generation, p.ResourceVersion = types.UID(uid), gen, "5"
	return *p
}

func liveBinding(t *testing.T, name, profile, mode, uid string, epoch int64) v1alpha1.ComplianceBinding {
	t.Helper()
	b := mustSet(t, bindingYAML(name, profile, mode)).Objects[0].Binding.DeepCopy()
	b.UID, b.Generation = types.UID(uid), epoch
	b.Spec.EnforcementEpoch = epoch
	return *b
}

func dispositions(c *Candidate) string {
	var out []string
	for _, e := range c.Entries {
		out = append(out, e.Identity.String()+"="+string(e.Disposition))
	}
	return strings.Join(out, " ")
}

func liveFixture(t *testing.T) Live {
	return Live{
		Profiles: []v1alpha1.ComplianceProfile{liveProfile(t, "base", "p-1", 3), liveProfile(t, "strict", "p-2", 1)},
		Bindings: []v1alpha1.ComplianceBinding{
			liveBinding(t, "audit-all", "base", "Audit", "b-1", 2),
			liveBinding(t, "deny-prod", "strict", "Deny", "b-2", 4),
		},
	}
}

func TestCandidatePartialInputPreservesUnrelatedObjects(t *testing.T) {
	live := liveFixture(t)
	proposed := mustSet(t, bindingYAML("audit-all", "base", "Deny"))
	c, err := BuildCandidate(live, proposed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := dispositions(c); got != "ComplianceBinding/audit-all=replaced ComplianceBinding/deny-prod=unchanged ComplianceProfile/base=unchanged ComplianceProfile/strict=unchanged" {
		t.Fatal(got)
	}
	if len(c.Profiles) != 2 || len(c.Bindings) != 2 {
		t.Fatalf("survivors: %d profiles %d bindings", len(c.Profiles), len(c.Bindings))
	}
	// Unchanged objects keep their observed identity.
	if c.Bindings[1].UID != "b-2" || c.Profiles[0].UID != "p-1" {
		t.Fatalf("observed identity lost: %+v %+v", c.Bindings[1].ObjectMeta, c.Profiles[0].ObjectMeta)
	}
	// The replaced object carries the proposed spec and NO observed identity,
	// so it can never be mistaken for the live revision.
	r := c.Bindings[0]
	if r.Spec.Mode != v1alpha1.ModeDeny || r.UID != "" || r.Generation != 0 || r.Spec.EnforcementEpoch != 0 || r.ResourceVersion != "" {
		t.Fatalf("replaced object: %+v", r)
	}
	e := c.Entries[0]
	if e.LiveBinding == nil || e.LiveBinding.UID != "b-1" || e.LiveFingerprint == e.CandidateFingerprint {
		t.Fatalf("entry sides: %+v", e)
	}
}

func TestCandidateEmptyProposedRemovesOnlyDeclaredIdentities(t *testing.T) {
	live := liveFixture(t)
	before := mustSet(t, profileYAML("base"), bindingYAML("audit-all", "base", "Audit"), bindingYAML("gone-already", "base", "Audit"))
	c, err := BuildCandidate(live, &Set{}, before)
	if err != nil {
		t.Fatal(err)
	}
	if got := dispositions(c); got != "ComplianceBinding/audit-all=removed ComplianceBinding/deny-prod=unchanged ComplianceProfile/base=removed ComplianceProfile/strict=unchanged" {
		t.Fatal(got)
	}
	if len(c.AbsentRemovals) != 1 || c.AbsentRemovals[0].Name != "gone-already" {
		t.Fatalf("absent removals: %+v", c.AbsentRemovals)
	}
	if len(c.Profiles) != 1 || c.Profiles[0].Name != "strict" || len(c.Bindings) != 1 || c.Bindings[0].Name != "deny-prod" {
		t.Fatalf("survivors: %+v %+v", c.Profiles, c.Bindings)
	}
	// Removal provenance is the previous set, not the live object.
	if c.Entries[0].Before == nil || c.Entries[0].Before.Source != "set.yaml" || c.Entries[0].Proposed != nil || c.Entries[0].CandidateFingerprint != "" {
		t.Fatalf("%+v", c.Entries[0])
	}
}

func TestCandidateAbsentRemovalIsNotAnImpact(t *testing.T) {
	live := Live{}
	before := mustSet(t, bindingYAML("never-existed", "p", "Audit"))
	c, err := BuildCandidate(live, &Set{}, before)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Entries) != 0 || len(c.AbsentRemovals) != 1 {
		t.Fatalf("%+v", c)
	}
}

func TestCandidateBeforeIsNotTheBaseline(t *testing.T) {
	// The previous set says Deny; live says Audit. Restating Audit is a no-op
	// against live even though it differs from the previous file.
	live := liveFixture(t)
	before := mustSet(t, bindingYAML("audit-all", "base", "Deny"))
	proposed := mustSet(t, bindingYAML("audit-all", "base", "Audit"))
	c, err := BuildCandidate(live, proposed, before)
	if err != nil {
		t.Fatal(err)
	}
	if c.Entries[0].Disposition != Unchanged || c.Bindings[0].UID != "b-1" {
		t.Fatalf("%+v", c.Entries[0])
	}
}

func TestCandidateProposedEqualToLiveIsNoOpEvenWithServerDecoration(t *testing.T) {
	live := liveFixture(t)
	exported := bindingYAML("audit-all", "base", "Audit")
	exported = strings.Replace(exported, "metadata:\n  name: audit-all\n", "metadata:\n  name: audit-all\n  uid: other\n  generation: 99\n", 1) + "status: {observedGeneration: 99}\n"
	exported = strings.Replace(exported, "mode: Audit\n", "mode: Audit\n  enforcementEpoch: 55\n  assessment: {interval: 24h, retention: 2160h}\n", 1)
	c, err := BuildCandidate(live, mustSet(t, exported), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Entries[0].Disposition != Unchanged {
		t.Fatalf("exported copy of the live object is not a no-op: %s", dispositions(c))
	}
}

func TestCandidateCreatedHasPendingIdentity(t *testing.T) {
	c, err := BuildCandidate(Live{}, mustSet(t, profileYAML("new"), bindingYAML("new-b", "new", "Audit")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := dispositions(c); got != "ComplianceBinding/new-b=created ComplianceProfile/new=created" {
		t.Fatal(got)
	}
	if c.Entries[0].LiveBinding != nil || c.Entries[0].LiveFingerprint != "" || c.Bindings[0].UID != "" {
		t.Fatalf("%+v", c.Entries[0])
	}
}

func TestCandidateDeletedReferencedProfileIsAttributableError(t *testing.T) {
	live := liveFixture(t)
	before := mustSet(t, profileYAML("base"))
	_, err := BuildCandidate(live, &Set{}, before)
	ie, ok := err.(InputErrors)
	if !ok || len(ie) != 1 {
		t.Fatalf("err = %v", err)
	}
	e := ie[0]
	if e.Code != CodeProfileRemoved || e.Identity != "ComplianceBinding/audit-all" || e.Field != "spec.profileRef.name" || !strings.Contains(e.Message, `"base"`) || !strings.Contains(e.Message, "may remain enforcing") {
		t.Fatalf("%+v", e)
	}
	// Removing the binding as well is a valid candidate.
	before = mustSet(t, profileYAML("base"), bindingYAML("audit-all", "base", "Audit"))
	if _, err := BuildCandidate(live, &Set{}, before); err != nil {
		t.Fatal(err)
	}
	// A proposed binding that still references the removed profile is also attributed.
	_, err = BuildCandidate(live, mustSet(t, bindingYAML("audit-all", "base", "Deny")), mustSet(t, profileYAML("base"), bindingYAML("audit-all", "base", "Audit")))
	if ie, ok := err.(InputErrors); !ok || len(ie) != 1 || ie[0].Code != CodeProfileRemoved || ie[0].Source != "set.yaml" {
		t.Fatalf("%v", err)
	}
}

func TestCandidateMissingProfileAttribution(t *testing.T) {
	// A proposed binding referencing a profile that exists nowhere is an input error.
	_, err := BuildCandidate(liveFixture(t), mustSet(t, bindingYAML("fresh", "nope", "Audit")), nil)
	if ie, ok := err.(InputErrors); !ok || len(ie) != 1 || ie[0].Code != CodeProfileNotFound || ie[0].Identity != "ComplianceBinding/fresh" {
		t.Fatalf("%v", err)
	}
	// A pre-existing dangling live reference not touched by the proposal is a
	// baseline condition for the resolver, not an input error.
	live := liveFixture(t)
	live.Bindings = append(live.Bindings, liveBinding(t, "dangling", "ghost", "Audit", "b-9", 1))
	if _, err := BuildCandidate(live, mustSet(t, bindingYAML("audit-all", "base", "Deny")), nil); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateDuplicateLiveObjectsAreRefused(t *testing.T) {
	live := liveFixture(t)
	live.Bindings = append(live.Bindings, live.Bindings[0])
	live.Profiles = append(live.Profiles, live.Profiles[0])
	_, err := BuildCandidate(live, &Set{}, nil)
	if ie, ok := err.(InputErrors); !ok || len(ie) != 2 || ie[0].Code != CodeDuplicateLive {
		t.Fatalf("%v", err)
	}
}

func TestCandidateIsDeterministicAndDoesNotAliasInputs(t *testing.T) {
	live := liveFixture(t)
	proposed := mustSet(t, bindingYAML("audit-all", "base", "Deny"))
	a, _ := BuildCandidate(live, proposed, nil)
	rev := Live{Profiles: []v1alpha1.ComplianceProfile{live.Profiles[1], live.Profiles[0]}, Bindings: []v1alpha1.ComplianceBinding{live.Bindings[1], live.Bindings[0]}}
	b, _ := BuildCandidate(rev, proposed, nil)
	if dispositions(a) != dispositions(b) || a.Bindings[0].Name != b.Bindings[0].Name {
		t.Fatal("order of live objects changed the candidate")
	}
	a.Bindings[1].Spec.Mode = "Mutated"
	if live.Bindings[1].Spec.Mode == "Mutated" {
		t.Fatal("candidate aliases the observed object")
	}
	a.Bindings[0].Spec.Mode = "Mutated"
	if proposed.Objects[0].Binding.Spec.Mode == "Mutated" {
		t.Fatal("candidate aliases the proposed object")
	}
}
