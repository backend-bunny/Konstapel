package targeting

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"os"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// evidenceFixture is the documented Audit-all/Deny-production example on the
// vendored content, plus a binding whose profile is missing.
func evidenceFixture(t *testing.T) (Input, map[string]*Content) {
	t.Helper()
	ref := v1alpha1.BundleReference{Name: "konstapel-vendored", Digest: vendoredDigest(t)}
	c, err := vendored().Content(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	p := profile("baseline", selfService(pol, 720*time.Hour))
	p.Spec.Bundle = ref
	in := Input{Cluster: "kube-system:fixture", Bundles: []Bundle{c.Bundle}, Profiles: []v1alpha1.ComplianceProfile{p},
		Bindings: []v1alpha1.ComplianceBinding{
			binding("audit-all", "baseline", v1alpha1.ModeAudit, v1alpha1.NamespaceSelector{}),
			binding("deny-production", "baseline", v1alpha1.ModeDeny, v1alpha1.NamespaceSelector{MatchLabels: map[string]v1alpha1.LabelValue{"environment": "production"}}),
			binding("dangling", "absent", v1alpha1.ModeDeny, v1alpha1.NamespaceSelector{}),
		},
		Namespaces: []Namespace{ns("shop-prod", "environment", "production"), ns("shop-dev", "environment", "development")}}
	return in, map[string]*Content{c.Bundle.Digest: c}
}

func TestExpectedEvidenceMatchesGolden(t *testing.T) {
	in, content := evidenceFixture(t)
	subjects, stale, err := ExpectedEvidence(Resolve(in), content)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.MarshalIndent(map[string]any{"contractVersion": ContractVersion, "subjects": subjects, "stale": stale}, "", "  ")
	got = append(got, '\n')
	path := "../../testdata/targeting/contract/evidence.json"
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(got) {
		t.Fatalf("expected-evidence contract changed. Bump ContractVersion if intended, then run go test ./internal/targeting -run TestExpectedEvidenceMatchesGolden -update\n%s", got)
	}
}

func TestExpectedEvidenceKeepsOverlapsDistinct(t *testing.T) {
	in, content := evidenceFixture(t)
	subjects, _, err := ExpectedEvidence(Resolve(in), content)
	if err != nil {
		t.Fatal(err)
	}
	var prod []EvidenceSubject
	for _, s := range subjects {
		if s.Namespace == "shop-prod" {
			prod = append(prod, s)
		}
	}
	if len(prod) != 2 || prod[0].LogicalPolicy != prod[1].LogicalPolicy {
		t.Fatalf("want two subjects for the same logical policy in shop-prod, got %+v", prod)
	}
	if prod[0].Revision == prod[1].Revision || prod[0].EnginePolicy == prod[1].EnginePolicy || prod[0].Mode == prod[1].Mode {
		t.Fatal("overlapping contributions must keep distinct revisions, engine policies and modes")
	}
	for _, s := range subjects {
		if len(s.Resources) == 0 || !strings.HasPrefix(s.EnginePolicy, "konstapel-") || s.SourceDigest == "" || s.Checks == nil {
			t.Fatalf("incomplete subject %+v", s)
		}
	}
	if !contains(subjects[0].Resources, "/v1/pods") || !contains(subjects[0].Resources, "apps/v1/deployments") || !contains(subjects[0].Resources, "/v1/pods/ephemeralcontainers") {
		t.Fatalf("resources %v", subjects[0].Resources)
	}
}

func TestExpectedEvidenceKeysByNamespaceUID(t *testing.T) {
	in, content := evidenceFixture(t)
	before, _, _ := ExpectedEvidence(Resolve(in), content)
	in.Namespaces[0].UID = types.UID("uid-shop-prod-recreated")
	after, _, _ := ExpectedEvidence(Resolve(in), content)
	for _, s := range after {
		if s.NamespaceUID == "uid-shop-prod" {
			t.Fatal("a recreated namespace reused the old subject UID")
		}
	}
	revs := func(ss []EvidenceSubject) map[string]bool {
		m := map[string]bool{}
		for _, s := range ss {
			m[s.Revision] = true
		}
		return m
	}
	if len(revs(before)) != len(revs(after)) {
		t.Fatal("namespace recreation must not change contribution revisions")
	}
}

func TestExpectedEvidenceReportsStaleScope(t *testing.T) {
	in, content := evidenceFixture(t)
	subjects, stale, err := ExpectedEvidence(Resolve(in), content)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 1 || stale[0].Binding.Name != "dangling" || stale[0].Reason != ReasonProfileNotFound || stale[0].Policy != "" {
		t.Fatalf("stale %+v", stale)
	}
	for _, s := range subjects {
		if s.BindingName == "dangling" {
			t.Fatal("a stale binding produced subjects")
		}
	}
}

func TestExpectedEvidenceRefusesMissingContent(t *testing.T) {
	in, _ := evidenceFixture(t)
	if _, _, err := ExpectedEvidence(Resolve(in), map[string]*Content{}); err == nil {
		t.Fatal("missing content must be an error, not a guess")
	}
}

func TestExpectedEvidenceIsOrderIndependent(t *testing.T) {
	in, content := evidenceFixture(t)
	want, _ := json.Marshal(must(ExpectedEvidence(Resolve(in), content)))
	rng := rand.New(rand.NewPCG(3, 4))
	for i := range 30 {
		got, _ := json.Marshal(must(ExpectedEvidence(Resolve(shuffled(in, rng)), content)))
		if string(got) != string(want) {
			t.Fatalf("permutation %d changed the output", i)
		}
	}
}

func must(s []EvidenceSubject, st []StaleScope, err error) any {
	if err != nil {
		panic(err)
	}
	return []any{s, st}
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}
