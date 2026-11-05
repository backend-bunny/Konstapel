package targeting

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func baseInput() EnforcementInput {
	return EnforcementInput{
		Cluster:             "kube-system:cluster-a",
		BindingUID:          "b-deny",
		BindingEpoch:        1,
		ProfileUID:          "p-baseline",
		ProfileGeneration:   1,
		Policy:              "disallow-privileged-containers",
		BundleDigest:        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		ConfigurationDigest: "sha256:aaaa",
		Mode:                v1alpha1.ModeDeny,
		NamespaceSelector:   v1alpha1.NamespaceSelector{MatchLabels: map[string]v1alpha1.LabelValue{"environment": "production"}},
	}
}

// The revision is pinned. Changing the algorithm or EnforcementInput
// invalidates every delivered engine policy name and exception acceptance,
// so it needs a ContractVersion bump and a deliberate update here.
const pinnedRevision = "sha256:2b1aaa92f68084acd6264719ad2a1b87bf94a37e67ca687f53446df757984338"

func TestEnforcementRevisionIsPinned(t *testing.T) {
	if got := EnforcementRevision(baseInput()); got != pinnedRevision {
		t.Fatalf("EnforcementRevision changed: got %s", got)
	}
}

func TestEnforcementRevisionChangesWithEveryEnforcementInput(t *testing.T) {
	base := EnforcementRevision(baseInput())
	mutations := map[string]func(*EnforcementInput){
		"cluster":              func(i *EnforcementInput) { i.Cluster = "kube-system:cluster-b" },
		"binding uid":          func(i *EnforcementInput) { i.BindingUID = "b-other" },
		"binding epoch":        func(i *EnforcementInput) { i.BindingEpoch = 2 },
		"profile uid":          func(i *EnforcementInput) { i.ProfileUID = "p-other" },
		"profile generation":   func(i *EnforcementInput) { i.ProfileGeneration = 2 },
		"policy":               func(i *EnforcementInput) { i.Policy = "restrict-capabilities" },
		"bundle digest":        func(i *EnforcementInput) { i.BundleDigest = "sha256:2222" },
		"configuration digest": func(i *EnforcementInput) { i.ConfigurationDigest = "sha256:bbbb" },
		"mode":                 func(i *EnforcementInput) { i.Mode = v1alpha1.ModeAudit },
		"selector":             func(i *EnforcementInput) { i.NamespaceSelector = v1alpha1.NamespaceSelector{} },
	}
	seen := map[string]string{base: "base"}
	for name, mutate := range mutations {
		in := baseInput()
		mutate(&in)
		got := EnforcementRevision(in)
		if prev, dup := seen[got]; dup {
			t.Errorf("%s: revision collides with %s", name, prev)
		}
		seen[got] = name
	}
}

func TestRollbackToEarlierSpecValuesYieldsANewRevision(t *testing.T) {
	// A -> B -> A: spec values return to A, but the epoch has advanced.
	a := baseInput()
	b := baseInput()
	b.BindingEpoch, b.Mode = 2, v1alpha1.ModeAudit
	aAgain := baseInput()
	aAgain.BindingEpoch = 3
	if EnforcementRevision(aAgain) == EnforcementRevision(a) || EnforcementRevision(aAgain) == EnforcementRevision(b) {
		t.Fatal("rollback reused an earlier revision")
	}
}

func TestConfigurationDigest(t *testing.T) {
	policy := func(params string, ex v1alpha1.ExceptionSettings) v1alpha1.ProfilePolicy {
		p := v1alpha1.ProfilePolicy{Name: "restrict-capabilities", Exceptions: ex}
		if params != "" {
			p.Parameters = &apiextensionsv1.JSON{Raw: []byte(params)}
		}
		return p
	}
	week := &metav1.Duration{Duration: 168 * time.Hour}
	ss := v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: week}
	d := func(p v1alpha1.ProfilePolicy) string {
		s, err := ConfigurationDigest(p)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if d(policy(`{"a":1,"b":[2]}`, ss)) != d(policy(`{ "b":[2], "a":1 }`, ss)) {
		t.Error("parameter key order or whitespace changed the digest")
	}
	if d(policy(`{"a":1}`, ss)) == d(policy(`{"a":2}`, ss)) {
		t.Error("parameter change did not change the digest")
	}
	if d(policy("", v1alpha1.ExceptionSettings{})) != d(policy("", v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsForbidden})) {
		t.Error("absent eligibility must equal the Forbidden default")
	}
	month := ss
	month.MaxLifetime = &metav1.Duration{Duration: 720 * time.Hour}
	if d(policy("", ss)) == d(policy("", month)) {
		t.Error("exception lifetime change did not change the digest")
	}
	if _, err := ConfigurationDigest(policy(`{`, ss)); err == nil {
		t.Error("invalid parameter JSON accepted")
	}
}

// The serialized contract is what dependent changes consume. The golden file
// must round-trip without loss and keep its field names.
func TestContractRoundTrip(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/targeting/contract/result.json")
	if err != nil {
		t.Fatal(err)
	}
	var r Result
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		t.Fatal(err)
	}
	if r.ContractVersion != ContractVersion {
		t.Fatalf("contractVersion %d, want %d", r.ContractVersion, ContractVersion)
	}
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(out)+"\n" != string(raw) {
		t.Fatalf("round trip changed the contract:\n%s", out)
	}
	c := r.Bindings[0].Contributions[0]
	in := baseInput()
	in.ConfigurationDigest = c.ConfigurationDigest
	if c.Revision != EnforcementRevision(in) {
		t.Errorf("golden contribution revision is stale; want %s", EnforcementRevision(in))
	}
	e := r.Eligibility[0]
	if e.Effective != v1alpha1.ExceptionsSelfService || e.MaxLifetime == nil || e.MaxLifetime.Duration != 168*time.Hour {
		t.Errorf("eligibility did not survive the round trip: %+v", e)
	}
}
