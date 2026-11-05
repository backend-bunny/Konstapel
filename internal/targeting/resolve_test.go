package targeting

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

const testDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func testBundle() Bundle {
	return Bundle{Name: "b", Digest: testDigest, Policies: []BundlePolicy{
		{Name: "p1", Scope: ScopeNamespaced},
		{Name: "p2", Scope: ScopeNamespaced},
		{Name: "cluster-check", Scope: ScopeCluster},
	}}
}

func profile(name string, policies ...v1alpha1.ProfilePolicy) v1alpha1.ComplianceProfile {
	p := v1alpha1.ComplianceProfile{}
	p.Name, p.UID, p.Generation = name, types.UID("uid-"+name), 1
	p.Spec.Bundle = v1alpha1.BundleReference{Name: "b", Digest: testDigest}
	p.Spec.Policies = policies
	return p
}

func selfService(name string, d time.Duration) v1alpha1.ProfilePolicy {
	return v1alpha1.ProfilePolicy{Name: name, Exceptions: v1alpha1.ExceptionSettings{
		Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: d}}}
}

func binding(name, profile string, mode v1alpha1.EnforcementMode, sel v1alpha1.NamespaceSelector) v1alpha1.ComplianceBinding {
	b := v1alpha1.ComplianceBinding{}
	b.Name, b.UID, b.Generation = name, types.UID("uid-"+name), 1
	b.Spec = v1alpha1.ComplianceBindingSpec{ProfileRef: v1alpha1.ProfileReference{Name: profile}, Mode: mode, NamespaceSelector: &sel}
	return b
}

func ns(name string, kv ...string) Namespace {
	l := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		l[kv[i]] = kv[i+1]
	}
	return Namespace{Name: name, UID: types.UID("uid-" + name), Labels: l}
}

func targetNames(r Result, binding string) []string {
	for _, b := range r.Bindings {
		if b.Binding.Name == binding {
			out := []string{}
			for _, t := range b.Targets {
				out = append(out, t.Name)
			}
			return out
		}
	}
	return nil
}

func TestSelectorSemantics(t *testing.T) {
	namespaces := []Namespace{
		ns("prod", "env", "production", "tier", "web"),
		ns("stage", "env", "staging"),
		ns("dev", "env", "development", "tier", "sandbox"),
		ns("bare"),
	}
	req := func(key string, op metav1.LabelSelectorOperator, values ...string) v1alpha1.NamespaceSelectorRequirement {
		return v1alpha1.NamespaceSelectorRequirement{Key: key, Operator: op, Values: values}
	}
	cases := []struct {
		name string
		sel  v1alpha1.NamespaceSelector
		want []string
	}{
		{"empty selects all, including unlabelled", v1alpha1.NamespaceSelector{}, []string{"bare", "dev", "prod", "stage"}},
		{"matchLabels", v1alpha1.NamespaceSelector{MatchLabels: map[string]v1alpha1.LabelValue{"env": "production"}}, []string{"prod"}},
		{"matchLabels are ANDed", v1alpha1.NamespaceSelector{MatchLabels: map[string]v1alpha1.LabelValue{"env": "production", "tier": "sandbox"}}, []string{}},
		{"In", v1alpha1.NamespaceSelector{MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{req("env", metav1.LabelSelectorOpIn, "production", "staging")}}, []string{"prod", "stage"}},
		{"NotIn includes namespaces without the key", v1alpha1.NamespaceSelector{MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{req("tier", metav1.LabelSelectorOpNotIn, "sandbox")}}, []string{"bare", "prod", "stage"}},
		{"Exists", v1alpha1.NamespaceSelector{MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{req("tier", metav1.LabelSelectorOpExists)}}, []string{"dev", "prod"}},
		{"DoesNotExist", v1alpha1.NamespaceSelector{MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{req("tier", metav1.LabelSelectorOpDoesNotExist)}}, []string{"bare", "stage"}},
		{"labels and expressions are ANDed", v1alpha1.NamespaceSelector{
			MatchLabels:      map[string]v1alpha1.LabelValue{"env": "production"},
			MatchExpressions: []v1alpha1.NamespaceSelectorRequirement{req("tier", metav1.LabelSelectorOpExists)},
		}, []string{"prod"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Resolve(Input{Bundles: []Bundle{testBundle()}, Profiles: []v1alpha1.ComplianceProfile{profile("pr", v1alpha1.ProfilePolicy{Name: "p1"})},
				Bindings: []v1alpha1.ComplianceBinding{binding("b", "pr", v1alpha1.ModeAudit, c.sel)}, Namespaces: namespaces})
			if got := targetNames(r, "b"); !slices.Equal(got, c.want) {
				t.Fatalf("targets %v, want %v", got, c.want)
			}
		})
	}
}

func TestNamespaceEventsChangeMembershipNotRevisions(t *testing.T) {
	in := Input{Cluster: "c", Bundles: []Bundle{testBundle()}, Profiles: []v1alpha1.ComplianceProfile{profile("pr", v1alpha1.ProfilePolicy{Name: "p1"})},
		Bindings: []v1alpha1.ComplianceBinding{binding("prod", "pr", v1alpha1.ModeDeny, v1alpha1.NamespaceSelector{MatchLabels: map[string]v1alpha1.LabelValue{"env": "production"}})}}
	revision := func(r Result) string { return r.Bindings[0].Contributions[0].Revision }

	in.Namespaces = []Namespace{ns("a", "env", "dev")}
	before := Resolve(in)
	in.Namespaces = append(in.Namespaces, ns("new", "env", "production")) // creation
	created := Resolve(in)
	in.Namespaces[0] = ns("a", "env", "production") // label change
	relabelled := Resolve(in)
	in.Namespaces = in.Namespaces[:1] // deletion of "new"
	deleted := Resolve(in)
	recreated := Resolve(Input{Cluster: in.Cluster, Bundles: in.Bundles, Profiles: in.Profiles, Bindings: in.Bindings,
		Namespaces: []Namespace{{Name: "a", UID: "uid-a-2", Labels: map[string]string{"env": "production"}}}})

	for _, step := range []struct {
		name string
		r    Result
		want []string
	}{{"before", before, []string{}}, {"created", created, []string{"new"}}, {"relabelled", relabelled, []string{"a", "new"}}, {"deleted", deleted, []string{"a"}}} {
		if got := targetNames(step.r, "prod"); !slices.Equal(got, step.want) {
			t.Errorf("%s: targets %v, want %v", step.name, got, step.want)
		}
		if step.r.Bindings[0].TargetCount != len(step.want) {
			t.Errorf("%s: targetCount %d", step.name, step.r.Bindings[0].TargetCount)
		}
		if revision(step.r) != revision(before) {
			t.Errorf("%s: membership change altered the configuration revision", step.name)
		}
	}
	if recreated.Bindings[0].Targets[0].UID != "uid-a-2" || recreated.Eligibility[0].Namespace.UID != "uid-a-2" {
		t.Error("a recreated namespace must be identified by its new UID")
	}
}

func TestAuditNeverRemovesDeny(t *testing.T) {
	all := v1alpha1.NamespaceSelector{}
	base := Input{Cluster: "c", Bundles: []Bundle{testBundle()},
		Profiles:   []v1alpha1.ComplianceProfile{profile("strict", v1alpha1.ProfilePolicy{Name: "p1"}), profile("lenient", selfService("p1", time.Hour), selfService("p2", time.Hour))},
		Bindings:   []v1alpha1.ComplianceBinding{binding("deny", "strict", v1alpha1.ModeDeny, all)},
		Namespaces: []Namespace{ns("x"), ns("y", "env", "production")}}
	denyContributions := func(r Result) []string {
		var out []string
		for _, b := range r.Bindings {
			for _, c := range b.Contributions {
				if c.Mode == v1alpha1.ModeDeny {
					out = append(out, c.Binding.Name+"/"+c.Policy+"/"+c.Revision)
				}
			}
		}
		slices.Sort(out)
		return out
	}
	want := denyContributions(Resolve(base))
	rng := rand.New(rand.NewPCG(7, 7))
	for i := range 200 {
		in := base
		in.Bindings = slices.Clone(base.Bindings)
		for j := range rng.IntN(4) + 1 {
			sel := all
			if rng.IntN(2) == 0 {
				sel = v1alpha1.NamespaceSelector{MatchLabels: map[string]v1alpha1.LabelValue{"env": "production"}}
			}
			in.Bindings = append(in.Bindings, binding(fmt.Sprintf("audit-%d", j), []string{"strict", "lenient"}[rng.IntN(2)], v1alpha1.ModeAudit, sel))
		}
		if got := denyContributions(Resolve(shuffled(in, rng))); !slices.Equal(got, want) {
			t.Fatalf("case %d: adding Audit bindings changed Deny contributions: %v, want %v", i, got, want)
		}
	}
}

func TestInvalidOrUnresolvedConfigurationNeverAuthorizesExceptions(t *testing.T) {
	all := v1alpha1.NamespaceSelector{}
	ok := binding("ok", "ss", v1alpha1.ModeDeny, all)
	okProfile := profile("ss", selfService("p1", time.Hour))
	cases := map[string]struct {
		profiles []v1alpha1.ComplianceProfile
		bindings []v1alpha1.ComplianceBinding
		bundles  []Bundle
	}{
		"restrictive Audit binding": {
			profiles: []v1alpha1.ComplianceProfile{okProfile, profile("forbid", v1alpha1.ProfilePolicy{Name: "p1"})},
			bindings: []v1alpha1.ComplianceBinding{ok, binding("audit", "forbid", v1alpha1.ModeAudit, all)},
		},
		"missing profile on another matching binding": {
			profiles: []v1alpha1.ComplianceProfile{okProfile},
			bindings: []v1alpha1.ComplianceBinding{ok, binding("dangling", "absent", v1alpha1.ModeAudit, all)},
		},
		"unavailable content on another matching binding": {
			profiles: []v1alpha1.ComplianceProfile{okProfile, func() v1alpha1.ComplianceProfile {
				p := profile("other", selfService("p1", time.Hour))
				p.Spec.Bundle.Digest = "sha256:" + fmt.Sprintf("%064d", 2)
				return p
			}()},
			bindings: []v1alpha1.ComplianceBinding{ok, binding("other", "other", v1alpha1.ModeAudit, all)},
		},
		"SelfService without a lifetime (bypassed admission)": {
			profiles: []v1alpha1.ComplianceProfile{okProfile, profile("bad", v1alpha1.ProfilePolicy{Name: "p1", Exceptions: v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService}})},
			bindings: []v1alpha1.ComplianceBinding{ok, binding("bad", "bad", v1alpha1.ModeAudit, all)},
		},
		"nonpositive lifetime (bypassed admission)": {
			profiles: []v1alpha1.ComplianceProfile{okProfile, profile("neg", selfService("p1", -time.Hour))},
			bindings: []v1alpha1.ComplianceBinding{ok, binding("neg", "neg", v1alpha1.ModeAudit, all)},
		},
		"unknown eligibility value": {
			profiles: []v1alpha1.ComplianceProfile{okProfile, profile("weird", v1alpha1.ProfilePolicy{Name: "p1", Exceptions: v1alpha1.ExceptionSettings{Eligibility: "Always"}})},
			bindings: []v1alpha1.ComplianceBinding{ok, binding("weird", "weird", v1alpha1.ModeAudit, all)},
		},
		"invalid parameters": {
			profiles: []v1alpha1.ComplianceProfile{okProfile, profile("params", v1alpha1.ProfilePolicy{Name: "p1", Parameters: &apiextensionsv1.JSON{Raw: []byte("{")},
				Exceptions: v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: time.Hour}}})},
			bindings: []v1alpha1.ComplianceBinding{ok, binding("params", "params", v1alpha1.ModeAudit, all)},
		},
		"bundle name does not match the pinned digest": {
			profiles: []v1alpha1.ComplianceProfile{okProfile, func() v1alpha1.ComplianceProfile {
				p := profile("renamed", selfService("p1", time.Hour))
				p.Spec.Bundle.Name = "something-else"
				return p
			}()},
			bindings: []v1alpha1.ComplianceBinding{ok, binding("renamed", "renamed", v1alpha1.ModeAudit, all)},
		},
	}
	// The baseline grants SelfService, so each case shows the added
	// configuration is what forbids.
	baseline := Resolve(Input{Bundles: []Bundle{testBundle()}, Profiles: []v1alpha1.ComplianceProfile{okProfile}, Bindings: []v1alpha1.ComplianceBinding{ok}, Namespaces: []Namespace{ns("x")}})
	if baseline.Eligibility[0].Effective != v1alpha1.ExceptionsSelfService {
		t.Fatalf("baseline should allow SelfService: %+v", baseline.Eligibility)
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			bundles := c.bundles
			if bundles == nil {
				bundles = []Bundle{testBundle()}
			}
			r := Resolve(Input{Bundles: bundles, Profiles: c.profiles, Bindings: c.bindings, Namespaces: []Namespace{ns("x")}})
			for _, e := range r.Eligibility {
				if e.Policy == "p1" {
					if e.Effective != v1alpha1.ExceptionsForbidden || e.MaxLifetime != nil {
						t.Fatalf("eligibility %s with lifetime %v, want Forbidden", e.Effective, e.MaxLifetime)
					}
					return
				}
			}
			t.Fatal("no eligibility result for p1")
		})
	}
}

func TestClusterScopedChecksAreNeverContributed(t *testing.T) {
	r := Resolve(Input{Bundles: []Bundle{testBundle()},
		Profiles:   []v1alpha1.ComplianceProfile{profile("pr", v1alpha1.ProfilePolicy{Name: "cluster-check"})},
		Bindings:   []v1alpha1.ComplianceBinding{binding("everything", "pr", v1alpha1.ModeDeny, v1alpha1.NamespaceSelector{})},
		Namespaces: []Namespace{ns("x")}})
	b := r.Bindings[0]
	if len(b.Contributions) != 0 {
		t.Fatalf("cluster-scoped check contributed: %+v", b.Contributions)
	}
	if len(b.Errors) != 1 || b.Errors[0].Reason != ReasonUnsupportedScope || b.Errors[0].Policy != "cluster-check" {
		t.Fatalf("want one UnsupportedScope error, got %+v", b.Errors)
	}
}

func TestZeroTargetsIsExplicit(t *testing.T) {
	r := Resolve(Input{Bundles: []Bundle{testBundle()},
		Profiles: []v1alpha1.ComplianceProfile{profile("pr", v1alpha1.ProfilePolicy{Name: "p1"})},
		Bindings: []v1alpha1.ComplianceBinding{binding("none", "pr", v1alpha1.ModeDeny, v1alpha1.NamespaceSelector{MatchLabels: map[string]v1alpha1.LabelValue{"env": "nowhere"}})}})
	b := r.Bindings[0]
	if b.TargetCount != 0 || b.Targets == nil || len(b.Errors) != 0 {
		t.Fatalf("want an explicit, error-free zero: %+v", b)
	}
	if len(b.Contributions) != 1 {
		t.Fatal("a zero-target binding still contributes, so namespaces created later are enforced")
	}
	if len(r.Eligibility) != 0 {
		t.Fatal("no namespace, no eligibility")
	}
}

func TestNilSelectorIsAnErrorNotEverything(t *testing.T) {
	b := binding("nil", "pr", v1alpha1.ModeDeny, v1alpha1.NamespaceSelector{})
	b.Spec.NamespaceSelector = nil
	r := Resolve(Input{Bundles: []Bundle{testBundle()}, Profiles: []v1alpha1.ComplianceProfile{profile("pr", v1alpha1.ProfilePolicy{Name: "p1"})},
		Bindings: []v1alpha1.ComplianceBinding{b}, Namespaces: []Namespace{ns("x")}})
	got := r.Bindings[0]
	if len(got.Targets) != 0 || len(got.Contributions) != 0 || len(got.Errors) != 1 || got.Errors[0].Reason != ReasonInvalidSelector {
		t.Fatalf("nil selector must resolve to an InvalidSelector error: %+v", got)
	}
}

func TestContributionsCarryProvenance(t *testing.T) {
	p := profile("pr", selfService("p1", time.Hour))
	p.Generation = 4
	b := binding("b", "pr", v1alpha1.ModeDeny, v1alpha1.NamespaceSelector{})
	b.Generation = 9
	r := Resolve(Input{Cluster: "kube-system:abc", Bundles: []Bundle{testBundle()}, Profiles: []v1alpha1.ComplianceProfile{p}, Bindings: []v1alpha1.ComplianceBinding{b}})
	c := r.Bindings[0].Contributions[0]
	cfg, _ := ConfigurationDigest(p.Spec.Policies[0])
	want := EnforcementRevision(EnforcementInput{Cluster: "kube-system:abc", BindingUID: b.UID, BindingEpoch: 9, ProfileUID: p.UID, ProfileGeneration: 4,
		Policy: "p1", BundleDigest: testDigest, ConfigurationDigest: cfg, Mode: v1alpha1.ModeDeny, NamespaceSelector: v1alpha1.NamespaceSelector{}})
	if c.Cluster != "kube-system:abc" || c.Binding.Generation != 9 || c.Profile.Generation != 4 || c.BundleName != "b" || c.BundleDigest != testDigest || c.ConfigurationDigest != cfg || c.Revision != want {
		t.Fatalf("provenance mismatch: %+v", c)
	}
}
