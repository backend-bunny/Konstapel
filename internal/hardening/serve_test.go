package hardening

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Task 3.1: the four variants are served by the vendored bundle next to the
// first loop's privileged check (composed by reference, not copied), and
// their identities and digests survive packaging and rendering.

func served(t *testing.T) (*targeting.Content, v1alpha1.BundleReference) {
	t.Helper()
	sums, err := os.ReadFile(filepath.Join(root, "content/SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	ref := v1alpha1.BundleReference{Name: "konstapel-vendored", Digest: "sha256:" + hexSum(sums)}
	lc := targeting.LocalContent{Root: filepath.Join(root, "content"), Name: ref.Name, Policies: assessment.ShippedPolicies}
	c, err := lc.Content(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	return c, ref
}

func TestBundleServesTheVariants(t *testing.T) {
	c, _ := served(t)
	var names []string
	for _, p := range c.Bundle.Policies {
		names = append(names, p.Name)
		if p.Scope != targeting.ScopeNamespaced || p.Parameters {
			t.Errorf("%s: scope %s, parameters %v", p.Name, p.Scope, p.Parameters)
		}
	}
	slices.Sort(names)
	want := []string{"disallow-capabilities-strict", "disallow-privilege-escalation", "disallow-privileged-containers", "require-run-as-nonroot", "restrict-seccomp-strict"}
	if !slices.Equal(names, want) {
		t.Fatalf("served policies %v, want %v", names, want)
	}
	// The served source for each hardening check is its variant, by digest.
	for _, v := range loadVariants(t).Variants {
		src := c.Policies[v.Check]
		if src.SourceDigest != "sha256:"+v.SHA256 {
			t.Errorf("%s served %s, variant is %s", v.Check, src.SourceDigest, v.SHA256)
		}
		if assessment.ShippedPolicies[v.Check] != v.File {
			t.Errorf("%s served from %s, variant file is %s", v.Check, assessment.ShippedPolicies[v.Check], v.File)
		}
	}
	// The privileged check is the first loop's upstream source, unchanged.
	if c.Policies[assessment.PolicyName].SourceDigest != "sha256:"+fileSum(t, assessment.SourcePolicy) {
		t.Error("the privileged check is not served from the first loop's source")
	}
}

func hexSum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Rendering a binding of the whole bundle keeps each check's identity, the
// variant's digest, background evaluation, the full source workload set and
// the variant's validations; only targeting-owned fields change.
func TestRenderedBundleInstancesKeepIdentityAndDigests(t *testing.T) {
	c, ref := served(t)
	var policies []v1alpha1.ProfilePolicy
	for _, p := range c.Bundle.Policies {
		policies = append(policies, v1alpha1.ProfilePolicy{Name: p.Name})
	}
	profile := v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "linux-hardening", UID: "p-1", Generation: 1},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: ref, Policies: policies}}
	bindings := []v1alpha1.ComplianceBinding{
		{ObjectMeta: metav1.ObjectMeta{Name: "audit-all", UID: "b-audit", Generation: 1},
			Spec: v1alpha1.ComplianceBindingSpec{ProfileRef: v1alpha1.ProfileReference{Name: profile.Name}, Mode: v1alpha1.ModeAudit, NamespaceSelector: &v1alpha1.NamespaceSelector{}, EnforcementEpoch: 1}},
		{ObjectMeta: metav1.ObjectMeta{Name: "deny-prod", UID: "b-deny", Generation: 1},
			Spec: v1alpha1.ComplianceBindingSpec{ProfileRef: v1alpha1.ProfileReference{Name: profile.Name}, Mode: v1alpha1.ModeDeny,
				NamespaceSelector: &v1alpha1.NamespaceSelector{MatchLabels: map[string]v1alpha1.LabelValue{"env": "prod"}}, EnforcementEpoch: 1}},
	}
	res := targeting.Resolve(targeting.Input{Cluster: "kube-system:test", Bundles: []targeting.Bundle{c.Bundle},
		Profiles: []v1alpha1.ComplianceProfile{profile}, Bindings: bindings,
		Namespaces: []targeting.Namespace{{Name: "shop-prod", UID: "ns-1", Labels: map[string]string{"env": "prod"}}, {Name: "shop-dev", UID: "ns-2"}}})
	rendered := 0
	revisions := map[string]bool{}
	for _, br := range res.Bindings {
		if len(br.Errors) > 0 {
			t.Fatalf("%s: %+v", br.Binding.Name, br.Errors)
		}
		for _, contrib := range br.Contributions {
			src := c.Policies[contrib.Policy]
			obj, err := targeting.Render(contrib, src)
			if err != nil {
				t.Fatalf("%s/%s: %v", br.Binding.Name, contrib.Policy, err)
			}
			rendered++
			ann := obj.GetAnnotations()
			if ann[targeting.AnnotationPolicy] != contrib.Policy || ann[targeting.AnnotationSourceDigest] != src.SourceDigest ||
				ann[targeting.AnnotationBundleDigest] != ref.Digest || ann[targeting.AnnotationRevision] != contrib.Revision {
				t.Errorf("%s/%s: provenance annotations %v", br.Binding.Name, contrib.Policy, ann)
			}
			if obj.GetLabels()[targeting.LabelPolicyHash] != targeting.PolicyHash(contrib.Policy) {
				t.Errorf("%s: policy-hash label", contrib.Policy)
			}
			if revisions[contrib.Revision] {
				t.Errorf("%s/%s: revision %s reused", br.Binding.Name, contrib.Policy, contrib.Revision)
			}
			revisions[contrib.Revision] = true

			spec := obj.Object["spec"].(map[string]any)
			wantMode := []any{string(contrib.Mode)}
			if !reflect.DeepEqual(spec["validationActions"], wantMode) {
				t.Errorf("%s: validationActions %v", contrib.Policy, spec["validationActions"])
			}
			if bg, _, _ := unstructuredBool(spec, "evaluation", "background", "enabled"); !bg {
				t.Errorf("%s: background evaluation disabled", contrib.Policy)
			}
			// Everything the source defines except Konstapel-owned fields is
			// unchanged: same workload/operation set, variables, validations.
			want := jsonRoundTrip(t, src.Manifest)["spec"].(map[string]any)
			for _, k := range []string{"variables", "validations"} {
				if !reflect.DeepEqual(jsonRoundTrip(t, spec)[k], want[k]) {
					t.Errorf("%s: rendered %s differ from the served source", contrib.Policy, k)
				}
			}
			gotRules := jsonRoundTrip(t, spec)["matchConstraints"].(map[string]any)["resourceRules"]
			if !reflect.DeepEqual(gotRules, want["matchConstraints"].(map[string]any)["resourceRules"]) {
				t.Errorf("%s: rendered resource rules differ from the source", contrib.Policy)
			}
		}
	}
	if rendered != 2*5 {
		t.Errorf("rendered %d instances, want 10", rendered)
	}
}

func unstructuredBool(m map[string]any, path ...string) (bool, bool, error) {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return false, false, nil
		}
		cur = mm[p]
	}
	b, ok := cur.(bool)
	return b, ok, nil
}

func jsonRoundTrip(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := yaml.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
