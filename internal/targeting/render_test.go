package targeting

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

var update = flag.Bool("update", false, "rewrite golden rendered policies")

const vendoredPolicy = "content/upstream/kyverno/disallow-privileged-containers/disallow-privileged-containers.yaml"

func vendored() LocalContent {
	return LocalContent{Root: "../../content", Name: "konstapel-vendored",
		Policies: map[string]string{"disallow-privileged-containers": vendoredPolicy}}
}

func vendoredDigest(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../content/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	return "sha256:" + hexSum(b)
}

func TestLocalContentServesVerifiedVendoredPolicy(t *testing.T) {
	ref := v1alpha1.BundleReference{Name: "konstapel-vendored", Digest: vendoredDigest(t)}
	c, err := vendored().Content(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Bundle.Policies) != 1 || c.Bundle.Policies[0] != (BundlePolicy{Name: "disallow-privileged-containers", Scope: ScopeNamespaced}) {
		t.Fatalf("bundle metadata %+v", c.Bundle)
	}
	src := c.Policies["disallow-privileged-containers"]
	raw, _ := os.ReadFile("../../" + vendoredPolicy)
	if src.SourceDigest != "sha256:"+hexSum(raw) {
		t.Fatal("source digest is not the file hash")
	}

	for name, r := range map[string]v1alpha1.BundleReference{
		"wrong digest": {Name: ref.Name, Digest: "sha256:" + strings.Repeat("0", 64)},
		"wrong name":   {Name: "other", Digest: ref.Digest},
	} {
		if _, err := vendored().Content(context.Background(), r); !errors.Is(err, ErrContentUnavailable) {
			t.Errorf("%s: want ErrContentUnavailable, got %v", name, err)
		}
	}
}

func TestLocalContentRejectsTamperedFiles(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "content")
	policy := filepath.Join(dir, vendoredPolicy)
	if err := os.MkdirAll(filepath.Dir(policy), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile("../../" + vendoredPolicy)
	sums := hexSum(raw) + "  " + vendoredPolicy + "\n"
	_ = os.WriteFile(filepath.Join(root, "SHA256SUMS"), []byte(sums), 0o644)
	_ = os.WriteFile(policy, append(raw, []byte("# tampered\n")...), 0o644)
	lc := LocalContent{Root: root, Name: "n", Policies: map[string]string{"p": vendoredPolicy}}
	_, err := lc.Content(context.Background(), v1alpha1.BundleReference{Name: "n", Digest: "sha256:" + hexSum([]byte(sums))})
	if !errors.Is(err, ErrContentUnavailable) || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("want checksum failure, got %v", err)
	}
}

func TestPolicyScopeOf(t *testing.T) {
	policy := func(group, resource string) map[string]any {
		return map[string]any{"apiVersion": "policies.kyverno.io/v1", "kind": "ValidatingPolicy", "spec": map[string]any{
			"matchConstraints": map[string]any{"resourceRules": []any{map[string]any{"apiGroups": []any{group}, "resources": []any{resource}}}}}}
	}
	for _, c := range []struct {
		group, resource string
		want            PolicyScope
	}{
		{"", "pods", ScopeNamespaced},
		{"apps", "deployments", ScopeNamespaced},
		{"rbac.authorization.k8s.io", "clusterrolebindings", ScopeCluster},
		{"", "namespaces", ScopeCluster},
		{"*", "*", ScopeCluster},
		{"", "*", ScopeCluster},
	} {
		if got, err := PolicyScopeOf(policy(c.group, c.resource), StandardWorkloadScopes); err != nil || got != c.want {
			t.Errorf("%s/%s: got %s %v, want %s", c.group, c.resource, got, err, c.want)
		}
	}
	if _, err := PolicyScopeOf(map[string]any{"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy"}, StandardWorkloadScopes); err == nil {
		t.Error("legacy policy types must be rejected")
	}
}

// renderedFixture resolves the documented Audit-all/Deny-production example
// against the real vendored content.
func renderedFixture(t *testing.T) map[string]*unstructured.Unstructured {
	t.Helper()
	ref := v1alpha1.BundleReference{Name: "konstapel-vendored", Digest: vendoredDigest(t)}
	content, err := vendored().Content(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	p := profile("baseline", selfService("disallow-privileged-containers", 720*time.Hour))
	p.Spec.Bundle = ref
	in := Input{Cluster: "kube-system:fixture", Bundles: []Bundle{content.Bundle}, Profiles: []v1alpha1.ComplianceProfile{p},
		Bindings: []v1alpha1.ComplianceBinding{
			binding("audit-all", "baseline", v1alpha1.ModeAudit, v1alpha1.NamespaceSelector{}),
			binding("deny-production", "baseline", v1alpha1.ModeDeny, v1alpha1.NamespaceSelector{MatchLabels: map[string]v1alpha1.LabelValue{"environment": "production"}}),
		}}
	out := map[string]*unstructured.Unstructured{}
	for _, b := range Resolve(in).Bindings {
		if len(b.Errors) > 0 || len(b.Contributions) != 1 {
			t.Fatalf("binding %s: %+v", b.Binding.Name, b)
		}
		c := b.Contributions[0]
		obj, err := Render(c, content.Policies[c.Policy])
		if err != nil {
			t.Fatal(err)
		}
		out[b.Binding.Name] = obj
	}
	return out
}

// The golden files are also the Kyverno CLI test input (task policies:test),
// so the CLI checks exactly what Render produces.
func TestRenderMatchesGoldenCLIFixtures(t *testing.T) {
	for name, obj := range renderedFixture(t) {
		got, err := yaml.Marshal(obj.Object)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join("../../testdata/targeting/rendered", name+".yaml")
		if *update {
			if err := os.WriteFile(path, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(want) != string(got) {
			t.Errorf("%s is stale; run go test ./internal/targeting -run TestRenderMatchesGoldenCLIFixtures -update\n%s", path, got)
		}
	}
}

func TestRenderPreservesSourceAndSetsOwnedFields(t *testing.T) {
	raw, _ := os.ReadFile("../../" + vendoredPolicy)
	var source map[string]any
	if err := yaml.Unmarshal(raw, &source); err != nil {
		t.Fatal(err)
	}
	for name, obj := range renderedFixture(t) {
		spec := obj.Object["spec"].(map[string]any)
		srcSpec := source["spec"].(map[string]any)
		for _, k := range []string{"variables", "validations"} {
			if !equalJSON(spec[k], srcSpec[k]) {
				t.Errorf("%s: %s changed", name, k)
			}
		}
		mc := spec["matchConstraints"].(map[string]any)
		if !equalJSON(mc["resourceRules"], srcSpec["matchConstraints"].(map[string]any)["resourceRules"]) {
			t.Errorf("%s: resourceRules changed", name)
		}
		wantMode := map[string]string{"audit-all": "Audit", "deny-production": "Deny"}[name]
		if !equalJSON(spec["validationActions"], []any{wantMode}) {
			t.Errorf("%s: validationActions %v", name, spec["validationActions"])
		}
		if enabled, _, _ := unstructured.NestedBool(obj.Object, "spec", "evaluation", "background", "enabled"); !enabled {
			t.Errorf("%s: background evaluation disabled", name)
		}
		for _, k := range []string{"policies.kyverno.io/title", "policies.kyverno.io/description"} {
			if obj.GetAnnotations()[k] == "" {
				t.Errorf("%s: source annotation %s dropped", name, k)
			}
		}
		if len(obj.GetName()) > 63 || !strings.HasPrefix(obj.GetName(), "konstapel-disallow-privileged-containers-") {
			t.Errorf("%s: name %q", name, obj.GetName())
		}
	}
}

func TestPolicyNamesAreRevisionScoped(t *testing.T) {
	c := Contribution{Binding: ObjectRevision{UID: "b"}, Policy: "p", Revision: "sha256:1"}
	again := c
	other := c
	other.Revision = "sha256:2"
	if PolicyName(c) != PolicyName(again) {
		t.Fatal("name is not deterministic")
	}
	if PolicyName(c) == PolicyName(other) {
		t.Fatal("a new revision must get a new name")
	}
	long := c
	long.Policy = strings.Repeat("Very_Long.Policy-Name", 20)
	if n := PolicyName(long); len(n) > 63 || strings.ContainsAny(n, "_.") {
		t.Fatalf("unsafe name %q", n)
	}
}

func TestRenderRejectsUnsupportedSources(t *testing.T) {
	raw, _ := os.ReadFile("../../" + vendoredPolicy)
	c := Contribution{Policy: "p", Mode: v1alpha1.ModeDeny, Binding: ObjectRevision{Name: "b", UID: "b"}}
	withSelector := map[string]any{}
	_ = yaml.Unmarshal(raw, &withSelector)
	_ = unstructured.SetNestedField(withSelector, map[string]any{}, "spec", "matchConstraints", "namespaceSelector")
	if _, err := Render(c, PolicySource{Manifest: withSelector}); err == nil {
		t.Error("a source namespaceSelector must be rejected, not overwritten")
	}
	cluster := map[string]any{}
	_ = yaml.Unmarshal(raw, &cluster)
	_ = unstructured.SetNestedSlice(cluster, []any{map[string]any{"apiGroups": []any{"rbac.authorization.k8s.io"}, "resources": []any{"clusterroles"}}}, "spec", "matchConstraints", "resourceRules")
	if _, err := Render(c, PolicySource{Manifest: cluster}); err == nil {
		t.Error("cluster-scoped sources must not render")
	}
	ok := map[string]any{}
	_ = yaml.Unmarshal(raw, &ok)
	c.Mode = "Warn"
	if _, err := Render(c, PolicySource{Manifest: ok}); err == nil {
		t.Error("unsupported mode rendered")
	}
}

func TestProfileParametersAreRejectedUnlessContentAcceptsThem(t *testing.T) {
	p := profile("pr", v1alpha1.ProfilePolicy{Name: "p1"})
	p.Spec.Policies[0].Parameters = jsonParams(`{"x":1}`)
	r := Resolve(Input{Bundles: []Bundle{testBundle()}, Profiles: []v1alpha1.ComplianceProfile{p},
		Bindings: []v1alpha1.ComplianceBinding{binding("b", "pr", v1alpha1.ModeDeny, v1alpha1.NamespaceSelector{})}, Namespaces: []Namespace{ns("x")}})
	b := r.Bindings[0]
	if len(b.Contributions) != 0 || len(b.Errors) != 1 || b.Errors[0].Reason != ReasonInvalidConfiguration {
		t.Fatalf("parameters for a policy without parameter support must be an error: %+v", b)
	}
	for _, empty := range []string{`{}`, `null`} {
		p.Spec.Policies[0].Parameters = jsonParams(empty)
		r := Resolve(Input{Bundles: []Bundle{testBundle()}, Profiles: []v1alpha1.ComplianceProfile{p},
			Bindings: []v1alpha1.ComplianceBinding{binding("b", "pr", v1alpha1.ModeDeny, v1alpha1.NamespaceSelector{})}})
		if len(r.Bindings[0].Errors) != 0 {
			t.Errorf("empty parameters %s rejected", empty)
		}
	}
}

// Kyverno CLI reports excluded resources as passing, so selector inclusion is
// checked here against the same namespace labels as the CLI values file.
func TestRenderedSelectorsMatchIntendedNamespaces(t *testing.T) {
	namespaces := map[string]labels.Set{"shop-prod": {"environment": "production"}, "shop-dev": {"environment": "development"}}
	want := map[string][]string{"audit-all": {"shop-dev", "shop-prod"}, "deny-production": {"shop-prod"}}
	for name, obj := range renderedFixture(t) {
		raw, _, _ := unstructured.NestedMap(obj.Object, "spec", "matchConstraints", "namespaceSelector")
		var ls metav1.LabelSelector
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &ls); err != nil {
			t.Fatal(err)
		}
		sel, err := metav1.LabelSelectorAsSelector(&ls)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for ns, l := range namespaces {
			if sel.Matches(l) {
				got = append(got, ns)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, want[name]) {
			t.Errorf("%s selects %v, want %v", name, got, want[name])
		}
	}
}
