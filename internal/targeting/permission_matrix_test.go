package targeting

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// The Kyverno permission matrix (docs/integration/kyverno-permission-matrix.json)
// is live evidence from scripts/kyverno-permission-matrix.sh. These tests keep it
// tied to the delivered content: a bundle that delivers another policy or matches
// another subresource needs a new live run, and the acceptance fixture must keep
// granting what the matrix found required.

const repoRoot = "../.."

type permissionGrant struct {
	Controller       string   `json:"controller"`
	ServiceAccount   string   `json:"serviceAccount"`
	AggregationLabel string   `json:"aggregationLabel"`
	APIGroup         string   `json:"apiGroup"`
	Resource         string   `json:"resource"`
	Verbs            []string `json:"verbs"`
	Modes            []string `json:"modes"`
	Reason           string   `json:"reason"`
}

type permissionMatrix struct {
	KyvernoChart        string            `json:"kyvernoChart"`
	Policies            []string          `json:"policies"`
	MatchedSubresources []string          `json:"matchedSubresources"`
	Required            []permissionGrant `json:"required"`
	NotRequired         []permissionGrant `json:"notRequired"`
	Scenarios           []struct {
		Scenario string `json:"scenario"`
	} `json:"scenarios"`
}

func loadPermissionMatrix(t *testing.T) permissionMatrix {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, "docs/integration/kyverno-permission-matrix.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m permissionMatrix
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// deliveredPolicyPaths lists every policy file an official bundle delivers.
func deliveredPolicyPaths(t *testing.T) []string {
	t.Helper()
	defs, err := filepath.Glob(filepath.Join(repoRoot, "bundles/*/definition.json"))
	if err != nil || len(defs) == 0 {
		t.Fatalf("bundle definitions: %v %v", defs, err)
	}
	var paths []string
	for _, d := range defs {
		raw, err := os.ReadFile(d)
		if err != nil {
			t.Fatal(err)
		}
		var def struct {
			Policies []struct {
				Path string `json:"path"`
			} `json:"policies"`
		}
		if err := json.Unmarshal(raw, &def); err != nil {
			t.Fatal(err)
		}
		for _, p := range def.Policies {
			if !slices.Contains(paths, p.Path) {
				paths = append(paths, p.Path)
			}
		}
	}
	slices.Sort(paths)
	return paths
}

func TestPermissionMatrixCoversDeliveredPolicies(t *testing.T) {
	m := loadPermissionMatrix(t)
	want := deliveredPolicyPaths(t)
	got := slices.Sorted(slices.Values(m.Policies))
	if !slices.Equal(got, want) {
		t.Fatalf("matrix policies %v, delivered %v: rerun scripts/kyverno-permission-matrix.sh", got, want)
	}
	var subresources []string
	for _, p := range want {
		raw, err := os.ReadFile(filepath.Join(repoRoot, p))
		if err != nil {
			t.Fatal(err)
		}
		var pol struct {
			Spec struct {
				MatchConstraints struct {
					ResourceRules []struct {
						APIGroups []string `json:"apiGroups"`
						Resources []string `json:"resources"`
					} `json:"resourceRules"`
				} `json:"matchConstraints"`
			} `json:"spec"`
		}
		if err := yaml.Unmarshal(raw, &pol); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		for _, r := range pol.Spec.MatchConstraints.ResourceRules {
			for _, res := range r.Resources {
				// Kubernetes' view role (bound by the Kyverno chart) covers top-level
				// workload reads; subresources are what operators must add.
				if strings.Contains(res, "/") && !slices.Contains(subresources, res) {
					subresources = append(subresources, res)
				}
			}
		}
	}
	slices.Sort(subresources)
	if !slices.Equal(subresources, slices.Sorted(slices.Values(m.MatchedSubresources))) {
		t.Fatalf("delivered policies match %v, matrix verified %v", subresources, m.MatchedSubresources)
	}
	for _, sub := range subresources {
		found := false
		for _, g := range m.Required {
			if g.Resource == sub && g.Controller == "reports-controller" && strings.TrimSpace(g.Reason) != "" &&
				slices.Equal(g.Modes, []string{"Audit", "Deny"}) {
				found = true
			}
		}
		if !found {
			t.Errorf("no verified reports-controller requirement for %s", sub)
		}
	}
	if len(m.Scenarios) == 0 || m.KyvernoChart == "" {
		t.Error("matrix lacks its live scenarios or chart version")
	}
}

func TestPermissionMatrixGrantsAreKyvernoOwned(t *testing.T) {
	m := loadPermissionMatrix(t)
	for _, g := range append(slices.Clone(m.Required), m.NotRequired...) {
		if !strings.HasPrefix(g.ServiceAccount, "kyverno-") || !strings.HasSuffix(g.AggregationLabel, "-"+g.Controller) ||
			slices.Contains(g.Verbs, "*") || strings.Contains(g.Resource, "*") || strings.TrimSpace(g.Reason) == "" {
			t.Errorf("grant %+v must name a Kyverno controller, its aggregation label, explicit verbs and a reason", g)
		}
	}
	// Konstapel never grants Kyverno permissions: its charts contain no Kyverno
	// aggregation labels and no ephemeral-container rules.
	err := filepath.WalkDir(filepath.Join(repoRoot, "charts"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if s := string(raw); strings.Contains(s, "rbac.kyverno.io/aggregate-to") || strings.Contains(s, "ephemeralcontainers") {
			t.Errorf("%s grants Kyverno permissions", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The acceptance environment installs the upstream fixture; it must grant at
// least what the matrix found required, through the same aggregation labels.
func TestAcceptanceFixtureGrantsRequiredPermissions(t *testing.T) {
	m := loadPermissionMatrix(t)
	raw, err := os.ReadFile(filepath.Join(repoRoot, "content/upstream/kyverno/disallow-privileged-containers/.chainsaw-test/ephemeral-rbac.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	type role struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
		Rules []struct {
			APIGroups []string `json:"apiGroups"`
			Resources []string `json:"resources"`
			Verbs     []string `json:"verbs"`
		} `json:"rules"`
	}
	var roles []role
	for _, doc := range strings.Split(string(raw), "\n---\n") {
		var r role
		if err := yaml.Unmarshal([]byte(doc), &r); err != nil {
			t.Fatal(err)
		}
		roles = append(roles, r)
	}
	for _, g := range m.Required {
		for _, verb := range g.Verbs {
			ok := false
			for _, r := range roles {
				if r.Metadata.Labels[g.AggregationLabel] != "true" {
					continue
				}
				for _, rule := range r.Rules {
					if slices.Contains(rule.APIGroups, g.APIGroup) && slices.Contains(rule.Resources, g.Resource) && slices.Contains(rule.Verbs, verb) {
						ok = true
					}
				}
			}
			if !ok {
				t.Errorf("acceptance fixture lacks %s %s for %s", verb, g.Resource, g.Controller)
			}
		}
	}
}
