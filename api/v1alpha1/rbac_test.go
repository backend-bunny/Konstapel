package v1alpha1_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

const platformAdminRole = "konstapel-compliance-admin"

var (
	centralResources = []string{"complianceprofiles", "compliancebindings"}
	writeVerbs       = []string{"create", "update", "patch", "delete", "deletecollection"}
	// Labels that fold a ClusterRole into the built-in namespace roles held by
	// application teams.
	namespaceAggregation = []string{
		"rbac.authorization.k8s.io/aggregate-to-admin",
		"rbac.authorization.k8s.io/aggregate-to-edit",
		"rbac.authorization.k8s.io/aggregate-to-view",
	}
)

type role struct {
	file, kind, name string
	labels           map[string]string
	rules            []rbacv1.PolicyRule
}

// loadRoles reads every Role and ClusterRole under config/rbac, including the
// generated controller role and roles other changes add later, such as the
// namespace exception role.
func loadRoles(t *testing.T) []role {
	t.Helper()
	var files []string
	err := filepath.WalkDir("../../config/rbac", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".yaml") {
			files = append(files, path)
		}
		return err
	})
	if err != nil || len(files) == 0 {
		t.Fatalf("no RBAC manifests: %v", err)
	}
	var out []role
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, doc := range bytes.Split(raw, []byte("\n---")) {
			var meta struct{ Kind string }
			if err := yaml.Unmarshal(doc, &meta); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			switch meta.Kind {
			case "ClusterRole":
				r := rbacv1.ClusterRole{}
				if err := yaml.UnmarshalStrict(doc, &r); err != nil {
					t.Fatalf("%s: %v", f, err)
				}
				out = append(out, role{f, meta.Kind, r.Name, r.Labels, r.Rules})
			case "Role":
				r := rbacv1.Role{}
				if err := yaml.UnmarshalStrict(doc, &r); err != nil {
					t.Fatalf("%s: %v", f, err)
				}
				out = append(out, role{f, meta.Kind, r.Name, r.Labels, r.Rules})
			}
		}
	}
	return out
}

func matches(list []string, v string) bool {
	return slices.Contains(list, v) || slices.Contains(list, "*")
}

// grants reports whether a rule set allows verb on the central resource,
// honouring wildcards the same way the RBAC authorizer does.
func grants(rules []rbacv1.PolicyRule, verb, resource string) bool {
	for _, r := range rules {
		if matches(r.APIGroups, v1alpha1.GroupVersion.Group) && matches(r.Resources, resource) && matches(r.Verbs, verb) {
			return true
		}
	}
	return false
}

func TestOnlyPlatformAdminsCanWriteProfilesAndBindings(t *testing.T) {
	roles := loadRoles(t)
	foundAdmin := false
	for _, r := range roles {
		for _, res := range centralResources {
			for _, verb := range writeVerbs {
				allowed := grants(r.rules, verb, res)
				switch {
				case r.kind == "ClusterRole" && r.name == platformAdminRole:
					foundAdmin = true
					if !allowed {
						t.Errorf("%s must allow %s %s", r.name, verb, res)
					}
				case allowed:
					t.Errorf("%s %s (%s) must not allow %s %s; only %s may", r.kind, r.name, r.file, verb, res, platformAdminRole)
				}
			}
		}
	}
	if !foundAdmin {
		t.Fatalf("ClusterRole %s not found", platformAdminRole)
	}
}

func TestComplianceRolesAreNotAggregatedIntoNamespaceRoles(t *testing.T) {
	for _, r := range loadRoles(t) {
		touchesGroup := false
		for _, rule := range r.rules {
			if matches(rule.APIGroups, v1alpha1.GroupVersion.Group) {
				touchesGroup = true
			}
		}
		if !touchesGroup {
			continue
		}
		for _, l := range namespaceAggregation {
			if r.labels[l] == "true" {
				t.Errorf("%s aggregates into a built-in namespace role via %s", r.name, l)
			}
		}
	}
}

func TestStatusIsWritableOnlyByTheController(t *testing.T) {
	for _, r := range loadRoles(t) {
		if strings.HasPrefix(r.name, "konstapel-controller") {
			continue
		}
		for _, res := range centralResources {
			for _, verb := range []string{"update", "patch"} {
				if grants(r.rules, verb, res+"/status") {
					t.Errorf("%s may %s %s/status; status is controller-owned", r.name, verb, res)
				}
			}
		}
	}
}
