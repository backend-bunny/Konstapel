package v1alpha1_test

import (
	"os"
	"reflect"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

// ComplianceException RBAC (add-self-service-policy-exceptions task 2.4),
// checked against every Role and ClusterRole shipped in config/rbac. The live
// counterpart is TestLiveExceptionAdmission.

const exceptionEditorRole = "konstapel-exception-editor"

var exceptionWriteVerbs = []string{"create", "update", "patch", "delete", "deletecollection"}

func TestExceptionStatusIsWritableOnlyByTheController(t *testing.T) {
	controller := false
	for _, r := range loadRoles(t) {
		if strings.HasPrefix(r.name, "konstapel-controller") {
			if r.kind == "ClusterRole" && r.name == "konstapel-controller" {
				controller = grants(r.rules, "update", "complianceexceptions/status") && grants(r.rules, "patch", "complianceexceptions/status")
			}
			continue
		}
		for _, verb := range []string{"create", "update", "patch"} {
			if grants(r.rules, verb, "complianceexceptions/status") {
				t.Errorf("%s may %s complianceexceptions/status; status is controller-owned", r.name, verb)
			}
		}
	}
	if !controller {
		t.Error("ClusterRole konstapel-controller must be able to write complianceexceptions/status")
	}
}

func TestExceptionEditorRoleIsNamespaceScopedSelfService(t *testing.T) {
	var editor *role
	roles := loadRoles(t)
	for i := range roles {
		if roles[i].name == exceptionEditorRole {
			editor = &roles[i]
		}
	}
	if editor == nil || editor.kind != "ClusterRole" {
		t.Fatalf("ClusterRole %s not found", exceptionEditorRole)
	}
	for _, verb := range []string{"get", "list", "watch", "create", "update", "patch", "delete"} {
		if !grants(editor.rules, verb, "complianceexceptions") {
			t.Errorf("%s must allow %s complianceexceptions", editor.name, verb)
		}
	}
	// Nothing but exceptions in its own group, no wildcards, and no access to
	// any other API group (snapshots, native engine exceptions, Secrets...).
	for _, rule := range editor.rules {
		for _, g := range rule.APIGroups {
			if g != "compliance.erenius.io" {
				t.Errorf("%s reaches API group %q", editor.name, g)
			}
		}
		for _, res := range rule.Resources {
			if res != "complianceexceptions" && res != "complianceexceptions/status" {
				t.Errorf("%s reaches resource %q", editor.name, res)
			}
		}
		for _, v := range rule.Verbs {
			if v == "*" {
				t.Errorf("%s uses a wildcard verb", editor.name)
			}
		}
		if len(rule.NonResourceURLs) > 0 || len(rule.ResourceNames) > 0 {
			t.Errorf("%s has an unexpected rule %+v", editor.name, rule)
		}
	}
	// The manifest must tell operators to bind it per namespace.
	raw, err := os.ReadFile(editor.file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "RoleBinding in the team's namespace, never a ClusterRoleBinding") {
		t.Errorf("%s must document namespace-only binding", editor.file)
	}
}

// Only the namespace editor role (bound per namespace) may write exceptions
// by default; central roles, viewers and the controller's default roles may
// not accept risk on a team's behalf. The one exception is the gated
// revocation-processing ClusterRole (task 3.6), bound only with
// --exception-revocation-processing and the fail-closed webhooks: it may
// update and patch an exception, which admission confines to releasing the
// revocation finalizer once the revocation is recorded independently; it
// never creates or deletes one.
func TestOnlyNamespaceEditorsWriteExceptions(t *testing.T) {
	gated := false
	for _, r := range loadRoles(t) {
		if r.name == exceptionEditorRole {
			continue
		}
		allowed := map[string]bool{}
		if r.kind == "ClusterRole" && r.name == revocationRole {
			allowed = map[string]bool{"update": true, "patch": true}
			gated = grants(r.rules, "update", "complianceexceptions") && grants(r.rules, "patch", "complianceexceptions")
		}
		for _, verb := range exceptionWriteVerbs {
			if !allowed[verb] && grants(r.rules, verb, "complianceexceptions") {
				t.Errorf("%s %s (%s) must not %s complianceexceptions", r.kind, r.name, r.file, verb)
			}
		}
	}
	if !gated {
		t.Errorf("ClusterRole %s must be able to update and patch complianceexceptions to release the revocation finalizer", revocationRole)
	}
}

// revocationRole is the gated revocation-processing grant
// (config/rbac/controller/exception-revocation.yaml).
const revocationRole = "konstapel-controller-exception-revocation"

// The gated revocation-processing ClusterRole holds exactly what processing
// needs beyond the default controller roles: the finalizer release, the
// identity lookup, and reading the two exception webhook configurations by
// name. The default ClusterRole has none of it.
func TestRevocationProcessingGrantIsGated(t *testing.T) {
	var gated *role
	for _, r := range loadRoles(t) {
		switch {
		case r.kind == "ClusterRole" && r.name == revocationRole:
			gated = &r
		case r.name == revocationRole:
			t.Errorf("%s %s (%s): the gated grant must be one ClusterRole", r.kind, r.name, r.file)
		case r.kind == "ClusterRole" && r.name == "konstapel-controller":
			for _, q := range [][3]string{
				{"compliance.erenius.io", "update", "complianceexceptions"},
				{"compliance.erenius.io", "patch", "complianceexceptions"},
				{"authentication.k8s.io", "create", "selfsubjectreviews"},
				{"admissionregistration.k8s.io", "get", "validatingwebhookconfigurations"},
			} {
				if grantsIn(r.rules, q[0], q[1], q[2]) {
					t.Errorf("the default controller ClusterRole grants %v; only the gated %s may", q, revocationRole)
				}
			}
		}
	}
	if gated == nil {
		t.Fatalf("ClusterRole %s not found", revocationRole)
	}
	if !strings.HasSuffix(gated.file, "config/rbac/controller/exception-revocation.yaml") {
		t.Errorf("%s is in %s; the runtime chart copies config/rbac/*.yaml, so the gated grant must stay outside it", revocationRole, gated.file)
	}
	want := []rbacv1.PolicyRule{
		{APIGroups: []string{"compliance.erenius.io"}, Resources: []string{"complianceexceptions"}, Verbs: []string{"update", "patch"}},
		{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"selfsubjectreviews"}, Verbs: []string{"create"}},
		{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"mutatingwebhookconfigurations", "validatingwebhookconfigurations"},
			ResourceNames: []string{"konstapel-exception-acceptance"}, Verbs: []string{"get"}},
	}
	if !reflect.DeepEqual(gated.rules, want) {
		t.Errorf("%s rules\n got %+v\nwant %+v", revocationRole, gated.rules, want)
	}
}

// The controller persists revocation records next to acceptance snapshots
// in its own namespace, with its default Role.
func TestControllerCanPersistRevocationHistory(t *testing.T) {
	namespaced := false
	for _, r := range loadRoles(t) {
		if r.kind == "Role" && r.name == "konstapel-controller" {
			namespaced = grantsIn(r.rules, "", "create", "configmaps") && grantsIn(r.rules, "", "get", "configmaps")
			for _, verb := range []string{"update", "patch", "delete", "deletecollection"} {
				if grantsIn(r.rules, "", verb, "configmaps") {
					t.Errorf("the controller may %s configmaps: snapshots and revocation records are immutable history", verb)
				}
			}
		}
	}
	if !namespaced {
		t.Error("the controller Role must get and create (only) konstapel-system configmaps")
	}
}

func grantsIn(rules []rbacv1.PolicyRule, group, verb, resource string) bool {
	for _, r := range rules {
		if matches(r.APIGroups, group) && matches(r.Resources, resource) && matches(r.Verbs, verb) {
			return true
		}
	}
	return false
}
