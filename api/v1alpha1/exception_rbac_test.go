package v1alpha1_test

import (
	"os"
	"strings"
	"testing"
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

// Only the namespace editor role (bound per namespace) and the controller
// may write exceptions; central roles and viewers may not accept risk on a
// team's behalf.
func TestOnlyNamespaceEditorsWriteExceptions(t *testing.T) {
	for _, r := range loadRoles(t) {
		if r.name == exceptionEditorRole {
			continue
		}
		for _, verb := range exceptionWriteVerbs {
			if grants(r.rules, verb, "complianceexceptions") {
				t.Errorf("%s %s (%s) must not %s complianceexceptions", r.kind, r.name, r.file, verb)
			}
		}
	}
}
