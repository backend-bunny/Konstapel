package charttest

import (
	"reflect"
	"strings"
	"testing"
)

// add-evidence-signing-recovery 1.4: the runtime chart ships the generated
// recovery roles and admission policies unchanged, binds neither role (they
// are platform grants the operator binds), points the status-writer policy at
// the ConfigMap naming the chart's own controller ServiceAccount, and gives
// that ServiceAccount request read and status write only. No Helm value is
// involved.
func TestRuntimeChartSigningRecovery(t *testing.T) {
	docs, _, err := render(t, controllerNS, "image.digest="+digest)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"konstapel-evidence-signing-recoverer", "konstapel-evidence-signing-recovery-reader"} {
		r := find(docs, "ClusterRole", name)
		if r == nil {
			t.Fatalf("%s not rendered", name)
		}
		if r["aggregationRule"] != nil {
			t.Errorf("%s aggregates other roles", name)
		}
		for k := range metadata(r)["labels"].(map[string]any) {
			if strings.HasPrefix(k, "rbac.authorization.k8s.io/aggregate-to-") {
				t.Errorf("%s aggregates into a built-in role via %s", name, k)
			}
		}
		for _, d := range docs {
			if (d["kind"] == "ClusterRoleBinding" || d["kind"] == "RoleBinding") && at(d, "roleRef", "name") == name {
				t.Errorf("%v %v binds %s; recovery is granted by the operator", d["kind"], metadata(d)["name"], name)
			}
		}
	}

	policy := func(kind, name string) map[string]any {
		p := find(docs, kind, name)
		if p == nil {
			t.Fatalf("%s %s not rendered", kind, name)
		}
		if !strings.HasSuffix(kind, "Binding") && at(p, "spec", "failurePolicy") != "Fail" {
			t.Errorf("%s %s does not fail closed", kind, name)
		}
		return p
	}
	policy("MutatingAdmissionPolicy", "konstapel-evidence-signing-requester")
	policy("ValidatingAdmissionPolicy", "konstapel-evidence-signing-requester")
	policy("ValidatingAdmissionPolicy", "konstapel-evidence-signing-status-writer")
	if b := policy("MutatingAdmissionPolicyBinding", "konstapel-evidence-signing-requester"); at(b, "spec", "policyName") != "konstapel-evidence-signing-requester" {
		t.Errorf("requester mutation binding: %v", b["spec"])
	}
	for _, name := range []string{"konstapel-evidence-signing-requester", "konstapel-evidence-signing-status-writer"} {
		b := policy("ValidatingAdmissionPolicyBinding", name)
		if at(b, "spec", "policyName") != name || !reflect.DeepEqual(at(b, "spec", "validationActions"), any([]any{"Deny"})) {
			t.Errorf("%s binding: %v", name, b["spec"])
		}
	}
	ref := at(find(docs, "ValidatingAdmissionPolicyBinding", "konstapel-evidence-signing-status-writer"), "spec", "paramRef").(map[string]any)
	if ref["parameterNotFoundAction"] != "Deny" || ref["namespace"] != controllerNS {
		t.Fatalf("status-writer paramRef does not fail closed in the controller namespace: %v", ref)
	}
	cm := find(docs, "ConfigMap", ref["name"].(string))
	ctl := find(docs, "Deployment", "konstapel-controller")
	if cm == nil || metadata(cm)["namespace"] != controllerNS || at(cm, "data", "controllerServiceAccountNamespace") != controllerNS ||
		at(cm, "data", "controllerServiceAccountName") != at(ctl, "spec", "template", "spec", "serviceAccountName") {
		t.Fatalf("status-writer identity %v does not name the chart's controller ServiceAccount", cm)
	}

	gs := controllerGrants(t, docs)
	for _, verb := range []string{"get", "list", "watch"} {
		if !allowed(gs, "", "compliance.erenius.io/evidencesigningrequests", verb, "") {
			t.Errorf("controller cannot %s evidencesigningrequests", verb)
		}
	}
	for _, verb := range []string{"get", "update", "patch"} {
		if !allowed(gs, "", "compliance.erenius.io/evidencesigningrequests/status", verb, "") {
			t.Errorf("controller cannot %s evidencesigningrequests/status", verb)
		}
	}
	for _, verb := range []string{"create", "update", "patch", "delete", "deletecollection"} {
		if allowed(gs, "", "compliance.erenius.io/evidencesigningrequests", verb, "") {
			t.Errorf("controller may %s evidencesigningrequests; requests are the administrators' audit record", verb)
		}
	}
}
