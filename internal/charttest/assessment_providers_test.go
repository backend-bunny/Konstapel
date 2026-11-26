package charttest

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// add-external-assessment-providers 2.1: the runtime chart ships the
// generated provider registration roles and status-writer admission policy
// unchanged, binds neither role (registering providers is a platform grant
// the operator binds), points the policy at the ConfigMap naming the chart's
// own controller ServiceAccount, and gives that ServiceAccount registration
// read and status write only. In every rendered configuration no bound
// subject can create, change or delete a registration, and only the
// controller writes its status: installing the chart grants nobody new
// write access to provider registration. No Helm value is involved.
func TestRuntimeChartAssessmentProviderRegistration(t *testing.T) {
	for name, set := range map[string][]string{
		"defaults":               nil,
		"bundles":                {"bundles.sourcesConfigMap=konstapel-bundle-sources"},
		"metrics":                {"metrics.enabled=true", "metrics.readers[0].namespace=monitoring", "metrics.readers[0].name=prometheus-k8s"},
		"exception webhooks":     {"exceptions.webhooks.enabled=true"},
		"exception revocation":   {"exceptions.webhooks.enabled=true", "exceptions.revocationProcessing.enabled=true"},
		"operator TLS, webhooks": {"tls.mode=secret", "tls.secret.name=konstapel-tls", "exceptions.webhooks.enabled=true", "exceptions.webhooks.tls.secretName=konstapel-webhook-tls", "exceptions.webhooks.tls.caBundle=" + fixtureCA},
		"no download service":    {"download.enabled=false"},
		"external providers":     {"externalProviders.enabled=true", "externalProviders.clientCertSecretName=" + clientCertSecret},
	} {
		t.Run(name, func(t *testing.T) {
			docs, out, err := render(t, controllerNS, append([]string{"image.digest=" + digest}, set...)...)
			if err != nil {
				t.Fatal(out)
			}
			providerRegistrationRender(t, docs)
		})
	}
}

func providerRegistrationRender(t *testing.T, docs []map[string]any) {
	t.Helper()
	for _, name := range []string{"konstapel-assessment-provider-admin", "konstapel-assessment-provider-viewer"} {
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
	}

	// Every subject every rendered binding grants: none but the controller
	// reaches registrations at all, and the controller only reads them and
	// writes their status.
	for _, b := range docs {
		if b["kind"] != "RoleBinding" && b["kind"] != "ClusterRoleBinding" {
			continue
		}
		roleKind, roleName := at(b, "roleRef", "kind").(string), at(b, "roleRef", "name").(string)
		if strings.HasPrefix(roleName, "konstapel-assessment-provider-") {
			t.Errorf("%v %v binds %s; registration is granted by the operator", b["kind"], metadata(b)["name"], roleName)
		}
		role := find(docs, roleKind, roleName)
		if role == nil {
			continue // a built-in role, such as the metrics reader's
		}
		controller := false
		for _, s := range at(b, "subjects").([]any) {
			s := s.(map[string]any)
			controller = controller || s["kind"] == "ServiceAccount" && s["name"] == "konstapel-controller" && s["namespace"] == controllerNS
		}
		for _, r := range role["rules"].([]any) {
			r := r.(map[string]any)
			if !strings.Contains(fmt.Sprint(r["apiGroups"]), "compliance.erenius.io") && !strings.Contains(fmt.Sprint(r["apiGroups"]), "*") {
				continue
			}
			for _, res := range r["resources"].([]any) {
				res := res.(string)
				if res != "*" && !strings.HasPrefix(res, "assessmentproviders") {
					continue
				}
				for _, v := range r["verbs"].([]any) {
					verb := v.(string)
					ok := controller && ((res == "assessmentproviders" && (verb == "get" || verb == "list" || verb == "watch")) ||
						(res == "assessmentproviders/status" && (verb == "get" || verb == "update" || verb == "patch")))
					if !ok {
						t.Errorf("%v %v (%s %s) grants %s %s", b["kind"], metadata(b)["name"], roleKind, roleName, verb, res)
					}
				}
			}
		}
	}

	gs := controllerGrants(t, docs)
	for _, verb := range []string{"get", "list", "watch"} {
		if !allowed(gs, "", "compliance.erenius.io/assessmentproviders", verb, "") {
			t.Errorf("controller cannot %s assessmentproviders", verb)
		}
	}
	for _, verb := range []string{"get", "update", "patch"} {
		if !allowed(gs, "", "compliance.erenius.io/assessmentproviders/status", verb, "") {
			t.Errorf("controller cannot %s assessmentproviders/status", verb)
		}
	}
	for _, verb := range []string{"create", "update", "patch", "delete", "deletecollection"} {
		if allowed(gs, "", "compliance.erenius.io/assessmentproviders", verb, "") {
			t.Errorf("controller may %s assessmentproviders; registrations are administrator configuration", verb)
		}
	}

	const writer = "konstapel-assessment-provider-status-writer"
	p := find(docs, "ValidatingAdmissionPolicy", writer)
	if p == nil || at(p, "spec", "failurePolicy") != "Fail" {
		t.Fatalf("%s is not rendered failing closed: %v", writer, p)
	}
	if !reflect.DeepEqual(at(p, "spec", "matchConstraints", "resourceRules", 0, "resources"), any([]any{"assessmentproviders/status"})) {
		t.Errorf("%s matches %v", writer, at(p, "spec", "matchConstraints"))
	}
	b := find(docs, "ValidatingAdmissionPolicyBinding", writer)
	if b == nil || at(b, "spec", "policyName") != writer || !reflect.DeepEqual(at(b, "spec", "validationActions"), any([]any{"Deny"})) {
		t.Fatalf("%s binding: %v", writer, b)
	}
	ref := at(b, "spec", "paramRef").(map[string]any)
	if ref["parameterNotFoundAction"] != "Deny" || ref["namespace"] != controllerNS {
		t.Fatalf("status-writer paramRef does not fail closed in the controller namespace: %v", ref)
	}
	cm := find(docs, "ConfigMap", ref["name"].(string))
	ctl := find(docs, "Deployment", "konstapel-controller")
	if cm == nil || metadata(cm)["namespace"] != controllerNS || at(cm, "data", "controllerServiceAccountNamespace") != controllerNS ||
		at(cm, "data", "controllerServiceAccountName") != at(ctl, "spec", "template", "spec", "serviceAccountName") {
		t.Fatalf("status-writer identity %v does not name the chart's controller ServiceAccount", cm)
	}
}
