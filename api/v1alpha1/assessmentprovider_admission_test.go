package v1alpha1_test

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// add-external-assessment-providers 2.1: the shipped
// konstapel-assessment-provider-status-writer policy, evaluated offline with
// its own CEL, admits AssessmentProvider status writes only from the
// controller ServiceAccount the shipped konstapel-assessment-admission
// ConfigMap names, denies everyone else (a cluster administrator included)
// and fails closed on missing or empty configuration. The API server's
// enforcement of the same files is TestLiveAssessmentProviderAPI.

const providerStatusWriter = "konstapel-assessment-provider-status-writer"

func admissionDocs(t *testing.T, path string) (policies []admissionregistrationv1.ValidatingAdmissionPolicy,
	bindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding, configMaps []corev1.ConfigMap) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, doc := range strings.Split(string(raw), "\n---") {
		var meta struct{ Kind string }
		if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		switch meta.Kind {
		case "ValidatingAdmissionPolicy":
			var p admissionregistrationv1.ValidatingAdmissionPolicy
			if err := yaml.UnmarshalStrict([]byte(doc), &p); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			policies = append(policies, p)
		case "ValidatingAdmissionPolicyBinding":
			var b admissionregistrationv1.ValidatingAdmissionPolicyBinding
			if err := yaml.UnmarshalStrict([]byte(doc), &b); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			bindings = append(bindings, b)
		case "ConfigMap":
			var c corev1.ConfigMap
			if err := yaml.UnmarshalStrict([]byte(doc), &c); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			configMaps = append(configMaps, c)
		case "":
		default:
			t.Fatalf("%s: unexpected %s", path, meta.Kind)
		}
	}
	return policies, bindings, configMaps
}

// statusWriterDecision evaluates the policy's variables, validation and
// message for user with the given ConfigMap data (nil: a ConfigMap without
// data).
func statusWriterDecision(t *testing.T, p admissionregistrationv1.ValidatingAdmissionPolicy, user string, data map[string]string) (bool, string) {
	t.Helper()
	env, err := cel.NewEnv(cel.OptionalTypes(), cel.Variable("request", cel.DynType), cel.Variable("params", cel.DynType),
		cel.Variable("variables", cel.MapType(cel.StringType, cel.DynType)))
	if err != nil {
		t.Fatal(err)
	}
	eval := func(expr string, vars map[string]any) any {
		ast, iss := env.Compile(expr)
		if iss.Err() != nil {
			t.Fatalf("%s: %v", expr, iss.Err())
		}
		prg, err := env.Program(ast)
		if err != nil {
			t.Fatal(err)
		}
		params := map[string]any{"apiVersion": "v1", "kind": "ConfigMap"}
		if data != nil {
			d := map[string]any{}
			for k, v := range data {
				d[k] = v
			}
			params["data"] = d
		}
		out, _, err := prg.Eval(map[string]any{
			"request":   map[string]any{"operation": "UPDATE", "userInfo": map[string]any{"username": user}},
			"params":    params,
			"variables": vars,
		})
		if err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
		return out.Value()
	}
	vars := map[string]any{}
	for _, v := range p.Spec.Variables {
		vars[v.Name] = eval(v.Expression, vars)
	}
	if len(p.Spec.Validations) != 1 {
		t.Fatalf("%s has %d validations", p.Name, len(p.Spec.Validations))
	}
	val := p.Spec.Validations[0]
	allowed, ok := eval(val.Expression, vars).(bool)
	if !ok {
		t.Fatalf("%s validation is not a bool", p.Name)
	}
	msg, _ := eval(val.MessageExpression, vars).(string)
	return allowed, msg
}

func TestAssessmentProviderStatusWriterPolicy(t *testing.T) {
	policies, bindings, _ := admissionDocs(t, "../../config/admission/assessment-provider-status-writer.yaml")
	if len(policies) != 1 || len(bindings) != 1 {
		t.Fatalf("want one policy and one binding, got %d and %d", len(policies), len(bindings))
	}
	p, b := policies[0], bindings[0]
	if p.Name != providerStatusWriter || b.Name != providerStatusWriter || b.Spec.PolicyName != providerStatusWriter {
		t.Fatalf("names: policy %s, binding %s for %s", p.Name, b.Name, b.Spec.PolicyName)
	}
	if p.Labels["app.kubernetes.io/part-of"] != "konstapel" || b.Labels["app.kubernetes.io/part-of"] != "konstapel" {
		t.Error("policy or binding lacks the part-of label")
	}
	if p.Spec.FailurePolicy == nil || *p.Spec.FailurePolicy != admissionregistrationv1.Fail {
		t.Error("the status-writer policy does not fail closed")
	}
	if !reflect.DeepEqual(b.Spec.ValidationActions, []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}) {
		t.Errorf("binding actions %v, want Deny only", b.Spec.ValidationActions)
	}
	ref := b.Spec.ParamRef
	if ref == nil || ref.Name != "konstapel-assessment-admission" || ref.Namespace != "konstapel-system" || ref.Selector != nil ||
		ref.ParameterNotFoundAction == nil || *ref.ParameterNotFoundAction != admissionregistrationv1.DenyAction {
		t.Errorf("paramRef %+v does not name the controller-identity ConfigMap and deny when it is missing", ref)
	}
	if p.Spec.ParamKind == nil || p.Spec.ParamKind.APIVersion != "v1" || p.Spec.ParamKind.Kind != "ConfigMap" {
		t.Errorf("paramKind %+v", p.Spec.ParamKind)
	}
	// Exactly status updates of registrations: the main resource stays
	// with RBAC, and nothing else is matched.
	rules := p.Spec.MatchConstraints.ResourceRules
	if len(rules) != 1 || p.Spec.MatchConstraints.NamespaceSelector != nil && len(p.Spec.MatchConstraints.NamespaceSelector.MatchLabels)+len(p.Spec.MatchConstraints.NamespaceSelector.MatchExpressions) > 0 ||
		p.Spec.MatchConstraints.ObjectSelector != nil || len(p.Spec.MatchConstraints.ExcludeResourceRules) > 0 || len(p.Spec.MatchConditions) > 0 {
		t.Fatalf("match constraints %+v narrow or widen the policy", p.Spec.MatchConstraints)
	}
	r := rules[0]
	if !reflect.DeepEqual(r.APIGroups, []string{"compliance.erenius.io"}) || !reflect.DeepEqual(r.APIVersions, []string{"v1alpha1"}) ||
		!reflect.DeepEqual(r.Resources, []string{"assessmentproviders/status"}) ||
		!reflect.DeepEqual(r.Operations, []admissionregistrationv1.OperationType{admissionregistrationv1.Update}) || len(r.ResourceNames) > 0 {
		t.Errorf("resource rule %+v, want UPDATE assessmentproviders/status", r)
	}

	// The identity logic is the reviewed EvidenceSigningRequest writer's.
	signing, _, _ := admissionDocs(t, "../../config/admission/evidence-signing-status-writer.yaml")
	if !reflect.DeepEqual(p.Spec.Variables, signing[0].Spec.Variables) || p.Spec.Validations[0].Expression != signing[0].Spec.Validations[0].Expression {
		t.Error("the controller identity check differs from konstapel-evidence-signing-status-writer's")
	}

	_, _, shipped := admissionDocs(t, "../../config/admission/assessment-run-scope.yaml")
	if len(shipped) != 1 || shipped[0].Name != ref.Name || shipped[0].Namespace != ref.Namespace {
		t.Fatalf("the shipped controller-identity ConfigMap is not %s/%s", ref.Namespace, ref.Name)
	}
	data := shipped[0].Data
	controller := "system:serviceaccount:" + data["controllerServiceAccountNamespace"] + ":" + data["controllerServiceAccountName"]
	if controller != "system:serviceaccount:konstapel-system:konstapel-controller" {
		t.Fatalf("shipped controller identity %s", controller)
	}
	const denied = "may write AssessmentProvider status"
	for _, c := range []struct {
		name, user string
		data       map[string]string
		allow      bool
		mention    string
	}{
		{"the configured controller", controller, data, true, ""},
		{"a cluster administrator", "kubernetes-admin", data, false, "only the Konstapel controller (konstapel-system/konstapel-controller) " + denied},
		{"the download service", "system:serviceaccount:konstapel-system:konstapel-download", data, false, denied},
		{"a longer name", controller + "-x", data, false, denied},
		{"another namespace's controller", "system:serviceaccount:team-a:konstapel-controller", data, false, denied},
		{"a user named like the account", "konstapel-controller", data, false, denied},
		{"an empty name", controller, map[string]string{"controllerServiceAccountNamespace": "konstapel-system", "controllerServiceAccountName": ""}, false, "(not configured) " + denied},
		{"an empty namespace", "system:serviceaccount::konstapel-controller", map[string]string{"controllerServiceAccountNamespace": "", "controllerServiceAccountName": "konstapel-controller"}, false, denied},
		{"no data", controller, nil, false, "(not configured) " + denied},
		{"no keys", controller, map[string]string{}, false, "(not configured) " + denied},
	} {
		allowed, msg := statusWriterDecision(t, p, c.user, c.data)
		if allowed != c.allow || !c.allow && !strings.Contains(msg, c.mention) {
			t.Errorf("%s: allowed %v (%q), want %v mentioning %q", c.name, allowed, msg, c.allow, c.mention)
		}
	}
}
