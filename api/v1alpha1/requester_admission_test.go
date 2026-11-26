package v1alpha1_test

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/policy/mutating/patch"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/cel/environment"
	"sigs.k8s.io/yaml"
)

// The shipped requester admission policies, evaluated offline with the API
// server's own CEL compiler and JSON Patch mutation (k8s.io/apiserver):
// konstapel-assessment-requester (AssessmentRequest spec.requester),
// konstapel-evidence-attachment-registrant (EvidenceAttachment
// spec.registeredBy) and konstapel-evidence-signing-requester
// (EvidenceSigningRequest spec.requestedBy).
//   - The mutation replaces the requester field as a whole with the
//     authenticated user: a forged name or UID never survives, also for a
//     user without a UID (X.509 or OIDC), and the rest of the spec is
//     unchanged.
//   - The validation, the fail-closed backstop when the mutation did not
//     run, admits exactly the authenticated user and nothing else.
// The API server's enforcement of the same files is
// TestLiveRequesterAttribution and TestLiveSigningRecoveryCredentials.

type requesterPolicy struct {
	file, field string
	gvr         schema.GroupVersionResource
	kind        string
	namespace   string
	spec        map[string]any
}

var requesterPolicies = []requesterPolicy{
	{"assessment-requester.yaml", "requester", schema.GroupVersionResource{Group: "compliance.erenius.io", Version: "v1alpha1", Resource: "assessmentrequests"},
		"AssessmentRequest", "team-a", map[string]any{"bindingRef": map[string]any{"name": "audit"}}},
	{"evidence-attachment-registrant.yaml", "registeredBy", schema.GroupVersionResource{Group: "compliance.erenius.io", Version: "v1alpha1", Resource: "evidenceattachments"},
		"EvidenceAttachment", "", map[string]any{"scope": map[string]any{"description": "DC North"}, "source": map[string]any{"issuer": "Example Audit AB"}}},
	{"evidence-signing-requester.yaml", "requestedBy", schema.GroupVersionResource{Group: "compliance.erenius.io", Version: "v1alpha1", Resource: "evidencesigningrequests"},
		"EvidenceSigningRequest", "", map[string]any{"reason": "key restored", "run": map[string]any{"name": "r", "uid": "0b1c2d3e-4f50-4617-8899-aabbccddeeff"}}},
}

// celCondition is a boolean validation expression.
type celCondition string

func (c celCondition) GetExpression() string  { return string(c) }
func (celCondition) ReturnTypes() []*cel.Type { return []*cel.Type{cel.BoolType} }

// requesterPolicyFile returns the mutation and the validation expressions of
// a shipped requester policy file, and checks that each is bound.
func requesterPolicyFile(t *testing.T, file string) (admissionregistrationv1.MutatingAdmissionPolicy, admissionregistrationv1.ValidatingAdmissionPolicy) {
	t.Helper()
	raw, err := os.ReadFile("../../config/admission/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var (
		maps  []admissionregistrationv1.MutatingAdmissionPolicy
		vaps  []admissionregistrationv1.ValidatingAdmissionPolicy
		bound = map[string]string{}
	)
	for _, doc := range strings.Split(string(raw), "\n---") {
		var meta struct{ Kind string }
		if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		switch meta.Kind {
		case "MutatingAdmissionPolicy":
			var p admissionregistrationv1.MutatingAdmissionPolicy
			if err := yaml.UnmarshalStrict([]byte(doc), &p); err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			maps = append(maps, p)
		case "ValidatingAdmissionPolicy":
			var p admissionregistrationv1.ValidatingAdmissionPolicy
			if err := yaml.UnmarshalStrict([]byte(doc), &p); err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			vaps = append(vaps, p)
		case "MutatingAdmissionPolicyBinding":
			var b admissionregistrationv1.MutatingAdmissionPolicyBinding
			if err := yaml.UnmarshalStrict([]byte(doc), &b); err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			bound["mutating "+b.Spec.PolicyName] = b.Name
		case "ValidatingAdmissionPolicyBinding":
			var b admissionregistrationv1.ValidatingAdmissionPolicyBinding
			if err := yaml.UnmarshalStrict([]byte(doc), &b); err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			if !reflect.DeepEqual(b.Spec.ValidationActions, []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}) {
				t.Errorf("%s: binding %s actions %v, want Deny", file, b.Name, b.Spec.ValidationActions)
			}
			bound["validating "+b.Spec.PolicyName] = b.Name
		case "":
		default:
			t.Fatalf("%s: unexpected %s", file, meta.Kind)
		}
	}
	if len(maps) != 1 || len(vaps) != 1 {
		t.Fatalf("%s: %d mutating and %d validating policies, want one each", file, len(maps), len(vaps))
	}
	m, v := maps[0], vaps[0]
	for _, p := range []struct {
		what, name string
		fail       *admissionregistrationv1.FailurePolicyType
	}{{"mutating", m.Name, m.Spec.FailurePolicy}, {"validating", v.Name, v.Spec.FailurePolicy}} {
		if bound[p.what+" "+p.name] == "" {
			t.Errorf("%s: %s policy %s is not bound", file, p.what, p.name)
		}
		if p.fail == nil || *p.fail != admissionregistrationv1.Fail {
			t.Errorf("%s: %s policy %s does not fail closed", file, p.what, p.name)
		}
	}
	if len(m.Spec.Mutations) != 1 || m.Spec.Mutations[0].PatchType != admissionregistrationv1.PatchTypeJSONPatch || m.Spec.Mutations[0].JSONPatch == nil {
		// An apply configuration merges into the submitted value and
		// cannot remove a forged UID when the user has none.
		t.Fatalf("%s: want one JSON Patch mutation that replaces the requester as a whole, got %+v", file, m.Spec.Mutations)
	}
	if len(v.Spec.Validations) != 1 {
		t.Fatalf("%s: %d validations, want one", file, len(v.Spec.Validations))
	}
	return m, v
}

func TestRequesterPoliciesRecordTheAuthenticatedUser(t *testing.T) {
	compiler, err := plugincel.NewCompositedCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()))
	if err != nil {
		t.Fatal(err)
	}
	users := map[string]*user.DefaultInfo{
		"ServiceAccount (with UID)":    {Name: "system:serviceaccount:platform:recoverer", UID: "6d538944-3924-4942-8c00-012ebdc047d7", Groups: []string{"system:serviceaccounts", "system:authenticated"}},
		"certificate or OIDC (no UID)": {Name: "platform-admin", Groups: []string{"platform-admins", "system:authenticated"}},
	}
	const other = "someone-else"
	for _, pol := range requesterPolicies {
		m, v := requesterPolicyFile(t, pol.file)
		mutation := compiler.CompileMutatingEvaluator(&patch.JSONPatchCondition{Expression: m.Spec.Mutations[0].JSONPatch.Expression},
			plugincel.OptionalVariableDeclarations{HasPatchTypes: true}, environment.NewExpressions)
		if errs := mutation.CompilationErrors(); len(errs) > 0 {
			t.Fatalf("%s: mutation: %v", pol.file, errs)
		}
		validation := compiler.CompileCondition([]plugincel.ExpressionAccessor{celCondition(v.Spec.Validations[0].Expression)},
			plugincel.OptionalVariableDeclarations{}, environment.NewExpressions)
		if errs := validation.CompilationErrors(); len(errs) > 0 {
			t.Fatalf("%s: validation: %v", pol.file, errs)
		}
		gvk := pol.gvr.GroupVersion().WithKind(pol.kind)
		object := func(supplied map[string]any) *unstructured.Unstructured {
			spec := runtime.DeepCopyJSON(pol.spec)
			if supplied != nil {
				spec[pol.field] = supplied
			}
			o := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
			o.SetGroupVersionKind(gvk)
			o.SetName("probe")
			o.SetNamespace(pol.namespace)
			return o
		}
		attributes := func(o *unstructured.Unstructured, u user.Info) *admission.VersionedAttributes {
			a := admission.NewAttributesRecord(o, nil, gvk, pol.namespace, o.GetName(), pol.gvr, "", admission.Create, &metav1.CreateOptions{}, false, u)
			return &admission.VersionedAttributes{Attributes: a, VersionedKind: gvk, VersionedObject: admission.NewLazyObject(o), VersionedOldObject: admission.NewLazyObject(nil)}
		}
		mutate := func(o *unstructured.Unstructured, u user.Info) *unstructured.Unstructured {
			t.Helper()
			got, err := patch.NewJSONPatcher(mutation).Patch(context.Background(), patch.Request{MatchedResource: pol.gvr, VersionedAttributes: attributes(o, u),
				ObjectInterfaces: admission.NewObjectInterfacesFromScheme(runtime.NewScheme())}, celconfig.RuntimeCELCostBudget)
			if err != nil {
				t.Fatalf("%s: mutation: %v", pol.file, err)
			}
			return got.(*unstructured.Unstructured)
		}
		admits := func(o *unstructured.Unstructured, u user.Info) bool {
			t.Helper()
			va := attributes(o, u)
			req := plugincel.CreateAdmissionRequest(va.Attributes, metav1.GroupVersionResource(pol.gvr), metav1.GroupVersionKind(gvk))
			results, _, err := validation.ForInput(context.Background(), va, req, plugincel.OptionalVariableBindings{}, nil, celconfig.RuntimeCELCostBudget)
			if err != nil || len(results) != 1 || results[0].Error != nil {
				t.Fatalf("%s: validation: %v %+v", pol.file, err, results)
			}
			return results[0].EvalResult == types.True
		}
		for who, u := range users {
			self := map[string]any{"username": u.Name}
			if u.UID != "" {
				self["uid"] = u.UID
			}
			for name, supplied := range map[string]map[string]any{
				"absent":                         nil,
				"another user":                   {"username": other},
				"another user and UID":           {"username": other, "uid": "uid-" + other},
				"its own name with a forged UID": {"username": u.Name, "uid": "uid-forged"},
				"its own name and UID":           self,
				"blank":                          {"username": ""},
			} {
				in := object(supplied)
				if got, want := admits(in, u), reflect.DeepEqual(supplied, self); got != want {
					t.Errorf("%s, %s supplies %s: validation alone admits %v, want %v", pol.file, who, name, got, want)
				}
				out := mutate(in, u)
				spec, _, _ := unstructured.NestedMap(out.Object, "spec")
				if got := spec[pol.field]; !reflect.DeepEqual(got, self) {
					t.Errorf("%s, %s supplies %s: recorded %v, want %v", pol.file, who, name, got, self)
				}
				delete(spec, pol.field)
				if !reflect.DeepEqual(spec, pol.spec) {
					t.Errorf("%s, %s supplies %s: the mutation changed the rest of the spec: %v", pol.file, who, name, spec)
				}
				if !admits(out, u) {
					t.Errorf("%s, %s supplies %s: the validation rejects the mutated object", pol.file, who, name)
				}
				if !reflect.DeepEqual(in.Object["spec"].(map[string]any)[pol.field], supplied) && supplied != nil {
					t.Errorf("%s: the mutation changed the submitted object in place", pol.file)
				}
			}
		}
	}
}
