package preview

import (
	"os"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/internal/crdtest"
)

// enforcementChangedProgram compiles the enforcementChanged variable of the
// shipped konstapel-binding-enforcement-epoch admission policy, so that the
// preview's mirror (enforcementFieldsChanged) is checked against the
// expression the API server actually evaluates rather than a restatement.
func enforcementChangedProgram(t *testing.T) cel.Program {
	t.Helper()
	raw, err := os.ReadFile("../../config/admission/binding-enforcement-epoch.yaml")
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(string(raw), "\n---\n")
	var policy struct {
		Kind string `json:"kind"`
		Spec struct {
			Variables []struct {
				Name       string `json:"name"`
				Expression string `json:"expression"`
			} `json:"variables"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal([]byte(first), &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Kind != "MutatingAdmissionPolicy" {
		t.Fatalf("unexpected first document %q", policy.Kind)
	}
	expr := ""
	for _, v := range policy.Spec.Variables {
		if v.Name == "enforcementChanged" {
			expr = v.Expression
		}
	}
	if expr == "" {
		t.Fatal("the admission policy no longer defines enforcementChanged; revisit enforcementFieldsChanged")
	}
	env, err := cel.NewEnv(cel.OptionalTypes(),
		cel.Variable("request", cel.DynType), cel.Variable("object", cel.DynType), cel.Variable("oldObject", cel.DynType))
	if err != nil {
		t.Fatal(err)
	}
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		t.Fatal(iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		t.Fatal(err)
	}
	return prg
}

// admissionEnforcementChanged evaluates the shipped policy's
// enforcementChanged expression for an UPDATE from live to proposed, on the
// specs as the API server presents them to admission (defaulted and pruned).
func admissionEnforcementChanged(t *testing.T, prg cel.Program, live, proposed map[string]any) bool {
	t.Helper()
	out, _, err := prg.Eval(map[string]any{
		"request":   map[string]any{"operation": "UPDATE"},
		"oldObject": map[string]any{"spec": storedForm(KindBinding, live)},
		"object":    map[string]any{"spec": storedForm(KindBinding, proposed)},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := out.Value().(bool)
	if !ok {
		t.Fatalf("enforcementChanged is %T", out.Value())
	}
	return got
}

// epochCases are the live bindings and the proposed edits the conformance
// tests evaluate pairwise: restatements, reporting-only edits, list order
// (the selector lists are atomic in the CRD, so plain CEL list equality,
// which is order-sensitive, is the API server's equality for them), and
// every enforcement field including a rollback.
func epochCases() (lives, cases map[string]string) {
	sel := "{matchExpressions: [{key: env, operator: In, values: [production, staging]}, {key: tier, operator: Exists}]}"
	live := bindingWith("b", "shared", "Deny", sel)
	cases = map[string]string{
		"restated":                live,
		"defaults written out":    live + "  assessment: {interval: 24h, maxEvidenceAge: 2h}\n",
		"reporting only":          live + "  assessment: {interval: 12h}\n",
		"every reporting setting": live + "  assessment: {interval: 1h, maxEvidenceAge: 30m, collectionTimeout: 10m, retention: 8760h, destinationRef: {name: archive, uid: d-1}}\n",
		"reordered expressions":   bindingWith("b", "shared", "Deny", "{matchExpressions: [{key: tier, operator: Exists}, {key: env, operator: In, values: [production, staging]}]}"),
		"reordered values":        bindingWith("b", "shared", "Deny", "{matchExpressions: [{key: env, operator: In, values: [staging, production]}, {key: tier, operator: Exists}]}"),
		"labels added":            bindingWith("b", "shared", "Deny", "{matchLabels: {a: b}, matchExpressions: [{key: env, operator: In, values: [production, staging]}, {key: tier, operator: Exists}]}"),
		"empty selector":          bindingWith("b", "shared", "Deny", "{}"),
		"mode":                    bindingWith("b", "shared", "Audit", sel),
		"profile":                 bindingWith("b", "other", "Deny", sel),
		"rollback to labels only": bindingWith("b", "shared", "Deny", "{matchLabels: {env: production}}"),
	}
	lives = map[string]string{
		"expressions": live,
		"labels":      bindingWith("b", "shared", "Deny", "{matchLabels: {env: production}}"),
		"empty":       bindingWith("b", "shared", "Deny", "{}"),
	}
	return lives, cases
}

// The preview decides whether an edit advances a binding's enforcement epoch
// with a Go mirror of the admission policy, because the assessment owner
// ships that classification only as the policy's CEL (and the CRD
// transition rule below), not as a Go function. For every pair here, the
// mirror must agree with the policy's own expression.
func TestEnforcementFieldsChangedMatchesTheAdmissionPolicy(t *testing.T) {
	prg := enforcementChangedProgram(t)
	spec := func(t *testing.T, doc string) map[string]any {
		t.Helper()
		return mustSet(t, doc).Objects[0].Spec
	}
	lives, cases := epochCases()
	for liveName, liveDoc := range lives {
		for name, doc := range cases {
			t.Run(liveName+"/"+name, func(t *testing.T) {
				old, proposed := spec(t, liveDoc), spec(t, doc)
				want := admissionEnforcementChanged(t, prg, old, proposed)
				if got := enforcementFieldsChanged(old, proposed); got != want {
					t.Fatalf("enforcementFieldsChanged = %v, the admission policy says %v", got, want)
				}
			})
		}
	}
}

// The CRD's transition rule is the API server's independent statement of
// the same classification: it accepts an update only with the epoch kept for
// a reporting-only edit and incremented by one for an enforcement change.
// The epoch the preview predicts must be the one the rule accepts, and the
// other choice must be rejected.
func TestEnforcementFieldsChangedMatchesTheCRDTransitionRule(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["ComplianceBinding"]
	object := func(spec map[string]any, epoch int64) map[string]any {
		s := runtime.DeepCopyJSON(spec)
		s["enforcementEpoch"] = epoch
		return map[string]any{"apiVersion": "compliance.erenius.io/v1alpha1", "kind": "ComplianceBinding",
			"metadata": map[string]any{"name": "b"}, "spec": s}
	}
	lives, cases := epochCases()
	for liveName, liveDoc := range lives {
		for name, doc := range cases {
			t.Run(liveName+"/"+name, func(t *testing.T) {
				old, proposed := mustSet(t, liveDoc).Objects[0].Spec, mustSet(t, doc).Objects[0].Spec
				const liveEpoch = 4
				predicted, other := int64(liveEpoch), int64(liveEpoch+1)
				if enforcementFieldsChanged(old, proposed) {
					predicted, other = other, predicted
				}
				if errs := v.ValidateUpdate(object(proposed, predicted), object(old, liveEpoch)); len(errs) > 0 {
					t.Fatalf("the CRD rejects the predicted epoch %d: %v", predicted, errs.ToAggregate())
				}
				errs := v.ValidateUpdate(object(proposed, other), object(old, liveEpoch))
				if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), "enforcementEpoch") {
					t.Fatalf("the CRD accepts epoch %d as well, so the prediction is not determined by it: %v", other, errs.ToAggregate())
				}
			})
		}
	}
}
