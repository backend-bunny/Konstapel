package preview

import (
	"os"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"sigs.k8s.io/yaml"
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

// The preview decides whether an edit advances a binding's enforcement epoch
// with a Go mirror of the admission policy. For every pair here, the mirror
// must agree with the policy's own CEL expression evaluated on the objects
// as the API server presents them to admission (defaulted and pruned). The
// selector lists are atomic in the CRD, so plain CEL list equality, which is
// order-sensitive, is the API server's equality for them.
func TestEnforcementFieldsChangedMatchesTheAdmissionPolicy(t *testing.T) {
	prg := enforcementChangedProgram(t)
	spec := func(t *testing.T, doc string) map[string]any {
		t.Helper()
		return mustSet(t, doc).Objects[0].Spec
	}
	sel := "{matchExpressions: [{key: env, operator: In, values: [production, staging]}, {key: tier, operator: Exists}]}"
	live := bindingWith("b", "shared", "Deny", sel)
	cases := map[string]string{
		"restated":                live,
		"defaults written out":    live + "  assessment: {interval: 24h, maxEvidenceAge: 2h}\n",
		"reporting only":          live + "  assessment: {interval: 12h}\n",
		"reordered expressions":   bindingWith("b", "shared", "Deny", "{matchExpressions: [{key: tier, operator: Exists}, {key: env, operator: In, values: [production, staging]}]}"),
		"reordered values":        bindingWith("b", "shared", "Deny", "{matchExpressions: [{key: env, operator: In, values: [staging, production]}, {key: tier, operator: Exists}]}"),
		"labels added":            bindingWith("b", "shared", "Deny", "{matchLabels: {a: b}, matchExpressions: [{key: env, operator: In, values: [production, staging]}, {key: tier, operator: Exists}]}"),
		"empty selector":          bindingWith("b", "shared", "Deny", "{}"),
		"mode":                    bindingWith("b", "shared", "Audit", sel),
		"profile":                 bindingWith("b", "other", "Deny", sel),
		"rollback to labels only": bindingWith("b", "shared", "Deny", "{matchLabels: {env: production}}"),
	}
	lives := map[string]string{
		"expressions": live,
		"labels":      bindingWith("b", "shared", "Deny", "{matchLabels: {env: production}}"),
		"empty":       bindingWith("b", "shared", "Deny", "{}"),
	}
	for liveName, liveDoc := range lives {
		for name, doc := range cases {
			t.Run(liveName+"/"+name, func(t *testing.T) {
				old, proposed := spec(t, liveDoc), spec(t, doc)
				out, _, err := prg.Eval(map[string]any{
					"request":   map[string]any{"operation": "UPDATE"},
					"oldObject": map[string]any{"spec": storedForm(KindBinding, old)},
					"object":    map[string]any{"spec": storedForm(KindBinding, proposed)},
				})
				if err != nil {
					t.Fatal(err)
				}
				want, ok := out.Value().(bool)
				if !ok {
					t.Fatalf("enforcementChanged is %T", out.Value())
				}
				if got := enforcementFieldsChanged(old, proposed); got != want {
					t.Fatalf("enforcementFieldsChanged = %v, the admission policy says %v", got, want)
				}
			})
		}
	}
}
