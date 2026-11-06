package targeting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/crdtest"
)

// The resolver fixture format. The README in testdata/targeting/resolver
// documents it; the group 2 resolver tests run these cases.

type fixtureCase struct {
	Scenarios []string        `json:"scenarios"`
	Input     fixtureInput    `json:"input"`
	Expected  fixtureExpected `json:"expected"`
	Steps     []fixtureStep   `json:"steps,omitempty"`
}

type fixtureInput struct {
	Cluster    string                       `json:"cluster"`
	Bundles    []Bundle                     `json:"bundles"`
	Profiles   []v1alpha1.ComplianceProfile `json:"profiles"`
	Bindings   []v1alpha1.ComplianceBinding `json:"bindings"`
	Namespaces []Namespace                  `json:"namespaces"`
}

type fixtureStep struct {
	Description    string          `json:"description"`
	Namespaces     []Namespace     `json:"namespaces,omitempty"`
	DeleteBindings []string        `json:"deleteBindings,omitempty"`
	Expected       fixtureExpected `json:"expected"`
}

type fixtureExpected struct {
	Bindings []struct {
		Binding       string   `json:"binding"`
		Targets       []string `json:"targets"`
		Contributions []struct {
			Policy string                   `json:"policy"`
			Mode   v1alpha1.EnforcementMode `json:"mode"`
		} `json:"contributions"`
		Errors []struct {
			Reason Reason `json:"reason"`
			Policy string `json:"policy,omitempty"`
		} `json:"errors,omitempty"`
	} `json:"bindings"`
	Eligibility []struct {
		Namespace    string                        `json:"namespace"`
		Policy       string                        `json:"policy"`
		Effective    v1alpha1.ExceptionEligibility `json:"effective"`
		MaxLifetime  *Duration                     `json:"maxLifetime,omitempty"`
		Contributors []string                      `json:"contributors"`
		Errors       []Reason                      `json:"errors,omitempty"`
	} `json:"eligibility"`
}

func loadFixtures(t *testing.T) map[string]fixtureCase {
	t.Helper()
	files, err := filepath.Glob("../../testdata/targeting/resolver/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no resolver fixtures: %v", err)
	}
	out := map[string]fixtureCase{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var c fixtureCase
		if err := yaml.UnmarshalStrict(raw, &c); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out[filepath.Base(f)] = c
	}
	return out
}

func TestResolverFixturesAreWellFormed(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	spec := readSpec(t)
	for name, c := range loadFixtures(t) {
		t.Run(name, func(t *testing.T) {
			if len(c.Scenarios) == 0 {
				t.Fatal("no scenarios")
			}
			for _, s := range c.Scenarios {
				if !bytes.Contains(spec, []byte("#### Scenario: "+s+"\n")) {
					t.Errorf("scenario %q is not in the compliance-targeting spec", s)
				}
			}
			// Every input object must be admissible, so fixtures cannot test
			// configurations the API server would never store.
			check := func(kind, objName string, v any) {
				raw, _ := json.Marshal(v)
				var obj map[string]any
				_ = json.Unmarshal(raw, &obj)
				obj["apiVersion"] = v1alpha1.GroupVersion.String()
				obj["kind"] = kind
				delete(obj, "status")
				if errs := crds[kind].Validate(obj); len(errs) > 0 {
					t.Errorf("%s %s is not admissible: %v", kind, objName, errs.ToAggregate())
				}
			}
			for _, p := range c.Input.Profiles {
				check("ComplianceProfile", p.Name, p)
			}
			for _, b := range c.Input.Bindings {
				check("ComplianceBinding", b.Name, b)
				if _, err := b.Spec.NamespaceSelector.AsSelector(); err != nil {
					t.Errorf("binding %s: %v", b.Name, err)
				}
			}
			if c.Input.Cluster == "" || len(c.Input.Bundles) == 0 {
				t.Error("input needs a cluster identity and bundle metadata")
			}
		})
	}
}

func readSpec(t *testing.T) []byte {
	t.Helper()
	for _, p := range []string{
		"../../openspec/specs/compliance-targeting/spec.md",
		"../../openspec/specs/compliance-targeting/spec.md",
	} {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Fatal("compliance-targeting spec not found")
	return nil
}

// project reduces a Result to the fixture's expected shape.
func project(r Result) fixtureExpected {
	var out fixtureExpected
	raw, _ := json.Marshal(struct {
		Bindings    []map[string]any `json:"bindings"`
		Eligibility []map[string]any `json:"eligibility"`
	}{projectBindings(r), projectEligibility(r)})
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return out
}

func projectBindings(r Result) []map[string]any {
	out := []map[string]any{}
	for _, b := range r.Bindings {
		targets := []string{}
		for _, t := range b.Targets {
			targets = append(targets, t.Name)
		}
		cs := []map[string]any{}
		for _, c := range b.Contributions {
			cs = append(cs, map[string]any{"policy": c.Policy, "mode": c.Mode})
		}
		m := map[string]any{"binding": b.Binding.Name, "targets": targets, "contributions": cs}
		if len(b.Errors) > 0 {
			errs := []map[string]any{}
			for _, e := range b.Errors {
				errs = append(errs, map[string]any{"reason": e.Reason, "policy": e.Policy})
			}
			m["errors"] = errs
		}
		out = append(out, m)
	}
	return out
}

func projectEligibility(r Result) []map[string]any {
	out := []map[string]any{}
	for _, e := range r.Eligibility {
		names := []string{}
		for _, c := range e.Contributors {
			names = append(names, c.Binding.Name)
		}
		m := map[string]any{"namespace": e.Namespace.Name, "policy": e.Policy, "effective": e.Effective, "contributors": names}
		if e.MaxLifetime != nil {
			m["maxLifetime"] = e.MaxLifetime
		}
		if len(e.Errors) > 0 {
			reasons := []Reason{}
			for _, er := range e.Errors {
				reasons = append(reasons, er.Reason)
			}
			m["errors"] = reasons
		}
		out = append(out, m)
	}
	return out
}

func (f fixtureInput) input() Input {
	return Input{Cluster: f.Cluster, Bundles: f.Bundles, Profiles: f.Profiles, Bindings: f.Bindings, Namespaces: f.Namespaces}
}

// shuffled returns a deep copy of in with every list in a random order.
func shuffled(in Input, rng *rand.Rand) Input {
	var out Input
	raw, _ := json.Marshal(in)
	_ = json.Unmarshal(raw, &out)
	shuffle := func(n int, swap func(i, j int)) { rng.Shuffle(n, swap) }
	shuffle(len(out.Bundles), func(i, j int) { out.Bundles[i], out.Bundles[j] = out.Bundles[j], out.Bundles[i] })
	for _, b := range out.Bundles {
		shuffle(len(b.Policies), func(i, j int) { b.Policies[i], b.Policies[j] = b.Policies[j], b.Policies[i] })
	}
	shuffle(len(out.Profiles), func(i, j int) { out.Profiles[i], out.Profiles[j] = out.Profiles[j], out.Profiles[i] })
	for _, p := range out.Profiles {
		shuffle(len(p.Spec.Policies), func(i, j int) { p.Spec.Policies[i], p.Spec.Policies[j] = p.Spec.Policies[j], p.Spec.Policies[i] })
	}
	shuffle(len(out.Bindings), func(i, j int) { out.Bindings[i], out.Bindings[j] = out.Bindings[j], out.Bindings[i] })
	shuffle(len(out.Namespaces), func(i, j int) { out.Namespaces[i], out.Namespaces[j] = out.Namespaces[j], out.Namespaces[i] })
	return out
}

// resolveStable resolves in, then checks that 50 random input orders produce
// an identical Result, revisions included.
func resolveStable(t *testing.T, in Input) Result {
	t.Helper()
	want := Resolve(in)
	for _, b := range want.Bindings {
		if b.TargetCount != len(b.Targets) {
			t.Fatalf("binding %s: targetCount %d, but %d targets", b.Binding.Name, b.TargetCount, len(b.Targets))
		}
	}
	wantJSON, _ := json.Marshal(want)
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range 50 {
		got, _ := json.Marshal(Resolve(shuffled(in, rng)))
		if string(got) != string(wantJSON) {
			t.Fatalf("permutation %d changed the result:\nwant %s\ngot  %s", i, wantJSON, got)
		}
	}
	return want
}

func TestResolverFixtures(t *testing.T) {
	for name, c := range loadFixtures(t) {
		t.Run(name, func(t *testing.T) {
			in := c.Input.input()
			compare(t, "input", c.Expected, resolveStable(t, in))
			for i, step := range c.Steps {
				if step.Namespaces != nil {
					in.Namespaces = step.Namespaces
				}
				in.Bindings = slices.DeleteFunc(in.Bindings, func(b v1alpha1.ComplianceBinding) bool {
					return slices.Contains(step.DeleteBindings, b.Name)
				})
				compare(t, fmt.Sprintf("step %d (%s)", i+1, step.Description), step.Expected, resolveStable(t, in))
			}
		})
	}
}

func compare(t *testing.T, label string, want fixtureExpected, got Result) {
	t.Helper()
	w, _ := json.MarshalIndent(normalize(want), "", "  ")
	g, _ := json.MarshalIndent(normalize(project(got)), "", "  ")
	if string(w) != string(g) {
		t.Errorf("%s:\nwant %s\ngot  %s", label, w, g)
	}
}

// normalize makes nil and empty lists compare equal.
func normalize(e fixtureExpected) fixtureExpected {
	raw, _ := json.Marshal(e)
	var m any
	_ = json.Unmarshal(raw, &m)
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				if l, ok := val.([]any); ok && len(l) == 0 || val == nil {
					delete(x, k)
					continue
				}
				x[k] = walk(val)
			}
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
		}
		return v
	}
	m = walk(m)
	raw, _ = json.Marshal(m)
	var out fixtureExpected
	_ = json.Unmarshal(raw, &out)
	return out
}

// TestDocsCiteEveryResolverFixture keeps the targeting guide and the
// executable fixtures in step: every fixture is documented, and every
// documented fixture exists and therefore runs.
func TestDocsCiteEveryResolverFixture(t *testing.T) {
	doc, err := os.ReadFile("../../docs/integration/targeting-api.md")
	if err != nil {
		t.Fatal(err)
	}
	cited := map[string]bool{}
	for _, m := range regexp.MustCompile(`testdata/targeting/resolver/([a-z0-9-]+\.yaml)`).FindAllSubmatch(doc, -1) {
		cited[string(m[1])] = true
	}
	fixtures := loadFixtures(t)
	for name := range fixtures {
		if !cited[name] {
			t.Errorf("resolver fixture %s is not cited in docs/integration/targeting-api.md", name)
		}
	}
	for name := range cited {
		if _, ok := fixtures[name]; !ok {
			t.Errorf("docs cite %s, which does not exist", name)
		}
	}
}
