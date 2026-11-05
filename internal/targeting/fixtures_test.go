package targeting

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
	Bundles    []fixtureBundle              `json:"bundles"`
	Profiles   []v1alpha1.ComplianceProfile `json:"profiles"`
	Bindings   []v1alpha1.ComplianceBinding `json:"bindings"`
	Namespaces []fixtureNamespace           `json:"namespaces"`
}

type fixtureBundle struct {
	Name     string `json:"name"`
	Digest   string `json:"digest"`
	Policies []struct {
		Name  string `json:"name"`
		Scope string `json:"scope"`
	} `json:"policies"`
}

type fixtureNamespace struct {
	Name   string            `json:"name"`
	UID    string            `json:"uid"`
	Labels map[string]string `json:"labels"`
}

type fixtureStep struct {
	Description    string             `json:"description"`
	Namespaces     []fixtureNamespace `json:"namespaces,omitempty"`
	DeleteBindings []string           `json:"deleteBindings,omitempty"`
	Expected       fixtureExpected    `json:"expected"`
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
		"../../openspec/changes/add-compliance-targeting-api/specs/compliance-targeting/spec.md",
	} {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Fatal("compliance-targeting spec not found")
	return nil
}
