package v1alpha1_test

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/crdtest"
)

type example struct {
	path   string
	expect string
	obj    map[string]any
}

func readExamples(t *testing.T, dir string) []example {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("../../testdata/targeting/examples", dir, "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no examples in %s: %v", dir, err)
	}
	var out []example
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		e := example{path: f}
		sc := bufio.NewScanner(bytes.NewReader(raw))
		for sc.Scan() {
			line := sc.Text()
			if rest, ok := strings.CutPrefix(line, "# expect: "); ok {
				e.expect = rest
			}
			if strings.HasPrefix(line, "# Scenario: ") {
				scenario := strings.TrimPrefix(line, "# Scenario: ")
				if i := strings.Index(scenario, " ("); i > 0 {
					scenario = scenario[:i]
				}
				for _, s := range strings.Split(scenario, " / ") {
					requireSpecScenario(t, f, s)
				}
			}
		}
		if err := yaml.Unmarshal(raw, &e.obj); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out = append(out, e)
	}
	return out
}

func TestValidExamplesAreAccepted(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	for _, e := range readExamples(t, "valid") {
		t.Run(filepath.Base(e.path), func(t *testing.T) {
			kind, _ := e.obj["kind"].(string)
			v := crds[kind]
			if v == nil {
				t.Fatalf("no CRD for kind %q", kind)
			}
			if errs := v.Validate(e.obj); len(errs) > 0 {
				t.Fatalf("rejected: %v", errs.ToAggregate())
			}
			// Accepted objects also decode strictly into the Go types.
			raw, _ := yaml.Marshal(e.obj)
			var typed any
			switch kind {
			case "ComplianceProfile":
				typed = &v1alpha1.ComplianceProfile{}
			case "ComplianceBinding":
				typed = &v1alpha1.ComplianceBinding{}
			}
			if err := yaml.UnmarshalStrict(raw, typed); err != nil {
				t.Fatalf("does not decode into Go type: %v", err)
			}
		})
	}
}

func TestInvalidExamplesAreRejectedWithFieldErrors(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	for _, e := range readExamples(t, "invalid") {
		t.Run(filepath.Base(e.path), func(t *testing.T) {
			if e.expect == "" {
				t.Fatal("invalid example has no '# expect:' line")
			}
			kind, _ := e.obj["kind"].(string)
			errs := crds[kind].Validate(e.obj)
			if len(errs) == 0 {
				t.Fatal("accepted, want rejection")
			}
			got := errs.ToAggregate().Error()
			if !strings.Contains(got, e.expect) {
				t.Fatalf("want error containing %q, got %q", e.expect, got)
			}
			if testing.Verbose() {
				t.Log(got)
			}
		})
	}
}

func TestExceptionEligibilityDefaultsToForbidden(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	for _, e := range readExamples(t, "valid") {
		if filepath.Base(e.path) != "profile-baseline.yaml" {
			continue
		}
		if errs := crds["ComplianceProfile"].Validate(e.obj); len(errs) > 0 {
			t.Fatal(errs.ToAggregate())
		}
		raw, _ := yaml.Marshal(e.obj)
		p := &v1alpha1.ComplianceProfile{}
		if err := yaml.Unmarshal(raw, p); err != nil {
			t.Fatal(err)
		}
		for _, pol := range p.Spec.Policies {
			if pol.Name == "require-run-as-non-root" {
				if pol.Exceptions.Eligibility != v1alpha1.ExceptionsForbidden {
					t.Fatalf("defaulted eligibility = %q, want Forbidden", pol.Exceptions.Eligibility)
				}
				return
			}
		}
	}
	t.Fatal("baseline example lacks a policy without exception settings")
}

// requireSpecScenario ties each example to a capability scenario, so examples
// cannot drift from the spec they illustrate.
func requireSpecScenario(t *testing.T, file, scenario string) {
	t.Helper()
	for _, spec := range []string{
		"../../openspec/specs/compliance-targeting/spec.md",
		"../../openspec/specs/compliance-targeting/spec.md",
	} {
		raw, err := os.ReadFile(spec)
		if err == nil && bytes.Contains(raw, []byte("#### Scenario: "+scenario+"\n")) {
			return
		}
	}
	t.Errorf("%s: scenario %q is not in the compliance-targeting spec", file, scenario)
}
