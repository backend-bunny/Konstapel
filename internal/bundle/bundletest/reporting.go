package bundletest

// Reporting-only check content (add-assessment-provider-contract Decision
// 8): a bundle whose provider contract is not the engine contract and whose
// policies are check definitions. The provider identity is a parameter, so
// this package names no provider; tests pass the test-only provider's.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing/fstest"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// ReportingCheck is one check definition of a reporting bundle.
type ReportingCheck struct {
	// Name is the logical check name: the definition's metadata.name, the
	// policy name and its rule and check ID.
	Name string
	// Definition is the definition document. Empty means a valid one of
	// ReportingOptions.APIVersion/Kind expecting Deployments.
	Definition string
	// ParameterSchema, when set, is packaged as the policy's content
	// parameter schema (which reporting-only content must not declare).
	ParameterSchema string
}

// ReportingOptions describe a reporting bundle.
type ReportingOptions struct {
	// Name and Version default to "reporting-checks" and "0.1.0".
	Name, Version string
	// Contract is compatibility.provider, e.g. "konstapel-reporttest/v1".
	Contract string
	// APIVersion and Kind are the default definitions' check kind.
	APIVersion, Kind string
	// Checks default to one check named "image-posture-current".
	Checks []ReportingCheck
	// ValidationTitle titles the component definition's validation
	// component; empty means the contract's provider name.
	ValidationTitle string
	// Source defaults to the repository at revision "f" * 40.
	Source bundle.Source
}

// ReportingDefinition is a valid check definition document.
func ReportingDefinition(apiVersion, kind, name string) string {
	return fmt.Sprintf("apiVersion: %s\nkind: %s\nmetadata:\n  name: %s\nspec:\n  resources:\n  - group: apps\n    version: v1\n    resource: deployments\n", apiVersion, kind, name)
}

// Reporting builds a reporting-only check bundle from the repository at
// repo: the NIST content and schemas are the repository's, the component
// definition is the repository's with the privileged-container rule renamed
// to each check and the validation component titled for the contract. The
// archive is built, not validated: tests decide what must reject it.
func Reporting(repo string, o ReportingOptions) (*bundle.Archive, error) {
	if o.Name == "" {
		o.Name = "reporting-checks"
	}
	if o.Version == "" {
		o.Version = "0.1.0"
	}
	if len(o.Checks) == 0 {
		o.Checks = []ReportingCheck{{Name: "image-posture-current"}}
	}
	if o.Source.Repository == "" {
		o.Source = bundle.Source{Repository: "https://github.com/backend-bunny/Konstapel", Revision: strings.Repeat("f", 40)}
	}
	provider, _, _ := strings.Cut(o.Contract, "/")
	if o.ValidationTitle == "" {
		o.ValidationTitle = provider
	}
	read := func(p string) ([]byte, error) { return os.ReadFile(filepath.Join(repo, filepath.FromSlash(p))) }
	src := fstest.MapFS{}
	add := func(p string, b []byte) { src[p] = &fstest.MapFile{Data: b} }
	for _, p := range []string{catalogPath, profilePath, "content/schemas/oscal-1.1.3.json", "content/schemas/oscal-1.2.3.json",
		"content/upstream/nist/LICENSE.md", "LICENSE"} {
		b, err := read(p)
		if err != nil {
			return nil, err
		}
		add(p, b)
	}
	cd, err := read("content/component-definition.json")
	if err != nil {
		return nil, err
	}
	const validation = `"title": "konstapel-kyverno",`
	if strings.Count(string(cd), validation) != 1 || strings.Count(string(cd), `"value": "`+assessment.PolicyName+`"`) != 5 {
		return nil, fmt.Errorf("vendored component definition changed; update bundletest.Reporting")
	}
	doc := strings.Replace(string(cd), validation, `"title": "`+o.ValidationTitle+`",`, 1)
	doc = strings.Replace(doc, "Kyverno policies.kyverno.io/v1 validation provider", "Reporting-only test validation provider", 1)
	// Every check maps like the vendored rule; the first one reuses it.
	doc = strings.ReplaceAll(doc, `"value": "`+assessment.PolicyName+`"`, `"value": "`+o.Checks[0].Name+`"`)
	if len(o.Checks) > 1 {
		return nil, fmt.Errorf("bundletest.Reporting maps one check")
	}
	add("content/component-definition.json", []byte(doc))
	add("content/provenance.json", []byte(`{
  "checkDefinitions": "authored test content; no upstream policy",
  "nistRepository": "https://github.com/usnistgov/oscal-content",
  "nistRevision": "f0de6d8d8c059d374f15e0ae07508d82e370fc1d",
  "schemaRepository": "https://github.com/usnistgov/OSCAL",
  "schemaVersions": ["1.1.3", "1.2.3"]
}
`))

	def := bundle.Definition{
		Name: o.Name, Version: o.Version, Source: o.Source,
		Scope:         bundle.Scope{Workloads: []string{"Deployment"}, OS: []string{"linux"}},
		Compatibility: bundle.Compatibility{Provider: o.Contract, Konstapel: "0.1.0"},
		OSCAL: []bundle.OSCALDocument{{Path: "content/component-definition.json", Version: "1.1.3"},
			{Path: catalogPath, Version: "1.2.3"}, {Path: profilePath, Version: "1.2.3"}},
		Include: []bundle.Include{
			{From: "content/component-definition.json", To: "content/component-definition.json", Role: bundle.RoleComponentDefinition},
			{From: "content/provenance.json", To: "content/provenance.json", Role: bundle.RoleProvenance},
			{Generate: bundle.GenerateSHA256Sums, To: "content/SHA256SUMS", Role: bundle.RoleChecksums},
			{From: "content/schemas/oscal-1.1.3.json", To: "content/schemas/oscal-1.1.3.json", Role: bundle.RoleSchema},
			{From: "content/schemas/oscal-1.2.3.json", To: "content/schemas/oscal-1.2.3.json", Role: bundle.RoleSchema},
			{From: catalogPath, To: catalogPath, Role: bundle.RoleUpstream},
			{From: profilePath, To: profilePath, Role: bundle.RoleUpstream},
			{From: "content/upstream/nist/LICENSE.md", To: "content/upstream/nist/LICENSE.md", Role: bundle.RoleLicense},
			{From: "LICENSE", To: "LICENSE", Role: bundle.RoleLicense},
		},
	}
	for _, c := range o.Checks {
		body := c.Definition
		if body == "" {
			body = ReportingDefinition(o.APIVersion, o.Kind, c.Name)
		}
		path := "content/checks/" + c.Name + ".yaml"
		add(path, []byte(body))
		// A declarative fixture: publication records name the tests that
		// ran, whatever the provider. Nothing here runs it.
		fixture := "tests/" + c.Name + "/fixture.yaml"
		add(fixture, []byte("check: "+c.Name+"\nexpect: pass\n"))
		def.Include = append(def.Include, bundle.Include{From: fixture, To: fixture, Role: bundle.RoleTest})
		p := bundle.Policy{Name: c.Name, Path: path, Checks: []bundle.Check{{RuleID: c.Name, CheckID: c.Name}}}
		def.Include = append(def.Include, bundle.Include{From: path, To: path, Role: bundle.RolePolicy})
		if c.ParameterSchema != "" {
			sp := "content/checks/" + c.Name + ".schema.json"
			add(sp, []byte(c.ParameterSchema))
			p.ParameterSchema = sp
			def.Include = append(def.Include, bundle.Include{From: sp, To: sp, Role: bundle.RoleSchema})
		}
		def.Policies = append(def.Policies, p)
	}
	return bundle.Build(def, src, time.Date(2026, 11, 28, 8, 0, 0, 0, time.UTC))
}
