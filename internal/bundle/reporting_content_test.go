package bundle_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/bundletest"
)

// A provider-neutral reporting contract and kind for the bundle format
// tests; the test-only provider's own tests use its identity.
const (
	reportingContract = "example-reporting/v1"
	reportingAPI      = "reporting.example.test/v1"
	reportingKind     = "Posture"
)

func reporting(t *testing.T, o bundletest.ReportingOptions) (*bundle.Descriptor, fstest.MapFS) {
	t.Helper()
	if o.Contract == "" {
		o.Contract = reportingContract
	}
	if o.APIVersion == "" {
		o.APIVersion, o.Kind = reportingAPI, reportingKind
	}
	a, err := bundletest.Reporting("../..", o)
	if err != nil {
		t.Fatal(err)
	}
	d, files, err := bundle.Unpack(a.Layer)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.VerifyPayload(files); err != nil {
		t.Fatal(err)
	}
	return d, files
}

// Reporting-only check definitions are validated in the same payload,
// with the same OSCAL closure and mapping rules, under the bundle's own
// provider name.
func TestReportingCheckContentValidates(t *testing.T) {
	d, files := reporting(t, bundletest.ReportingOptions{})
	if err := bundle.ValidateContent(d, files); err != nil {
		t.Fatal(err)
	}
	if d.Format != bundle.FormatV1 || d.Compatibility.Provider != reportingContract {
		t.Fatalf("format %s provider %s", d.Format, d.Compatibility.Provider)
	}
	raw := files[d.Policies[0].Path].Data
	def, err := bundle.ParseCheckDefinition(raw)
	if err != nil {
		t.Fatal(err)
	}
	if def.CheckKind() != reportingAPI+"/"+reportingKind || def.Metadata.Name != "image-posture-current" ||
		len(def.Spec.Resources) != 1 || def.Spec.Resources[0] != (bundle.CheckResource{Group: "apps", Version: "v1", Resource: "deployments"}) {
		t.Fatalf("definition %+v", def)
	}
}

// Definitions are data: anything that is not the kind, the name or the
// expected resources rejects the bundle, so content can never select an
// executable, image, endpoint, permission or engine resource.
func TestReportingCheckContentRejections(t *testing.T) {
	def := func(body string) []bundletest.ReportingCheck {
		return []bundletest.ReportingCheck{{Name: "image-posture-current", Definition: body}}
	}
	base := bundletest.ReportingDefinition(reportingAPI, reportingKind, "image-posture-current")
	cases := map[string]struct {
		o    bundletest.ReportingOptions
		want string
	}{
		"executable image": {bundletest.ReportingOptions{Checks: def(base + "  image: registry.example.test/scanner@sha256:" + strings.Repeat("a", 64) + "\n")}, "field image not found"},
		"command":          {bundletest.ReportingOptions{Checks: def(base + "  command: [/bin/sh, -c, scan]\n")}, "field command not found"},
		"endpoint":         {bundletest.ReportingOptions{Checks: def(base + "endpoint: https://scanner.example.test\n")}, "field endpoint not found"},
		"permissions":      {bundletest.ReportingOptions{Checks: def(base + "  permissions:\n  - verbs: [get]\n")}, "field permissions not found"},
		"service account":  {bundletest.ReportingOptions{Checks: def(strings.Replace(base, "metadata:\n", "metadata:\n  annotations: {serviceAccount: scanner}\n", 1))}, "field annotations not found"},
		"parameter values": {bundletest.ReportingOptions{Checks: def(base + "  parameters: {maxEvidenceAge: 1h}\n")}, "field parameters not found"},
		"resource extras":  {bundletest.ReportingOptions{Checks: def(strings.Replace(base, "resource: deployments\n", "resource: deployments\n    verbs: [delete]\n", 1))}, "field verbs not found"},
		"engine policy": {bundletest.ReportingOptions{Checks: def(strings.Replace(base, "apiVersion: "+reportingAPI+"\nkind: "+reportingKind,
			"apiVersion: policies.kyverno.io/v1\nkind: ValidatingPolicy", 1))}, "is engine policy content"},
		"kyverno group": {bundletest.ReportingOptions{Checks: def(strings.Replace(base, reportingAPI, "kyverno.io/v1", 1))}, "is engine policy content"},
		"no resources":  {bundletest.ReportingOptions{Checks: def(strings.SplitAfter(base, "spec:\n")[0] + "  resources: []\n")}, "at least one resource"},
		"repeated resource": {bundletest.ReportingOptions{Checks: def(base + "  - group: apps\n    version: v1\n    resource: deployments\n")},
			"listed twice"},
		"core group spelled out": {bundletest.ReportingOptions{Checks: def(strings.Replace(base, "group: apps", "group: Core", 1))}, "spec.resources[0]"},
		"duplicate key":          {bundletest.ReportingOptions{Checks: def(base + "kind: Other\n")}, "already defined"},
		"second document":        {bundletest.ReportingOptions{Checks: def(base + "---\n" + base)}, "exactly one document"},
		"name differs":           {bundletest.ReportingOptions{Checks: def(strings.Replace(base, "name: image-posture-current", "name: other", 1))}, "metadata.name is \"other\""},
		"no group":               {bundletest.ReportingOptions{Checks: def(strings.Replace(base, reportingAPI, "v1", 1))}, "must be <group>/<version>"},
		"content parameter schema": {bundletest.ReportingOptions{Checks: []bundletest.ReportingCheck{{Name: "image-posture-current",
			ParameterSchema: `{"type":"object","properties":{"maxEvidenceAge":{"type":"string"}}}`}}}, "declares no parameter schema"},
		"validation component of another provider": {bundletest.ReportingOptions{ValidationTitle: "konstapel-kyverno"}, "missing validation provider example-reporting"},
		"definition under the engine contract":     {bundletest.ReportingOptions{Contract: bundle.EngineContract}, "only policies.kyverno.io/v1 ValidatingPolicy is supported"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d, files := reporting(t, c.o)
			err := bundle.ValidateContent(d, files)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want %q", err, c.want)
			}
		})
	}
}

// The payload inventory covers definitions exactly as policies: a changed
// definition byte fails the checksum before any content rule runs.
func TestReportingCheckContentChecksums(t *testing.T) {
	d, files := reporting(t, bundletest.ReportingOptions{})
	p := d.Policies[0].Path
	files[p] = &fstest.MapFile{Data: []byte(strings.Replace(string(files[p].Data), "deployments", "daemonsets", 1))}
	if err := d.VerifyPayload(files); err == nil || !strings.Contains(err.Error(), p) {
		t.Fatalf("tampered definition: %v", err)
	}
}

// Content closure: a reporting bundle's mappings must resolve inside it.
func TestReportingCheckContentClosure(t *testing.T) {
	d, files := reporting(t, bundletest.ReportingOptions{})
	delete(files, "content/upstream/nist/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json")
	if err := bundle.ValidateContent(d, files); err == nil {
		t.Fatal("a bundle without its catalog validated")
	}
	d, files = reporting(t, bundletest.ReportingOptions{})
	cd := "content/component-definition.json"
	files[cd] = &fstest.MapFile{Data: []byte(strings.Replace(string(files[cd].Data),
		`"source": "upstream/nist/`, `"source": "https://example.test/nist/`, 1))}
	if err := bundle.ValidateContent(d, files); err == nil || !strings.Contains(err.Error(), "external") {
		t.Fatalf("external mapping source: %v", err)
	}
}
