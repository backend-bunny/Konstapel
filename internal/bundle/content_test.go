package bundle

import (
	"strings"
	"testing"
	"testing/fstest"
)

const (
	cdPath     = "content/component-definition.json"
	policyPath = "content/upstream/kyverno/disallow-privileged-containers/disallow-privileged-containers.yaml"
)

// officialPayload returns a private copy of the real unpacked bundle so a
// test can corrupt one thing and see which rule rejects it.
func officialPayload(t *testing.T) (*Descriptor, fstest.MapFS) {
	t.Helper()
	a, files := buildOfficial(t)
	cp := fstest.MapFS{}
	for p, f := range files {
		cp[p] = &fstest.MapFile{Data: append([]byte(nil), f.Data...)}
	}
	d := *a.Descriptor
	d.Policies = append([]Policy(nil), d.Policies...)
	for i := range d.Policies {
		d.Policies[i].Checks = append([]Check(nil), d.Policies[i].Checks...)
	}
	d.OSCAL = append([]OSCALDocument(nil), d.OSCAL...)
	return &d, cp
}

func edit(files fstest.MapFS, p, old, new string) {
	files[p] = &fstest.MapFile{Data: []byte(strings.Replace(string(files[p].Data), old, new, 1))}
}

func TestOfficialContentValidates(t *testing.T) {
	d, files := officialPayload(t)
	if err := ValidateContent(d, files); err != nil {
		t.Fatal(err)
	}
	// Mixed declared OSCAL versions are the normal case: authored 1.1.3 beside
	// official 1.2.3.
	versions := map[string]bool{}
	for _, o := range d.OSCAL {
		versions[o.Version] = true
	}
	if !versions["1.1.3"] || !versions["1.2.3"] {
		t.Fatalf("official bundle should declare both OSCAL versions, got %v", versions)
	}
}

func TestContentRejections(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Descriptor, fstest.MapFS)
		want   string
	}{
		"other provider":         {func(d *Descriptor, f fstest.MapFS) { d.Compatibility.Provider = "evil-exec/v1" }, "only \"konstapel-kyverno/v1\""},
		"unknown schema version": {func(d *Descriptor, f fstest.MapFS) { d.OSCAL[0].Version = "1.9.0" }, "is not in the archive"},
		"declared version differs from document": {func(d *Descriptor, f fstest.MapFS) {
			d.OSCAL[1].Version = "1.1.3" // the catalog is 1.2.3
		}, "document says oscal-version"},
		"authored definition at 1.2.3": {func(d *Descriptor, f fstest.MapFS) {
			edit(f, cdPath, `"oscal-version": "1.1.3"`, `"oscal-version": "1.2.3"`)
			d.OSCAL[0].Version = "1.2.3"
		}, "must declare OSCAL 1.1.3"},
		"duplicate JSON key": {func(d *Descriptor, f fstest.MapFS) {
			edit(f, cdPath, `"metadata": {`, `"metadata": {"title": "a", "title": "b",`)
		}, "duplicate JSON key"},
		"duplicate YAML key": {func(d *Descriptor, f fstest.MapFS) {
			edit(f, policyPath, "kind: ValidatingPolicy\n", "kind: ValidatingPolicy\nkind: ValidatingPolicy\n")
		}, "already defined"},
		"unresolved control source": {func(d *Descriptor, f fstest.MapFS) {
			edit(f, cdPath, `"source": "upstream/nist/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"`, `"source": "upstream/nist/missing.json"`)
		}, "does not resolve inside the archive"},
		"external control source": {func(d *Descriptor, f fstest.MapFS) {
			edit(f, cdPath, `"source": "upstream/nist/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"`, `"source": "https://example.com/catalog.json"`)
		}, "is external"},
		"external component-definition import": {func(d *Descriptor, f fstest.MapFS) {
			edit(f, cdPath, `"components": [`, `"import-component-definitions": [{"href": "https://example.com/cd.json"}], "components": [`)
		}, "is external"},
		"external schema ref": {func(d *Descriptor, f fstest.MapFS) {
			f[schemaPath("1.1.3")] = &fstest.MapFile{Data: []byte(`{"$ref": "https://example.com/oscal.json"}`)}
		}, "external schema reference"},
		"control outside Moderate": {func(d *Descriptor, f fstest.MapFS) {
			edit(f, cdPath, `"control-id": "ac-6"`, `"control-id": "pm-1"`)
			edit(f, cdPath, `"statement-id": "ac-6_smt"`, `"statement-id": "pm-1_smt"`)
		}, "Moderate baseline"},
		"statement not in control": {func(d *Descriptor, f fstest.MapFS) {
			edit(f, cdPath, `"statement-id": "ac-6_smt"`, `"statement-id": "ac-2_smt"`)
		}, "invalid statement"},
		"mapped rule undeclared in descriptor": {func(d *Descriptor, f fstest.MapFS) {
			d.Policies[0].Checks = []Check{{RuleID: "other", CheckID: "other"}}
		}, "not mapped by any declared component definition"},
		"descriptor omits a mapped rule": {func(d *Descriptor, f fstest.MapFS) {
			d.Policies = append(d.Policies[:0:0], Policy{Name: "extra", Path: policyPath, Checks: []Check{{RuleID: "extra", CheckID: "extra"}}})
			edit(f, policyPath, "name: disallow-privileged-containers", "name: extra")
		}, "is not a vendored policy"},
		"policy name mismatch": {func(d *Descriptor, f fstest.MapFS) {
			edit(f, policyPath, "name: disallow-privileged-containers", "name: renamed")
		}, "metadata.name is \"renamed\""},
		"unsupported policy kind": {func(d *Descriptor, f fstest.MapFS) {
			edit(f, policyPath, "kind: ValidatingPolicy", "kind: ClusterPolicy")
		}, "only policies.kyverno.io/v1 ValidatingPolicy"},
		"check id differs from rule id": {func(d *Descriptor, f fstest.MapFS) {
			d.Policies[0].Checks[0].CheckID = "different"
		}, "must equal ruleID"},
		"missing catalog": {func(d *Descriptor, f fstest.MapFS) {
			d.OSCAL = d.OSCAL[:1]
			delete(f, "content/upstream/nist/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json")
		}, "catalog"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d, files := officialPayload(t)
			tc.mutate(d, files)
			err := ValidateContent(d, files)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestDuplicateKeyScanner(t *testing.T) {
	for in, ok := range map[string]bool{
		`{"a":1,"b":{"a":2},"c":[{"a":1},{"a":2}]}`: true,
		`{"a":1,"a":2}`:             false,
		`{"a":{"b":1,"b":2}}`:       false,
		`[{"a":1},{"a":1}]`:         true,
		`{"a":[1,2],"b":"x","a":3}`: false,
		`"scalar"`:                  true,
	} {
		if err := noDuplicateJSONKeys([]byte(in)); (err == nil) != ok {
			t.Errorf("%s: err=%v, want ok=%v", in, err, ok)
		}
	}
	if _, err := ParseDescriptor([]byte(`{"format":"x","format":"y"}`)); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Errorf("descriptor with a repeated key: %v", err)
	}
}

func paramFixture() (*Descriptor, fstest.MapFS) {
	d := &Descriptor{Name: "p", Policies: []Policy{
		{Name: "tunable", Path: "content/policies/t.yaml", ParameterSchema: "content/schemas/t.json"},
		{Name: "fixed", Path: "content/policies/f.yaml"},
	}}
	return d, fstest.MapFS{"content/schemas/t.json": {Data: []byte(`{
		"type": "object", "additionalProperties": false, "required": ["allowedImages"],
		"properties": {"allowedImages": {"type": "array", "items": {"type": "string"}}}}`)}}
}

func TestValidateParameters(t *testing.T) {
	d, files := paramFixture()
	ok := map[string]any{"allowedImages": []any{"registry.example/app"}}
	for name, tc := range map[string]struct {
		policy string
		params map[string]any
		want   string
	}{
		"valid":                {"tunable", ok, ""},
		"missing required":     {"tunable", map[string]any{}, "allowedImages"},
		"unknown parameter":    {"tunable", map[string]any{"allowedImages": []any{}, "extra": 1}, "extra"},
		"wrong type":           {"tunable", map[string]any{"allowedImages": "x"}, "allowedImages"},
		"none for fixed":       {"fixed", nil, ""},
		"unexpected for fixed": {"fixed", map[string]any{"a": 1}, "declares no parameters"},
		"unknown policy":       {"absent", nil, "no policy"},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateParameters(d, files, tc.policy, tc.params)
			if (tc.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParameterSchemaMustBeSelfContained(t *testing.T) {
	d, files := paramFixture()
	for name, schema := range map[string]string{
		"remote ref": `{"type":"object","properties":{"a":{"$ref":"https://example.com/s.json"}}}`,
		"file ref":   `{"type":"object","properties":{"a":{"$ref":"other.json"}}}`,
		"not object": `{"type":"string"}`,
		"duplicate":  `{"type":"object","type":"object"}`,
		"invalid":    `{"type":"object","properties":{"a":{"type":"bogus"}}}`,
		"not a doc":  `nope`,
	} {
		t.Run(name, func(t *testing.T) {
			files["content/schemas/t.json"] = &fstest.MapFile{Data: []byte(schema)}
			if err := ValidateParameters(d, files, "tunable", map[string]any{}); err == nil {
				t.Fatal("accepted an unsafe or invalid parameter schema")
			}
		})
	}
}
