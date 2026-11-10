package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"
)

// fixture builds a payload and its matching descriptor. org switches to an
// organization-style bundle (no upstream NIST sources, a custom variant).
func fixture(t *testing.T, org bool) (*Descriptor, fstest.MapFS) {
	t.Helper()
	files := map[string]struct{ role, body string }{
		"content/component-definition.json": {RoleComponentDefinition, `{"component-definition":{}}`},
		"content/policies/privileged.yaml":  {RolePolicy, "kind: ClusterPolicy\n"},
		"content/schemas/privileged.json":   {RoleSchema, `{"type":"object"}`},
		"content/provenance.json":           {RoleProvenance, `{"tool":"x"}`},
		"content/SHA256SUMS":                {RoleChecksums, "abc  content/policies/privileged.yaml\n"},
		"tests/privileged.yaml":             {RoleTest, "cases: []\n"},
		"LICENSE":                           {RoleLicense, "Apache-2.0\n"},
		"NOTICE":                            {RoleLicense, "notice\n"},
	}
	name := "konstapel-official"
	if org {
		name = "acme-baseline"
	} else {
		files["content/upstream/nist.json"] = struct{ role, body string }{RoleUpstream, "{}"}
	}
	d := &Descriptor{
		Format:  FormatV1,
		Name:    name,
		Version: "1.2.3",
		Source:  Source{Repository: "https://github.com/backend-bunny/Konstapel", Revision: strings.Repeat("a", 40)},
		Policies: []Policy{{
			Name: "privileged", Path: "content/policies/privileged.yaml",
			ParameterSchema: "content/schemas/privileged.json",
			Checks:          []Check{{RuleID: "no-privileged", CheckID: "check-no-privileged"}},
		}},
		Scope:         Scope{Workloads: []string{"Pod", "Deployment"}, OS: []string{"linux"}},
		Compatibility: Compatibility{Provider: "kyverno/v1", Konstapel: "0.1.0"},
		OSCAL:         []OSCALDocument{{Path: "content/component-definition.json", Version: "1.1.3"}},
	}
	fsys := fstest.MapFS{DescriptorPath: {Data: []byte("{}")}}
	for p, f := range files {
		sum := sha256.Sum256([]byte(f.body))
		d.Files = append(d.Files, File{Path: p, Role: f.role, Size: int64(len(f.body)), SHA256: hex.EncodeToString(sum[:])})
		fsys[p] = &fstest.MapFile{Data: []byte(f.body)}
	}
	return d, fsys
}

func encode(t *testing.T, d *Descriptor) []byte {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestValidFixtures(t *testing.T) {
	for _, org := range []bool{false, true} {
		d, fsys := fixture(t, org)
		got, err := ParseDescriptor(encode(t, d))
		if err != nil {
			t.Fatalf("org=%v: %v", org, err)
		}
		if err := got.VerifyPayload(fsys); err != nil {
			t.Fatalf("org=%v payload: %v", org, err)
		}
	}
}

func TestDescriptorRejections(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Descriptor)
		want   string
	}{
		"unsupported format":     {func(d *Descriptor) { d.Format = "konstapel.policy.bundle/v2" }, "unsupported format"},
		"bad name":               {func(d *Descriptor) { d.Name = "Not_A_Label" }, "DNS label"},
		"bad version":            {func(d *Descriptor) { d.Version = "1.2" }, "SemVer"},
		"short revision":         {func(d *Descriptor) { d.Source.Revision = "main" }, "40-character"},
		"duplicate file path":    {func(d *Descriptor) { d.Files = append(d.Files, d.Files[0]) }, "duplicate path"},
		"escaping path":          {func(d *Descriptor) { d.Files[0].Path = "content/../../etc/passwd" }, "clean relative"},
		"descriptor inventoried": {func(d *Descriptor) { d.Files[0].Path = DescriptorPath }, "clean relative"},
		"unknown role":           {func(d *Descriptor) { d.Files[0].Role = "binary" }, "unknown role"},
		"duplicate policy":       {func(d *Descriptor) { d.Policies = append(d.Policies, d.Policies[0]) }, "duplicate policy name"},
		"duplicate rule id": {func(d *Descriptor) {
			d.Policies[0].Checks = append(d.Policies[0].Checks, Check{"no-privileged", "other"})
		}, "duplicate ruleID"},
		"duplicate check id": {func(d *Descriptor) {
			d.Policies[0].Checks = append(d.Policies[0].Checks, Check{"other", "check-no-privileged"})
		}, "duplicate checkID"},
		"policy path missing":     {func(d *Descriptor) { d.Policies[0].Path = "content/policies/absent.yaml" }, "not in the file inventory"},
		"policy wrong role":       {func(d *Descriptor) { d.Policies[0].Path = "tests/privileged.yaml" }, "want \"policy\""},
		"schema wrong role":       {func(d *Descriptor) { d.Policies[0].ParameterSchema = "content/policies/privileged.yaml" }, "want \"schema\""},
		"oscal not inventoried":   {func(d *Descriptor) { d.OSCAL[0].Path = "content/other.json" }, "not in the file inventory"},
		"oscal bad version":       {func(d *Descriptor) { d.OSCAL[0].Version = "2.0.0" }, "OSCAL 1.x.y"},
		"no component definition": {func(d *Descriptor) { d.OSCAL = []OSCALDocument{{Path: "content/provenance.json", Version: "1.1.3"}} }, "component-definition entry point"},
		"unsupported OS":          {func(d *Descriptor) { d.Scope.OS = []string{"plan9"} }, "not supported"},
		"unexpected path":         {func(d *Descriptor) { d.Files[0].Path = "scripts/run.sh" }, "outside content/"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d, _ := fixture(t, false)
			tc.mutate(d)
			_, err := ParseDescriptor(encode(t, d))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestMissingLicenseOrProvenance(t *testing.T) {
	d, _ := fixture(t, false)
	var kept []File
	for _, f := range d.Files {
		if f.Role != RoleProvenance && f.Path != "LICENSE" {
			kept = append(kept, f)
		}
	}
	d.Files = kept
	err := d.Validate()
	if err == nil || !strings.Contains(err.Error(), "exactly one provenance") || !strings.Contains(err.Error(), "LICENSE") {
		t.Fatalf("got %v", err)
	}
}

func TestParseStrict(t *testing.T) {
	d, _ := fixture(t, false)
	good := string(encode(t, d))
	for name, in := range map[string]string{
		"unknown field": strings.Replace(good, `{"format"`, `{"extra":1,"format"`, 1),
		"trailing data": good + `{}`,
		"not json":      "nope",
	} {
		if _, err := ParseDescriptor([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVerifyPayloadMismatches(t *testing.T) {
	d, fsys := fixture(t, false)
	fsys["content/policies/privileged.yaml"] = &fstest.MapFile{Data: []byte("kind: Tampered\n")}
	fsys["content/extra.txt"] = &fstest.MapFile{Data: []byte("x")}
	delete(fsys, "tests/privileged.yaml")
	err := d.VerifyPayload(fsys)
	if err == nil {
		t.Fatal("accepted a tampered payload")
	}
	for _, want := range []string{"does not match inventory", "not inventoried", "inventoried but missing"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func manifest(mut func(m map[string]any)) []byte {
	m := map[string]any{
		"schemaVersion": 2,
		"mediaType":     manifestMediaType,
		"artifactType":  ArtifactType,
		"config":        map[string]any{"mediaType": EmptyConfigMediaType, "digest": EmptyConfigDigest, "size": 2},
		"layers": []any{map[string]any{
			"mediaType": LayerMediaType, "digest": "sha256:" + strings.Repeat("b", 64), "size": 1234,
		}},
	}
	if mut != nil {
		mut(m)
	}
	b, _ := json.Marshal(m)
	return b
}

func TestValidateManifest(t *testing.T) {
	digest, size, err := ValidateManifest(manifest(nil))
	if err != nil || digest != "sha256:"+strings.Repeat("b", 64) || size != 1234 {
		t.Fatalf("valid manifest: %s %d %v", digest, size, err)
	}
	layer := func(mt string) any {
		return map[string]any{"mediaType": mt, "digest": "sha256:" + strings.Repeat("c", 64), "size": 1}
	}
	cases := map[string]struct {
		mut  func(map[string]any)
		want string
	}{
		"index":          {func(m map[string]any) { m["manifests"] = []any{} }, "indexes"},
		"wrong artifact": {func(m map[string]any) { m["artifactType"] = "application/x" }, "artifactType"},
		"non-empty cfg": {func(m map[string]any) {
			m["config"] = map[string]any{"mediaType": "application/json", "digest": "sha256:" + strings.Repeat("d", 64), "size": 9}
		}, "empty descriptor"},
		"two layers":  {func(m map[string]any) { m["layers"] = []any{layer(LayerMediaType), layer(LayerMediaType)} }, "exactly one layer"},
		"no layers":   {func(m map[string]any) { m["layers"] = []any{} }, "exactly one layer"},
		"wrong layer": {func(m map[string]any) { m["layers"] = []any{layer("application/vnd.oci.image.layer.v1.tar")} }, "layer mediaType"},
		"bad digest": {func(m map[string]any) {
			m["layers"] = []any{map[string]any{"mediaType": LayerMediaType, "digest": "md5:1", "size": 1}}
		}, "must be sha256"},
		"schema version": {func(m map[string]any) { m["schemaVersion"] = 1 }, "schemaVersion"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := ValidateManifest(manifest(tc.mut))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	if _, _, err := ValidateManifest([]byte("{")); err == nil {
		t.Error("accepted invalid JSON")
	}
}

func TestEmptyConfigDigest(t *testing.T) {
	sum := sha256.Sum256([]byte("{}"))
	if "sha256:"+hex.EncodeToString(sum[:]) != EmptyConfigDigest {
		t.Fatal("EmptyConfigDigest is not the digest of {}")
	}
}
