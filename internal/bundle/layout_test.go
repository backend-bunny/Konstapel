package bundle

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestLayoutRoundTrip(t *testing.T) {
	def, root := buildInputs(t)
	a, err := Build(def, root, epoch)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "oci")
	if err := WriteLayout(dir, a); err != nil {
		t.Fatal(err)
	}
	d, digest, err := VerifyLayout(dir)
	if err != nil || digest != a.ManifestDigest || d.Name != def.Name {
		t.Fatalf("round trip: %v %s %v", d, digest, err)
	}
	if err := WriteLayout(dir, a); err == nil || !strings.Contains(err.Error(), "never replaced") {
		t.Fatalf("overwrote a frozen layout: %v", err)
	}
}

func TestVerifyLayoutDetectsTampering(t *testing.T) {
	def, root := buildInputs(t)
	a, _ := Build(def, root, epoch)
	for name, mutate := range map[string]func(dir string){
		"layer bytes":   func(dir string) { os.WriteFile(blobPath(dir, a.LayerDigest), []byte("x"), 0o644) },
		"manifest":      func(dir string) { os.WriteFile(blobPath(dir, a.ManifestDigest), []byte("{}"), 0o644) },
		"missing blob":  func(dir string) { os.Remove(blobPath(dir, a.LayerDigest)) },
		"empty config":  func(dir string) { os.WriteFile(blobPath(dir, EmptyConfigDigest), []byte("[]"), 0o644) },
		"layout marker": func(dir string) { os.WriteFile(filepath.Join(dir, "oci-layout"), []byte("{}"), 0o644) },
		"two manifests": func(dir string) {
			os.WriteFile(filepath.Join(dir, "index.json"), []byte(`{"manifests":[{},{}]}`), 0o644)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "oci")
			if err := WriteLayout(dir, a); err != nil {
				t.Fatal(err)
			}
			mutate(dir)
			if _, _, err := VerifyLayout(dir); err == nil {
				t.Fatal("accepted a tampered layout")
			}
		})
	}
}

// Every checked-in definition must build and verify, so format and content
// problems fail `task check` rather than a release.
func TestAllDefinitionsBuildAndVerify(t *testing.T) {
	matches, err := filepath.Glob("../../bundles/*/definition.json")
	if err != nil || len(matches) == 0 {
		t.Fatalf("no bundle definitions found: %v", err)
	}
	for _, m := range matches {
		raw, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		def, err := LoadDefinition(raw)
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		if want := filepath.Base(filepath.Dir(m)); def.Name != want {
			t.Errorf("%s: name %q must equal its directory %q", m, def.Name, want)
		}
		def.Source.Revision = strings.Repeat("d", 40)
		a, err := Build(def, os.DirFS("../.."), epoch)
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		dir := filepath.Join(t.TempDir(), "oci")
		if err := WriteLayout(dir, a); err != nil {
			t.Fatal(err)
		}
		if _, _, err := VerifyLayout(dir); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		d, payload, err := Unpack(a.Layer)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateContent(d, payload); err != nil {
			t.Fatalf("%s: content validation: %v", m, err)
		}
	}
}

// Taskfile exposes one public bundle workflow now; signing, checksum and
// summary helpers stay behind it (AGENTS.md: Taskfile scope).
func TestTaskfileExposesOnlyThePackageWorkflow(t *testing.T) {
	raw, err := os.ReadFile("../../Taskfile.yml")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range regexp.MustCompile(`(?m)^  (bundles:[A-Za-z0-9:_-]*):`).FindAllStringSubmatch(string(raw), -1) {
		got = append(got, m[1])
	}
	// bundles:acceptance joins this list when that workflow lands (task 8.1).
	if len(got) != 1 || got[0] != "bundles:package" {
		t.Fatalf("bundle tasks = %v, want only bundles:package", got)
	}
}
