package bundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func frozenFixture(t *testing.T) (string, *Archive, FrozenIdentity) {
	t.Helper()
	a, _ := buildOfficial(t)
	d := a.Descriptor
	id := FrozenIdentity{FrozenVersion: FrozenVersion, Name: d.Name, Version: d.Version, Source: d.Source,
		Digests: Digests{Revision: d.Source.Revision, Content: d.ContentDigest(), Archive: a.LayerDigest, OCI: a.ManifestDigest}}
	dir := filepath.Join(t.TempDir(), "frozen")
	if _, err := WriteFrozen(dir, a.Manifest, a.Layer, id); err != nil {
		t.Fatal(err)
	}
	return dir, a, id
}

func TestFrozenRoundTrip(t *testing.T) {
	dir, a, id := frozenFixture(t)
	f, err := ReadFrozen(dir)
	if err != nil {
		t.Fatal(err)
	}
	if f.Identity.Digests != id.Digests || f.Descriptor.Name != a.Descriptor.Name {
		t.Fatalf("%+v", f.Identity)
	}
	if _, err := WriteFrozen(dir, a.Manifest, a.Layer, id); err == nil {
		t.Fatal("an existing frozen directory was replaced")
	}
}

func TestWriteFrozenRejectsInconsistentIdentity(t *testing.T) {
	_, a, id := frozenFixture(t)
	for name, mutate := range map[string]func(*FrozenIdentity){
		"manifest digest": func(i *FrozenIdentity) { i.Digests.OCI = "sha256:" + strings.Repeat("0", 64) },
		"content digest":  func(i *FrozenIdentity) { i.Digests.Content = "sha256:" + strings.Repeat("0", 64) },
		"archive digest":  func(i *FrozenIdentity) { i.Digests.Archive = "sha256:" + strings.Repeat("0", 64) },
		"name":            func(i *FrozenIdentity) { i.Name = "other" },
		"version":         func(i *FrozenIdentity) { i.FrozenVersion = 2 },
		"revision":        func(i *FrozenIdentity) { i.Digests.Revision = strings.Repeat("e", 40) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := id
			mutate(&bad)
			dir := filepath.Join(t.TempDir(), "frozen")
			if _, err := WriteFrozen(dir, a.Manifest, a.Layer, bad); err == nil {
				t.Fatal("accepted")
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("left a directory behind")
			}
		})
	}
	if _, err := WriteFrozen(filepath.Join(t.TempDir(), "f"), a.Manifest, a.Layer[:len(a.Layer)-1], id); err == nil {
		t.Fatal("a truncated layer was accepted")
	}
}

func TestReadFrozenDetectsTampering(t *testing.T) {
	for name, tamper := range map[string]func(dir string) error{
		"content edited": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "content/component-definition.json"), []byte("{}"), 0o600)
		},
		"content added": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "content/extra.json"), []byte("{}"), 0o600)
		},
		"content removed": func(dir string) error { return os.Remove(filepath.Join(dir, "content/provenance.json")) },
		"descriptor edited": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, FrozenDescriptor), []byte("{}"), 0o600)
		},
		"identity edited": func(dir string) error {
			p := filepath.Join(dir, FrozenIdentityFile)
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(p, []byte(strings.Replace(string(b), `"version": "`, `"version": "9`, 1)), 0o600)
		},
		"extra proof file": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, FrozenDir, "other.json"), []byte("{}"), 0o600)
		},
		"manifest removed": func(dir string) error { return os.Remove(filepath.Join(dir, FrozenManifest)) },
	} {
		t.Run(name, func(t *testing.T) {
			dir, _, _ := frozenFixture(t)
			if err := tamper(dir); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadFrozen(dir); err == nil {
				t.Fatal("tampered frozen content verified")
			}
		})
	}
}
