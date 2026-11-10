package release

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// frozen writes the official bundle as package.sh would: a verified layout
// plus package.json, built from this repository's checked-in content.
func frozen(t *testing.T, revision string) (string, Release) {
	t.Helper()
	root := filepath.Join("..", "..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "bundles", "konstapel-privileged-containers", "definition.json"))
	if err != nil {
		t.Fatal(err)
	}
	def, err := bundle.LoadDefinition(raw)
	if err != nil {
		t.Fatal(err)
	}
	def.Source.Revision = revision
	a, err := bundle.Build(def, os.DirFS(root), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	if err := bundle.WriteLayout(dir, a); err != nil {
		t.Fatal(err)
	}
	writeRecord(t, dir, map[string]any{
		"name": def.Name, "version": def.Version,
		"source":         map[string]string{"repository": def.Source.Repository, "revision": revision},
		"manifestDigest": a.ManifestDigest, "layerDigest": a.LayerDigest,
	})
	return dir, Release{Name: def.Name, Version: def.Version, Commit: revision, Tag: TagName(def.Name, def.Version)}
}

func writeRecord(t *testing.T, dir string, rec map[string]any) {
	t.Helper()
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPackage(t *testing.T) {
	commit := strings.Repeat("ab", 20)
	dir, rel := frozen(t, commit)
	digest, err := VerifyPackage(dir, rel)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("digest %q", digest)
	}

	for _, tc := range []struct {
		name string
		mut  func(*Release)
	}{
		{"other commit", func(r *Release) { r.Commit = strings.Repeat("cd", 20) }},
		{"other version", func(r *Release) { r.Version = "9.9.9" }},
		{"other bundle", func(r *Release) { r.Name = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := rel
			tc.mut(&r)
			if _, err := VerifyPackage(dir, r); err == nil || !strings.Contains(err.Error(), "frozen layout is") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	t.Run("package record disagrees with the layout", func(t *testing.T) {
		writeRecord(t, dir, map[string]any{
			"name": rel.Name, "version": rel.Version,
			"source": map[string]string{"revision": rel.Commit}, "manifestDigest": "sha256:" + strings.Repeat("0", 64),
		})
		if _, err := VerifyPackage(dir, rel); err == nil || !strings.Contains(err.Error(), "does not match the verified layout") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("tampered blob", func(t *testing.T) {
		d, r := frozen(t, commit)
		blobs, err := filepath.Glob(filepath.Join(d, "blobs", "sha256", "*"))
		if err != nil || len(blobs) == 0 {
			t.Fatal(blobs, err)
		}
		for _, b := range blobs {
			if err := os.WriteFile(b, []byte("tampered"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := VerifyPackage(d, r); err == nil || !strings.Contains(err.Error(), "frozen layout") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing package record", func(t *testing.T) {
		d, r := frozen(t, commit)
		if err := os.Remove(filepath.Join(d, "package.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyPackage(d, r); err == nil {
			t.Fatal("no error")
		}
	})
}
