package s3store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// goldenFile compares got with testdata/name. KONSTAPEL_UPDATE_GOLDEN=1
// rewrites it; the committed files were captured before evidence signing
// existed, so unsigned records must keep matching them byte for byte.
func goldenFile(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("KONSTAPEL_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s changed:\n got %s\nwant %s", name, got, want)
	}
}

// An unsigned commit manifest keeps its pre-signing bytes.
func TestUnsignedCommitManifestBytesAreUnchanged(t *testing.T) {
	m := manifest{APIVersion: publication.APIVersion, Kind: "PublicationCommit", PublicationID: testRun.PublicationID(), Run: testRun,
		DescriptorSHA256: "1111111111111111111111111111111111111111111111111111111111111111",
		ArchiveKey:       "konstapel/evidence/synthetic-cluster/binding-uid-1/run-uid-1/attempts/0011223344556677/package.tar.gz", ArchiveVersionID: "v1",
		PackageSHA256: "2222222222222222222222222222222222222222222222222222222222222222", PackageSize: 4096,
		Retention: publication.Retention{Duration: "2160h0m0s", BindingConfiguration: "binding-uid-1/7", SelectedAt: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)}}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	goldenFile(t, "commit-unsigned.json", b)
}
