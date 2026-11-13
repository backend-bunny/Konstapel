package publication_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

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

// An unsigned receipt, its publication status, and the AssessmentRun status
// form keep their pre-signing bytes (testdata captured before signing).
func TestUnsignedPublicationRecordsAreUnchanged(t *testing.T) {
	at := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	r := publication.Receipt{PublicationID: "kube-system:c/b/r",
		Destination:      publication.Destination{ID: "dest-uid", Endpoint: "https://s3.example.internal", Bucket: "evidence", Prefix: "clusters/prod", CredentialRef: &publication.SecretRef{Name: "konstapel-s3"}},
		Commit:           publication.Commit{ManifestKey: "clusters/prod/evidence/c/b/r/commit.json", ManifestVersionID: "m1", ArchiveKey: "clusters/prod/evidence/c/b/r/attempts/00/package.tar.gz", ArchiveVersionID: "a1"},
		DescriptorSHA256: "1111111111111111111111111111111111111111111111111111111111111111",
		PackageSHA256:    "2222222222222222222222222222222222222222222222222222222222222222", PackageSize: 4096,
		PublishedAt: at, Retention: publication.Retention{Duration: "2160h0m0s", BindingConfiguration: "b/7", SelectedAt: at}, ExpiresAt: at.Add(2160 * time.Hour)}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	st := publication.Committed(r)
	st.OwnedObjects = []publication.OwnedObject{{Role: publication.ObjectArchive, AttemptID: "00", Key: r.Commit.ArchiveKey, VersionID: "a1"}}
	for name, v := range map[string]any{"receipt-unsigned.json": r, "status-unsigned.json": st, "run-publication-unsigned.json": publication.ToAPI(st)} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		goldenFile(t, name, b)
	}
}
