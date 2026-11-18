package s3store_test

// The publication fault fixtures (add-controller-high-availability 1.2)
// against the S3 publisher and an in-memory S3 server. This is a shared fake
// store: it checks the publisher's handling of lost responses, conflicting
// bytes and separate clients, not real storage. Durable-backend acceptance
// is TestLivePublicationFaults against the pinned RustFS service.

import (
	"path/filepath"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/publication/publicationtest"
	"github.com/backend-bunny/Konstapel/internal/s3store"
	"github.com/backend-bunny/Konstapel/internal/s3store/s3storetest"
)

func TestPublicationFaults(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	creds := &s3store.StaticCredentials{AccessKeyID: "AKIAFAKE", SecretAccessKey: "fake-secret"}
	for _, mode := range []string{"", "Enabled", "Suspended"} {
		t.Run("versioning="+mode, func(t *testing.T) {
			t.Parallel()
			d := s3store.ServeFakeS3(t, mode)
			r := publicationtest.RunPublicationFaults(t, s3storetest.FaultStore("s3store+fakeS3", publicationtest.SharedFakeStore, root, d, creds))
			if r.DurableAcceptance() || len(r.Cases) != 4 {
				t.Fatalf("report %+v", r)
			}
		})
	}
}
