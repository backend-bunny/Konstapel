//go:build live

package controller

// Live publication fault fixtures (add-controller-high-availability 1.2):
// the shared fault suite against the pinned RustFS service in every bucket
// versioning mode. This is the durable-backend run: each client is an
// independent S3 publisher sharing nothing but the service, the lost
// responses land in the service before they are dropped, and recovery,
// conflicts and commit-once are decided by the service's own conditional
// writes. The in-memory runs of the same suite (TestPublicationFaults in
// internal/publication/fake and internal/s3store) prove only the contract.
// Run through scripts/targeting-live.sh.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/backend-bunny/Konstapel/internal/publication/publicationtest"
	"github.com/backend-bunny/Konstapel/internal/s3store"
	"github.com/backend-bunny/Konstapel/internal/s3store/s3storetest"
)

func TestLivePublicationFaults(t *testing.T) {
	l := newLive(t)
	pub := startS3(t, l)
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	creds := &s3store.StaticCredentials{AccessKeyID: l.s3Access, SecretAccessKey: l.s3Secret}
	for _, mode := range []s3store.Versioning{s3store.Unversioned, s3store.Enabled, s3store.Suspended} {
		t.Run(string(mode), func(t *testing.T) {
			d := pub.Dest
			d.Bucket, d.Prefix = "konstapel-faults-"+strings.ToLower(string(mode)), "konstapel-test/faults"
			if _, err := pub.Client.CreateBucket(l.ctx, &s3.CreateBucketInput{Bucket: aws.String(d.Bucket)}); err != nil {
				t.Fatal(err)
			}
			for _, status := range map[s3store.Versioning][]types.BucketVersioningStatus{
				s3store.Enabled:   {types.BucketVersioningStatusEnabled},
				s3store.Suspended: {types.BucketVersioningStatusEnabled, types.BucketVersioningStatusSuspended},
			}[mode] {
				if _, err := pub.Client.PutBucketVersioning(l.ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(d.Bucket),
					VersioningConfiguration: &types.VersioningConfiguration{Status: status}}); err != nil {
					t.Fatal(err)
				}
			}
			c, err := s3store.NewClient(l.ctx, d, creds)
			if err != nil {
				t.Fatal(err)
			}
			if r, err := s3store.Probe(l.ctx, c, d); err != nil || !r.Ready || r.Versioning != mode {
				t.Fatalf("bucket %s: %+v %v", d.Bucket, r, err)
			}
			report := publicationtest.RunPublicationFaults(t, s3storetest.FaultStore("rustfs/"+string(mode), publicationtest.DurableBackend, root, d, creds))
			if !report.DurableAcceptance() || len(report.Cases) != 4 {
				t.Fatalf("report %+v", report)
			}
			l.record("publication-faults", map[string]any{"versioning": mode, "image": os.Getenv("KONSTAPEL_S3_IMAGE"), "report": report})
		})
	}
}
