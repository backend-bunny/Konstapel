//go:build s3compat

package s3store

// Real-endpoint compatibility suite (add-s3-evidence-publishing task 1.3).
// Run through scripts/s3-compat.sh, which starts a pinned, test-owned
// S3-compatible service. The suite creates one test bucket per versioning
// mode, probes each, and records the results.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestCompatibility(t *testing.T) {
	endpoint, out := os.Getenv("KONSTAPEL_S3_ENDPOINT"), os.Getenv("KONSTAPEL_S3_OUTPUT")
	creds := &StaticCredentials{AccessKeyID: os.Getenv("KONSTAPEL_S3_ACCESS_KEY"), SecretAccessKey: os.Getenv("KONSTAPEL_S3_SECRET_KEY")}
	if endpoint == "" || out == "" || creds.AccessKeyID == "" {
		t.Fatal("KONSTAPEL_S3_ENDPOINT, KONSTAPEL_S3_ACCESS_KEY, KONSTAPEL_S3_SECRET_KEY and KONSTAPEL_S3_OUTPUT are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	results := map[string]any{"endpoint": endpoint, "image": os.Getenv("KONSTAPEL_S3_IMAGE"), "date": time.Now().UTC().Format("2006-01-02")}
	modes := map[string]Compatibility{}
	for _, mode := range []Versioning{Unversioned, Enabled, Suspended} {
		d := Destination{ID: "compat", Endpoint: endpoint, Bucket: "konstapel-compat-" + string(lower(mode)), Region: "us-east-1",
			Prefix: "konstapel-test", Addressing: AddressingPath, CredentialSecret: &SecretRef{Name: "compat"}, DevelopmentFixture: true}
		c, err := NewClient(ctx, d, creds)
		if err != nil {
			t.Fatal(err)
		}
		// The service is test-owned: creating its buckets is part of the fixture.
		if _, err := c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(d.Bucket)}); err != nil && !alreadyOwned(err) {
			t.Fatalf("create %s: %v", d.Bucket, sanitize(err))
		}
		if mode != Unversioned {
			status := types.BucketVersioningStatusEnabled
			if _, err := c.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(d.Bucket),
				VersioningConfiguration: &types.VersioningConfiguration{Status: status}}); err != nil {
				t.Fatalf("enable versioning on %s: %v", d.Bucket, sanitize(err))
			}
			if mode == Suspended {
				if _, err := c.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(d.Bucket),
					VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusSuspended}}); err != nil {
					t.Fatalf("suspend versioning on %s: %v", d.Bucket, sanitize(err))
				}
			}
		}
		r, err := Probe(ctx, c, d)
		if err != nil {
			t.Errorf("%s: %v", mode, err)
		}
		modes[string(mode)] = r
		if r.Versioning != mode {
			t.Errorf("%s bucket reports versioning %s", mode, r.Versioning)
		}
		if !r.Ready {
			t.Errorf("%s: not ready: %v", mode, r.Problems)
		}
	}
	results["modes"] = modes
	raw, _ := json.MarshalIndent(results, "", "  ")
	if err := os.WriteFile(filepath.Join(out, "s3-compat.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s", raw)
}

func lower(v Versioning) string {
	b := []byte(v)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func alreadyOwned(err error) bool {
	var owned *types.BucketAlreadyOwnedByYou
	var exists *types.BucketAlreadyExists
	return errors.As(err, &owned) || errors.As(err, &exists)
}
