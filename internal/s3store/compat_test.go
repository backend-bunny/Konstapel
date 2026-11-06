//go:build s3compat

package s3store

// Real-endpoint compatibility suite (add-s3-evidence-publishing task 1.3).
// Run through scripts/s3-compat.sh, which starts a pinned, test-owned
// S3-compatible service. The suite creates one test bucket per versioning
// mode, probes each, and records the results.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/publicationtest"
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

// TestPublisherRoundTrip publishes a complete package to the real test
// service in each versioning mode and checks the commit protocol there.
func TestPublisherRoundTrip(t *testing.T) {
	endpoint := os.Getenv("KONSTAPEL_S3_ENDPOINT")
	creds := &StaticCredentials{AccessKeyID: os.Getenv("KONSTAPEL_S3_ACCESS_KEY"), SecretAccessKey: os.Getenv("KONSTAPEL_S3_SECRET_KEY")}
	if endpoint == "" || creds.AccessKeyID == "" {
		t.Fatal("KONSTAPEL_S3_ENDPOINT and credentials are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, mode := range []Versioning{Unversioned, Enabled, Suspended} {
		t.Run(string(mode), func(t *testing.T) {
			d := Destination{ID: "compat", Endpoint: endpoint, Bucket: "konstapel-compat-" + lower(mode), Region: "us-east-1",
				Prefix: "konstapel-test/publisher", Addressing: AddressingPath, CredentialSecret: &SecretRef{Name: "compat"}, DevelopmentFixture: true}
			c, err := NewClient(ctx, d, creds)
			if err != nil {
				t.Fatal(err)
			}
			clock := time.Now()
			p := &Publisher{Client: c, Dest: d, Now: func() time.Time { return clock }}
			if _, err := p.Ready(ctx); err != nil {
				t.Fatal(err)
			}
			run := testRun
			run.RunUID = "run-" + lower(mode)
			dir := filepath.Join(t.TempDir(), "pkg")
			if _, err := publicationtest.FullAssessmentPackage(repoRoot(t), dir, run); err != nil {
				t.Fatal(err)
			}
			s, err := p.Stage(ctx, publication.StageRequest{Run: run, Dir: dir})
			if err != nil {
				t.Fatal(err)
			}
			r, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("1h")})
			if err != nil {
				t.Fatal(err)
			}
			if again, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("2160h")}); err != nil || !reflect.DeepEqual(again, r) {
				t.Fatalf("retry changed the commit: %v", err)
			}
			other := filepath.Join(t.TempDir(), "other")
			if _, err := publicationtest.FullAssessmentPackage(repoRoot(t), other, run); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Stage(ctx, publication.StageRequest{Run: run, Dir: other}); !errors.Is(err, publication.ErrConflict) {
				t.Fatalf("conflicting content staged: %v", err)
			}
			b, err := p.read(ctx, r.Commit.ArchiveKey, r.Commit.ArchiveVersionID)
			if sum := sha256.Sum256(b); err != nil || hex.EncodeToString(sum[:]) != r.PackageSHA256 {
				t.Fatalf("downloaded archive does not match its commit: %v", err)
			}
			if drift := time.Since(r.PublishedAt); drift > MaxClockSkew || drift < -MaxClockSkew {
				t.Fatalf("publishedAt %v is not the server's commit time", r.PublishedAt)
			}
			clock = r.ExpiresAt.Add(time.Second)
			if cl, err := p.Delete(ctx, run); err != nil || cl.State != publication.CleanupDeleted {
				t.Fatalf("cleanup %+v %v", cl, err)
			}
			if left := cleanup(ctx, c, d.Bucket, p.runPrefix(run)); len(left) != 0 {
				t.Fatalf("cleanup left problems: %v", left)
			}
			v, err := c.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(d.Bucket), Prefix: aws.String(p.runPrefix(run))})
			if err == nil && (len(v.Versions) > 0 || len(v.DeleteMarkers) > 0) {
				t.Fatalf("owned versions survived deletion: %d versions, %d markers", len(v.Versions), len(v.DeleteMarkers))
			}
		})
	}
}
