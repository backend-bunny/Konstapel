//go:build s3compat

package s3store

// Real-endpoint compatibility suite (add-s3-evidence-publishing task 1.3).
// Run through scripts/s3-compat.sh, which starts a pinned, test-owned
// S3-compatible service. The suite creates one test bucket per versioning
// mode, probes each, and records the results.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/publicationtest"
)

// requireTestOwned refuses to run the suite, which creates buckets and
// writes objects, against anything but the loopback service that
// scripts/s3-compat.sh starts and removes.
func requireTestOwned(t *testing.T, endpoint string) {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() != "127.0.0.1" {
		t.Fatalf("the compatibility suite only runs against a test-owned loopback service, not %q", endpoint)
	}
}

func TestCompatibility(t *testing.T) {
	endpoint, out := os.Getenv("KONSTAPEL_S3_ENDPOINT"), os.Getenv("KONSTAPEL_S3_OUTPUT")
	requireTestOwned(t, endpoint)
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
	requireTestOwned(t, endpoint)
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
			archives := func() int {
				l, err := c.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(d.Bucket), Prefix: aws.String(p.runPrefix(run) + "attempts/")})
				if err != nil {
					t.Fatal(err)
				}
				n := 0
				for _, o := range l.Contents {
					if strings.HasSuffix(aws.ToString(o.Key), "/package.tar.gz") {
						n++
					}
				}
				return n
			}
			// A retry after the upload reuses it.
			if again, err := p.Stage(ctx, publication.StageRequest{Run: run, Dir: dir}); err != nil || again != s || archives() != 1 {
				t.Fatalf("retried stage uploaded again: %v archives %d", err, archives())
			}
			r, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("1h")})
			if err != nil {
				t.Fatal(err)
			}
			// The receipt never reached Kubernetes: a new leader stages and
			// publishes again, uploads nothing, and gets the original receipt.
			leader := &Publisher{Client: c, Dest: d, Now: func() time.Time { return clock.Add(time.Minute) }}
			if s2, err := leader.Stage(ctx, publication.StageRequest{Run: run, Dir: dir}); err != nil || s2 != s || archives() != 1 {
				t.Fatalf("stage after commit: %v archives %d", err, archives())
			} else if got, err := leader.Publish(ctx, publication.PublishRequest{Staged: s2, Retention: retention("24h")}); err != nil || !reflect.DeepEqual(got, r) {
				t.Fatalf("recovered receipt differs: %v", err)
			}
			if again, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("2160h")}); err != nil || !reflect.DeepEqual(again, r) {
				t.Fatalf("retry changed the commit: %v", err)
			}
			// Orphan cleanup: an interrupted attempt, an incomplete multipart
			// upload, and unrelated objects in the shared bucket/prefix.
			put := func(key, body string) {
				if _, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(d.Bucket), Key: aws.String(key), Body: strings.NewReader(body)}); err != nil {
					t.Fatal(err)
				}
			}
			intent, _ := json.Marshal(attemptIntent{Run: run, Created: time.Now()})
			put(p.runPrefix(run)+"attempts/interrupted/"+intentFile, string(intent))
			put(p.runPrefix(run)+"attempts/interrupted/package.tar.gz", "partial")
			unrelated := d.KeyPrefix() + "unrelated-" + lower(mode)
			put(unrelated, "keep me")
			mp, err := c.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String(d.Bucket), Key: aws.String(p.runPrefix(run) + "attempts/interrupted/big")})
			if err != nil {
				t.Fatal(err)
			}
			if err := p.CleanupAttempts(ctx, run); err != nil {
				t.Fatal(err)
			}
			if l, _ := c.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(d.Bucket), Prefix: aws.String(p.runPrefix(run) + "attempts/interrupted/")}); len(l.Contents) != 0 {
				t.Fatalf("interrupted attempt survived: %d objects", len(l.Contents))
			}
			if ups, err := c.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(d.Bucket), Prefix: aws.String(p.runPrefix(run))}); err != nil || len(ups.Uploads) != 0 {
				_, _ = c.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: aws.String(d.Bucket), Key: mp.Key, UploadId: mp.UploadId})
				t.Fatalf("multipart upload not aborted: %v", err)
			}
			if _, err := p.read(ctx, unrelated, ""); err != nil {
				t.Fatalf("unrelated object removed: %v", err)
			}
			if st, err := p.Inspect(ctx, run); err != nil || st.Phase != publication.PhaseCommitted || archives() != 1 {
				t.Fatalf("committed package damaged by cleanup: %+v %v", st, err)
			}
			other := filepath.Join(t.TempDir(), "other")
			if _, err := publicationtest.FullAssessmentPackage(repoRoot(t), other, run); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Stage(ctx, publication.StageRequest{Run: run, Dir: other}); !errors.Is(err, publication.ErrConflict) {
				t.Fatalf("conflicting content staged: %v", err)
			}
			if body, st, err := p.Open(ctx, run); err != nil || st.PackageSHA256 != r.PackageSHA256 {
				t.Fatalf("open committed archive: %v", err)
			} else {
				ob, _ := io.ReadAll(body)
				_ = body.Close()
				if sum := sha256.Sum256(ob); hex.EncodeToString(sum[:]) != r.PackageSHA256 {
					t.Fatal("opened archive does not match its commit")
				}
			}
			b, err := p.read(ctx, r.Commit.ArchiveKey, r.Commit.ArchiveVersionID)
			if sum := sha256.Sum256(b); err != nil || hex.EncodeToString(sum[:]) != r.PackageSHA256 {
				t.Fatalf("downloaded archive does not match its commit: %v", err)
			}
			if drift := time.Since(r.PublishedAt); drift > MaxClockSkew || drift < -MaxClockSkew {
				t.Fatalf("publishedAt %v is not the server's commit time", r.PublishedAt)
			}
			if st, err := p.Inspect(ctx, run); err != nil || st.Availability != publication.AvailabilityAvailable {
				t.Fatalf("intact package not available: %+v %v", st, err)
			}
			// Early loss (for example an external lifecycle rule): unavailable,
			// still committed, and expiry cleanup still completes.
			del := &s3.DeleteObjectInput{Bucket: aws.String(d.Bucket), Key: aws.String(r.Commit.ArchiveKey)}
			if r.Commit.ArchiveVersionID != "" {
				del.VersionId = aws.String(r.Commit.ArchiveVersionID)
			}
			if _, err := c.DeleteObject(ctx, del); err != nil {
				t.Fatal(err)
			}
			if st, err := p.Inspect(ctx, run); err != nil || st.Availability != publication.AvailabilityUnavailable || st.Failure == nil ||
				st.Failure.Reason != publication.FailureObjectMissing || st.Phase != publication.PhaseCommitted {
				t.Fatalf("early loss not reported: %+v %v", st, err)
			}
			clock = r.ExpiresAt.Add(time.Second)
			if cl, err := p.Delete(ctx, run); err != nil || cl.State != publication.CleanupDeleted {
				t.Fatalf("cleanup %+v %v", cl, err)
			}
			if left := cleanup(ctx, c, d.Bucket, p.runPrefix(run)); len(left) != 0 {
				t.Fatalf("cleanup left problems: %v", left)
			}
			// Expiry deletion is scoped to the run's own prefix.
			if _, err := p.read(ctx, unrelated, ""); err != nil {
				t.Fatalf("expiry deletion removed an unrelated object: %v", err)
			}
			cleanup(ctx, c, d.Bucket, unrelated)
			v, err := c.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(d.Bucket), Prefix: aws.String(p.runPrefix(run))})
			if err == nil && (len(v.Versions) > 0 || len(v.DeleteMarkers) > 0) {
				t.Fatalf("owned versions survived deletion: %d versions, %d markers", len(v.Versions), len(v.DeleteMarkers))
			}
		})
	}
}

// TestSignedPublisherRoundTrip runs the signed commit protocol against the
// real S3-compatible service: the signature object is created once with
// If-None-Match (a second, different bundle loses), the commit gate commits
// the verified pair as a SignedPublicationCommit, a new leader recovers the
// same signed receipt, and attempt cleanup keeps the signature.
func TestSignedPublisherRoundTrip(t *testing.T) {
	endpoint := os.Getenv("KONSTAPEL_S3_ENDPOINT")
	requireTestOwned(t, endpoint)
	creds := &StaticCredentials{AccessKeyID: os.Getenv("KONSTAPEL_S3_ACCESS_KEY"), SecretAccessKey: os.Getenv("KONSTAPEL_S3_SECRET_KEY")}
	if endpoint == "" || creds.AccessKeyID == "" {
		t.Fatal("KONSTAPEL_S3_ENDPOINT and credentials are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, mode := range []Versioning{Unversioned, Enabled, Suspended} {
		t.Run(string(mode), func(t *testing.T) {
			d := Destination{ID: "compat", Endpoint: endpoint, Bucket: "konstapel-compat-" + lower(mode), Region: "us-east-1",
				Prefix: "konstapel-test/signed", Addressing: AddressingPath, CredentialSecret: &SecretRef{Name: "compat"}, DevelopmentFixture: true}
			c, err := NewClient(ctx, d, creds)
			if err != nil {
				t.Fatal(err)
			}
			p := &Publisher{Client: c, Dest: d, Now: time.Now}
			if _, err := p.Ready(ctx); err != nil {
				t.Fatal(err)
			}
			run := testRun
			run.RunUID = "signed-" + lower(mode)
			dir := filepath.Join(t.TempDir(), "pkg")
			if _, err := publicationtest.FullAssessmentPackage(repoRoot(t), dir, run); err != nil {
				t.Fatal(err)
			}
			s, err := p.Stage(ctx, publication.StageRequest{Run: run, Dir: dir})
			if err != nil {
				t.Fatal(err)
			}
			signer := testSigner(t)
			req := publication.PublishRequest{Staged: s, Retention: retention("1h"), Signing: requiredBy(signer)}
			if _, err := p.Publish(ctx, req); !errors.Is(err, publication.ErrSignatureRequired) {
				t.Fatalf("committed without a signature: %v", err)
			}
			first, second := signStaged(t, signer, s), signStaged(t, signer, s)
			if got, _, err := p.StoreSignature(ctx, run, first); err != nil || !bytes.Equal(got, first) {
				t.Fatalf("store: %v", err)
			}
			if got, _, err := p.StoreSignature(ctx, run, second); err != nil || !bytes.Equal(got, first) {
				t.Fatalf("a second bundle replaced the first: %v", err)
			}
			r, err := p.Publish(ctx, req)
			if err != nil || r.Signature == nil || r.Signature.KeyFingerprint != signer.PublicKey().Fingerprint {
				t.Fatalf("signed publish: %+v %v", r.Signature, err)
			}
			leader := &Publisher{Client: c, Dest: d, Now: time.Now}
			if got, err := leader.Publish(ctx, req); err != nil || !reflect.DeepEqual(got, r) {
				t.Fatalf("recovered signed receipt differs: %v", err)
			}
			if _, err := leader.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("1h")}); !errors.Is(err, publication.ErrConflict) {
				t.Fatalf("an unsigned intent accepted the signed commit: %v", err)
			}
			if err := p.CleanupAttempts(ctx, run); err != nil {
				t.Fatal(err)
			}
			if b, _, err := p.ReadSignature(ctx, run); err != nil || !bytes.Equal(b, first) {
				t.Fatalf("signature after attempt cleanup: %v", err)
			}
			if st, err := p.Inspect(ctx, run); err != nil || st.Signature == nil || st.Validate() != nil {
				t.Fatalf("inspect: %v", err)
			}
		})
	}
}
