//go:build s3compat

package s3store

// Attachment storage against the real, test-owned S3-compatible service in
// each versioning mode (add-supporting-evidence-attachments 2.2-2.4). Run
// through scripts/s3-compat.sh with the publisher compatibility suite.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/backend-bunny/Konstapel/internal/attachments"
)

// dropCommitResponse lets the first commit-manifest PUT land and reports a
// transport error instead of its response.
type dropCommitResponse struct {
	inner s3.HTTPClient
	n     atomic.Int32
}

func (d *dropCommitResponse) Do(r *http.Request) (*http.Response, error) {
	resp, err := d.inner.Do(r)
	if err == nil && r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/commit.json") && d.n.Add(1) == 1 {
		resp.Body.Close()
		return nil, errors.New("connection reset (test: commit response dropped)")
	}
	return resp, err
}

func TestAttachmentStoreCompatibility(t *testing.T) {
	endpoint, out := os.Getenv("KONSTAPEL_S3_ENDPOINT"), os.Getenv("KONSTAPEL_S3_OUTPUT")
	requireTestOwned(t, endpoint)
	creds := &StaticCredentials{AccessKeyID: os.Getenv("KONSTAPEL_S3_ACCESS_KEY"), SecretAccessKey: os.Getenv("KONSTAPEL_S3_SECRET_KEY")}
	if out == "" || creds.AccessKeyID == "" {
		t.Fatal("KONSTAPEL_S3_ENDPOINT, KONSTAPEL_S3_ACCESS_KEY, KONSTAPEL_S3_SECRET_KEY and KONSTAPEL_S3_OUTPUT are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	results := map[string]any{"image": os.Getenv("KONSTAPEL_S3_IMAGE"), "date": time.Now().UTC().Format("2006-01-02")}
	for _, mode := range []Versioning{Unversioned, Enabled, Suspended} {
		t.Run(string(mode), func(t *testing.T) {
			d := Destination{ID: "attach-compat", Endpoint: endpoint, Bucket: "konstapel-attach-" + lower(mode), Region: "us-east-1",
				Prefix: "konstapel-test", Addressing: AddressingPath, CredentialSecret: &SecretRef{Name: "compat"}, DevelopmentFixture: true}
			c, err := NewClient(ctx, d, creds)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(d.Bucket)}); err != nil && !alreadyOwned(err) {
				t.Fatalf("create bucket: %v", sanitize(err))
			}
			if mode != Unversioned {
				for _, st := range []types.BucketVersioningStatus{types.BucketVersioningStatusEnabled, types.BucketVersioningStatusSuspended} {
					if _, err := c.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(d.Bucket),
						VersioningConfiguration: &types.VersioningConfiguration{Status: st}}); err != nil {
						t.Fatal(sanitize(err))
					}
					if mode == Enabled {
						break
					}
				}
			}
			if r, err := Probe(ctx, c, d); err != nil || !r.Ready || r.Versioning != mode {
				t.Fatalf("probe: %+v %v", r, err)
			}
			now := time.Now().UTC()
			store := &AttachmentStore{Client: c, Dest: d, Now: func() time.Time { return now }}
			ref := attachments.Ref{ClusterID: "kube-system:compat", UID: "att-" + lower(mode)}
			body := []byte("%PDF-1.7 compatibility document " + string(mode))
			who := attachments.Principal{Username: "compat-uploader"}
			req := attachments.CommitRequest{Ref: ref, SpecDigest: "sha256:" + strings.Repeat("a", 64), Document: doc(body),
				ValidUntil: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), Retention: time.Hour}

			if _, err := store.Stage(ctx, attachments.StageRequest{Ref: ref, Document: doc(body), Uploader: who, Body: bytes.NewReader([]byte("other bytes"))}); !errors.Is(err, attachments.ErrIntegrity) {
				t.Fatalf("mismatched bytes: %v", err)
			}
			const writers = 3
			receipts, errs := make([]attachments.Receipt, writers), make([]error, writers)
			var wg sync.WaitGroup
			for i := range writers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					cl := c
					if i == 0 {
						cl = s3.New(c.Options(), func(o *s3.Options) { o.HTTPClient = &dropCommitResponse{inner: o.HTTPClient} })
					}
					w := &AttachmentStore{Client: cl, Dest: d, Now: store.Now}
					if _, err := w.Stage(ctx, attachments.StageRequest{Ref: ref, Document: doc(body), Uploader: who, Body: bytes.NewReader(body)}); err != nil {
						errs[i] = err
						return
					}
					receipts[i], errs[i] = w.Commit(ctx, req)
				}()
			}
			wg.Wait()
			for i := range writers {
				if errs[i] != nil || receipts[i] != receipts[0] {
					t.Fatalf("writer %d: %+v %v", i, receipts[i], errs[i])
				}
			}
			r := receipts[0]
			if mode == Enabled && (r.DocumentVersionID == "" || r.ManifestVersionID == "") {
				t.Fatal("no version IDs recorded on a versioned bucket")
			}
			retry := req
			retry.Retention = attachments.DefaultRetention
			if again, err := (&AttachmentStore{Client: c, Dest: d}).Commit(ctx, retry); err != nil || again != r {
				t.Fatalf("retry: %+v %v", again, err)
			}
			conflict := req
			conflict.SpecDigest = "sha256:" + strings.Repeat("b", 64)
			if _, err := store.Commit(ctx, conflict); !errors.Is(err, attachments.ErrConflict) {
				t.Fatalf("conflict: %v", err)
			}
			if p, err := store.Health(ctx, r); err != nil || p != nil {
				t.Fatalf("health: %v %v", p, err)
			}
			prefix := AttachmentPrefix(d, ref)
			unrelated := prefix + "operator-notes.txt"
			if _, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(d.Bucket), Key: aws.String(unrelated), Body: strings.NewReader("keep")}); err != nil {
				t.Fatal(sanitize(err))
			}
			multipart := true
			if _, err := c.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String(d.Bucket), Key: aws.String(prefix + "attempts/abandoned/document")}); err != nil {
				multipart = false
				t.Logf("multipart uploads unsupported: %v", sanitize(err))
			}
			if err := store.CleanupAttempts(ctx, ref, now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			current, err := store.pub().listCurrent(ctx, prefix+"attempts/")
			if err != nil {
				t.Fatal(err)
			}
			for _, o := range current {
				if path.Dir(o.key) != path.Dir(r.DocumentKey) {
					t.Fatalf("abandoned attempt object remains: %s", o.key)
				}
			}
			if multipart {
				ups, err := c.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(d.Bucket), Prefix: aws.String(prefix)})
				if err != nil || len(ups.Uploads) != 0 {
					t.Fatalf("multipart uploads remain: %v %v", ups, err)
				}
			}
			if _, err := store.Delete(ctx, r, r.ExpiresAt.Add(-time.Second)); !errors.Is(err, attachments.ErrRetentionActive) {
				t.Fatalf("deletion before expiry: %v", err)
			}
			if cl, err := store.Delete(ctx, r, r.ExpiresAt); err != nil || cl.State != attachments.CleanupDeleted {
				t.Fatalf("deletion: %+v %v", cl, err)
			}
			left, err := store.listRaw(ctx, prefix)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range left {
				if v.key != unrelated {
					t.Fatalf("owned version remains after deletion: %s %s", v.key, v.version)
				}
			}
			results[string(mode)] = map[string]any{"receipt": r, "writers": writers, "lostResponse": true, "multipartCleanup": multipart, "remaining": len(left)}
		})
	}
	raw, _ := json.MarshalIndent(results, "", "  ")
	if err := os.WriteFile(filepath.Join(out, "attachment-compat.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}
