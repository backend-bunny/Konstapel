package s3store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/backend-bunny/Konstapel/internal/attachments"
)

// add-supporting-evidence-attachments 2.1-2.4 against the fake S3 service:
// staged upload, checksum/read-back verification, one conditional commit,
// identical retries, conflicting bytes, concurrent writers, lost responses,
// restart recovery, frozen expiry, owned attempt cleanup and deletion.

var (
	attRef   = attachments.Ref{ClusterID: "kube-system:cluster-1", UID: "att-uid-1"}
	otherRef = attachments.Ref{ClusterID: "kube-system:cluster-1", UID: "att-uid-2"}
	alice    = attachments.Principal{Username: "platform-uploader", UID: "uid-alice"}
	bob      = attachments.Principal{Username: "other-uploader", UID: "uid-bob"}
	specA    = "sha256:" + strings.Repeat("a", 64)
	specB    = "sha256:" + strings.Repeat("b", 64)
)

func doc(body []byte) attachments.Document {
	sum := sha256.Sum256(body)
	return attachments.Document{SHA256: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(body))}
}

func attachmentStore(t *testing.T, f *fakeS3) (*AttachmentStore, *time.Time) {
	t.Helper()
	_, d := f.serve(t)
	c, err := NewClient(context.Background(), d, &StaticCredentials{AccessKeyID: "AKIAFAKE", SecretAccessKey: "fake-secret"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	return &AttachmentStore{Client: c, Dest: d, Now: func() time.Time { return now }}, &now
}

func stage(t *testing.T, a *AttachmentStore, ref attachments.Ref, body []byte, who attachments.Principal) attachments.Staged {
	t.Helper()
	s, err := a.Stage(context.Background(), attachments.StageRequest{Ref: ref, Document: doc(body), Uploader: who, Body: bytes.NewReader(body)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func commitReq(ref attachments.Ref, body []byte, spec string, validUntil time.Time, retention time.Duration) attachments.CommitRequest {
	return attachments.CommitRequest{Ref: ref, SpecDigest: spec, Document: doc(body), ValidUntil: validUntil, Retention: retention}
}

func TestAttachmentCommitFreezesExpiry(t *testing.T) {
	for _, mode := range []string{"", "Enabled"} {
		t.Run("versioning="+mode, func(t *testing.T) {
			f := newFake()
			f.versioning = mode
			a, _ := attachmentStore(t, f)
			ctx := context.Background()
			body := []byte("%PDF-1.7 datacenter audit")
			stage(t, a, attRef, body, alice)
			validUntil := time.Now().Add(365 * 24 * time.Hour).UTC().Truncate(time.Second)
			r, err := a.Commit(ctx, commitReq(attRef, body, specA, validUntil, attachments.DefaultRetention))
			if err != nil {
				t.Fatal(err)
			}
			if r.Uploader != alice || r.Document != doc(body) || r.SpecDigest != specA || r.Destination.ID != "fake" {
				t.Fatalf("receipt %+v", r)
			}
			if !r.ExpiresAt.Equal(validUntil.Add(attachments.DefaultRetention)) {
				t.Fatalf("expiry %s, want validUntil + 2160h", r.ExpiresAt)
			}
			if mode == "Enabled" && (r.DocumentVersionID == "" || r.ManifestVersionID == "") {
				t.Fatal("versioned commitment records no version IDs")
			}
			if !strings.HasPrefix(r.DocumentKey, "konstapel/attachments/cluster-1/att-uid-1/attempts/") || r.ManifestKey != "konstapel/attachments/cluster-1/att-uid-1/commit.json" {
				t.Fatalf("keys %s %s", r.DocumentKey, r.ManifestKey)
			}
			// An identical retry, with changed retention and validity (a
			// policy change), returns the first commitment unchanged.
			again, err := a.Commit(ctx, commitReq(attRef, body, specA, validUntil.Add(time.Hour), time.Hour))
			if err != nil || again != r {
				t.Fatalf("retry: %+v %v", again, err)
			}
			// A document already expired at commitment still gets the
			// retention tail after its commitment time.
			stage(t, a, otherRef, body, alice)
			old, err := a.Commit(ctx, commitReq(otherRef, body, specA, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if !old.ExpiresAt.Equal(old.CommittedAt.Add(time.Hour)) {
				t.Fatalf("expired document expiry %s, committed %s", old.ExpiresAt, old.CommittedAt)
			}
		})
	}
}

func TestAttachmentStageRejectsMismatchedBytes(t *testing.T) {
	f := newFake()
	a, _ := attachmentStore(t, f)
	body := []byte("registered bytes")
	for name, sent := range map[string][]byte{"different": []byte("REGISTERED BYTES"), "short": body[:4], "long": append(append([]byte{}, body...), 'x')} {
		_, err := a.Stage(context.Background(), attachments.StageRequest{Ref: attRef, Document: doc(body), Uploader: alice, Body: bytes.NewReader(sent)})
		if !errors.Is(err, attachments.ErrIntegrity) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if k := f.keys(""); len(k) != 0 {
		t.Fatalf("mismatched bytes reached storage: %v", k)
	}
	if _, err := a.Commit(context.Background(), commitReq(attRef, body, specA, time.Now(), time.Hour)); !errors.Is(err, attachments.ErrNotFound) {
		t.Fatalf("commit without a verified upload: %v", err)
	}
}

func TestAttachmentStageDetectsCorruptStorage(t *testing.T) {
	f := newFake()
	f.corrupt = true
	a, _ := attachmentStore(t, f)
	body := []byte("bytes the service truncates")
	_, err := a.Stage(context.Background(), attachments.StageRequest{Ref: attRef, Document: doc(body), Uploader: alice, Body: bytes.NewReader(body)})
	if err == nil {
		t.Fatal("a corrupted stored document was accepted")
	}
	if _, err := a.Commit(context.Background(), commitReq(attRef, body, specA, time.Now(), time.Hour)); !errors.Is(err, attachments.ErrNotFound) {
		t.Fatalf("an unverified attempt was committable: %v", err)
	}
}

func TestAttachmentConflictingCommitPreservesOriginal(t *testing.T) {
	f := newFake()
	a, _ := attachmentStore(t, f)
	ctx := context.Background()
	first, second := []byte("first document"), []byte("second document")
	stage(t, a, attRef, first, alice)
	r, err := a.Commit(ctx, commitReq(attRef, first, specA, time.Now().Add(time.Hour), time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	stage(t, a, attRef, second, bob)
	for name, req := range map[string]attachments.CommitRequest{
		"other bytes": commitReq(attRef, second, specB, time.Now(), time.Hour),
		"other spec":  commitReq(attRef, first, specB, time.Now(), time.Hour),
	} {
		if _, err := a.Commit(ctx, req); !errors.Is(err, attachments.ErrConflict) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if got, err := a.Committed(ctx, attRef); err != nil || got != r {
		t.Fatalf("original commitment changed: %+v %v", got, err)
	}
}

func TestAttachmentConcurrentWritersConverge(t *testing.T) {
	f := newFake()
	f.versioning = "Enabled"
	a, _ := attachmentStore(t, f)
	body := []byte("shared facility evidence")
	const writers = 4
	receipts := make([]attachments.Receipt, writers)
	errs := make([]error, writers)
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			who := alice
			if i%2 == 1 {
				who = bob
			}
			// Separate store instances: separate replicas.
			b := &AttachmentStore{Client: a.Client, Dest: a.Dest, Now: a.Now}
			if _, err := b.Stage(context.Background(), attachments.StageRequest{Ref: attRef, Document: doc(body), Uploader: who, Body: bytes.NewReader(body)}); err != nil {
				errs[i] = err
				return
			}
			receipts[i], errs[i] = b.Commit(context.Background(), commitReq(attRef, body, specA, time.Now().Add(time.Hour), time.Hour))
		}()
	}
	wg.Wait()
	for i := range writers {
		if errs[i] != nil {
			t.Fatalf("writer %d: %v", i, errs[i])
		}
		if receipts[i] != receipts[0] {
			t.Fatalf("writer %d got %+v, writer 0 %+v", i, receipts[i], receipts[0])
		}
	}
	f.mu.Lock()
	versions := len(f.objects[receipts[0].ManifestKey])
	f.mu.Unlock()
	if versions != 1 {
		t.Fatalf("%d commit versions, want exactly one", versions)
	}
	// The losers' attempts are abandoned; cleanup removes them and keeps
	// the committed one.
	if err := a.CleanupAttempts(context.Background(), attRef, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	dirs := map[string]bool{}
	for _, k := range f.keys(AttachmentPrefix(a.Dest, attRef) + "attempts/") {
		dirs[k[:strings.LastIndex(k, "/")]] = true
	}
	if len(dirs) != 1 || !dirs[receipts[0].DocumentKey[:strings.LastIndex(receipts[0].DocumentKey, "/")]] {
		t.Fatalf("attempts after cleanup: %v", dirs)
	}
	if _, err := a.Health(context.Background(), receipts[0]); err != nil {
		t.Fatal(err)
	}
}

func TestAttachmentLostCommitResponseAndRestart(t *testing.T) {
	f := newFake()
	f.loseCommits = true
	a, _ := attachmentStore(t, f)
	ctx := context.Background()
	body := []byte("committed while the response was lost")
	stage(t, a, attRef, body, alice)
	r, err := a.Commit(ctx, commitReq(attRef, body, specA, time.Now().Add(time.Hour), time.Hour))
	if err != nil {
		t.Fatalf("a commitment whose response was lost was not recovered: %v", err)
	}
	// A restarted process (new store) sees the same commitment.
	restarted := &AttachmentStore{Client: a.Client, Dest: a.Dest}
	if got, err := restarted.Committed(ctx, attRef); err != nil || got != r {
		t.Fatalf("after restart: %+v %v", got, err)
	}
	// Staged but uncommitted before a restart: the new process commits it
	// without another upload.
	f.loseCommits = false
	stage(t, a, otherRef, body, bob)
	before := len(f.keys(""))
	got, err := restarted.Commit(ctx, commitReq(otherRef, body, specA, time.Now().Add(time.Hour), time.Hour))
	if err != nil || got.Uploader != bob {
		t.Fatalf("restart commit: %+v %v", got, err)
	}
	if after := len(f.keys("")); after != before+1 {
		t.Fatalf("restart commit wrote %d objects, want only the commit", after-before)
	}
}

func TestAttachmentRecordsFailClosed(t *testing.T) {
	f := newFake()
	a, _ := attachmentStore(t, f)
	ctx := context.Background()
	key := AttachmentPrefix(a.Dest, attRef) + "commit.json"
	for name, rec := range map[string]string{
		"future version": `{"apiVersion":"storage.konstapel.dev/attachments/v2","kind":"AttachmentCommit"}`,
		"unknown field":  `{"apiVersion":"storage.konstapel.dev/attachments/v1","kind":"AttachmentCommit","verdict":"Satisfied"}`,
		"not json":       `{`,
	} {
		if _, err := a.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(a.Dest.Bucket), Key: aws.String(key), Body: strings.NewReader(rec)}); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Committed(ctx, attRef); !errors.Is(err, attachments.ErrUnsupportedRecord) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestAttachmentCleanupIsOwnedAndBounded(t *testing.T) {
	f := newFake()
	f.versioning = "Enabled"
	f.uploads = map[string]string{}
	a, now := attachmentStore(t, f)
	ctx := context.Background()
	body := []byte("document")
	stage(t, a, attRef, body, alice) // abandoned, old
	stage(t, a, otherRef, body, alice)
	prefix := AttachmentPrefix(a.Dest, attRef)
	unrelated := []string{prefix + "operator-notes.txt", prefix + "attempts/stray.txt", prefix + "attempts/foreign/intent.json"}
	for _, k := range unrelated {
		if _, err := a.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(a.Dest.Bucket), Key: aws.String(k), Body: strings.NewReader("x")}); err != nil {
			t.Fatal(err)
		}
	}
	f.mu.Lock()
	f.uploads["mine"], f.uploads["theirs"] = prefix+"attempts/x/document", AttachmentPrefix(a.Dest, otherRef)+"attempts/y/document"
	f.mu.Unlock()
	// Young attempts are kept.
	if err := a.CleanupAttempts(ctx, attRef, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(f.keys(prefix+"attempts/")) != 3+2 {
		t.Fatalf("young attempt removed: %v", f.keys(prefix))
	}
	if err := a.CleanupAttempts(ctx, attRef, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	left := f.keys(prefix)
	for _, k := range unrelated {
		if !strings.Contains(strings.Join(left, " "), k) {
			t.Fatalf("unrelated %s deleted", k)
		}
	}
	if len(left) != len(unrelated) {
		t.Fatalf("owned attempt objects remain: %v", left)
	}
	if len(f.keys(AttachmentPrefix(a.Dest, otherRef))) != 3 {
		t.Fatal("another attachment's attempt was touched")
	}
	f.mu.Lock()
	_, mine := f.uploads["mine"]
	_, theirs := f.uploads["theirs"]
	f.mu.Unlock()
	if mine || !theirs {
		t.Fatalf("multipart cleanup: mine=%v theirs=%v", mine, theirs)
	}
	// Withdrawal before any commitment removes the remaining owned attempts.
	stage(t, a, attRef, body, alice)
	if c, err := a.DeleteUncommitted(ctx, attRef); err != nil || c.State != attachments.CleanupDeleted {
		t.Fatalf("withdraw uncommitted: %+v %v", c, err)
	}
	if left := f.keys(prefix); len(left) != len(unrelated) {
		t.Fatalf("after withdrawal: %v", left)
	}
}

func TestAttachmentDeleteWaitsForExpiryAndKeepsUnrelated(t *testing.T) {
	f := newFake()
	f.versioning = "Enabled"
	a, now := attachmentStore(t, f)
	ctx := context.Background()
	body := []byte("annual audit")
	stage(t, a, attRef, body, alice)
	r, err := a.Commit(ctx, commitReq(attRef, body, specA, now.Add(time.Hour), time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.DeleteUncommitted(ctx, attRef); !errors.Is(err, attachments.ErrConflict) {
		t.Fatalf("uncommitted deletion of a committed attachment: %v", err)
	}
	if _, err := a.Delete(ctx, r, r.ExpiresAt.Add(-time.Second)); !errors.Is(err, attachments.ErrRetentionActive) {
		t.Fatalf("deletion before expiry: %v", err)
	}
	// Before expiry the document opens; afterwards source downloads stop.
	rc, err := a.Open(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	rc.Close()
	prefix := AttachmentPrefix(a.Dest, attRef)
	if _, err := a.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(a.Dest.Bucket), Key: aws.String(prefix + "operator-notes.txt"), Body: strings.NewReader("x")}); err != nil {
		t.Fatal(err)
	}
	*now = r.ExpiresAt
	if _, err := a.Open(ctx, r); !errors.Is(err, attachments.ErrNotFound) {
		t.Fatalf("expired source opened: %v", err)
	}
	f.denyDelete = true
	if c, err := a.Delete(ctx, r, *now); !errors.Is(err, attachments.ErrRetentionBlocked) || c.State != attachments.CleanupRetentionBlocked {
		t.Fatalf("blocked deletion: %+v %v", c, err)
	}
	if _, err := a.Committed(ctx, attRef); err != nil {
		t.Fatalf("a failed deletion lost the commitment: %v", err)
	}
	f.denyDelete = false
	if c, err := a.Delete(ctx, r, *now); err != nil || c.State != attachments.CleanupDeleted {
		t.Fatalf("deletion: %+v %v", c, err)
	}
	if left := f.keys(prefix); len(left) != 1 || left[0] != prefix+"operator-notes.txt" {
		t.Fatalf("after deletion: %v", left)
	}
	if _, err := a.Committed(ctx, attRef); !errors.Is(err, attachments.ErrNotFound) {
		t.Fatalf("commit remains: %v", err)
	}
}

func TestAttachmentHealthDetectsDamage(t *testing.T) {
	f := newFake()
	a, _ := attachmentStore(t, f)
	ctx := context.Background()
	body := []byte("document to damage")
	stage(t, a, attRef, body, alice)
	r, err := a.Commit(ctx, commitReq(attRef, body, specA, time.Now().Add(time.Hour), time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if p, err := a.Health(ctx, r); err != nil || p != nil {
		t.Fatalf("intact: %v %v", p, err)
	}
	if _, err := a.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(a.Dest.Bucket), Key: aws.String(r.DocumentKey), Body: strings.NewReader("tampered")}); err != nil {
		t.Fatal(err)
	}
	if p, err := a.Health(ctx, r); err != nil || p == nil || p.Reason != attachments.ProblemIntegrity {
		t.Fatalf("tampered: %v %v", p, err)
	}
	if _, err := a.Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(a.Dest.Bucket), Key: aws.String(r.DocumentKey)}); err != nil {
		t.Fatal(err)
	}
	if p, err := a.Health(ctx, r); err != nil || p == nil || p.Reason != attachments.ProblemMissing {
		t.Fatalf("missing: %v %v", p, err)
	}
}

func TestAttachmentReceiptIsBoundToDestination(t *testing.T) {
	f := newFake()
	a, _ := attachmentStore(t, f)
	ctx := context.Background()
	body := []byte("document")
	stage(t, a, attRef, body, alice)
	if _, err := a.Commit(ctx, commitReq(attRef, body, specA, time.Now().Add(time.Hour), time.Hour)); err != nil {
		t.Fatal(err)
	}
	// The same bucket and prefix configured as another destination ID (a
	// changed default) never adopts the commitment silently.
	moved := &AttachmentStore{Client: a.Client, Dest: a.Dest}
	moved.Dest.ID = "new-default"
	if _, err := moved.Committed(ctx, attRef); !errors.Is(err, attachments.ErrConflict) {
		t.Fatalf("commitment adopted by another destination: %v", err)
	}
}

// commitDuringDelete runs commit once, before the first DELETE it forwards:
// an upload that passed its last withdrawal check commits while the
// withdrawal is removing the attempts.
type commitDuringDelete struct {
	inner  s3.HTTPClient
	once   sync.Once
	commit func()
}

func (c *commitDuringDelete) Do(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodDelete {
		c.once.Do(c.commit)
	}
	return c.inner.Do(r)
}

// add-supporting-evidence-attachments 3.1: a commit that lands while an
// uncommitted record's attempts are being removed is reported as a
// conflict, so the controller records and retains it instead of releasing
// the record over a live commitment.
func TestAttachmentDeleteUncommittedSeesALateCommit(t *testing.T) {
	f := newFake()
	uploader, _ := attachmentStore(t, f)
	ctx := context.Background()
	body := []byte("uploaded just before withdrawal")
	stage(t, uploader, attRef, body, alice)
	var committed error
	wrap := &commitDuringDelete{commit: func() {
		_, committed = uploader.Commit(ctx, commitReq(attRef, body, specA, time.Now().Add(time.Hour), time.Hour))
	}}
	withdrawer := &AttachmentStore{Dest: uploader.Dest, Now: uploader.Now,
		Client: s3.New(uploader.Client.Options(), func(o *s3.Options) { wrap.inner = o.HTTPClient; o.HTTPClient = wrap })}
	if _, err := withdrawer.DeleteUncommitted(ctx, attRef); !errors.Is(err, attachments.ErrConflict) {
		t.Fatalf("withdrawal over a late commit: %v (commit: %v)", err, committed)
	}
	if committed != nil {
		t.Fatal(committed)
	}
	if _, err := withdrawer.Committed(ctx, attRef); err != nil {
		t.Fatalf("the late commitment was removed: %v", err)
	}
}

// add-supporting-evidence-attachments 4.2/4.3: owned cleanup removes every
// owned version and delete marker, never an unrelated object (outside the
// attachment's prefix, under it, or inside one of its own attempt
// directories) and never a historical package. A deletion refused part-way
// keeps the ownership records, so its retry still finds and removes the
// owned bytes.
func TestAttachmentCleanupFailsSafeAndRecovers(t *testing.T) {
	for _, mode := range []string{"", "Enabled", "Suspended"} {
		t.Run("versioning="+mode, func(t *testing.T) {
			f := newFake()
			f.versioning = mode
			a, now := attachmentStore(t, f)
			ctx := context.Background()
			body := []byte("annual audit, committed")
			loser := stage(t, a, attRef, []byte("a losing upload of other bytes"), alice)
			stage(t, a, attRef, body, alice)
			r, err := a.Commit(ctx, commitReq(attRef, body, specA, now.Add(time.Hour), time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			prefix := AttachmentPrefix(a.Dest, attRef)
			loserDir := prefix + "attempts/" + loser.AttemptID + "/"
			committedDir := r.DocumentKey[:strings.LastIndex(r.DocumentKey, "/")+1]
			put := func(key, body string) {
				t.Helper()
				if _, err := a.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(a.Dest.Bucket), Key: aws.String(key), Body: strings.NewReader(body)}); err != nil {
					t.Fatal(err)
				}
			}
			// Objects Konstapel does not own, and a historical package.
			pkg := RunPrefix(a.Dest, testRun) + "package.tar.gz"
			unrelated := map[string]string{prefix + "operator-notes.txt": "keep", loserDir + "operator-notes.txt": "keep too",
				committedDir + "legal-hold.txt": "keep as well", pkg: "historical package bytes"}
			for k, v := range unrelated {
				put(k, v)
			}
			if mode == "Enabled" {
				// A delete marker on an owned key is owned too.
				if _, err := a.Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(a.Dest.Bucket), Key: aws.String(loserDir + attachmentDocumentFile)}); err != nil {
					t.Fatal(err)
				}
			}
			*now = r.ExpiresAt
			// An object lock on the losing upload's document refuses deletion
			// part-way: its ownership records and the commit are kept.
			f.denyDeleteKey = func(k string) bool { return k == loserDir+attachmentDocumentFile }
			if c, err := a.Delete(ctx, r, *now); !errors.Is(err, attachments.ErrRetentionBlocked) || c.State != attachments.CleanupRetentionBlocked {
				t.Fatalf("locked document: %+v %v", c, err)
			}
			for _, k := range []string{loserDir + intentFile, loserDir + attachmentAttemptFile} {
				if len(f.objects[k]) == 0 {
					t.Fatalf("ownership record %s removed before the bytes it owns", k)
				}
			}
			if _, err := a.Committed(ctx, attRef); err != nil {
				t.Fatalf("a refused deletion lost the commitment: %v", err)
			}
			// The lock is lifted: the retry removes every owned object.
			f.denyDeleteKey = nil
			if c, err := a.Delete(ctx, r, *now); err != nil || c.State != attachments.CleanupDeleted {
				t.Fatalf("retry: %+v %v", c, err)
			}
			for k, versions := range f.objects {
				if _, keep := unrelated[k]; keep {
					if got := versions[len(versions)-1]; got.deleted || string(got.body) != unrelated[k] {
						t.Fatalf("unrelated object %s changed", k)
					}
					continue
				}
				if strings.HasPrefix(k, prefix) {
					t.Fatalf("owned object %s (%d versions) remains", k, len(versions))
				}
			}
			if len(f.objects) != len(unrelated) {
				t.Fatalf("objects left: %d, want %d unrelated", len(f.objects), len(unrelated))
			}
		})
	}
}

// Withdrawal of an uncommitted record and abandoned-attempt cleanup keep
// the same order: a refused document keeps its attempt owned and cleanable.
func TestAttachmentUncommittedCleanupFailsSafeAndRecovers(t *testing.T) {
	f := newFake()
	f.versioning = "Enabled"
	a, now := attachmentStore(t, f)
	ctx := context.Background()
	s1 := stage(t, a, attRef, []byte("abandoned upload one"), alice)
	s2 := stage(t, a, otherRef, []byte("abandoned upload two"), bob)
	prefix := AttachmentPrefix(a.Dest, attRef)
	dir1 := prefix + "attempts/" + s1.AttemptID + "/"
	dir2 := AttachmentPrefix(a.Dest, otherRef) + "attempts/" + s2.AttemptID + "/"
	f.denyDeleteKey = func(k string) bool { return strings.HasSuffix(k, "/"+attachmentDocumentFile) }
	if c, err := a.DeleteUncommitted(ctx, attRef); !errors.Is(err, attachments.ErrRetentionBlocked) || c.State != attachments.CleanupRetentionBlocked {
		t.Fatalf("locked withdrawal: %+v %v", c, err)
	}
	if err := a.CleanupAttempts(ctx, otherRef, now.Add(time.Hour)); err == nil {
		t.Fatal("a refused attempt cleanup reported success")
	}
	for _, k := range []string{dir1 + intentFile, dir1 + attachmentAttemptFile, dir2 + intentFile, dir2 + attachmentAttemptFile} {
		if len(f.objects[k]) == 0 {
			t.Fatalf("ownership record %s removed before its document", k)
		}
	}
	f.denyDeleteKey = nil
	if c, err := a.DeleteUncommitted(ctx, attRef); err != nil || c.State != attachments.CleanupDeleted {
		t.Fatalf("retried withdrawal: %+v %v", c, err)
	}
	if err := a.CleanupAttempts(ctx, otherRef, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if left := f.keys(prefix); len(left) != 0 {
		t.Fatalf("withdrawn attempt objects remain: %v", left)
	}
	if left := f.keys(dir2); len(left) != 0 {
		t.Fatalf("abandoned attempt objects remain: %v", left)
	}
}
