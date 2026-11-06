package s3store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/backend-bunny/Konstapel/internal/publication/publicationtest"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

func (f *fakeS3) put(key string, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	f.objects[key] = append(f.objects[key], fakeVersion{id: "x" + key, body: []byte(body), at: time.Now()})
}

func (f *fakeS3) keys(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k, vs := range f.objects {
		if strings.HasPrefix(k, prefix) && len(vs) > 0 {
			out = append(out, k)
		}
	}
	return out
}

// After a commit, abandoned attempts (an interrupted upload with only its
// intent, a superseded full attempt) and incomplete multipart uploads are
// removed; the committed attempt, the commit, other runs' objects, and
// objects whose ownership cannot be established survive.
func TestCleanupAttemptsKeepsCommittedAndUnowned(t *testing.T) {
	for _, mode := range []string{"", "Enabled"} {
		f := newFake()
		f.versioning = mode
		p := newPublisher(t, f, time.Now)
		ctx := context.Background()
		dir := fullPackage(t)
		s, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
		r, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("2160h")})
		if err != nil {
			t.Fatal(err)
		}
		prefix := p.runPrefix(testRun)
		// An interrupted upload: intent written, archive partially uploaded.
		f.put(prefix+"attempts/interrupted/"+intentFile, `{"run":`+statusJSONRun(testRun)+`}`)
		f.put(prefix+"attempts/interrupted/package.tar.gz", "partial")
		// A directory without an owner record, a stray key, and another run.
		f.put(prefix+"attempts/unknown/package.tar.gz", "who knows")
		f.put(prefix+"attempts/stray", "x")
		other := testRun
		other.RunUID = "run-uid-2"
		otherPrefix := p.runPrefix(other)
		f.put(otherPrefix+"attempts/a/"+intentFile, `{"run":`+statusJSONRun(other)+`}`)
		f.put("unrelated/object", "x")
		f.uploads = map[string]string{"u1": prefix + "attempts/interrupted/big", "u2": otherPrefix + "attempts/a/big"}

		if err := p.CleanupAttempts(ctx, testRun); err != nil {
			t.Fatal(mode, err)
		}
		left := strings.Join(f.keys(""), ",")
		for _, gone := range []string{"attempts/interrupted/"} {
			if strings.Contains(left, prefix+gone) {
				t.Fatalf("%s abandoned attempt kept: %s", mode, left)
			}
		}
		for _, kept := range []string{r.Commit.ArchiveKey, r.Commit.ManifestKey, prefix + "attempts/unknown/package.tar.gz", prefix + "attempts/stray", otherPrefix + "attempts/a/" + intentFile, "unrelated/object"} {
			if !strings.Contains(left, kept) {
				t.Fatalf("%s %s removed: %s", mode, kept, left)
			}
		}
		if _, ok := f.uploads["u1"]; ok || len(f.uploads) != 1 {
			t.Fatalf("%s multipart uploads: %v", mode, f.uploads)
		}
		if got, err := p.Inspect(ctx, testRun); err != nil || got.Phase != publication.PhaseCommitted {
			t.Fatalf("%s commit damaged: %+v %v", mode, got, err)
		}
		// Idempotent.
		if err := p.CleanupAttempts(ctx, testRun); err != nil {
			t.Fatal(mode, err)
		}
	}
}

// A run that never committed loses every attempt it owns.
func TestCleanupAttemptsWithoutCommit(t *testing.T) {
	f := newFake()
	p := newPublisher(t, f, time.Now)
	ctx := context.Background()
	if _, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: fullPackage(t)}); err != nil {
		t.Fatal(err)
	}
	if err := p.CleanupAttempts(ctx, testRun); err != nil {
		t.Fatal(err)
	}
	if left := f.keys(p.runPrefix(testRun)); len(left) != 0 {
		t.Fatalf("attempts survived: %v", left)
	}
	if _, err := p.Recover(ctx, testRun); err == nil {
		t.Fatal("cleaned attempt still recoverable")
	}
}

func statusJSONRun(r publication.RunRef) string {
	b, _ := json.Marshal(r)
	return string(b)
}

func TestOpenServesOnlyCommittedUnexpiredArchives(t *testing.T) {
	f := newFake()
	clock := time.Now()
	p := newPublisher(t, f, func() time.Time { return clock })
	ctx := context.Background()
	s, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: fullPackage(t)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Open(ctx, testRun); !errors.Is(err, publication.ErrNotFound) {
		t.Fatalf("uncommitted archive opened: %v", err)
	}
	r, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("1h")})
	if err != nil {
		t.Fatal(err)
	}
	body, st, err := p.Open(ctx, testRun)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(body)
	_ = body.Close()
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != r.PackageSHA256 || st.PackageSHA256 != r.PackageSHA256 || st.PublicationID != r.PublicationID {
		t.Fatal("opened bytes or status differ from the commit")
	}
	f.mu.Lock()
	delete(f.objects, r.Commit.ArchiveKey)
	f.mu.Unlock()
	if _, _, err := p.Open(ctx, testRun); !errors.Is(err, publication.ErrUnavailable) {
		t.Fatalf("missing archive: %v", err)
	}
	clock = r.ExpiresAt.Add(time.Second)
	if _, _, err := p.Open(ctx, testRun); !errors.Is(err, publication.ErrExpired) {
		t.Fatalf("expired archive: %v", err)
	}
}

// Expiry deletion removes every owned version of one run and nothing else;
// a refused deletion is RetentionBlocked and keeps the commit.
func TestDeleteAfterExpiryIsScopedAndTruthful(t *testing.T) {
	for _, mode := range []string{"", "Enabled", "Suspended"} {
		f := newFake()
		f.versioning = mode
		clock := time.Now()
		p := newPublisher(t, f, func() time.Time { return clock })
		ctx := context.Background()
		publish := func(run publication.RunRef, retention string) publication.Receipt {
			s, err := p.Stage(ctx, publication.StageRequest{Run: run, Dir: fullPackageFor(t, run)})
			if err != nil {
				t.Fatal(err)
			}
			r, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retentionOf(retention)})
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		short := publish(testRun, "1h")
		other := testRun
		other.RunUID = "run-uid-kept"
		publish(other, "2160h")
		f.put("unrelated/object", "x")
		if _, err := p.Delete(ctx, testRun); !errors.Is(err, publication.ErrRetentionActive) {
			t.Fatalf("%s deleted before expiry: %v", mode, err)
		}
		clock = short.ExpiresAt.Add(time.Second)
		f.denyDelete = true
		cl, err := p.Delete(ctx, testRun)
		if !errors.Is(err, publication.ErrRetentionBlocked) || cl.State != publication.CleanupRetentionBlocked {
			t.Fatalf("%s refused deletion reported as %+v %v", mode, cl, err)
		}
		if _, err := p.read(ctx, short.Commit.ManifestKey, ""); err != nil {
			t.Fatalf("%s commit lost after a refused deletion: %v", mode, err)
		}
		f.denyDelete = false
		if cl, err := p.Delete(ctx, testRun); err != nil || cl.State != publication.CleanupDeleted {
			t.Fatalf("%s deletion: %+v %v", mode, cl, err)
		}
		if left := f.keys(p.runPrefix(testRun)); len(left) != 0 {
			t.Fatalf("%s owned objects survived: %v", mode, left)
		}
		if st, err := p.Inspect(ctx, other); err != nil || st.Phase != publication.PhaseCommitted {
			t.Fatalf("%s separately retained package affected: %+v %v", mode, st, err)
		}
		if len(f.keys("unrelated/")) != 1 {
			t.Fatalf("%s unrelated object removed", mode)
		}
	}
}

func retentionOf(d string) publication.Retention { return retention(d) }

func fullPackageFor(t *testing.T, run publication.RunRef) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pkg")
	if _, err := publicationtest.FullAssessmentPackage(repoRoot(t), dir, run); err != nil {
		t.Fatal(err)
	}
	return dir
}
