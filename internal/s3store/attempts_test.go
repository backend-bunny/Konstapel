package s3store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
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
