package s3fault

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// backend records what reaches the S3 service.
type backend struct {
	mu   sync.Mutex
	reqs []string // "METHOD path host body"
}

func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	b.mu.Lock()
	b.reqs = append(b.reqs, r.Method+" "+r.URL.Path+" "+r.Host+" "+string(body))
	b.mu.Unlock()
	_, _ = io.WriteString(w, "ok")
}

func (b *backend) seen() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.reqs...)
}

func setup(t *testing.T) (*Proxy, *backend, string) {
	t.Helper()
	be := &backend{}
	bs := httptest.NewServer(be)
	t.Cleanup(bs.Close)
	p := &Proxy{Backend: strings.TrimPrefix(bs.URL, "http://")}
	ps := httptest.NewServer(p)
	t.Cleanup(ps.Close)
	return p, be, ps.URL
}

const run = "0b6c5a52-1111-4b5e-9d1a-2b3c4d5e6f70"

func send(t *testing.T, url, method, path, body string, commit bool) (int, error) {
	t.Helper()
	req, _ := http.NewRequest(method, url+path, strings.NewReader(body))
	req.Host = "signed.example:9000"
	if commit {
		req.Header.Set("If-None-Match", "*")
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

var commitPath = "/bucket/p/evidence/c/b/" + run + "/commit.json"

func TestPassKeepsTheSignedHost(t *testing.T) {
	p, be, url := setup(t)
	p.Arm(ModePass, run)
	if code, err := send(t, url, http.MethodPut, commitPath, "manifest", true); err != nil || code != http.StatusOK {
		t.Fatalf("commit through a passing proxy: %d %v", code, err)
	}
	if got := be.seen(); len(got) != 1 || got[0] != "PUT "+commitPath+" signed.example:9000 manifest" {
		t.Fatalf("backend saw %q", got)
	}
	if st := p.Snapshot(); st.CommitArrivals != 1 || st.CommitsForwarded != 1 || st.LastCommitStatus != http.StatusOK {
		t.Fatalf("state %+v", st)
	}
}

func TestHoldNeverForwardsTheCommit(t *testing.T) {
	p, be, url := setup(t)
	p.Arm(ModeHold, run)
	// Staging traffic and another key's conditional create (the readiness
	// probe) pass.
	for _, path := range []string{"/bucket/p/evidence/c/b/" + run + "/attempts/a/package.tar.gz", "/bucket/p/probe/commit.json"} {
		if code, err := send(t, url, http.MethodPut, path, "x", strings.HasSuffix(path, "commit.json")); err != nil || code != http.StatusOK {
			t.Fatalf("%s: %d %v", path, code, err)
		}
	}
	done := make(chan int, 1)
	go func() { code, _ := send(t, url, http.MethodPut, commitPath, "manifest", true); done <- code }()
	eventually(t, "the commit held", func() bool { st := p.Snapshot(); return st.CommitsHeld == 1 && st.Waiting == 1 })
	select {
	case code := <-done:
		t.Fatalf("held commit answered %d", code)
	case <-time.After(200 * time.Millisecond):
	}
	p.Release()
	if code := <-done; code != http.StatusServiceUnavailable {
		t.Fatalf("released held commit: %d", code)
	}
	for _, r := range be.seen() {
		if strings.Contains(r, run+"/commit.json") {
			t.Fatalf("held commit reached the backend: %q", r)
		}
	}
	// After release the next commit passes.
	if code, err := send(t, url, http.MethodPut, commitPath, "manifest", true); err != nil || code != http.StatusOK {
		t.Fatalf("commit after release: %d %v", code, err)
	}
	if st := p.Snapshot(); st.CommitArrivals != 2 || st.CommitsHeld != 1 || st.CommitsForwarded != 1 {
		t.Fatalf("state %+v", st)
	}
}

func TestAfterCommitLandsAndLosesTheResponse(t *testing.T) {
	p, be, url := setup(t)
	p.Arm(ModeAfter, run)
	done := make(chan int, 2)
	go func() { code, _ := send(t, url, http.MethodPut, commitPath, "manifest", true); done <- code }()
	eventually(t, "the commit forwarded", func() bool { st := p.Snapshot(); return st.CommitsForwarded == 1 && st.Blackhole && st.Waiting == 1 })
	if st := p.Snapshot(); st.LastCommitStatus != http.StatusOK {
		t.Fatalf("state %+v", st)
	}
	// Every later request is blackholed and never forwarded.
	go func() { code, _ := send(t, url, http.MethodGet, commitPath, "", false); done <- code }()
	eventually(t, "a later request blackholed", func() bool { return p.Snapshot().Waiting == 2 })
	if got := be.seen(); len(got) != 1 || got[0] != "PUT "+commitPath+" signed.example:9000 manifest" {
		t.Fatalf("backend saw %q", got)
	}
	p.Release()
	for range 2 {
		if code := <-done; code != http.StatusServiceUnavailable {
			t.Fatalf("blocked request after release: %d", code)
		}
	}
	if code, err := send(t, url, http.MethodGet, commitPath, "", false); err != nil || code != http.StatusOK {
		t.Fatalf("read after release: %d %v", code, err)
	}
	if st := p.Snapshot(); st.CommitArrivals != 1 || st.CommitsForwarded != 1 || st.Blackholed != 1 {
		t.Fatalf("state %+v", st)
	}
}

func TestControl(t *testing.T) {
	p, _, _ := setup(t)
	cs := httptest.NewServer(p.Control())
	defer cs.Close()
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/arm?mode=hold", http.StatusBadRequest},
		{http.MethodPost, "/arm?mode=drop&run=" + run, http.StatusBadRequest},
		{http.MethodPost, "/arm?mode=hold&run=" + run, http.StatusOK},
		{http.MethodPost, "/blackhole", http.StatusOK},
		{http.MethodGet, "/state", http.StatusOK},
	} {
		if code, err := send(t, cs.URL, c.method, c.path, "", false); err != nil || code != c.want {
			t.Fatalf("%s %s: %d %v", c.method, c.path, code, err)
		}
	}
	if st := p.Snapshot(); st.Mode != ModeHold || st.Run != run || !st.Blackhole {
		t.Fatalf("state %+v", st)
	}
	if code, _ := send(t, cs.URL, http.MethodPost, "/release", "", false); code != http.StatusOK || p.Snapshot().Mode != ModePass {
		t.Fatalf("release: %d %+v", code, p.Snapshot())
	}
}
