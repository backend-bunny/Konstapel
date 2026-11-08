// Package s3fault is a test-owned, fault-injecting reverse proxy for an S3
// service. Live acceptance puts it between the Helm-installed controller and
// the test S3 backend to interrupt one run's publication deterministically
// at a durable boundary, without changing the controller:
//   - hold: the run's conditional commit (PUT .../<run UID>/commit.json with
//     If-None-Match: *) is held and never forwarded, so the package is
//     durably staged and uncommitted while the leader is mid-commit;
//   - after: the run's first commit is forwarded and lands, its response is
//     never delivered, and every later request is blackholed, so the
//     package is committed and the leader cannot record the receipt.
//
// Requests are forwarded with their Host header unchanged, so SigV4
// signatures made for the proxy's address stay valid at the backend. A
// held or blackholed request is never forwarded; on release it fails with
// 503 and the client retries against the passing proxy.
package s3fault

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"
)

// Modes for a run's commit.
const (
	ModePass  = "pass"
	ModeHold  = "hold"
	ModeAfter = "after"
)

// State is what the proxy observed since it was last armed.
type State struct {
	Mode string `json:"mode"`
	Run  string `json:"run,omitempty"`
	// CommitArrivals counts the run's commit requests that reached the
	// proxy; CommitsHeld those held in hold mode or blackholed;
	// CommitsForwarded those sent to the backend.
	CommitArrivals   int `json:"commitArrivals"`
	CommitsHeld      int `json:"commitsHeld"`
	CommitsForwarded int `json:"commitsForwarded"`
	// LastCommitStatus is the backend status of the last forwarded commit.
	LastCommitStatus int `json:"lastCommitStatus"`
	// Blackhole holds every request until release; Blackholed counts them.
	Blackhole  bool `json:"blackhole"`
	Blackholed int  `json:"blackholed"`
	// Waiting is the number of requests blocked right now.
	Waiting int `json:"waiting"`
}

// Proxy forwards S3 requests to Backend (host:port, plain HTTP) and injects
// the armed fault.
type Proxy struct {
	Backend string
	// Logf, when set, records every injected fault and control action.
	Logf func(format string, args ...any)

	once     sync.Once
	rp       *httputil.ReverseProxy
	mu       sync.Mutex
	st       State
	released chan struct{}
	fired    bool
}

func (p *Proxy) init() {
	p.once.Do(func() {
		p.rp = &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = "http", p.Backend
			pr.Out.Host = pr.In.Host // signed by the client
		}}
		p.st.Mode = ModePass
		p.released = make(chan struct{})
	})
}

func (p *Proxy) logf(format string, args ...any) {
	if p.Logf != nil {
		p.Logf(format, args...)
	}
}

func (p *Proxy) isCommit(r *http.Request, run string) bool {
	return run != "" && r.Method == http.MethodPut && r.Header.Get("If-None-Match") == "*" &&
		strings.HasSuffix(r.URL.Path, "/"+run+"/commit.json")
}

// ServeHTTP is the S3 data path.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.init()
	p.mu.Lock()
	commit := p.isCommit(r, p.st.Run)
	if commit {
		p.st.CommitArrivals++
	}
	switch {
	case p.st.Blackhole:
		p.st.Blackholed++
		if commit {
			p.st.CommitsHeld++
		}
		p.logf("blackholed %s %s (commit %t)", r.Method, r.URL.Path, commit)
		p.block(w, r)
		return
	case commit && p.st.Mode == ModeHold:
		p.st.CommitsHeld++
		p.logf("held commit %s (arrival %d), not forwarded", r.URL.Path, p.st.CommitArrivals)
		p.block(w, r)
		return
	case commit && p.st.Mode == ModeAfter && !p.fired:
		p.fired = true
		p.mu.Unlock()
		status := p.forwardDiscarding(r)
		p.mu.Lock()
		p.st.CommitsForwarded++
		p.st.LastCommitStatus = status
		// The commit landed; nothing more reaches the backend, and its
		// response is never delivered.
		p.st.Blackhole = true
		p.logf("forwarded commit %s: backend status %d; response withheld, blackholing every request", r.URL.Path, status)
		p.block(w, r)
		return
	case commit:
		p.st.CommitsForwarded++
	}
	p.mu.Unlock()
	rec := &statusWriter{ResponseWriter: w}
	p.rp.ServeHTTP(rec, r)
	if commit {
		p.mu.Lock()
		p.st.LastCommitStatus = rec.status
		p.mu.Unlock()
	}
}

// block is called with p.mu held and releases it: the request waits until
// the client gives up or the fault is released, and is never forwarded.
func (p *Proxy) block(w http.ResponseWriter, r *http.Request) {
	released := p.released
	p.st.Waiting++
	p.mu.Unlock()
	select {
	case <-released:
	case <-r.Context().Done():
	}
	p.mu.Lock()
	p.st.Waiting--
	p.mu.Unlock()
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = io.WriteString(w, "<Error><Code>ServiceUnavailable</Code><Message>s3fault: request held and not forwarded</Message></Error>")
}

// forwardDiscarding sends r to the backend, independent of the client's
// cancellation, and returns the backend's status without relaying it.
func (p *Proxy) forwardDiscarding(r *http.Request) int {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 20*time.Second)
	defer cancel()
	out := r.Clone(ctx)
	out.RequestURI = ""
	out.URL.Scheme, out.URL.Host = "http", p.Backend
	out.Host = r.Host
	out.Header.Del("Connection")
	resp, err := http.DefaultTransport.RoundTrip(out)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// Arm resets the observations and sets a mode for one run's commit.
func (p *Proxy) Arm(mode, run string) {
	p.init()
	p.mu.Lock()
	defer p.mu.Unlock()
	close(p.released)
	p.released = make(chan struct{})
	p.st = State{Mode: mode, Run: run}
	p.fired = false
	p.logf("armed %s for run %s", mode, run)
}

// SetBlackhole holds every further request until Release.
func (p *Proxy) SetBlackhole() {
	p.init()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.st.Blackhole = true
	p.logf("blackholing every request")
}

// Release ends every fault: blocked requests fail with 503 and later ones
// pass. Observations and the armed run are kept.
func (p *Proxy) Release() {
	p.init()
	p.mu.Lock()
	defer p.mu.Unlock()
	close(p.released)
	p.released = make(chan struct{})
	p.st.Mode, p.st.Blackhole = ModePass, false
	p.logf("released: %d requests were blocked; passing", p.st.Waiting)
}

// Snapshot returns the current observations.
func (p *Proxy) Snapshot() State {
	p.init()
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.st
}

// Control serves the test's controls: GET /state, POST /arm?mode=&run=,
// POST /blackhole and POST /release.
func (p *Proxy) Control() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /state", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p.Snapshot())
	})
	mux.HandleFunc("POST /arm", func(w http.ResponseWriter, r *http.Request) {
		mode, run := r.URL.Query().Get("mode"), r.URL.Query().Get("run")
		if (mode != ModeHold && mode != ModeAfter && mode != ModePass) || (mode != ModePass && run == "") {
			http.Error(w, "mode must be pass, hold or after, with a run UID", http.StatusBadRequest)
			return
		}
		p.Arm(mode, run)
	})
	mux.HandleFunc("POST /blackhole", func(http.ResponseWriter, *http.Request) { p.SetBlackhole() })
	mux.HandleFunc("POST /release", func(http.ResponseWriter, *http.Request) { p.Release() })
	return mux
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Flush keeps streamed responses flowing through the reverse proxy.
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
