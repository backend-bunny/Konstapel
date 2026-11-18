package s3fault

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
)

// ErrLostResponse is what a client sees for a request whose response
// LostResponses discarded after the backend processed it.
var ErrLostResponse = errors.New("s3fault: response lost after the backend processed the request")

// HTTPDoer is the HTTP client interface of the S3 SDK (s3.HTTPClient).
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// LostResponses is a client-side fault for one in-process S3 client: it
// forwards every request to Inner, and once armed, a matching request still
// reaches the backend and takes effect there, but its response is discarded
// and the caller gets ErrLostResponse, as when a replica loses the
// connection or dies right after sending. Retries of a matching request
// lose their responses too. Unlike Proxy it needs no network hop, so a test
// can lose the response of any operation of one client while every other
// client of the same backend is unaffected.
type LostResponses struct {
	Inner HTTPDoer
	// Observe, when set, sees the backend status of every forwarded
	// request, including those whose response is then discarded.
	Observe func(r *http.Request, status int)

	mu    sync.Mutex
	match func(*http.Request) bool
	lost  int
}

// Arm makes every later request that match accepts lose its response.
func (l *LostResponses) Arm(match func(*http.Request) bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.match = match
}

// Lost reports how many responses were discarded.
func (l *LostResponses) Lost() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lost
}

// Do implements HTTPDoer.
func (l *LostResponses) Do(r *http.Request) (*http.Response, error) {
	l.mu.Lock()
	match := l.match
	l.mu.Unlock()
	resp, err := l.Inner.Do(r)
	if err != nil {
		return resp, err
	}
	if l.Observe != nil {
		l.Observe(r, resp.StatusCode)
	}
	if match == nil || !match(r) {
		return resp, nil
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	l.mu.Lock()
	l.lost++
	l.mu.Unlock()
	return nil, ErrLostResponse
}

// IsCommitWrite matches a write of a run's commit: PUT
// .../<run UID>/commit.json, conditional (If-None-Match: *) or not.
func IsCommitWrite(r *http.Request) bool {
	return r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/commit.json")
}

// IsAttemptRecord matches the upload that completes a staged attempt: PUT
// .../attempts/<id>/attempt.json. The archive is already stored and
// verified when it is sent.
func IsAttemptRecord(r *http.Request) bool {
	return r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/attempts/") && strings.HasSuffix(r.URL.Path, "/attempt.json")
}
