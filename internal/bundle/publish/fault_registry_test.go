package publish

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const testRepoPath = "bundles/konstapel-privileged-containers"

// request is one request the fake registry received.
type request struct {
	Method, Path, Query string
	Auth                bool
}

func (r request) String() string { return r.Method + " " + r.Path }

type stored struct {
	mediaType string
	body      []byte
}

// faultRegistry is an in-process OCI distribution registry with fault
// injection: blobs (monolithic POST+PUT uploads), manifests by digest and
// tag, and either the OCI 1.1 referrers API or (tagSchema) none, in which
// case clients maintain the sha256-<hex> referrers index tag themselves.
// Writes require Basic credentials; reads are anonymous unless private.
//
// It records every request and every event that would replace or remove
// content, and by default fails the test if any happened.
type faultRegistry struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string]stored
	tags      map[string]string
	requests  []request
	// events that must never happen: deletes, re-uploads of existing blobs,
	// re-pushes of existing manifests, tag moves (except the referrers tag
	// schema index, which clients maintain).
	violations []string
	// relists counts identical manifest re-pushes (allowed only when a test
	// expects a listing repair).
	relists     int
	indexMoves  int
	user, pass  string
	private     bool
	tagSchema   bool
	allowRelist bool
	uploads     atomic.Int64
	// hook runs before normal handling; returning true means it answered.
	hook func(w http.ResponseWriter, r *http.Request, n int) bool
	n    int
}

func newFaultRegistry(t *testing.T, tagSchema bool) *faultRegistry {
	t.Helper()
	f := &faultRegistry{
		t: t, blobs: map[string][]byte{}, manifests: map[string]stored{}, tags: map[string]string{},
		user: "publisher", pass: "pw-" + strings.Repeat("s3cr3t", 3), tagSchema: tagSchema,
	}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	t.Cleanup(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, v := range f.violations {
			t.Errorf("registry content was replaced or removed: %s", v)
		}
		if f.relists > 0 && !f.allowRelist {
			t.Errorf("%d existing manifests were pushed again", f.relists)
		}
	})
	return f
}

func (f *faultRegistry) host() string { return strings.TrimPrefix(f.srv.URL, "http://") }
func (f *faultRegistry) repo() string { return f.host() + "/" + testRepoPath }

func (f *faultRegistry) setHook(h func(w http.ResponseWriter, r *http.Request, n int) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook = h
}

func (f *faultRegistry) log() []request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]request(nil), f.requests...)
}

// writes returns the mutating requests received since index from.
func (f *faultRegistry) writes(from int) []request {
	var out []request
	for _, r := range f.log()[from:] {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			out = append(out, r)
		}
	}
	return out
}

// snapshot copies the stored state for before/after comparisons.
func (f *faultRegistry) snapshot() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"blobs": f.blobs, "manifests": len(f.manifests), "tags": f.tags})
	keys := []string{}
	for k := range f.manifests {
		keys = append(keys, k)
	}
	return string(b) + fmt.Sprint(len(keys))
}

func (f *faultRegistry) tag(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tags[name]
}

func (f *faultRegistry) manifest(d string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.manifests[d].body
}

// seedBlob and seedManifest store content directly, as another client would.
func (f *faultRegistry) seedBlob(b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blobs[digest.FromBytes(b).String()] = b
}

func (f *faultRegistry) seedManifest(b []byte, tag string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := digest.FromBytes(b).String()
	f.manifests[d] = stored{ocispec.MediaTypeImageManifest, b}
	if tag != "" {
		f.tags[tag] = d
	}
	return d
}

// setTag moves a tag directly, as an out-of-band writer would; it is not a
// violation by the code under test.
func (f *faultRegistry) setTag(tag, d string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tags[tag] = d
}

func (f *faultRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, _, hasAuth := r.BasicAuth()
	f.mu.Lock()
	f.requests = append(f.requests, request{r.Method, r.URL.Path, r.URL.RawQuery, hasAuth})
	f.n++
	hook, n := f.hook, f.n
	f.mu.Unlock()
	if hook != nil && hook(w, r, n) {
		return
	}
	write := r.Method != http.MethodGet && r.Method != http.MethodHead
	if write || f.private || hasAuth {
		if u, p, ok := r.BasicAuth(); !ok || u != f.user || p != f.pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="fault"`)
			writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
			return
		}
	}
	if r.URL.Path == "/v2/" {
		return
	}
	prefix := "/v2/" + testRepoPath + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		writeErr(w, http.StatusNotFound, "NAME_UNKNOWN", "repository unknown")
		return
	}
	kind, ref, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, prefix), "/")
	switch {
	case r.Method == http.MethodDelete:
		f.mu.Lock()
		f.violations = append(f.violations, "DELETE "+r.URL.Path)
		f.mu.Unlock()
		w.WriteHeader(http.StatusMethodNotAllowed)
	case kind == "blobs" && ref == "uploads/" && r.Method == http.MethodPost:
		w.Header().Set("Location", prefix+"blobs/uploads/"+fmt.Sprint(f.uploads.Add(1)))
		w.WriteHeader(http.StatusAccepted)
	case kind == "blobs" && strings.HasPrefix(ref, "uploads/") && r.Method == http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		want := r.URL.Query().Get("digest")
		if digest.FromBytes(body).String() != want {
			writeErr(w, http.StatusBadRequest, "DIGEST_INVALID", "digest mismatch")
			return
		}
		f.mu.Lock()
		if _, ok := f.blobs[want]; ok {
			f.violations = append(f.violations, "blob uploaded again: "+want)
		}
		f.blobs[want] = body
		f.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", want)
		w.Header().Set("Location", prefix+"blobs/"+want)
		w.WriteHeader(http.StatusCreated)
	case kind == "blobs":
		f.mu.Lock()
		b, ok := f.blobs[ref]
		f.mu.Unlock()
		if !ok {
			writeErr(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob unknown")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Docker-Content-Digest", ref)
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		if r.Method == http.MethodGet {
			w.Write(b)
		}
	case kind == "manifests" && r.Method == http.MethodPut:
		f.putManifest(w, r, ref)
	case kind == "manifests":
		f.mu.Lock()
		d := ref
		if t, ok := f.tags[ref]; ok {
			d = t
		}
		m, ok := f.manifests[d]
		f.mu.Unlock()
		if !ok {
			writeErr(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest unknown")
			return
		}
		w.Header().Set("Content-Type", m.mediaType)
		w.Header().Set("Docker-Content-Digest", d)
		w.Header().Set("Content-Length", fmt.Sprint(len(m.body)))
		if r.Method == http.MethodGet {
			w.Write(m.body)
		}
	case kind == "referrers" && f.tagSchema:
		w.WriteHeader(http.StatusNotFound)
	case kind == "referrers":
		f.serveReferrers(w, r, ref)
	default:
		writeErr(w, http.StatusNotFound, "NAME_UNKNOWN", "unknown endpoint")
	}
}

func (f *faultRegistry) putManifest(w http.ResponseWriter, r *http.Request, ref string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	d := digest.FromBytes(body).String()
	if strings.HasPrefix(ref, "sha256:") && ref != d {
		writeErr(w, http.StatusBadRequest, "DIGEST_INVALID", "digest mismatch")
		return
	}
	var m struct {
		Subject *ocispec.Descriptor `json:"subject"`
	}
	_ = json.Unmarshal(body, &m)
	f.mu.Lock()
	if old, ok := f.manifests[d]; ok && string(old.body) == string(body) && ref == d {
		f.relists++
	}
	if !strings.HasPrefix(ref, "sha256:") {
		if old, ok := f.tags[ref]; ok && old != d {
			if strings.HasPrefix(ref, "sha256-") {
				f.indexMoves++
			} else {
				f.violations = append(f.violations, fmt.Sprintf("tag %s moved from %s to %s", ref, old, d))
			}
		}
		f.tags[ref] = d
	}
	f.manifests[d] = stored{r.Header.Get("Content-Type"), body}
	f.mu.Unlock()
	if m.Subject != nil && !f.tagSchema {
		w.Header().Set("OCI-Subject", m.Subject.Digest.String())
	}
	w.Header().Set("Docker-Content-Digest", d)
	w.WriteHeader(http.StatusCreated)
}

// serveReferrers derives the listing from stored manifests, as a registry
// with the referrers API does.
func (f *faultRegistry) serveReferrers(w http.ResponseWriter, r *http.Request, subject string) {
	f.mu.Lock()
	descs := []ocispec.Descriptor{}
	for d, s := range f.manifests {
		var m struct {
			ArtifactType string              `json:"artifactType"`
			Subject      *ocispec.Descriptor `json:"subject"`
		}
		if json.Unmarshal(s.body, &m) == nil && m.Subject != nil && m.Subject.Digest.String() == subject {
			descs = append(descs, ocispec.Descriptor{MediaType: s.mediaType, Digest: digest.Digest(d), Size: int64(len(s.body)), ArtifactType: m.ArtifactType})
		}
	}
	f.mu.Unlock()
	body, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": ocispec.MediaTypeImageIndex, "manifests": descs})
	w.Header().Set("Content-Type", ocispec.MediaTypeImageIndex)
	w.Write(body)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"errors": []any{map[string]string{"code": code, "message": msg}}})
}

// isTagPut reports a PUT of the version tag (not a digest or referrers tag).
func isTagPut(r *http.Request, tag string) bool {
	return r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/manifests/"+tag)
}

func isTagGet(r *http.Request, tag string) bool {
	return r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/manifests/"+tag)
}
