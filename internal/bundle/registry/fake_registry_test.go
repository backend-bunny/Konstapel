package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

const repoPath = "bundles/konstapel-privileged-containers"

var specsVersioned = specs.Versioned{SchemaVersion: 2}

var (
	officialOnce sync.Once
	officialArch *bundle.Archive
	officialErr  error
)

// official builds the checked-in privileged-container bundle once, so tests
// serve real manifest and layer bytes.
func official(t *testing.T) *bundle.Archive {
	t.Helper()
	officialOnce.Do(func() {
		root := "../../.."
		raw, err := os.ReadFile(filepath.Join(root, "bundles/konstapel-privileged-containers/definition.json"))
		if err != nil {
			officialErr = err
			return
		}
		def, err := bundle.LoadDefinition(raw)
		if err != nil {
			officialErr = err
			return
		}
		def.Source.Revision = strings.Repeat("c", 40)
		officialArch, officialErr = bundle.Build(def, os.DirFS(root), time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC))
	})
	if officialErr != nil {
		t.Fatal(officialErr)
	}
	return officialArch
}

type manifestEntry struct {
	mediaType string
	body      []byte
}

// fakeRegistry is an in-process OCI distribution registry: manifests and
// blobs by digest, tags, and the OCI 1.1 referrers API. Behaviour can be
// overridden per test with hook.
type fakeRegistry struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	manifests map[string]manifestEntry
	blobs     map[string][]byte
	tags      map[string]string
	referrers map[string][]ocispec.Descriptor
	requests  []string
	// hook runs first; returning true means it wrote the response.
	hook func(w http.ResponseWriter, r *http.Request) bool
	// basic, when set, requires these Basic credentials on /v2/ requests.
	basicUser, basicPass string
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	f := &fakeRegistry{
		t: t, manifests: map[string]manifestEntry{}, blobs: map[string][]byte{},
		tags: map[string]string{}, referrers: map[string][]ocispec.Descriptor{},
	}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRegistry) host() string { return strings.TrimPrefix(f.srv.URL, "http://") }

func (f *fakeRegistry) source() bundle.BundleSource {
	return bundle.BundleSource{Name: "konstapel-privileged-containers", Repository: f.host() + "/" + repoPath}
}

func (f *fakeRegistry) setHook(h func(w http.ResponseWriter, r *http.Request) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook = h
}

func (f *fakeRegistry) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func (f *fakeRegistry) count(substr string) int {
	n := 0
	for _, r := range f.log() {
		if strings.Contains(r, substr) {
			n++
		}
	}
	return n
}

func (f *fakeRegistry) putBlob(b []byte) digest.Digest {
	d := digest.FromBytes(b)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blobs[d.String()] = b
	return d
}

func (f *fakeRegistry) putManifest(mediaType string, body []byte) digest.Digest {
	d := digest.FromBytes(body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.manifests[d.String()] = manifestEntry{mediaType, body}
	return d
}

func (f *fakeRegistry) publish(a *bundle.Archive) digest.Digest {
	f.putBlob(a.Layer)
	f.putBlob([]byte("{}"))
	return f.putManifest(ocispec.MediaTypeImageManifest, a.Manifest)
}

// cosignReferrer builds a referrer in the layout `cosign sign` / `cosign
// attest` v3.1.3 write: an OCI manifest with the Sigstore bundle artifact
// type, an empty config, one bundle layer, the subject, and the
// predicate-type annotation.
func cosignReferrer(subject digest.Digest, subjectSize int64, predicateType string, bundleJSON []byte) []byte {
	m := map[string]any{
		"schemaVersion": 2,
		"mediaType":     ocispec.MediaTypeImageManifest,
		"artifactType":  SigstoreBundleArtifactType,
		"config": map[string]any{
			"mediaType": "application/vnd.oci.empty.v1+json", "artifactType": SigstoreBundleArtifactType,
			"digest": bundle.EmptyConfigDigest, "size": 2,
		},
		"layers": []any{map[string]any{
			"mediaType": SigstoreBundleArtifactType, "digest": digest.FromBytes(bundleJSON).String(), "size": len(bundleJSON),
		}},
		"subject": map[string]any{
			"mediaType": ocispec.MediaTypeImageManifest, "digest": subject.String(), "size": subjectSize,
		},
		"annotations": map[string]string{
			"org.opencontainers.image.created": "2026-11-10T08:00:00Z",
			"dev.sigstore.bundle.content":      "dsse-envelope",
			PredicateTypeAnnotation:            predicateType,
		},
	}
	raw, _ := json.Marshal(m)
	return raw
}

func sigstoreBundle(tag string) []byte {
	return []byte(fmt.Sprintf(`{"mediaType":%q,"dsseEnvelope":{"payloadType":"application/vnd.in-toto+json","payload":%q}}`,
		SigstoreBundleArtifactType, tag))
}

// attach stores a cosign-shaped referrer for listed (the referrers index it
// appears under) whose manifest names subject. It returns the referrer digest.
func (f *fakeRegistry) attach(listed, subject digest.Digest, subjectSize int64, predicateType string) digest.Digest {
	b := sigstoreBundle(predicateType + "/" + subject.String())
	f.putBlob(b)
	raw := cosignReferrer(subject, subjectSize, predicateType, b)
	d := f.putManifest(ocispec.MediaTypeImageManifest, raw)
	f.list(listed, ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest, Digest: d, Size: int64(len(raw)),
		ArtifactType: SigstoreBundleArtifactType,
		Annotations:  map[string]string{PredicateTypeAnnotation: predicateType},
	})
	return d
}

func (f *fakeRegistry) list(subject digest.Digest, desc ocispec.Descriptor) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.referrers[subject.String()] = append(f.referrers[subject.String()], desc)
}

// publishSigned publishes the official bundle with a signature and a
// provenance attestation and returns its digest.
func (f *fakeRegistry) publishSigned(t *testing.T) digest.Digest {
	a := official(t)
	d := f.publish(a)
	f.attach(d, d, int64(len(a.Manifest)), CosignSignPredicateType)
	f.attach(d, d, int64(len(a.Manifest)), SLSAProvenanceV1PredicateType)
	return d
}

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	hook, user, pass := f.hook, f.basicUser, f.basicPass
	f.mu.Unlock()
	if hook != nil && hook(w, r) {
		return
	}
	if user != "" {
		if u, p, ok := r.BasicAuth(); !ok || u != user || p != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="fake"`)
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
			return
		}
	}
	if r.URL.Path == "/v2/" {
		return
	}
	prefix := "/v2/" + repoPath + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		writeError(w, http.StatusNotFound, "NAME_UNKNOWN", "repository unknown")
		return
	}
	kind, ref, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, prefix), "/")
	f.mu.Lock()
	defer f.mu.Unlock()
	switch kind {
	case "manifests":
		if d, ok := f.tags[ref]; ok {
			ref = d
		}
		m, ok := f.manifests[ref]
		if !ok {
			writeError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest unknown")
			return
		}
		w.Header().Set("Content-Type", m.mediaType)
		w.Header().Set("Docker-Content-Digest", digest.FromBytes(m.body).String())
		w.Header().Set("Content-Length", fmt.Sprint(len(m.body)))
		if r.Method == http.MethodGet {
			w.Write(m.body)
		}
	case "blobs":
		b, ok := f.blobs[ref]
		if !ok {
			writeError(w, http.StatusNotFound, "BLOB_UNKNOWN", "blob unknown")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		w.Write(b)
	case "referrers":
		descs := f.referrers[ref]
		if descs == nil {
			descs = []ocispec.Descriptor{}
		}
		body, _ := json.Marshal(ocispec.Index{
			Versioned: specsVersioned, MediaType: ocispec.MediaTypeImageIndex, Manifests: descs,
		})
		w.Header().Set("Content-Type", ocispec.MediaTypeImageIndex)
		w.Write(body)
	default:
		writeError(w, http.StatusNotFound, "NAME_UNKNOWN", "unknown endpoint")
	}
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"errors": []any{map[string]string{"code": code, "message": msg}}})
}

// writeChunked sends body without a Content-Length, so the client cannot
// rely on the header and must bound its own reads.
func writeChunked(w http.ResponseWriter, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	w.Write(body)
}
