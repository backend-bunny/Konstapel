package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

func newTestClient(t *testing.T, f *fakeRegistry, limits Limits, creds CredentialProvider) *Client {
	t.Helper()
	c, err := NewClient(Options{
		Transport: f.srv.Client().Transport, Credentials: creds, Limits: limits, TestOnlyPlainHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func fetch(t *testing.T, f *fakeRegistry, limits Limits, d digest.Digest) (*Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return newTestClient(t, f, limits, nil).Fetch(ctx, f.source(), d.String())
}

// noTagRequests fails if any manifest was requested by something other than
// a digest: retrieval must never resolve a tag.
func noTagRequests(t *testing.T, f *fakeRegistry) {
	t.Helper()
	for _, r := range f.log() {
		if _, ref, ok := strings.Cut(r, "/manifests/"); ok && !strings.HasPrefix(ref, "sha256:") {
			t.Errorf("tag requested: %s", r)
		}
		if strings.Contains(r, "sha256-") {
			t.Errorf("legacy referrers tag requested: %s", r)
		}
	}
}

func TestFetchSuccess(t *testing.T) {
	f := newFakeRegistry(t)
	d := f.publishSigned(t)
	f.list(d, ocispec.Descriptor{ // an SBOM-style referrer is listed but unrelated
		MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("sbom"), Size: 10,
		ArtifactType: "application/spdx+json",
	})
	res, err := fetch(t, f, Limits{}, d)
	if err != nil {
		t.Fatal(err)
	}
	a := official(t)
	if res.Digest != d.String() || !bytes.Equal(res.Manifest, a.Manifest) || !bytes.Equal(res.Layer, a.Layer) || res.LayerDigest != a.LayerDigest {
		t.Fatal("result does not carry the published bytes")
	}
	if _, _, err := bundle.Unpack(res.Layer); err != nil {
		t.Fatalf("retrieved layer does not unpack: %v", err)
	}
	if res.ReferrerCount != 3 || len(res.Proofs) != 2 || len(res.Skipped) != 1 || res.Skipped[0].Reason != "unrelated artifact type" {
		t.Fatalf("proofs %+v skipped %+v count %d", res.Proofs, res.Skipped, res.ReferrerCount)
	}
	for _, p := range res.Proofs {
		if digest.FromBytes(p.Manifest).String() != p.ManifestDigest || digest.FromBytes(p.Bundle).String() != p.BundleDigest ||
			p.BundleMediaType != SigstoreBundleArtifactType {
			t.Errorf("proof %+v is inconsistent", p.Kind)
		}
	}
	if err := res.RequireProofs(RequiredProofs...); err != nil {
		t.Fatal(err)
	}
	if res.MetadataBytes <= 0 || res.MetadataBytes > DefaultLimits().MaxMetadataBytes {
		t.Fatalf("metadata bytes %d", res.MetadataBytes)
	}
	if n := f.count("/manifests/" + d.String()); n != 1 {
		t.Fatalf("subject manifest fetched %d times", n)
	}
	if f.count("/blobs/"+bundle.EmptyConfigDigest) != 0 {
		t.Fatal("the empty config needs no download")
	}
	noTagRequests(t, f)
}

func TestMovedTagHasNoEffect(t *testing.T) {
	f := newFakeRegistry(t)
	d := f.publishSigned(t)
	other := f.putManifest(ocispec.MediaTypeImageManifest, []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`))
	f.mu.Lock()
	f.tags["latest"], f.tags["1.0.0"], f.tags[d.Encoded()] = other.String(), other.String(), other.String()
	f.mu.Unlock()
	res, err := fetch(t, f, Limits{}, d)
	if err != nil {
		t.Fatal(err)
	}
	if res.Digest != d.String() || digest.FromBytes(res.Manifest) != d {
		t.Fatal("a moved tag changed the selected manifest")
	}
	noTagRequests(t, f)
}

func TestExactSubjectSelection(t *testing.T) {
	f := newFakeRegistry(t)
	a := official(t)
	d := f.publish(a)
	other := digest.FromString("another bundle manifest")
	size := int64(len(a.Manifest))
	// Listed under the pinned digest but naming another subject, or the right
	// digest with the wrong size: never used.
	wrongSubject := f.attach(d, other, size, CosignSignPredicateType)
	wrongSize := f.attach(d, d, size+1, CosignSignPredicateType)
	f.attach(d, d, size, SLSAProvenanceV1PredicateType)
	// A proof for another subject listed under that subject is never seen.
	f.attach(other, other, 10, CosignSignPredicateType)

	res, err := fetch(t, f, Limits{}, d)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Proofs) != 1 || res.Proofs[0].Kind != ProofProvenance {
		t.Fatalf("proofs %+v", res.Proofs)
	}
	reasons := map[string]string{}
	for _, s := range res.Skipped {
		reasons[s.Digest] = s.Reason
	}
	if !strings.Contains(reasons[wrongSubject.String()], "is not the pinned manifest") ||
		!strings.Contains(reasons[wrongSize.String()], "subject size") {
		t.Fatalf("skipped %+v", res.Skipped)
	}
	if got := res.Missing(RequiredProofs...); !slices.Equal(got, []ProofKind{ProofSignature}) {
		t.Fatalf("missing %v", got)
	}
	if f.count("/blobs/") != 2 { // the provenance layer and the bundle layer only
		t.Fatalf("unexpected blob downloads: %v", f.log())
	}
}

func TestMissingProofs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		attach  []string
		missing []ProofKind
	}{
		{"none", nil, []ProofKind{ProofSignature, ProofProvenance}},
		{"signature only", []string{CosignSignPredicateType}, []ProofKind{ProofProvenance}},
		{"provenance only", []string{SLSAProvenanceV1PredicateType}, []ProofKind{ProofSignature}},
		{"other predicates", []string{"https://slsa.dev/provenance/v0.2", "https://spdx.dev/Document"}, []ProofKind{ProofSignature, ProofProvenance}},
		{"both", []string{CosignSignPredicateType, SLSAProvenanceV1PredicateType}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRegistry(t)
			a := official(t)
			d := f.publish(a)
			for _, p := range tc.attach {
				f.attach(d, d, int64(len(a.Manifest)), p)
			}
			res, err := fetch(t, f, Limits{}, d)
			if err != nil {
				t.Fatal(err)
			}
			if got := res.Missing(RequiredProofs...); !slices.Equal(got, tc.missing) {
				t.Fatalf("missing %v, want %v", got, tc.missing)
			}
			err = res.RequireProofs(RequiredProofs...)
			if len(tc.missing) == 0 {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var mp *MissingProofsError
			if !errors.Is(err, ErrMissingProofs) || !errors.As(err, &mp) || !slices.Equal(mp.Missing, tc.missing) {
				t.Fatalf("err %v", err)
			}
			for _, k := range tc.missing {
				if !strings.Contains(err.Error(), string(k)) {
					t.Errorf("%q does not name %s", err, k)
				}
			}
		})
	}
}

func manifestJSON(t *testing.T, mutate func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(official(t).Manifest, &m); err != nil {
		t.Fatal(err)
	}
	mutate(m)
	raw, _ := json.Marshal(m)
	return raw
}

func TestUnexpectedSubject(t *testing.T) {
	index := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	for _, tc := range []struct {
		name      string
		mediaType string
		body      func(t *testing.T) []byte
	}{
		{"index", ocispec.MediaTypeImageIndex, func(*testing.T) []byte { return index }},
		{"index served as a manifest", ocispec.MediaTypeImageManifest, func(*testing.T) []byte { return index }},
		{"docker manifest", "application/vnd.docker.distribution.manifest.v2+json", func(t *testing.T) []byte { return official(t).Manifest }},
		{"wrong artifact type", ocispec.MediaTypeImageManifest, func(t *testing.T) []byte {
			return manifestJSON(t, func(m map[string]any) { m["artifactType"] = "application/vnd.example+json" })
		}},
		{"two layers", ocispec.MediaTypeImageManifest, func(t *testing.T) []byte {
			return manifestJSON(t, func(m map[string]any) { m["layers"] = append(m["layers"].([]any), m["layers"].([]any)[0]) })
		}},
		{"wrong layer media type", ocispec.MediaTypeImageManifest, func(t *testing.T) []byte {
			return manifestJSON(t, func(m map[string]any) {
				m["layers"].([]any)[0].(map[string]any)["mediaType"] = "application/vnd.oci.image.layer.v1.tar"
			})
		}},
		{"non-empty config", ocispec.MediaTypeImageManifest, func(t *testing.T) []byte {
			return manifestJSON(t, func(m map[string]any) { m["config"].(map[string]any)["size"] = 3 })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRegistry(t)
			f.putBlob(official(t).Layer)
			d := f.putManifest(tc.mediaType, tc.body(t))
			_, err := fetch(t, f, Limits{}, d)
			if !errors.Is(err, ErrUnexpectedDescriptor) || Classify(err) != ClassPermanent {
				t.Fatalf("err %v", err)
			}
			if f.count("/blobs/") != 0 || f.count("/referrers/") != 0 {
				t.Fatalf("continued after rejecting the subject: %v", f.log())
			}
		})
	}
}

func TestIntegrity(t *testing.T) {
	a := official(t)
	tampered := bytes.Clone(a.Layer)
	tampered[len(tampered)/2] ^= 0xff
	for _, tc := range []struct {
		name string
		hook func(f *fakeRegistry, d digest.Digest) func(w http.ResponseWriter, r *http.Request) bool
	}{
		{"manifest bytes differ, header claims the digest", func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			other := manifestJSON(t, func(m map[string]any) { m["annotations"] = map[string]string{"x": "y"} })
			return func(w http.ResponseWriter, r *http.Request) bool {
				if !strings.HasSuffix(r.URL.Path, "/manifests/"+d.String()) {
					return false
				}
				w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
				w.Header().Set("Docker-Content-Digest", d.String())
				w.Write(other)
				return true
			}
		}},
		{"manifest bytes differ, chunked", func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			other := manifestJSON(t, func(m map[string]any) { m["annotations"] = map[string]string{"x": "y"} })
			return func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/manifests/"+d.String()) {
					return false
				}
				writeChunked(w, ocispec.MediaTypeImageManifest, other)
				return true
			}
		}},
		{"layer tampered", func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			return serveBlob(digest.Digest(a.LayerDigest), tampered, false)
		}},
		{"layer longer than its descriptor", func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			return serveBlob(digest.Digest(a.LayerDigest), append(bytes.Clone(a.Layer), make([]byte, 1<<20)...), true)
		}},
		{"layer truncated", func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			return serveBlob(digest.Digest(a.LayerDigest), a.Layer[:len(a.Layer)-1], true)
		}},
		{"referrer manifest longer than its descriptor", func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			ref := f.attach(d, d, int64(len(a.Manifest)), CosignSignPredicateType)
			body := append(bytes.Clone(f.manifests[ref.String()].body), ' ')
			return func(w http.ResponseWriter, r *http.Request) bool {
				if !strings.HasSuffix(r.URL.Path, "/manifests/"+ref.String()) {
					return false
				}
				writeChunked(w, ocispec.MediaTypeImageManifest, body)
				return true
			}
		}},
		{"proof layer tampered", func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			f.attach(d, d, int64(len(a.Manifest)), CosignSignPredicateType)
			b := sigstoreBundle(CosignSignPredicateType + "/" + d.String())
			bad := bytes.Clone(b)
			bad[0] = '['
			return serveBlob(digest.FromBytes(b), bad, false)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRegistry(t)
			d := f.publish(a)
			f.setHook(tc.hook(f, d))
			_, err := fetch(t, f, Limits{}, d)
			if !errors.Is(err, ErrIntegrity) || Classify(err) != ClassPermanent {
				t.Fatalf("err %v", err)
			}
		})
	}
}

// serveBlob serves body for want, optionally without a Content-Length.
func serveBlob(want digest.Digest, body []byte, chunked bool) func(http.ResponseWriter, *http.Request) bool {
	return func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasSuffix(r.URL.Path, "/blobs/"+want.String()) {
			return false
		}
		if chunked {
			writeChunked(w, "application/octet-stream", body)
			return true
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Write(body)
		return true
	}
}

func TestLimits(t *testing.T) {
	a := official(t)
	size := int64(len(a.Manifest))
	for _, tc := range []struct {
		name   string
		limits Limits
		setup  func(f *fakeRegistry, d digest.Digest)
		check  func(t *testing.T, f *fakeRegistry)
	}{
		{name: "manifest over limit", limits: Limits{MaxManifestBytes: size - 1}},
		{name: "payload over limit", limits: Limits{MaxPayloadBytes: int64(len(a.Layer)) - 1},
			check: func(t *testing.T, f *fakeRegistry) {
				if f.count("/blobs/"+a.LayerDigest) != 0 {
					t.Error("an oversized layer was downloaded")
				}
			}},
		{name: "referrer count over limit", limits: Limits{MaxReferrers: 2}, setup: func(f *fakeRegistry, d digest.Digest) {
			for range 3 {
				f.list(d, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("x"), Size: 1, ArtifactType: "application/x"})
			}
		}},
		{name: "proofs over metadata limit", limits: Limits{MaxMetadataBytes: 3000}, setup: func(f *fakeRegistry, d digest.Digest) {
			for range 4 {
				f.attach(d, d, size, CosignSignPredicateType)
				f.attach(d, d, size, SLSAProvenanceV1PredicateType)
			}
		}},
		{name: "listing over metadata limit", limits: Limits{MaxMetadataBytes: 4096}, setup: func(f *fakeRegistry, d digest.Digest) {
			for i := range 40 {
				f.list(d, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString(fmt.Sprint(i)), Size: 1, ArtifactType: "application/x"})
			}
		}},
		{name: "referrer descriptor larger than remaining metadata", limits: Limits{MaxMetadataBytes: 1 << 10}, setup: func(f *fakeRegistry, d digest.Digest) {
			f.list(d, ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("big"), Size: 1 << 30, ArtifactType: SigstoreBundleArtifactType})
		}, check: func(t *testing.T, f *fakeRegistry) {
			if f.count("/manifests/"+digest.FromString("big").String()) != 0 {
				t.Error("an oversized referrer was downloaded")
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRegistry(t)
			d := f.publish(a)
			if tc.setup != nil {
				tc.setup(f, d)
			}
			_, err := fetch(t, f, tc.limits, d)
			if !errors.Is(err, ErrLimitExceeded) || Classify(err) != ClassPermanent {
				t.Fatalf("err %v", err)
			}
			if tc.check != nil {
				tc.check(t, f)
			}
		})
	}
}

func TestReferrersUnsupported(t *testing.T) {
	for _, tc := range []struct {
		name  string
		serve func(w http.ResponseWriter)
	}{
		{"404 without a body", func(w http.ResponseWriter) { w.WriteHeader(http.StatusNotFound) }},
		{"404 with a non-repository error", func(w http.ResponseWriter) { writeError(w, http.StatusNotFound, "UNSUPPORTED", "nope") }},
		{"501", func(w http.ResponseWriter) { writeError(w, http.StatusNotImplemented, "UNSUPPORTED", "nope") }},
		{"405", func(w http.ResponseWriter) { w.WriteHeader(http.StatusMethodNotAllowed) }},
		{"not an index", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html></html>"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRegistry(t)
			d := f.publishSigned(t)
			f.setHook(func(w http.ResponseWriter, r *http.Request) bool {
				if !strings.Contains(r.URL.Path, "/referrers/") {
					return false
				}
				tc.serve(w)
				return true
			})
			_, err := fetch(t, f, Limits{}, d)
			if !errors.Is(err, ErrReferrersUnsupported) || Classify(err) != ClassPermanent {
				t.Fatalf("err %v", err)
			}
			if !strings.Contains(err.Error(), "referrers API") {
				t.Fatalf("unclear error %q", err)
			}
			noTagRequests(t, f)
		})
	}
}

func TestRegistryErrorsAreClassified(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusForbidden, ErrUnauthorized},
		{http.StatusNotFound, ErrNotFound},
		{http.StatusTooManyRequests, ErrUnavailable},
		{http.StatusServiceUnavailable, ErrUnavailable},
	} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			f := newFakeRegistry(t)
			d := f.publishSigned(t)
			f.setHook(func(w http.ResponseWriter, r *http.Request) bool {
				if !strings.Contains(r.URL.Path, "/blobs/") {
					return false
				}
				writeError(w, tc.status, "DENIED", "no")
				return true
			})
			_, err := fetch(t, f, Limits{}, d)
			if !errors.Is(err, tc.want) || Classify(err) != ClassRetryable {
				t.Fatalf("err %v", err)
			}
		})
	}
}

func TestInvalidRequests(t *testing.T) {
	f := newFakeRegistry(t)
	c := newTestClient(t, f, Limits{}, nil)
	good := digest.FromString("x").String()
	for _, tc := range []struct{ repo, digest string }{
		{f.host() + "/" + repoPath, "sha256:abc"},
		{f.host() + "/" + repoPath, strings.ToUpper(good)},
		{f.host() + "/" + repoPath, "sha512:" + strings.Repeat("a", 128)},
		{f.host() + "/" + repoPath, "latest"},
		{f.host() + "/" + repoPath + ":latest", good},
		{"https://" + f.host() + "/" + repoPath, good},
	} {
		_, err := c.Fetch(context.Background(), bundle.BundleSource{Name: "n", Repository: tc.repo}, tc.digest)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s@%s: %v", tc.repo, tc.digest, err)
		}
	}
	if len(f.log()) != 0 {
		t.Fatalf("invalid requests reached the registry: %v", f.log())
	}
	if _, err := NewClient(Options{Limits: Limits{MaxReferrers: -1}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal(err)
	}
	if _, err := NewClient(Options{Limits: Limits{Retry: RetryPolicy{Min: time.Hour, Max: time.Minute}}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal(err)
	}
}
