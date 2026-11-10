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
	"sync/atomic"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// sbomReferrer lists an unrelated, SBOM-style referrer under subject.
func (f *fakeRegistry) sbomReferrer(subject digest.Digest) {
	f.list(subject, ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("sbom"), Size: 10,
		ArtifactType: "application/spdx+json",
	})
}

func referrersTagPath(d digest.Digest) string { return "/manifests/sha256-" + d.Encoded() }

func TestReferrersListingSource(t *testing.T) {
	onAPI := func(serve func(w http.ResponseWriter)) func(w http.ResponseWriter, r *http.Request) bool {
		return func(w http.ResponseWriter, r *http.Request) bool {
			if !strings.Contains(r.URL.Path, "/referrers/") {
				return false
			}
			serve(w)
			return true
		}
	}
	for _, tc := range []struct {
		name           string
		noAPI, tagIdx  bool
		attach         bool
		hook           func(w http.ResponseWriter, r *http.Request) bool
		want           ReferrersSource
		proofs, listed int
	}{
		{name: "api preferred when both exist", tagIdx: true, attach: true, want: ReferrersFromAPI, proofs: 2, listed: 3},
		{name: "api without referrers", want: ReferrersFromAPI},
		{name: "api 404 without a body, tag index used", noAPI: true, tagIdx: true, attach: true, want: ReferrersFromTagSchema, proofs: 2, listed: 3},
		{name: "api 404 MANIFEST_UNKNOWN (ghcr.io), tag index used", tagIdx: true, attach: true, want: ReferrersFromTagSchema, proofs: 2, listed: 3,
			hook: onAPI(func(w http.ResponseWriter) {
				writeError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "manifest unknown")
			})},
		{name: "api 405, tag index used", tagIdx: true, attach: true, want: ReferrersFromTagSchema, proofs: 2, listed: 3,
			hook: onAPI(func(w http.ResponseWriter) { w.WriteHeader(http.StatusMethodNotAllowed) })},
		{name: "api 501, tag index used", tagIdx: true, attach: true, want: ReferrersFromTagSchema, proofs: 2, listed: 3,
			hook: onAPI(func(w http.ResponseWriter) { writeError(w, http.StatusNotImplemented, "UNSUPPORTED", "nope") })},
		{name: "api answers with a non-index, tag index used", tagIdx: true, attach: true, want: ReferrersFromTagSchema, proofs: 2, listed: 3,
			hook: onAPI(func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte("<html></html>"))
			})},
		{name: "neither api nor tag", noAPI: true, attach: true, want: ReferrersNone},
		{name: "tag schema without a tag for the subject", noAPI: true, tagIdx: true, want: ReferrersNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRegistry(t)
			a := official(t)
			d := f.publish(a)
			if tc.attach {
				f.attach(d, d, int64(len(a.Manifest)), CosignSignPredicateType)
				f.attach(d, d, int64(len(a.Manifest)), SLSAProvenanceV1PredicateType)
				f.sbomReferrer(d)
			}
			f.noAPI, f.tagSchema = tc.noAPI, tc.tagIdx
			if tc.hook != nil {
				f.setHook(tc.hook)
			}
			res, err := fetch(t, f, Limits{}, d)
			if err != nil {
				t.Fatal(err)
			}
			if res.ReferrersSource != tc.want || len(res.Proofs) != tc.proofs || res.ReferrerCount != tc.listed {
				t.Fatalf("source %q proofs %d listed %d", res.ReferrersSource, len(res.Proofs), res.ReferrerCount)
			}
			if !bytes.Equal(res.Layer, a.Layer) {
				t.Fatal("bundle layer not retrieved")
			}
			tagRequests := f.count(referrersTagPath(d))
			switch tc.want {
			case ReferrersFromAPI:
				if tagRequests != 0 {
					t.Fatalf("referrers tag read although the API answered: %v", f.log())
				}
				noTagRequests(t, f)
			default:
				if tagRequests != 1 {
					t.Fatalf("referrers tag read %d times", tagRequests)
				}
				noTagRequests(t, f, d)
			}
			if tc.proofs == 2 {
				if err := res.RequireProofs(RequiredProofs...); err != nil {
					t.Fatal(err)
				}
				if len(res.Skipped) != 1 || res.Skipped[0].Reason != "unrelated artifact type" {
					t.Fatalf("skipped %+v", res.Skipped)
				}
				return
			}
			// No listing is never success with proofs.
			var mp *MissingProofsError
			if err := res.RequireProofs(RequiredProofs...); !errors.Is(err, ErrMissingProofs) || !errors.As(err, &mp) ||
				!slices.Equal(mp.Missing, RequiredProofs) {
				t.Fatalf("err %v", err)
			}
		})
	}
}

func TestReferrersAPIRepositoryUnknownIsNotFallback(t *testing.T) {
	f := newFakeRegistry(t)
	d := f.publishSigned(t)
	f.tagSchema = true
	f.setHook(func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.Contains(r.URL.Path, "/referrers/") {
			return false
		}
		writeError(w, http.StatusNotFound, "NAME_UNKNOWN", "repository unknown")
		return true
	})
	_, err := fetch(t, f, Limits{}, d)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err %v", err)
	}
	if f.count(referrersTagPath(d)) != 0 {
		t.Fatal("fell back to the tag schema for an unknown repository")
	}
}

func TestTagSchemaExactSubjectSelection(t *testing.T) {
	f := newFakeRegistry(t)
	f.referrersTagOnly()
	a := official(t)
	d := f.publish(a)
	other := digest.FromString("another bundle manifest")
	size := int64(len(a.Manifest))
	// The tag index is an untrusted listing: entries naming another subject
	// or the wrong subject size are never used.
	wrongSubject := f.attach(d, other, size, CosignSignPredicateType)
	wrongSize := f.attach(d, d, size+1, CosignSignPredicateType)
	f.attach(d, d, size, SLSAProvenanceV1PredicateType)
	f.attach(other, other, 10, CosignSignPredicateType) // under another subject's tag

	res, err := fetch(t, f, Limits{}, d)
	if err != nil {
		t.Fatal(err)
	}
	if res.ReferrersSource != ReferrersFromTagSchema || len(res.Proofs) != 1 || res.Proofs[0].Kind != ProofProvenance {
		t.Fatalf("source %q proofs %+v", res.ReferrersSource, res.Proofs)
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
	noTagRequests(t, f, d)
}

func TestTagSchemaUnusableEntries(t *testing.T) {
	f := newFakeRegistry(t)
	f.referrersTagOnly()
	d := f.publishSigned(t)
	f.mu.Lock()
	sig := f.referrers[d.String()][0]
	f.mu.Unlock()
	f.list(d, sig) // a duplicate entry
	nested := sig
	nested.MediaType, nested.Digest = ocispec.MediaTypeImageIndex, digest.FromString("nested index")
	f.list(d, nested) // not an image manifest
	f.sbomReferrer(d)

	res, err := fetch(t, f, Limits{}, d)
	if err != nil {
		t.Fatal(err)
	}
	if res.ReferrerCount != 5 || len(res.Proofs) != 2 || len(res.Skipped) != 3 {
		t.Fatalf("listed %d proofs %d skipped %+v", res.ReferrerCount, len(res.Proofs), res.Skipped)
	}
	for i, want := range []string{"listed more than once", "is not an OCI image manifest", "unrelated artifact type"} {
		if !strings.Contains(res.Skipped[i].Reason, want) {
			t.Errorf("skipped[%d] = %+v, want %q", i, res.Skipped[i], want)
		}
	}
	if f.count("/manifests/"+sig.Digest.String()) != 1 || f.count("/manifests/"+nested.Digest.String()) != 0 {
		t.Fatalf("duplicate or non-manifest entry fetched: %v", f.log())
	}
}

// indexHook serves body at the referrers tag of d with the given headers.
type indexHook struct {
	d           digest.Digest
	body        []byte
	contentType string
	dcd         string // Docker-Content-Digest; "-" omits it
	chunked     bool   // GET without Content-Length; HEAD declares headBody
	headBody    []byte
}

func (h indexHook) serve(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasSuffix(r.URL.Path, referrersTagPath(h.d)) {
		return false
	}
	ct := h.contentType
	if ct == "" {
		ct = ocispec.MediaTypeImageIndex
	}
	declared := h.body
	if h.chunked && h.headBody != nil {
		declared = h.headBody
	}
	switch h.dcd {
	case "-":
	case "":
		w.Header().Set("Docker-Content-Digest", digest.FromBytes(declared).String())
	default:
		w.Header().Set("Docker-Content-Digest", h.dcd)
	}
	if r.Method == http.MethodHead || !h.chunked {
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Content-Length", fmt.Sprint(len(declared)))
		if r.Method == http.MethodGet {
			w.Write(h.body)
		}
		return true
	}
	writeChunked(w, ct, h.body)
	return true
}

func indexJSON(m map[string]any) []byte {
	raw, _ := json.Marshal(m)
	return raw
}

func validIndex(manifests []ocispec.Descriptor) map[string]any {
	return map[string]any{"schemaVersion": 2, "mediaType": ocispec.MediaTypeImageIndex, "manifests": manifests}
}

func TestTagSchemaIndexFailures(t *testing.T) {
	a := official(t)
	size := int64(len(a.Manifest))
	unrelated := func(i int) ocispec.Descriptor {
		return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString(fmt.Sprint(i)), Size: 1, ArtifactType: "application/x"}
	}
	with := func(mutate func(m map[string]any)) []byte {
		m := validIndex([]ocispec.Descriptor{unrelated(0)})
		mutate(m)
		return indexJSON(m)
	}
	for _, tc := range []struct {
		name   string
		limits Limits
		// setup prepares f and returns a hook (nil: the fake's own index).
		setup func(f *fakeRegistry, d digest.Digest) func(w http.ResponseWriter, r *http.Request) bool
		want  error
	}{
		{name: "malformed JSON", want: ErrUnexpectedDescriptor, setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			return indexHook{d: d, body: []byte(`{"schemaVersion":2,"mediaType":`)}.serve
		}},
		{name: "wrong mediaType in the body", want: ErrUnexpectedDescriptor, setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			return indexHook{d: d, body: with(func(m map[string]any) { m["mediaType"] = ocispec.MediaTypeImageManifest })}.serve
		}},
		{name: "no mediaType in the body", want: ErrUnexpectedDescriptor, setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			return indexHook{d: d, body: with(func(m map[string]any) { delete(m, "mediaType") })}.serve
		}},
		{name: "wrong schemaVersion", want: ErrUnexpectedDescriptor, setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			return indexHook{d: d, body: with(func(m map[string]any) { m["schemaVersion"] = 1 })}.serve
		}},
		{name: "no manifests list", want: ErrUnexpectedDescriptor, setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			return indexHook{d: d, body: with(func(m map[string]any) { delete(m, "manifests") })}.serve
		}},
		{name: "tag serves an image manifest", want: ErrUnexpectedDescriptor, setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			return indexHook{d: d, body: a.Manifest, contentType: ocispec.MediaTypeImageManifest}.serve
		}},
		{name: "tag resolves to the subject", want: ErrUnexpectedDescriptor, setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			return indexHook{d: d, body: indexJSON(validIndex(nil)), dcd: d.String()}.serve
		}},
		{name: "index bytes differ from the declared digest", want: ErrIntegrity, setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			return indexHook{d: d, body: indexJSON(validIndex(nil)), dcd: digest.FromString("other").String()}.serve
		}},
		{name: "chunked index longer than declared", want: ErrIntegrity, setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			body := indexJSON(validIndex(nil))
			return indexHook{d: d, body: append(bytes.Clone(body), ' '), chunked: true, headBody: body}.serve
		}},
		{name: "index over the 4 MiB manifest cap", want: ErrLimitExceeded, setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			body := append(indexJSON(validIndex(nil)), bytes.Repeat([]byte(" "), 4<<20)...)
			return indexHook{d: d, body: body}.serve
		}},
		{name: "index over the cap without a digest header", want: ErrLimitExceeded, setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			body := append(indexJSON(validIndex(nil)), bytes.Repeat([]byte(" "), 4<<20)...)
			return indexHook{d: d, body: body, dcd: "-"}.serve
		}},
		{name: "index over a lowered manifest cap", limits: Limits{MaxManifestBytes: size + 1}, want: ErrLimitExceeded,
			setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
				for range 8 {
					f.attach(d, d, size, CosignSignPredicateType)
				}
				return nil
			}},
		{name: "more entries than the referrer limit", want: ErrLimitExceeded, setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			for i := range DefaultLimits().MaxReferrers + 1 {
				f.list(d, unrelated(i))
			}
			return nil
		}},
		{name: "duplicate entries count toward the limit", limits: Limits{MaxReferrers: 2}, want: ErrLimitExceeded,
			setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
				for range 3 {
					f.list(d, unrelated(0))
				}
				return nil
			}},
		{name: "index body exceeds the metadata budget", limits: Limits{MaxMetadataBytes: 200}, want: ErrLimitExceeded,
			setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
				f.list(d, unrelated(0)) // the index alone is over 200 bytes
				return nil
			}},
		{name: "tampered referrer manifest", want: ErrIntegrity, setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			ref := f.attach(d, d, size, CosignSignPredicateType)
			body := bytes.Clone(f.manifests[ref.String()].body)
			body[len(body)/2] ^= 0x01
			return func(w http.ResponseWriter, r *http.Request) bool {
				if !strings.HasSuffix(r.URL.Path, "/manifests/"+ref.String()) {
					return false
				}
				w.Header().Set("Content-Type", ocispec.MediaTypeImageManifest)
				w.Header().Set("Content-Length", fmt.Sprint(len(body)))
				w.Write(body)
				return true
			}
		}},
		{name: "tag access denied", want: ErrUnauthorized, setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			return func(w http.ResponseWriter, r *http.Request) bool {
				if !strings.HasSuffix(r.URL.Path, referrersTagPath(d)) {
					return false
				}
				writeError(w, http.StatusForbidden, "DENIED", "no")
				return true
			}
		}},
		{name: "tag unavailable", want: ErrUnavailable, setup: func(f *fakeRegistry, d digest.Digest) func(http.ResponseWriter, *http.Request) bool {
			return func(w http.ResponseWriter, r *http.Request) bool {
				if !strings.HasSuffix(r.URL.Path, referrersTagPath(d)) {
					return false
				}
				writeError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "later")
				return true
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRegistry(t)
			f.referrersTagOnly()
			d := f.publish(a)
			if hook := tc.setup(f, d); hook != nil {
				f.setHook(hook)
			}
			res, err := fetch(t, f, tc.limits, d)
			if !errors.Is(err, tc.want) || res != nil {
				t.Fatalf("res %v err %v, want %v", res, err, tc.want)
			}
			wantClass := ClassPermanent
			if tc.want == ErrUnauthorized || tc.want == ErrUnavailable {
				wantClass = ClassRetryable
			}
			if Classify(err) != wantClass {
				t.Fatalf("class %s for %v", Classify(err), err)
			}
			if tc.want == ErrLimitExceeded && f.count("/blobs/") != 0 {
				t.Fatalf("downloaded proofs or the layer past a listing limit: %v", f.log())
			}
			noTagRequests(t, f, d)
		})
	}
}

func TestTagSchemaMetadataBytes(t *testing.T) {
	f := newFakeRegistry(t)
	f.referrersTagOnly()
	d := f.publishSigned(t)
	f.sbomReferrer(d)
	f.mu.Lock()
	index := f.referrersIndexBody(d.String())
	f.mu.Unlock()
	res, err := fetch(t, f, Limits{}, d)
	if err != nil {
		t.Fatal(err)
	}
	want := int64(len(index))
	for _, p := range res.Proofs {
		want += int64(len(p.Manifest) + len(p.Bundle))
	}
	if res.MetadataBytes != want {
		t.Fatalf("metadata bytes %d, want %d (index %d)", res.MetadataBytes, want, len(index))
	}
	// One byte less than that fails, never truncates.
	if _, err := fetch(t, f, Limits{MaxMetadataBytes: want - 1}, d); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err %v", err)
	}
}

// tagBlocker holds referrers tag GETs open until released or abandoned.
type tagBlocker struct {
	d         digest.Digest
	release   chan struct{}
	started   chan struct{}
	abandoned atomic.Int32
}

func (b *tagBlocker) hook(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasSuffix(r.URL.Path, referrersTagPath(b.d)) {
		return false
	}
	b.started <- struct{}{}
	select {
	case <-b.release:
		return false
	case <-r.Context().Done():
		b.abandoned.Add(1)
		return true
	}
}

func TestTagSchemaCancellation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		limits Limits
		cancel bool
		want   func(error) bool
	}{
		{"resolution timeout", Limits{ResolutionTimeout: 150 * time.Millisecond}, false,
			func(err error) bool {
				return errors.Is(err, context.DeadlineExceeded) && Classify(err) == ClassRetryable
			}},
		{"request timeout", Limits{RequestTimeout: 100 * time.Millisecond}, false,
			func(err error) bool { return err != nil && Classify(err) == ClassRetryable }},
		{"caller cancellation", Limits{}, true,
			func(err error) bool { return errors.Is(err, context.Canceled) && Classify(err) == ClassCanceled }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRegistry(t)
			f.referrersTagOnly()
			d := f.publishSigned(t)
			b := &tagBlocker{d: d, release: make(chan struct{}), started: make(chan struct{}, 10)}
			f.setHook(b.hook)
			defer close(b.release)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				go func() { <-b.started; cancel() }()
			}
			start := time.Now()
			_, err := newTestClient(t, f, tc.limits, nil).Fetch(ctx, f.source(), d.String())
			if !tc.want(err) || time.Since(start) > 5*time.Second {
				t.Fatalf("err %v after %s", err, time.Since(start))
			}
			waitFor(t, "the referrers tag request to be abandoned", func() bool { return b.abandoned.Load() == 1 })
		})
	}
}

func TestTagSchemaCredentials(t *testing.T) {
	cred := Credential{Username: "robot", Password: secretPassword}
	src := func(f *fakeRegistry) bundle.BundleSource {
		s := f.source()
		s.CredentialSecret = &bundle.ObjectRef{Name: "registry-creds"}
		return s
	}

	t.Run("authenticated retrieval through the tag schema", func(t *testing.T) {
		f := newFakeRegistry(t)
		f.referrersTagOnly()
		d := f.publishSigned(t)
		f.basicUser, f.basicPass = "robot", secretPassword
		creds := &recordingCreds{cred: cred}
		res, err := newTestClient(t, f, Limits{}, creds).Fetch(context.Background(), src(f), d.String())
		if err != nil {
			t.Fatal(err)
		}
		if res.ReferrersSource != ReferrersFromTagSchema || res.RequireProofs(RequiredProofs...) != nil {
			t.Fatalf("source %q proofs %+v", res.ReferrersSource, res.Proofs)
		}
		for _, h := range creds.hosts {
			if h != f.host() {
				t.Fatalf("credential requested for %q", h)
			}
		}
	})

	t.Run("a tag request echoing credentials is redacted", func(t *testing.T) {
		f := newFakeRegistry(t)
		f.referrersTagOnly()
		d := f.publishSigned(t)
		f.setHook(func(w http.ResponseWriter, r *http.Request) bool {
			if !strings.HasSuffix(r.URL.Path, referrersTagPath(d)) {
				return false
			}
			writeError(w, http.StatusForbidden, "DENIED",
				fmt.Sprintf("rejected %q (password %s)", r.Header.Get("Authorization"), secretPassword))
			return true
		})
		f.basicUser, f.basicPass = "robot", secretPassword
		_, err := newTestClient(t, f, Limits{}, staticCreds{cred}).Fetch(context.Background(), src(f), d.String())
		if !errors.Is(err, ErrUnauthorized) || strings.Contains(err.Error(), secretPassword) ||
			strings.Contains(fmt.Sprintf("%+v %#v", err, err), secretPassword) || !strings.Contains(err.Error(), "[REDACTED]") {
			t.Fatalf("err %v", err)
		}
	})
}

func TestNoUsableCredentialIsUnauthorized(t *testing.T) {
	for _, tc := range []struct {
		name   string
		creds  CredentialProvider
		secret bool
	}{
		{"anonymous source against a Basic challenge", nil, false},
		{"username without password", staticCreds{Credential{Username: "robot"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRegistry(t)
			d := f.publishSigned(t)
			f.basicUser, f.basicPass = "robot", secretPassword
			s := f.source()
			if tc.secret {
				s.CredentialSecret = &bundle.ObjectRef{Name: "registry-creds"}
			}
			_, err := newTestClient(t, f, Limits{}, tc.creds).Fetch(context.Background(), s, d.String())
			if !errors.Is(err, ErrUnauthorized) || Classify(err) != ClassRetryable || strings.Contains(err.Error(), secretPassword) {
				t.Fatalf("err %v", err)
			}
		})
	}
}
