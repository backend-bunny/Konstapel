//go:build registrycompat

package registry_test

// Write-once publication (internal/bundle/publish) against the real
// registries of TestRegistryCompat: the distribution registry (no referrers
// API: the publisher maintains the referrers tag schema index) anonymous and
// htpasswd-protected, and Zot (referrers API) requiring htpasswd credentials
// for writes and allowing anonymous reads, as a public ghcr.io package does.
// A TLS proxy in front of them injects failures to show recovery against
// real servers. publish imports this package, so these cases live in the
// external test package and register themselves in registry.CompatCases.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/publish"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

func init() { registry.CompatCases = append(registry.CompatCases, publishCompat) }

type compatRunner struct{}

func (compatRunner) Name() string                            { return "kyverno test --require-tests" }
func (compatRunner) Version(context.Context) (string, error) { return "v0.0.0-compat", nil }
func (compatRunner) Run(context.Context, string, []string) error {
	return nil // the real CLI is covered by publish's unit tests and the release workflow
}

func tlsConfig(pool *x509.CertPool) *tls.Config { return &tls.Config{RootCAs: pool} }

func compatFrozen(t *testing.T, revision string) *publish.Frozen {
	t.Helper()
	raw, err := os.ReadFile("../../../bundles/konstapel-privileged-containers/definition.json")
	if err != nil {
		t.Fatal(err)
	}
	def, err := bundle.LoadDefinition(raw)
	if err != nil {
		t.Fatal(err)
	}
	def.Source.Revision = revision
	a, err := bundle.Build(def, os.DirFS("../../.."), time.Date(2026, 11, 11, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir() + "/bundle"
	if err := bundle.WriteLayout(dir, a); err != nil {
		t.Fatal(err)
	}
	f, err := publish.Freeze(context.Background(), dir, publish.FreezeInput{
		DefinitionSHA256: strings.Repeat("ab", 32), Tools: []publish.Tool{{Name: "go", Version: "compat"}}, Runner: compatRunner{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// recorder logs every request a client sends, to assert what was written.
type recorder struct {
	base http.RoundTripper
	mu   sync.Mutex
	reqs []string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req.Method+" "+req.URL.Path+"?"+req.URL.RawQuery)
	r.mu.Unlock()
	return r.base.RoundTrip(req)
}

func (r *recorder) writesSince(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, q := range r.reqs[n:] {
		if !strings.HasPrefix(q, "GET ") && !strings.HasPrefix(q, "HEAD ") {
			out = append(out, q)
		}
	}
	return out
}

func (r *recorder) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reqs)
}

type hostCred map[string]registry.Credential

func (h hostCred) Credential(_ context.Context, _ bundle.BundleSource, host string) (registry.Credential, error) {
	return h[host], nil
}

// faultProxy is a TLS reverse proxy to a real registry that fails the first
// request matching fail (when set).
type faultProxy struct {
	srv  *httptest.Server
	mu   sync.Mutex
	fail func(*http.Request) bool
}

func newFaultProxy(t *testing.T, upstream string, upstreamCAs *x509.CertPool) *faultProxy {
	t.Helper()
	target, _ := url.Parse("https://" + upstream)
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = &http.Transport{TLSClientConfig: tlsConfig(upstreamCAs)}
	p := &faultProxy{}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		fail := p.fail
		if fail != nil && fail(r) {
			p.fail = nil
			p.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"errors":[{"code":"UNKNOWN","message":"injected"}]}`)
			return
		}
		p.mu.Unlock()
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *faultProxy) host() string { return strings.TrimPrefix(p.srv.URL, "https://") }

func (p *faultProxy) failNext(f func(*http.Request) bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fail = f
}

// cosignLike attaches a referrer in the cosign v3 layout for kind.
type cosignLike struct{ w *registry.Client }

func (c cosignLike) Complete(ctx context.Context, s publish.Subject, missing []registry.ProofKind) error {
	sess, err := c.w.Open(ctx, bundle.BundleSource{Name: s.Record.Name, Repository: s.Repository, CredentialSecret: &publish.PublisherCredential})
	if err != nil {
		return err
	}
	for _, k := range missing {
		pt := map[registry.ProofKind]string{registry.ProofSignature: registry.CosignSignPredicateType, registry.ProofProvenance: registry.SLSAProvenanceV1PredicateType}[k]
		layer := []byte(fmt.Sprintf(`{"mediaType":%q,"proof":%q}`, registry.SigstoreBundleArtifactType, k))
		ld := ocispec.Descriptor{MediaType: registry.SigstoreBundleArtifactType, Digest: digest.FromBytes(layer), Size: int64(len(layer))}
		if err := sess.Repository.Blobs().Push(ctx, ld, bytes.NewReader(layer)); err != nil {
			return sess.Err("push proof layer", err)
		}
		empty := ocispec.Descriptor{MediaType: bundle.EmptyConfigMediaType, Digest: bundle.EmptyConfigDigest, Size: 2}
		if ok, _ := sess.Repository.Blobs().Exists(ctx, empty); !ok {
			if err := sess.Repository.Blobs().Push(ctx, empty, bytes.NewReader([]byte("{}"))); err != nil {
				return sess.Err("push empty config", err)
			}
		}
		m, _ := json.Marshal(map[string]any{
			"schemaVersion": 2, "mediaType": ocispec.MediaTypeImageManifest, "artifactType": registry.SigstoreBundleArtifactType,
			"config":      empty,
			"layers":      []any{ld},
			"subject":     map[string]any{"mediaType": ocispec.MediaTypeImageManifest, "digest": s.Digest, "size": s.Size},
			"annotations": map[string]string{registry.PredicateTypeAnnotation: pt},
		})
		md := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(m), Size: int64(len(m))}
		if err := sess.Repository.Manifests().Push(ctx, md, bytes.NewReader(m)); err != nil {
			return sess.Err("push proof", err)
		}
	}
	return nil
}

func publishCompat(t *testing.T, env registry.CompatEnv) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(env.CAPEM) {
		t.Fatal("CA")
	}
	frozenA := compatFrozen(t, strings.Repeat("e", 40))
	frozenB := compatFrozen(t, strings.Repeat("f", 40))
	creds := registry.Credential{Username: env.User, Password: env.Pass}

	// clients returns a recording writer with credentials for host and an
	// anonymous reader, both trusting pool.
	clients := func(host string, pool *x509.CertPool) (*registry.Client, *registry.Client, *recorder) {
		rec := &recorder{base: &http.Transport{TLSClientConfig: tlsConfig(pool)}}
		w, err := registry.NewClient(registry.Options{Transport: rec, Credentials: hostCred{host: creds}})
		if err != nil {
			t.Fatal(err)
		}
		r, err := registry.NewClient(registry.Options{Transport: &http.Transport{TLSClientConfig: tlsConfig(pool)}})
		if err != nil {
			t.Fatal(err)
		}
		return w, r, rec
	}
	record := func(name string, ok bool, err error, detail string) {
		if !ok && err == nil {
			err = errors.New("unexpected result")
		}
		if ok {
			err = nil
		}
		env.Record(name, err, detail)
		if !ok {
			t.Errorf("%s: %v (%s)", name, err, detail)
		}
	}

	type reg struct {
		label, host string
		via         registry.ReferrersSource
	}
	for i, r := range []reg{
		{"distribution registry (tag schema), anonymous writes", env.Anon, registry.ReferrersFromTagSchema},
		{"Zot (referrers API), htpasswd writes and anonymous reads", env.APIAuthd, registry.ReferrersFromAPI},
	} {
		t.Run("publish: "+r.label, func(t *testing.T) {
			w, rd, rec := clients(r.host, pool)
			repo := fmt.Sprintf("%s/bundles/publish-compat-%d", r.host, i)
			tgt := publish.Target{Repository: repo, Writer: w, Reader: rd, ReadBackDelay: 200 * time.Millisecond}

			res, err := publish.Publish(ctx, frozenA, tgt)
			record(t.Name()+": first publication creates, tag last, anonymous read-back",
				err == nil && res.Outcome == publish.Created && res.ReadBack.Verified && res.ReadBack.Anonymous &&
					res.ReadBack.ReferrersSource == r.via && fmt.Sprint(res.Missing) == "[signature provenance]",
				err, fmt.Sprintf("digest %s, record %s, referrers via %s, missing %v", res.Digest, res.RecordDigest, res.ReadBack.ReferrersSource, res.Missing))
			writes := rec.writesSince(0)
			last := ""
			if len(writes) > 0 {
				last = writes[len(writes)-1]
			}
			record(t.Name()+": version tag is the last write, no deletes",
				strings.HasPrefix(last, "PUT ") && strings.Contains(last, "/manifests/0.1.0?") && !strings.Contains(strings.Join(writes, "\n"), "DELETE"),
				nil, fmt.Sprintf("%d writes, last %q", len(writes), last))

			n := rec.len()
			res, err = publish.Publish(ctx, frozenA, tgt)
			record(t.Name()+": rerun is idempotent and writes nothing",
				err == nil && res.Outcome == publish.AlreadyPublished && len(rec.writesSince(n)) == 0, err, fmt.Sprint(rec.writesSince(n)))

			n = rec.len()
			_, err = publish.Publish(ctx, frozenB, tgt)
			still, _ := publish.Publish(ctx, frozenA, tgt)
			record(t.Name()+": different bytes under the version are refused without writes",
				errors.Is(err, publish.ErrConflict) && len(rec.writesSince(n)) == 0 && still != nil && still.Digest == frozenA.ManifestDigest,
				err, "")

			n = rec.len()
			res, err = publish.Publish(ctx, frozenA, publish.Target{Repository: repo, Writer: w, Reader: rd, Proofs: cosignLike{w: w}})
			subjectWrites := 0
			for _, q := range rec.writesSince(n) {
				if strings.Contains(q, "/manifests/0.1.0?") || strings.Contains(q, "/manifests/"+frozenA.ManifestDigest+"?") ||
					strings.Contains(q, strings.TrimPrefix(frozenA.LayerDigest, "sha256:")) {
					subjectWrites++
				}
			}
			record(t.Name()+": missing proofs completed without touching the subject",
				err == nil && res.Outcome == publish.Completed && res.Complete && subjectWrites == 0,
				err, fmt.Sprintf("added %v, subject writes %d", res.ProofsAdded, subjectWrites))
			// The consumer adapter now finds both proofs on the same digest.
			got, err := rd.Fetch(ctx, bundle.BundleSource{Name: "konstapel-privileged-containers", Repository: repo}, frozenA.ManifestDigest)
			record(t.Name()+": consumer retrieval finds the subject, both proofs and skips the record",
				err == nil && got.RequireProofs(registry.RequiredProofs...) == nil && len(got.Skipped) == 1 &&
					got.Skipped[0].ArtifactType == publish.RecordArtifactType, err, "")
		})
	}

	t.Run("publish: recovery through a fault-injecting proxy", func(t *testing.T) {
		for i, up := range []string{env.Anon, env.APIAuthd} {
			proxy := newFaultProxy(t, up, pool)
			proxyPool := x509.NewCertPool()
			proxyPool.AddCert(proxy.srv.Certificate())
			w, rd, rec := clients(proxy.host(), proxyPool)
			repo := fmt.Sprintf("%s/bundles/publish-recovery-%d", proxy.host(), i)
			tgt := publish.Target{Repository: repo, Writer: w, Reader: rd, ReadBackDelay: 200 * time.Millisecond}
			name := fmt.Sprintf("%s (upstream %d)", t.Name(), i)

			proxy.failNext(func(r *http.Request) bool {
				return r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/manifests/"+frozenA.ManifestDigest)
			})
			_, err := publish.Publish(ctx, frozenA, tgt)
			record(name+": blobs accepted, manifest fails", errors.Is(err, publish.ErrIncompleteRemote), err, "")
			proxy.failNext(func(r *http.Request) bool {
				return r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/manifests/0.1.0")
			})
			res, err := publish.Publish(ctx, frozenA, tgt)
			states := map[string]string{}
			if res != nil {
				for _, a := range res.Actions {
					states[a.Piece] = a.State
				}
			}
			record(name+": rerun pushes only the manifest and record; then the tag fails",
				errors.Is(err, publish.ErrIncompleteRemote) && states["config"] == publish.StateExisting && states["layer"] == publish.StateExisting &&
					states["manifest"] == publish.StatePushed && states["record"] == publish.StatePushed, err, fmt.Sprint(states))
			n := rec.len()
			res, err = publish.Publish(ctx, frozenA, tgt)
			uploads := 0
			for _, q := range rec.writesSince(n) {
				if strings.HasPrefix(q, "POST ") || strings.Contains(q, "/manifests/sha256:") {
					uploads++
				}
			}
			record(name+": final rerun only adds the tag and verifies",
				err == nil && res.Outcome == publish.Created && res.ReadBack.Verified && uploads == 0 && len(rec.writesSince(n)) == 1,
				err, fmt.Sprint(rec.writesSince(n)))
		}
	})

	t.Run("publish: anonymous read-back of a protected registry fails clearly", func(t *testing.T) {
		w, rd, _ := clients(env.Authd, pool)
		repo := env.Authd + "/bundles/publish-private"
		res, err := publish.Publish(ctx, frozenA, publish.Target{Repository: repo, Writer: w, Reader: rd, ReadBackAttempts: 2, ReadBackDelay: 100 * time.Millisecond})
		ok := errors.Is(err, publish.ErrReadBack) && errors.Is(err, registry.ErrUnauthorized) && strings.Contains(err.Error(), "private") &&
			res != nil && !res.Complete && !strings.Contains(err.Error(), env.Pass)
		record(t.Name(), ok, err, "the subject is pushed with credentials but not reported complete")
		// An organization registry may read back with credentials.
		rdAuth, _ := registry.NewClient(registry.Options{Transport: &http.Transport{TLSClientConfig: tlsConfig(pool)}, Credentials: hostCred{env.Authd: creds}})
		res, err = publish.Publish(ctx, frozenA, publish.Target{Repository: repo, Writer: w, Reader: rdAuth, AuthenticatedReadBack: true})
		record(t.Name()+": authenticated read-back for a private organization registry",
			err == nil && res.Outcome == publish.AlreadyPublished && res.ReadBack.Verified && !res.ReadBack.Anonymous, err, "")
	})

	t.Run("publish: wrong password is refused and never echoed", func(t *testing.T) {
		w, err := registry.NewClient(registry.Options{Transport: &http.Transport{TLSClientConfig: tlsConfig(pool)},
			Credentials: hostCred{env.APIAuthd: {Username: env.User, Password: "wrong-" + env.Pass}}})
		if err != nil {
			t.Fatal(err)
		}
		rd, _ := registry.NewClient(registry.Options{Transport: &http.Transport{TLSClientConfig: tlsConfig(pool)}})
		_, err = publish.Publish(ctx, frozenA, publish.Target{Repository: env.APIAuthd + "/bundles/publish-wrong-password", Writer: w, Reader: rd})
		record(t.Name(), errors.Is(err, registry.ErrUnauthorized) && !strings.Contains(err.Error(), env.Pass), err, "")
	})
}
