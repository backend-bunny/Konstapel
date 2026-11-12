package sources

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/cache"
	"github.com/backend-bunny/Konstapel/internal/bundle/content"
	"github.com/backend-bunny/Konstapel/internal/bundle/internal/provfixture"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/resolve"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

var t0 = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

// fetcher is a fake registry serving the signed fixture; it can be taken
// down, and onFetch runs inside a retrieval (after the resolver began, before
// it records), which gives deterministic interleavings.
type fetcher struct {
	res     *registry.Result
	down    atomic.Bool
	calls   atomic.Int64
	mu      sync.Mutex
	onFetch func()
}

func (f *fetcher) Fetch(_ context.Context, _ bundle.BundleSource, digest string) (*registry.Result, error) {
	f.calls.Add(1)
	f.mu.Lock()
	hook := f.onFetch
	f.onFetch = nil
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	if f.down.Load() {
		return nil, fmt.Errorf("%w: connection refused", registry.ErrUnavailable)
	}
	if f.res.Digest != digest {
		return nil, registry.ErrNotFound
	}
	return f.res, nil
}

type pipeline struct {
	*fixture
	pf    *provfixture.Fixtures
	fetch *fetcher
	cache *cache.Cache
	r     *resolve.Resolver
}

// newPipeline wires the Watcher as the real resolver's Revisions over a real
// cache and the real verifier, with the Cosign-signed fixture bundle.
func newPipeline(t *testing.T) *pipeline {
	t.Helper()
	pf, err := provfixture.Load()
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	provfixture.PutKey(f.objs, "org", pf.PubOrg)
	provfixture.PutKey(f.objs, "org-copy", pf.PubOrg)
	provfixture.PutKey(f.objs, "other", pf.PubOther)
	f.putCreds("creds", planted)
	compat := content.Compatibility{Controller: "0.1.0"}
	w, err := New(Options{Namespace: ns, Config: f.cfg, Objects: f.objs, Acceptances: f.acc, Transport: f.trans, Compatibility: compat.Revision})
	if err != nil {
		t.Fatal(err)
	}
	f.w = w
	c, err := cache.Open(t.TempDir(), cache.Config{OnRemove: func(d string) { f.acc.InvalidateDigest(d) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	v, err := verify.New(f.objs, verify.WithClock(func() time.Time { return t0 }))
	if err != nil {
		t.Fatal(err)
	}
	fe := &fetcher{res: pf.Result("sign-org", "prov-valid")}
	r, err := resolve.New(resolve.Config{Cache: c, Fetcher: fe, Verifier: v, Acceptances: f.acc, Revisions: w,
		Compatible: compat.Check, Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	p := &pipeline{fixture: f, pf: pf, fetch: fe, cache: c, r: r}
	p.set(p.source("org", pf.FPOrg, provfixture.Repository))
	p.sync()
	return p
}

func (p *pipeline) source(keySecret, fp, repo string) bundle.BundleSource {
	s := p.pf.Source()
	s.Repository = repo
	s.CredentialSecret = &bundle.ObjectRef{Name: "creds"}
	s.Publisher.PublicKey = &bundle.ObjectRef{Kind: bundle.KindSecret, Name: keySecret}
	s.Publisher.KeyFingerprint = fp
	return s
}

func (p *pipeline) resolve() (bundle.ResolvedContent, error) {
	h, err := p.r.Resolve(context.Background(), resolve.Request{Name: provfixture.Name, Digest: p.pf.Subject, Holder: bundle.HolderProfile, Owner: "test"})
	if err == nil {
		if rerr := p.r.Release(h); rerr != nil {
			p.t.Fatal(rerr)
		}
	}
	if n := p.cache.Stats().Leases; n != 0 {
		p.t.Fatalf("%d leases held", n)
	}
	return h, err
}

// End to end through the real resolver: an acceptance is never recorded for
// a configuration that changed during its verification; credential, CA and
// mirror changes keep acceptances (offline reuse works without the
// registry); trust revocation makes the content untrusted; recovery works.
func TestResolverFollowsConfiguration(t *testing.T) {
	p := newPipeline(t)

	// A rule change (same key, other object) lands while the first
	// retrieval is in flight: that resolution is stale and records nothing.
	p.fetch.mu.Lock()
	p.fetch.onFetch = func() {
		p.set(p.source("org-copy", p.pf.FPOrg, provfixture.Repository))
		p.sync()
	}
	p.fetch.mu.Unlock()
	if _, err := p.resolve(); !errors.Is(err, resolve.ErrStale) {
		t.Fatalf("resolution across a configuration change: %v", err)
	}
	if p.acc.Len() != 0 {
		t.Fatal("an acceptance was recorded for the configuration that changed")
	}
	h, err := p.resolve()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := p.w.Trust(p.source("org-copy", p.pf.FPOrg, provfixture.Repository))
	if err != nil || tok != "public-key:"+h.Receipt.TrustRevision {
		t.Fatalf("trust token %q (%v) does not match the receipt's trust revision %q", tok, err, h.Receipt.TrustRevision)
	}
	if p.acc.Len() != 1 {
		t.Fatalf("%d acceptances", p.acc.Len())
	}

	// Transport-only changes keep the acceptance: served without the registry.
	p.fetch.down.Store(true)
	calls := p.fetch.calls.Load()
	for _, step := range []struct {
		name   string
		change func()
	}{
		{"credential rotated", func() { p.putCreds("creds", "rotated") }},
		{"credential deleted", func() { p.objs.Delete("Secret", "creds") }},
		{"mirror", func() {
			p.set(p.source("org-copy", p.pf.FPOrg, "mirror.example.test/fixtures/konstapel-privileged-containers"))
		}},
	} {
		name := step.name
		step.change()
		ch := p.sync()
		if len(ch.Invalidated) != 0 || ch.InvalidatedAll || len(ch.Affected) != 1 {
			t.Fatalf("%s: %+v", name, ch)
		}
		if p.acc.Len() != 1 {
			t.Fatalf("%s dropped the acceptance", name)
		}
		if _, err := p.resolve(); err != nil {
			t.Fatalf("%s: offline reuse failed: %v", name, err)
		}
	}
	if p.fetch.calls.Load() != calls {
		t.Fatal("reuse contacted the registry")
	}

	// Trust revocation: the rule now names the other key. The cached
	// content and its evidence no longer satisfy trust, and fresh evidence
	// (the registry is back) does not either.
	p.fetch.down.Store(false)
	p.set(p.source("other", p.pf.FPOther, provfixture.Repository))
	if ch := p.sync(); len(ch.Invalidated) != 1 {
		t.Fatalf("revocation: %+v", ch)
	}
	if p.acc.Len() != 0 {
		t.Fatal("revocation kept the acceptance")
	}
	_, err = p.resolve()
	if !errors.Is(err, resolve.ErrUntrusted) {
		t.Fatalf("revoked trust: %v", err)
	}

	// Removing the key object instead: the trust revision is unavailable.
	p.set(p.source("org", p.pf.FPOrg, provfixture.Repository))
	p.sync()
	p.objs.Delete("Secret", "org")
	p.sync()
	if _, err := p.resolve(); !errors.Is(err, resolve.ErrConfig) {
		t.Fatalf("missing key: %v", err)
	}
	oci, err := content.New(content.Config{Resolver: p.r, Entries: p.cache})
	if err != nil {
		t.Fatal(err)
	}
	_, err = oci.Content(context.Background(), v1alpha1.BundleReference{Name: provfixture.Name, Digest: p.pf.Subject})
	if targeting.ContentErrorClassOf(err) != targeting.ContentErrorConfig {
		t.Fatalf("missing key through OCIContent: %v", err)
	}

	// Recovery: the key is back; offline recheck of the retained evidence.
	p.fetch.down.Store(true)
	provfixture.PutKey(p.objs, "org", p.pf.PubOrg)
	p.sync()
	if _, err := p.resolve(); err != nil {
		t.Fatalf("recovery: %v", err)
	}
}
