package resolve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/cache"
	"github.com/backend-bunny/Konstapel/internal/bundle/internal/provfixture"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
)

var (
	t0      = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	fixOnce sync.Once
	fix     *provfixture.Fixtures
	fixErr  error
)

func fixtures(t testing.TB) *provfixture.Fixtures {
	t.Helper()
	fixOnce.Do(func() { fix, fixErr = provfixture.Load() })
	if fixErr != nil {
		t.Fatal(fixErr)
	}
	return fix
}

// revs is a settable configuration. Changes follow the invalidation
// protocol: update, then invalidate.
type revs struct {
	mu     sync.Mutex
	src    map[string]bundle.BundleSource
	trust  map[string]string
	compat string
}

func (r *revs) Source(name string) (bundle.BundleSource, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.src[name]
	if !ok {
		return bundle.BundleSource{}, fmt.Errorf("%w: %q", bundle.ErrUnconfigured, name)
	}
	return s, nil
}

func (r *revs) Trust(src bundle.BundleSource) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.trust[src.Name], nil
}

func (r *revs) Compatibility() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.compat, nil
}

func (r *revs) edit(f func(r *revs)) { r.mu.Lock(); f(r); r.mu.Unlock() }

// fetcher is a fake registry: it serves res unless down, and counts calls.
type fetcher struct {
	res   *registry.Result
	down  atomic.Bool
	calls atomic.Int64
}

func (f *fetcher) Fetch(_ context.Context, _ bundle.BundleSource, digest string) (*registry.Result, error) {
	f.calls.Add(1)
	if f.down.Load() {
		return nil, fmt.Errorf("%w: connection refused", registry.ErrUnavailable)
	}
	if f.res == nil || f.res.Digest != digest {
		return nil, registry.ErrNotFound
	}
	return f.res, nil
}

type world struct {
	t            *testing.T
	f            *provfixture.Fixtures
	dir          string
	cache        *cache.Cache
	reader       *kubeaccess.MemoryReader
	revs         *revs
	fetch        *fetcher
	acc          *Acceptances
	r            *Resolver
	incompatible atomic.Bool
}

func noCheck(*bundle.Descriptor, string) error { return nil }

func newWorld(t *testing.T) *world {
	t.Helper()
	f := fixtures(t)
	w := &world{t: t, f: f, dir: t.TempDir(), reader: f.Reader(), fetch: &fetcher{res: f.Result("sign-org", "prov-valid")}}
	w.revs = &revs{src: map[string]bundle.BundleSource{provfixture.Name: f.Source()}, trust: map[string]string{provfixture.Name: "trust-1"}, compat: "kyverno/v1;konstapel/0.1.0"}
	w.open()
	return w
}

// open (re)starts the process: a cache over the same directory and a new,
// empty acceptance store.
func (w *world) open() {
	w.t.Helper()
	w.acc = NewAcceptances()
	c, err := cache.Open(w.dir, cache.Config{CheckContent: noCheck, OnRemove: func(d string) { w.acc.InvalidateDigest(d) }})
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { c.Close() })
	w.cache = c
	v, err := verify.New(w.reader, verify.WithClock(func() time.Time { return t0 }))
	if err != nil {
		w.t.Fatal(err)
	}
	w.r, err = New(Config{Cache: c, Fetcher: w.fetch, Verifier: v, Acceptances: w.acc, Revisions: w.revs,
		Compatible: func(d *bundle.Descriptor) bundle.ContentCompatibility {
			if w.incompatible.Load() {
				return bundle.ContentCompatibility{Provider: d.Compatibility.Provider, Reasons: []string{"provider contract kyverno/v2 required"}}
			}
			return bundle.ContentCompatibility{Compatible: true, Provider: d.Compatibility.Provider, Konstapel: d.Compatibility.Konstapel, OSCAL: []string{"1.1.3"}}
		},
		Now: func() time.Time { return t0 }})
	if err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) restart() {
	w.t.Helper()
	if err := w.cache.Close(); err != nil {
		w.t.Fatal(err)
	}
	w.open()
}

func (w *world) req(owner string) Request {
	return Request{Name: provfixture.Name, Digest: w.f.Subject, Holder: bundle.HolderProfile, Owner: owner}
}

func (w *world) resolve(owner string) (bundle.ResolvedContent, error) {
	return w.r.Resolve(context.Background(), w.req(owner))
}

// mustResolve resolves, checks the handle and releases its lease.
func (w *world) mustResolve() bundle.ResolvedContent {
	w.t.Helper()
	h, err := w.resolve("profile/p")
	if err != nil {
		w.t.Fatal(err)
	}
	if err := h.Validate(); err != nil {
		w.t.Fatal(err)
	}
	if h.Digests.OCI != w.f.Subject || h.Lease.Digest != w.f.Subject || h.Lease.Holder != bundle.HolderProfile || h.Lease.Owner != "profile/p" {
		w.t.Fatalf("handle %+v", h)
	}
	if err := w.r.Release(h); err != nil {
		w.t.Fatal(err)
	}
	return h
}

func (w *world) keyReads() int {
	return w.reader.Reads(bundle.KindSecret, "org") + w.reader.Reads(bundle.KindSecret, "other") + w.reader.Reads(bundle.KindSecret, "org-renamed")
}

func (w *world) noLeases() {
	w.t.Helper()
	if n := w.cache.Stats().Leases; n != 0 {
		w.t.Fatalf("%d leases held", n)
	}
}

func wantErr(t *testing.T, err error, sentinels ...error) {
	t.Helper()
	if err == nil {
		t.Fatalf("succeeded, want %v", sentinels)
	}
	for _, s := range sentinels {
		if !errors.Is(err, s) {
			t.Fatalf("%v: not %v", err, s)
		}
	}
	if !errors.Is(err, ErrUnresolved) {
		t.Fatalf("%v does not wrap ErrUnresolved", err)
	}
}

// The first resolution retrieves and verifies; the next is served from the
// acceptance with no registry request and no verification.
func TestResolvePaths(t *testing.T) {
	w := newWorld(t)
	h := w.mustResolve()
	if w.fetch.calls.Load() != 1 || w.acc.Len() != 1 {
		t.Fatalf("fetches %d, acceptances %d", w.fetch.calls.Load(), w.acc.Len())
	}
	if h.Receipt.Signer.KeyFingerprint != w.f.FPOrg || !h.Compatibility.Content.Compatible || h.Compatibility.Engine != bundle.EngineUnknown {
		t.Fatalf("handle %+v", h)
	}
	if _, err := w.cache.Proofs(w.f.Subject); err != nil {
		t.Fatalf("evidence not retained: %v", err)
	}
	reads := w.keyReads()
	w.fetch.down.Store(true)
	w.mustResolve()
	if w.fetch.calls.Load() != 1 || w.keyReads() != reads {
		t.Fatalf("acceptance hit fetched (%d) or verified (%d reads)", w.fetch.calls.Load(), w.keyReads()-reads)
	}
	w.noLeases()
	// Several owners pin one entry; each releases its own lease.
	h1, err := w.resolve("profile/a")
	if err != nil {
		t.Fatal(err)
	}
	h2, err := w.r.Resolve(context.Background(), Request{Name: provfixture.Name, Digest: w.f.Subject, Holder: bundle.HolderApplied, Owner: "applied/a"})
	if err != nil {
		t.Fatal(err)
	}
	if s := w.cache.Stats(); s.Leases != 2 {
		t.Fatalf("%+v", s)
	}
	if err := w.r.Release(h1); err != nil {
		t.Fatal(err)
	}
	if err := w.r.Release(h1); !errors.Is(err, cache.ErrLease) {
		t.Fatalf("double release: %v", err)
	}
	if err := w.r.Release(h2); err != nil {
		t.Fatal(err)
	}
	w.noLeases()
	// Malformed requests.
	for _, req := range []Request{{Name: "", Digest: w.f.Subject, Holder: bundle.HolderProfile, Owner: "o"},
		{Name: provfixture.Name, Digest: "sha256:x", Holder: bundle.HolderProfile, Owner: "o"},
		{Name: provfixture.Name, Digest: w.f.Subject, Holder: "boss", Owner: "o"}} {
		_, err := w.r.Resolve(context.Background(), req)
		wantErr(t, err, ErrRequest)
	}
}

// Every key component is read from current configuration at lookup: a
// change to any of them misses (and is re-established by a recheck of the
// retained evidence, offline), while a mirror or credential/CA change hits.
func TestAcceptanceKey(t *testing.T) {
	type change struct {
		edit func(w *world)
		hit  bool
	}
	renamedKey := func(w *world) {
		provfixture.PutKey(w.reader, "org-renamed", w.f.PubOrg)
		w.revs.edit(func(r *revs) {
			s := r.src[provfixture.Name]
			s.Publisher.PublicKey = &bundle.ObjectRef{Kind: bundle.KindSecret, Name: "org-renamed"}
			r.src[provfixture.Name] = s
		})
	}
	src := func(f func(s *bundle.BundleSource)) func(w *world) {
		return func(w *world) {
			w.revs.edit(func(r *revs) { s := r.src[provfixture.Name]; f(&s); r.src[provfixture.Name] = s })
		}
	}
	for name, c := range map[string]change{
		"mirror repository":  {src(func(s *bundle.BundleSource) { s.Repository = "mirror.example.test/bundles/x" }), true},
		"credential secret":  {src(func(s *bundle.BundleSource) { s.CredentialSecret = &bundle.ObjectRef{Name: "pull-2"} }), true},
		"custom CA":          {src(func(s *bundle.BundleSource) { s.CA = &bundle.ObjectRef{Kind: bundle.KindConfigMap, Name: "ca"} }), true},
		"rule (key moved)":   {renamedKey, false},
		"trust revision":     {func(w *world) { w.revs.edit(func(r *revs) { r.trust[provfixture.Name] = "trust-2" }) }, false},
		"compat revision":    {func(w *world) { w.revs.edit(func(r *revs) { r.compat = "kyverno/v1;konstapel/0.2.0" }) }, false},
		"nothing (identity)": {func(*world) {}, true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			w.mustResolve()
			w.fetch.down.Store(true) // whatever happens, no retrieval
			reads := w.keyReads()
			c.edit(w)
			h := w.mustResolve()
			hit := w.keyReads() == reads
			if hit != c.hit {
				t.Fatalf("hit=%v, want %v", hit, c.hit)
			}
			if w.fetch.calls.Load() != 1 {
				t.Fatalf("retrieved during the outage: %d", w.fetch.calls.Load())
			}
			if name == "rule (key moved)" && h.Receipt.TrustRoot != "Secret/org-renamed[cosign.pub]" {
				t.Fatalf("recomputed receipt not used: %+v", h.Receipt)
			}
			w.noLeases()
		})
	}
	// The name and digest are key components by construction; a key that
	// differs in any single component misses.
	w := newWorld(t)
	w.mustResolve()
	t1, _, err := w.r.begin(provfixture.Name, w.f.Subject)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := w.acc.Lookup(t1.Key); !ok {
		t.Fatal("current key misses")
	}
	for name, edit := range map[string]func(k *Key){
		"name": func(k *Key) { k.Name += "x" }, "digest": func(k *Key) { k.Digest = w.f.LayerDigest },
		"rule": func(k *Key) { k.Rule += "x" }, "trust": func(k *Key) { k.Trust += "x" }, "compat": func(k *Key) { k.Compat += "x" },
	} {
		k := t1.Key
		edit(&k)
		if _, ok := w.acc.Lookup(k); ok {
			t.Errorf("%s: a changed component hit", name)
		}
	}
}

// Registry outage: intact content with complete evidence that satisfies
// current trust is reused offline after a restart; everything else is
// unresolved with a typed error, never a stale success.
func TestOutage(t *testing.T) {
	t.Run("reuse after restart", func(t *testing.T) {
		w := newWorld(t)
		w.mustResolve()
		w.restart()
		if w.acc.Len() != 0 || w.cache.Stats().Leases != 0 {
			t.Fatal("acceptance or lease survived a restart")
		}
		w.fetch.down.Store(true)
		calls := w.fetch.calls.Load()
		reads := w.keyReads()
		h := w.mustResolve()
		if w.fetch.calls.Load() != calls {
			t.Fatal("the reuse path called the registry")
		}
		if w.keyReads() == reads {
			t.Fatal("reused without rechecking under current trust")
		}
		if !h.Receipt.VerifiedAt.Equal(t0) || h.Receipt.Signer.KeyFingerprint != w.f.FPOrg {
			t.Fatalf("%+v", h.Receipt)
		}
	})

	cases := map[string]struct {
		edit  func(t *testing.T, w *world)
		want  []error
		fetch bool // whether retrieval was attempted
	}{
		"lost cache": {func(t *testing.T, w *world) {
			w.cache.Close()
			if err := os.RemoveAll(w.dir); err != nil {
				t.Fatal(err)
			}
			w.open()
		}, []error{ErrContentUnavailable, registry.ErrUnavailable}, true},
		"missing evidence": {func(t *testing.T, w *world) {
			w.cache.Close()
			if err := os.Remove(filepath.Join(w.dir, "proofs/sha256", w.f.Subject[7:])); err != nil {
				t.Fatal(err)
			}
			w.open()
		}, []error{ErrProofUnavailable, cache.ErrNoProofs, registry.ErrUnavailable}, true},
		// Evidence is read only when there is no current acceptance (see
		// TestCorruptEvidenceUnderAcceptance), so the process restarts here.
		"corrupt evidence": {func(t *testing.T, w *world) {
			flip(t, filepath.Join(w.dir, "proofs/sha256", w.f.Subject[7:]), 500)
			w.restart()
		}, []error{ErrProofUnavailable, cache.ErrCorrupt, registry.ErrUnavailable}, true},
		"corrupt content": {func(t *testing.T, w *world) {
			flip(t, filepath.Join(w.dir, "blobs/sha256", w.f.LayerDigest[7:]), 1000)
		}, []error{ErrContentUnavailable, registry.ErrUnavailable}, true},
		"key rotated out of the rule": {func(t *testing.T, w *world) {
			w.revs.edit(func(r *revs) {
				s := r.src[provfixture.Name]
				s.Publisher.PublicKey = &bundle.ObjectRef{Kind: bundle.KindSecret, Name: "other"}
				s.Publisher.KeyFingerprint = w.f.FPOther
				r.src[provfixture.Name] = s
			})
			w.acc.InvalidateSource(provfixture.Name)
		}, []error{ErrUntrusted, verify.ErrSignature, registry.ErrUnavailable}, true},
		"key material swapped": {func(t *testing.T, w *world) {
			provfixture.PutKey(w.reader, "org", w.f.PubOther)
			w.revs.edit(func(r *revs) { r.trust[provfixture.Name] = "trust-2" })
			w.acc.InvalidateSource(provfixture.Name)
		}, []error{ErrUntrusted, verify.ErrKeyFingerprint}, false},
		"rule requires another builder": {func(t *testing.T, w *world) {
			w.revs.edit(func(r *revs) {
				s := r.src[provfixture.Name]
				s.Publisher.Provenance.Builder += "/v2"
				r.src[provfixture.Name] = s
			})
			w.acc.InvalidateSource(provfixture.Name)
		}, []error{ErrUntrusted, verify.ErrProvenanceBuilder, registry.ErrUnavailable}, true},
		"source removed": {func(t *testing.T, w *world) {
			w.revs.edit(func(r *revs) { delete(r.src, provfixture.Name) })
			w.acc.InvalidateSource(provfixture.Name)
		}, []error{ErrConfig, bundle.ErrUnconfigured}, false},
		"provider incompatible": {func(t *testing.T, w *world) {
			w.incompatible.Store(true)
			w.revs.edit(func(r *revs) { r.compat = "kyverno/v2" })
			w.acc.InvalidateAll()
		}, []error{ErrIncompatible}, false},
	}
	for name, c := range cases {
		for _, restart := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/restart=%v", name, restart), func(t *testing.T) {
				t.Parallel()
				w := newWorld(t)
				w.mustResolve()
				w.fetch.down.Store(true)
				if restart {
					w.restart()
				}
				c.edit(t, w)
				calls := w.fetch.calls.Load()
				h, err := w.resolve("profile/p")
				wantErr(t, err, c.want...)
				if h.Digests.OCI != "" {
					t.Fatalf("a handle came with the error: %+v", h)
				}
				if (w.fetch.calls.Load() != calls) != c.fetch {
					t.Fatalf("retrieval attempted=%v, want %v", w.fetch.calls.Load() != calls, c.fetch)
				}
				w.noLeases()
				if k, _, err := w.r.currentKey(provfixture.Name, w.f.Subject); err == nil {
					if _, ok := w.acc.Lookup(k); ok {
						t.Fatal("an acceptance was recorded")
					}
				}
			})
		}
	}

	t.Run("recovery when the registry returns", func(t *testing.T) {
		w := newWorld(t)
		w.mustResolve()
		w.fetch.down.Store(true)
		w.cache.Close()
		os.Remove(filepath.Join(w.dir, "proofs/sha256", w.f.Subject[7:]))
		w.open()
		_, err := w.resolve("p")
		wantErr(t, err, ErrProofUnavailable)
		w.fetch.down.Store(false)
		w.mustResolve()
		if _, err := w.cache.Proofs(w.f.Subject); err != nil {
			t.Fatalf("fresh evidence not retained: %v", err)
		}
	})
}

func flip(t *testing.T, p string, at int64) {
	t.Helper()
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[at] ^= 1
	if err := os.WriteFile(p, b, 0o444); err != nil {
		t.Fatal(err)
	}
}

// Retained evidence is rechecked, never trusted: an edited receipt is
// replaced by the recomputed one, and a receipt claiming success over
// evidence from another key cannot create an acceptance.
func TestRetainedReceiptIsNotAuthority(t *testing.T) {
	store := func(t *testing.T, w *world, edit func(rb *verify.RecheckBundle)) {
		t.Helper()
		if _, err := w.cache.Put(context.Background(), w.f.Manifest, w.f.Layer); err != nil {
			t.Fatal(err)
		}
		v, _ := verify.New(w.reader, verify.WithClock(func() time.Time { return t0 }))
		acc, err := v.Accept(context.Background(), w.f.Source(), w.f.Result("sign-org", "prov-valid"))
		if err != nil {
			t.Fatal(err)
		}
		rb := *acc.Recheck
		edit(&rb)
		if err := w.cache.PutProofs(context.Background(), w.f.Subject, &rb); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("edited receipt", func(t *testing.T) {
		w := newWorld(t)
		w.fetch.down.Store(true)
		store(t, w, func(rb *verify.RecheckBundle) {
			rb.Receipt.Signer.KeyFingerprint = w.f.FPOther
			rb.Receipt.Provenance.Builder = "https://ci.example.test/forged"
		})
		h := w.mustResolve()
		if h.Receipt.Signer.KeyFingerprint != w.f.FPOrg || h.Receipt.Provenance.Builder != provfixture.Builder {
			t.Fatalf("forged claims adopted: %+v", h.Receipt)
		}
		// The recomputed material replaced the edited one.
		rb, err := w.cache.Proofs(w.f.Subject)
		if err != nil || rb.Receipt.Signer.KeyFingerprint != w.f.FPOrg {
			t.Fatalf("%v %+v", err, rb)
		}
	})
	t.Run("consistent receipt over evidence of another key", func(t *testing.T) {
		w := newWorld(t)
		w.fetch.down.Store(true)
		store(t, w, func(rb *verify.RecheckBundle) {
			for _, p := range []struct {
				slot   *verify.RetainedProof
				digest *bundle.ProofDigests
				name   string
			}{{&rb.Signature, &rb.Receipt.Proofs.Signature, "sign-other"}, {&rb.Attestation, &rb.Receipt.Proofs.Attestation, "prov-valid-other"}} {
				src := w.f.Proofs[p.name]
				*p.slot = verify.RetainedProof{Manifest: src.Manifest, Bundle: src.Bundle}
				st, err := provfixture.StatementDigest(src.Bundle)
				if err != nil {
					t.Fatal(err)
				}
				*p.digest = bundle.ProofDigests{Manifest: src.ManifestDigest, Bundle: src.BundleDigest, Statement: st}
			}
		})
		_, err := w.resolve("p")
		wantErr(t, err, ErrUntrusted, verify.ErrSignature, registry.ErrUnavailable)
		if w.acc.Len() != 0 {
			t.Fatal("forged evidence created an acceptance")
		}
		w.noLeases()
	})
}

// A result invalidated, or whose revisions changed, while it was verified or
// between verification and adoption is rejected: nothing is recorded or
// adopted and no lease is held. Deterministic: the change runs in a hook at
// the exact point.
func TestConcurrentInvalidation(t *testing.T) {
	changes := map[string]func(w *world){
		"source invalidated":    func(w *world) { w.acc.InvalidateSource(provfixture.Name) },
		"digest invalidated":    func(w *world) { w.acc.InvalidateDigest(w.f.Subject) },
		"all invalidated":       func(w *world) { w.acc.InvalidateAll() },
		"predicate invalidated": func(w *world) { w.acc.Invalidate(func(k Key) bool { return k.Trust == "unrelated" }) },
		"trust revision only (watch lagging)": func(w *world) {
			w.revs.edit(func(r *revs) { r.trust[provfixture.Name] = "trust-2" })
		},
		"rule changed and invalidated": func(w *world) {
			w.revs.edit(func(r *revs) {
				s := r.src[provfixture.Name]
				s.Publisher.Provenance.Builder += "/v2"
				r.src[provfixture.Name] = s
			})
			w.acc.InvalidateSource(provfixture.Name)
		},
	}
	paths := map[string]func(w *world){
		"retrieval": func(*world) {},
		"recheck": func(w *world) {
			w.mustResolve()
			w.restart()
			w.fetch.down.Store(true)
		},
	}
	for pname, setup := range paths {
		for cname, change := range changes {
			for _, point := range []string{"after verification", "before adoption"} {
				t.Run(fmt.Sprintf("%s/%s/%s", pname, cname, point), func(t *testing.T) {
					t.Parallel()
					w := newWorld(t)
					setup(w)
					fired := 0
					hook := func() {
						fired++
						if fired == 1 {
							change(w)
						}
					}
					if point == "after verification" {
						w.r.afterVerify = hook
					} else {
						w.r.beforeAdopt = hook
					}
					_, err := w.resolve("p")
					wantErr(t, err, ErrStale)
					if fired != 1 {
						t.Fatalf("hook fired %d times", fired)
					}
					w.noLeases()
					if point == "after verification" && w.acc.Len() != 0 {
						t.Fatal("a stale result was recorded")
					}
					// An unrelated predicate invalidation makes the
					// in-flight result stale conservatively, but the
					// acceptance it recorded is still correct.
					if k, _, err := w.r.currentKey(provfixture.Name, w.f.Subject); err == nil && cname != "predicate invalidated" {
						if _, ok := w.acc.Lookup(k); ok {
							t.Fatal("a stale result is visible under the current revisions")
						}
					}
				})
			}
		}
	}
	// An unrelated source's invalidation does not disturb a resolution.
	w := newWorld(t)
	w.r.afterVerify = func() { w.acc.InvalidateSource("other-bundle") }
	w.mustResolve()
}

// The store alone: a ticket is refused once anything it depends on moved.
func TestAcceptancesTickets(t *testing.T) {
	a := NewAcceptances()
	key := Key{Name: "b", Digest: "sha256:1", Rule: "r", Trust: "t", Compat: "c"}
	begin := func() Ticket { tk := a.Begin("b", "sha256:1"); tk.Key = key; return tk }
	acc := Acceptance{Key: key}

	tk := begin()
	if err := a.Record(tk, acc); err != nil {
		t.Fatal(err)
	}
	if err := a.Valid(tk); err != nil {
		t.Fatal(err)
	}
	a.InvalidateSource("other")
	a.InvalidateDigest("sha256:2")
	if err := a.Valid(tk); err != nil {
		t.Fatalf("unrelated invalidation: %v", err)
	}
	for name, inv := range map[string]func(){
		"source": func() { a.InvalidateSource("b") }, "digest": func() { a.InvalidateDigest("sha256:1") },
		"all": func() { a.InvalidateAll() }, "predicate": func() { a.Invalidate(func(k Key) bool { return k.Trust == "t" }) },
	} {
		tk := begin()
		inv()
		if err := a.Record(tk, acc); !errors.Is(err, ErrStale) {
			t.Errorf("%s: record %v", name, err)
		}
		if _, ok := a.Lookup(key); ok {
			t.Errorf("%s: recorded", name)
		}
		tk = begin()
		if err := a.Record(tk, acc); err != nil {
			t.Fatal(err)
		}
		inv()
		if err := a.Valid(tk); !errors.Is(err, ErrStale) {
			t.Errorf("%s: valid %v", name, err)
		}
		if _, ok := a.Lookup(key); ok {
			t.Errorf("%s: not dropped", name)
		}
	}
	tk = begin()
	if err := a.Record(tk, Acceptance{Key: Key{Name: "b"}}); !errors.Is(err, ErrStale) {
		t.Fatalf("mismatched key: %v", err)
	}
	// An unrelated predicate drops nothing but still fails tickets in
	// flight.
	if err := a.Record(begin(), acc); err != nil {
		t.Fatal(err)
	}
	tk = begin()
	if n := a.Invalidate(func(k Key) bool { return k.Trust == "other" }); n != 0 || a.Len() != 1 {
		t.Fatal(n, a.Len())
	}
	if err := a.Valid(tk); !errors.Is(err, ErrStale) {
		t.Fatalf("in-flight ticket after a predicate invalidation: %v", err)
	}
}

// While an acceptance is current, corrupt retained evidence is not read and
// does not matter: the decision was made from intact evidence under the
// same revisions. The next decision (after any change or a restart) reads
// it, detects the corruption and does not use it.
func TestCorruptEvidenceUnderAcceptance(t *testing.T) {
	w := newWorld(t)
	w.mustResolve()
	w.fetch.down.Store(true)
	flip(t, filepath.Join(w.dir, "proofs/sha256", w.f.Subject[7:]), 500)
	w.mustResolve()
	w.revs.edit(func(r *revs) { r.trust[provfixture.Name] = "trust-2" })
	w.acc.InvalidateSource(provfixture.Name)
	_, err := w.resolve("p")
	wantErr(t, err, ErrProofUnavailable, cache.ErrCorrupt)
	w.noLeases()
}

// Corruption found in a cached entry drops its acceptance (OnRemove), so a
// later lookup cannot serve an entry that is gone.
func TestRemovalDropsAcceptance(t *testing.T) {
	w := newWorld(t)
	w.mustResolve()
	if w.acc.Len() != 1 {
		t.Fatal(w.acc.Len())
	}
	flip(t, filepath.Join(w.dir, "blobs/sha256", w.f.Subject[7:]), 5)
	if _, err := w.cache.Get(context.Background(), w.f.Subject); !errors.Is(err, cache.ErrCorrupt) {
		t.Fatal(err)
	}
	if w.acc.Len() != 0 {
		t.Fatal("acceptance outlived its entry")
	}
	// The registry restores it.
	w.mustResolve()
}

// Concurrent resolutions with concurrent invalidations and revision changes:
// every result is either a valid handle under a current acceptance or
// ErrStale, and every lease is released.
func TestResolveStress(t *testing.T) {
	w := newWorld(t)
	w.mustResolve()
	var wg sync.WaitGroup
	errc := make(chan error, 256)
	stop := make(chan struct{})
	var flips atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			rev := fmt.Sprint("trust-", i%3)
			w.revs.edit(func(r *revs) { r.trust[provfixture.Name] = rev })
			w.acc.InvalidateSource(provfixture.Name)
			flips.Add(1)
			runtime.Gosched()
		}
	}()
	var resolvers sync.WaitGroup
	for g := 0; g < 6; g++ {
		resolvers.Add(1)
		go func() {
			defer resolvers.Done()
			for i := 0; i < 8; i++ {
				h, err := w.r.Resolve(context.Background(), Request{Name: provfixture.Name, Digest: w.f.Subject, Holder: bundle.HolderAssessment, Owner: fmt.Sprint("a", g)})
				if errors.Is(err, ErrStale) {
					continue
				}
				if err != nil {
					errc <- err
					continue
				}
				if err := h.Validate(); err != nil {
					errc <- err
				}
				if err := w.r.Release(h); err != nil {
					errc <- err
				}
			}
		}()
	}
	resolvers.Wait()
	close(stop)
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Error(err)
	}
	w.noLeases()
	if flips.Load() == 0 {
		t.Fatal("no concurrent change happened")
	}
	// Settled: resolution succeeds again and Confirm accepts it.
	h, err := w.resolve("final")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.r.Confirm(h); err != nil {
		t.Fatal(err)
	}
	w.revs.edit(func(r *revs) { r.trust[provfixture.Name] = "trust-9" })
	if err := w.r.Confirm(h); !errors.Is(err, ErrStale) {
		t.Fatalf("confirm after a change: %v", err)
	}
	if err := w.r.Release(h); err != nil {
		t.Fatal(err)
	}
}
