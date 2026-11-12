// Package resolve composes retrieval, the content cache, verification and
// acceptance into one resolution of a pinned bundle digest. It is the
// minimal seam the controller (task group 5) plugs into; it has no
// controller dependencies, does no retries, watches or status reporting, and
// is not linked into the shipped binaries.
//
// A cache entry is never an authorization. Content is adopted only under an
// Acceptance for the current source rule, trust and compatibility
// revisions, obtained in this order:
//
//  1. an acceptance recorded under the current revisions: served from the
//     cache, no registry request and no verification;
//  2. a cached entry with retained evidence: verify.Verifier.Recheck under
//     the current rule and trust, offline (this works during a registry
//     outage), then the compatibility check;
//  3. otherwise retrieval by digest, full verification, storage of the
//     bytes and the evidence, and the compatibility check.
//
// Lost content, missing evidence, evidence that no longer satisfies current
// trust, incompatibility and a changed configuration all end unresolved with
// a typed error, never with a stale success.
package resolve

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/cache"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
)

// Fetcher retrieves a pinned subject and its proofs. *registry.Client
// implements it (bounded by its own limits).
type Fetcher interface {
	Fetch(ctx context.Context, src bundle.BundleSource, manifestDigest string) (*registry.Result, error)
}

var _ Fetcher = (*registry.Client)(nil)

// Revisions supplies the current configuration. Its methods are called on
// every resolution, again before an acceptance is recorded and again before
// adoption; they must be cheap, must not block on the Acceptances store and
// must reflect a change before the matching Invalidate call is made.
type Revisions interface {
	// Source returns the source configured now for a bundle name, or an
	// error wrapping bundle.ErrUnconfigured when there is none.
	Source(name string) (bundle.BundleSource, error)
	// Trust returns the revision of the trust material src references now
	// (its trusted root or public key object). Credential and CA changes
	// must not change it.
	Trust(src bundle.BundleSource) (string, error)
	// Compatibility returns the revision of the compatibility contract the
	// Compatible check implements (controller and provider versions).
	Compatibility() (string, error)
}

// Compatible judges a verified descriptor against the running controller
// and provider. An incompatible verdict must give reasons.
type Compatible func(d *bundle.Descriptor) bundle.ContentCompatibility

// Config wires a Resolver. Every field but Now is required.
type Config struct {
	Cache       *cache.Cache
	Fetcher     Fetcher
	Verifier    *verify.Verifier
	Acceptances *Acceptances
	Revisions   Revisions
	Compatible  Compatible
	// Now stamps acceptances; nil means time.Now.
	Now func() time.Time
}

// Resolver resolves pinned bundle digests. It is safe for concurrent use.
type Resolver struct {
	cfg Config

	// Test hooks: after verification, before recording; and after
	// recording, before the adoption check.
	afterVerify func()
	beforeAdopt func()
}

// New validates cfg.
func New(cfg Config) (*Resolver, error) {
	if cfg.Cache == nil || cfg.Fetcher == nil || cfg.Verifier == nil || cfg.Acceptances == nil || cfg.Revisions == nil || cfg.Compatible == nil {
		return nil, errors.New("resolve: Cache, Fetcher, Verifier, Acceptances, Revisions and Compatible are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Resolver{cfg: cfg}, nil
}

// Request asks for one bundle digest on behalf of a lease holder.
type Request struct {
	// Name is the bundle (and source) name; Digest its OCI manifest digest.
	Name   string
	Digest string
	// Holder and Owner name the lease the resolved content is pinned by
	// (bundle.HolderProfile, HolderApplied or HolderAssessment).
	Holder string
	Owner  string
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Resolve returns the handle for req's digest under a current acceptance,
// pinned by a new lease that the caller must release (Release) when it
// finishes or advances. On error no lease is held.
func (r *Resolver) Resolve(ctx context.Context, req Request) (bundle.ResolvedContent, error) {
	if req.Name == "" || !digestPattern.MatchString(req.Digest) {
		return bundle.ResolvedContent{}, fmt.Errorf("%w: name %q and digest %q", ErrRequest, req.Name, req.Digest)
	}
	t, src, err := r.begin(req.Name, req.Digest)
	if err != nil {
		return bundle.ResolvedContent{}, err
	}

	// Pin a cached entry first, so that it cannot be evicted while it is
	// verified and adopted, then check its integrity.
	var entry *cache.Entry
	lease, err := r.cfg.Cache.Acquire(req.Digest, req.Holder, req.Owner)
	switch {
	case errors.Is(err, cache.ErrLease):
		return bundle.ResolvedContent{}, fmt.Errorf("%w: %w", ErrRequest, err)
	case err == nil:
		entry, err = r.cfg.Cache.Get(ctx, req.Digest)
		if err != nil {
			r.release(lease)
			if !errors.Is(err, cache.ErrNotFound) && !errors.Is(err, cache.ErrCorrupt) {
				return bundle.ResolvedContent{}, err
			}
			entry = nil
		}
	case !errors.Is(err, cache.ErrNotFound):
		return bundle.ResolvedContent{}, err
	}

	// Without a cached entry, a missing or unusable one is not trusted.
	var reuse error
	if entry != nil {
		if acc, ok := r.cfg.Acceptances.Lookup(t.Key); ok {
			return r.adopt(t, entry, acc, lease) // (1)
		}
		acc, err := r.recheck(ctx, t, src, entry) // (2)
		switch {
		case err == nil:
			return r.commit(t, entry, acc, lease)
		case errors.Is(err, errRetrieve):
			reuse = err // try fresh evidence
		default:
			r.release(lease)
			return bundle.ResolvedContent{}, err
		}
	}

	// (3) Retrieve, verify, store.
	res, err := r.cfg.Fetcher.Fetch(ctx, src, req.Digest)
	if err != nil {
		if entry != nil {
			r.release(lease)
		}
		if reuse != nil {
			return bundle.ResolvedContent{}, fmt.Errorf("%w; retrieval: %w", reuse, err)
		}
		return bundle.ResolvedContent{}, fmt.Errorf("%w: %s@%s: %w", ErrContentUnavailable, req.Name, req.Digest, err)
	}
	accepted, err := r.cfg.Verifier.Accept(ctx, src, res)
	if err != nil {
		if entry != nil {
			r.release(lease)
		}
		return bundle.ResolvedContent{}, fmt.Errorf("%w: %w", ErrUntrusted, err)
	}
	compat, err := r.compatible(accepted.Descriptor)
	if err != nil {
		if entry != nil {
			r.release(lease)
		}
		return bundle.ResolvedContent{}, err
	}
	if entry == nil {
		entry, lease, err = r.cfg.Cache.PutLeased(ctx, res.Manifest, res.Layer, req.Holder, req.Owner)
		if err != nil {
			return bundle.ResolvedContent{}, storeErr(err)
		}
	}
	if err := r.cfg.Cache.PutProofs(ctx, req.Digest, accepted.Recheck); err != nil {
		r.release(lease)
		return bundle.ResolvedContent{}, storeErr(err)
	}
	return r.commit(t, entry, Acceptance{Key: t.Key, Receipt: accepted.Receipt, Compatibility: compat, AcceptedAt: r.cfg.Now().UTC()}, lease)
}

// Release ends the lease of a resolved handle.
func (r *Resolver) Release(h bundle.ResolvedContent) error { return r.cfg.Cache.Release(h.Lease) }

// Confirm is the adoption guard for a handle resolved earlier: it fails with
// ErrStale unless an acceptance for its bundle and digest exists under the
// revisions current now. Callers check it immediately before applying.
func (r *Resolver) Confirm(h bundle.ResolvedContent) error {
	t, _, err := r.begin(h.Name, h.Digests.OCI)
	if err != nil {
		return err
	}
	acc, ok := r.cfg.Acceptances.Lookup(t.Key)
	if !ok || acc.Receipt.Subject.Digest != h.Digests.OCI {
		return fmt.Errorf("%w: no acceptance for %s@%s under the current revisions", ErrStale, h.Name, h.Digests.OCI)
	}
	return nil
}

// errRetrieve marks a reuse failure that fresh evidence from the registry
// could repair: missing or corrupt retained evidence, or evidence that does
// not satisfy the current rule.
var errRetrieve = errors.New("retrieve fresh evidence")

type retrieveErr struct{ err error }

func (e retrieveErr) Error() string   { return e.err.Error() }
func (e retrieveErr) Unwrap() []error { return []error{e.err, errRetrieve} }

// recheck establishes an acceptance from the cached entry's retained
// evidence under the current rule and trust, without the registry.
func (r *Resolver) recheck(ctx context.Context, t Ticket, src bundle.BundleSource, entry *cache.Entry) (Acceptance, error) {
	rb, err := r.cfg.Cache.Proofs(entry.Digest)
	if errors.Is(err, cache.ErrNoProofs) || errors.Is(err, cache.ErrCorrupt) {
		return Acceptance{}, retrieveErr{fmt.Errorf("%w: %w", ErrProofUnavailable, err)}
	}
	if err != nil {
		return Acceptance{}, err
	}
	layer, err := entry.Layer()
	if err != nil {
		return Acceptance{}, fmt.Errorf("%w: %w", ErrContentUnavailable, err)
	}
	res, err := r.cfg.Verifier.Recheck(ctx, src, rb, layer)
	switch {
	case errors.Is(err, verify.ErrRecheckBundle):
		return Acceptance{}, retrieveErr{fmt.Errorf("%w: %w", ErrProofUnavailable, err)}
	case err != nil:
		// Unreadable or inconsistent trust input: fresh evidence would be
		// judged the same way.
		return Acceptance{}, fmt.Errorf("%w: %w", ErrUntrusted, err)
	case res.Outcome == verify.RecheckInvalid:
		return Acceptance{}, retrieveErr{fmt.Errorf("%w: retained evidence: %w", ErrUntrusted, res.Reason)}
	}
	cur := res.Current // recomputed; the stored receipt is never used
	if res.Outcome == verify.RecheckChanged {
		if err := r.cfg.Cache.PutProofs(ctx, entry.Digest, cur.Recheck); err != nil {
			return Acceptance{}, storeErr(err)
		}
	}
	compat, err := r.compatible(cur.Descriptor)
	if err != nil {
		return Acceptance{}, err
	}
	return Acceptance{Key: t.Key, Receipt: cur.Receipt, Compatibility: compat, AcceptedAt: r.cfg.Now().UTC()}, nil
}

// begin captures generations, then reads the current revisions.
func (r *Resolver) begin(name, digest string) (Ticket, bundle.BundleSource, error) {
	t := r.cfg.Acceptances.Begin(name, digest)
	k, src, err := r.currentKey(name, digest)
	if err != nil {
		return Ticket{}, bundle.BundleSource{}, err
	}
	t.Key = k
	return t, src, nil
}

func (r *Resolver) currentKey(name, digest string) (Key, bundle.BundleSource, error) {
	src, err := r.cfg.Revisions.Source(name)
	if err != nil {
		return Key{}, bundle.BundleSource{}, fmt.Errorf("%w: source %q: %w", ErrConfig, name, err)
	}
	if src.Name != name {
		return Key{}, bundle.BundleSource{}, fmt.Errorf("%w: source for %q is named %q", ErrConfig, name, src.Name)
	}
	rule, err := verify.RuleRevision(src)
	if err != nil {
		return Key{}, bundle.BundleSource{}, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	trust, err := r.cfg.Revisions.Trust(src)
	if err != nil {
		return Key{}, bundle.BundleSource{}, fmt.Errorf("%w: trust revision of %q: %w", ErrConfig, name, err)
	}
	compat, err := r.cfg.Revisions.Compatibility()
	if err != nil {
		return Key{}, bundle.BundleSource{}, fmt.Errorf("%w: compatibility revision: %w", ErrConfig, err)
	}
	return Key{Name: name, Digest: digest, Rule: rule, Trust: trust, Compat: compat}, src, nil
}

// unchanged fails with ErrStale if the revisions moved since t began.
func (r *Resolver) unchanged(t Ticket) error {
	k, _, err := r.currentKey(t.Key.Name, t.Key.Digest)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStale, err)
	}
	if k != t.Key {
		return fmt.Errorf("%w: revisions of %s@%s changed", ErrStale, t.Key.Name, t.Key.Digest)
	}
	return nil
}

// commit records a fresh acceptance unless the configuration changed or the
// result was invalidated since t began, then adopts it.
func (r *Resolver) commit(t Ticket, entry *cache.Entry, acc Acceptance, lease bundle.Lease) (bundle.ResolvedContent, error) {
	if r.afterVerify != nil {
		r.afterVerify()
	}
	if err := r.unchanged(t); err != nil {
		r.release(lease)
		return bundle.ResolvedContent{}, err
	}
	if err := r.cfg.Acceptances.Record(t, acc); err != nil {
		r.release(lease)
		return bundle.ResolvedContent{}, err
	}
	return r.adopt(t, entry, acc, lease)
}

// adopt checks, immediately before returning the handle, that no
// concurrent revision has invalidated the acceptance.
func (r *Resolver) adopt(t Ticket, entry *cache.Entry, acc Acceptance, lease bundle.Lease) (bundle.ResolvedContent, error) {
	if r.beforeAdopt != nil {
		r.beforeAdopt()
	}
	if err := r.unchanged(t); err != nil {
		r.release(lease)
		return bundle.ResolvedContent{}, err
	}
	if err := r.cfg.Acceptances.Valid(t); err != nil {
		r.release(lease)
		return bundle.ResolvedContent{}, err
	}
	a := &bundle.Archive{Descriptor: entry.Descriptor, LayerDigest: entry.LayerDigest, ManifestDigest: entry.Digest}
	h := bundle.NewHandle(a, acc.Compatibility, acc.Receipt, lease)
	if err := h.Validate(); err != nil {
		r.release(lease)
		return bundle.ResolvedContent{}, fmt.Errorf("%w: handle: %w", ErrUnresolved, err)
	}
	return h, nil
}

func (r *Resolver) compatible(d *bundle.Descriptor) (bundle.ContentCompatibility, error) {
	c := r.cfg.Compatible(d)
	if !c.Compatible {
		return c, fmt.Errorf("%w: %s@%s: %v", ErrIncompatible, d.Name, d.Version, c.Reasons)
	}
	return c, nil
}

func (r *Resolver) release(l bundle.Lease) { _ = r.cfg.Cache.Release(l) }

func storeErr(err error) error {
	if errors.Is(err, cache.ErrCapacity) {
		return fmt.Errorf("%w: %w", ErrCapacity, err)
	}
	return fmt.Errorf("%w: storing content: %w", ErrUnresolved, err)
}
