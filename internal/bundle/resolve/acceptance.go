package resolve

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// Key identifies one acceptance decision. Every component is a revision of
// something the decision depends on; a change to any of them makes the old
// decision unreachable:
//
//   - Name and Digest: the bundle (source name) and its OCI manifest digest.
//   - Rule: verify.RuleRevision of the source as configured now. It covers
//     the publisher rule (type, issuer, identity, key and root references,
//     fingerprint, provenance source repository and builder) and excludes
//     the repository (a mirror) and credentials and CA (transport only).
//   - Trust: the revision of the trust material the rule references now (the
//     trusted root or public key object), from Revisions.Trust.
//   - Compat: the controller/provider compatibility revision, from
//     Revisions.Compatibility.
type Key struct {
	Name   string
	Digest string
	Rule   string
	Trust  string
	Compat string
}

// Acceptance is a derived, in-memory decision that a cached bundle may be
// used under the revisions in its Key. It is never persisted: after a
// restart there is none until verification or a recheck of retained
// evidence recomputes it. The receipt is the one recomputed by that
// verification, never one read back from storage.
type Acceptance struct {
	Key           Key
	Receipt       bundle.Receipt
	Compatibility bundle.ContentCompatibility
	AcceptedAt    time.Time
}

// Ticket captures, when a verification begins, the key it verifies for and
// the invalidation generations of everything it depends on. Record and
// Valid refuse it (ErrStale) once any of them has moved.
type Ticket struct {
	Key                    Key
	global, source, digest uint64
}

// Acceptances stores acceptance decisions by Key. It is safe for concurrent
// use.
//
// Invalidation protocol: whoever changes a configuration input must first
// make Revisions return the new value and then call the matching
// Invalidate method. A verification captures generations (Begin) before it
// reads revisions, so either it reads the new revisions or its ticket is
// refused at Record and Valid. Lookups compute the key from current
// revisions, so a decision under old revisions is never found even before it
// is invalidated.
type Acceptances struct {
	mu      sync.Mutex
	global  uint64
	sources map[string]uint64
	digests map[string]uint64
	m       map[Key]Acceptance
}

// NewAcceptances returns an empty store.
func NewAcceptances() *Acceptances {
	return &Acceptances{sources: map[string]uint64{}, digests: map[string]uint64{}, m: map[Key]Acceptance{}}
}

// Begin captures the generations a verification of name@digest depends on.
// Call it before reading the revisions; then fill in the Key's Rule, Trust
// and Compat (its Name and Digest are set).
func (a *Acceptances) Begin(name, digest string) Ticket {
	a.mu.Lock()
	defer a.mu.Unlock()
	return Ticket{Key: Key{Name: name, Digest: digest}, global: a.global, source: a.sources[name], digest: a.digests[digest]}
}

func (a *Acceptances) staleLocked(t Ticket) bool {
	return t.global != a.global || t.source != a.sources[t.Key.Name] || t.digest != a.digests[t.Key.Digest]
}

// Lookup returns the acceptance for exactly k.
func (a *Acceptances) Lookup(k Key) (Acceptance, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	acc, ok := a.m[k]
	return acc, ok
}

// Record commits an acceptance for t.Key unless anything t depends on was
// invalidated since Begin, in which case it records nothing and returns
// ErrStale.
func (a *Acceptances) Record(t Ticket, acc Acceptance) error {
	if acc.Key != t.Key {
		return fmt.Errorf("%w: acceptance key does not match its ticket", ErrStale)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.staleLocked(t) {
		return fmt.Errorf("%w: %s@%s was invalidated during its verification", ErrStale, t.Key.Name, t.Key.Digest)
	}
	a.m[t.Key] = acc
	return nil
}

// Valid is the check before adoption: nothing t depends on was invalidated
// and the acceptance for t.Key is still recorded.
func (a *Acceptances) Valid(t Ticket) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.staleLocked(t) {
		return fmt.Errorf("%w: %s@%s was invalidated before adoption", ErrStale, t.Key.Name, t.Key.Digest)
	}
	if _, ok := a.m[t.Key]; !ok {
		return fmt.Errorf("%w: no acceptance for %s@%s under the current revisions", ErrStale, t.Key.Name, t.Key.Digest)
	}
	return nil
}

// InvalidateSource drops every acceptance for a source name and fails
// verifications of it in flight: use it when the source's rule, its trust
// material, or its presence changes.
func (a *Acceptances) InvalidateSource(name string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sources[name]++
	return a.dropLocked(func(k Key) bool { return k.Name == name })
}

// InvalidateDigest drops every acceptance for a manifest digest and fails
// verifications of it in flight: the cache calls it (Config.OnRemove) when
// the entry is evicted or found corrupt.
func (a *Acceptances) InvalidateDigest(digest string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.digests[digest]++
	return a.dropLocked(func(k Key) bool { return k.Digest == digest })
}

// Invalidate drops the acceptances pred selects (for example one trust
// revision, or one compatibility revision) and, conservatively, fails every
// verification in flight.
func (a *Acceptances) Invalidate(pred func(Key) bool) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.global++
	return a.dropLocked(pred)
}

// InvalidateAll drops every acceptance and fails every verification in
// flight: use it for a compatibility (controller or provider) change.
func (a *Acceptances) InvalidateAll() int {
	return a.Invalidate(func(Key) bool { return true })
}

// Len is the number of recorded acceptances.
func (a *Acceptances) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.m)
}

func (a *Acceptances) dropLocked(pred func(Key) bool) int {
	n := 0
	for k := range a.m {
		if pred(k) {
			delete(a.m, k)
			n++
		}
	}
	return n
}

// Errors. Every resolution failure wraps ErrUnresolved and exactly one of
// the more specific errors below; underlying errors (registry, verifier,
// cache) stay reachable with errors.Is.
var (
	// ErrUnresolved: no current acceptance could be established. Nothing
	// was adopted and no lease is held.
	ErrUnresolved = errors.New("bundle content is unresolved")
	// ErrRequest: the request is malformed.
	ErrRequest = fmt.Errorf("%w: invalid resolution request", ErrUnresolved)
	// ErrConfig: the source is not configured, or a current revision
	// (rule, trust, compatibility) cannot be determined.
	ErrConfig = fmt.Errorf("%w: source configuration unavailable", ErrUnresolved)
	// ErrContentUnavailable: the content is not cached (lost or never
	// stored) and could not be retrieved.
	ErrContentUnavailable = fmt.Errorf("%w: content is not cached and could not be retrieved", ErrUnresolved)
	// ErrProofUnavailable: the content is cached, but complete verification
	// evidence is not retained and could not be retrieved.
	ErrProofUnavailable = fmt.Errorf("%w: verification evidence is not retained and could not be retrieved", ErrUnresolved)
	// ErrUntrusted: the evidence does not satisfy the current source rule
	// and trust material, or the trust material cannot be read, and no
	// evidence that does could be retrieved.
	ErrUntrusted = fmt.Errorf("%w: content does not satisfy current trust", ErrUnresolved)
	// ErrIncompatible: the content is not compatible with the current
	// controller and provider.
	ErrIncompatible = fmt.Errorf("%w: content is incompatible", ErrUnresolved)
	// ErrCapacity: the cache cannot hold the content or its evidence
	// without evicting leased entries.
	ErrCapacity = fmt.Errorf("%w: cache capacity exhausted by leased content", ErrUnresolved)
	// ErrStale: a revision the result depends on changed, or the result
	// was invalidated, between the start of verification and adoption. The
	// caller should resolve again.
	ErrStale = fmt.Errorf("%w: configuration changed during resolution", ErrUnresolved)
)
