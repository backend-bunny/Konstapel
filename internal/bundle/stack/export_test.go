package stack

import (
	"time"

	"github.com/backend-bunny/Konstapel/internal/targeting"

	"github.com/backend-bunny/Konstapel/internal/bundle/resolve"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
)

// Test seams, visible to this package's tests and to stack_test.

// WithTestFetcher replaces the registry client as the resolver's fetcher.
func WithTestFetcher(d Deps, f resolve.Fetcher) Deps { d.fetcher = f; return d }

// WithTestClock fixes the verifier's, resolver's and cache's clock.
func WithTestClock(d Deps, now func() time.Time) Deps {
	d.now = now
	d.verifyOptions = append(d.verifyOptions, verify.WithClock(now))
	return d
}

// WithTestProviders replaces the installed provider allowlist.
func WithTestProviders(d Deps, providers ...string) Deps { d.providers = providers; return d }

// NewTestRouter is the router over any OCI content source and adoption
// guard, for content the signed fixtures cannot carry.
func NewTestRouter(local targeting.ContentSource, localName string, oci targeting.ContentSource, confirm func(name, digest string) error) *Router {
	return newRouter(local, localName, oci, confirm)
}

// MemoLen reports the router's memoized entries.
func (r *Router) MemoLen() int { return r.memoLen() }

// SetPassHook makes Start report each completed pass on ch.
func (p *Pinner) SetPassHook(ch chan struct{}) { p.passes = ch }
