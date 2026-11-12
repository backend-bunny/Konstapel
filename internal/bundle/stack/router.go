package stack

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle/resolve"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// memoSize bounds the content memo (distinct name@digest pairs).
const memoSize = 16

// maxDetail bounds a ContentError detail, as the content package does.
const maxDetail = 512

// Router is the targeting.ContentSource the controller hands to every
// consumer (profile, binding and assessment reconcilers and the exception
// admission webhooks). The bundle name of the image's vendored content is
// always served by the local source, exactly as before; it is not a source
// name in the central configuration, so the two never collide, and its
// digest is the sha256 of content/SHA256SUMS, not an OCI manifest digest.
// Every other name goes to the OCI content source when bundle sources are
// enabled, and is a Config ContentError ("no source is configured") when
// they are not.
//
// Successful OCI results are memoized per name@digest (bounded) and served
// again only while Confirm passes: an acceptance for exactly that name and
// digest exists under the revisions current now. Every invalidation (source,
// rule, trust or compatibility change, configuration loss, cache removal)
// makes Confirm fail, and the entry is dropped and resolved again, so the
// memo never serves content past an invalidation.
type Router struct {
	local     targeting.ContentSource
	localName string
	oci       targeting.ContentSource // nil when disabled
	confirm   func(name, digest string) error

	mu    sync.Mutex
	memo  map[string]*targeting.Content
	order []string // least recently used first
}

var _ targeting.ContentSource = (*Router)(nil)

// NewRouter returns the router of a controller without bundle sources:
// only localName is served.
func NewRouter(local targeting.ContentSource, localName string) *Router {
	return newRouter(local, localName, nil, nil)
}

func newRouter(local targeting.ContentSource, localName string, oci targeting.ContentSource, confirm func(name, digest string) error) *Router {
	return &Router{local: local, localName: localName, oci: oci, confirm: confirm, memo: map[string]*targeting.Content{}}
}

// Enabled reports whether non-vendored names are served from OCI content.
func (r *Router) Enabled() bool { return r.oci != nil }

// LocalName is the vendored bundle name.
func (r *Router) LocalName() string { return r.localName }

// Content implements targeting.ContentSource.
func (r *Router) Content(ctx context.Context, ref v1alpha1.BundleReference) (*targeting.Content, error) {
	if ref.Name == r.localName {
		return r.local.Content(ctx, ref)
	}
	if r.oci == nil {
		return nil, notConfigured(ref)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("resolving %s@%s: %w", ref.Name, ref.Digest, err)
	}
	key := ref.Name + "@" + ref.Digest
	if c, ok := r.lookup(key); ok {
		if r.confirm(ref.Name, ref.Digest) == nil {
			return copyContent(c), nil
		}
		r.drop(key)
	}
	c, err := r.oci.Content(ctx, ref)
	if err != nil {
		r.drop(key)
		return nil, err
	}
	r.store(key, copyContent(c))
	return c, nil
}

// Confirm is the adoption guard a caller runs immediately before applying
// content it read earlier: nil for the vendored bundle (its bytes are in the
// image and nothing revokes them), the resolver's Confirm for OCI content
// (resolve.ErrStale unless an acceptance for exactly ref exists under the
// current revisions), and the Config error when bundle sources are off.
func (r *Router) Confirm(_ context.Context, ref v1alpha1.BundleReference) error {
	switch {
	case ref.Name == r.localName:
		return nil
	case r.oci == nil:
		return notConfigured(ref)
	}
	return r.confirm(ref.Name, ref.Digest)
}

func (r *Router) lookup(key string) (*targeting.Content, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.memo[key]
	if ok {
		r.touch(key)
	}
	return c, ok
}

func (r *Router) store(key string, c *targeting.Content) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.memo[key] = c
	r.touch(key)
	for len(r.order) > memoSize {
		delete(r.memo, r.order[0])
		r.order = r.order[1:]
	}
}

func (r *Router) drop(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.memo, key)
	r.order = slices.DeleteFunc(r.order, func(k string) bool { return k == key })
}

// touch moves key to the most recently used end; r.mu is held.
func (r *Router) touch(key string) {
	r.order = append(slices.DeleteFunc(r.order, func(k string) bool { return k == key }), key)
}

// memoLen reports the number of memoized entries (tests).
func (r *Router) memoLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.memo)
}

func notConfigured(ref v1alpha1.BundleReference) error {
	detail := fmt.Sprintf("%s@%s: no source is configured: OCI bundle sources are not enabled in this controller", ref.Name, ref.Digest)
	if len(detail) > maxDetail {
		detail = detail[:maxDetail-3] + "..."
	}
	return &targeting.ContentError{Class: targeting.ContentErrorConfig, Detail: detail, Err: resolve.ErrConfig}
}

// copyContent returns a deep copy, so no caller can change what the memo
// serves to the next one.
func copyContent(c *targeting.Content) *targeting.Content {
	out := &targeting.Content{
		Bundle:   targeting.Bundle{Name: c.Bundle.Name, Digest: c.Bundle.Digest, Policies: slices.Clone(c.Bundle.Policies)},
		Policies: make(map[string]targeting.PolicySource, len(c.Policies)),
	}
	for _, name := range slices.Sorted(maps.Keys(c.Policies)) {
		p := c.Policies[name]
		p.Manifest, _ = copyValue(p.Manifest).(map[string]any)
		p.ParameterSchema = slices.Clone(p.ParameterSchema)
		out.Policies[name] = p
	}
	return out
}

func copyValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		if x == nil {
			return x
		}
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = copyValue(e)
		}
		return m
	case []any:
		if x == nil {
			return x
		}
		s := make([]any, len(x))
		for i, e := range x {
			s[i] = copyValue(e)
		}
		return s
	default:
		// JSON scalars (string, float64, int64, bool, nil) are values.
		return x
	}
}
