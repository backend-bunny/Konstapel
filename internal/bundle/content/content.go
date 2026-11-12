// Package content serves verified OCI bundle content to targeting: OCIContent
// implements targeting.ContentSource over the bundle resolver and content
// cache, so the existing profile, binding and exception code consumes bundles
// from registries exactly as it consumes the vendored LocalContent.
//
// It owns no transport, trust or caching of its own: resolve.Resolver decides
// whether a pinned digest may be used now (current source rule, trust and
// compatibility), and the cache supplies the integrity-checked bytes.
// Targeting keeps rendering, names and revisions; the bundle digest it uses is
// the OCI manifest digest, so a mirror or credential change never creates a
// new revision.
//
// Bundle files are data. Only the files the descriptor names as a policy's
// source (role "policy") are read as policies; tests, upstream fixtures,
// licenses, OSCAL documents and any other file, even one that looks like a
// policy, are never turned into a policy or a resource.
package content

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/cache"
	"github.com/backend-bunny/Konstapel/internal/bundle/resolve"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Resolver resolves pinned digests under a lease. *resolve.Resolver
// implements it.
type Resolver interface {
	Resolve(ctx context.Context, req resolve.Request) (bundle.ResolvedContent, error)
	Release(h bundle.ResolvedContent) error
}

// Entries returns integrity-checked cache entries. *cache.Cache implements it.
type Entries interface {
	Get(ctx context.Context, digest string) (*cache.Entry, error)
}

var (
	_ Resolver = (*resolve.Resolver)(nil)
	_ Entries  = (*cache.Cache)(nil)
)

// readOwnerPrefix names the short-lived lease each Content call takes.
const readOwnerPrefix = "content-read/"

// Config wires an OCIContent.
type Config struct {
	// Resolver and Entries are required, and must share one cache.
	Resolver Resolver
	Entries  Entries
	// Scope classifies matched resources; nil means
	// targeting.StandardWorkloadScopes, as for LocalContent.
	Scope targeting.ScopeFunc
}

// OCIContent is a targeting.ContentSource over resolved OCI bundles. It is
// safe for concurrent use.
type OCIContent struct {
	cfg  Config
	seq  atomic.Uint64
	hook func(point string) // test hook
}

var _ targeting.ContentSource = (*OCIContent)(nil)

// New validates cfg.
func New(cfg Config) (*OCIContent, error) {
	if cfg.Resolver == nil || cfg.Entries == nil {
		return nil, errors.New("content: Resolver and Entries are required")
	}
	if cfg.Scope == nil {
		cfg.Scope = targeting.StandardWorkloadScopes
	}
	return &OCIContent{cfg: cfg}, nil
}

// Content implements targeting.ContentSource. ref.Digest is the OCI manifest
// digest; only exactly that digest, under exactly that name, is served.
//
// The content is resolved under a short-lived lease that is released before
// Content returns, on every path including a panic. The result is a deep
// copy: it references no cache file, so callers hold no lease. Callers that
// must keep the content available across calls (a desired profile, an applied
// contribution, an assessment) hold a Pin.
//
// Errors: a cancelled or expired ctx is returned as such and is not
// ErrContentUnavailable. A resolution outcome or unusable content is a
// *targeting.ContentError (errors.Is(err, targeting.ErrContentUnavailable)).
// Any other error (a closed cache, an internal store failure) is returned
// unclassified.
func (o *OCIContent) Content(ctx context.Context, ref v1alpha1.BundleReference) (c *targeting.Content, err error) {
	h, err := o.resolve(ctx, ref, bundle.HolderProfile, readOwnerPrefix+strconv.FormatUint(o.seq.Add(1), 10))
	if err != nil {
		return nil, err
	}
	defer func() {
		if rerr := o.cfg.Resolver.Release(h); rerr != nil && err == nil {
			c, err = nil, fmt.Errorf("content: releasing the read lease on %s@%s: %w", ref.Name, ref.Digest, rerr)
		}
	}()
	o.at("resolved")
	entry, err := o.cfg.Entries.Get(ctx, ref.Digest)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, contextError(ref, cerr)
		}
		if errors.Is(err, cache.ErrNotFound) || errors.Is(err, cache.ErrCorrupt) {
			return nil, contentError(targeting.ContentErrorContentUnavailable, resolve.ErrContentUnavailable,
				fmt.Sprintf("%s@%s: the resolved entry is no longer intact in the cache", ref.Name, ref.Digest))
		}
		return nil, err
	}
	if entry.Digest != ref.Digest || entry.Descriptor == nil || entry.Descriptor.Name != ref.Name {
		return nil, mismatch(ref, "the cache entry is not the pinned bundle")
	}
	return o.read(ref, entry)
}

// read builds the targeting view from the verified entry.
func (o *OCIContent) read(ref v1alpha1.BundleReference, entry *cache.Entry) (*targeting.Content, error) {
	d := entry.Descriptor
	files := make(map[string]bundle.File, len(d.Files))
	for _, f := range d.Files {
		files[f.Path] = f
	}
	payload := entry.FS()
	// readFile reads one inventoried file with the given role and checks
	// its bytes against the inventory again: the cache verified the tree
	// when it returned the entry, and this closes the window after that.
	readFile := func(path, role string) ([]byte, bundle.File, error) {
		f, ok := files[path]
		if !ok || f.Role != role {
			return nil, f, contentError(targeting.ContentErrorMalformed, nil,
				fmt.Sprintf("%s@%s: %s is not an inventoried %s file", ref.Name, ref.Digest, path, role))
		}
		raw, err := fs.ReadFile(payload, path)
		if err != nil || int64(len(raw)) != f.Size || hexSum(raw) != f.SHA256 {
			return nil, f, contentError(targeting.ContentErrorContentUnavailable, resolve.ErrContentUnavailable,
				fmt.Sprintf("%s@%s: %s no longer matches its verified digest", ref.Name, ref.Digest, path))
		}
		return raw, f, nil
	}

	c := &targeting.Content{
		Bundle:   targeting.Bundle{Name: ref.Name, Digest: ref.Digest, Policies: []targeting.BundlePolicy{}},
		Policies: make(map[string]targeting.PolicySource, len(d.Policies)),
	}
	for _, p := range d.Policies {
		raw, f, err := readFile(p.Path, bundle.RolePolicy)
		if err != nil {
			return nil, err
		}
		m, err := targeting.ParsePolicyManifest(raw)
		if err != nil || m == nil {
			return nil, contentError(targeting.ContentErrorMalformed, nil,
				fmt.Sprintf("%s@%s: policy %s at %s is not a YAML document", ref.Name, ref.Digest, p.Name, p.Path))
		}
		scope, err := targeting.PolicyScopeOf(m, o.cfg.Scope)
		if err != nil {
			// Reported per policy: profiles that do not use it still resolve.
			scope = targeting.ScopeUnsupported
		}
		src := targeting.PolicySource{Manifest: m, SourceDigest: "sha256:" + f.SHA256, ParametersValidated: true}
		if p.ParameterSchema != "" {
			schema, _, err := readFile(p.ParameterSchema, bundle.RoleSchema)
			if err != nil {
				return nil, err
			}
			src.ParameterSchema = schema
		}
		// Parameters stays false: the renderer does not render parameters
		// yet, and parameters it would drop must be rejected (see
		// ValidateParameters).
		c.Bundle.Policies = append(c.Bundle.Policies, targeting.BundlePolicy{Name: p.Name, Scope: scope})
		c.Policies[p.Name] = src
	}
	return c, nil
}

// Pin keeps a resolved bundle in the cache for a long-lived holder
// (bundle.HolderProfile for a desired profile, HolderApplied for the last
// applied contribution, HolderAssessment for an active assessment) until it
// is released. The pin is taken under a current acceptance, exactly as
// Content resolves, and fails the same way.
//
// Pins live in memory only, like cache leases: after a restart none exists,
// and each owner re-establishes its pins from its own state (the desired
// profile, the applied contribution recorded by targeting, the active
// assessment). A pin keeps the bytes; it never authorizes later use, which
// is re-decided by every Content call.
func (o *OCIContent) Pin(ctx context.Context, ref v1alpha1.BundleReference, holder, owner string) (*Pin, error) {
	h, err := o.resolve(ctx, ref, holder, owner)
	if err != nil {
		return nil, err
	}
	return &Pin{Handle: h, release: func() error { return o.cfg.Resolver.Release(h) }}, nil
}

// Pin is a held lease on resolved content.
type Pin struct {
	// Handle is the resolved-content handle, with its receipt and lease.
	Handle  bundle.ResolvedContent
	once    sync.Once
	release func() error
	err     error
}

// Release ends the pin. Later calls return the first result.
func (p *Pin) Release() error {
	p.once.Do(func() { p.err = p.release() })
	return p.err
}

// resolve resolves ref for a lease holder and checks that the handle is
// exactly the pinned bundle; on error no lease is held.
func (o *OCIContent) resolve(ctx context.Context, ref v1alpha1.BundleReference, holder, owner string) (bundle.ResolvedContent, error) {
	if err := ctx.Err(); err != nil {
		return bundle.ResolvedContent{}, contextError(ref, err)
	}
	h, err := o.cfg.Resolver.Resolve(ctx, resolve.Request{Name: ref.Name, Digest: ref.Digest, Holder: holder, Owner: owner})
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return bundle.ResolvedContent{}, contextError(ref, cerr)
		}
		if ce := classify(ref, err); ce != nil {
			return bundle.ResolvedContent{}, ce
		}
		return bundle.ResolvedContent{}, err
	}
	if h.Name != ref.Name || h.Digests.OCI != ref.Digest || h.Lease.Digest != ref.Digest {
		_ = o.cfg.Resolver.Release(h)
		return bundle.ResolvedContent{}, mismatch(ref, fmt.Sprintf("resolved %s@%s", h.Name, h.Digests.OCI))
	}
	return h, nil
}

func (o *OCIContent) at(point string) {
	if o.hook != nil {
		o.hook(point)
	}
}

func mismatch(ref v1alpha1.BundleReference, what string) error {
	return contentError(targeting.ContentErrorDigestMismatch, nil,
		fmt.Sprintf("%s@%s: %s; content is never substituted", ref.Name, ref.Digest, what))
}

// contextError reports the caller's cancellation or deadline. It is not
// ErrContentUnavailable: nothing is known about the content.
func contextError(ref v1alpha1.BundleReference, err error) error {
	return fmt.Errorf("resolving %s@%s: %w", ref.Name, ref.Digest, err)
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ValidateParameters checks a profile policy's parameters against the
// policy's declared contract, for content that declares one
// (src.ParametersValidated, as OCIContent always does). It uses
// bundle.ValidatePolicyParameters' semantics: a policy without a schema
// accepts no parameters, and otherwise the parameters must be a JSON object
// valid against the schema.
//
// For a source without a declared contract (LocalContent) it returns nil:
// such parameters stay governed by targeting's BundlePolicy.Parameters gate
// alone, which rejects them, exactly as before.
//
// Passing this check does not make parameters effective. The renderer does
// not render parameters, so BundlePolicy.Parameters stays false and the
// targeting resolver still rejects any non-empty parameters with
// InvalidConfiguration; this check gives that rejection a precise reason and
// is the contract a parameter renderer will rely on.
func ValidateParameters(src targeting.PolicySource, policy string, params []byte) error {
	if !src.ParametersValidated {
		return nil
	}
	return bundle.ValidatePolicyParameters(policy, src.ParameterSchema, bytes.Clone(params))
}
