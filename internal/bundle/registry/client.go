// Package registry retrieves a pinned policy bundle and the proof artifacts
// attached to it from an OCI registry, strictly by digest and within fixed
// limits. It uses ORAS Go for the OCI distribution protocol and its standard
// registry challenge/token handling.
//
// The adapter never resolves a tag to select content, verifies every byte it
// downloads against its digest, and rejects indexes and unexpected layouts.
// Proofs are listed through the OCI 1.1 referrers API or, when a registry does
// not serve it, the OCI referrers tag schema index; either listing is treated
// as unauthenticated and every entry is fetched by digest and checked. It
// reports which proofs it found but does not decide trust: signature and
// provenance verification are separate steps.
//
// Transport and credentials are injected (Options.Transport,
// Options.Credentials) so that Secret-backed credentials and custom CA pools
// can be supplied without changing retrieval. The package is not yet wired
// into the controller.
package registry

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/opencontainers/go-digest"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// Credential is a registry credential for one host. A zero Credential means
// anonymous access. Its values never appear in errors or logs.
type Credential struct {
	Username      string
	Password      string
	IdentityToken string // OAuth2 refresh token
	RegistryToken string // bearer access token
}

// String redacts the credential.
func (Credential) String() string { return "Credential{redacted}" }

// GoString redacts the credential for %#v.
func (Credential) GoString() string { return "registry.Credential{redacted}" }

func (c Credential) empty() bool { return c == Credential{} }

// CredentialProvider supplies the credential for a source. It is asked only
// for the registry host of src.Repository, never for a token realm or any
// other origin. When src.CredentialSecret is set, the provider must return a
// non-empty credential or an error; retrieval then fails without an anonymous
// attempt. Errors must not contain credential values.
type CredentialProvider interface {
	Credential(ctx context.Context, src bundle.BundleSource, host string) (Credential, error)
}

// Options configures a Client.
type Options struct {
	// Transport performs HTTP exchanges; nil uses a clone of
	// http.DefaultTransport (system roots). A transport that disables TLS
	// verification is rejected. Custom CA pools are configured here.
	Transport http.RoundTripper
	// Credentials supplies registry credentials; nil means anonymous only, and
	// a source with a credentialSecret then fails with ErrCredentials.
	Credentials CredentialProvider
	// Limits; zero fields take DefaultLimits.
	Limits Limits
	// TestOnlyPlainHTTP speaks plain HTTP to the registry and permits
	// loopback token realms. It exists solely for in-process test fixtures
	// and must never be set by production configuration.
	TestOnlyPlainHTTP bool
}

// Client retrieves pinned bundles. It is safe for concurrent use; concurrent
// requests for the same source and digest share one retrieval.
type Client struct {
	transport http.RoundTripper
	creds     CredentialProvider
	limits    Limits
	plainHTTP bool
	slots     chan struct{}

	mu       sync.Mutex
	inflight map[string]*call
	caches   map[string]auth.Cache
}

// NewClient validates opts and returns a Client.
func NewClient(opts Options) (*Client, error) {
	limits, err := opts.Limits.withDefaults()
	if err != nil {
		return nil, err
	}
	t := opts.Transport
	if t == nil {
		t = http.DefaultTransport.(*http.Transport).Clone()
	}
	if ht, ok := t.(*http.Transport); ok && ht.TLSClientConfig != nil && ht.TLSClientConfig.InsecureSkipVerify {
		return nil, fmt.Errorf("%w: TLS verification must not be disabled", ErrInvalidRequest)
	}
	return &Client{
		transport: t,
		creds:     opts.Credentials,
		limits:    limits,
		plainHTTP: opts.TestOnlyPlainHTTP,
		slots:     make(chan struct{}, limits.MaxConcurrentResolutions),
		inflight:  map[string]*call{},
		caches:    map[string]auth.Cache{},
	}, nil
}

// Limits returns the effective limits.
func (c *Client) Limits() Limits { return c.limits }

// call is one shared in-flight retrieval.
type call struct {
	done    chan struct{}
	res     *Result
	err     error
	waiters int
	cancel  context.CancelFunc
}

// sourceKey identifies the source and the credential it would use, so two
// requests are shared (and tokens cached) only when they would authenticate
// identically.
func sourceKey(src bundle.BundleSource) string {
	secret := ""
	if s := src.CredentialSecret; s != nil {
		secret = s.Kind + "/" + s.Name + "/" + s.Key
	}
	return src.Name + "\x00" + src.Repository + "\x00" + secret
}

// Fetch retrieves the manifest pinned by manifestDigest from src.Repository,
// its bundle layer and the proofs that refer to it. The only tag it reads is
// the subject's referrers tag schema index, as an untrusted listing.
//
// Concurrent calls for the same source and digest share one retrieval. A
// caller whose ctx ends stops waiting and gets ctx's error; the shared work
// continues for the remaining waiters and is canceled only when the last
// waiter leaves. At most Limits.MaxConcurrentResolutions retrievals run at
// once; each attempt is bounded by Limits.ResolutionTimeout after it starts.
// The work runs on its own goroutine, so callers such as reconcilers can
// bound their wait with ctx without blocking on the network.
func (c *Client) Fetch(ctx context.Context, src bundle.BundleSource, manifestDigest string) (*Result, error) {
	if err := bundle.ValidateRepository(src.Repository); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	d, err := digest.Parse(manifestDigest)
	if err != nil || d.Algorithm() != digest.SHA256 || d.String() != strings.ToLower(manifestDigest) {
		return nil, fmt.Errorf("%w: manifest digest %q must be sha256:<64 lowercase hex>", ErrInvalidRequest, manifestDigest)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	key := sourceKey(src) + "\x00" + d.String()
	c.mu.Lock()
	cl, ok := c.inflight[key]
	if ok {
		cl.waiters++
	} else {
		// The work is detached from the first caller's cancellation (but keeps
		// its values); it ends when every waiter has left.
		work, cancel := context.WithCancel(context.WithoutCancel(ctx))
		cl = &call{done: make(chan struct{}), waiters: 1, cancel: cancel}
		c.inflight[key] = cl
		go c.run(work, key, cl, src, d)
	}
	c.mu.Unlock()

	select {
	case <-cl.done:
		return cl.res, cl.err
	case <-ctx.Done():
		c.mu.Lock()
		cl.waiters--
		if cl.waiters == 0 {
			cl.cancel()
			if c.inflight[key] == cl {
				delete(c.inflight, key)
			}
		}
		c.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (c *Client) run(ctx context.Context, key string, cl *call, src bundle.BundleSource, d digest.Digest) {
	defer cl.cancel()
	res, err := c.acquireAndRetrieve(ctx, src, d)
	c.mu.Lock()
	if c.inflight[key] == cl {
		delete(c.inflight, key)
	}
	cl.res, cl.err = res, err
	c.mu.Unlock()
	close(cl.done)
}

func (c *Client) acquireAndRetrieve(ctx context.Context, src bundle.BundleSource, d digest.Digest) (*Result, error) {
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(ctx, c.limits.ResolutionTimeout)
	defer cancel()
	return c.retrieve(ctx, src, d)
}

// ResetTokens discards cached registry tokens and challenge state for src,
// for example after its credential Secret rotates. Later requests
// authenticate afresh.
func (c *Client) ResetTokens(src bundle.BundleSource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.caches, sourceKey(src))
}

func (c *Client) tokenCache(src bundle.BundleSource) auth.Cache {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := sourceKey(src)
	cache, ok := c.caches[k]
	if !ok {
		cache = auth.NewCache()
		c.caches[k] = cache
	}
	return cache
}

// credentialFunc answers ORAS only for the source's own registry host.
func (c *Client) credentialFunc(src bundle.BundleSource, host string, rec *secrets) auth.CredentialFunc {
	return func(ctx context.Context, hostport string) (auth.Credential, error) {
		if hostport != host || c.creds == nil {
			return auth.EmptyCredential, nil
		}
		cred, err := c.creds.Credential(ctx, src, host)
		if err != nil {
			return auth.EmptyCredential, fmt.Errorf("%w for source %q", ErrCredentials, src.Name)
		}
		rec.addCredential(cred)
		return auth.Credential{
			Username: cred.Username, Password: cred.Password,
			RefreshToken: cred.IdentityToken, AccessToken: cred.RegistryToken,
		}, nil
	}
}

// preflightCredential fails before any request when a configured credential
// is unavailable, so a public registry is never accessed anonymously instead.
func (c *Client) preflightCredential(ctx context.Context, src bundle.BundleSource, host string, rec *secrets) error {
	if src.CredentialSecret == nil {
		return nil
	}
	if c.creds == nil {
		return fmt.Errorf("%w: source %q references a credential Secret but no provider is configured", ErrCredentials, src.Name)
	}
	cred, err := c.creds.Credential(ctx, src, host)
	if err != nil {
		return fmt.Errorf("%w for source %q", ErrCredentials, src.Name)
	}
	rec.addCredential(cred)
	if cred.empty() {
		return fmt.Errorf("%w: source %q has an empty credential", ErrCredentials, src.Name)
	}
	return nil
}
