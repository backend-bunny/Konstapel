// Package kubeaccess supplies registry credentials and TLS trust for bundle
// sources from Kubernetes objects in the controller's own namespace: a
// kubernetes.io/dockerconfigjson Secret named by BundleSource.CredentialSecret
// and a PEM CA bundle in the ConfigMap or Secret named by BundleSource.CA.
//
// Provider implements registry.CredentialProvider and
// registry.TransportProvider. It reads objects one at a time by name through
// an ObjectReader (no list, no watch, no other namespace), never executes
// credential helpers, offers a credential only for the source's own registry
// host, and never falls back to anonymous access or to system-only trust when
// a configured object is missing or invalid.
//
// Freshness: an object read is reused for at most Options.CacheFor (30 s by
// default). The caller that watches Secrets and ConfigMaps (the controller,
// not yet wired) calls Invalidate(kind, name) on every change or deletion, so
// the next retrieval re-reads at once. When the credential a source resolves
// to changes or disappears, the provider calls ResetTokens for that source on
// the bound registry.Client before returning, so cached bearer tokens
// obtained with the old credential are never used by a later retrieval. When
// a CA bundle changes, the source's transport is rebuilt and the old one's
// idle connections are closed.
package kubeaccess

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

// Cache bounds for object reads.
const (
	DefaultCacheFor = 30 * time.Second
	MaxCacheFor     = 5 * time.Minute
)

// TokenResetter discards cached registry tokens for a source;
// *registry.Client implements it.
type TokenResetter interface {
	ResetTokens(src bundle.BundleSource)
}

// Options configures a Provider.
type Options struct {
	// Reader reads objects in the controller namespace. Required.
	Reader ObjectReader
	// CacheFor bounds how long an object read is reused without an
	// Invalidate call: zero means DefaultCacheFor, a negative value disables
	// reuse, and more than MaxCacheFor is rejected.
	CacheFor time.Duration
	// SystemRoots returns the system trust pool that custom CAs are added
	// to; nil uses x509.SystemCertPool. A failure makes sources with a CA
	// unavailable rather than trusting only their extra roots.
	SystemRoots func() (*x509.CertPool, error)
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
}

// Provider resolves credentials and transports for bundle sources. It is
// safe for concurrent use.
type Provider struct {
	reader      ObjectReader
	cacheFor    time.Duration
	systemRoots func() (*x509.CertPool, error)
	now         func() time.Time
	base        *http.Transport // system roots only, for sources without a CA

	mu         sync.Mutex
	resetter   TokenResetter
	objects    map[string]*objectEntry
	locks      map[string]*sync.Mutex
	creds      map[string][sha256.Size]byte
	transports map[string]*transportEntry
}

type objectEntry struct {
	mu      sync.Mutex
	gen     uint64 // bumped by Invalidate; guarded by Provider.mu
	readGen uint64 // gen when obj was read; guarded by mu
	obj     Object
	readAt  time.Time
	valid   bool
}

type transportEntry struct {
	sum [sha256.Size]byte
	t   *http.Transport
}

// New returns a Provider. Bind it to the registry.Client that uses it (or
// build both with NewClient) before use.
func New(opts Options) (*Provider, error) {
	if opts.Reader == nil {
		return nil, errors.New("kubeaccess: an ObjectReader is required")
	}
	switch {
	case opts.CacheFor == 0:
		opts.CacheFor = DefaultCacheFor
	case opts.CacheFor > MaxCacheFor:
		return nil, fmt.Errorf("kubeaccess: CacheFor %s exceeds %s", opts.CacheFor, MaxCacheFor)
	}
	if opts.SystemRoots == nil {
		opts.SystemRoots = x509.SystemCertPool
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Provider{
		reader: opts.Reader, cacheFor: opts.CacheFor, systemRoots: opts.SystemRoots, now: opts.Now,
		base:       newTransport(nil, nil),
		objects:    map[string]*objectEntry{},
		locks:      map[string]*sync.Mutex{},
		creds:      map[string][sha256.Size]byte{},
		transports: map[string]*transportEntry{},
	}, nil
}

// NewClient builds a registry.Client whose credentials and transports come
// from p, and binds p to it. opts.Credentials, opts.Transport and
// opts.Transports must be unset.
func NewClient(p *Provider, opts registry.Options) (*registry.Client, error) {
	if opts.Credentials != nil || opts.Transport != nil || opts.Transports != nil {
		return nil, fmt.Errorf("%w: credentials and transports come from the provider", registry.ErrInvalidRequest)
	}
	opts.Credentials, opts.Transports = p, p
	c, err := registry.NewClient(opts)
	if err != nil {
		return nil, err
	}
	p.Bind(c)
	return c, nil
}

// Bind sets the client whose token caches are reset on rotation. Until a
// resetter is bound, Credential fails for every source with a
// credentialSecret.
func (p *Provider) Bind(r TokenResetter) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resetter = r
}

// Invalidate makes the next use of kind/name re-read it. Call it whenever
// a watched Secret or ConfigMap changes or is deleted.
func (p *Provider) Invalidate(kind, name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.objects[kind+"/"+name]; ok {
		e.gen++
	}
}

// InvalidateAll makes the next use of every object re-read it, for example
// after a watch restarts.
func (p *Provider) InvalidateAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.objects {
		e.gen++
	}
}

// Close closes the idle connections of every transport.
func (p *Provider) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.base.CloseIdleConnections()
	for _, e := range p.transports {
		e.t.CloseIdleConnections()
	}
}

// lock serializes resolution per source, so that reading an object,
// comparing it with the last credential and resetting tokens happen in
// order: a slower, older read can never replace a newer credential.
func (p *Provider) lock(key string) func() {
	p.mu.Lock()
	l, ok := p.locks[key]
	if !ok {
		l = &sync.Mutex{}
		p.locks[key] = l
	}
	p.mu.Unlock()
	l.Lock()
	return l.Unlock
}

// read returns kind/name, reusing a read younger than cacheFor that has not
// been invalidated since it started.
func (p *Provider) read(ctx context.Context, kind, name string) (Object, error) {
	id := kind + "/" + name
	p.mu.Lock()
	e, ok := p.objects[id]
	if !ok {
		e = &objectEntry{}
		p.objects[id] = e
	}
	p.mu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	p.mu.Lock()
	gen := e.gen
	p.mu.Unlock()
	if e.valid && e.readGen == gen && p.cacheFor > 0 && p.now().Sub(e.readAt) < p.cacheFor {
		return e.obj, nil
	}
	obj, err := p.reader.Get(ctx, kind, name)
	if err != nil {
		e.valid, e.obj = false, Object{}
		return Object{}, err
	}
	// An Invalidate during the read bumped gen, so this result is used once
	// and re-read next time.
	e.obj, e.readAt, e.valid, e.readGen = obj, p.now(), true, gen
	return obj, nil
}

// sourceKey identifies a source together with its references.
func sourceKey(src bundle.BundleSource) string {
	ref := func(r *bundle.ObjectRef) string {
		if r == nil {
			return ""
		}
		return r.Kind + "/" + r.Name + "/" + r.Key
	}
	return src.Name + "\x00" + src.Repository + "\x00" + ref(src.CredentialSecret) + "\x00" + ref(src.CA)
}

func registryHost(repository string) string {
	host, _, _ := strings.Cut(repository, "/")
	return host
}

// Credential implements registry.CredentialProvider. A source without a
// credentialSecret gets the zero (anonymous) credential. Otherwise the
// referenced Secret must exist, be of type kubernetes.io/dockerconfigjson,
// hold the key, and contain exactly one auths entry for the source's
// registry host; anything else is an error wrapping registry.ErrCredentials,
// never an anonymous credential or a previously read one.
func (p *Provider) Credential(ctx context.Context, src bundle.BundleSource, host string) (registry.Credential, error) {
	ref := src.CredentialSecret
	if ref == nil {
		return registry.Credential{}, nil
	}
	if want := registryHost(src.Repository); host != want {
		return registry.Credential{}, fmt.Errorf("%w: credential requested for a host other than the source's registry", registry.ErrCredentials)
	}
	if ref.Kind != "" && ref.Kind != bundle.KindSecret {
		return registry.Credential{}, fmt.Errorf("%w: credentialSecret must be a Secret", registry.ErrCredentials)
	}
	p.mu.Lock()
	resetter := p.resetter
	p.mu.Unlock()
	if resetter == nil {
		return registry.Credential{}, fmt.Errorf("%w: the credential provider is not bound to a registry client", registry.ErrCredentials)
	}

	key := sourceKey(src)
	defer p.lock(key)()
	cred, err := p.resolveCredential(ctx, ref, host)

	p.mu.Lock()
	prev, had := p.creds[key]
	if err != nil {
		delete(p.creds, key)
	} else {
		p.creds[key] = credentialSum(cred)
	}
	p.mu.Unlock()
	// Reset before returning: tokens cached for the old credential (or for a
	// removed one) must not serve any later request.
	if had && (err != nil || prev != credentialSum(cred)) {
		resetter.ResetTokens(src)
	}
	if err != nil {
		return registry.Credential{}, err
	}
	return cred, nil
}

func (p *Provider) resolveCredential(ctx context.Context, ref *bundle.ObjectRef, host string) (registry.Credential, error) {
	dataKey := ref.Key
	if dataKey == "" {
		dataKey = bundle.DefaultCredentialKey
	}
	obj, err := p.read(ctx, bundle.KindSecret, ref.Name)
	if err != nil {
		return registry.Credential{}, fmt.Errorf("%w: credentialSecret %q: %w", registry.ErrCredentials, ref.Name, err)
	}
	if obj.Type() != string(corev1.SecretTypeDockerConfigJson) {
		return registry.Credential{}, fmt.Errorf("%w: credentialSecret %q has type %q, want %q",
			registry.ErrCredentials, ref.Name, obj.Type(), corev1.SecretTypeDockerConfigJson)
	}
	doc, ok := obj.Value(dataKey)
	if !ok {
		return registry.Credential{}, fmt.Errorf("%w: credentialSecret %q has no key %q", registry.ErrCredentials, ref.Name, dataKey)
	}
	cred, err := CredentialForHost(doc, host)
	if err != nil {
		return registry.Credential{}, fmt.Errorf("credentialSecret %q key %q: %w", ref.Name, dataKey, err)
	}
	return cred, nil
}

// credentialSum fingerprints a credential for change detection only; it is
// never logged or returned.
func credentialSum(c registry.Credential) [sha256.Size]byte {
	h := sha256.New()
	for _, v := range []string{c.Username, c.Password, c.IdentityToken, c.RegistryToken} {
		fmt.Fprintf(h, "%d:%s\x00", len(v), v)
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Transport implements registry.TransportProvider. A source without a CA
// uses a shared transport with the system roots. A source with a CA gets
// its own transport trusting the system roots plus the referenced
// certificates, rebuilt when they change; another source never shares it. A
// missing or invalid CA object is an error wrapping registry.ErrTrustConfig
// and drops the source's transport: there is no fallback to system-only
// trust.
func (p *Provider) Transport(ctx context.Context, src bundle.BundleSource) (http.RoundTripper, error) {
	key := sourceKey(src)
	defer p.lock(key)()
	if src.CA == nil {
		p.dropTransport(key)
		return p.base, nil
	}
	t, err := p.resolveTransport(ctx, key, src.CA)
	if err != nil {
		p.dropTransport(key)
		return nil, err
	}
	return t, nil
}

func (p *Provider) resolveTransport(ctx context.Context, key string, ref *bundle.ObjectRef) (http.RoundTripper, error) {
	if ref.Kind != bundle.KindConfigMap && ref.Kind != bundle.KindSecret {
		return nil, fmt.Errorf("%w: ca kind %q must be ConfigMap or Secret", registry.ErrTrustConfig, ref.Kind)
	}
	dataKey := ref.Key
	if dataKey == "" {
		dataKey = bundle.DefaultCAKey
	}
	obj, err := p.read(ctx, ref.Kind, ref.Name)
	if err != nil {
		return nil, fmt.Errorf("%w: ca %s %q: %w", registry.ErrTrustConfig, ref.Kind, ref.Name, err)
	}
	pemData, ok := obj.Value(dataKey)
	if !ok {
		return nil, fmt.Errorf("%w: ca %s %q has no key %q", registry.ErrTrustConfig, ref.Kind, ref.Name, dataKey)
	}
	certs, err := ParseCABundle(pemData)
	if err != nil {
		return nil, fmt.Errorf("ca %s %q key %q: %w", ref.Kind, ref.Name, dataKey, err)
	}
	sum := sha256.Sum256(pemData)

	p.mu.Lock()
	cur, ok := p.transports[key]
	p.mu.Unlock()
	if ok && cur.sum == sum {
		return cur.t, nil
	}
	roots, err := p.systemRoots()
	if err != nil || roots == nil {
		return nil, fmt.Errorf("%w: the system roots are unavailable; custom CAs are added to them, never used alone", registry.ErrTrustConfig)
	}
	t := newTransport(roots, certs)
	p.mu.Lock()
	p.transports[key] = &transportEntry{sum: sum, t: t}
	p.mu.Unlock()
	if ok {
		cur.t.CloseIdleConnections()
	}
	return t, nil
}

func (p *Provider) dropTransport(key string) {
	p.mu.Lock()
	cur, ok := p.transports[key]
	delete(p.transports, key)
	p.mu.Unlock()
	if ok {
		cur.t.CloseIdleConnections()
	}
}
