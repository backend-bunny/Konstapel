package stack

import (
	"context"
	"errors"
	"fmt"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/cache"
	"github.com/backend-bunny/Konstapel/internal/bundle/content"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
	"github.com/backend-bunny/Konstapel/internal/bundle/resolve"
	"github.com/backend-bunny/Konstapel/internal/bundle/sources"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Deps are the cluster readers the stack uses.
type Deps struct {
	// APIReader is the manager's uncached API reader. It is used only to
	// get referenced Secrets and ConfigMaps by name in the controller
	// namespace (credentials, CAs, public keys, trusted roots), so the
	// controller needs "get" on exactly those objects and no list or watch.
	APIReader client.Reader
	// Config reads the sources ConfigMap: a cache built with
	// sources.ConfigMapCacheOptions, which holds only that object.
	Config client.Reader

	// Test seams, set through export_test.go only.
	fetcher       resolve.Fetcher
	verifyOptions []verify.Option
	now           func() time.Time
}

// Stack is the assembled machinery. Every part is safe for concurrent use.
type Stack struct {
	Options       Options
	Cache         *cache.Cache
	Acceptances   *resolve.Acceptances
	Provider      *kubeaccess.Provider
	Registry      *registry.Client
	Watcher       *sources.Watcher
	Resolver      *resolve.Resolver
	Content       *content.OCIContent
	Compatibility content.Compatibility
}

// New assembles the stack for an enabled, valid configuration. It opens the
// content cache last, so a configuration error creates nothing on disk; a
// cache that cannot be opened (an unwritable directory, or another process
// holding its lock) fails startup with that reason.
func New(opts Options, deps Deps) (*Stack, error) {
	if !opts.Enabled() {
		return nil, errors.New("bundle stack: bundle sources are not enabled")
	}
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if deps.APIReader == nil || deps.Config == nil {
		return nil, errors.New("bundle stack: the API reader and the sources ConfigMap reader are required")
	}
	objects, err := kubeaccess.NewClientReader(deps.APIReader, opts.Namespace)
	if err != nil {
		return nil, err
	}
	provider, err := kubeaccess.New(kubeaccess.Options{Reader: objects, CacheFor: opts.refresh()})
	if err != nil {
		return nil, err
	}
	reg, err := kubeaccess.NewClient(provider, registry.Options{})
	if err != nil {
		provider.Close()
		return nil, err
	}
	var fetcher resolve.Fetcher = reg
	if deps.fetcher != nil {
		fetcher = deps.fetcher
	}
	verifier, err := verify.New(objects, deps.verifyOptions...)
	if err != nil {
		provider.Close()
		return nil, err
	}
	acc := resolve.NewAcceptances()
	compat := content.Compatibility{Controller: opts.ControllerVersion}
	watcher, err := sources.New(sources.Options{
		Namespace: opts.Namespace, Name: opts.SourcesConfigMap,
		Config: deps.Config, Objects: objects, Acceptances: acc, Transport: provider,
		Compatibility: compat.Revision, Interval: opts.refresh(),
	})
	if err != nil {
		provider.Close()
		return nil, err
	}
	lim, err := opts.limits()
	if err != nil {
		provider.Close()
		return nil, err
	}
	// An entry removed by eviction or found corrupt drops its acceptances,
	// so nothing is served from a decision about bytes that are gone.
	c, err := cache.Open(opts.CacheDir, cache.Config{Limits: lim, OnRemove: onRemove(acc), Now: deps.now})
	if err != nil {
		provider.Close()
		return nil, fmt.Errorf("bundle cache %s: %w", opts.CacheDir, err)
	}
	r, err := resolve.New(resolve.Config{Cache: c, Fetcher: fetcher, Verifier: verifier, Acceptances: acc,
		Revisions: watcher, Compatible: compat.Check, Now: deps.now})
	if err != nil {
		c.Close()
		provider.Close()
		return nil, err
	}
	oci, err := content.New(content.Config{Resolver: r, Entries: c})
	if err != nil {
		c.Close()
		provider.Close()
		return nil, err
	}
	return &Stack{Options: opts, Cache: c, Acceptances: acc, Provider: provider, Registry: reg, Watcher: watcher,
		Resolver: r, Content: oci, Compatibility: compat}, nil
}

// onRemove is the cache's removal callback. It is a separate function so a
// test can prove the wiring by removing an entry.
func onRemove(acc *resolve.Acceptances) func(string) {
	return func(digest string) { acc.InvalidateDigest(digest) }
}

// CompatibilityProblem explains why the controller version cannot satisfy
// any bundle's compatibility check (a development build that is not
// SemVer), or returns nil. Startup logs it; it is not fatal.
func (s *Stack) CompatibilityProblem() error { return s.Compatibility.Validate() }

// Close releases the cache lock and idle registry connections. The
// controller does not call it (the process exit releases both); tests and
// failed startups do.
func (s *Stack) Close() error {
	s.Provider.Close()
	return s.Cache.Close()
}

// Router returns the content source every consumer uses: local serves
// localName exactly as before, everything else is this stack's OCI content.
func (s *Stack) Router(local targeting.ContentSource, localName string) *Router {
	return newRouter(local, localName, s.Content, func(name, digest string) error {
		return s.Resolver.Confirm(bundle.ResolvedContent{Name: name, Digests: bundle.Digests{OCI: digest}})
	})
}

// Pin pins ref for a holder through the OCI content source. It is the
// Pinner's PinFunc.
func (s *Stack) Pin(ctx context.Context, ref v1alpha1.BundleReference, holder, owner string) (func() error, error) {
	p, err := s.Content.Pin(ctx, ref, holder, owner)
	if err != nil {
		return nil, err
	}
	return p.Release, nil
}
