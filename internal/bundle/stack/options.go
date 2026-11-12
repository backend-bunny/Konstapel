// Package stack assembles the verified OCI bundle machinery for the
// controller: the content cache, the registry client with its in-cluster
// credential and CA provider, the verifier, the acceptance store, the
// central source Watcher, the resolver and the OCI content source, plus the
// Router that keeps the image's vendored bundle on LocalContent and the
// Pinner that keeps desired, applied and assessed content in the cache.
//
// The feature is off unless Options.SourcesConfigMap is set. Off, nothing
// here is constructed: no cache directory is created, no informer or
// watcher runs and no registry or Kubernetes object is read.
package stack

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/backend-bunny/Konstapel/internal/bundle/cache"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
)

// DefaultRefreshInterval is how often referenced Secrets and ConfigMaps are
// re-read by name (and the transport's object reads are reused at most).
const DefaultRefreshInterval = kubeaccess.DefaultCacheFor

// MaxRefreshInterval bounds the refresh interval (kubeaccess.MaxCacheFor).
const MaxRefreshInterval = kubeaccess.MaxCacheFor

// Options configure the bundle stack. The zero value is disabled.
type Options struct {
	// SourcesConfigMap names the central sources ConfigMap in Namespace.
	// Setting it enables OCI bundle content; empty disables it.
	SourcesConfigMap string
	// Namespace is the controller namespace (POD_NAMESPACE). Required when
	// enabled: the ConfigMap, credentials, CAs and keys are read only there.
	Namespace string
	// CacheDir is the content cache directory, owned exclusively by this
	// process (an emptyDir by default). Required when enabled.
	CacheDir string
	// CacheCapacity bounds the cache in bytes; zero means the cache default
	// (cache.DefaultLimits().CapacityBytes, 1 GiB).
	CacheCapacity int64
	// RefreshInterval is how often referenced objects are re-read; zero
	// means DefaultRefreshInterval. At most MaxRefreshInterval.
	RefreshInterval time.Duration
	// ControllerVersion is the running controller's release (SemVer), for
	// the compatibility check. A version that is not SemVer (a development
	// build) does not fail startup: every OCI bundle is then unavailable as
	// a configuration error, and the vendored bundle is unaffected.
	ControllerVersion string
}

// Enabled reports whether OCI bundle content is configured.
func (o Options) Enabled() bool { return o.SourcesConfigMap != "" }

// Validate checks an enabled configuration. A disabled one is valid only
// when it sets nothing else, so a half-configured feature is a clear startup
// error rather than silently off.
func (o Options) Validate() error {
	if !o.Enabled() {
		if o.CacheDir != "" || o.CacheCapacity != 0 || o.RefreshInterval != 0 {
			return errors.New("bundle cache and refresh settings require the bundle sources ConfigMap to be set")
		}
		return nil
	}
	var errs []error
	if msgs := validation.IsDNS1123Subdomain(o.SourcesConfigMap); len(msgs) > 0 {
		errs = append(errs, fmt.Errorf("bundle sources ConfigMap name %q is invalid: %v", o.SourcesConfigMap, msgs))
	}
	if o.Namespace == "" {
		errs = append(errs, errors.New("bundle sources need the controller namespace (POD_NAMESPACE)"))
	} else if msgs := validation.IsDNS1123Label(o.Namespace); len(msgs) > 0 {
		errs = append(errs, fmt.Errorf("controller namespace %q is invalid: %v", o.Namespace, msgs))
	}
	if o.CacheDir == "" {
		errs = append(errs, errors.New("bundle sources need a cache directory"))
	} else if !filepath.IsAbs(o.CacheDir) {
		errs = append(errs, fmt.Errorf("bundle cache directory %q must be absolute", o.CacheDir))
	}
	if o.CacheCapacity < 0 {
		errs = append(errs, fmt.Errorf("bundle cache capacity %d must not be negative", o.CacheCapacity))
	} else if _, err := o.limits(); err != nil {
		errs = append(errs, fmt.Errorf("bundle cache capacity: %w", err))
	}
	if o.RefreshInterval < 0 || o.RefreshInterval > MaxRefreshInterval {
		errs = append(errs, fmt.Errorf("bundle refresh interval %s must be between 0 and %s", o.RefreshInterval, MaxRefreshInterval))
	}
	return errors.Join(errs...)
}

func (o Options) limits() (cache.Limits, error) {
	lim := cache.DefaultLimits()
	if o.CacheCapacity > 0 {
		lim.CapacityBytes = o.CacheCapacity
	}
	return lim, lim.Validate()
}

func (o Options) refresh() time.Duration {
	if o.RefreshInterval == 0 {
		return DefaultRefreshInterval
	}
	return o.RefreshInterval
}
