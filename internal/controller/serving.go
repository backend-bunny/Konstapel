package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sync/atomic"

	"sigs.k8s.io/controller-runtime/pkg/healthz"

	"github.com/backend-bunny/Konstapel/internal/download"
)

// Serving readiness (add-controller-high-availability 3.1). Every replica,
// elected or not, serves the probes and the admission webhooks; none of
// them is a leader-only runnable. /readyz answers "can this replica serve
// requests now?" from local prerequisites only:
//   - informers: this replica's informer caches completed their initial
//     sync. controller-runtime starts the probe server before the caches,
//     so without this check a starting replica reported ready on a cold
//     view;
//   - webhook (when webhooks are served): the webhook server accepts TLS
//     on its port and its certificate is the verified, unexpired one. A
//     rejected rotation keeps the last good certificate serving, but the
//     replica leaves service endpoints until the mounted files verify;
//   - shutdown: termination has not begun.
//
// Leadership, the policy engine, bundle sources and the evidence backend
// are not readiness inputs: their absence fails only the affected
// operations (binding Conditions, ContentUnavailable admission denials,
// run status). /healthz (liveness and startup) stays a process check.

// informerSync reports when this replica's informer caches have synced. It
// runs on every replica, in the manager group that starts after the caches
// synced; it waits for them itself as well. Once synced it stays synced:
// informers relist on their own afterwards, and a later leader-only
// informer for an absent external API must not take a serving replica out
// of its Service.
type informerSync struct {
	wait   func(context.Context) bool
	synced atomic.Bool
}

func (*informerSync) NeedLeaderElection() bool { return false }

func (s *informerSync) Start(ctx context.Context) error {
	if s.wait(ctx) {
		s.synced.Store(true)
	}
	<-ctx.Done()
	return nil
}

// check is the "informers" readiness check.
func (s *informerSync) check(*http.Request) error {
	if !s.synced.Load() {
		return errors.New("informer caches have not synced")
	}
	return nil
}

// webhookTLS loads the admission webhook certificate from dir (tls.crt and
// tls.key). Startup fails on invalid files. The API server verifies the
// certificate against the caBundle of the webhook configuration, which
// this process does not know, so no CA bundle or names are checked here.
func webhookTLS(dir string) (*download.Certificates, error) {
	certs, err := download.LoadCertificates(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"), "", nil)
	if err != nil {
		return nil, fmt.Errorf("webhook TLS: %w", err)
	}
	return certs, nil
}

// webhookTLSOptions serves the verified webhook certificate on every
// handshake instead of controller-runtime's unverified file watcher.
func webhookTLSOptions(certs *download.Certificates) []func(*tls.Config) {
	return []func(*tls.Config){func(c *tls.Config) {
		c.MinVersion = tls.VersionTLS12
		c.GetCertificate = certs.GetCertificate
	}}
}

// webhookReady is the "webhook" readiness check: the served certificate is
// valid now and the server answers a TLS handshake (started).
func webhookReady(certs *download.Certificates, started healthz.Checker) healthz.Checker {
	return func(r *http.Request) error {
		if err := certs.Ready(); err != nil {
			return fmt.Errorf("webhook TLS: %w", err)
		}
		return started(r)
	}
}
