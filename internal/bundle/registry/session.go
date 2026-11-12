package registry

import (
	"context"
	"fmt"

	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// Session is one connection to a source's repository with the same transport,
// TLS trust, credential preflight, credential scope, redirect rules and token
// cache that Fetch uses. It exists for the bundle publisher, a build tool that
// must write with exactly the guarantees the consumer reads with; the
// controller never opens one.
//
// Repository is a plain ORAS repository and can write. It is configured never
// to delete: ORAS's referrers tag schema garbage collection is disabled, so a
// replaced referrers index is kept rather than deleted. Errors from its calls
// must pass through Err (or Redact) before they are returned or logged.
type Session struct {
	Repository *remote.Repository
	rec        *secrets
}

// Open returns a Session for src. As with Fetch, a source that references a
// credential Secret fails with ErrCredentials before any request when no
// usable credential is available, so a write is never attempted anonymously
// instead; an anonymous source never sends a credential.
func (c *Client) Open(ctx context.Context, src bundle.BundleSource) (*Session, error) {
	if err := bundle.ValidateRepository(src.Repository); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	rec := &secrets{}
	meta := &budget{limit: c.limits.MaxMetadataBytes, remaining: c.limits.MaxMetadataBytes}
	repo, err := c.repository(ctx, src, rec, meta, auth.ActionPull, auth.ActionPush)
	if err != nil {
		return nil, rec.redact(err)
	}
	repo.MaxMetadataBytes = c.limits.MaxManifestBytes
	repo.ReferrerListMaxPages = c.limits.MaxReferrers + 1
	// Never delete: keep a superseded referrers tag schema index.
	repo.SkipReferrersGC = true
	return &Session{Repository: repo, rec: rec}, nil
}

// Err classifies err like Fetch does (ErrUnauthorized, ErrNotFound,
// ErrUnavailable, ...) and removes every credential value this session used.
func (s *Session) Err(what string, err error) error {
	if err == nil {
		return nil
	}
	return s.rec.redact(wrap(what, err))
}

// Redact removes every credential value this session used from err's text,
// keeping its errors.Is classification.
func (s *Session) Redact(err error) error { return s.rec.redact(err) }
