package registry

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

// Errors returned by Fetch wrap one of these sentinels; test with errors.Is
// and use Classify for retry decisions. Messages never contain credentials.
var (
	// ErrInvalidRequest: the source or digest is malformed, or the client is
	// misconfigured.
	ErrInvalidRequest = errors.New("invalid registry retrieval request")
	// ErrCredentials: a configured credential could not be obtained. There is
	// no anonymous fallback.
	ErrCredentials = errors.New("registry credentials are unavailable")
	// ErrUnauthorized: the registry refused the request (401/403).
	ErrUnauthorized = errors.New("registry denied access")
	// ErrNotFound: the pinned manifest or one of its blobs is absent.
	ErrNotFound = errors.New("content not found in the configured repository")
	// ErrUnavailable: the registry reported a server error or throttling.
	ErrUnavailable = errors.New("registry unavailable")
	// ErrIntegrity: downloaded bytes do not match their digest or size.
	ErrIntegrity = errors.New("content does not match its digest or size")
	// ErrUnexpectedDescriptor: an index, a wrong media or artifact type, or an
	// unexpected layer layout.
	ErrUnexpectedDescriptor = errors.New("unexpected OCI content")
	// ErrLimitExceeded: a size, count or page limit would be exceeded.
	ErrLimitExceeded = errors.New("retrieval limit exceeded")
	// ErrReferrersUnsupported: the registry does not implement the OCI 1.1
	// referrers API, which this version requires.
	ErrReferrersUnsupported = errors.New("registry does not support the OCI referrers API")
	// ErrInsecureRedirect: the registry redirected to plain HTTP.
	ErrInsecureRedirect = errors.New("refusing a redirect to non-HTTPS")
	// ErrMissingProofs: a required proof kind was not attached to the subject.
	ErrMissingProofs = errors.New("required verification proofs are missing")
)

// wrap attaches a sentinel to an ORAS or transport error.
func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	var resp *errcode.ErrorResponse
	switch {
	case errors.As(err, &resp):
		switch code := resp.StatusCode; {
		case code == http.StatusUnauthorized || code == http.StatusForbidden:
			return fmt.Errorf("%w: %s: %w", ErrUnauthorized, what, err)
		case code == http.StatusNotFound:
			return fmt.Errorf("%w: %s: %w", ErrNotFound, what, err)
		case code == http.StatusTooManyRequests || code >= 500:
			return fmt.Errorf("%w: %s: %w", ErrUnavailable, what, err)
		}
	case errors.Is(err, errdef.ErrNotFound):
		return fmt.Errorf("%w: %s: %w", ErrNotFound, what, err)
	case errors.Is(err, errdef.ErrSizeExceedsLimit), errors.Is(err, errdef.ErrTooManyPages):
		return fmt.Errorf("%w: %s: %w", ErrLimitExceeded, what, err)
	}
	return fmt.Errorf("%s: %w", what, err)
}

// secrets records the credential values one retrieval used, so they can be
// removed from any error text (a hostile registry may echo request headers).
type secrets struct {
	mu     sync.Mutex
	values []string
}

func (s *secrets) add(vs ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range vs {
		// Very short values cannot be redacted without mangling ordinary
		// text; they are still never logged by this package.
		if len(v) >= 4 {
			s.values = append(s.values, v)
		}
	}
}

func (s *secrets) addCredential(c Credential) {
	s.add(c.Password, c.IdentityToken, c.RegistryToken)
	if c.Username != "" || c.Password != "" {
		s.add(base64.StdEncoding.EncodeToString([]byte(c.Username + ":" + c.Password)))
	}
}

// addAuthorization records an Authorization header value and its token.
func (s *secrets) addAuthorization(h string) {
	if h == "" {
		return
	}
	s.add(h)
	if _, token, ok := strings.Cut(h, " "); ok {
		s.add(strings.TrimSpace(token))
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token)); err == nil {
			if _, pass, ok := strings.Cut(string(raw), ":"); ok {
				s.add(pass)
			}
		}
	}
}

// redactedError hides its cause's text but keeps errors.Is classification.
// It deliberately has no Unwrap, which would expose the unredacted text.
type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string        { return e.msg }
func (e *redactedError) Is(target error) bool { return errors.Is(e.cause, target) }

func (s *secrets) redact(err error) error {
	if err == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	msg := err.Error()
	clean := msg
	// Longest first, so a header value is removed before its token part.
	for _, v := range sortedByLength(s.values) {
		clean = strings.ReplaceAll(clean, v, "[REDACTED]")
	}
	if clean == msg {
		return err
	}
	return &redactedError{msg: clean, cause: err}
}

func sortedByLength(vs []string) []string {
	out := slices.Clone(vs)
	slices.SortStableFunc(out, func(a, b string) int { return len(b) - len(a) })
	return out
}
