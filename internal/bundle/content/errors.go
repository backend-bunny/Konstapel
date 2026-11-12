package content

import (
	"errors"
	"fmt"
	"strings"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle/cache"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/resolve"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// maxDetail bounds a ContentError's detail.
const maxDetail = 512

// classes maps resolver errors to content error classes, most specific
// first: every resolver error wraps resolve.ErrUnresolved, and a reuse
// failure followed by a failed retrieval wraps two of them.
var classes = []struct {
	sentinel error
	class    targeting.ContentErrorClass
}{
	{resolve.ErrStale, targeting.ContentErrorStale},
	{resolve.ErrCapacity, targeting.ContentErrorCapacity},
	{resolve.ErrIncompatible, targeting.ContentErrorIncompatible},
	{resolve.ErrUntrusted, targeting.ContentErrorUntrusted},
	{resolve.ErrProofUnavailable, targeting.ContentErrorProofUnavailable},
	{resolve.ErrContentUnavailable, targeting.ContentErrorContentUnavailable},
	{resolve.ErrConfig, targeting.ContentErrorConfig},
	{resolve.ErrUnresolved, targeting.ContentErrorUnresolved},
}

// causes are the sentinels whose fixed texts may appear in a detail. Only
// these texts are ever copied from a cause: raw error messages (which can
// echo registry responses or configuration) never reach the detail, so it
// is credential-free by construction, not by redaction.
var causes = []error{
	registry.ErrInvalidRequest, registry.ErrCredentials, registry.ErrUnauthorized, registry.ErrNotFound,
	registry.ErrUnavailable, registry.ErrIntegrity, registry.ErrUnexpectedDescriptor, registry.ErrLimitExceeded,
	registry.ErrInsecureRedirect, registry.ErrTrustConfig, registry.ErrCredentialScope, registry.ErrMissingProofs,
	verify.ErrTrustConfig, verify.ErrMalformedProof, verify.ErrProofTooLarge, verify.ErrSigner, verify.ErrAlgorithm,
	verify.ErrSignature, verify.ErrTransparency, verify.ErrSigningTime, verify.ErrStatement, verify.ErrSubject,
	verify.ErrPredicateType, verify.ErrNoValidProof, verify.ErrMixedSigner, verify.ErrProvenanceContract,
	verify.ErrProvenanceBuilder, verify.ErrProvenanceSource, verify.ErrProvenanceRelease, verify.ErrProvenanceMaterial,
	verify.ErrRecheckBundle, verify.ErrContent,
	cache.ErrNotFound, cache.ErrCorrupt, cache.ErrNoProofs, cache.ErrProofs, cache.ErrCapacity, cache.ErrNoSpace,
	cache.ErrLimit, cache.ErrMalformed, cache.ErrIntegrity, cache.ErrContent, cache.ErrLease,
}

// classify turns a resolver error into a *targeting.ContentError. It returns
// nil for an error that is not a bundle resolution outcome (a closed cache,
// an internal store error); the caller propagates those unchanged.
func classify(ref v1alpha1.BundleReference, err error) *targeting.ContentError {
	for _, c := range classes {
		if !errors.Is(err, c.sentinel) {
			continue
		}
		var why []string
		for _, s := range causes {
			if errors.Is(err, s) {
				why = append(why, s.Error())
			}
		}
		detail := fmt.Sprintf("%s@%s: %s", ref.Name, ref.Digest, c.sentinel.Error())
		if c.class == targeting.ContentErrorIncompatible {
			// The resolver's incompatibility error is built only from the
			// verdict's reasons, which Compatibility.Check composes from
			// validated descriptor fields; nothing retrieved is in it.
			detail = fmt.Sprintf("%s@%s: %s", ref.Name, ref.Digest, strings.TrimPrefix(err.Error(), resolve.ErrIncompatible.Error()+": "))
		}
		if len(why) > 0 {
			detail += " (" + strings.Join(why, "; ") + ")"
		}
		return contentError(c.class, c.sentinel, detail)
	}
	return nil
}

func contentError(class targeting.ContentErrorClass, sentinel error, detail string) *targeting.ContentError {
	if len(detail) > maxDetail {
		detail = detail[:maxDetail-3] + "..."
	}
	return &targeting.ContentError{Class: class, Detail: detail, Err: sentinel}
}
