package registry

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Limits bounds every retrieval. A zero field takes its value from
// DefaultLimits; negative values are rejected by NewClient.
type Limits struct {
	// MaxConcurrentResolutions caps retrievals running at once across all
	// sources. Deduplicated waiters share one slot.
	MaxConcurrentResolutions int
	// RequestTimeout bounds each individual HTTP exchange, including reading
	// its body and any token request.
	RequestTimeout time.Duration
	// ResolutionTimeout bounds one whole retrieval attempt once it holds a
	// concurrency slot.
	ResolutionTimeout time.Duration
	// MaxManifestBytes bounds the pinned subject manifest and each page of the
	// referrers listing.
	MaxManifestBytes int64
	// MaxReferrers bounds how many referrers the registry may list for the
	// subject, whatever their type. More is an error, never a truncation.
	MaxReferrers int
	// MaxMetadataBytes bounds the combined verification metadata of one
	// retrieval: referrers listing bodies, referrer manifests and proof
	// layers. More is an error, never a truncation.
	MaxMetadataBytes int64
	// MaxPayloadBytes bounds the compressed bundle layer.
	MaxPayloadBytes int64
	// Retry is the backoff the resolver applies between failed attempts.
	Retry RetryPolicy
}

// DefaultLimits are the documented deployment defaults (design section 4/6).
func DefaultLimits() Limits {
	return Limits{
		MaxConcurrentResolutions: 4,
		RequestTimeout:           30 * time.Second,
		ResolutionTimeout:        2 * time.Minute,
		MaxManifestBytes:         4 << 20,
		MaxReferrers:             64,
		MaxMetadataBytes:         16 << 20,
		MaxPayloadBytes:          64 << 20,
		Retry:                    RetryPolicy{Min: 5 * time.Second, Max: 5 * time.Minute},
	}
}

func (l Limits) withDefaults() (Limits, error) {
	d := DefaultLimits()
	if l.MaxConcurrentResolutions < 0 || l.RequestTimeout < 0 || l.ResolutionTimeout < 0 ||
		l.MaxManifestBytes < 0 || l.MaxReferrers < 0 || l.MaxMetadataBytes < 0 ||
		l.MaxPayloadBytes < 0 || l.Retry.Min < 0 || l.Retry.Max < 0 {
		return l, fmt.Errorf("%w: limits must not be negative", ErrInvalidRequest)
	}
	if l.MaxConcurrentResolutions == 0 {
		l.MaxConcurrentResolutions = d.MaxConcurrentResolutions
	}
	if l.RequestTimeout == 0 {
		l.RequestTimeout = d.RequestTimeout
	}
	if l.ResolutionTimeout == 0 {
		l.ResolutionTimeout = d.ResolutionTimeout
	}
	if l.MaxManifestBytes == 0 {
		l.MaxManifestBytes = d.MaxManifestBytes
	}
	if l.MaxReferrers == 0 {
		l.MaxReferrers = d.MaxReferrers
	}
	if l.MaxMetadataBytes == 0 {
		l.MaxMetadataBytes = d.MaxMetadataBytes
	}
	if l.MaxPayloadBytes == 0 {
		l.MaxPayloadBytes = d.MaxPayloadBytes
	}
	if l.Retry.Min == 0 {
		l.Retry.Min = d.Retry.Min
	}
	if l.Retry.Max == 0 {
		l.Retry.Max = d.Retry.Max
	}
	if l.Retry.Min > l.Retry.Max {
		return l, fmt.Errorf("%w: retry minimum %s exceeds maximum %s", ErrInvalidRequest, l.Retry.Min, l.Retry.Max)
	}
	return l, nil
}

// RetryPolicy is jittered exponential backoff between Min and Max. The retry
// loop itself belongs to the resolver; this is only the schedule.
type RetryPolicy struct {
	Min time.Duration
	Max time.Duration
}

// Delay returns the wait before retry number attempt (0 for the first
// retry). The ceiling doubles from 2*Min per attempt up to Max, and the delay
// is drawn uniformly from [ceiling/2, ceiling], never below Min. rnd returns a
// value in [0, 1); it is injected so callers and tests control the jitter.
func (p RetryPolicy) Delay(attempt int, rnd func() float64) time.Duration {
	if p.Max <= 0 || p.Min <= 0 {
		return 0
	}
	if attempt < 0 {
		attempt = 0
	}
	ceiling := p.Max
	// Double from 2*Min without overflowing: stop as soon as Max is reached.
	if c := 2 * p.Min; c < p.Max {
		ceiling = c
		for i := 0; i < attempt && ceiling < p.Max; i++ {
			ceiling *= 2
		}
		ceiling = min(ceiling, p.Max)
	}
	floor := max(ceiling/2, p.Min)
	r := rnd()
	if r < 0 || r >= 1 {
		r = 0
	}
	return floor + time.Duration(r*float64(ceiling-floor))
}

// Class says how the resolver should treat a retrieval error.
type Class int

const (
	// ClassNone is a nil error.
	ClassNone Class = iota
	// ClassCanceled means the caller abandoned the work; do not retry.
	ClassCanceled
	// ClassRetryable covers transport failures, timeouts, registry
	// unavailability, missing content and authentication failures (a Secret
	// can be fixed or rotated). Retry with RetryPolicy.
	ClassRetryable
	// ClassPermanent covers content that can never become acceptable under the
	// same configuration and digest: digest/size mismatches, unexpected
	// descriptors, exceeded limits, an unsupported referrers API and invalid
	// requests. Retry only after the source configuration changes.
	ClassPermanent
)

func (c Class) String() string {
	return [...]string{"none", "canceled", "retryable", "permanent"}[c]
}

// Classify classifies an error returned by Client.Fetch. Unrecognized errors
// (for example network failures) are retryable.
func Classify(err error) Class {
	switch {
	case err == nil:
		return ClassNone
	case errors.Is(err, context.Canceled):
		return ClassCanceled
	case errors.Is(err, ErrIntegrity), errors.Is(err, ErrUnexpectedDescriptor),
		errors.Is(err, ErrLimitExceeded), errors.Is(err, ErrReferrersUnsupported),
		errors.Is(err, ErrInvalidRequest):
		return ClassPermanent
	default:
		return ClassRetryable
	}
}
