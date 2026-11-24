package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Collection bounds (add-assessment-provider-contract 2.3).
//
// The host bounds every collection, not the adapter. Collect gives an
// adapter readers that share one budget and a context with the host's
// deadline, and then decides what the adapter's result means:
//
//   - The host's context ends (leadership loss, shutdown): Collect returns
//     that error. Nothing the adapter collected is used, and the caller
//     records nothing for this pass.
//   - A bound stops the collection (its deadline, or an object, byte or
//     request limit, or a list that cannot be completed): every later read
//     is refused, and Collect discards the adapter's whole result and
//     returns one limitation instead. Expected subjects then have missing
//     evidence. A truncated collection is never returned as a complete one,
//     even when the adapter ignored the error it was given.
//   - Otherwise the adapter's result is returned unchanged.
//
// Lists are paginated. A list is complete only when its last page is read;
// partial pages are never returned.

// Limits bound one collection: every read an adapter makes through the
// Sources of one Collect call, across namespaces and pages.
type Limits struct {
	// Timeout bounds the whole collection. The assessment controller passes
	// the binding's collection timeout.
	Timeout time.Duration
	// PageSize is the limit of each list request.
	PageSize int64
	// MaxPages bounds the list requests of one collection.
	MaxPages int
	// MaxObjects bounds the objects one collection reads.
	MaxObjects int
	// MaxBytes bounds the JSON encoding of the objects one collection reads.
	MaxBytes int64
}

// Default collection limits. DefaultCollectionTimeout equals the
// ComplianceBinding's default spec.assessment.collectionTimeout. The other
// defaults are those of the read-only preview observation
// (preview.DefaultObserveLimits), except the request bound, which allows one
// list for each namespace of a 10,000-namespace scope plus 200 full pages.
const (
	DefaultCollectionTimeout       = 5 * time.Minute
	DefaultPageSize          int64 = 500
	DefaultMaxPages                = 20_000
	DefaultMaxObjects              = 100_000
	DefaultMaxBytes          int64 = 512 << 20
)

// DefaultLimits are the host's collection limits.
func DefaultLimits() Limits {
	return Limits{Timeout: DefaultCollectionTimeout, PageSize: DefaultPageSize, MaxPages: DefaultMaxPages,
		MaxObjects: DefaultMaxObjects, MaxBytes: DefaultMaxBytes}
}

// WithDefaults fills every zero or negative limit from DefaultLimits.
func (l Limits) WithDefaults() Limits {
	d := DefaultLimits()
	if l.Timeout <= 0 {
		l.Timeout = d.Timeout
	}
	if l.PageSize <= 0 {
		l.PageSize = d.PageSize
	}
	if l.MaxPages <= 0 {
		l.MaxPages = d.MaxPages
	}
	if l.MaxObjects <= 0 {
		l.MaxObjects = d.MaxObjects
	}
	if l.MaxBytes <= 0 {
		l.MaxBytes = d.MaxBytes
	}
	return l
}

// Validate requires every limit to be positive.
func (l Limits) Validate() error {
	if l.Timeout <= 0 || l.PageSize <= 0 || l.MaxPages <= 0 || l.MaxObjects <= 0 || l.MaxBytes <= 0 {
		return fmt.Errorf("collection limits must be positive: %+v", l)
	}
	return nil
}

// StopCode classifies why a bound stopped a collection.
type StopCode string

// Stop codes.
const (
	StopTimeout           StopCode = "timeout"
	StopCanceled          StopCode = "canceled"
	StopObjectLimit       StopCode = "object-limit"
	StopByteLimit         StopCode = "byte-limit"
	StopPageLimit         StopCode = "page-limit"
	StopPaginationExpired StopCode = "pagination-expired"
	StopInvalidList       StopCode = "invalid-list"
)

// ErrCollectionStopped matches every LimitError.
var ErrCollectionStopped = errors.New("collection stopped by a host bound")

// LimitError is the bound that stopped a collection. Once a collection has
// one, every later read of that collection returns it.
type LimitError struct {
	Code StopCode
	// Message says which bound was met, and where.
	Message string
}

func (e *LimitError) Error() string { return e.Message }

// Is matches ErrCollectionStopped.
func (e *LimitError) Is(target error) bool { return target == ErrCollectionStopped }

// Limitation is the limitation Collect records for a collection of
// contract that this bound stopped. Its consequence comes first, so the
// status's 256-character bound never cuts it off.
func (e *LimitError) Limitation(contract string) string {
	return fmt.Sprintf("%s evidence is not used: collection stopped (%s): %s", contract, e.Code, e.Message)
}

// budget is the shared bound of one collection.
type budget struct {
	l  Limits
	mu sync.Mutex
	// pages are the list requests made; objects and bytes are those of the
	// pages kept (a restarted list gives its pages' objects back).
	pages, objects int
	bytes          int64
	stop           *LimitError
}

func (b *budget) stopped() *LimitError {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stop
}

// halt records the first bound met and returns the collection's bound.
func (b *budget) halt(e *LimitError) *LimitError {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.haltLocked(e)
}

func (b *budget) haltLocked(e *LimitError) *LimitError {
	if b.stop == nil {
		b.stop = e
	}
	return b.stop
}

// request admits one list request, or refuses it once the collection is
// stopped, its context has ended, or its request bound is spent.
func (b *budget) request(ctx context.Context, what string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case b.stop != nil:
		return b.stop
	case ctx.Err() != nil:
		return b.haltLocked(contextStop(ctx, b.l, what))
	case b.pages >= b.l.MaxPages:
		return b.haltLocked(&LimitError{Code: StopPageLimit, Message: fmt.Sprintf("the collection needed more than %d list requests (at %s)", b.l.MaxPages, what)})
	}
	b.pages++
	return nil
}

// take counts one page's objects and bytes against the limits.
func (b *budget) take(objects int, bytes int64, what string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stop != nil {
		return b.stop
	}
	b.objects += objects
	b.bytes += bytes
	switch {
	case b.objects > b.l.MaxObjects:
		return b.haltLocked(&LimitError{Code: StopObjectLimit, Message: fmt.Sprintf("the collection read more than %d objects (at %s)", b.l.MaxObjects, what)})
	case b.bytes > b.l.MaxBytes:
		return b.haltLocked(&LimitError{Code: StopByteLimit, Message: fmt.Sprintf("the collection read more than %d bytes (at %s)", b.l.MaxBytes, what)})
	}
	return nil
}

// giveBack returns the objects and bytes of discarded pages.
func (b *budget) giveBack(objects int, bytes int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.objects -= objects
	b.bytes -= bytes
}

// failed classifies a failed request. A request that failed because the
// collection's context ended, or that client-side rate limiting refused
// because it could not be sent before the deadline, stops the collection;
// any other failure is the source's and stops nothing.
func (b *budget) failed(ctx context.Context, err error, what string) {
	switch {
	case ctx.Err() != nil:
		b.halt(contextStop(ctx, b.l, what))
	case rateLimitedPastDeadline(ctx, err):
		b.halt(&LimitError{Code: StopTimeout, Message: fmt.Sprintf("the collection could not send its next request within its %sdeadline (at %s)", deadline(b.l), what)})
	}
}

// deadline names the collection's timeout, when the host set one.
func deadline(l Limits) string {
	if l.Timeout > 0 {
		return l.Timeout.String() + " "
	}
	return ""
}

func contextStop(ctx context.Context, l Limits, what string) *LimitError {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &LimitError{Code: StopTimeout, Message: fmt.Sprintf("the collection exceeded its %sdeadline (at %s)", deadline(l), what)}
	}
	return &LimitError{Code: StopCanceled, Message: fmt.Sprintf("the collection was canceled (at %s)", what)}
}

// rateLimitedPastDeadline matches client-go's client-side rate limiter
// refusing to wait beyond the context deadline: the deadline has not passed
// yet, but the request can no longer be sent within it.
func rateLimitedPastDeadline(ctx context.Context, err error) bool {
	_, ok := ctx.Deadline()
	return ok && strings.Contains(err.Error(), "would exceed context deadline")
}

// jsonSize is the length of v's JSON encoding.
func jsonSize(v any) (int64, error) {
	var w countingWriter
	if err := json.NewEncoder(&w).Encode(v); err != nil {
		return 0, err
	}
	return w.n - 1, nil // Encode appends a newline
}

type countingWriter struct{ n int64 }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}

// Collect runs one collection adapter under the host's bounds: readers over
// c for the declared reads of d, limited to scope and sharing one budget of
// l, and a context that ends at l.Timeout or with ctx. It returns:
//
//   - ctx's error when ctx ended (leadership loss, shutdown), with no
//     result: the caller must not record anything from this pass;
//   - when a bound stopped the collection, or its deadline passed before
//     the adapter returned, no result and the single limitation that says
//     so; the adapter's evidence and limitations are discarded;
//   - otherwise the adapter's result, unchanged.
func Collect[T any](ctx context.Context, c client.Reader, d Descriptor, scope Scope, l Limits,
	adapter func(context.Context, Sources) (T, []string, error)) (T, []string, error) {
	var zero T
	if err := l.Validate(); err != nil {
		return zero, nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, l.Timeout)
	defer cancel()
	b := &budget{l: l}
	out, limits, err := adapter(cctx, clientSources{c: c, d: d, scope: scope, b: b})
	if ctx.Err() != nil {
		return zero, nil, fmt.Errorf("%s collection: %w", d.Contract(), ctx.Err())
	}
	stop := b.stopped()
	if stop == nil && cctx.Err() != nil {
		stop = b.halt(contextStop(cctx, l, "the adapter's return"))
	}
	if stop != nil {
		return zero, []string{stop.Limitation(d.Contract())}, nil
	}
	return out, limits, err
}
