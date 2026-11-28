package providerkit

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
)

// Error is a protocol failure classified by its ErrorReason. Servers return
// it as a gRPC status carrying one providerv1.ErrorDetail; clients return it
// for both a provider's status and a check the client made itself, such as
// an incompatible description, before or instead of sending a request.
type Error struct {
	Reason  providerv1.ErrorReason
	Message string
	// cause is the context error a status without a detail stands for:
	// a peer ending the call on its own deadline or cancellation.
	cause error
}

// Unwrap returns the context error of a DeadlineExceeded or Canceled status
// without a detail, so errors.Is(err, context.DeadlineExceeded) holds when
// the provider ended the call on the propagated deadline just before the
// host's own context did.
func (e *Error) Unwrap() error { return e.cause }

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Reason, e.Message)
}

// Is matches another *Error with the same reason, so
// errors.Is(err, &Error{Reason: r}) tests a reason.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Reason == e.Reason
}

// Errorf returns an *Error with the reason and a formatted message.
func Errorf(reason providerv1.ErrorReason, format string, args ...any) *Error {
	return &Error{Reason: reason, Message: fmt.Sprintf(format, args...)}
}

// ReasonOf returns the reason of the first *Error in err's chain, or
// ERROR_REASON_UNSPECIFIED when there is none.
func ReasonOf(err error) providerv1.ErrorReason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return providerv1.ErrorReason_ERROR_REASON_UNSPECIFIED
}

// Code is the gRPC status code a reason is served with. Clients branch on the
// reason, not the code; the code only keeps generic gRPC tooling meaningful.
func Code(reason providerv1.ErrorReason) codes.Code {
	switch reason {
	case providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PROTOCOL_VERSION,
		providerv1.ErrorReason_ERROR_REASON_PROVIDER_MISMATCH,
		providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CONTRACT_VERSION,
		providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PAYLOAD_VERSION,
		providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_EVALUATOR_VERSION,
		providerv1.ErrorReason_ERROR_REASON_RESULT_EXPIRED:
		return codes.FailedPrecondition
	case providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CAPABILITY:
		return codes.Unimplemented
	case providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST,
		providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH:
		return codes.InvalidArgument
	case providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED:
		return codes.ResourceExhausted
	case providerv1.ErrorReason_ERROR_REASON_OPERATION_CONFLICT:
		return codes.AlreadyExists
	case providerv1.ErrorReason_ERROR_REASON_NOT_FOUND:
		return codes.NotFound
	case providerv1.ErrorReason_ERROR_REASON_UNAVAILABLE:
		return codes.Unavailable
	default:
		return codes.Internal
	}
}

// toStatus converts a handler or validation error to the gRPC status a
// server returns. A context error keeps its own code. Any error that is not
// an *Error is the provider's own failure, ERROR_REASON_UNAVAILABLE.
func toStatus(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, err.Error())
	}
	var e *Error
	if !errors.As(err, &e) {
		e = &Error{Reason: providerv1.ErrorReason_ERROR_REASON_UNAVAILABLE, Message: err.Error()}
	}
	st, derr := status.New(Code(e.Reason), e.Message).
		WithDetails(protoadapt.MessageV1Of(&providerv1.ErrorDetail{Reason: e.Reason}))
	if derr != nil {
		return status.Error(codes.Internal, e.Error())
	}
	return st.Err()
}

// fromStatus converts a failed call's status to an *Error. A status without
// exactly one ErrorDetail keeps its code in the message and has reason
// ERROR_REASON_UNSPECIFIED, and a DeadlineExceeded or Canceled one also
// matches its context error; a context error is returned as such.
func fromStatus(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	var reasons []providerv1.ErrorReason
	for _, d := range st.Details() {
		if detail, ok := d.(*providerv1.ErrorDetail); ok {
			reasons = append(reasons, detail.GetReason())
		}
	}
	if len(reasons) != 1 {
		e := &Error{Reason: providerv1.ErrorReason_ERROR_REASON_UNSPECIFIED,
			Message: fmt.Sprintf("%s: %s", st.Code(), st.Message())}
		switch st.Code() {
		case codes.DeadlineExceeded:
			e.cause = context.DeadlineExceeded
		case codes.Canceled:
			e.cause = context.Canceled
		}
		return e
	}
	return &Error{Reason: reasons[0], Message: st.Message()}
}
