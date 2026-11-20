package exception

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// RevocationAnnotation holds the protected revocation record (design §2).
// Only the exception admission webhook writes it, once, when spec.revoked
// first becomes true at an acceptance revision. It never changes afterwards;
// an explicit renewal of the revoked revision removes it, and only once its
// independent RevocationRecord is durable and matches.
const RevocationAnnotation = "compliance.erenius.io/revocation"

// RevocationFinalizer is added together with the revocation record. While
// the record exists only on this resource, deleting the resource would
// erase the last copy of the revocation intent, so no application identity
// can remove the finalizer. The controller persists the intent as an
// independent RevocationRecord and only then releases the finalizer
// (add-self-service-policy-exceptions task 3.6); the validating webhook lets
// only the controller identity release it, and only once that record is
// durable and matches.
const RevocationFinalizer = "compliance.erenius.io/revocation-history"

// Denial reasons for revocation. They match the lifecycle fixture vocabulary
// (testdata/exceptions) and prefix the admission message.
const (
	ReasonInvalidRevocationTransition = "InvalidRevocationTransition"
	ReasonRenewalRequired             = "RenewalRequired"
	ReasonRevocationHistoryPending    = "RevocationHistoryPending"
	ReasonProtectedField              = "ProtectedField"
)

// Revocation is what admission records when an acceptance revision is
// revoked. It is kept apart from the Acceptance record, which revocation
// never changes.
type Revocation struct {
	// ExceptionUID and Revision identify the revoked acceptance.
	ExceptionUID types.UID `json:"exceptionUID"`
	Revision     int64     `json:"revision"`
	// RequestedAt is the time of the revoking request as seen by admission.
	// It is not the time the engine stopped granting the exception.
	RequestedAt metav1.Time `json:"requestedAt"`
	// Actor is the authenticated principal of the revoking request.
	Actor Actor `json:"actor"`
	// Claim is the caller-supplied ClaimAnnotation of the revoking request,
	// unverified.
	Claim string `json:"claim,omitempty"`
}

// ParseRevocation reads the protected revocation record of an exception.
func ParseRevocation(ex *v1alpha1.ComplianceException) (Revocation, bool, error) {
	raw, ok := ex.Annotations[RevocationAnnotation]
	if !ok {
		return Revocation{}, false, nil
	}
	var r Revocation
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return Revocation{}, true, err
	}
	return r, true, nil
}

// operation is what an admitted write does to the acceptance lifecycle.
type operation int

const (
	// opOther changes no acceptance and no revocation: a metadata edit, a
	// re-apply, or repeating a revocation.
	opOther operation = iota
	// opAcceptance is a creation or an explicit renewal.
	opAcceptance
	// opRevocation is the first false-to-true change of spec.revoked at the
	// current acceptance revision.
	opRevocation
	// opRenewalOfRevoked is an explicit renewal of a revoked revision. It is
	// an acceptance that also clears the revocation record, so it needs the
	// durable independent copy of that record first (task 3.6).
	opRenewalOfRevoked
)

// accepting reports whether the operation records a new acceptance.
func (op operation) accepting() bool { return op == opAcceptance || op == opRenewalOfRevoked }

// classify returns the lifecycle operation of a request, or the Denial of a
// transition that is never allowed. The CRD rejects the same transitions; the
// webhooks check them too, before resolving anything, so a mutating webhook
// never records an acceptance or a revocation for one.
func classify(req admission.Request, ex, old *v1alpha1.ComplianceException) (operation, *Denial) {
	switch req.Operation {
	case admissionv1.Create:
		if ex.Spec.Revoked {
			return opOther, &Denial{ReasonInvalidRevocationTransition, "a new exception starts with spec.revoked false; revoke an existing acceptance revision in a separate update"}
		}
		return opAcceptance, nil
	case admissionv1.Update:
		if old == nil {
			return opOther, nil
		}
		renewal := ex.Spec.AcceptanceRevision != old.Spec.AcceptanceRevision
		switch {
		case renewal && ex.Spec.Revoked:
			return opOther, &Denial{ReasonInvalidRevocationTransition, "a renewal starts with spec.revoked false; renew and revoke in separate updates"}
		case renewal && old.Spec.Revoked:
			// Clearing the intent needs its independent, durable copy
			// first; renewable checks that before anything is resolved.
			return opRenewalOfRevoked, nil
		case renewal:
			return opAcceptance, nil
		case old.Spec.Revoked && !ex.Spec.Revoked:
			return opOther, &Denial{ReasonRenewalRequired, fmt.Sprintf(
				"acceptance revision %d is revoked and cannot be reactivated; an update that sets or defaults spec.revoked to false needs a renewal (acceptanceRevision %d), or create a new ComplianceException",
				old.Spec.AcceptanceRevision, old.Spec.AcceptanceRevision+1)}
		case !old.Spec.Revoked && ex.Spec.Revoked:
			return opRevocation, nil
		}
	}
	return opOther, nil
}

// revoke records the revocation of the current acceptance revision and adds
// the finalizer that keeps it. It reads nothing: revocation never depends on
// current eligibility, the expiry or the cluster, so an expired, Forbidden or
// unresolvable acceptance can always be revoked.
func revoke(req admission.Request, ex, old *v1alpha1.ComplianceException, now time.Time) (*v1alpha1.ComplianceException, error) {
	r := Revocation{
		// The stored object's UID: the request body need not carry one.
		ExceptionUID: old.UID,
		Revision:     ex.Spec.AcceptanceRevision,
		RequestedAt:  metav1.NewTime(now.UTC().Truncate(time.Second)),
		Actor:        actorOf(req),
		Claim:        ex.Annotations[ClaimAnnotation],
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	updated := ex.DeepCopy()
	if updated.Annotations == nil {
		updated.Annotations = map[string]string{}
	}
	// Overwrites any caller-supplied value.
	updated.Annotations[RevocationAnnotation] = string(raw)
	if !slices.Contains(updated.Finalizers, RevocationFinalizer) {
		updated.Finalizers = append(updated.Finalizers, RevocationFinalizer)
	}
	return updated, nil
}

// checkRevocation verifies the revocation record and its finalizer: on a
// revocation they must be present and belong to the operation; on any other
// operation they must be exactly as stored (absent on creation).
func checkRevocation(req admission.Request, op operation, ex, old *v1alpha1.ComplianceException, now time.Time) error {
	got, present := ex.Annotations[RevocationAnnotation]
	finalized := slices.Contains(ex.Finalizers, RevocationFinalizer)
	if op == opRevocation {
		if !present {
			return &Denial{ReasonProtectedField, RevocationAnnotation + " is missing: the exception admission webhook did not record this revocation"}
		}
		var r Revocation
		if err := json.Unmarshal([]byte(got), &r); err != nil {
			return &Denial{ReasonProtectedField, fmt.Sprintf("%s is not a valid revocation record: %v", RevocationAnnotation, err)}
		}
		actor := actorOf(req)
		switch {
		case r.ExceptionUID != old.UID:
			return &Denial{ReasonProtectedField, fmt.Sprintf("%s records exception UID %q, not %q", RevocationAnnotation, r.ExceptionUID, old.UID)}
		case r.Revision != ex.Spec.AcceptanceRevision:
			return &Denial{ReasonProtectedField, fmt.Sprintf("%s records revision %d, not %d", RevocationAnnotation, r.Revision, ex.Spec.AcceptanceRevision)}
		case r.Actor.Username != actor.Username || r.Actor.UID != actor.UID || !slices.Equal(r.Actor.Groups, actor.Groups):
			return &Denial{ReasonProtectedField, RevocationAnnotation + " does not name the authenticated caller"}
		case r.Claim != ex.Annotations[ClaimAnnotation]:
			return &Denial{ReasonProtectedField, fmt.Sprintf("%s records a different claim than %s", RevocationAnnotation, ClaimAnnotation)}
		case r.RequestedAt.Sub(now).Abs() > acceptanceSkew:
			return &Denial{ReasonProtectedField, fmt.Sprintf("%s request time %s is not this request's", RevocationAnnotation, r.RequestedAt.UTC().Format(time.RFC3339))}
		case !finalized:
			return &Denial{ReasonProtectedField, "a revocation needs the " + RevocationFinalizer + " finalizer, which the exception admission webhook adds"}
		}
		return nil
	}
	if op == opRenewalOfRevoked {
		// renewable has checked the independent record; the renewal clears
		// what it replaces, and a new acceptance starts without history.
		switch {
		case present:
			return &Denial{ReasonProtectedField, RevocationAnnotation + " is cleared by a renewal of a revoked revision; its independent record keeps it"}
		case finalized:
			return &Denial{ReasonProtectedField, "a renewal does not carry the " + RevocationFinalizer + " finalizer"}
		}
		return nil
	}
	var was string
	var wasPresent, wasFinalized bool
	if old != nil {
		was, wasPresent = old.Annotations[RevocationAnnotation]
		wasFinalized = slices.Contains(old.Finalizers, RevocationFinalizer)
	}
	switch {
	case got != was || present != wasPresent:
		return &Denial{ReasonProtectedField, RevocationAnnotation + " is protected: admission records it once, when spec.revoked becomes true, and only a renewal clears it"}
	case wasFinalized && !finalized:
		return &Denial{ReasonProtectedField, "finalizer " + RevocationFinalizer + " is protected: it keeps this revoked exception until its revocation is recorded independently, and only the Konstapel controller releases it"}
	case finalized && !wasFinalized:
		return &Denial{ReasonProtectedField, "finalizer " + RevocationFinalizer + " is protected: admission adds it with a revocation"}
	}
	return nil
}

// renewable checks that a renewal may replace the revoked revision of old
// (design §3): Konstapel has released its finalizer, and the independent
// revocation record is durable and holds exactly the intent recorded on
// the resource. It reads only that record. A missing or conflicting record
// is a RevocationHistoryPending denial; a read failure is returned as is,
// so the webhook fails closed.
func renewable(ctx context.Context, reader client.Reader, namespace string, old *v1alpha1.ComplianceException) error {
	rev := old.Spec.AcceptanceRevision
	if slices.Contains(old.Finalizers, RevocationFinalizer) {
		return &Denial{ReasonRevocationHistoryPending, fmt.Sprintf(
			"acceptance revision %d is revoked and Konstapel has not yet confirmed its independent revocation record (the %s finalizer is still present); retry the renewal once the RevocationRecorded condition is True, or create a new ComplianceException",
			rev, RevocationFinalizer)}
	}
	err := VerifyHistory(ctx, reader, namespace, old)
	var conflict HistoryConflict
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrHistoryPending) || errors.As(err, &conflict):
		return &Denial{ReasonRevocationHistoryPending, fmt.Sprintf(
			"acceptance revision %d is revoked and a renewal would clear its revocation, which is not durably recorded independently: %v", rev, err)}
	}
	return fmt.Errorf("verify the revocation history of acceptance revision %d: %w", rev, err)
}

// checkController restricts updates by the controller identity to
// releasing RevocationFinalizer, once the revocation it protects is
// durably recorded independently. Status is written through the status
// subresource, which these webhooks do not see.
func checkController(ctx context.Context, reader client.Reader, namespace, identity string, op operation, ex, old *v1alpha1.ComplianceException) error {
	restricted := &Denial{ReasonProtectedField, fmt.Sprintf(
		"the Konstapel controller identity %s may only release the %s finalizer; it cannot accept, renew, revoke or edit an exception", identity, RevocationFinalizer)}
	released := slices.Contains(old.Finalizers, RevocationFinalizer) && !slices.Contains(ex.Finalizers, RevocationFinalizer)
	remaining := slices.DeleteFunc(slices.Clone(old.Finalizers), func(f string) bool { return released && f == RevocationFinalizer })
	switch {
	case op != opOther:
		return restricted
	case !reflect.DeepEqual(ex.Spec, old.Spec) || !maps.Equal(ex.Labels, old.Labels) || !maps.Equal(ex.Annotations, old.Annotations) ||
		!slices.Equal(ex.Finalizers, remaining) || !reflect.DeepEqual(ex.OwnerReferences, old.OwnerReferences):
		return restricted
	case !released:
		return nil
	}
	err := VerifyHistory(ctx, reader, namespace, old)
	var conflict HistoryConflict
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrHistoryPending) || errors.As(err, &conflict):
		return &Denial{ReasonRevocationHistoryPending, "the " + RevocationFinalizer + " finalizer stays until the revocation is durably recorded independently: " + err.Error()}
	}
	return fmt.Errorf("verify the revocation history before releasing %s: %w", RevocationFinalizer, err)
}
