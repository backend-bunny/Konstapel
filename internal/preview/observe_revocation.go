package preview

import (
	"context"
	"errors"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/exception"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// This file observes exception revocation (task 2.5): spec.revoked, the
// admission-protected revocation record (exception.RevocationAnnotation) and
// its finalizer on each ComplianceException, the controller's independent
// revocation record ConfigMaps in the controller namespace, and the owner's
// RevocationRecorded condition. Every rule comes from the exception owner:
// exception.RevocationRecordFrom verifies a record, exception.NewRevocationRecord
// decides whether a revocation can be recorded, and exception.VerifyHistory
// decides whether its record is durable and matching. The observation only
// reads; it never writes a record or releases a finalizer.

// revocationSelector selects revocation record ConfigMaps as the exception
// controller writes them (exception.RevocationRecord.ConfigMap).
var revocationSelector = exception.LabelComponent + "=" + exception.ComponentRevocation + "," + targeting.LabelManagedBy + "=" + targeting.ManagedByValue

// revocationCondition returns the owner's RevocationRecorded condition of an
// exception, without its message and timestamps, or nil when there is none.
func revocationCondition(u *unstructured.Unstructured, ex *v1alpha1.ComplianceException) (*OwnerCondition, *Diagnostic) {
	raw, found, err := unstructured.NestedSlice(u.Object, "status", "conditions")
	if err != nil || !found {
		return nil, nil
	}
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok || m["type"] != v1alpha1.ConditionRevocationRecorded {
			continue
		}
		var cond metav1.Condition
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(m, &cond); err != nil {
			return nil, &Diagnostic{Code: ObserveInvalidObject, Resource: resourceString(gvrExceptions), Namespace: u.GetNamespace(), Name: u.GetName(),
				Message: "status.conditions " + v1alpha1.ConditionRevocationRecorded + ": " + err.Error()}
		}
		return &OwnerCondition{Type: cond.Type, Status: string(cond.Status), Reason: cond.Reason, ObservedGeneration: cond.ObservedGeneration,
			Current: cond.ObservedGeneration == ex.Generation}, nil
	}
	return nil, nil
}

// readRevocations lists the revocation records in the controller namespace
// by label, as readSnapshots lists acceptance snapshots, and then checks the
// revocation of every observed exception against them.
func (c *capture) readRevocations(ctx context.Context, opts ObserveOptions) *Diagnostic {
	items, d := c.list(ctx, gvrConfigMaps, opts.Namespace, revocationSelector)
	if d != nil {
		return d
	}
	listed := map[string]*corev1.ConfigMap{}
	for i := range items {
		u := &items[i]
		cm := &corev1.ConfigMap{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, cm); err != nil {
			return &Diagnostic{Code: ObserveInvalidObject, Resource: resourceString(gvrConfigMaps), Namespace: u.GetNamespace(), Name: u.GetName(), Message: err.Error()}
		}
		listed[cm.Name] = cm
		o := ObservedRevocationRecord{ObjectRef: c.observeRecord(u, cm)}
		rec, digest, err := exception.RevocationRecordFrom(cm)
		o.Digest = digest
		if err != nil {
			o.VerifyError = err.Error()
			c.limitations = append(c.limitations, Diagnostic{Code: LimitRevocationRecordInvalid, Resource: o.Resource, Namespace: o.ObjectRef.Namespace, Name: o.Name,
				Message: "this revocation record does not verify against its recorded digest and format, so the revocation it would record is not established by it: " + err.Error()})
		} else {
			o.Cluster, o.ExceptionUID, o.ExceptionName, o.ExceptionNamespace = rec.Cluster, rec.Exception.UID, rec.Exception.Name, rec.Exception.Namespace
			o.AcceptanceRevision, o.Namespace, o.Policy, o.Acceptance = rec.AcceptanceRevision, rec.Namespace, rec.Policy, rec.Acceptance
			if !rec.Revocation.RequestedAt.IsZero() {
				t := rec.Revocation.RequestedAt.UTC()
				o.RequestedAt = &t
			}
		}
		c.revocations = append(c.revocations, o)
	}
	for i := range c.exceptions {
		if d := c.checkRevocation(ctx, opts.Namespace, &c.exceptions[i], &c.exceptionObjs[i], c.exceptionOwners[i], listed); d != nil {
			return d
		}
	}
	return nil
}

// observeRecord records a revocation record's identity and the fields its
// verification reads: data, the recorded digest, the labels and immutability.
func (c *capture) observeRecord(u *unstructured.Unstructured, cm *corev1.ConfigMap) ObjectRef {
	return c.observe(gvrConfigMaps, u, struct {
		Data      map[string]string `json:"data"`
		Digest    string            `json:"digest"`
		Labels    map[string]string `json:"labels"`
		Immutable bool              `json:"immutable"`
	}{cm.Data, cm.Annotations[exception.AnnotationRecordDigest], cm.Labels, cm.Immutable != nil && *cm.Immutable})
}

// checkRevocation classifies the revocation of one exception's current
// revision and records it as a limitation. An exception that is not revoked
// and carries neither a revocation record nor its finalizer has no
// revocation, as for the controller.
func (c *capture) checkRevocation(ctx context.Context, namespace string, o *ObservedException, ex *v1alpha1.ComplianceException, owner *OwnerCondition, listed map[string]*corev1.ConfigMap) *Diagnostic {
	_, annotated := ex.Annotations[exception.RevocationAnnotation]
	held := slices.Contains(ex.Finalizers, exception.RevocationFinalizer)
	if !ex.Spec.Revoked && !annotated && !held {
		return nil
	}
	rv := &ObservedRevocation{Finalizer: held, Owner: owner}
	o.Revocation = rv
	if r, present, err := exception.ParseRevocation(ex); present && err == nil {
		rv.Revision = r.Revision
		if !r.RequestedAt.IsZero() {
			t := r.RequestedAt.UTC()
			rv.RequestedAt = &t
		}
	}
	rev := ex.Spec.AcceptanceRevision
	limit := func(code ObserveCode, format string, args ...any) {
		c.limitations = append(c.limitations, Diagnostic{Code: code, Resource: resourceString(gvrExceptions), Namespace: ex.Namespace, Name: ex.Name,
			Message: fmt.Sprintf(format, args...) + ownerText(owner)})
	}
	// The owner's own rule for a recordable revocation. Its error texts are
	// not kept: they can quote the revoking actor.
	if _, err := exception.NewRevocationRecord(ex, namespace); err != nil {
		rv.State = RevocationInvalid
		limit(LimitRevocationInvalid, "spec.revoked and the admission-protected revocation record (%s) do not form a recordable revocation of acceptance revision %d, so no independent record can hold it",
			exception.RevocationAnnotation, rev)
		return nil
	}
	rv.Record = exception.RevocationRecordName(ex.UID, rev)
	where := namespace + "/" + rv.Record
	rr := &recordReader{c: c, namespace: namespace, listed: listed}
	err := exception.VerifyHistory(ctx, rr, namespace, ex)
	var conflict exception.HistoryConflict
	switch {
	case rr.diag != nil:
		return rr.diag
	case err == nil:
		rv.State = RevocationRecorded
		if i := slices.IndexFunc(c.revocations, func(r ObservedRevocationRecord) bool { return r.Name == rv.Record }); i >= 0 {
			rv.RecordDigest = c.revocations[i].Digest
		}
		limit(LimitRevocationRecorded, "acceptance revision %d is revoked and its independent revocation record %s (%s) holds exactly this revocation; a revocation records when it was requested, not when an engine stopped granting the exception",
			rev, where, rv.RecordDigest)
	case errors.Is(err, exception.ErrHistoryPending):
		rv.State = RevocationPending
		code := LimitRevocationPending
		if owner != nil && owner.Current && owner.Status == string(metav1.ConditionFalse) && owner.Reason == v1alpha1.ReasonRevocationProcessingDisabled {
			code = LimitRevocationProcessingDisabled
		}
		limit(code, "acceptance revision %d is revoked, but its independent revocation record %s does not exist yet: the revocation is recorded only on the resource", rev, where)
	case errors.As(err, &conflict):
		rv.State = RevocationConflict
		limit(LimitRevocationConflict, "acceptance revision %d is revoked, but the object at its revocation record name %s is not a verified record of this revocation, and it is never overwritten", rev, where)
	default:
		return &Diagnostic{Code: ObserveRequestFailed, Resource: resourceString(gvrConfigMaps), Namespace: namespace, Name: rv.Record,
			Message: "the revocation record could not be checked"}
	}
	return nil
}

// ownerText reports the owner's RevocationRecorded condition as it is, never
// an inferred one.
func ownerText(o *OwnerCondition) string {
	switch {
	case o == nil:
		return "; the controller reports no " + v1alpha1.ConditionRevocationRecorded + " condition"
	case !o.Current:
		return fmt.Sprintf("; the controller's %s condition (%s, %s) describes generation %d, not the observed one", o.Type, o.Status, o.Reason, o.ObservedGeneration)
	}
	return fmt.Sprintf("; the controller reports %s=%s (%s)", o.Type, o.Status, o.Reason)
}

// recordReader serves exception.VerifyHistory from this capture: a record
// the labelled list returned is used as listed; any other name is read by
// name with the caller's identity, so an object at the record's name that
// lacks the record labels is still found, as the controller would find it.
type recordReader struct {
	c         *capture
	namespace string
	listed    map[string]*corev1.ConfigMap
	// diag is the observation error of a named read; it makes the
	// capture incomplete.
	diag *Diagnostic
}

var _ client.Reader = (*recordReader)(nil)

func (r *recordReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok || key.Namespace != r.namespace {
		return fmt.Errorf("preview: unexpected revocation record read %T %s", obj, key)
	}
	if l, ok := r.listed[key.Name]; ok {
		l.DeepCopyInto(cm)
		return nil
	}
	u, found, d := r.c.get(ctx, gvrConfigMaps, key.Namespace, key.Name)
	if d != nil {
		r.diag = d
		return d
	}
	// An object that appears or disappears at the name adds or removes its
	// projection, which is drift.
	if !found {
		return apierrors.NewNotFound(corev1.Resource("configmaps"), key.Name)
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, cm); err != nil {
		r.diag = &Diagnostic{Code: ObserveInvalidObject, Resource: resourceString(gvrConfigMaps), Namespace: key.Namespace, Name: key.Name, Message: err.Error()}
		return r.diag
	}
	r.c.observeRecord(u, cm)
	return nil
}

func (r *recordReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("preview: revocation records are listed by the capture")
}
