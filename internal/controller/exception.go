package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/exception"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Acceptance snapshots and revocation records are immutable ConfigMaps in
// the controller namespace: the controller creates and reads them and never
// updates or deletes them.
// +kubebuilder:rbac:groups="",namespace=konstapel-system,resources=configmaps,verbs=get;create

// DefaultSnapshotNamespace is the protected namespace for acceptance
// snapshots and revocation records.
const DefaultSnapshotNamespace = "konstapel-system"

// Retry intervals for revocation history. A fixed interval, rather than the
// controller's growing per-item backoff, keeps a recovered store from
// waiting minutes before the record is written.
const (
	// historyRetry follows a failed attempt to persist a record.
	historyRetry = 5 * time.Second
	// historyConflictRetry rechecks a record name another object holds;
	// only an operator can clear it.
	historyConflictRetry = time.Minute
)

// ExceptionReconciler persists an immutable snapshot of each acceptance
// revision (add-self-service-policy-exceptions task 3.1) and records its
// reference in status. Native grants (task 3.2) are delivered only after
// the snapshot exists.
//
// For a revoked revision it also persists the independent, immutable
// revocation record (task 3.6) and only then releases the revocation
// finalizer, so neither deletion of the exception or its namespace nor a
// renewal can erase the last copy of the intent. Persisting history never
// waits for, and never holds up, anything else the reconciler does.
type ExceptionReconciler struct {
	Client client.Client
	// Reader reads snapshot and record ConfigMaps directly, so the manager
	// does not cache (or need list/watch on) ConfigMaps, and an existing
	// record is read back from the API server, not from a cache.
	Reader    client.Reader
	Namespace string
}

func (r *ExceptionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ex := &v1alpha1.ComplianceException{}
	if err := r.Client.Get(ctx, req.NamespacedName, ex); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	pending := slices.Contains(ex.Finalizers, exception.RevocationFinalizer)
	deleting := !ex.DeletionTimestamp.IsZero()
	if deleting && !pending {
		return ctrl.Result{}, nil
	}
	updated := ex.DeepCopy()
	var errs []error

	// The acceptance snapshot of the current revision. For a terminating
	// revoked exception it is history its finalization keeps, so a revoked,
	// never-activated acceptance gets its snapshot too.
	ref, accepted := r.snapshot(ctx, ex)
	if accepted.Reason == "" {
		errs = append(errs, fmt.Errorf("snapshot exception %s/%s: %s", ex.Namespace, ex.Name, accepted.Message))
	} else {
		if ref != nil {
			updated.Status.Acceptance = ref
		}
		accepted.ObservedGeneration = ex.Generation
		meta.SetStatusCondition(&updated.Status.Conditions, accepted)
	}

	// The revocation record, independently of the snapshot outcome.
	history, retry := r.revocationHistory(ctx, ex)
	if history == nil {
		meta.RemoveStatusCondition(&updated.Status.Conditions, v1alpha1.ConditionRevocationRecorded)
	} else {
		history.ObservedGeneration = ex.Generation
		meta.SetStatusCondition(&updated.Status.Conditions, *history)
	}

	// The finalizer goes only once the record is durable and the snapshot
	// is settled: not pending on a transient error, and not blocked by a
	// conflicting object, while the acceptance record on this resource is
	// its last copy.
	if pending && history != nil && history.Status == metav1.ConditionTrue &&
		accepted.Reason != "" && accepted.Reason != v1alpha1.ReasonSnapshotConflict {
		released, err := r.release(ctx, ex)
		switch {
		case err != nil:
			errs = append(errs, err)
		case released == nil || deleting:
			// Gone, or removed now that nothing holds the deletion.
			return ctrl.Result{}, errors.Join(errs...)
		default:
			updated.ObjectMeta = released.ObjectMeta
		}
	}

	if !equalStatus(ex.Status, updated.Status) {
		if err := r.Client.Status().Update(ctx, updated); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return ctrl.Result{}, errors.Join(errs...)
	}
	return ctrl.Result{RequeueAfter: retry}, nil
}

// revocationHistory ensures the independent record of the current revoked
// revision exists and holds exactly the intent admission recorded. It
// returns the RevocationRecorded condition (nil when the current revision is
// not revoked) and when to retry. The record is built from the stored
// resource only and is never rewritten: an existing record either matches
// or is a conflict.
func (r *ExceptionReconciler) revocationHistory(ctx context.Context, ex *v1alpha1.ComplianceException) (*metav1.Condition, time.Duration) {
	cond := func(status metav1.ConditionStatus, reason, msg string) *metav1.Condition {
		return &metav1.Condition{Type: v1alpha1.ConditionRevocationRecorded, Status: status, Reason: reason, Message: msg}
	}
	_, annotated := ex.Annotations[exception.RevocationAnnotation]
	if !ex.Spec.Revoked && !annotated && !slices.Contains(ex.Finalizers, exception.RevocationFinalizer) {
		return nil, 0
	}
	rec, err := exception.NewRevocationRecord(ex, r.Namespace)
	if err != nil {
		// The protected record is immutable: retrying cannot help, and
		// nothing is released.
		return cond(metav1.ConditionFalse, v1alpha1.ReasonRevocationInvalid, "the revocation cannot be recorded: "+err.Error()), 0
	}
	want, _, err := rec.ConfigMap(r.Namespace)
	if err != nil {
		return cond(metav1.ConditionFalse, v1alpha1.ReasonRevocationInvalid, err.Error()), 0
	}
	name := r.Namespace + "/" + want.Name
	pending := func(err error) (*metav1.Condition, time.Duration) {
		return cond(metav1.ConditionFalse, v1alpha1.ReasonRevocationHistoryPending,
			"revocation record "+name+" is not persisted yet, so the intent and its finalizer stay: "+err.Error()), historyRetry
	}
	got := &corev1.ConfigMap{}
	err = r.Reader.Get(ctx, client.ObjectKeyFromObject(want), got)
	if apierrors.IsNotFound(err) {
		err = r.Client.Create(ctx, want)
		if err == nil {
			_, digest, _ := rec.Document()
			return recordedCondition(cond, name, rec.AcceptanceRevision, digest), 0
		}
		if !apierrors.IsAlreadyExists(err) {
			return pending(err)
		}
		// Created concurrently, or an earlier response was lost: verify
		// what is there.
		err = r.Reader.Get(ctx, client.ObjectKeyFromObject(want), got)
	}
	if err != nil {
		return pending(err)
	}
	existing, digest, err := exception.RevocationRecordFrom(got)
	if err == nil {
		err = existing.Matches(got, rec.Revocation)
	}
	if err != nil {
		return cond(metav1.ConditionFalse, v1alpha1.ReasonRevocationRecordConflict,
			"configmap "+name+" exists but does not hold this revocation, and is never overwritten: "+err.Error()), historyConflictRetry
	}
	return recordedCondition(cond, name, rec.AcceptanceRevision, digest), 0
}

func recordedCondition(cond func(metav1.ConditionStatus, string, string) *metav1.Condition, name string, revision int64, digest string) *metav1.Condition {
	return cond(metav1.ConditionTrue, v1alpha1.ReasonRevocationRecorded,
		fmt.Sprintf("revocation of acceptance revision %d is recorded independently in %s (%s)", revision, name, digest))
}

// release removes the revocation finalizer with an optimistic lock, so it
// never applies to a newer state of the exception than the one whose
// record was verified. It returns nil when the exception is gone.
func (r *ExceptionReconciler) release(ctx context.Context, ex *v1alpha1.ComplianceException) (*v1alpha1.ComplianceException, error) {
	out := ex.DeepCopy()
	out.Finalizers = slices.DeleteFunc(out.Finalizers, func(f string) bool { return f == exception.RevocationFinalizer })
	if err := r.Client.Patch(ctx, out, client.MergeFromWithOptions(ex, client.MergeFromWithOptimisticLock{})); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("release %s on %s/%s: %w", exception.RevocationFinalizer, ex.Namespace, ex.Name, err)
	}
	return out, nil
}

// snapshot ensures the current revision's snapshot exists and matches the
// acceptance record. It returns the reference to record and the condition.
// A condition without a reason is a transient error to retry.
func (r *ExceptionReconciler) snapshot(ctx context.Context, ex *v1alpha1.ComplianceException) (*v1alpha1.AcceptanceSnapshotReference, metav1.Condition) {
	cond := func(status metav1.ConditionStatus, reason, msg string) metav1.Condition {
		return metav1.Condition{Type: v1alpha1.ConditionAcceptanceRecorded, Status: status, Reason: reason, Message: msg}
	}
	a, present, err := exception.ParseAcceptance(ex)
	switch {
	case !present:
		return nil, cond(metav1.ConditionFalse, v1alpha1.ReasonAcceptanceMissing, "no acceptance was recorded by admission; the exception grants nothing")
	case err != nil:
		return nil, cond(metav1.ConditionFalse, v1alpha1.ReasonAcceptanceInvalid, "the acceptance record is unreadable: "+err.Error())
	case a.Revision != ex.Spec.AcceptanceRevision:
		return nil, cond(metav1.ConditionFalse, v1alpha1.ReasonAcceptancePending, fmt.Sprintf("acceptance revision %d has no record yet", ex.Spec.AcceptanceRevision))
	}
	snap, err := exception.NewSnapshot(ex, a)
	if err != nil {
		return nil, cond(metav1.ConditionFalse, v1alpha1.ReasonAcceptanceInvalid, err.Error())
	}
	want, digest, err := snap.ConfigMap(r.Namespace)
	if err != nil {
		return nil, cond(metav1.ConditionFalse, v1alpha1.ReasonAcceptanceInvalid, err.Error())
	}
	ref := &v1alpha1.AcceptanceSnapshotReference{Revision: a.Revision, Snapshot: r.Namespace + "/" + want.Name, Digest: digest}

	got := &corev1.ConfigMap{}
	err = r.Reader.Get(ctx, client.ObjectKeyFromObject(want), got)
	if apierrors.IsNotFound(err) {
		err = r.Client.Create(ctx, want)
		if err == nil {
			return ref, cond(metav1.ConditionTrue, v1alpha1.ReasonSnapshotRecorded, "snapshot "+ref.Snapshot+" records acceptance revision "+fmt.Sprint(a.Revision))
		}
		if !apierrors.IsAlreadyExists(err) {
			return nil, metav1.Condition{Message: err.Error()}
		}
		// Created concurrently: verify what is there.
		err = r.Reader.Get(ctx, client.ObjectKeyFromObject(want), got)
	}
	if err != nil {
		return nil, metav1.Condition{Message: err.Error()}
	}
	// An existing snapshot is never rewritten. It must be ours, immutable and
	// identical to what this acceptance record produces.
	_, gotDigest, verr := exception.SnapshotFrom(got)
	switch {
	case got.Labels[targeting.LabelManagedBy] != targeting.ManagedByValue || got.Immutable == nil || !*got.Immutable:
		return nil, cond(metav1.ConditionFalse, v1alpha1.ReasonSnapshotConflict, "configmap "+ref.Snapshot+" exists but is not an immutable Konstapel snapshot")
	case verr != nil:
		return nil, cond(metav1.ConditionFalse, v1alpha1.ReasonSnapshotConflict, verr.Error())
	case gotDigest != digest:
		return nil, cond(metav1.ConditionFalse, v1alpha1.ReasonSnapshotConflict,
			fmt.Sprintf("snapshot %s has digest %s; the acceptance record produces %s", ref.Snapshot, gotDigest, digest))
	}
	return ref, cond(metav1.ConditionTrue, v1alpha1.ReasonSnapshotRecorded, "snapshot "+ref.Snapshot+" records acceptance revision "+fmt.Sprint(a.Revision))
}

func equalStatus(a, b v1alpha1.ComplianceExceptionStatus) bool {
	if (a.Acceptance == nil) != (b.Acceptance == nil) || (a.Acceptance != nil && *a.Acceptance != *b.Acceptance) || len(a.Conditions) != len(b.Conditions) {
		return false
	}
	for i := range a.Conditions {
		x, y := a.Conditions[i], b.Conditions[i]
		if x.Type != y.Type || x.Status != y.Status || x.Reason != y.Reason || x.Message != y.Message || x.ObservedGeneration != y.ObservedGeneration {
			return false
		}
	}
	return true
}

func setupExceptions(mgr manager.Manager, namespace string) error {
	if namespace == "" {
		namespace = DefaultSnapshotNamespace
	}
	return builder.ControllerManagedBy(mgr).Named("complianceexception").
		// Spec changes (renewals), the admission records (annotations) and
		// any change while the revocation finalizer is held, deletion
		// included, matter; other status updates do not.
		For(&v1alpha1.ComplianceException{}, builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.AnnotationChangedPredicate{}, revocationPending))).
		Complete(&ExceptionReconciler{Client: mgr.GetClient(), Reader: mgr.GetAPIReader(), Namespace: namespace})
}

// revocationPending passes updates of exceptions that still hold the
// revocation finalizer.
var revocationPending = predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
	return slices.Contains(e.ObjectNew.GetFinalizers(), exception.RevocationFinalizer)
}}

// identityWarmup looks up the controller identity once at startup on every
// replica, retrying until it succeeds. The validating webhook also looks it
// up on demand when a finalizer release needs it.
type identityWarmup struct {
	identity *exception.Identity
	retry    time.Duration
}

func (identityWarmup) NeedLeaderElection() bool { return false }

func (w identityWarmup) Start(ctx context.Context) error {
	for {
		lookup, cancel := context.WithTimeout(ctx, capabilityTimeout)
		_, err := w.identity.Get(lookup)
		cancel()
		if err == nil {
			return nil
		}
		ctrl.LoggerFrom(ctx).Info("controller identity lookup failed; retrying", "error", err.Error())
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(w.retry):
		}
	}
}
