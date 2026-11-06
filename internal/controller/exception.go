package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/exception"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Acceptance snapshots are immutable ConfigMaps in the controller namespace:
// the controller creates and reads them and never updates or deletes them.
// +kubebuilder:rbac:groups="",namespace=konstapel-system,resources=configmaps,verbs=get;create

// DefaultSnapshotNamespace is the protected namespace for acceptance snapshots.
const DefaultSnapshotNamespace = "konstapel-system"

// ExceptionReconciler persists an immutable snapshot of each acceptance
// revision (add-self-service-policy-exceptions task 3.1) and records its
// reference in status. Native grants (task 3.2) are delivered only after
// the snapshot exists.
type ExceptionReconciler struct {
	Client client.Client
	// Reader reads snapshot ConfigMaps directly, so the manager does not
	// cache (or need list/watch on) ConfigMaps.
	Reader    client.Reader
	Namespace string
}

func (r *ExceptionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ex := &v1alpha1.ComplianceException{}
	if err := r.Client.Get(ctx, req.NamespacedName, ex); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !ex.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	ref, cond := r.snapshot(ctx, ex)
	if cond.Reason == "" {
		return ctrl.Result{}, fmt.Errorf("snapshot exception %s/%s: %s", ex.Namespace, ex.Name, cond.Message)
	}
	updated := ex.DeepCopy()
	if ref != nil {
		updated.Status.Acceptance = ref
	}
	cond.ObservedGeneration = ex.Generation
	meta.SetStatusCondition(&updated.Status.Conditions, cond)
	if equalStatus(ex.Status, updated.Status) {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, r.Client.Status().Update(ctx, updated)
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
		// Spec changes (renewals) and the admission record (an annotation)
		// both matter; status updates do not.
		For(&v1alpha1.ComplianceException{}, builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.AnnotationChangedPredicate{}))).
		Complete(&ExceptionReconciler{Client: mgr.GetClient(), Reader: mgr.GetAPIReader(), Namespace: namespace})
}
