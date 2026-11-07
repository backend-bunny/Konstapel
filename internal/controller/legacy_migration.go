package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// ConditionLegacyMigrated reports a legacy run's migration to an
// EvidenceDestination: True once its location is verified and pinned, False
// with the blocker while it cannot be.
const ConditionLegacyMigrated = "LegacyMigrated"

// Legacy migration reasons.
const (
	ReasonLegacyMigrated           = "Migrated"
	ReasonLegacyNoDestination      = "NoDestination"
	ReasonLegacyAmbiguous          = "AmbiguousDestination"
	ReasonLegacyUnavailable        = "DestinationUnavailable"
	ReasonLegacyConfiguration      = "ConfigurationUnavailable"
	ReasonLegacyLocationMismatch   = "LocationMismatch"
	ReasonLegacyReceiptMissing     = "ReceiptMissing"
	ReasonLegacyLabelledElsewhere  = "LabelledForAnotherDestination"
	legacyMigrationRetry           = 10 * time.Minute
	legacyInterruptedRunFailureMsg = "started with the removed legacy file destination before anything was stored; a new run is needed"
)

// The preserved legacy configuration is read from the controller namespace.
// +kubebuilder:rbac:groups="",namespace=konstapel-system,resources=configmaps,verbs=get

// legacy handles a run that has no destination pin while the controller
// has no legacy publisher: a run started under the removed
// --evidence-destination file. It reports whether it handled the run.
//
//   - A run with a recorded receipt is migrated: exactly one
//     EvidenceDestination must declare the receipt's legacy destination ID,
//     and the receipt, the preserved legacy configuration, and that
//     destination must name the same endpoint, bucket, region (from the
//     configuration; receipts do not record it), and prefix. The verified
//     association is recorded in the run's pin and governs everything after.
//     Anything else leaves the run visibly blocked, with its ownership and
//     finalizer intact, and never touches storage.
//   - A run still collecting stored nothing yet; it ends so a new run can
//     start against a destination.
//   - A publishing or terminal run without a receipt may own upload
//     attempts at an unknown location; it stays blocked unless its attempts
//     were already cleaned.
//
// Archive bytes, commit manifests, keys, versions, publication time and
// expiry are never rewritten: the pinned destination resolves to the same
// keys the legacy destination used.
func (r *AssessmentRunReconciler) legacy(ctx context.Context, run *v1alpha1.AssessmentRun) (bool, ctrl.Result, error) {
	switch run.Status.Phase {
	case "", v1alpha1.RunPending:
		return false, ctrl.Result{}, nil // not started: it pins normally
	}
	if runDone(run) && !controllerutil.ContainsFinalizer(run, RetentionFinalizer) {
		return true, ctrl.Result{}, nil // nothing owned remains
	}
	rec := run.Status.Publication
	if rec == nil || rec.Destination == nil {
		switch {
		case run.Status.Phase == v1alpha1.RunCollecting || run.Status.Phase == v1alpha1.RunExporting:
			return true, ctrl.Result{}, r.fail(ctx, run, v1alpha1.ConditionPublished, ReasonDestinationUnavailable, legacyInterruptedRunFailureMsg)
		case runDone(run) && (run.Status.Scope == nil || meta.IsStatusConditionTrue(run.Status.Conditions, v1alpha1.ConditionAttemptsCleaned)):
			return true, ctrl.Result{}, r.release(ctx, run)
		}
		return r.legacyBlocked(ctx, run, ReasonLegacyReceiptMissing, "the run may own upload attempts but recorded no destination; its location cannot be established")
	}
	id := rec.Destination.ID
	var list v1alpha1.EvidenceDestinationList
	if err := r.reader().List(ctx, &list); err != nil {
		return true, ctrl.Result{}, err
	}
	var matches []*v1alpha1.EvidenceDestination
	for i := range list.Items {
		if l := list.Items[i].Spec.Legacy; l != nil && l.DestinationID == id {
			matches = append(matches, &list.Items[i])
		}
	}
	switch {
	case len(matches) == 0:
		return r.legacyBlocked(ctx, run, ReasonLegacyNoDestination, "no EvidenceDestination declares legacy destination "+id)
	case len(matches) > 1:
		names := make([]string, len(matches))
		for i, ed := range matches {
			names[i] = ed.Name
		}
		return r.legacyBlocked(ctx, run, ReasonLegacyAmbiguous, fmt.Sprintf("legacy destination %s is declared by %d EvidenceDestinations (%s); exactly one is required", id, len(matches), strings.Join(names, ", ")))
	}
	ed := matches[0]
	if !ed.DeletionTimestamp.IsZero() || ed.Status.OrphanIntent != nil {
		return r.legacyBlocked(ctx, run, ReasonLegacyUnavailable, "EvidenceDestination "+ed.Name+" is being deleted")
	}
	cfg, err := r.legacyConfiguration(ctx, ed)
	if err != nil {
		return r.legacyBlocked(ctx, run, ReasonLegacyConfiguration, err.Error())
	}
	if why := legacyMismatch(id, rec.Destination, cfg, ed); why != "" {
		return r.legacyBlocked(ctx, run, ReasonLegacyLocationMismatch, why)
	}
	if uid := run.Labels[LabelRunDestination]; uid != "" && uid != string(ed.UID) {
		return r.legacyBlocked(ctx, run, ReasonLegacyLabelledElsewhere, "the run is labelled for destination "+uid)
	}
	return true, ctrl.Result{}, r.attachMigrated(ctx, run, ed, id)
}

// legacyConfiguration reads and parses the preserved legacy destination file.
func (r *AssessmentRunReconciler) legacyConfiguration(ctx context.Context, ed *v1alpha1.EvidenceDestination) (s3store.Destination, error) {
	ref := ed.Spec.Legacy.Configuration
	key := ref.Key
	if key == "" {
		key = "destination.yaml"
	}
	cm := &corev1.ConfigMap{}
	if err := r.reader().Get(ctx, client.ObjectKey{Namespace: controllerNamespace(r.Runtime.ControllerNamespace), Name: ref.Name}, cm); err != nil {
		return s3store.Destination{}, fmt.Errorf("preserved legacy configuration ConfigMap %s: %w", ref.Name, err)
	}
	raw, ok := cm.Data[key]
	if !ok {
		return s3store.Destination{}, fmt.Errorf("preserved legacy configuration ConfigMap %s has no key %s", ref.Name, key)
	}
	d, err := s3store.ParseDestination([]byte(raw))
	if err != nil {
		return s3store.Destination{}, fmt.Errorf("preserved legacy configuration ConfigMap %s: %w", ref.Name, err)
	}
	return d, nil
}

// legacyMismatch compares the receipt, the preserved configuration, and the
// destination. It returns why they differ, or "".
func legacyMismatch(id string, rec *v1alpha1.PublicationDestination, cfg s3store.Destination, ed *v1alpha1.EvidenceDestination) string {
	endpoint := func(s string) string { return strings.TrimSuffix(s, "/") }
	prefix := func(s string) string { return s3store.Destination{Prefix: s}.KeyPrefix() }
	s := ed.Spec.S3
	for _, c := range []struct{ field, receipt, config, dest string }{
		{"id", id, cfg.ID, ed.Spec.Legacy.DestinationID},
		{"endpoint", endpoint(rec.Endpoint), endpoint(cfg.Endpoint), endpoint(s.Endpoint)},
		{"bucket", rec.Bucket, cfg.Bucket, s.Bucket},
		{"prefix", prefix(rec.Prefix), prefix(cfg.Prefix), prefix(s.Prefix)},
	} {
		if c.receipt != c.config || c.config != c.dest {
			return fmt.Sprintf("%s differs: receipt %q, preserved configuration %q, EvidenceDestination %s %q", c.field, c.receipt, c.config, ed.Name, c.dest)
		}
	}
	// Receipts do not record the region: the preserved configuration does.
	if cfg.Region != s.Region {
		return fmt.Sprintf("region differs: preserved configuration %q, EvidenceDestination %s %q", cfg.Region, ed.Name, s.Region)
	}
	return ""
}

// attachMigrated pins a verified legacy run to its destination with the
// same protocol as a starting run: label first, then an uncached
// confirmation that adds the destination's finalizer conditioned on its
// resourceVersion, then the pin in status. A retry repeats it idempotently.
func (r *AssessmentRunReconciler) attachMigrated(ctx context.Context, run *v1alpha1.AssessmentRun, ed *v1alpha1.EvidenceDestination, id string) error {
	if run.Labels[LabelRunDestination] == "" {
		if run.Labels == nil {
			run.Labels = map[string]string{}
		}
		run.Labels[LabelRunDestination] = string(ed.UID)
		status := run.Status.DeepCopy()
		if err := r.Client.Update(ctx, run); err != nil {
			return err
		}
		run.Status = *status
	}
	fresh := &v1alpha1.EvidenceDestination{}
	if err := r.reader().Get(ctx, client.ObjectKey{Name: ed.Name}, fresh); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("EvidenceDestination %s disappeared while migrating; retrying", ed.Name)
		}
		return err
	}
	if fresh.UID != ed.UID || !fresh.DeletionTimestamp.IsZero() {
		return fmt.Errorf("EvidenceDestination %s changed while migrating; retrying", ed.Name)
	}
	controllerutil.AddFinalizer(fresh, DestinationFinalizer)
	if err := r.Client.Update(ctx, fresh); err != nil {
		return err
	}
	now := metav1.NewTime(r.now())
	s := fresh.Spec.S3
	run.Status.Destination = &v1alpha1.DestinationPin{DestinationReference: v1alpha1.DestinationReference{Name: fresh.Name, UID: string(fresh.UID)},
		Endpoint: s.Endpoint, Bucket: s.Bucket, Region: s.Region, Prefix: s.Prefix, Source: v1alpha1.DestinationMigrated, PinnedAt: now,
		Legacy: &v1alpha1.LegacyPin{DestinationID: id, VerifiedAt: now}}
	meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{Type: ConditionLegacyMigrated, Status: metav1.ConditionTrue, Reason: ReasonLegacyMigrated,
		Message: truncateMsg("legacy destination " + id + " verified and attached to EvidenceDestination " + fresh.Name)})
	return r.Client.Status().Update(ctx, run)
}

// legacyBlocked records why a legacy run cannot be migrated and checks
// again later. Nothing is stored, released, or cleaned meanwhile.
func (r *AssessmentRunReconciler) legacyBlocked(ctx context.Context, run *v1alpha1.AssessmentRun, reason, msg string) (bool, ctrl.Result, error) {
	c := metav1.Condition{Type: ConditionLegacyMigrated, Status: metav1.ConditionFalse, Reason: reason, Message: truncateMsg(msg)}
	if old := meta.FindStatusCondition(run.Status.Conditions, ConditionLegacyMigrated); old == nil || old.Status != c.Status || old.Reason != c.Reason || old.Message != c.Message {
		meta.SetStatusCondition(&run.Status.Conditions, c)
		if err := r.Client.Status().Update(ctx, run); err != nil {
			return true, ctrl.Result{}, err
		}
	}
	return true, ctrl.Result{RequeueAfter: legacyMigrationRetry}, nil
}
