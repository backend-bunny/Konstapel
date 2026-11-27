package controller

// Selection changes observed after a run froze (add-assessment-provider-
// contract 3.5, owner decision 2026-11-27).
//
// A run freezes the bundle its binding selected when it started
// (coverage-selection.json) and keeps using it. While it collects, each
// observation compares the binding's current selection with that frozen
// one; the first difference is recorded once in
// status.observedSelectionChange with the observation time. The field
// reports only what was observed: a change made and reverted between two
// observations is invisible and is not claimed, a later change or a revert
// after the record does not rewrite it, and a run whose frozen bundle is
// unknown (staged by an earlier controller) records nothing. The frozen
// content, capture, package descriptor and publication are unchanged.

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// observeSelection records the first observed selection change of a
// collecting run. profile is the binding's profile as just read (nil when
// it selects none). It writes status only when it records.
func (r *AssessmentRunReconciler) observeSelection(ctx context.Context, run *v1alpha1.AssessmentRun, profile *v1alpha1.ComplianceProfile, now time.Time) error {
	if run.Status.ObservedSelectionChange != nil {
		return nil // written once
	}
	rec, err := r.readSelection(run)
	if err != nil || (rec.Profile != nil && rec.Bundle == nil) {
		return nil // the frozen selection is unknown: nothing is inferred
	}
	var observed *v1alpha1.BundleReference
	if profile != nil {
		ref := profile.Spec.Bundle
		observed = &ref
	}
	if sameBundle(rec.Bundle, observed) {
		return nil
	}
	run.Status.ObservedSelectionChange = &v1alpha1.ObservedSelectionChange{ObservedTime: metav1.NewTime(now), Frozen: rec.Bundle, Observed: observed}
	log.FromContext(ctx).Info("observed a selection change after the run froze; the run keeps its frozen selection", "run", run.Name)
	return r.Client.Status().Update(ctx, run)
}

func sameBundle(a, b *v1alpha1.BundleReference) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
