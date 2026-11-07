package controller

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// orphan applies the Orphaned disposition to a run pinned to a destination
// whose handoff inventory is saved, and then releases its retention
// finalizer. It issues no storage operation.
//
//   - The pin records orphanedAt; Konstapel never touches the run's storage
//     again, whatever later happens to the destination or its location.
//   - A publication keeps its original receipt, checksums, and expiry and
//     becomes Orphaned and Unavailable with operator-owned cleanup. A
//     publication already verified Deleted stays Deleted.
//   - An unfinished run ends Failed (DestinationOrphaned), never Published,
//     which releases its binding's active run slot.
//
// Runs already pending deletion take the same path: their ownership is in
// the saved inventory before their finalizer is released.
func (r *AssessmentRunReconciler) orphan(ctx context.Context, run *v1alpha1.AssessmentRun, ed *v1alpha1.EvidenceDestination) error {
	now := metav1.NewTime(r.now())
	run.Status.Destination.OrphanedAt = &now
	if pub := run.Status.Publication; pub != nil {
		orphanPublication(pub)
	}
	msg := fmt.Sprintf("storage handed to an operator by the orphan handoff of destination %s (inventory %s)", ed.Name, ed.Status.OrphanHandoff.Inventory.Header)
	if !runDone(run) {
		if err := r.fail(ctx, run, v1alpha1.ConditionPublished, v1alpha1.ReasonDestinationOrphaned, msg); err != nil {
			return err
		}
	} else if err := r.Client.Status().Update(ctx, run); err != nil {
		return err
	}
	return r.release(ctx, run)
}

// orphanPublication marks a publication Orphaned, keeping its receipt.
func orphanPublication(pub *v1alpha1.PublicationStatus) {
	if pub.Phase == v1alpha1.PublicationPhase(publication.PhaseDeleted) {
		return
	}
	pub.Phase = v1alpha1.PublicationPhase(publication.PhaseOrphaned)
	pub.Availability = v1alpha1.Availability(publication.AvailabilityUnavailable)
	pub.Cleanup.State = v1alpha1.CleanupState(publication.CleanupOrphaned)
	pub.Cleanup.Message = "an operator owns this storage; Konstapel does not delete it at expiry"
}
