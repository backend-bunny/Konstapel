package observability

import (
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// conditionStatus reads a binding Condition for its current generation. A
// missing Condition, or one observed for an older generation, is unknown:
// it does not describe the binding's current specification.
func conditionStatus(b *v1alpha1.ComplianceBinding, t string) Status {
	c := meta.FindStatusCondition(b.Status.Conditions, t)
	if c == nil || c.ObservedGeneration != b.Generation {
		return StatusUnknown
	}
	switch c.Status {
	case metav1.ConditionTrue:
		return StatusTrue
	case metav1.ConditionFalse:
		return StatusFalse
	}
	return StatusUnknown
}

// BindingTargetingFrom projects one binding's targeting status. The target
// count is known only when status was observed for the current generation.
func BindingTargetingFrom(b *v1alpha1.ComplianceBinding) BindingTargeting {
	out := BindingTargeting{
		Binding:     BindingRef{Name: b.Name, UID: string(b.UID)},
		Created:     b.CreationTimestamp.Time,
		Resolved:    conditionStatus(b, v1alpha1.ConditionResolved),
		EngineReady: conditionStatus(b, v1alpha1.ConditionEngineReady),
	}
	if b.Status.TargetCount != nil && b.Status.ObservedGeneration == b.Generation {
		n := int(*b.Status.TargetCount)
		out.TargetNamespaces = &n
	}
	return out
}

// TargetingFrom builds the targeting snapshot from the owner's bindings
// and the state of its enabled capabilities.
func TargetingFrom(bindings []v1alpha1.ComplianceBinding, capabilities map[Capability]Status) TargetingSnapshot {
	s := TargetingSnapshot{Bindings: make([]BindingTargeting, 0, len(bindings)), Capabilities: capabilities}
	for i := range bindings {
		s.Bindings = append(s.Bindings, BindingTargetingFrom(&bindings[i]))
	}
	return s
}

// StorageFrom derives the durable publication and cleanup backlog from the
// retained AssessmentRun records at now. It never lists storage.
//
//   - publication pending: closed runs still publishing whose last attempt
//     did not fail;
//   - publication failed: runs still publishing whose last attempt failed
//     and is being retried (actionable), including required signing that
//     is not yet met. A run whose publication finally
//     failed is a historical failure and is not counted;
//   - cleanup pending: committed packages past their recorded expiry whose
//     deletion is not yet confirmed, including failed deletions that are
//     retried with backoff;
//   - cleanup blocked: deletions refused by storage retention (object lock),
//     which need action.
//
// Deleted and operator-owned (orphaned) packages are not backlog. The
// records outlive their bindings, so the backlog does too.
func StorageFrom(runs []v1alpha1.AssessmentRun, now time.Time) StorageSnapshot {
	var s StorageSnapshot
	oldest := func(t *metav1.Time) {
		if t != nil && (s.OldestCleanupExpiry == nil || t.Time.Before(*s.OldestCleanupExpiry)) {
			v := t.Time
			s.OldestCleanupExpiry = &v
		}
	}
	for i := range runs {
		r := &runs[i]
		if r.Status.Phase == v1alpha1.RunPublishing {
			if c := meta.FindStatusCondition(r.Status.Conditions, v1alpha1.ConditionPublished); c != nil && c.Status == metav1.ConditionFalse && (c.Reason == v1alpha1.ReasonPublicationRetrying || c.Reason == v1alpha1.ReasonSigningPending) {
				s.PublicationFailed++
			} else {
				s.PublicationPending++
			}
			continue
		}
		p := r.Status.Publication
		if r.Status.Phase != v1alpha1.RunCompleted || p == nil {
			continue
		}
		switch {
		case p.Phase == v1alpha1.PublicationPhase(publication.PhaseDeleted), p.Phase == v1alpha1.PublicationPhase(publication.PhaseOrphaned),
			p.Cleanup.State == v1alpha1.CleanupState(publication.CleanupDeleted), p.Cleanup.State == v1alpha1.CleanupState(publication.CleanupOrphaned):
		case p.Cleanup.State == v1alpha1.CleanupState(publication.CleanupRetentionBlocked):
			s.CleanupBlocked++
			oldest(p.ExpiresAt)
		case p.ExpiresAt != nil && !now.Before(p.ExpiresAt.Time):
			s.CleanupPending++
			oldest(p.ExpiresAt)
		}
	}
	return s
}
