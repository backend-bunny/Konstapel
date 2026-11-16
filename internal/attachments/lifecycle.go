package attachments

// Attachment lifecycle states (add-supporting-evidence-attachments 4.1-4.2).
//
// A record has four independent axes, and no combined verdict:
//   - temporal: the declared validity at an instant, validFrom <= T <
//     validUntil, from the immutable spec only. Upload, commitment, copy
//     and re-upload times never move it;
//   - content: whether the committed bytes are available (controller
//     status), and never available at or after the source expiry;
//   - association: each association's resolution against its binding's
//     identity, catalog and selected baseline (controller status);
//   - withdrawal: the record was deleted. A withdrawn record never enters
//     new coverage, while its retained source and cleanup ownership stay
//     until the recorded expiry.

import (
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// Temporal classifies the declared validity at asOf and returns the next
// declared boundary after it (zero once expired). The window is half-open:
// validFrom is the first valid instant, validUntil the first expired one.
func Temporal(v v1alpha1.AttachmentValidity, asOf time.Time) (v1alpha1.TemporalState, time.Time) {
	switch {
	case asOf.Before(v.ValidFrom.Time):
		return v1alpha1.TemporalNotYetValid, v.ValidFrom.UTC()
	case asOf.Before(v.ValidUntil.Time):
		return v1alpha1.TemporalCurrent, v.ValidUntil.UTC()
	}
	return v1alpha1.TemporalExpired, time.Time{}
}

// Withdrawn reports whether a record is withdrawn: deleted, or recorded as
// withdrawn by the controller.
func Withdrawn(a *v1alpha1.EvidenceAttachment) bool {
	return !a.DeletionTimestamp.IsZero() || a.Status.Withdrawal != nil
}

// Observation is one record's documentary context for one binding at an
// instant. It records states only; it never states that a control is met.
type Observation struct {
	Name, UID string
	// SpecDigest identifies the immutable registration.
	SpecDigest string
	// Association is the record's association with the binding, and its
	// last resolution (Pending until the controller resolved it).
	Association       v1alpha1.AttachmentAssociation
	AssociationStatus v1alpha1.AttachmentAssociationStatus
	Temporal          v1alpha1.TemporalState
	Content           v1alpha1.ContentState
	ContentReason     string
}

// Observe returns the record's context for the binding with this exact UID
// at asOf, or false when the record does not name that binding. Temporal
// state is computed at asOf from the declared validity, so it is exact at
// the boundaries whatever the controller last wrote; content is the
// controller's last observation, but never Available at or after the
// recorded source expiry.
func Observe(a *v1alpha1.EvidenceAttachment, bindingUID string, asOf time.Time) (Observation, bool) {
	for i, as := range a.Spec.Associations {
		if as.Binding.UID != bindingUID {
			continue
		}
		o := Observation{Name: a.Name, UID: string(a.UID), SpecDigest: SpecDigest(a.Spec), Association: as,
			AssociationStatus: v1alpha1.AttachmentAssociationStatus{Binding: as.Binding, State: v1alpha1.AssociationPending, Reason: v1alpha1.ReasonAssociationPending},
			Content:           v1alpha1.ContentPending, ContentReason: v1alpha1.ReasonAwaitingUpload}
		if i < len(a.Status.Associations) && a.Status.Associations[i].Binding == as.Binding {
			o.AssociationStatus = a.Status.Associations[i]
		}
		o.Temporal, _ = Temporal(a.Spec.Validity, asOf)
		if c := a.Status.Content; c != nil {
			o.Content, o.ContentReason = c.State, c.Reason
		}
		if st := a.Status.Storage; st != nil && st.Commitment != nil && !asOf.Before(st.Commitment.ExpiresAt.Time) {
			o.Content, o.ContentReason = v1alpha1.ContentUnavailable, v1alpha1.ReasonSourceExpired
		}
		return o, true
	}
	return Observation{}, false
}

// ForBinding selects the records for new coverage of the binding with this
// exact UID at asOf. Withdrawn records are never selected. Every other
// record that names the binding is, whatever its states, so a report can
// explain an expired, future, unavailable, pending or mismatched document
// rather than silently omit it.
func ForBinding(records []v1alpha1.EvidenceAttachment, bindingUID string, asOf time.Time) []Observation {
	var out []Observation
	for i := range records {
		if Withdrawn(&records[i]) {
			continue
		}
		if o, ok := Observe(&records[i], bindingUID, asOf); ok {
			out = append(out, o)
		}
	}
	return out
}
