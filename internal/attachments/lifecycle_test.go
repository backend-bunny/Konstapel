package attachments

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// add-supporting-evidence-attachments 4.1/4.2: the temporal axis is exact at
// its boundaries and independent of upload time; withdrawn records never
// enter new coverage; content is never available past the source expiry.

var (
	from  = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	until = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
)

func validity() v1alpha1.AttachmentValidity {
	return v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(from), ValidUntil: metav1.NewTime(until)}
}

func TestTemporalBoundariesAreExact(t *testing.T) {
	for _, c := range []struct {
		at    time.Time
		state v1alpha1.TemporalState
		next  time.Time
	}{
		{from.Add(-time.Nanosecond), v1alpha1.TemporalNotYetValid, from},
		{from, v1alpha1.TemporalCurrent, until},
		{until.Add(-time.Nanosecond), v1alpha1.TemporalCurrent, until},
		{until, v1alpha1.TemporalExpired, time.Time{}},
		{until.Add(100 * 365 * 24 * time.Hour), v1alpha1.TemporalExpired, time.Time{}},
	} {
		state, next := Temporal(validity(), c.at)
		if state != c.state || !next.Equal(c.next) {
			t.Errorf("at %s: %s next %s, want %s next %s", c.at.Format(time.RFC3339Nano), state, next, c.state, c.next)
		}
	}
}

func record(name string, bindings ...string) v1alpha1.EvidenceAttachment {
	a := v1alpha1.EvidenceAttachment{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID("uid-" + name)}, Spec: v1alpha1.EvidenceAttachmentSpec{
		Document: v1alpha1.AttachmentDocument{Title: name, MediaType: "application/pdf", Size: 1, SHA256: "sha256:" + strings.Repeat("0", 64)},
		Validity: validity()}}
	for _, b := range bindings {
		as := v1alpha1.AttachmentAssociation{Binding: v1alpha1.ExactBindingReference{Name: "binding-" + b, UID: b}, Controls: []v1alpha1.AttachmentControl{{ID: "pe-3"}}}
		a.Spec.Associations = append(a.Spec.Associations, as)
		a.Status.Associations = append(a.Status.Associations, v1alpha1.AttachmentAssociationStatus{Binding: as.Binding, State: v1alpha1.AssociationValid, Reason: v1alpha1.ReasonAssociationsValid})
	}
	committed := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	a.Status.Storage = &v1alpha1.AttachmentStorage{Commitment: &v1alpha1.AttachmentCommitment{CommittedAt: metav1.NewTime(committed),
		Retention: metav1.Duration{Duration: DefaultRetention}, ExpiresAt: metav1.NewTime(ExpiresAt(committed, until, DefaultRetention))}}
	a.Status.Content = &v1alpha1.AttachmentContentStatus{State: v1alpha1.ContentAvailable, Reason: v1alpha1.ReasonContentVerified}
	return a
}

func names(obs []Observation) []string {
	var out []string
	for _, o := range obs {
		out = append(out, o.Name)
	}
	return out
}

func TestWithdrawnRecordsNeverEnterNewCoverage(t *testing.T) {
	asOf := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	deleting := record("deleting", "b1")
	deleting.DeletionTimestamp = &metav1.Time{Time: asOf.Add(-time.Hour)}
	// The withdrawal is durable in status as well; either marks it.
	recorded := record("recorded", "b1")
	recorded.Status.Withdrawal = &v1alpha1.AttachmentWithdrawal{WithdrawnAt: metav1.NewTime(asOf.Add(-time.Hour))}
	expired := record("expired", "b1")
	expired.Spec.Validity.ValidUntil = metav1.NewTime(asOf.Add(-time.Second))
	mismatched := record("mismatched", "b1")
	mismatched.Status.Associations[0].State, mismatched.Status.Associations[0].Reason = v1alpha1.AssociationMismatched, v1alpha1.ReasonBindingReplaced
	recs := []v1alpha1.EvidenceAttachment{record("current", "b1", "b2"), deleting, recorded, expired, mismatched, record("other", "b2")}
	got := ForBinding(recs, "b1", asOf)
	if n := names(got); len(n) != 3 || n[0] != "current" || n[1] != "expired" || n[2] != "mismatched" {
		t.Fatalf("selected %v, want current, expired and mismatched (withdrawn never; other bindings never)", n)
	}
	// Each axis is reported separately.
	if got[0].Temporal != v1alpha1.TemporalCurrent || got[0].Content != v1alpha1.ContentAvailable || got[0].AssociationStatus.State != v1alpha1.AssociationValid {
		t.Errorf("current: %+v", got[0])
	}
	if got[1].Temporal != v1alpha1.TemporalExpired || got[1].Content != v1alpha1.ContentAvailable || got[1].AssociationStatus.State != v1alpha1.AssociationValid {
		t.Errorf("expired: %+v", got[1])
	}
	if got[2].Temporal != v1alpha1.TemporalCurrent || got[2].AssociationStatus.State != v1alpha1.AssociationMismatched {
		t.Errorf("mismatched: %+v", got[2])
	}
	if !Withdrawn(&deleting) || !Withdrawn(&recorded) || Withdrawn(&recs[0]) {
		t.Error("withdrawal is not recognised")
	}
}

// A late upload (or a re-upload of the same document) never renews its
// declared validity, and the source is never Available after its expiry
// even before the controller notices.
func TestUploadTimeNeverRenewsValidity(t *testing.T) {
	old := record("old", "b1")
	old.Spec.Validity = v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
		ValidUntil: metav1.NewTime(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))}
	committed := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	c := old.Status.Storage.Commitment
	c.CommittedAt, c.ExpiresAt = metav1.NewTime(committed), metav1.NewTime(ExpiresAt(committed, old.Spec.Validity.ValidUntil.Time, DefaultRetention))
	for _, at := range []time.Time{committed, committed.Add(time.Minute), committed.Add(30 * 24 * time.Hour)} {
		o, ok := Observe(&old, "b1", at)
		if !ok || o.Temporal != v1alpha1.TemporalExpired {
			t.Fatalf("at %s after an upload: %s", at, o.Temporal)
		}
	}
	o, _ := Observe(&old, "b1", c.ExpiresAt.Time.Add(-time.Nanosecond))
	if o.Content != v1alpha1.ContentAvailable {
		t.Fatalf("before the source expiry: %s", o.Content)
	}
	o, _ = Observe(&old, "b1", c.ExpiresAt.Time)
	if o.Content != v1alpha1.ContentUnavailable || o.ContentReason != v1alpha1.ReasonSourceExpired {
		t.Fatalf("at the source expiry: %s/%s", o.Content, o.ContentReason)
	}
	// Without a controller observation the association and content are
	// Pending, never assumed.
	fresh := record("fresh", "b1")
	fresh.Status = v1alpha1.EvidenceAttachmentStatus{}
	o, _ = Observe(&fresh, "b1", from)
	if o.AssociationStatus.State != v1alpha1.AssociationPending || o.Content != v1alpha1.ContentPending {
		t.Fatalf("unobserved: %+v", o)
	}
}
