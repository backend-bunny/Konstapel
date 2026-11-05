package publication

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// ToAPI converts a publication status into its AssessmentRun status form.
func ToAPI(s Status) v1alpha1.PublicationStatus {
	out := v1alpha1.PublicationStatus{
		Phase: v1alpha1.PublicationPhase(s.Phase), PublicationID: s.PublicationID,
		DescriptorSHA256: s.DescriptorSHA256, PackageSHA256: s.PackageSHA256, PackageSize: s.PackageSize,
		PublishedAt: mt(s.PublishedAt), ExpiresAt: mt(s.ExpiresAt), Availability: v1alpha1.Availability(s.Availability),
		Cleanup: v1alpha1.PublicationCleanup{State: v1alpha1.CleanupState(s.Cleanup.State), Attempts: int32(s.Cleanup.Attempts), LastAttempt: mt(s.Cleanup.LastAttempt), Message: s.Cleanup.Message},
	}
	if d := s.Destination; d != nil {
		out.Destination = &v1alpha1.PublicationDestination{ID: d.ID, Endpoint: d.Endpoint, Bucket: d.Bucket, Prefix: d.Prefix}
		if d.CredentialRef != nil {
			out.Destination.CredentialRef = &v1alpha1.SecretReference{Namespace: d.CredentialRef.Namespace, Name: d.CredentialRef.Name}
		}
	}
	for _, o := range s.OwnedObjects {
		out.OwnedObjects = append(out.OwnedObjects, v1alpha1.OwnedObject{Role: v1alpha1.ObjectRole(o.Role), AttemptID: o.AttemptID, Key: o.Key, VersionID: o.VersionID, UploadID: o.UploadID})
	}
	if c := s.Commit; c != nil {
		out.Commit = &v1alpha1.PublicationCommit{ManifestKey: c.ManifestKey, ManifestVersionID: c.ManifestVersionID, ArchiveKey: c.ArchiveKey, ArchiveVersionID: c.ArchiveVersionID}
	}
	if r := s.Retention; r != nil {
		out.Retention = &v1alpha1.PublicationRetention{Duration: r.Duration, BindingConfiguration: r.BindingConfiguration, SelectedAt: metav1.NewTime(r.SelectedAt)}
	}
	if f := s.Failure; f != nil {
		out.Failure = &v1alpha1.PublicationFailure{Reason: f.Reason, Message: f.Message, Retryable: f.Retryable, At: metav1.NewTime(f.At)}
	}
	return out
}

// FromAPI converts an AssessmentRun publication status back to the
// backend-facing form.
func FromAPI(s v1alpha1.PublicationStatus) Status {
	out := Status{
		Phase: Phase(s.Phase), PublicationID: s.PublicationID,
		DescriptorSHA256: s.DescriptorSHA256, PackageSHA256: s.PackageSHA256, PackageSize: s.PackageSize,
		PublishedAt: tm(s.PublishedAt), ExpiresAt: tm(s.ExpiresAt), Availability: Availability(s.Availability),
		Cleanup: Cleanup{State: CleanupState(s.Cleanup.State), Attempts: int(s.Cleanup.Attempts), LastAttempt: tm(s.Cleanup.LastAttempt), Message: s.Cleanup.Message},
	}
	if d := s.Destination; d != nil {
		out.Destination = &Destination{ID: d.ID, Endpoint: d.Endpoint, Bucket: d.Bucket, Prefix: d.Prefix}
		if d.CredentialRef != nil {
			out.Destination.CredentialRef = &SecretRef{Namespace: d.CredentialRef.Namespace, Name: d.CredentialRef.Name}
		}
	}
	for _, o := range s.OwnedObjects {
		out.OwnedObjects = append(out.OwnedObjects, OwnedObject{Role: ObjectRole(o.Role), AttemptID: o.AttemptID, Key: o.Key, VersionID: o.VersionID, UploadID: o.UploadID})
	}
	if c := s.Commit; c != nil {
		out.Commit = &Commit{ManifestKey: c.ManifestKey, ManifestVersionID: c.ManifestVersionID, ArchiveKey: c.ArchiveKey, ArchiveVersionID: c.ArchiveVersionID}
	}
	if r := s.Retention; r != nil {
		out.Retention = &Retention{Duration: r.Duration, BindingConfiguration: r.BindingConfiguration, SelectedAt: r.SelectedAt.UTC()}
	}
	if f := s.Failure; f != nil {
		out.Failure = &Failure{Reason: f.Reason, Message: f.Message, Retryable: f.Retryable, At: f.At.UTC()}
	}
	return out
}

// SummaryToAPI converts a run summary's result fields to the API form used by
// AssessmentRequest and AssessmentRun status.
func SummaryToAPI(s RunSummary) v1alpha1.AssessmentSummary {
	e, o := s.Evidence, s.Outcomes
	return v1alpha1.AssessmentSummary{
		Evidence: v1alpha1.EvidenceSummary{Completeness: v1alpha1.EvidenceCompleteness(e.Completeness), Expected: int32(e.Expected), Attributable: int32(e.Attributable), Missing: int32(e.Missing), Rejected: int32(e.Rejected), Unresolved: int32(e.Unresolved), StaleScopes: int32(e.StaleScopes)},
		Outcomes: v1alpha1.OutcomeCounts{Pass: int32(o.Pass), Fail: int32(o.Fail), Error: int32(o.Error), Skip: int32(o.Skip), AcceptedRisk: int32(o.AcceptedRisk), NotApplicable: int32(o.NotApplicable), Unknown: int32(o.Unknown)},
		Export:   v1alpha1.ExportState(s.Export),
	}
}

func mt(t *time.Time) *metav1.Time {
	if t == nil {
		return nil
	}
	v := metav1.NewTime(*t)
	return &v
}

func tm(t *metav1.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC()
	return &v
}
