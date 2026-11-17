package controller

// Supporting evidence in assessment runs (add-supporting-evidence-
// attachments 5.1, 5.2).
//
// The attachment owner maps its records onto the coverage owner's
// SupportingEvidenceContext (konstapel.io/supporting-evidence-context/v1)
// and the package owner places the platform package's protected files:
//
//   - At run start the run freezes, for its binding's exact UID, every
//     record attachments.ForBinding selects (withdrawn records never are):
//     identity, immutable registration and its digest, the association,
//     its last resolution, the content state and the recorded commitment
//     (supporting-start.json). Integration problems are recorded as an
//     unavailable context, never as an empty list.
//   - While collecting, a platform (Binding-scope) run copies each frozen
//     document whose association is Valid and whose content is Available
//     from its own pinned destination, verified against the registered size
//     and SHA-256, into run staging (supporting/<uid>). Reads stop at the
//     collection window's end; a document not copied by then is reported
//     unavailable (NotRetrieved). A namespace run copies nothing.
//   - At closure the records are read again: a record that was withdrawn
//     (deleted or gone) is marked withdrawn, one whose association or
//     content state changed is marked changed. States stay those frozen at
//     start; coverage classifies validity at the closure time. The context
//     is frozen with the closure (closed.json), so a re-export after a crash
//     uses the same context and the same staged bytes, or fails as capture
//     loss; it never reads a newer document.
//   - A platform package carries the context and the included copies with
//     protected roles; a namespace package carries only coverage's
//     sanitized projection (restricted entries, no private metadata, no
//     copy). Documents never add a check, an observation, a finding or an
//     outcome.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/attachments"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/coverage"
)

const (
	runSupportingFile    = "supporting-start.json"
	runSupportingDir     = "supporting"
	runSupportingVersion = 1

	// maxSupportingCopies and maxSupportingCopyBytes bound the documents
	// one platform package includes (the archive is bounded by
	// s3store.MaxArchiveBytes). Documents beyond them are reported but not
	// included (PackageLimit).
	maxSupportingCopies          = 64
	maxSupportingCopyBytes int64 = 256 << 20
	// maxSupportingCopyAttempt bounds one document read.
	maxSupportingCopyAttempt = 2 * time.Minute
)

// Coded content reasons of a run's supporting context.
const (
	// reasonNotRetrieved: the document was available at run start but was
	// not retrieved and verified within the collection window.
	reasonNotRetrieved = "NotRetrieved"
	// reasonPackageLimit: the package's copy budget was exhausted.
	reasonPackageLimit = "PackageLimit"
	// reasonRecordsUnavailable: the attachment records could not be read.
	reasonRecordsUnavailable = "RecordsUnavailable"
)

// supportingStart is the staged record of a run's frozen attachments.
type supportingStart struct {
	Version int `json:"version"`
	// Reason is set when the records could not be read: the context is
	// then unavailable, never empty.
	Reason     string             `json:"reason,omitempty"`
	ObservedAt time.Time          `json:"observedAt"`
	Entries    []frozenAttachment `json:"entries"`
}

// frozenAttachment is one record as frozen at run start.
type frozenAttachment struct {
	Name        string                               `json:"name"`
	UID         string                               `json:"uid"`
	SpecDigest  string                               `json:"specDigest"`
	Spec        v1alpha1.EvidenceAttachmentSpec      `json:"spec"`
	Association v1alpha1.AttachmentAssociation       `json:"association"`
	Resolution  v1alpha1.AttachmentAssociationStatus `json:"resolution"`
	Content     v1alpha1.ContentState                `json:"content"`
	Reason      string                               `json:"contentReason,omitempty"`
	Destination *v1alpha1.DestinationReference       `json:"destination,omitempty"`
	Commitment  *v1alpha1.AttachmentCommitment       `json:"commitment,omitempty"`
}

// includable reports whether a frozen document is to be copied into a
// platform package: a valid association to committed, available bytes.
func (f frozenAttachment) includable() bool {
	return f.Resolution.State == v1alpha1.AssociationValid && f.Content == v1alpha1.ContentAvailable &&
		f.Destination != nil && f.Commitment != nil
}

func (r *AssessmentRunReconciler) attachmentReader() client.Reader {
	if r.Assess != nil && r.Assess.Reader != nil {
		return r.Assess.Reader
	}
	return r.Client
}

// freezeSupporting stages the attachments a starting run assesses.
func (r *AssessmentRunReconciler) freezeSupporting(ctx context.Context, run *v1alpha1.AssessmentRun, b *v1alpha1.ComplianceBinding, now time.Time) error {
	rec := supportingStart{Version: runSupportingVersion, ObservedAt: now, Entries: []frozenAttachment{}}
	var list v1alpha1.EvidenceAttachmentList
	if err := r.attachmentReader().List(ctx, &list); err != nil {
		log.FromContext(ctx).Info("attachment records unavailable at run start; supporting evidence is reported unavailable", "run", run.Name, "error", err.Error())
		rec.Reason = reasonRecordsUnavailable
	} else {
		byUID := map[string]*v1alpha1.EvidenceAttachment{}
		for i := range list.Items {
			byUID[string(list.Items[i].UID)] = &list.Items[i]
		}
		for _, o := range attachments.ForBinding(list.Items, string(b.UID), now) {
			a := byUID[o.UID]
			f := frozenAttachment{Name: o.Name, UID: o.UID, SpecDigest: o.SpecDigest, Spec: *a.Spec.DeepCopy(), Association: o.Association,
				Resolution: o.AssociationStatus, Content: o.Content, Reason: o.ContentReason}
			if st := a.Status.Storage; st != nil {
				f.Destination, f.Commitment = st.Destination.DeepCopy(), st.Commitment.DeepCopy()
			}
			rec.Entries = append(rec.Entries, f)
		}
		slices.SortFunc(rec.Entries, func(x, y frozenAttachment) int { return strings.Compare(x.UID, y.UID) })
	}
	return assessment.Write(filepath.Join(r.staging(run), runSupportingFile), rec)
}

func (r *AssessmentRunReconciler) readSupporting(run *v1alpha1.AssessmentRun) (*supportingStart, error) {
	var rec supportingStart
	if err := assessment.Read(filepath.Join(r.staging(run), runSupportingFile), &rec); err != nil {
		return nil, err
	}
	if rec.Version != runSupportingVersion {
		return nil, fmt.Errorf("supporting record version %d is not %d", rec.Version, runSupportingVersion)
	}
	return &rec, nil
}

func (r *AssessmentRunReconciler) supportingCopy(run *v1alpha1.AssessmentRun, uid string) string {
	return filepath.Join(r.staging(run), runSupportingDir, uid)
}

// copySupporting copies a platform run's includable documents that are not
// yet staged, within budget, before deadline. Failures are retried on the
// next poll; whatever is staged at closure is what the package includes.
func (r *AssessmentRunReconciler) copySupporting(ctx context.Context, run *v1alpha1.AssessmentRun, now, deadline time.Time) {
	if run.Spec.Scope == v1alpha1.RunScopeNamespace || r.Attachments == nil || r.Attachments.Stores == nil || !now.Before(deadline) {
		return
	}
	rec, err := r.readSupporting(run)
	if err != nil || rec.Reason != "" {
		return
	}
	var used int64
	n := 0
	for _, f := range rec.Entries {
		if !f.includable() || n >= maxSupportingCopies || used+f.Commitment.Size > maxSupportingCopyBytes {
			continue
		}
		n++
		used += f.Commitment.Size
		if _, err := os.Stat(r.supportingCopy(run, f.UID)); err == nil {
			continue
		}
		if !now.Before(f.Commitment.ExpiresAt.Time) {
			continue // the source expired: never retrieved
		}
		end := now.Add(maxSupportingCopyAttempt)
		if deadline.Before(end) {
			end = deadline
		}
		actx, cancel := context.WithDeadline(ctx, end)
		err := r.fetchSupporting(actx, run, f)
		cancel()
		if err != nil {
			log.FromContext(ctx).Info("supporting document not retrieved; retried until the collection window closes", "run", run.Name, "attachment", f.Name, "error", truncateMsg(err.Error()))
		}
	}
}

// fetchSupporting reads one committed document from its pinned destination
// and stages it once its size and SHA-256 match the registration and the
// recorded commitment.
func (r *AssessmentRunReconciler) fetchSupporting(ctx context.Context, run *v1alpha1.AssessmentRun, f frozenAttachment) error {
	s := r.Attachments
	if s.Fences != nil {
		var done func()
		var err error
		if ctx, done, err = s.Fences.Begin(ctx, f.Destination.UID, "run "+run.Name+" supporting "+f.Name); err != nil {
			return fmt.Errorf("destination %s is fenced: %w", f.Destination.Name, err)
		}
		defer done()
	}
	st, err := s.Stores.Store(ctx, *f.Destination)
	if err != nil {
		return err
	}
	a := &v1alpha1.EvidenceAttachment{ObjectMeta: metav1.ObjectMeta{Name: f.Name, UID: types.UID(f.UID)}, Spec: f.Spec}
	want := attachments.Expected(f.Spec)
	if f.Commitment.SHA256 != want.SHA256 || f.Commitment.Size != want.Size || f.Commitment.SpecDigest != f.SpecDigest {
		return errors.New("the recorded commitment is not the registered document")
	}
	body, err := st.Open(ctx, s.receipt(a, f.Commitment, st))
	if err != nil {
		return err
	}
	defer body.Close()
	dir := filepath.Join(r.staging(run), runSupportingDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".fetch-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(body, want.Size+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != want.Size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != want.SHA256 {
		return fmt.Errorf("%w: the stored document does not match its registered size and sha256", attachments.ErrIntegrity)
	}
	return os.Rename(tmp.Name(), r.supportingCopy(run, f.UID))
}

// verifyStagedCopy re-checks a staged copy against its registration.
func verifyStagedCopy(p string, want attachments.Document) error {
	fh, err := os.Open(p)
	if err != nil {
		return err
	}
	defer fh.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(fh, want.Size+1))
	if err != nil {
		return err
	}
	if n != want.Size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != want.SHA256 {
		return collector.ErrSupportingCopy
	}
	return nil
}

func associationState(s v1alpha1.AssociationState) string {
	switch s {
	case v1alpha1.AssociationValid:
		return coverage.SupportingAssociationValid
	case v1alpha1.AssociationMismatched:
		return coverage.SupportingAssociationMismatched
	}
	return coverage.SupportingAssociationPending
}

func contentState(s v1alpha1.ContentState) string {
	switch s {
	case v1alpha1.ContentAvailable:
		return coverage.SupportingContentAvailable
	case v1alpha1.ContentUnavailable:
		return coverage.SupportingContentUnavailable
	}
	return coverage.SupportingContentPending
}

// closeSupporting builds the run's supporting context at closure. A run
// started without a frozen record (by an earlier controller) has none: its
// coverage reports the integration disabled rather than guessing.
func (r *AssessmentRunReconciler) closeSupporting(ctx context.Context, run *v1alpha1.AssessmentRun, b *v1alpha1.ComplianceBinding, closed time.Time) *coverage.SupportingEvidenceContext {
	rec, err := r.readSupporting(run)
	if err != nil {
		return nil
	}
	out := &coverage.SupportingEvidenceContext{Version: coverage.SupportingContextVersion, Integration: coverage.IntegrationAvailable, Entries: []coverage.SupportingEntry{}}
	if rec.Reason != "" {
		out.Integration, out.Reason = coverage.IntegrationUnavailable, rec.Reason
		return out
	}
	// A platform context naming a document makes the package protected:
	// write one only while every deployed reader enforces document read.
	if run.Spec.Scope != v1alpha1.RunScopeNamespace && len(rec.Entries) > 0 {
		if err := r.protectedReaders(ctx); err != nil {
			log.FromContext(ctx).Info("package readers not verified to enforce document read; supporting evidence is reported unavailable", "run", run.Name, "error", err.Error())
			out.Integration, out.Reason = coverage.IntegrationUnavailable, reasonReadersUnverified
			return out
		}
	}
	var list v1alpha1.EvidenceAttachmentList
	if err := r.attachmentReader().List(ctx, &list); err != nil {
		// Withdrawal and changes during the capture cannot be told.
		log.FromContext(ctx).Info("attachment records unavailable at closure; supporting evidence is reported unavailable", "run", run.Name, "error", err.Error())
		out.Integration, out.Reason = coverage.IntegrationUnavailable, reasonRecordsUnavailable
		return out
	}
	now := map[string]*v1alpha1.EvidenceAttachment{}
	for i := range list.Items {
		now[string(list.Items[i].UID)] = &list.Items[i]
	}
	platform := run.Spec.Scope != v1alpha1.RunScopeNamespace
	var used int64
	n := 0
	for _, f := range rec.Entries {
		e := coverage.SupportingEntry{Source: f.UID, Revision: f.SpecDigest, ObservedAt: closed, BindingUID: f.Association.Binding.UID,
			CatalogDigest: f.Association.CatalogDigest, Association: associationState(f.Resolution.State), Content: contentState(f.Content),
			ContentReason: f.Reason, ValidFrom: f.Spec.Validity.ValidFrom.UTC(), ValidUntil: f.Spec.Validity.ValidUntil.UTC(), Access: coverage.AccessNotIncluded}
		for _, c := range f.Association.Controls {
			e.Controls = append(e.Controls, coverage.SupportingControl{ID: c.ID, Statements: slices.Clone(c.Statements)})
		}
		cur := now[f.UID]
		if cur == nil || attachments.Withdrawn(cur) {
			e.Withdrawn = true
		} else if o, ok := attachments.Observe(cur, string(b.UID), closed); !ok || o.AssociationStatus.State != f.Resolution.State || o.Content != f.Content {
			e.Changed = true
		}
		if !platform {
			// A namespace package sees the sanitized projection only.
			e.Revision, e.Access = "", coverage.AccessRestricted
			out.Entries = append(out.Entries, e)
			continue
		}
		e.Document = &coverage.SupportingDocument{Title: f.Spec.Document.Title, Issuer: f.Spec.Source.Issuer, Scope: f.Spec.Scope.Description,
			MediaType: f.Spec.Document.MediaType, Size: f.Spec.Document.Size, SHA256: strings.TrimPrefix(f.Spec.Document.SHA256, "sha256:")}
		if f.includable() {
			switch {
			case n >= maxSupportingCopies || used+f.Commitment.Size > maxSupportingCopyBytes:
				e.ContentReason = reasonPackageLimit
			case verifyStagedCopy(r.supportingCopy(run, f.UID), attachments.Expected(f.Spec)) == nil:
				n++
				used += f.Commitment.Size
				e.Access, e.Document.Copy = coverage.AccessIncluded, coverage.SupportingCopyPath(f.UID)
			default:
				n++
				used += f.Commitment.Size
				e.Content, e.ContentReason = coverage.SupportingContentUnavailable, reasonNotRetrieved
			}
		}
		out.Entries = append(out.Entries, e)
	}
	return out
}

// supportingFiles are the protected files of a platform package for the
// frozen context sup: the context itself and every included copy, each
// re-verified. A staged copy that no longer verifies is capture loss.
func (r *AssessmentRunReconciler) supportingFiles(run *v1alpha1.AssessmentRun, sup *coverage.SupportingEvidenceContext, closed time.Time) (*collector.SupportingFiles, error) {
	if run.Spec.Scope == v1alpha1.RunScopeNamespace || sup == nil || sup.Integration != coverage.IntegrationAvailable || len(sup.Entries) == 0 ||
		sup.Validate(closed) != nil {
		// An invalid context is left to coverage, which reports it as
		// ContextInvalid; it is never packaged.
		return nil, nil
	}
	raw, err := json.MarshalIndent(sup, "", "  ")
	if err != nil {
		return nil, err
	}
	out := &collector.SupportingFiles{Context: append(raw, '\n')}
	for _, e := range sup.Entries {
		if e.Access != coverage.AccessIncluded {
			continue
		}
		p := r.supportingCopy(run, e.Source)
		if err := verifyStagedCopy(p, attachments.Document{SHA256: "sha256:" + e.Document.SHA256, Size: e.Document.Size}); err != nil {
			return nil, fmt.Errorf("staged supporting document %s: %w", e.Source, err)
		}
		out.Documents = append(out.Documents, collector.SupportingDocument{ID: e.Source, Source: p, SHA256: e.Document.SHA256, Size: e.Document.Size,
			Title: e.Document.Title, MediaType: e.Document.MediaType})
	}
	return out, nil
}
