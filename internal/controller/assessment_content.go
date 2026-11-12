package controller

// Content an assessment run exports from (add-policy-bundle-distribution
// 7.2 through the add-continuous-assessments package contract). A run of
// the image's vendored bundle exports from the runtime's ContentRoot exactly
// as before. A run of an OCI bundle freezes the exact verified bundle bytes
// into its staging directory when it starts, and exports, replays and
// packages only that copy: later cache eviction, registry loss or trust
// changes never alter the run's evidence, and no other content is ever
// substituted. Content that cannot be frozen makes the run's package an
// explicit Diagnostic.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// ContentFreezer freezes the bundle content an assessment run uses.
// stack.Router implements it: the vendored bundle reports vendored and is
// never copied; OCI content is copied out of the verified cache, or fails
// with its classified ContentError. A content source that does not
// implement it serves only vendored content.
type ContentFreezer interface {
	Freeze(ctx context.Context, ref v1alpha1.BundleReference, dir string) (frozen *bundle.Frozen, vendored bool, err error)
}

var _ ContentFreezer = (*stack.Router)(nil)

// freezerFor is the freezer of a content source: the source itself when it
// freezes; otherwise one that reports the source's vendored bundle (a
// targeting.LocalContent's name) as vendored and refuses every other name,
// so an unrouted source never stands in for OCI content.
func freezerFor(src targeting.ContentSource) ContentFreezer {
	if f, ok := src.(ContentFreezer); ok {
		return f
	}
	local, _ := src.(targeting.LocalContent)
	return localFreezer{name: local.Name}
}

type localFreezer struct{ name string }

func (l localFreezer) Freeze(_ context.Context, ref v1alpha1.BundleReference, _ string) (*bundle.Frozen, bool, error) {
	if l.name != "" && ref.Name == l.name {
		return nil, true, nil
	}
	return nil, false, fmt.Errorf("%w: %s@%s: this content source serves only vendored content and cannot freeze bundles", targeting.ErrContentUnavailable, ref.Name, ref.Digest)
}

// Staging files of a run's content.
const (
	// runContentFile records the run's OCI bundle and whether it was
	// frozen. Its absence means a vendored run (including runs staged
	// before content freezing existed).
	runContentFile = "content.json"
	// frozenContentDir is the frozen bundle (bundle.WriteFrozen layout).
	frozenContentDir = "frozen-bundle"
)

// runContent is the staged record of a run's OCI bundle.
type runContent struct {
	Ref v1alpha1.BundleReference `json:"ref"`
	// Failure explains why the bundle is not frozen; nil once it is.
	Failure *collector.ContentFailure `json:"failure,omitempty"`
}

func (r *AssessmentRunReconciler) frozenDir(run *v1alpha1.AssessmentRun) string {
	return filepath.Join(r.staging(run), frozenContentDir)
}

// readRunContent returns the staged content record, or nil for a vendored
// run.
func (r *AssessmentRunReconciler) readRunContent(run *v1alpha1.AssessmentRun) (*runContent, error) {
	var rc runContent
	switch err := assessment.Read(filepath.Join(r.staging(run), runContentFile), &rc); {
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return &rc, nil
}

// runBundle is the bundle a capture was resolved against: the one its
// subjects and contributions name, or the profile's selection when nothing
// in it resolved. More than one bundle is a mismatch, never a choice.
func runBundle(c collector.CaptureV2, selected *v1alpha1.BundleReference) (*v1alpha1.BundleReference, *collector.ContentFailure) {
	refs := map[v1alpha1.BundleReference]bool{}
	for _, s := range c.Subjects {
		refs[v1alpha1.BundleReference{Name: s.BundleName, Digest: s.BundleDigest}] = true
	}
	for _, x := range c.Contributions {
		refs[v1alpha1.BundleReference{Name: x.BundleName, Digest: x.BundleDigest}] = true
	}
	switch len(refs) {
	case 0:
		return selected, nil
	case 1:
		for ref := range refs {
			return &ref, nil
		}
	}
	return selected, &collector.ContentFailure{Reason: collector.ReasonContentMismatch,
		Message: fmt.Sprintf("the capture references %d bundles; a run is exported from exactly one", len(refs))}
}

// freezeContent decides and stages the content of a starting run. A
// vendored run stages nothing. An OCI run stages its record and, when the
// bundle resolves under current trust, its frozen copy; otherwise the
// record carries the failure, and collection continues (freezing is
// retried once more when the window closes). Only cancellation and staging I/O
// errors are returned.
func (r *AssessmentRunReconciler) freezeContent(ctx context.Context, run *v1alpha1.AssessmentRun, c collector.CaptureV2, selected *v1alpha1.BundleReference) error {
	ref, mismatch := runBundle(c, selected)
	if ref == nil {
		return nil // no profile: the vendored no-target plan, as before
	}
	_ = os.Remove(filepath.Join(r.staging(run), runContentFile))
	if err := os.RemoveAll(r.frozenDir(run)); err != nil {
		return err
	}
	if mismatch != nil {
		return assessment.Write(filepath.Join(r.staging(run), runContentFile), runContent{Ref: *ref, Failure: mismatch})
	}
	rc, vendored, err := r.freeze(ctx, freezerFor(r.Assess.Content), run, *ref)
	if err != nil || vendored {
		return err
	}
	return assessment.Write(filepath.Join(r.staging(run), runContentFile), rc)
}

// freeze freezes ref into the run's staging directory. A content failure
// is recorded in the returned record, not returned.
func (r *AssessmentRunReconciler) freeze(ctx context.Context, freezer ContentFreezer, run *v1alpha1.AssessmentRun, ref v1alpha1.BundleReference) (runContent, bool, error) {
	_, vendored, err := freezer.Freeze(ctx, ref, r.frozenDir(run))
	switch {
	case vendored:
		return runContent{}, true, nil
	case err == nil:
		return runContent{Ref: ref}, false, nil
	case ctx.Err() != nil:
		return runContent{}, false, ctx.Err()
	}
	log.FromContext(ctx).Info("run content could not be frozen", "run", run.Name, "bundle", ref.Name+"@"+ref.Digest, "error", err.Error())
	return runContent{Ref: ref, Failure: &collector.ContentFailure{Reason: collector.ReasonContentUnavailable,
		Message: truncateMsg(fmt.Sprintf("%s@%s could not be frozen for this run: %s", ref.Name, ref.Digest, contentMessage(err)))}}, false, nil
}

// retryFreeze retries, when the window closes, freezing an OCI run's
// bundle that was unavailable at start. The bundle is the one recorded at start, never a newer
// selection.
func (r *AssessmentRunReconciler) retryFreeze(ctx context.Context, run *v1alpha1.AssessmentRun) error {
	rc, err := r.readRunContent(run)
	if err != nil || rc == nil || rc.Failure == nil || rc.Failure.Reason != collector.ReasonContentUnavailable {
		return err
	}
	if err := os.RemoveAll(r.frozenDir(run)); err != nil {
		return err
	}
	next, vendored, err := r.freeze(ctx, freezerFor(r.Assess.Content), run, rc.Ref)
	if err != nil || vendored {
		return err
	}
	return assessment.Write(filepath.Join(r.staging(run), runContentFile), next)
}

// exportContent sets the content of an export request from the staged
// record: vendored runs keep the runtime's ContentRoot; an OCI run exports
// from its verified frozen copy, or records why it cannot. A frozen copy
// that is lost or no longer verifies is never re-resolved.
func (r *AssessmentRunReconciler) exportContent(run *v1alpha1.AssessmentRun, req *collector.ExportRequest) error {
	rc, err := r.readRunContent(run)
	switch {
	case err != nil:
		// An unreadable record cannot say which content the run used.
		req.Content = &collector.ContentFailure{Reason: collector.ReasonContentLost,
			Message: truncateMsg("the run's content record is unreadable; content is never re-resolved: " + err.Error())}
		return nil
	case rc == nil:
		return nil
	}
	ref := rc.Ref
	req.ContentRef = &ref
	if rc.Failure != nil {
		req.Content = rc.Failure
		return nil
	}
	f, err := bundle.ReadFrozen(r.frozenDir(run))
	if err != nil {
		req.Content = &collector.ContentFailure{Reason: collector.ReasonContentLost,
			Message: truncateMsg(fmt.Sprintf("the frozen copy of %s@%s is lost or no longer verifies; it is never re-resolved: %v", ref.Name, ref.Digest, err))}
		return nil
	}
	if f.Identity.Name != ref.Name || f.Identity.Digests.OCI != ref.Digest {
		req.Content = &collector.ContentFailure{Reason: collector.ReasonContentLost,
			Message: fmt.Sprintf("the frozen copy is %s@%s, not the run's %s@%s", f.Identity.Name, f.Identity.Digests.OCI, ref.Name, ref.Digest)}
		return nil
	}
	req.Root, req.Bundle, req.TrustedRoot = r.frozenDir(run), f, r.Runtime.ContentRoot
	return nil
}
