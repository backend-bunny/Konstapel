package controller

// Content an assessment run exports from (add-policy-bundle-distribution
// 7.2 and 7.4 through the add-continuous-assessments package contract).
//
// A run's content is a set keyed by bundle manifest digest: every bundle a
// contribution the run assesses was applied from (its subjects' bundles,
// which come from the applied engine policies' bundle and bundle-digest
// annotations), and, only when nothing was applied, the desired bundle its
// plan names. The desired bundle (the profile's selection) is recorded
// separately, with the explicit desired/applied differences.
//
// A run whose contributions were all applied from the image's vendored
// content while it was also desired exports from the runtime's ContentRoot
// exactly as before and stages nothing. Every other run freezes each OCI
// bundle of its set, the exact verified bytes, into its staging directory
// when it starts, under an assessment cache lease (Router.Freeze ->
// OCIContent.Freeze), and exports, replays and packages only those copies:
// later cache eviction, registry loss or trust changes never alter the
// run's evidence. Content that cannot be frozen (retried once when the
// window closes), a lost or altered copy, or vendored content of another
// image makes the package an explicit Diagnostic; desired or vendored
// content is never substituted for applied content.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

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

// vendoredName is the content source's vendored bundle name ("" if none).
func vendoredName(src targeting.ContentSource) string {
	switch s := src.(type) {
	case interface{ LocalName() string }:
		return s.LocalName()
	case targeting.LocalContent:
		return s.Name
	}
	return ""
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
	// runContentFile records the run's content set. Its absence means a
	// vendored run (including runs staged before content freezing existed).
	runContentFile = "content.json"
	// frozenContentDir holds one frozen bundle (bundle.WriteFrozen layout)
	// per OCI member, named by the hex of its manifest digest.
	frozenContentDir = "frozen-bundles"
	// runContentVersion versions runContent. A record of another version
	// (staged by an earlier controller) is never re-resolved: its package
	// is ContentLost.
	runContentVersion = 2
)

// runContent is the staged record of a run's content set.
type runContent struct {
	Version int `json:"version"`
	// Desired is the profile's selection when the run started.
	Desired *v1alpha1.BundleReference `json:"desired,omitempty"`
	// Members are the applied bundles, and the desired one when nothing
	// was applied, sorted by manifest digest.
	Members []runMember `json:"members"`
}

// runMember is one bundle of a run's content set.
type runMember struct {
	Ref      v1alpha1.BundleReference `json:"ref"`
	Applied  bool                     `json:"applied"`
	Vendored bool                     `json:"vendored,omitempty"`
	// Failure explains why the bundle is not frozen; nil once it is.
	Failure *collector.ContentFailure `json:"failure,omitempty"`
}

func (r *AssessmentRunReconciler) frozenDir(run *v1alpha1.AssessmentRun, digest string) string {
	return filepath.Join(r.staging(run), frozenContentDir, strings.TrimPrefix(digest, "sha256:"))
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
	if rc.Version != runContentVersion {
		return nil, fmt.Errorf("content record version %d is not %d", rc.Version, runContentVersion)
	}
	return &rc, nil
}

// appliedContent is the set of bundles a capture's contributions were
// applied from: the bundles its subjects and contributions name, sorted by
// manifest digest.
func appliedContent(c collector.CaptureV2) []v1alpha1.BundleReference {
	refs := map[v1alpha1.BundleReference]bool{}
	for _, s := range c.Subjects {
		refs[v1alpha1.BundleReference{Name: s.BundleName, Digest: s.BundleDigest}] = true
	}
	for _, x := range c.Contributions {
		refs[v1alpha1.BundleReference{Name: x.BundleName, Digest: x.BundleDigest}] = true
	}
	out := make([]v1alpha1.BundleReference, 0, len(refs))
	for ref := range refs {
		out = append(out, ref)
	}
	slices.SortFunc(out, func(a, b v1alpha1.BundleReference) int {
		return strings.Compare(a.Digest+"\x00"+a.Name, b.Digest+"\x00"+b.Name)
	})
	return out
}

// freezeContent decides and stages the content of a starting run. A run
// whose applied and desired content is only the vendored bundle stages
// nothing. Any other run stages its record and, for every OCI member that
// resolves under current trust, its frozen copy; a member that does not is
// recorded with its failure, and collection continues (freezing is retried
// once more when the window closes). Only cancellation and staging I/O
// errors are returned.
func (r *AssessmentRunReconciler) freezeContent(ctx context.Context, run *v1alpha1.AssessmentRun, c collector.CaptureV2, desired *v1alpha1.BundleReference) error {
	_ = os.Remove(filepath.Join(r.staging(run), runContentFile))
	if err := os.RemoveAll(filepath.Join(r.staging(run), frozenContentDir)); err != nil {
		return err
	}
	local := vendoredName(r.Assess.Content)
	applied := appliedContent(c)
	rec := runContent{Version: runContentVersion, Desired: desired, Members: []runMember{}}
	for _, ref := range applied {
		rec.Members = append(rec.Members, runMember{Ref: ref, Applied: true, Vendored: local != "" && ref.Name == local})
	}
	if len(applied) == 0 && desired != nil {
		rec.Members = append(rec.Members, runMember{Ref: *desired, Vendored: local != "" && desired.Name == local})
	}
	vendoredOnly := !slices.ContainsFunc(rec.Members, func(m runMember) bool { return !m.Vendored })
	if vendoredOnly && (desired == nil || desired.Name == local) {
		return nil // the vendored run, exactly as before
	}
	freezer := freezerFor(r.Assess.Content)
	for i := range rec.Members {
		m := &rec.Members[i]
		if m.Vendored {
			m.Failure = r.vendoredFailure(m.Ref, collector.ReasonContentUnavailable)
			continue
		}
		f, err := r.freeze(ctx, freezer, run, m.Ref)
		if err != nil {
			return err
		}
		m.Failure = f
	}
	return assessment.Write(filepath.Join(r.staging(run), runContentFile), rec)
}

// vendoredFailure is nil when ref is the image's vendored content: the
// sha256 of the runtime's content/SHA256SUMS. Vendored content of another
// digest (applied by another image) is never stood in for.
func (r *AssessmentRunReconciler) vendoredFailure(ref v1alpha1.BundleReference, reason string) *collector.ContentFailure {
	sums, err := os.ReadFile(filepath.Join(r.Runtime.ContentRoot, "content", "SHA256SUMS"))
	if err != nil {
		return &collector.ContentFailure{Reason: reason, Message: truncateMsg(fmt.Sprintf("the vendored content %s@%s is not readable: %v", ref.Name, ref.Digest, err))}
	}
	h := sha256.Sum256(sums)
	if have := "sha256:" + hex.EncodeToString(h[:]); have != ref.Digest {
		return &collector.ContentFailure{Reason: reason,
			Message: fmt.Sprintf("the vendored content %s@%s is not this controller's (%s); other content is never substituted", ref.Name, ref.Digest, have)}
	}
	return nil
}

// freeze freezes ref into the run's staging directory. A content failure
// is returned as the record's failure (nil once frozen), not as an error.
func (r *AssessmentRunReconciler) freeze(ctx context.Context, freezer ContentFreezer, run *v1alpha1.AssessmentRun, ref v1alpha1.BundleReference) (*collector.ContentFailure, error) {
	dir := r.frozenDir(run, ref.Digest)
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return nil, err
	}
	_, vendored, err := freezer.Freeze(ctx, ref, dir)
	switch {
	case vendored:
		// Only a member recorded as OCI reaches here: the source serves
		// this name as vendored content, which is never a frozen copy.
		return &collector.ContentFailure{Reason: collector.ReasonContentUnavailable,
			Message: fmt.Sprintf("%s@%s is served as vendored content and cannot be frozen", ref.Name, ref.Digest)}, nil
	case err == nil:
		return nil, nil
	case ctx.Err() != nil:
		return nil, ctx.Err()
	}
	log.FromContext(ctx).Info("run content could not be frozen", "run", run.Name, "bundle", ref.Name+"@"+ref.Digest, "error", err.Error())
	return &collector.ContentFailure{Reason: collector.ReasonContentUnavailable,
		Message: truncateMsg(fmt.Sprintf("%s@%s could not be frozen for this run: %s", ref.Name, ref.Digest, contentMessage(err)))}, nil
}

// retryFreeze retries, when the window closes, freezing the OCI members
// that were unavailable at start. The members are the ones recorded at
// start, never a newer selection.
func (r *AssessmentRunReconciler) retryFreeze(ctx context.Context, run *v1alpha1.AssessmentRun) error {
	rc, err := r.readRunContent(run)
	if err != nil || rc == nil {
		return nil // an unreadable record is reported at export
	}
	changed := false
	freezer := freezerFor(r.Assess.Content)
	for i := range rc.Members {
		m := &rc.Members[i]
		if m.Vendored || m.Failure == nil || m.Failure.Reason != collector.ReasonContentUnavailable {
			continue
		}
		f, err := r.freeze(ctx, freezer, run, m.Ref)
		if err != nil {
			return err
		}
		m.Failure, changed = f, true
	}
	if !changed {
		return nil
	}
	return assessment.Write(filepath.Join(r.staging(run), runContentFile), rc)
}

// exportContent sets the content of an export request from the staged
// record: vendored runs keep the runtime's ContentRoot; every other run
// exports from its verified frozen copies (and the runtime's vendored
// content for a vendored member of the same digest), or records why it
// cannot. A frozen copy that is lost or no longer verifies is never
// re-resolved.
func (r *AssessmentRunReconciler) exportContent(run *v1alpha1.AssessmentRun, req *collector.ExportRequest) error {
	rc, err := r.readRunContent(run)
	switch {
	case err != nil:
		// An unreadable record cannot say which content the run used.
		req.Content = &collector.RunContent{Failure: &collector.ContentFailure{Reason: collector.ReasonContentLost,
			Message: truncateMsg("the run's content record is unreadable; content is never re-resolved: " + err.Error())}}
		return nil
	case rc == nil:
		return nil
	}
	out := &collector.RunContent{Desired: rc.Desired, DesiredVendored: rc.Desired != nil && rc.Desired.Name == vendoredName(r.Assess.Content)}
	for _, m := range rc.Members {
		cm := collector.ContentMember{Ref: m.Ref, Applied: m.Applied, Vendored: m.Vendored, Failure: m.Failure}
		switch {
		case cm.Failure != nil:
		case m.Vendored:
			if cm.Failure = r.vendoredFailure(m.Ref, collector.ReasonContentLost); cm.Failure == nil {
				cm.Root = r.Runtime.ContentRoot
			}
		default:
			dir := r.frozenDir(run, m.Ref.Digest)
			f, err := bundle.ReadFrozen(dir)
			switch {
			case err != nil:
				cm.Failure = &collector.ContentFailure{Reason: collector.ReasonContentLost,
					Message: truncateMsg(fmt.Sprintf("the frozen copy of %s@%s is lost or no longer verifies; it is never re-resolved: %v", m.Ref.Name, m.Ref.Digest, err))}
			case f.Identity.Name != m.Ref.Name || f.Identity.Digests.OCI != m.Ref.Digest:
				cm.Failure = &collector.ContentFailure{Reason: collector.ReasonContentLost,
					Message: fmt.Sprintf("the frozen copy is %s@%s, not the run's %s@%s", f.Identity.Name, f.Identity.Digests.OCI, m.Ref.Name, m.Ref.Digest)}
			default:
				cm.Root, cm.Frozen = dir, f
			}
		}
		out.Members = append(out.Members, cm)
	}
	req.Content, req.TrustedRoot = out, r.Runtime.ContentRoot
	return nil
}
