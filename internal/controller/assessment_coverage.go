package controller

// Control coverage of an assessment run's package (add-control-coverage-
// reporting 3.2).
//
// The run's package carries coverage.json and coverage.txt, built by
// internal/coverage from exactly what the package carries: the frozen
// content of the bundle the binding's profile selected when the run
// started (read back from the package directory, verified again), the
// profile's policy selection frozen at start (coverage-selection.json in
// staging), and the frozen, evaluated capture. Nothing is read from the
// live cache, the registry, the current profile, or the vendored tree for
// an OCI run. Coverage that cannot be built is a coverage diagnostic (an
// unresolved report with a coded limitation), never a guessed inventory or
// an OSCAL finding, and it never blocks or changes the technical evidence:
// collector.Export packages the run without coverage when the producer
// fails.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/coverage"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

const (
	// runSelectionFile records, at run start, the binding's profile and its
	// policy selection. Its absence (a run started by an earlier
	// controller) makes coverage a SelectionUnavailable diagnostic: the
	// current profile is never read in its place.
	runSelectionFile    = "coverage-selection.json"
	runSelectionVersion = 1
)

// runSelection is the staged record of a run's profile selection.
type runSelection struct {
	Version int `json:"version"`
	// Profile is nil when the binding selected no profile.
	Profile   *profileRef         `json:"profile,omitempty"`
	Selection *coverage.Selection `json:"selection,omitempty"`
	// Bundle is the bundle the profile selected, for observing selection
	// changes (observeSelection). A record with a profile and no bundle
	// was staged by an earlier controller: its frozen bundle is unknown.
	Bundle *v1alpha1.BundleReference `json:"bundle,omitempty"`
}

type profileRef struct {
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
}

// freezeSelection stages the profile selection a starting run assesses.
func (r *AssessmentRunReconciler) freezeSelection(run *v1alpha1.AssessmentRun, profile *v1alpha1.ComplianceProfile) error {
	rec := runSelection{Version: runSelectionVersion}
	if profile != nil {
		sel := coverage.SelectionOf(profile.Spec)
		rec.Profile = &profileRef{Name: profile.Name, UID: string(profile.UID), Generation: profile.Generation}
		rec.Selection = &sel
		ref := profile.Spec.Bundle
		rec.Bundle = &ref
	}
	return assessment.Write(filepath.Join(r.staging(run), runSelectionFile), rec)
}

func (r *AssessmentRunReconciler) readSelection(run *v1alpha1.AssessmentRun) (*runSelection, error) {
	var rec runSelection
	if err := assessment.Read(filepath.Join(r.staging(run), runSelectionFile), &rec); err != nil {
		return nil, err
	}
	if rec.Version != runSelectionVersion {
		return nil, fmt.Errorf("selection record version %d is not %d", rec.Version, runSelectionVersion)
	}
	if (rec.Profile == nil) != (rec.Selection == nil) {
		return nil, errors.New("selection record is inconsistent")
	}
	return &rec, nil
}

// exportCoverage sets the export's coverage producer. The returned
// function, called after the export, is the status summary of the report
// the package actually carries: nil when the export left coverage out or
// packaged other bytes than the producer rendered.
func (r *AssessmentRunReconciler) exportCoverage(ctx context.Context, run *v1alpha1.AssessmentRun, b *v1alpha1.ComplianceBinding, req *collector.ExportRequest,
	supporting *coverage.SupportingEvidenceContext) func(publication.Descriptor) *publication.CoverageSummary {
	scope, c, ev := req.Scope, req.Capture, req.Evaluation
	var produced *publication.CoverageSummary
	req.Coverage = func(p collector.CoveragePackage) (collector.CoverageFiles, error) {
		produced = nil
		rep := r.coverageReport(run, b, scope, c, ev, p, supporting)
		f, err := coverage.Render(rep)
		if err != nil {
			return collector.CoverageFiles{}, err
		}
		if err := coverage.VerifyFiles(f); err != nil {
			return collector.CoverageFiles{}, err
		}
		h := sha256.Sum256(f.JSON)
		sum := coverage.Summarize(rep, hex.EncodeToString(h[:]))
		sum.InputsSHA256 = r.coverageInputs(run, scope)
		sum.ValidUntil = ev.NextExpiry
		produced = &sum
		return collector.CoverageFiles{JSON: f.JSON, Text: f.Text}, nil
	}
	req.CoverageOmitted = func(err error) {
		produced = nil
		log.FromContext(ctx).Info("control coverage left out of the package; technical evidence is unaffected", "run", run.Name, "error", err.Error())
	}
	return func(d publication.Descriptor) *publication.CoverageSummary {
		if produced == nil {
			return nil
		}
		for _, f := range d.Files {
			if f.Role == publication.RoleCoverage && f.Path == publication.CoverageFile && f.SHA256 == produced.SHA256 {
				return produced
			}
		}
		return nil
	}
}

// coverageInputs is the inputs digest of a run's coverage: its binding,
// the package scope's namespaces and the selection frozen at start. It is
// "" when the selection was not recorded, so the report never compares
// equal to a binding's current inputs.
func (r *AssessmentRunReconciler) coverageInputs(run *v1alpha1.AssessmentRun, scope publication.Scope) string {
	rec, err := r.readSelection(run)
	if err != nil {
		return ""
	}
	return coverage.InputsDigest(scope.BindingUID, scope.NamespaceUIDs, rec.Selection)
}

// coverageReport builds the run's coverage from the package p and the
// run's frozen supporting context (nil: no integration).
func (r *AssessmentRunReconciler) coverageReport(run *v1alpha1.AssessmentRun, b *v1alpha1.ComplianceBinding, scope publication.Scope,
	c collector.CaptureV2, ev collector.Evaluation, p collector.CoveragePackage, supporting *coverage.SupportingEvidenceContext) *coverage.Report {
	in := coverage.Input{Scope: coverageScope(b, scope, c), Evidence: &coverage.Evidence{Capture: c, Evaluation: ev},
		Packaging: &coverage.Packaging{}, Supporting: supporting}
	for _, s := range []struct{ path, kind string }{{"capture.json", coverage.SourceCapture}, {"evaluation.json", coverage.SourceEvaluation}} {
		raw, err := os.ReadFile(filepath.Join(p.Dir, s.path))
		if err != nil {
			continue // the package owner refuses a report without them
		}
		h := sha256.Sum256(raw)
		in.Packaging.Evidence = append(in.Packaging.Evidence, coverage.Source{Path: s.path, Kind: s.kind, SHA256: hex.EncodeToString(h[:])})
	}

	rec, err := r.readSelection(run)
	if err != nil {
		return coverage.Unavailable(in, coverage.CodeSelectionUnavailable, "",
			"the binding profile's selection was not recorded when this run started (%s); the current profile is never used in its place", errText(err))
	}
	if rec.Profile == nil {
		return coverage.Unavailable(in, coverage.CodeBaselineNotSelected, "", "the binding selected no ComplianceProfile when this run started, so it has no baseline")
	}
	in.Selection = *rec.Selection
	ref := in.Selection.Bundle
	in.Content = coverage.Content{Bundle: ref}
	id := ref.Name + "@" + ref.Digest
	if p.Kind != publication.KindAssessment {
		reason := ""
		if p.Diagnostic != nil {
			reason = p.Diagnostic.Reason
		}
		return coverage.Unavailable(in, coverage.CodeContentUnavailable, id,
			"the package is a %s (%s) and carries no content, so the baseline of %s is not read", p.Kind, reason, id)
	}
	local := vendoredName(r.Assess.Content)
	i := slices.IndexFunc(p.Content, func(pc collector.PackagedContent) bool {
		return pc.Ref.Digest == ref.Digest && (pc.Ref.Name == ref.Name || (pc.Ref.Name == "" && pc.Vendored && ref.Name == local))
	})
	if i < 0 {
		return coverage.Unavailable(in, coverage.CodeContentUnavailable, id,
			"the selected bundle %s is not packaged with this run (no assessed contribution was applied from it); coverage is never built from other or live content", id)
	}
	pc := p.Content[i]
	in.Packaging.ContentPath = pc.Path
	schemas, err := trustedOSCALSchemas(r.Runtime.ContentRoot)
	if err != nil {
		return coverage.Unavailable(in, coverage.CodeContentUnavailable, id, "the controller's OSCAL schemas are not readable: %s", errText(err))
	}
	in.Options = coverage.Options{Schemas: schemas}
	root := filepath.Join(p.Dir, filepath.FromSlash(pc.Path))
	if pc.Vendored {
		in.Content, err = coverage.FromVendored(os.DirFS(root), ref, vendoredOSCAL(), vendoredPolicies())
		// The vendored SHA256SUMS names the profile's closure; the
		// controller names the profile it ships.
		in.Options.Profile = assessment.NIST + "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"
	} else {
		var f *bundle.Frozen
		if f, err = bundle.ReadFrozen(root); err == nil {
			if f.Identity.Name != ref.Name || f.Identity.Digests.OCI != ref.Digest {
				err = fmt.Errorf("the packaged bundle is %s@%s", f.Identity.Name, f.Identity.Digests.OCI)
			} else {
				in.Content, err = coverage.FromFrozen(f)
			}
		}
	}
	if err != nil {
		in.Content = coverage.Content{Bundle: ref}
		return coverage.Unavailable(in, coverage.CodeContentUnavailable, id, "the packaged content of %s does not verify: %s", id, errText(err))
	}
	return coverage.Build(in)
}

// coverageScope is the report scope of a package scope.
func coverageScope(b *v1alpha1.ComplianceBinding, s publication.Scope, c collector.CaptureV2) coverage.Scope {
	names := map[string]string{}
	for _, x := range c.Subjects {
		names[string(x.NamespaceUID)] = x.Namespace
	}
	for _, w := range c.Workloads {
		names[w.NamespaceUID] = w.Namespace
	}
	if q := s.Request; q != nil {
		names[q.NamespaceUID] = q.Namespace
	}
	out := coverage.Scope{Kind: string(s.Kind), Cluster: s.ClusterID, Binding: &coverage.ObjectRef{Name: b.Name, UID: s.BindingUID}}
	for _, uid := range s.NamespaceUIDs {
		out.Namespaces = append(out.Namespaces, coverage.NamespaceRef{Name: names[uid], UID: uid})
	}
	return out
}

// trustedOSCALSchemas are the controller's own OSCAL schemas.
func trustedOSCALSchemas(root string) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, v := range coverage.SupportedOSCAL {
		b, err := os.ReadFile(filepath.Join(root, "content", "schemas", "oscal-"+v+".json"))
		if err != nil {
			return nil, err
		}
		out[v] = b
	}
	return out, nil
}

// vendoredOSCAL are the vendored content's declared OSCAL entry points:
// the shipped component definitions and the NIST catalog and profile.
func vendoredOSCAL() []bundle.OSCALDocument {
	var out []bundle.OSCALDocument
	for _, d := range assessment.ComponentDefinitions {
		out = append(out, bundle.OSCALDocument{Path: d, Version: "1.1.3"})
	}
	return append(out,
		bundle.OSCALDocument{Path: assessment.NIST + "NIST_SP-800-53_rev5_catalog.json", Version: "1.2.3"},
		bundle.OSCALDocument{Path: assessment.NIST + "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json", Version: "1.2.3"})
}

// vendoredPolicies are the vendored logical policies, one check each.
func vendoredPolicies() []bundle.Policy {
	var out []bundle.Policy
	for _, name := range slices.Sorted(maps.Keys(assessment.ShippedPolicies)) {
		out = append(out, bundle.Policy{Name: name, Path: assessment.ShippedPolicies[name], Checks: []bundle.Check{{RuleID: name, CheckID: name}}})
	}
	return out
}

func errText(err error) string { return truncateMsg(err.Error()) }

// currentCoverageInputs is the inputs digest of b's current scope: its
// namespaces as the current capture resolves them and its profile's
// selection now (nil without a profile), as a run starting now would
// record them.
func currentCoverageInputs(b *v1alpha1.ComplianceBinding, c collector.CaptureV2, profile *v1alpha1.ComplianceProfile) string {
	set := map[string]bool{}
	for _, s := range c.Subjects {
		set[string(s.NamespaceUID)] = true
	}
	var sel *coverage.Selection
	if profile != nil {
		s := coverage.SelectionOf(profile.Spec)
		sel = &s
	}
	return coverage.InputsDigest(string(b.UID), sortedKeys(set), sel)
}

// currentCoverage judges the binding's newest committed full-binding
// run's coverage report at time now (add-control-coverage-reporting 3.3,
// 3.4). The report and the run's summary of it are never changed: only
// this view of them follows the clock and the binding's current inputs.
// Namespace runs never stand in for the binding.
func (r *AssessmentReconciler) currentCoverage(ctx context.Context, b *v1alpha1.ComplianceBinding, now time.Time, inputs string) (*v1alpha1.CurrentCoverage, error) {
	var runs v1alpha1.AssessmentRunList
	if err := r.Client.List(ctx, &runs, client.MatchingLabels{LabelRunBinding: string(b.UID)}); err != nil {
		return nil, err
	}
	var newest *v1alpha1.AssessmentRun
	for i := range runs.Items {
		run := &runs.Items[i]
		st := run.Status
		if run.Spec.BindingRef.Name != b.Name || run.Spec.Scope != v1alpha1.RunScopeBinding || st.Phase != v1alpha1.RunCompleted ||
			st.Publication == nil || st.Publication.Phase != v1alpha1.PublicationPhase(publication.PhaseCommitted) || st.Window == nil || st.Window.Closed == nil {
			continue
		}
		if newest == nil || st.Window.Closed.After(newest.Status.Window.Closed.Time) ||
			st.Window.Closed.Equal(newest.Status.Window.Closed) && run.Name > newest.Name {
			newest = run
		}
	}
	if newest == nil {
		return &v1alpha1.CurrentCoverage{State: v1alpha1.CoverageNoReport}, nil
	}
	out := &v1alpha1.CurrentCoverage{State: v1alpha1.CoverageNoReport, Run: &v1alpha1.RunReference{Name: newest.Name, UID: string(newest.UID)}}
	if newest.Status.Summary == nil || newest.Status.Summary.Coverage == nil {
		return out, nil
	}
	cov := newest.Status.Summary.Coverage.DeepCopy()
	out.Summary = cov
	switch {
	case cov.InputsSHA256 == "" || inputs == "" || cov.InputsSHA256 != inputs:
		out.State = v1alpha1.CoverageScopeChanged
	case newest.Status.Publication.Availability != v1alpha1.Availability(publication.AvailabilityAvailable),
		cov.ValidUntil != nil && !now.Before(cov.ValidUntil.Time):
		out.State = v1alpha1.CoverageExpired
	default:
		out.State = v1alpha1.CoverageCurrent
	}
	return out, nil
}

// coverageExpiry is when a current coverage report expires, or zero when
// it is not current or never expires by age.
func coverageExpiry(c *v1alpha1.CurrentCoverage) time.Time {
	if c == nil || c.State != v1alpha1.CoverageCurrent || c.Summary == nil || c.Summary.ValidUntil == nil {
		return time.Time{}
	}
	return c.Summary.ValidUntil.Time
}
