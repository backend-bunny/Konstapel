package preview

import (
	"context"
	"errors"
	"io"
	"slices"
	"time"
)

// This file is the preview pipeline behind `konstapel preview` (task 6.1):
// rendered inputs, the caller's kubeconfig, the read-only observation, the
// verified content and the comparison, always ending in a Report. It starts
// no manager, provider subprocess, delivery code, metrics server or leader
// election, and it sends no Kubernetes write: the observation's transport
// guard refuses anything but discovery, get and list.

// RunOptions configures one preview.
type RunOptions struct {
	Inputs      Inputs
	Stdin       io.Reader
	InputLimits Limits
	// Kubeconfig and Context select the caller's identity (RESTConfig);
	// there is no in-cluster fallback.
	Kubeconfig string
	Context    string
	// ControllerNamespace and SourcesConfigMap name the Konstapel
	// installation, as the controller's POD_NAMESPACE and
	// --bundle-sources-configmap.
	ControllerNamespace string
	SourcesConfigMap    string
	// SourcesExplicit is true when the caller stated SourcesConfigMap, even
	// as empty. Without it, an observed or proposed OCI pin makes the report
	// incomplete: the preview cannot know whether the controller has sources.
	SourcesExplicit bool
	ObserveLimits   ObserveLimits
	Content         ContentOptions
	// Now is the clock of the observation; time.Now when nil.
	Now func() time.Time
}

// Run performs one preview and returns its report; it never returns nil.
// Every failure after option parsing is a coded error of an incomplete
// report, so callers can always write the report they asked for.
func Run(ctx context.Context, o RunOptions) *Report {
	r := newReport()
	proposed, before, streams, err := LoadStreams(o.Inputs, o.Stdin, o.InputLimits)
	r.Inputs = inputsOf(streams, proposed, before)
	if err != nil {
		if !r.inputErrors(err) {
			r.fail(StageInput, ObserveCode(CodeReadFailed), err.Error())
		}
		return r.finish()
	}
	cfg, ctxName, err := RESTConfig(o.Kubeconfig, o.Context)
	if err != nil {
		r.fail(StageKubeconfig, ReportKubeconfigInvalid, err.Error())
		return r.finish()
	}
	snap, err := Observe(ctx, ObserveOptions{Config: cfg, Context: ctxName, Namespace: o.ControllerNamespace,
		SourcesConfigMap: o.SourcesConfigMap, Limits: o.ObserveLimits, Now: o.Now})
	if snap == nil {
		r.fail(StageObservation, ReportObservationFailed, err.Error())
		return r.finish()
	}
	r.Observation = observationOf(snap, o.SourcesConfigMap, o.Content.ControllerVersion)
	for _, d := range snap.Errors {
		r.Errors = append(r.Errors, fromDiagnostic(StageObservation, d))
	}
	if !snap.Complete {
		for _, d := range snap.Limitations {
			r.Limitations = append(r.Limitations, fromDiagnostic(StageObservation, d))
		}
		return r.finish()
	}
	if !o.SourcesExplicit && o.SourcesConfigMap == "" {
		r.requireSources(snap, proposed, o.Content.Vendored.Name)
	}
	bc, err := OpenContent(ctx, snap, o.Content)
	if err != nil {
		r.fail(StageContent, ReportContentSetupFailed, err.Error())
		return r.finish()
	}
	defer func() { _ = bc.Close() }()
	c, err := Compare(ctx, CompareInput{Snapshot: snap, Proposed: proposed, Before: before, Content: bc})
	if err != nil {
		switch {
		case r.inputErrors(err):
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			r.fail(StageComparison, ObserveTimeout, "the preview timed out while resolving content: "+err.Error())
		case errors.Is(ctx.Err(), context.Canceled):
			r.fail(StageComparison, ObserveCanceled, "the preview was canceled while resolving content")
		default:
			r.fail(StageComparison, ReportComparisonFailed, err.Error())
		}
		for _, d := range snap.Limitations {
			r.Limitations = append(r.Limitations, fromDiagnostic(StageObservation, d))
		}
		return r.finish()
	}
	r.fillComparison(c, snap.Limitations)
	r.fillExceptions(snap, r.Changes)
	r.fillEvidence(snap, c)
	return r.finish()
}

// requireSources makes the report incomplete when a live or proposed profile
// pins a bundle other than the vendored one and the caller did not say which
// bundle-source ConfigMap the controller uses. Defaulting silently to none
// would report the controller's OCI pins as its own configuration problem.
func (r *Report) requireSources(snap *Snapshot, proposed *Set, vendored string) {
	var names []string
	for _, p := range snap.Live.Profiles {
		if p.Spec.Bundle.Name != vendored {
			names = append(names, p.Spec.Bundle.Name)
		}
	}
	if proposed != nil {
		for _, o := range proposed.Objects {
			if o.Profile != nil && o.Profile.Spec.Bundle.Name != vendored {
				names = append(names, o.Profile.Spec.Bundle.Name)
			}
		}
	}
	slices.Sort(names)
	for _, n := range slices.Compact(names) {
		r.Errors = append(r.Errors, ReportDiagnostic{Code: ReportSourcesRequired, Stage: StageContent, Name: n,
			Message: "a profile pins this OCI bundle, but no bundle-source ConfigMap was named: pass --bundle-sources-configmap with the controller's value, or --bundle-sources-configmap= when the controller runs without bundle sources"})
	}
}
