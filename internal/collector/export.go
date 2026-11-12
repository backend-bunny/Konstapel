package collector

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
	"strings"
	"time"

	oscal "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/oscal-compass/compliance-to-policy-go/v2/framework/actions"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// ExportVersion identifies this exporter in package descriptors.
const ExportVersion = "collector-export/v1"

// ExportRequest describes one frozen, evaluated run to package.
type ExportRequest struct {
	// Root contains the image's verified vendored content/ tree (mapping,
	// catalog, profile, schemas). A run without Content exports from it.
	Root string
	// Content is the run's content set when the run is not purely vendored:
	// one member per applied bundle (each OCI member a frozen copy). OSCAL
	// is then derived per member only from that member's content (its
	// component definitions, policies, catalog and profile) for the
	// observations of the contributions applied from it, and each member is
	// packaged under its own directory. A failed member, or a run-level
	// failure, makes the package a Diagnostic with that reason; no OSCAL is
	// produced from any other content.
	Content *RunContent
	// TrustedRoot is the image's own content tree. With Content, its OSCAL
	// schemas are the ones every document is validated against; a bundle
	// that ships different schema bytes is incompatible.
	TrustedRoot string
	// Out must not exist or be empty; the package is written there.
	Out                  string
	Run                  publication.RunRef
	Scope                publication.Scope
	BindingConfiguration string
	Capture              CaptureV2
	Evaluation           Evaluation
}

// Export writes a package for an evaluated capture. When valid OSCAL can be
// produced it is an Assessment package, including for incomplete evidence.
// When it cannot, every OSCAL document is removed and a typed Diagnostic
// package records why; invalid OSCAL is never packaged as an assessment.
// Evidence completeness and outcomes are recorded unchanged either way.
func Export(ctx context.Context, req ExportRequest) (publication.Descriptor, error) {
	if entries, err := os.ReadDir(req.Out); err == nil && len(entries) > 0 {
		return publication.Descriptor{}, fmt.Errorf("output %s is not empty", req.Out)
	}
	if err := os.MkdirAll(req.Out, 0o755); err != nil {
		return publication.Descriptor{}, err
	}
	if err := req.Capture.Validate(); err != nil {
		return publication.Descriptor{}, fmt.Errorf("capture: %w", err)
	}
	switch {
	case req.Scope.Kind == publication.ScopeNamespace:
		// Projection happens before export; verify it independently.
		if err := ValidateProjection(req.Capture); err != nil {
			return publication.Descriptor{}, fmt.Errorf("namespace package: %w", err)
		}
		if req.Scope.Request == nil || req.Scope.Request.NamespaceUID != req.Capture.Projection.NamespaceUID {
			return publication.Descriptor{}, errors.New("namespace package scope does not match its projection")
		}
	case req.Capture.Projection != nil:
		return publication.Descriptor{}, errors.New("a namespace projection cannot be exported as a binding package")
	}
	for name, v := range map[string]any{"capture.json": req.Capture, "evaluation.json": req.Evaluation} {
		if err := assessment.Write(filepath.Join(req.Out, name), v); err != nil {
			return publication.Descriptor{}, err
		}
	}

	kind := publication.KindAssessment
	var diag *publication.Diagnostic
	var err error
	if rc := req.Content; rc != nil {
		if f := rc.failure(); f != nil {
			err = f
		}
	}
	if err == nil {
		err = writeOSCAL(ctx, req)
	}
	if err != nil {
		for _, p := range []string{"assessment-plan.json", "assessment-results.json", "system-security-plan.json", "content", bundle.FrozenDir, bundlesDir} {
			if rmErr := os.RemoveAll(filepath.Join(req.Out, p)); rmErr != nil {
				return publication.Descriptor{}, rmErr
			}
		}
		kind = publication.KindDiagnostic
		reason := "ExportFailed"
		if cf := (*ContentFailure)(nil); errors.As(err, &cf) {
			reason = cf.Reason
		}
		diag = &publication.Diagnostic{Reason: reason, MissingExports: []publication.FileRole{publication.RoleAssessmentResults}, Message: truncate(err.Error(), 1024)}
		if err := assessment.Write(filepath.Join(req.Out, "diagnostic.json"), diag); err != nil {
			return publication.Descriptor{}, err
		}
	}
	export := publication.ExportAssessment
	if kind == publication.KindDiagnostic {
		export = publication.ExportDiagnostic
	}
	summary := map[string]any{"scope": req.Scope.Kind, "evidence": req.Evaluation.Evidence, "outcomes": req.Evaluation.Outcomes, "export": export}
	if err := assessment.Write(filepath.Join(req.Out, "summary.json"), summary); err != nil {
		return publication.Descriptor{}, err
	}

	files, err := publication.Inventory(req.Out, exportRole)
	if err != nil {
		return publication.Descriptor{}, err
	}
	var enforcement []string
	for _, s := range req.Capture.Subjects {
		if !slices.Contains(enforcement, s.Revision) {
			enforcement = append(enforcement, s.Revision)
		}
	}
	slices.Sort(enforcement)
	checks := []string{"capture-inventory"}
	if kind == publication.KindAssessment {
		checks = append(checks, "oscal-schema-1.1.3", "reference-closure")
		if req.Content != nil {
			checks = append(checks, "frozen-bundle-content")
		}
	}
	d := publication.Descriptor{
		APIVersion: publication.APIVersion, Kind: publication.DescriptorKind, Run: req.Run, PackageKind: kind,
		Scope: req.Scope, ScopeSHA256: req.Scope.Digest(),
		Revisions: publication.Revisions{BindingConfiguration: req.BindingConfiguration, Enforcement: enforcement, MappingSHA256: req.Capture.MappingSHA256,
			Content: contentRevision(req, kind)},
		Window:   publication.Window{Started: req.Capture.Window.Started, Closed: req.Capture.Window.Closed},
		Evidence: req.Evaluation.Evidence, Outcomes: req.Evaluation.Outcomes, Diagnostic: diag,
		Producer: publication.Producer{Name: "konstapel-controller", Version: ExportVersion, ValidatedAt: time.Now().UTC().Truncate(time.Second), Checks: checks},
		Files:    files,
	}
	if err := d.Validate(); err != nil {
		return d, err
	}
	if err := assessment.Write(filepath.Join(req.Out, publication.DescriptorFile), d); err != nil {
		return d, err
	}
	if err := publication.VerifyDir(req.Out, d); err != nil {
		return d, err
	}
	if kind == publication.KindAssessment {
		return d, VerifyContent(req.Out, d.Revisions.Content)
	}
	return d, nil
}

// bundlesDir holds one directory per member of a run's content set.
const bundlesDir = "bundles"

// oscalPart is the OSCAL of one content root: the vendored run's content,
// or one member of a run's content set with the observations of the
// contributions applied from it.
type oscalPart struct {
	// prefix is the package directory of the content ("" for a vendored
	// run, "bundles/<hex>/" for a member).
	prefix string
	root   string
	set    assessment.ContentSet
	member *ContentMember
	// capture holds the part's subjects and expected observations.
	capture CaptureV2
	cov     coverage
	plan    *oscal.AssessmentPlan
	ar      *oscal.AssessmentResults
	mapping string
}

// exportParts splits the request into its OSCAL parts and returns the root
// whose schemas validate every output.
func exportParts(req ExportRequest) ([]*oscalPart, string, error) {
	rc := req.Content
	if rc == nil {
		return []*oscalPart{{root: req.Root, set: assessment.Shipped, capture: req.Capture, mapping: "content/component-definition.json"}}, req.Root, nil
	}
	if req.TrustedRoot == "" {
		return nil, "", contentFailure(ReasonContentIncompatible, "no trusted content root is configured to validate frozen bundle content")
	}
	applied := map[v1alpha1.BundleReference]bool{}
	for _, m := range rc.Members {
		if m.Applied {
			applied[m.Ref] = true
		}
	}
	if err := captureUses(req.Capture, applied); err != nil {
		return nil, "", err
	}
	// Each observation belongs to the bundle its contribution was applied
	// from; overlapping revisions of one policy stay with their own bundle.
	type contribution struct{ binding, revision, policy string }
	bundleOf := map[contribution]v1alpha1.BundleReference{}
	for _, s := range req.Capture.Subjects {
		bundleOf[contribution{string(s.BindingUID), s.Revision, s.EnginePolicy}] = v1alpha1.BundleReference{Name: s.BundleName, Digest: s.BundleDigest}
	}
	var parts []*oscalPart
	for i := range rc.Members {
		m := &rc.Members[i]
		if !m.Applied && len(applied) > 0 {
			continue
		}
		set, err := memberContent(*m, req.TrustedRoot)
		if err != nil {
			return nil, "", err
		}
		sub := req.Capture
		sub.Subjects = slices.DeleteFunc(slices.Clone(sub.Subjects), func(s targeting.EvidenceSubject) bool {
			return s.BundleName != m.Ref.Name || s.BundleDigest != m.Ref.Digest
		})
		sub.Expected = slices.DeleteFunc(slices.Clone(sub.Expected), func(e Expected) bool {
			return bundleOf[contribution{e.Contribution.BindingUID, e.Contribution.Revision, e.Contribution.EnginePolicy}] != m.Ref
		})
		prefix := m.Path() + "/"
		parts = append(parts, &oscalPart{prefix: prefix, root: m.Root, set: set, member: m, capture: sub, mapping: prefix + set.Definitions[0]})
	}
	if len(parts) == 0 {
		return nil, "", contentFailure(ReasonContentMismatch, "the run's content set has no content to export")
	}
	return parts, req.TrustedRoot, nil
}

// writeOSCAL writes the plan, results, and SSP plus the content they
// reference, then validates schemas and reference closure. A run with a
// content set gets one OSCAL result per member, each derived only from
// that member's content and naming its bundle; the plan joins the members'
// plans, so overlapping revisions are never collapsed into one bundle.
func writeOSCAL(ctx context.Context, req ExportRequest) error {
	parts, schemaRoot, err := exportParts(req)
	if err != nil {
		return err
	}
	ev := req.Evaluation.Evidence
	for _, p := range parts {
		if err := p.export(ctx, req); err != nil {
			return err
		}
	}
	if req.Content != nil {
		// The controller's schemas, at the package path verifiers read.
		for _, s := range trustedSchemas {
			if err := copyFile(filepath.Join(schemaRoot, filepath.FromSlash(s)), filepath.Join(req.Out, filepath.FromSlash(s))); err != nil {
				return err
			}
		}
	}
	plans, ars := make([]*oscal.AssessmentPlan, len(parts)), make([]*oscal.AssessmentResults, len(parts))
	for i, p := range parts {
		plans[i], ars[i] = p.plan, p.ar
	}
	plan, ar := mergePlans(plans), mergeResults(ars)
	plan.Metadata.Title = "Konstapel continuous assessment plan"
	plan.Metadata.OscalVersion = "1.1.3"
	if err := assessment.Write(filepath.Join(req.Out, "assessment-plan.json"), assessment.Object{"assessment-plan": plan}); err != nil {
		return err
	}

	ar.Metadata.Title = "Konstapel continuous assessment results (partial technical evidence)"
	ar.Metadata.OscalVersion = "1.1.3"
	props := []oscal.Property{
		{Name: "evidence-completeness", Ns: ns, Value: string(ev.Completeness)},
		{Name: "expected-observations", Ns: ns, Value: fmt.Sprint(ev.Expected)},
		{Name: "attributable-observations", Ns: ns, Value: fmt.Sprint(ev.Attributable)},
		{Name: "stale-scopes", Ns: ns, Value: fmt.Sprint(ev.StaleScopes)},
		{Name: "cluster-id", Ns: ns, Value: req.Capture.Cluster},
		{Name: "run-uid", Ns: ns, Value: req.Run.RunUID},
	}
	if len(parts) == 1 {
		// One content root: the document is that content's, as before.
		props = append(props, oscal.Property{Name: "mapping-sha256", Ns: ns, Value: assessment.FileHash(filepath.Join(req.Out, filepath.FromSlash(parts[0].mapping)))})
		props = append(props, parts[0].bundleProps()...)
	}
	ar.Metadata.Props = &props
	ar.Metadata.Links = &[]oscal.Link{
		{Href: "capture.json", Rel: "related", Text: "Frozen scope, expected inventory, and raw reports"},
		{Href: "evaluation.json", Rel: "related", Text: "Per-observation evidence states and reasons"},
	}
	for _, p := range parts {
		if p.member != nil && p.member.Frozen != nil {
			*ar.Metadata.Links = append(*ar.Metadata.Links, oscal.Link{Href: p.prefix + bundle.FrozenIdentityFile, Rel: "related", Text: "Applied bundle identity and verification context, frozen with its content"})
		}
		for _, def := range p.cov.definitions {
			// Each definition that maps an assessed check is referenced, so the
			// package resolves every mapping it relies on.
			*ar.Metadata.Links = append(*ar.Metadata.Links, oscal.Link{Href: p.prefix + def, Rel: "related", Text: "Authored partial mapping"})
		}
	}
	if err := assessment.Write(filepath.Join(req.Out, "assessment-results.json"), assessment.Object{"assessment-results": ar}); err != nil {
		return err
	}
	if err := assessment.Write(filepath.Join(req.Out, "system-security-plan.json"), contextSSP(req.Capture.Cluster, req.Capture.Window.Closed, mergeCoverage(parts), parts[0].prefix)); err != nil {
		return err
	}
	schema := filepath.Join(schemaRoot, "content/schemas/oscal-1.1.3.json")
	for _, name := range []string{"assessment-plan", "assessment-results", "system-security-plan"} {
		if err := assessment.Schema(filepath.Join(req.Out, name+".json"), schema); err != nil {
			return fmt.Errorf("%s schema: %w", name, err)
		}
	}
	if err := assessment.ValidateReferences(req.Out); err != nil {
		return err
	}
	// Every engine policy must re-render from the packaged, digest-pinned
	// source; otherwise the evidence is not attributable to that content.
	if err := VerifyPackage(req.Out); err != nil {
		return fmt.Errorf("engine policy verification: %w", err)
	}
	return nil
}

// export derives the part's coverage, plan and results and packages its
// content (and frozen proofs) under its prefix.
func (p *oscalPart) export(ctx context.Context, req ExportRequest) error {
	var frozen *bundle.Frozen
	if p.member != nil {
		frozen = p.member.Frozen
	}
	cov, err := coverageFor(p.root, p.set, p.capture, frozen)
	if err != nil {
		return fmt.Errorf("mapping: %w", err)
	}
	p.cov = cov
	input, plan, err := assessment.InputFromSet(p.root, p.set, cov.rules)
	if err != nil {
		return fmt.Errorf("mapping: %w", err)
	}
	if err := os.CopyFS(filepath.Join(req.Out, filepath.FromSlash(p.prefix), "content"), os.DirFS(filepath.Join(p.root, "content"))); err != nil {
		return err
	}
	if frozen != nil {
		// The frozen proofs travel with the content they prove.
		if err := os.CopyFS(filepath.Join(req.Out, filepath.FromSlash(p.prefix), bundle.FrozenDir), os.DirFS(filepath.Join(p.root, bundle.FrozenDir))); err != nil {
			return err
		}
	}
	if plan.BackMatter != nil && plan.BackMatter.Resources != nil {
		for i := range *plan.BackMatter.Resources {
			if r := &(*plan.BackMatter.Resources)[i]; r.Rlinks != nil {
				for j := range *r.Rlinks {
					(*r.Rlinks)[j].Href = p.prefix + assessment.NIST + "NIST_SP-800-53_rev5_catalog.json"
				}
			}
		}
	}
	p.plan = plan

	results, attributableFail := pvpResults(p.capture, req.Evaluation)
	ar, err := actions.Report(ctx, input, "assessment-plan.json", *plan, results)
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}
	ev := req.Evaluation.Evidence
	for i := range ar.Results {
		r := &ar.Results[i]
		r.Title = "Konstapel continuous assessment"
		r.Description = fmt.Sprintf("Evidence %s: %d of %d expected observations attributable, %d stale scopes. %s",
			ev.Completeness, ev.Attributable, ev.Expected, ev.StaleScopes, cov.summary)
		if p.member != nil {
			id := p.member.Ref.Name + "@" + p.member.Ref.Digest
			r.Title = "Konstapel continuous assessment of " + id
			r.Description = fmt.Sprintf("Contributions applied from %s: %d expected observations. %s", id, len(p.capture.Expected), r.Description)
			props := append([]oscal.Property{{Name: "mapping-sha256", Ns: ns, Value: assessment.FileHash(filepath.Join(req.Out, filepath.FromSlash(p.mapping)))}}, p.bundleProps()...)
			r.Props = &props
		}
		// Only an attributable failure is an observed violation. Missing,
		// rejected, or unresolved evidence and zero targets make no claim.
		if !attributableFail {
			r.Findings = nil
		}
		retargetFindings(r.Findings, cov)
		if r.LocalDefinitions != nil && r.LocalDefinitions.InventoryItems != nil {
			for j := range *r.LocalDefinitions.InventoryItems {
				if item := &(*r.LocalDefinitions.InventoryItems)[j]; item.Props != nil && len(*item.Props) == 0 {
					item.Props = nil
				}
			}
		}
		if r.Observations != nil {
			for j := range *r.Observations {
				o := &(*r.Observations)[j]
				o.Collected = req.Capture.Window.Closed
				if o.Subjects == nil {
					continue
				}
				for k := range *o.Subjects {
					s := &(*o.Subjects)[k]
					if s.Props == nil {
						continue
					}
					attributable := slices.ContainsFunc(*s.Props, func(p oscal.Property) bool {
						return p.Name == "evidence-state" && p.Value == string(Attributable)
					})
					kept := []oscal.Property{}
					for _, p := range *s.Props {
						// Never present an evaluation time for unattributable evidence.
						p.Value = strings.TrimSpace(p.Value)
						if p.Value == "" || (!attributable && p.Name == "evaluated-on") {
							continue
						}
						kept = append(kept, p)
					}
					s.Props = &kept
				}
			}
		}
	}
	p.ar = ar
	return nil
}

// bundleProps name the part's bundle: its name and manifest digest, and
// for frozen content its version and content digest.
func (p *oscalPart) bundleProps() []oscal.Property {
	m := p.member
	if m == nil {
		return nil
	}
	out := []oscal.Property{{Name: "bundle-name", Ns: ns, Value: m.Ref.Name}}
	if f := m.Frozen; f != nil {
		out = append(out, oscal.Property{Name: "bundle-version", Ns: ns, Value: f.Identity.Version})
	}
	out = append(out, oscal.Property{Name: "bundle-digest", Ns: ns, Value: m.Ref.Digest})
	if f := m.Frozen; f != nil {
		out = append(out, oscal.Property{Name: "bundle-content-digest", Ns: ns, Value: f.Identity.Digests.Content})
	}
	return out
}

// mergePlans joins the members' plans into one: each member's activities,
// tasks, subjects and reviewed controls are kept as generated (their UUIDs
// are fresh per plan); a component defined by several members (the same
// component definition UUID) is listed once.
func mergePlans(plans []*oscal.AssessmentPlan) *oscal.AssessmentPlan {
	out := *plans[0]
	for _, p := range plans[1:] {
		out.ReviewedControls.ControlSelections = append(slices.Clone(out.ReviewedControls.ControlSelections), p.ReviewedControls.ControlSelections...)
		join(&out.ReviewedControls.ControlObjectiveSelections, p.ReviewedControls.ControlObjectiveSelections)
		join(&out.ReviewedControls.Links, p.ReviewedControls.Links)
		join(&out.AssessmentSubjects, p.AssessmentSubjects)
		join(&out.Tasks, p.Tasks)
		if p.LocalDefinitions != nil {
			if out.LocalDefinitions == nil {
				out.LocalDefinitions = &oscal.LocalDefinitions{}
			} else {
				ld := *out.LocalDefinitions
				out.LocalDefinitions = &ld
			}
			join(&out.LocalDefinitions.Activities, p.LocalDefinitions.Activities)
			join(&out.LocalDefinitions.InventoryItems, p.LocalDefinitions.InventoryItems)
			join(&out.LocalDefinitions.Users, p.LocalDefinitions.Users)
			join(&out.LocalDefinitions.ObjectivesAndMethods, p.LocalDefinitions.ObjectivesAndMethods)
			joinComponents(&out.LocalDefinitions.Components, p.LocalDefinitions.Components)
		}
		if p.AssessmentAssets != nil {
			if out.AssessmentAssets == nil {
				out.AssessmentAssets = &oscal.AssessmentAssets{}
			} else {
				aa := *out.AssessmentAssets
				out.AssessmentAssets = &aa
			}
			out.AssessmentAssets.AssessmentPlatforms = append(slices.Clone(out.AssessmentAssets.AssessmentPlatforms), p.AssessmentAssets.AssessmentPlatforms...)
			joinComponents(&out.AssessmentAssets.Components, p.AssessmentAssets.Components)
		}
		if p.BackMatter != nil {
			if out.BackMatter == nil {
				out.BackMatter = &oscal.BackMatter{}
			} else {
				bm := *out.BackMatter
				out.BackMatter = &bm
			}
			join(&out.BackMatter.Resources, p.BackMatter.Resources)
		}
	}
	return &out
}

// mergeResults joins the members' results documents: one result per
// member, each naming its bundle.
func mergeResults(ars []*oscal.AssessmentResults) *oscal.AssessmentResults {
	out := *ars[0]
	for _, a := range ars[1:] {
		out.Results = append(slices.Clone(out.Results), a.Results...)
		if a.BackMatter != nil {
			if out.BackMatter == nil {
				out.BackMatter = &oscal.BackMatter{}
			} else {
				bm := *out.BackMatter
				out.BackMatter = &bm
			}
			join(&out.BackMatter.Resources, a.BackMatter.Resources)
		}
		if a.LocalDefinitions != nil {
			if out.LocalDefinitions == nil {
				out.LocalDefinitions = &oscal.LocalDefinitions{}
			} else {
				ld := *out.LocalDefinitions
				out.LocalDefinitions = &ld
			}
			join(&out.LocalDefinitions.Activities, a.LocalDefinitions.Activities)
			join(&out.LocalDefinitions.InventoryItems, a.LocalDefinitions.InventoryItems)
			join(&out.LocalDefinitions.Users, a.LocalDefinitions.Users)
			joinComponents(&out.LocalDefinitions.Components, a.LocalDefinitions.Components)
		}
	}
	return &out
}

func join[T any](dst **[]T, src *[]T) {
	if src == nil || len(*src) == 0 {
		return
	}
	var have []T
	if *dst != nil {
		have = slices.Clone(**dst)
	}
	have = append(have, *src...)
	*dst = &have
}

func joinComponents(dst **[]oscal.SystemComponent, src *[]oscal.SystemComponent) {
	if src == nil {
		return
	}
	var have []oscal.SystemComponent
	if *dst != nil {
		have = slices.Clone(**dst)
	}
	for _, c := range *src {
		if !slices.ContainsFunc(have, func(x oscal.SystemComponent) bool { return x.UUID == c.UUID }) {
			have = append(have, c)
		}
	}
	*dst = &have
}

// mergeCoverage is the coverage the context SSP states: every part's
// mapped controls, with each member's summary naming its bundle.
func mergeCoverage(parts []*oscalPart) coverage {
	if len(parts) == 1 {
		return parts[0].cov
	}
	out := coverage{controls: map[string]map[string][]string{}}
	var summaries []string
	for _, p := range parts {
		for ctl, stmts := range p.cov.controls {
			if out.controls[ctl] == nil {
				out.controls[ctl] = map[string][]string{}
			}
			for st, rs := range stmts {
				for _, r := range rs {
					if !slices.Contains(out.controls[ctl][st], r) {
						out.controls[ctl][st] = append(out.controls[ctl][st], r)
					}
				}
			}
		}
		summaries = append(summaries, fmt.Sprintf("[%s@%s] %s", p.member.Ref.Name, p.member.Ref.Digest, p.cov.summary))
	}
	out.summary = strings.Join(summaries, " ")
	return out
}

func copyFile(from, to string) error {
	b, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		return err
	}
	return os.WriteFile(to, b, 0o644)
}

const ns = "https://konstapel.dev/ns"

// pvpResults builds one C2P check per logical policy with one subject per
// expected observation, so overlapping contributions stay distinct subjects
// of one control mapping instead of multiplying coverage.
func pvpResults(c CaptureV2, ev Evaluation) ([]policy.PVPResult, bool) {
	byKey := map[string]Observation{}
	for _, o := range ev.Observations {
		byKey[o.Key] = o
	}
	checks := map[string]*policy.ObservationByCheck{}
	var order []string
	fail := false
	for _, e := range c.Expected {
		lp := e.Contribution.LogicalPolicy
		obs, ok := checks[lp]
		if !ok {
			obs = &policy.ObservationByCheck{Title: lp, Description: "Konstapel controller observations for " + lp + "; see evaluation.json",
				CheckID: lp, Methods: []string{"TEST"}, Collected: c.Window.Closed,
				RelevantEvidences: []policy.Link{{Href: "capture.json", Description: "Frozen scope, expected inventory, and raw reports"}}}
			checks[lp] = obs
			order = append(order, lp)
		}
		o := byKey[e.Key()]
		h := sha256.Sum256([]byte(e.Key()))
		s := policy.Subject{
			Title:      fmt.Sprintf("%s %s/%s (binding %s, check %d)", e.Workload.Resource, e.Workload.Namespace, e.Workload.Name, e.Contribution.BindingUID, e.Check.Index),
			Type:       "inventory-item",
			ResourceID: "konstapel:" + hex.EncodeToString(h[:16]),
			Result:     policy.ResultError,
			Reason:     reason(o),
			Props: []policy.Property{
				{Name: "evidence-state", Value: string(o.State)},
				{Name: "cluster-id", Value: e.Cluster}, {Name: "namespace-uid", Value: e.NamespaceUID},
				{Name: "resource-uid", Value: e.Workload.UID}, {Name: "workload-state-sha256", Value: e.Workload.StateSHA256},
				{Name: "engine-policy", Value: e.Check.EnginePolicy}, {Name: "validation-index", Value: fmt.Sprint(e.Check.Index)},
				{Name: "check-sha256", Value: e.Check.SHA256}, {Name: "binding-uid", Value: e.Contribution.BindingUID},
				{Name: "enforcement-revision", Value: e.Contribution.Revision}, {Name: "mode", Value: e.Contribution.Mode},
				{Name: "source-sha256", Value: e.SourceSHA256},
			},
		}
		if o.Applicability == NotApplicable {
			// Outside the check's scope: not a result for this check. The
			// observation description names the subject so reports show it
			// was excluded, and its raw outcome stays in evaluation.json.
			// C2P keeps the observation description (not its properties).
			obs.Description += "; out of scope (declares Windows): " + s.Title
			continue
		}
		if o.State == Attributable && o.Evaluated != nil {
			s.Result, s.EvaluatedOn, s.Reason = assessment.Normalize(o.Outcome), *o.Evaluated, "source outcome "+o.Outcome
			s.Props = append(s.Props, policy.Property{Name: "source-outcome", Value: o.Outcome},
				policy.Property{Name: "source-report-uid", Value: o.Report}, policy.Property{Name: "source-result-index", Value: fmt.Sprint(o.Index)})
			if s.Result == policy.ResultFail {
				fail = true
			}
		}
		obs.Subjects = append(obs.Subjects, s)
	}
	out := policy.PVPResult{}
	for _, lp := range order {
		out.ObservationsByCheck = append(out.ObservationsByCheck, *checks[lp])
	}
	return []policy.PVPResult{out}, fail
}

// contextSSP is the minimal system context the results import. It states
// what it is not: Konstapel does not author a system security plan.
//
// It imports the profile packaged under prefix (the first part's content:
// a generated context has one profile import even when the run's members
// ship their own profiles, which stay packaged with each member).
func contextSSP(cluster string, at time.Time, cov coverage, prefix string) assessment.Object {
	id := func() string { return uuid.NewString() }
	note := "Generated assessment context for a Konstapel-assessed cluster; not an authored system security plan."
	return assessment.Object{"system-security-plan": assessment.Object{
		"uuid":           id(),
		"metadata":       assessment.Object{"title": note, "last-modified": at, "version": "1.0.0", "oscal-version": "1.1.3"},
		"import-profile": assessment.Object{"href": prefix + assessment.NIST + "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"},
		"system-characteristics": assessment.Object{
			"system-ids": []any{assessment.Object{"id": cluster}}, "system-name": "Kubernetes cluster " + cluster, "description": note,
			"system-information":     assessment.Object{"information-types": []any{assessment.Object{"uuid": id(), "title": "Cluster workloads", "description": "Workloads selected by ComplianceBindings."}}},
			"status":                 assessment.Object{"state": "operational"},
			"authorization-boundary": assessment.Object{"description": "Namespaces selected by the assessed binding in cluster " + cluster},
		},
		"system-implementation": assessment.Object{
			"users":      []any{assessment.Object{"uuid": id(), "title": "Platform operator", "description": "Operates the assessed cluster."}},
			"components": []any{assessment.Object{"uuid": id(), "type": "this-system", "title": "Assessed cluster", "description": cluster, "status": assessment.Object{"state": "operational"}}},
		},
		"control-implementation": assessment.Object{"description": cov.summary, "implemented-requirements": cov.requirements(id)},
	}}
}

func exportRole(p string) publication.FileRole {
	switch {
	case p == "assessment-results.json":
		return publication.RoleAssessmentResults
	case p == "assessment-plan.json":
		return publication.RoleAssessmentPlan
	case p == "system-security-plan.json":
		return publication.RoleSystemSecurityPlan
	case p == "content/component-definition.json":
		return publication.RoleComponentDefinition
	case p == "capture.json":
		return publication.RoleCapture
	case p == "evaluation.json":
		return publication.RoleEvidenceExtract
	case p == "summary.json":
		return publication.RoleSummary
	case p == "diagnostic.json":
		return publication.RoleDiagnostic
	case strings.HasPrefix(p, "content/"):
		return publication.RoleContent
	case strings.HasPrefix(p, bundlesDir+"/") && strings.Contains(p, "/content/"):
		// A member's content (its proofs under bundle/ are provenance).
		return publication.RoleContent
	}
	return publication.RoleProvenance
}

// reason explains an unattributable observation; OSCAL strings may not have
// leading or trailing whitespace.
func reason(o Observation) string {
	if len(o.Reasons) == 0 {
		return string(o.State)
	}
	return strings.TrimSpace(truncate(string(o.State)+": "+strings.Join(o.Reasons, "; "), 512))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// coverage is the bounded control mapping of the checks a capture assesses,
// read from every shipped component definition.
type coverage struct {
	summary string
	// controls maps control id -> statement id -> rationales, sorted on output.
	controls map[string]map[string][]string
	// rules are the assessed checks the plan is scoped to.
	rules []string
	// definitions are the component definitions (package-relative) that map
	// the assessed checks, sorted.
	definitions []string
}

// coverageFor collects the mappings of the logical policies in the capture's
// scope. A capture with nothing in scope reports the first-loop coverage
// statement for vendored content, and every mapping of a frozen bundle, so
// the context SSP always names a requirement of the content assessed.
func coverageFor(root string, set assessment.ContentSet, c CaptureV2, frozen *bundle.Frozen) (coverage, error) {
	all, err := assessment.MappingsOf(root, set)
	if err != nil {
		return coverage{}, err
	}
	policies := map[string]bool{}
	for _, s := range c.Subjects {
		policies[s.LogicalPolicy] = true
	}
	for _, e := range c.Expected {
		policies[e.Contribution.LogicalPolicy] = true
	}
	where := "shipped"
	if frozen != nil {
		where = "frozen bundle " + frozen.Identity.Name + "@" + frozen.Identity.Version
		if len(policies) == 0 {
			// Nothing in scope: plan every check the frozen bundle maps,
			// never the vendored first-loop check.
			for rule := range all {
				policies[rule] = true
			}
		}
	}
	cov := coverage{controls: map[string]map[string][]string{}}
	var parts []string
	for _, p := range slices.Sorted(maps.Keys(policies)) {
		ms, ok := all[p]
		if !ok {
			return coverage{}, fmt.Errorf("logical policy %s has no %s control mapping", p, where)
		}
		var ids []string
		for _, m := range ms {
			if cov.controls[m.ControlID] == nil {
				cov.controls[m.ControlID] = map[string][]string{}
			}
			if !slices.Contains(cov.controls[m.ControlID][m.StatementID], m.Rationale) {
				cov.controls[m.ControlID][m.StatementID] = append(cov.controls[m.ControlID][m.StatementID], m.Rationale)
			}
			ids = append(ids, m.StatementID)
		}
		parts = append(parts, fmt.Sprintf("%s (%s): %s", p, strings.Join(ids, ", "), ms[0].Rationale))
	}
	cov.rules = slices.Sorted(maps.Keys(policies))
	defs := map[string]bool{}
	for _, p := range cov.rules {
		for _, m := range all[p] {
			defs[m.Definition] = true
		}
	}
	cov.definitions = slices.Sorted(maps.Keys(defs))
	if len(parts) == 0 {
		if frozen != nil {
			return coverage{}, fmt.Errorf("%s maps no checks", where)
		}
		// Nothing in scope: plan the first-loop check so the package still
		// names the mapping it would have assessed.
		cov.rules = []string{assessment.PolicyName}
		cov.definitions = []string{assessment.ComponentDefinitions[0]}
		cov.summary = assessment.Coverage
		cov.controls["ac-6"] = map[string][]string{"ac-6_smt": {assessment.Coverage}}
		return cov, nil
	}
	cov.summary = "Partial technical evidence only. " + strings.Join(parts, " ")
	return cov, nil
}

// requirements renders one implemented requirement per mapped control, with
// its statements and their partial-coverage rationales.
func (c coverage) requirements(id func() string) []any {
	var out []any
	for _, ctl := range slices.Sorted(maps.Keys(c.controls)) {
		var stmts []any
		var remarks []string
		for _, st := range slices.Sorted(maps.Keys(c.controls[ctl])) {
			r := strings.Join(c.controls[ctl][st], " ")
			stmts = append(stmts, assessment.Object{"statement-id": st, "uuid": id(), "remarks": r})
			remarks = append(remarks, r)
		}
		out = append(out, assessment.Object{"uuid": id(), "control-id": ctl, "statements": stmts, "remarks": strings.Join(remarks, " ")})
	}
	return out
}

// retargetFindings narrows C2P's findings, which target the whole control
// statement (<control>_smt), to the single statement part a mapping claims
// (for example cm-6_smt.b), so a finding never names more of a control than
// was assessed. Controls mapped to several statements keep C2P's target.
func retargetFindings(findings *[]oscal.Finding, cov coverage) {
	if findings == nil {
		return
	}
	for j := range *findings {
		tgt := &(*findings)[j].Target
		ctl, ok := strings.CutSuffix(tgt.TargetId, "_smt")
		if stmts := cov.controls[ctl]; ok && len(stmts) == 1 {
			for st := range stmts {
				tgt.TargetId = st
			}
		}
	}
}
