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

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// ExportVersion identifies this exporter in package descriptors.
const ExportVersion = "collector-export/v1"

// ExportRequest describes one frozen, evaluated run to package.
type ExportRequest struct {
	// Root contains the verified content/ tree (mapping, catalog, profile, schemas).
	Root string
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
	if err := writeOSCAL(ctx, req); err != nil {
		for _, p := range []string{"assessment-plan.json", "assessment-results.json", "system-security-plan.json", "content"} {
			if rmErr := os.RemoveAll(filepath.Join(req.Out, p)); rmErr != nil {
				return publication.Descriptor{}, rmErr
			}
		}
		kind = publication.KindDiagnostic
		diag = &publication.Diagnostic{Reason: "ExportFailed", MissingExports: []publication.FileRole{publication.RoleAssessmentResults}, Message: truncate(err.Error(), 1024)}
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
	}
	d := publication.Descriptor{
		APIVersion: publication.APIVersion, Kind: publication.DescriptorKind, Run: req.Run, PackageKind: kind,
		Scope: req.Scope, ScopeSHA256: req.Scope.Digest(),
		Revisions: publication.Revisions{BindingConfiguration: req.BindingConfiguration, Enforcement: enforcement, MappingSHA256: req.Capture.MappingSHA256},
		Window:    publication.Window{Started: req.Capture.Window.Started, Closed: req.Capture.Window.Closed},
		Evidence:  req.Evaluation.Evidence, Outcomes: req.Evaluation.Outcomes, Diagnostic: diag,
		Producer: publication.Producer{Name: "konstapel-controller", Version: ExportVersion, ValidatedAt: time.Now().UTC().Truncate(time.Second), Checks: checks},
		Files:    files,
	}
	if err := d.Validate(); err != nil {
		return d, err
	}
	if err := assessment.Write(filepath.Join(req.Out, publication.DescriptorFile), d); err != nil {
		return d, err
	}
	return d, publication.VerifyDir(req.Out, d)
}

// writeOSCAL writes the plan, results, and SSP plus the content they
// reference, then validates schemas and reference closure.
func writeOSCAL(ctx context.Context, req ExportRequest) error {
	cov, err := coverageFor(req.Root, req.Capture)
	if err != nil {
		return fmt.Errorf("mapping: %w", err)
	}
	input, plan, err := assessment.InputFrom(req.Root, assessment.ComponentDefinitions, cov.rules)
	if err != nil {
		return fmt.Errorf("mapping: %w", err)
	}
	if err := os.CopyFS(filepath.Join(req.Out, "content"), os.DirFS(filepath.Join(req.Root, "content"))); err != nil {
		return err
	}
	if plan.BackMatter != nil && plan.BackMatter.Resources != nil {
		for i := range *plan.BackMatter.Resources {
			if r := &(*plan.BackMatter.Resources)[i]; r.Rlinks != nil {
				for j := range *r.Rlinks {
					(*r.Rlinks)[j].Href = assessment.NIST + "NIST_SP-800-53_rev5_catalog.json"
				}
			}
		}
	}
	plan.Metadata.Title = "Konstapel continuous assessment plan"
	plan.Metadata.OscalVersion = "1.1.3"
	if err := assessment.Write(filepath.Join(req.Out, "assessment-plan.json"), assessment.Object{"assessment-plan": plan}); err != nil {
		return err
	}

	results, attributableFail := pvpResults(req.Capture, req.Evaluation)
	ar, err := actions.Report(ctx, input, "assessment-plan.json", *plan, results)
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}
	mapping := assessment.FileHash(filepath.Join(req.Out, "content/component-definition.json"))
	ar.Metadata.Title = "Konstapel continuous assessment results (partial technical evidence)"
	ar.Metadata.OscalVersion = "1.1.3"
	ev := req.Evaluation.Evidence
	props := []oscal.Property{
		{Name: "evidence-completeness", Ns: ns, Value: string(ev.Completeness)},
		{Name: "expected-observations", Ns: ns, Value: fmt.Sprint(ev.Expected)},
		{Name: "attributable-observations", Ns: ns, Value: fmt.Sprint(ev.Attributable)},
		{Name: "stale-scopes", Ns: ns, Value: fmt.Sprint(ev.StaleScopes)},
		{Name: "cluster-id", Ns: ns, Value: req.Capture.Cluster},
		{Name: "run-uid", Ns: ns, Value: req.Run.RunUID},
		{Name: "mapping-sha256", Ns: ns, Value: mapping},
	}
	ar.Metadata.Props = &props
	ar.Metadata.Links = &[]oscal.Link{
		{Href: "capture.json", Rel: "related", Text: "Frozen scope, expected inventory, and raw reports"},
		{Href: "evaluation.json", Rel: "related", Text: "Per-observation evidence states and reasons"},
	}
	for _, def := range cov.definitions {
		// Each definition that maps an assessed check is referenced, so the
		// package resolves every mapping it relies on.
		*ar.Metadata.Links = append(*ar.Metadata.Links, oscal.Link{Href: def, Rel: "related", Text: "Authored partial mapping"})
	}
	for i := range ar.Results {
		r := &ar.Results[i]
		r.Title = "Konstapel continuous assessment"
		r.Description = fmt.Sprintf("Evidence %s: %d of %d expected observations attributable, %d stale scopes. %s",
			ev.Completeness, ev.Attributable, ev.Expected, ev.StaleScopes, cov.summary)
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
	if err := assessment.Write(filepath.Join(req.Out, "assessment-results.json"), assessment.Object{"assessment-results": ar}); err != nil {
		return err
	}
	if err := assessment.Write(filepath.Join(req.Out, "system-security-plan.json"), contextSSP(req.Capture.Cluster, req.Capture.Window.Closed, cov)); err != nil {
		return err
	}
	schema := filepath.Join(req.Root, "content/schemas/oscal-1.1.3.json")
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
func contextSSP(cluster string, at time.Time, cov coverage) assessment.Object {
	id := func() string { return uuid.NewString() }
	note := "Generated assessment context for a Konstapel-assessed cluster; not an authored system security plan."
	return assessment.Object{"system-security-plan": assessment.Object{
		"uuid":           id(),
		"metadata":       assessment.Object{"title": note, "last-modified": at, "version": "1.0.0", "oscal-version": "1.1.3"},
		"import-profile": assessment.Object{"href": assessment.NIST + "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"},
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
// statement, so the context SSP always names a requirement.
func coverageFor(root string, c CaptureV2) (coverage, error) {
	all, err := assessment.Mappings(root)
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
	cov := coverage{controls: map[string]map[string][]string{}}
	var parts []string
	for _, p := range slices.Sorted(maps.Keys(policies)) {
		ms, ok := all[p]
		if !ok {
			return coverage{}, fmt.Errorf("logical policy %s has no shipped control mapping", p)
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
