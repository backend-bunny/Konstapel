package collector

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Transformations recorded on projected report results.
const (
	// TransformExact copies an in-scope result's allowlisted fields unchanged.
	TransformExact = "exact"
	// TransformResourceFiltered keeps only the in-scope resource references of
	// a mixed-scope result and drops its message, which may describe siblings.
	TransformResourceFiltered = "resource-filtered/v1"
	// SourceField carries a projected result's provenance.
	SourceField = "konstapelSource"
)

// Projection records how a capture was projected to one namespace.
type Projection struct {
	Namespace     string     `json:"namespace"`
	NamespaceUID  string     `json:"namespaceUID"`
	SourceReports int        `json:"sourceReports"`
	Extracts      int        `json:"extracts"`
	Withheld      []Withheld `json:"withheld,omitempty"`
	// WithheldTotal counts every withheld result; Withheld is bounded.
	WithheldTotal int `json:"withheldTotal,omitempty"`
}

// Withheld is a source result excluded because its scope could not be
// established. Only its source identity is recorded, never its content.
type Withheld struct {
	Report string `json:"report"`
	Index  int    `json:"resultIndex"`
	Reason string `json:"reason"`
}

// maxWithheld bounds the recorded withheld results.
const maxWithheld = 100

// Project returns the capture restricted to one namespace instance. Subjects,
// checks, workloads, expected observations, and scope changes outside it are
// dropped. Each report result is rebuilt from allowlisted fields: in-scope
// results are copied exactly; mixed-scope results keep only in-scope resource
// references and lose their message; results without an attributable
// resource are withheld. Every extract records its source report UID and
// digest, original result index, and transformation. Free-text messages of
// stale scopes and configuration changes are dropped because they may name
// other namespaces.
func Project(c CaptureV2, namespaceUID string) (CaptureV2, error) {
	if err := validateOpen(c); err != nil {
		return CaptureV2{}, err
	}
	var ns string
	out := c
	out.Subjects = []targeting.EvidenceSubject{}
	policies := map[string]bool{}
	for _, s := range c.Subjects {
		if string(s.NamespaceUID) == namespaceUID {
			ns = s.Namespace
			out.Subjects = append(out.Subjects, s)
			policies[s.EnginePolicy] = true
		}
	}
	if ns == "" {
		return CaptureV2{}, fmt.Errorf("namespace %s: %w", namespaceUID, ErrNotInScope)
	}
	out.Stale = []targeting.StaleScope{}
	for _, s := range c.Stale {
		out.Stale = append(out.Stale, targeting.StaleScope{Binding: s.Binding, Policy: s.Policy, Reason: s.Reason, Message: "redacted in namespace scope"})
	}
	out.Checks = slices.DeleteFunc(slices.Clone(c.Checks), func(k Check) bool { return !policies[k.EnginePolicy] })
	out.Workloads = slices.DeleteFunc(slices.Clone(c.Workloads), func(w Workload) bool { return w.NamespaceUID != namespaceUID })
	out.Expected = slices.DeleteFunc(slices.Clone(c.Expected), func(e Expected) bool { return e.NamespaceUID != namespaceUID })
	out.CollectionErrors = nil
	out.ScopeChanges = nil
	for _, ch := range c.ScopeChanges {
		switch {
		case ch.NamespaceUID == namespaceUID:
			out.ScopeChanges = append(out.ScopeChanges, ch)
		case ch.NamespaceUID == "" && (ch.Kind == ConfigurationChanged || ch.Kind == WatchDiscontinuity):
			ch.Detail = ""
			out.ScopeChanges = append(out.ScopeChanges, ch)
		}
	}

	p := Projection{Namespace: ns, NamespaceUID: namespaceUID}
	out.Reports = ProjectReports(c.Reports, &p)
	slices.SortFunc(p.Withheld, func(a, b Withheld) int { return cmp.Or(cmp.Compare(a.Report, b.Report), cmp.Compare(a.Index, b.Index)) })
	out.Projection = &p
	return out, validateOpen(out)
}

// ErrNotInScope means the namespace is not part of the frozen scope.
var ErrNotInScope = errors.New("namespace is not in the frozen scope")

// validateOpen validates a capture whose collection window may still be open.
func validateOpen(c CaptureV2) error {
	if c.Window.Closed.IsZero() {
		c.Window.Closed = c.Window.Started
	}
	return c.Validate()
}

// ProjectReports rebuilds reports as namespace extracts for p.Namespace (see
// Project), adding to p's source, extract, and withheld counts. It works
// without the rest of the capture, so a run whose namespace left scope can
// still project new reports for the frozen namespace.
func ProjectReports(reports []assessment.Object, p *Projection) []assessment.Object {
	out := []assessment.Object{}
	p.SourceReports += len(reports)
	for _, report := range reports {
		uid := assessment.Str(assessment.At(report, "metadata", "uid"))
		digest := assessment.Digest(report)
		results, _ := report["results"].([]any)
		var kept []any
		for i, raw := range results {
			r := assessment.Map(raw)
			refs, ok := r["resources"].([]any)
			if !ok {
				if scope := assessment.Map(report["scope"]); scope != nil {
					refs = []any{scope}
				}
			}
			var inScope []any
			attributable := len(refs) > 0
			for _, ref := range refs {
				m := assessment.Map(ref)
				if m == nil || assessment.Str(m["uid"]) == "" || assessment.Str(m["namespace"]) == "" {
					attributable = false
					break
				}
				if assessment.Str(m["namespace"]) == p.Namespace {
					inScope = append(inScope, assessment.Object{"apiVersion": m["apiVersion"], "kind": m["kind"], "namespace": m["namespace"], "name": m["name"], "uid": m["uid"]})
				}
			}
			if !attributable {
				p.WithheldTotal++
				if len(p.Withheld) < maxWithheld {
					p.Withheld = append(p.Withheld, Withheld{Report: uid, Index: i, Reason: "result resources lack namespace or UID; scope cannot be established"})
				}
				continue
			}
			if len(inScope) == 0 {
				continue // entirely another namespace's result
			}
			transform := TransformExact
			if len(inScope) != len(refs) {
				transform = TransformResourceFiltered
			}
			e := assessment.Object{"policy": r["policy"], "result": r["result"], "source": r["source"], "rule": r["rule"], "timestamp": r["timestamp"],
				"resources": inScope,
				SourceField: assessment.Object{"report": uid, "reportSha256": digest, "resultIndex": i, "transformation": transform}}
			if idx := assessment.At(r, "properties", "cel.validationIndex"); idx != nil {
				e["properties"] = assessment.Object{"cel.validationIndex": idx}
			}
			if transform == TransformExact && r["message"] != nil {
				e["message"] = r["message"]
			}
			for k, v := range e {
				if v == nil {
					delete(e, k)
				}
			}
			kept = append(kept, e)
		}
		if len(kept) == 0 {
			continue
		}
		p.Extracts += len(kept)
		out = append(out, assessment.Object{
			"apiVersion": report["apiVersion"], "kind": report["kind"],
			"metadata": assessment.Object{"uid": uid, "namespace": p.Namespace},
			"results":  kept,
		})
	}
	slices.SortFunc(p.Withheld, func(a, b Withheld) int { return cmp.Or(cmp.Compare(a.Report, b.Report), cmp.Compare(a.Index, b.Index)) })
	return out
}

// ValidateProjection independently checks that a projected capture contains
// nothing attributable to another namespace: every subject, workload,
// expected observation, scope change, and report resource belongs to the
// projection's namespace, and every report result carries provenance.
func ValidateProjection(c CaptureV2) error {
	p := c.Projection
	if p == nil {
		return errors.New("capture is not a namespace projection")
	}
	var errs []error
	for _, s := range c.Subjects {
		if string(s.NamespaceUID) != p.NamespaceUID {
			errs = append(errs, fmt.Errorf("subject in namespace %s", s.NamespaceUID))
		}
	}
	for _, w := range c.Workloads {
		if w.NamespaceUID != p.NamespaceUID {
			errs = append(errs, fmt.Errorf("workload %s outside the namespace", w.UID))
		}
	}
	for _, e := range c.Expected {
		if e.NamespaceUID != p.NamespaceUID {
			errs = append(errs, fmt.Errorf("expected observation outside the namespace"))
		}
	}
	for _, ch := range c.ScopeChanges {
		if ch.NamespaceUID != "" && ch.NamespaceUID != p.NamespaceUID {
			errs = append(errs, fmt.Errorf("%s change for another namespace", ch.Kind))
		}
	}
	for _, report := range c.Reports {
		if assessment.Str(assessment.At(report, "metadata", "namespace")) != p.Namespace || report["scope"] != nil {
			errs = append(errs, errors.New("report is not a namespace extract"))
		}
		results, _ := report["results"].([]any)
		for _, raw := range results {
			r := assessment.Map(raw)
			if assessment.Map(r[SourceField]) == nil {
				errs = append(errs, errors.New("extract without provenance"))
			}
			refs, _ := r["resources"].([]any)
			if len(refs) == 0 {
				errs = append(errs, errors.New("extract without resources"))
			}
			for _, ref := range refs {
				if assessment.Str(assessment.Map(ref)["namespace"]) != p.Namespace {
					errs = append(errs, errors.New("extract references another namespace"))
				}
			}
		}
	}
	return errors.Join(errs...)
}
