package collector

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/provider/projection"
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
	// RedactedInNamespace replaces binding-wide free text, such as a stale
	// scope's message, in a namespace projection: it may name other
	// namespaces.
	RedactedInNamespace = "redacted in namespace scope"
	// ObserverDiscontinuity is the detail of the watch discontinuity the
	// controller records when another process resumes a capture.
	ObserverDiscontinuity = "controller restart or leader change; earlier observations are not continuous"
	// SealedSourcePrefix starts the opaque reference that stands in for a
	// source report the namespace may not see (sealedSource).
	SealedSourcePrefix = "sealed-sha256:"
)

// Projection records how a capture was projected to one namespace. It
// counts only what the namespace may see: its own extracts.
type Projection struct {
	Namespace    string `json:"namespace"`
	NamespaceUID string `json:"namespaceUID"`
	// SourceReports, Withheld and WithheldTotal are what earlier releases
	// recorded: every source report of the collection, and the source
	// report UID and index of every unattributable result, including
	// sibling namespaces' reports. They remain only so that those captures
	// still decode. No projection writes them, and ValidateProjection
	// refuses one that carries them (owner decision 2026-11-27: no sibling
	// report counts or metadata).
	SourceReports int        `json:"sourceReports,omitempty"`
	Extracts      int        `json:"extracts"`
	Withheld      []Withheld `json:"withheld,omitempty"`
	WithheldTotal int        `json:"withheldTotal,omitempty"`
}

// Withheld is an earlier release's record of an unattributable source
// result (see Projection). Projections no longer record one.
type Withheld struct {
	Report string `json:"report"`
	Index  int    `json:"resultIndex"`
	Reason string `json:"reason"`
}

// Project returns the capture restricted to one namespace instance. Subjects,
// checks, workloads, expected observations, and scope changes outside it are
// dropped. ProjectReports attributes and rebuilds the report results against
// the namespace's frozen workloads. Free-text messages of stale scopes and
// configuration changes are dropped because they may name other namespaces.
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
		out.Stale = append(out.Stale, targeting.StaleScope{Binding: s.Binding, Policy: s.Policy, Reason: s.Reason, Message: RedactedInNamespace})
	}
	out.Checks = slices.DeleteFunc(slices.Clone(c.Checks), func(k Check) bool { return !policies[k.EnginePolicy] })
	out.EnginePolicies = slices.DeleteFunc(slices.Clone(c.EnginePolicies), func(p assessment.Object) bool {
		return !policies[assessment.Str(assessment.At(p, "metadata", "name"))]
	})
	out.Contributions = slices.DeleteFunc(slices.Clone(c.Contributions), func(x targeting.Contribution) bool {
		return !slices.ContainsFunc(out.Subjects, func(s targeting.EvidenceSubject) bool {
			return s.BindingUID == x.Binding.UID && s.LogicalPolicy == x.Policy && s.Revision == x.Revision
		})
	})
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
	out.Reports = ProjectReports(c.Reports, out.Workloads, &p)
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

// Attribution of a resource reference to one namespace instance
// (attribute).
type attribution int

const (
	// attributedHere: the reference names a workload the capture froze in
	// the namespace instance, under the namespace's frozen name.
	attributedHere attribution = iota
	// attributedElsewhere: the reference names neither the namespace nor
	// one of its frozen workloads.
	attributedElsewhere
	// unresolved: the reference lacks a namespace or UID, or its namespace
	// and its workload identity disagree with the frozen scope. It stays
	// unresolved, and its result is disclosed in no namespace view.
	unresolved
)

// frozenIdentities are the workload UIDs the capture froze in the
// namespace instance, with the namespace name each was frozen under.
func frozenIdentities(workloads []Workload, namespaceUID string) map[string]string {
	out := map[string]string{}
	for _, w := range workloads {
		if w.NamespaceUID == namespaceUID && w.UID != "" {
			out[w.UID] = w.Namespace
		}
	}
	return out
}

// attribute attributes one resource reference to the namespace instance
// named ns, whose frozen workloads are frozen. It reads only the reference
// and the frozen scope, never the cluster.
func attribute(ref map[string]any, ns string, frozen map[string]string) attribution {
	uid, refNS := assessment.Str(ref["uid"]), assessment.Str(ref["namespace"])
	if uid == "" || refNS == "" {
		return unresolved
	}
	frozenNS, isFrozen := frozen[uid]
	switch {
	case isFrozen && refNS == ns && frozenNS == ns:
		return attributedHere
	case !isFrozen && refNS != ns:
		return attributedElsewhere
	}
	// The namespace's name with an identity it never froze, or one of its
	// frozen identities under another name.
	return unresolved
}

// sealedSource is the opaque reference of a source report that the
// namespace may not see: a digest of the report UID and the namespace
// instance. The platform, which holds the binding package, recomputes it
// to trace the extract. The namespace learns nothing about the report, and
// the same report seals differently in every namespace.
func sealedSource(reportUID, namespaceUID string) string {
	return SealedSourcePrefix + assessment.Hash([]byte("konstapel-extract-source/v1\x00"+reportUID+"\x00"+namespaceUID))
}

// ProjectReports rebuilds reports as namespace extracts for the namespace
// instance p names, and adds the extracts to p's count. It attributes
// every result on its own, by its resource references (or its report's
// scope), against workloads: the capture's frozen workloads. A run whose
// namespace left scope therefore still projects new reports for the
// frozen namespace, and no live lookup decides what a namespace sees.
//
//   - A reference is the namespace's when it names a workload frozen in
//     the namespace instance, under the namespace's frozen name.
//   - A result is unresolved when any of its references lacks a namespace
//     or UID, names the namespace with an identity it never froze, or names
//     one of its frozen workloads under another name. An unresolved result
//     is disclosed in no namespace view, and nothing about it is recorded.
//   - A result whose references are all the namespace's is copied exactly
//     from allowlisted fields. A result that also names other namespaces
//     keeps only the namespace's references and loses its message, which
//     may describe the sibling (resource-filtered). Any other result is
//     another namespace's.
//
// Each extract records its provenance under SourceField, naming only what
// the namespace may see. A PolicyReport in the namespace itself is the
// namespace's own: the extract keeps its UID, report digest and result
// index. Any other source report (another namespace's, or cluster-scoped)
// is named only by its sealed reference (sealedSource), with no digest or
// index, and its extract never copies the report.
func ProjectReports(reports []assessment.Object, workloads []Workload, p *Projection) []assessment.Object {
	out := []assessment.Object{}
	frozen := frozenIdentities(workloads, p.NamespaceUID)
	for _, report := range reports {
		uid := assessment.Str(assessment.At(report, "metadata", "uid"))
		own := assessment.Str(assessment.At(report, "metadata", "namespace")) == p.Namespace
		ref := uid
		if !own {
			ref = sealedSource(uid, p.NamespaceUID)
		}
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
			resolved := len(refs) > 0
			for _, x := range refs {
				m := assessment.Map(x)
				if m == nil {
					resolved = false
					break
				}
				switch attribute(m, p.Namespace, frozen) {
				case attributedHere:
					inScope = append(inScope, assessment.Object{"apiVersion": m["apiVersion"], "kind": m["kind"], "namespace": m["namespace"], "name": m["name"], "uid": m["uid"]})
				case unresolved:
					resolved = false
				}
				if !resolved {
					break
				}
			}
			if !resolved || len(inScope) == 0 {
				continue // unresolved, or entirely another namespace's result
			}
			transform := TransformExact
			if len(inScope) != len(refs) {
				transform = TransformResourceFiltered
			}
			src := assessment.Object{"report": ref, "transformation": transform}
			if own {
				src["reportSha256"] = assessment.Digest(report)
				src["resultIndex"] = i
			}
			e := assessment.Object{"policy": r["policy"], "result": r["result"], "source": r["source"], "rule": r["rule"], "timestamp": r["timestamp"],
				"resources": inScope, SourceField: src}
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
			"metadata": assessment.Object{"uid": ref, "namespace": p.Namespace},
			"results":  kept,
		})
	}
	return out
}

// ValidateProjection independently checks that a projected capture discloses
// nothing but its namespace's evidence. It runs the Kyverno payload's own
// allowlist, then the shared check (projection.Check) on every item that
// names a namespace.
//
// The allowlist accepts exactly what Project and ProjectReports produce:
//
//   - reports are namespace extracts, with only apiVersion, kind, metadata
//     (uid and namespace) and at least one result; no summary, scope,
//     labels or annotations
//   - every result carries only the extract fields with their source types,
//     at least one resource reference with only reference fields, and
//     provenance whose report is the extract's own: an own report's UID,
//     digest, index and transformation, or a sealed reference and the
//     transformation only; only an exact extract keeps its message, and
//     properties keep only cel.validationIndex
//   - every resource reference names a workload the capture froze in the
//     namespace instance, under the namespace's name
//   - stale scopes keep their reason, never their message, and the capture
//     has no collection errors
//   - binding-wide scope changes are configuration changes or watch
//     discontinuities that name no namespace or workload and carry no free
//     text
//   - checks, engine policies and contributions belong to a projected subject
//   - the projection counts nothing but its own extracts: no source report
//     count and no withheld results, which would describe siblings' reports
//
// The namespaces the extract names are those of its subjects, workloads,
// expected observations, scope changes, extracts and resource references.
// Each must be the projection's namespace instance (projection.Check).
// Errors locate the offending item and never repeat its content.
func ValidateProjection(c CaptureV2) error {
	p := c.Projection
	if p == nil {
		return errors.New("capture is not a namespace projection")
	}
	if p.Namespace == "" || p.NamespaceUID == "" {
		return errors.New("the projection names no namespace instance")
	}
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	var items []projection.Disclosure
	disclose := func(item, ns, uid string) {
		items = append(items, projection.Disclosure{Item: item, Namespace: ns, NamespaceUID: uid})
	}
	workload := func(item string, w Workload) { disclose(item, w.Namespace, w.NamespaceUID) }

	policies := map[string]bool{}
	for i, s := range c.Subjects {
		disclose(fmt.Sprintf("subjects[%d]", i), s.Namespace, string(s.NamespaceUID))
		policies[s.EnginePolicy] = true
	}
	for i, w := range c.Workloads {
		workload(fmt.Sprintf("workloads[%d]", i), w)
	}
	for i, e := range c.Expected {
		disclose(fmt.Sprintf("expected[%d]", i), "", e.NamespaceUID)
		workload(fmt.Sprintf("expected[%d].workload", i), e.Workload)
	}
	for i, s := range c.Stale {
		if s.Message != RedactedInNamespace {
			fail("stale[%d] keeps its binding-wide message", i)
		}
	}
	if len(c.CollectionErrors) > 0 {
		fail("the projection keeps binding-wide collection errors")
	}
	for i, k := range c.Checks {
		if !policies[k.EnginePolicy] {
			fail("checks[%d] belongs to no projected subject", i)
		}
	}
	for i, ep := range c.EnginePolicies {
		if !policies[assessment.Str(assessment.At(ep, "metadata", "name"))] {
			fail("enginePolicies[%d] belongs to no projected subject", i)
		}
	}
	for i, x := range c.Contributions {
		if !slices.ContainsFunc(c.Subjects, func(s targeting.EvidenceSubject) bool {
			return s.BindingUID == x.Binding.UID && s.LogicalPolicy == x.Policy && s.Revision == x.Revision
		}) {
			fail("contributions[%d] belongs to no projected subject", i)
		}
	}
	for i, ch := range c.ScopeChanges {
		item := fmt.Sprintf("scopeChanges[%d]", i)
		if ch.Namespace == "" && ch.NamespaceUID == "" && ch.Previous == nil && ch.Current == nil {
			if !bindingWideChange(ch) {
				fail("%s is a binding-wide %s change with detail a namespace may not see", item, ch.Kind)
			}
			continue
		}
		disclose(item, ch.Namespace, ch.NamespaceUID)
		if ch.Previous != nil {
			workload(item+".previous", *ch.Previous)
		}
		if ch.Current != nil {
			workload(item+".current", *ch.Current)
		}
	}
	frozen := frozenIdentities(c.Workloads, p.NamespaceUID)
	for i, report := range c.Reports {
		items = append(items, validateExtract(fmt.Sprintf("reports[%d]", i), report, p, frozen, fail)...)
	}
	if p.SourceReports != 0 || len(p.Withheld) > 0 || p.WithheldTotal != 0 {
		fail("the projection counts or names source reports beyond its own extracts")
	}
	if extracts := countExtracts(c.Reports); p.Extracts != extracts {
		fail("the projection's extract count is not its extracts")
	}
	if err := projection.Check(projection.Scope{Name: p.Namespace, UID: p.NamespaceUID}, items); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// bindingWideChange reports whether a change that names no namespace or
// workload is one a namespace projection keeps: a configuration change or
// watch discontinuity whose detail is empty, the controller's fixed
// discontinuity text, or a stale scope's reason with its message redacted.
func bindingWideChange(ch ScopeChange) bool {
	switch ch.Kind {
	case WatchDiscontinuity:
		return ch.Detail == "" || ch.Detail == ObserverDiscontinuity
	case ConfigurationChanged:
		if ch.Detail == "" {
			return true
		}
		reason, ok := strings.CutPrefix(ch.Detail, "stale: ")
		if reason, ok = strings.CutSuffix(reason, ": "+RedactedInNamespace); !ok || reason == "" {
			return false
		}
		return strings.IndexFunc(reason, func(r rune) bool { return !('A' <= r && r <= 'Z' || 'a' <= r && r <= 'z') }) < 0
	}
	return false
}

// Fields a namespace extract may keep (ProjectReports).
var (
	extractFields    = fieldSet("apiVersion", "kind", "metadata", "results")
	extractMetadata  = fieldSet("uid", "namespace")
	resultFields     = fieldSet("policy", "result", "source", "rule", "timestamp", "resources", "properties", "message", SourceField)
	resultStrings    = []string{"policy", "result", "source", "rule", "message"}
	referenceFields  = fieldSet("apiVersion", "kind", "namespace", "name", "uid")
	provenanceFields = fieldSet("report", "reportSha256", "resultIndex", "transformation")
	timestampFields  = fieldSet("seconds", "nanos")
)

func fieldSet(names ...string) map[string]bool {
	out := map[string]bool{}
	for _, n := range names {
		out[n] = true
	}
	return out
}

// onlyFields reports whether m has no field outside allowed.
func onlyFields(m map[string]any, allowed map[string]bool) bool {
	for k := range m {
		if !allowed[k] {
			return false
		}
	}
	return true
}

// countExtracts counts the extracted results of reports.
func countExtracts(reports []assessment.Object) int {
	n := 0
	for _, r := range reports {
		results, _ := r["results"].([]any)
		n += len(results)
	}
	return n
}

// Provenance an extract may record (ProjectReports): an own report's, or a
// sealed source's.
var sealedProvenanceFields = fieldSet("report", "transformation")

// validateExtract checks one report extract against the allowlist and the
// namespace's frozen workloads, and returns the namespaces it names.
func validateExtract(item string, report map[string]any, p *Projection, frozen map[string]string, fail func(string, ...any)) []projection.Disclosure {
	if !onlyFields(report, extractFields) {
		fail("%s is not a namespace extract: it keeps a source report field", item)
	}
	meta := assessment.Map(report["metadata"])
	_, uidIsString := meta["uid"].(string)
	if meta == nil || !onlyFields(meta, extractMetadata) || !uidIsString {
		fail("%s metadata is not an extract's uid and namespace", item)
	}
	ns, _ := meta["namespace"].(string)
	items := []projection.Disclosure{{Item: item, Namespace: ns}}
	uid := assessment.Str(meta["uid"])
	results, ok := report["results"].([]any)
	if !ok || len(results) == 0 {
		fail("%s has no extracted results", item)
	}
	for j, raw := range results {
		at := fmt.Sprintf("%s.results[%d]", item, j)
		r := assessment.Map(raw)
		if r == nil || !onlyFields(r, resultFields) {
			fail("%s keeps a field outside the extract allowlist", at)
			continue
		}
		for _, k := range resultStrings {
			if v, present := r[k]; present {
				if _, ok := v.(string); !ok {
					fail("%s.%s is not a string", at, k)
				}
			}
		}
		if ts, present := r["timestamp"]; present {
			m := assessment.Map(ts)
			if m == nil || !onlyFields(m, timestampFields) {
				fail("%s.timestamp is not a seconds and nanos timestamp", at)
			}
			for _, v := range m {
				if _, ok := integral(v); !ok {
					fail("%s.timestamp is not a seconds and nanos timestamp", at)
				}
			}
		}
		if props, present := r["properties"]; present {
			m := assessment.Map(props)
			_, isString := m["cel.validationIndex"].(string)
			if len(m) != 1 || !isString {
				fail("%s.properties keeps more than cel.validationIndex", at)
			}
		}
		src := assessment.Map(r[SourceField])
		if src == nil {
			fail("%s is an extract without provenance", at)
		} else {
			index, indexOK := integral(src["resultIndex"])
			_, shaIsString := src["reportSha256"].(string)
			srcReport, reportIsString := src["report"].(string)
			transform := src["transformation"]
			validTransform := transform == TransformExact || transform == TransformResourceFiltered
			if strings.HasPrefix(srcReport, SealedSourcePrefix) {
				// A source the namespace may not see: no digest of it, no
				// index into it, nothing but its sealed reference.
				if len(src) != len(sealedProvenanceFields) || !onlyFields(src, sealedProvenanceFields) || !validSeal(srcReport) || srcReport != uid || !validTransform {
					fail("%s provenance of a sealed source is not its sealed reference and transformation", at)
				}
			} else if len(src) != len(provenanceFields) || !onlyFields(src, provenanceFields) || !indexOK || index < 0 || !shaIsString || !reportIsString || srcReport != uid || !validTransform {
				fail("%s provenance is not its source report, digest, index and transformation", at)
			}
			if _, present := r["message"]; present && transform != TransformExact {
				fail("%s keeps the message of a resource-filtered result", at)
			}
		}
		refs, _ := r["resources"].([]any)
		if len(refs) == 0 {
			fail("%s is an extract without resources", at)
		}
		for k, raw := range refs {
			ref := fmt.Sprintf("%s.resources[%d]", at, k)
			m := assessment.Map(raw)
			if m == nil || !onlyFields(m, referenceFields) || assessment.Str(m["uid"]) == "" {
				fail("%s is not a resource reference with a UID", ref)
			}
			for _, f := range []string{"apiVersion", "kind", "name"} {
				if v := m[f]; v != nil {
					if _, ok := v.(string); !ok {
						fail("%s.%s is not a string", ref, f)
					}
				}
			}
			ns, _ := m["namespace"].(string)
			if m != nil && attribute(m, p.Namespace, frozen) != attributedHere {
				fail("%s is not a workload the capture froze in the namespace", ref)
			}
			items = append(items, projection.Disclosure{Item: ref, Namespace: ns})
		}
	}
	return items
}

// validSeal reports whether s is a sealed reference: the prefix and a
// SHA-256 in lowercase hex.
func validSeal(s string) bool {
	h, ok := strings.CutPrefix(s, SealedSourcePrefix)
	return ok && len(h) == 64 && strings.IndexFunc(h, func(r rune) bool { return !('0' <= r && r <= '9' || 'a' <= r && r <= 'f') }) < 0
}

// ValidateProjectedEvaluation checks that an evaluation discloses only its
// projected capture's evidence, before its summary or any export uses it.
// The capture must pass ValidateProjection. Every observation must be one of
// the capture's expected observations, evaluated once. Every report it
// references must be one of the capture's extracts, and its summary must
// count exactly those observations. Errors never repeat an observation's
// content.
func ValidateProjectedEvaluation(c CaptureV2, ev Evaluation) error {
	if err := ValidateProjection(c); err != nil {
		return err
	}
	expected := map[string]bool{}
	for _, e := range c.Expected {
		expected[e.Key()] = true
	}
	reports := map[string]bool{}
	for _, r := range c.Reports {
		reports[assessment.Str(assessment.At(r, "metadata", "uid"))] = true
	}
	var errs []error
	seen := map[string]bool{}
	for i, o := range ev.Observations {
		switch {
		case !expected[o.Key]:
			errs = append(errs, fmt.Errorf("observations[%d] is not an expected observation of the projection", i))
		case seen[o.Key]:
			errs = append(errs, fmt.Errorf("observations[%d] repeats an observation", i))
		}
		seen[o.Key] = true
		if o.Report != "" && !reports[o.Report] {
			errs = append(errs, fmt.Errorf("observations[%d] references a report that is not an extract of the projection", i))
		}
	}
	if e, o := Tally(ev.Observations, len(c.Stale)); e != ev.Evidence || o != ev.Outcomes {
		errs = append(errs, errors.New("the evaluation summary does not count exactly its observations"))
	}
	return errors.Join(errs...)
}
