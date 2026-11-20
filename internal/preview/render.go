package preview

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// RenderText renders the report as human-readable text. It reads only the
// report model, the same values the JSON carries, in the report's order, so
// a report decoded from saved JSON renders to the same text.
func RenderText(r *Report) []byte {
	var b bytes.Buffer
	t := textWriter{w: &b}
	t.header(r)
	t.observation(r.Observation)
	t.inputs(r.Inputs)
	t.content(r.Content)
	t.changes(r)
	t.applied(r.AppliedState)
	t.exceptions(r.Exceptions)
	t.evidence(r.Evidence)
	t.diagnostics("Limitations (informational)", r.Limitations)
	t.diagnostics("Errors", r.Errors)
	return b.Bytes()
}

type textWriter struct{ w io.Writer }

func (t textWriter) line(indent int, format string, args ...any) {
	fmt.Fprintf(t.w, "%s%s\n", strings.Repeat("  ", indent), fmt.Sprintf(format, args...))
}

func (t textWriter) section(title string) { t.line(0, "\n%s", title) }

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func (t textWriter) header(r *Report) {
	t.line(0, "Konstapel policy change preview (%s v%d)", r.Kind, r.SchemaVersion)
	switch {
	case r.Complete:
		t.line(0, "Result: complete, %s", plural(r.ImpactCount, "policy impact", "policy impacts"))
	case r.Summary.Compared:
		t.line(0, "Result: INCOMPLETE (%s); %s determined so far; no statement about the absence of impacts", plural(len(r.Errors), "error", "errors"), plural(r.ImpactCount, "policy impact", "policy impacts"))
	default:
		t.line(0, "Result: INCOMPLETE (%s); nothing was compared", plural(len(r.Errors), "error", "errors"))
	}
	s := r.Summary
	if s.Compared {
		t.line(1, "%s with impacts, %s with impacts; %s, %s",
			plural(s.ContributionImpacts, "contribution row", "contribution rows"), plural(s.NamespaceImpacts, "namespace row", "namespace rows"),
			plural(s.Objects, "object", "objects"), plural(s.ReportingOnly, "reporting-only object", "reporting-only objects"))
		if s.EquivalentReplacements > 0 {
			t.line(1, "%s: configuration semantically equivalent, but enforcement revisions are replaced (counted as impacts)",
				plural(s.EquivalentReplacements, "equivalent replacement", "equivalent replacements"))
		}
		if len(s.Categories) > 0 {
			var parts []string
			for _, c := range slices.Sorted(maps.Keys(s.Categories)) {
				parts = append(parts, fmt.Sprintf("%s %d", c, s.Categories[c]))
			}
			t.line(1, "impact categories: %s", strings.Join(parts, ", "))
		}
	}
	t.line(1, "impact counts are configuration rows, not workloads, failures or controls")
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func (t textWriter) observation(o *ReportObservation) {
	t.section("Observation")
	if o == nil {
		t.line(1, "not observed")
		return
	}
	state := "complete"
	if !o.Complete {
		state = "INCOMPLETE"
	}
	t.line(1, "%s observation of cluster %s (context %s, server %s)", state, orNone(o.Cluster), o.Context, orNone(o.Server))
	t.line(1, "controller namespace %s, bundle sources %s", o.ControllerNamespace, orDefault(o.SourcesConfigMap, "not selected (vendored bundle only)"))
	if o.ControllerVersion != "" {
		t.line(1, "OCI bundle compatibility checked against controller release %s (assumed, not observed)", o.ControllerVersion)
	}
	t.line(1, "window %s to %s, %s, %s, %s", ts(o.Start), ts(o.End), plural(o.Captures, "capture", "captures"),
		plural(len(o.Objects), "object", "objects"), plural(len(o.Namespaces), "namespace", "namespaces"))
	for _, d := range o.Drift {
		t.line(2, "capture %d recaptured after %s: %s", d.Capture, d.Reason, strings.Join(d.Changed, ", "))
	}
	var contracts []string
	for _, k := range slices.Sorted(maps.Keys(o.Contracts)) {
		contracts = append(contracts, fmt.Sprintf("%s v%d", k, o.Contracts[k]))
	}
	if len(contracts) > 0 {
		t.line(1, "contracts: %s", strings.Join(contracts, ", "))
	}
	if s := o.Sources; s != nil {
		switch {
		case s.Missing:
			t.line(1, "bundle-source ConfigMap %s/%s: missing", s.ConfigMap.Namespace, s.ConfigMap.Name)
		case s.ParseError != "":
			t.line(1, "bundle-source ConfigMap %s/%s: invalid: %s", s.ConfigMap.Namespace, s.ConfigMap.Name, s.ParseError)
		default:
			t.line(1, "bundle-source ConfigMap %s/%s %s: %s", s.ConfigMap.Namespace, s.ConfigMap.Name, s.Digest, plural(len(s.Sources), "source", "sources"))
		}
		for _, sec := range s.Secrets {
			t.line(2, "Secret %s/%s: %s", sec.Namespace, sec.Name, sec.Access)
		}
	}
}

func orNone(s string) string { return orDefault(s, "(none)") }

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func (t textWriter) inputs(in ReportInputs) {
	t.section("Inputs")
	if len(in.Streams) == 0 {
		t.line(1, "none")
	}
	for _, s := range in.Streams {
		if s.Read {
			t.line(1, "%s %s %s (%s)", s.Role, s.Path, s.Digest, plural(int(s.Bytes), "byte", "bytes"))
		} else {
			t.line(1, "%s %s (not read)", s.Role, s.Path)
		}
		for _, o := range in.Objects {
			if o.Role != s.Role || o.Source != s.Path {
				continue
			}
			t.line(2, "%s #%d:%d, configuration %s", o.Identity, o.Document, o.Line, o.Fingerprint)
			if len(o.Ignored) > 0 {
				t.line(3, "ignored server-owned fields: %s", strings.Join(o.Ignored, ", "))
			}
		}
	}
}

func (t textWriter) content(cs []ContentRecord) {
	t.section("Bundle content")
	if len(cs) == 0 {
		t.line(1, "none read")
	}
	for _, c := range cs {
		state := "verified"
		if !c.Resolved {
			state = "NOT RESOLVED"
			if c.ErrorClass != "" {
				state += " (" + string(c.ErrorClass) + ")"
			}
		}
		repo := ""
		if c.Repository != "" {
			repo = " from " + c.Repository
		}
		t.line(1, "%s@%s [%s]%s: %s", c.Name, c.Digest, c.DigestKind, repo, state)
		if c.Error != "" {
			t.line(2, "%s", c.Error)
		}
	}
}

func refs(ns []targeting.NamespaceRef) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = n.Name + " (" + string(n.UID) + ")"
	}
	return strings.Join(parts, ", ")
}

func contributors(cs []ContributorRef) string {
	parts := make([]string, len(cs))
	for i, c := range cs {
		p := c.Binding + " " + string(c.Mode)
		if c.RevisionEffect != "" {
			p += ", " + string(c.RevisionEffect)
		}
		parts[i] = p
	}
	return strings.Join(parts, "; ")
}

func keyString(k ContributionKey) string {
	uid := "pending creation"
	if k.BindingUID != "" {
		uid = "uid " + string(k.BindingUID)
	}
	return fmt.Sprintf("binding %s (%s) policy %s", k.Binding, uid, k.Policy)
}

func (t textWriter) impacts(indent int, is []Impact) {
	for _, i := range is {
		change := ""
		if i.Before != "" || i.After != "" {
			change = fmt.Sprintf(" %s -> %s", orNone(i.Before), orNone(i.After))
		}
		t.line(indent, "%s [%s]%s: %s", i.Category, i.Area, change, i.Reason)
	}
}

func (t textWriter) changes(r *Report) {
	t.section("Changes")
	ch := r.Changes
	if ch == nil {
		t.line(1, "not determined: no comparison ran")
		return
	}
	t.line(1, "Objects")
	if len(ch.Objects) == 0 {
		t.line(2, "none")
	}
	for _, o := range ch.Objects {
		var notes []string
		if o.ConfigurationChanged {
			notes = append(notes, "configuration changed")
		} else {
			notes = append(notes, "configuration unchanged")
		}
		if o.StoredSpec != "" {
			notes = append(notes, "stored spec "+string(o.StoredSpec))
		}
		if o.ReportingOnly {
			notes = append(notes, "reporting-only (not an impact)")
		}
		if o.PendingIdentity {
			notes = append(notes, "server identity pending application")
		}
		if o.Observed != nil {
			notes = append(notes, fmt.Sprintf("observed uid %s generation %d", o.Observed.UID, o.Observed.Generation))
		}
		t.line(2, "%s: %s; %s", o.Identity, o.Disposition, strings.Join(notes, ", "))
		for _, n := range o.Notes {
			t.line(3, "%s", n)
		}
	}
	for _, a := range ch.AbsentRemovals {
		t.line(2, "%s: removal declared, already absent (no impact)", a)
	}
	t.line(1, "Contributions")
	if len(ch.Contributions) == 0 {
		t.line(2, "none")
	}
	for _, c := range ch.Contributions {
		label := string(c.Change)
		if c.RevisionEffect != "" {
			label += ", revision " + string(c.RevisionEffect)
		}
		if c.SemanticallyEquivalent {
			label += ", semantically equivalent configuration but the revision is replaced (counted as an impact)"
		}
		t.line(2, "%s: %s", keyString(c.Key), label)
		for _, side := range []struct {
			name string
			s    *ContributionSide
		}{{"observed", c.Before}, {"proposed", c.After}} {
			if side.s == nil {
				continue
			}
			t.line(3, "%s: profile %s, bundle %s@%s [%s], mode %s, selector %s, %s", side.name, side.s.Profile, side.s.BundleName,
				side.s.BundleDigest, side.s.BundleDigestKind, side.s.Mode, selectorString(side.s.NamespaceSelector), plural(side.s.TargetCount, "target namespace", "target namespaces"))
		}
		if len(c.NamespacesAdded) > 0 {
			t.line(3, "namespaces added: %s", refs(c.NamespacesAdded))
		}
		if len(c.NamespacesRemoved) > 0 {
			t.line(3, "namespaces removed: %s", refs(c.NamespacesRemoved))
		}
		for _, resp := range c.Responsible {
			t.line(3, "responsible: %s (%s) %s", resp.Identity, resp.Disposition, location(resp.Source, resp.Document, resp.Line))
		}
		t.impacts(3, c.Impacts)
	}
	t.line(1, "Namespaces")
	if len(ch.Namespaces) == 0 {
		t.line(2, "none")
	}
	for _, n := range ch.Namespaces {
		t.line(2, "%s (%s) policy %s", n.Namespace.Name, n.Namespace.UID, n.Policy)
		for _, l := range []struct {
			name string
			cs   []ContributorRef
		}{{"added", n.Added}, {"removed", n.Removed}, {"replaced", n.Replaced}, {"remaining", n.Remaining}} {
			if len(l.cs) > 0 {
				t.line(3, "%s: %s", l.name, contributors(l.cs))
			}
		}
		t.line(3, "exception eligibility: %s -> %s", eligibilityText(n.Before), eligibilityText(n.After))
		t.impacts(3, n.Impacts)
	}
}

func eligibilityText(e *EligibilitySide) string {
	if e == nil {
		return "none (no contribution applies)"
	}
	s := string(e.Effective)
	if e.MaxLifetime != nil {
		s += " max " + e.MaxLifetime.String()
	}
	return s
}

func location(source string, doc, line int) string {
	if source == "" {
		return ""
	}
	return fmt.Sprintf("at %s#%d:%d", source, doc, line)
}

func (t textWriter) applied(a *AppliedState) {
	t.section("Observed applied state (informational)")
	if a == nil {
		t.line(1, "not determined: no comparison ran")
		return
	}
	if len(a.Policies) == 0 {
		t.line(1, "no Konstapel-owned engine policy observed")
	}
	for _, p := range a.Policies {
		ready := "ready"
		if !p.Ready {
			ready = "not ready"
		}
		t.line(1, "%s: %s, proposed %s, %s, binding %s policy %s mode %s, scope %s", p.Policy.Name, p.Condition, p.Proposed, ready,
			orNone(p.Binding), orNone(p.Logical), orNone(string(p.Mode)), orNone(refs(p.Scope)))
	}
	for _, p := range a.Pending {
		state := "no engine policy yet"
		if p.Applied {
			state = "engine policy not accepted yet"
		}
		t.line(1, "pending delivery: %s: %s", keyString(p.Key), state)
	}
	for _, u := range a.Unowned {
		t.line(1, "unowned Konstapel-labelled policy %s (never treated as owned)", u.Name)
	}
}

func (t textWriter) exceptions(e ExceptionReport) {
	t.section("Exceptions")
	t.line(1, "analysis %s: %s", e.Analysis, e.Reason)
	if e.Observed != nil {
		t.line(1, "%s observed", plural(*e.Observed, "ComplianceException", "ComplianceExceptions"))
	}
	for _, s := range e.PotentiallyAffected {
		var keys []string
		for _, k := range s.Contributions {
			keys = append(keys, k.Binding)
		}
		t.line(2, "%s/%s policy %s (accepted %t, revision %d): consequence unknown; changed bindings %s, %s", s.Namespace, s.Name, s.Policy,
			s.Accepted, s.AcceptanceRevision, orNone(strings.Join(keys, ", ")), plural(s.NamespaceRows, "namespace row", "namespace rows"))
	}
	for _, c := range e.Consequences {
		t.line(2, "%s/%s: %s: %s", c.Exception.Namespace, c.Exception.Name, c.Consequence, c.Reason)
	}
}

func (t textWriter) evidence(e EvidenceReport) {
	t.section("Evidence (context, never an impact)")
	t.line(1, "analysis %s: %s", e.Analysis, e.Reason)
	for _, en := range e.Entries {
		t.line(2, "%s namespace %s: %s", keyString(en.Key), en.Namespace.Name, en.State)
	}
}

func (t textWriter) diagnostics(title string, ds []ReportDiagnostic) {
	t.section(title)
	if len(ds) == 0 {
		t.line(1, "none")
	}
	for _, d := range ds {
		var where []string
		if d.Source != "" {
			loc := d.Source
			if d.Document > 0 {
				loc += fmt.Sprintf("#%d", d.Document)
			}
			if d.Line > 0 {
				loc += fmt.Sprintf(":%d", d.Line)
			}
			where = append(where, loc)
		}
		for _, s := range []string{d.Identity, d.Field, d.Resource} {
			if s != "" {
				where = append(where, s)
			}
		}
		if d.Namespace != "" || d.Name != "" {
			where = append(where, strings.TrimPrefix(d.Namespace+"/"+d.Name, "/"))
		}
		at := ""
		if len(where) > 0 {
			at = " " + strings.Join(where, " ") + ":"
		}
		t.line(1, "[%s] %s%s %s", d.Code, d.Stage, at, d.Message)
	}
}
