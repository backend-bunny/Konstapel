package coverage

// Scope projection of a report's inputs (add-control-coverage-reporting
// 4.2).
//
// Build and Unavailable project their input before anything else reads it,
// so the JSON, the text and every diagnostic or limitation derived from the
// input see only what the scope may disclose. A namespace report keeps the
// public baseline inventory and authored mappings, the technical evidence
// of its one namespace only when that evidence is verifiably a projection
// to it, and only sanitized supporting context: states, validity and an
// opaque identity, never a document's title, issuer, scope description,
// digest, copy or link.
//
// Any scope kind other than a binding package (or an unpackaged report) is
// projected as a namespace with nothing authorized unless it names exactly
// one namespace.

import (
	"slices"

	"github.com/backend-bunny/Konstapel/internal/collector"
)

// Projections of a report's inputs.
const (
	// ProjectionPlatform: a binding package (or an unpackaged report): the
	// inputs are reported as supplied.
	ProjectionPlatform = "platform"
	// ProjectionNamespace: a namespace package: the inputs are restricted
	// to the one authorized namespace.
	ProjectionNamespace = "namespace"
)

// Scope kinds of a package (publication.ScopeBinding, ScopeNamespace).
const (
	scopeBinding   = "Binding"
	scopeNamespace = "Namespace"
)

// projection is the scope's projection of one report's inputs.
type projection struct {
	kind string
	// namespace is the one authorized namespace UID of a namespace
	// projection; "" authorizes none.
	namespace string
	// withheld: the evidence is not a valid projection to the namespace,
	// so none of it is reported.
	withheld    bool
	limitations []Limitation
}

// project restricts in to what its scope may disclose.
func project(in Input) (Input, projection) {
	if in.Scope.Kind == "" || in.Scope.Kind == scopeBinding {
		return in, projection{kind: ProjectionPlatform}
	}
	p := projection{kind: ProjectionNamespace}
	if in.Scope.Kind == scopeNamespace && len(in.Scope.Namespaces) == 1 && in.Scope.Namespaces[0].UID != "" {
		p.namespace = in.Scope.Namespaces[0].UID
	} else {
		p.limitations = append(p.limitations, *blocking(CodeScopeProjectionInvalid, "", "scope",
			"the report's scope is not one authorized namespace; no technical evidence or supporting context is reported"))
	}
	in.Scope.Namespaces = slices.DeleteFunc(slices.Clone(in.Scope.Namespaces), func(n NamespaceRef) bool { return n.UID != p.namespace })
	if len(in.Scope.Namespaces) == 0 {
		in.Scope.Namespaces = nil
	}
	if in.Evidence != nil && !projectedTo(*in.Evidence, p.namespace) {
		if in.AsOf.IsZero() {
			in.AsOf = in.Evidence.Capture.Window.Closed // the closure time names no namespace
		}
		in.Evidence = nil
		p.withheld = true
		p.limitations = append(p.limitations, *blocking(CodeEvidenceWithheld, "", "technicalEvidence",
			"the technical evidence is not a valid projection to this namespace; none of it is reported here, and the platform report records why"))
	}
	if p.namespace == "" && in.Supporting != nil {
		in.Supporting = &SupportingEvidenceContext{Version: SupportingContextVersion, Integration: IntegrationUnavailable, Reason: "ScopeNotAuthorized"}
	}
	return in, p
}

// projectedTo reports whether ev is verifiably the owner's projection to
// namespace ns: the capture is projected to it and passes the owner's
// independent projection check, every evaluated observation is one of its
// expected observations, and the evaluation's summary counts exactly those.
// The reason for a failure is not kept: it may name another namespace.
func projectedTo(ev Evidence, ns string) bool {
	c := ev.Capture
	if ns == "" || c.Projection == nil || c.Projection.NamespaceUID != ns || collector.ValidateProjection(c) != nil {
		return false
	}
	expected := map[string]bool{}
	for _, e := range c.Expected {
		if e.NamespaceUID != ns {
			return false
		}
		expected[e.Key()] = true
	}
	seen := map[string]bool{}
	var obs []collector.Observation
	for _, o := range ev.Evaluation.Observations {
		if !expected[o.Key] {
			return false
		}
		if !seen[o.Key] {
			seen[o.Key] = true
			obs = append(obs, o)
		}
	}
	e, o := collector.Tally(obs, len(c.Stale))
	return e == ev.Evaluation.Evidence && o == ev.Evaluation.Outcomes
}

// supporting is an entry as the projection may disclose it. A namespace
// sees states, the declared validity, the associated controls and the
// opaque source only: never the private metadata, the registration digest
// or a copy.
func (p projection) supporting(e SupportingEntry) SupportingEntry {
	if p.kind == ProjectionPlatform {
		if e.Document != nil {
			d := *e.Document
			e.Document = &d
		}
		return e
	}
	e.Document = nil
	e.Revision = ""
	e.Access = AccessRestricted
	return e
}

// restrictedMessage is the fixed message of a coverage diagnostic in a
// namespace projection: the caller's detail is not vetted for the scope.
func restrictedMessage(code string) string {
	switch code {
	case CodeContentUnavailable:
		return "the baseline content is not available for this scope; the platform report records why"
	case CodeBaselineNotSelected:
		return "the binding selected no ComplianceProfile when this run started, so it has no baseline"
	case CodeSelectionUnavailable:
		return "the binding profile's selection was not recorded when this run started"
	}
	return "coverage could not be built for this scope; the platform report records why"
}
