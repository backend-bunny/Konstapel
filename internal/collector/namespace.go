package collector

// Namespace projection across providers (add-assessment-provider-contract
// 3.3). The provider-neutral scope, shared check and extractor interface
// are package projection's. This file dispatches a capture to its
// provider's extraction. Kyverno payload 2 is the collector's own payload:
// Project and ProjectReports extract it, and ValidateProjection checks it
// with Kyverno's field allowlist and then projection.Check. A payload
// without an installed extractor has no namespace packages. Its capture is
// refused, never disclosed unprojected.

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/backend-bunny/Konstapel/internal/provider/projection"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// ErrNamespaceProjection marks a capture that has no namespace projection:
// no installed extractor reads its payload, or the scope to project to is
// not one namespace instance.
var ErrNamespaceProjection = errors.New("the capture cannot be projected to a namespace")

// PayloadRef names one provider payload version.
type PayloadRef struct {
	Provider string
	Version  int
}

// NamespaceExtractors are the extractors of installed providers' payloads.
// Kyverno payload 2 is the collector's own and needs no entry. Production
// installs none, so every other provider's capture has no namespace
// package.
type NamespaceExtractors map[PayloadRef]projection.Extractor

// ProjectNamespace returns the capture's extract for ns, with the same
// header. The extract is checked by projection.Check before it is
// returned.
//
// A Kyverno payload 2 capture is projected by Project and checked by
// ValidateProjection. Its extract keeps the header, and V2 returns the
// projected capture. Any other payload is projected by its extractor in
// others. A payload without one is refused (ErrNamespaceProjection), and so
// is a Kyverno version 1 capture, which predates namespace projection.
func (d CaptureDocument) ProjectNamespace(ns projection.Scope, others NamespaceExtractors) (CaptureDocument, error) {
	if ns.UID == "" {
		return CaptureDocument{}, fmt.Errorf("%w: the scope names no namespace instance", ErrNamespaceProjection)
	}
	if d.kyverno() {
		c, err := d.V2()
		if err != nil {
			return CaptureDocument{}, err
		}
		p, err := Project(c, ns.UID)
		if err != nil {
			return CaptureDocument{}, err
		}
		if err := validateNamespaceV2(p, ns); err != nil {
			return CaptureDocument{}, err
		}
		raw, err := json.Marshal(p)
		if err != nil {
			return CaptureDocument{}, err
		}
		return CaptureDocument{Header: d.Header, Payload: raw, v2: &p}, nil
	}
	x, err := d.extractor(others)
	if err != nil {
		return CaptureDocument{}, err
	}
	raw, err := x.Extract(d.Payload, ns)
	if err != nil {
		return CaptureDocument{}, fmt.Errorf("%w: %s: %w", ErrNamespaceProjection, d.Header, err)
	}
	out := CaptureDocument{Header: d.Header, Payload: raw}
	if err := checkExtract(x, out, ns); err != nil {
		return CaptureDocument{}, err
	}
	return out, nil
}

// ValidateNamespace checks that the capture is an extract for ns, so it
// may be disclosed in that namespace's package. A Kyverno payload 2 capture
// must be a projection to ns that ValidateProjection accepts. Any other
// payload is read back by its extractor in others and checked by
// projection.Check. A payload without an extractor is refused.
func (d CaptureDocument) ValidateNamespace(ns projection.Scope, others NamespaceExtractors) error {
	if ns.UID == "" {
		return fmt.Errorf("%w: the scope names no namespace instance", ErrNamespaceProjection)
	}
	if d.kyverno() {
		c, err := d.V2()
		if err != nil {
			return err
		}
		return validateNamespaceV2(c, ns)
	}
	x, err := d.extractor(others)
	if err != nil {
		return err
	}
	return checkExtract(x, d, ns)
}

// kyverno reports whether the capture is the collector's own Kyverno
// payload 2.
func (d CaptureDocument) kyverno() bool {
	return d.Header.Provider == LegacyProvider && d.Header.PayloadVersion == CaptureV2Version
}

func (d CaptureDocument) extractor(others NamespaceExtractors) (projection.Extractor, error) {
	x := others[PayloadRef{Provider: d.Header.Provider, Version: d.Header.PayloadVersion}]
	if x == nil {
		return nil, fmt.Errorf("%w: %s: no installed extractor reads this payload, so it is never disclosed in a namespace package", ErrNamespaceProjection, d.Header)
	}
	return x, nil
}

func checkExtract(x projection.Extractor, d CaptureDocument, ns projection.Scope) error {
	items, err := x.Disclosures(d.Payload)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", projection.ErrDisclosure, d.Header, err)
	}
	if err := projection.Check(ns, items); err != nil {
		return fmt.Errorf("%s: %w", d.Header, err)
	}
	return nil
}

// validateNamespaceV2 checks a Kyverno projection against the scope it is
// disclosed in.
func validateNamespaceV2(c CaptureV2, ns projection.Scope) error {
	if err := ValidateProjection(c); err != nil {
		return fmt.Errorf("%w: %w", projection.ErrDisclosure, err)
	}
	if p := c.Projection; p.NamespaceUID != ns.UID || ns.Name != "" && p.Namespace != ns.Name {
		return fmt.Errorf("%w: the projection is to another namespace than its scope", projection.ErrDisclosure)
	}
	return nil
}

// namespaceDiagnostics are the only diagnostic texts a namespace package
// carries, one per stable reason code (owner decision 2026-11-27). A
// content failure's own message names the binding's bundles, digests and
// subjects and wraps raw registry, engine and schema errors, so it stays on
// the platform-scoped run and its binding package.
var namespaceDiagnostics = map[string]string{
	ReasonContentUnavailable:  "the run's assessment content was unavailable, so no assessment results were produced",
	ReasonContentLost:         "the run's frozen assessment content was lost before export, so no assessment results were produced",
	ReasonContentIncompatible: "the run's assessment content cannot be exported by this controller, so no assessment results were produced",
	ReasonContentMismatch:     "the run's assessment content does not match its evidence, so no assessment results were produced",
	ReasonExportFailed:        "the evidence package could not be produced",
}

// ReasonExportFailed is the diagnostic reason of an export that failed for
// any reason but content.
const ReasonExportFailed = "ExportFailed"

// NamespaceDiagnostic is the diagnostic a namespace package records for a
// failure with reason: the reason when it is one of the stable codes
// (ReasonExportFailed otherwise) and that code's fixed text, never the
// failure's own message.
func NamespaceDiagnostic(reason string) *publication.Diagnostic {
	if _, ok := namespaceDiagnostics[reason]; !ok {
		reason = ReasonExportFailed
	}
	return &publication.Diagnostic{Reason: reason, MissingExports: []publication.FileRole{publication.RoleAssessmentResults}, Message: namespaceDiagnostics[reason]}
}

// ValidateNamespaceDiagnostic checks that a namespace package's diagnostic,
// if it has one, is exactly NamespaceDiagnostic of its reason. The refusal
// never repeats the diagnostic's text.
func ValidateNamespaceDiagnostic(d *publication.Diagnostic) error {
	if d == nil {
		return nil
	}
	want := NamespaceDiagnostic(d.Reason)
	if d.Reason != want.Reason || d.Message != want.Message || !slices.Equal(d.MissingExports, want.MissingExports) {
		return fmt.Errorf("%w: the diagnostic is not the fixed text of a stable reason", projection.ErrDisclosure)
	}
	return nil
}
