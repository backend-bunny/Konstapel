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

	"github.com/backend-bunny/Konstapel/internal/provider/projection"
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
