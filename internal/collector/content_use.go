package collector

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Provider captures and the run's content set (add-assessment-provider-contract
// 3.2). A capture read through ReadCapture uses the run's content in one of
// two roles, decided by its installed provider. The content set itself, its
// frozen copies, leases and failures, stays owned by RunContent and the
// controller that freezes it; a provider never resolves content.

// ContentRole is how a provider's captures use a run's content.
type ContentRole string

const (
	// ContentApplied: the capture's contributions were applied to an
	// engine, and the capture names the bundle (name and manifest digest)
	// each was applied from. The run's content is exactly those bundles;
	// the desired bundle stands in only when nothing was applied, as the
	// content the plan names.
	ContentApplied ContentRole = "Applied"
	// ContentSelected: the provider's checks are reporting-only. Nothing was
	// applied, so the capture names no bundle. Its content is the run's
	// frozen selection: the bundle the binding selected when the run
	// started, frozen then. It has no engine-applied state, and none is
	// recorded for it.
	ContentSelected ContentRole = "Selected"
)

// ContentRoles is the installed compatibility a capture's content role is
// decided against, the provider registry (*provider.Registry).
type ContentRoles interface {
	// ReportingOnly reports whether every check kind the installed provider
	// for contract declares is reporting-only (delivers nothing). It fails
	// for a provider that is not installed and never falls back to another.
	ReportingOnly(contract string) (bool, error)
}

// ContentReference is one applied-content reference of a capture.
type ContentReference struct {
	Ref v1alpha1.BundleReference
	// By is what references it: "subject <engine policy>" or
	// "contribution <policy>".
	By string
}

// ContentUse is the content a capture assesses.
type ContentUse struct {
	Role ContentRole
	// References are the applied-content references in capture order
	// (subjects, then contributions). A ContentSelected use has none.
	References []ContentReference
}

// Bundles are the distinct applied bundles, sorted by manifest digest and
// name. Two names of one digest are two bundles: resolution identity is
// the name and digest, never the digest alone.
func (u ContentUse) Bundles() []v1alpha1.BundleReference {
	out := []v1alpha1.BundleReference{}
	for _, r := range u.References {
		if !slices.Contains(out, r.Ref) {
			out = append(out, r.Ref)
		}
	}
	slices.SortFunc(out, func(a, b v1alpha1.BundleReference) int {
		return strings.Compare(a.Digest+"\x00"+a.Name, b.Digest+"\x00"+b.Name)
	})
	return out
}

// KyvernoContentUse is the applied content of a Kyverno payload 2 capture:
// the bundles its subjects and contributions name.
func KyvernoContentUse(c CaptureV2) ContentUse {
	u := ContentUse{Role: ContentApplied, References: []ContentReference{}}
	for _, s := range c.Subjects {
		u.References = append(u.References, ContentReference{Ref: v1alpha1.BundleReference{Name: s.BundleName, Digest: s.BundleDigest}, By: "subject " + s.EnginePolicy})
	}
	for _, x := range c.Contributions {
		u.References = append(u.References, ContentReference{Ref: v1alpha1.BundleReference{Name: x.BundleName, Digest: x.BundleDigest}, By: "contribution " + x.Policy})
	}
	return u
}

// ContentUse is the content the capture assesses, by its installed
// provider's role:
//
//   - Kyverno payload 2, legacy or envelope, or payload 3: its applied content
//     (KyvernoContentUse).
//   - Kyverno payload 1, the prototype's capture: refused. It predates
//     content sets and is read only against its package's vendored
//     content.
//   - a provider whose check kinds are all reporting-only: ContentSelected.
//   - any other provider: refused. Only the Kyverno payload names applied
//     content, and no other reader of it exists.
//
// Every refusal wraps ErrUnsupportedCapture; no capture is assumed to use
// the desired, vendored or another provider's content.
func (d CaptureDocument) ContentUse(roles ContentRoles) (ContentUse, error) {
	h := d.Header
	if h.Provider == LegacyProvider {
		if !d.Continuous() {
			return ContentUse{}, fmt.Errorf("%w: %s predates run content sets; it is read only against its package's vendored content", ErrUnsupportedCapture, h)
		}
		c, err := d.KyvernoCapture()
		if err != nil {
			return ContentUse{}, err
		}
		return KyvernoContentUse(c), nil
	}
	if roles == nil {
		return ContentUse{}, fmt.Errorf("%w: %s: no installed providers to decide its content with", ErrUnsupportedCapture, h)
	}
	reporting, err := roles.ReportingOnly(h.Provider)
	if err != nil {
		return ContentUse{}, fmt.Errorf("%w: %s: %w", ErrUnsupportedCapture, h, err)
	}
	if !reporting {
		return ContentUse{}, fmt.Errorf("%w: %s: the provider delivers checks, but only %s payload %d names the content they were applied from",
			ErrUnsupportedCapture, h, LegacyProvider, CaptureV2Version)
	}
	return ContentUse{Role: ContentSelected, References: []ContentReference{}}, nil
}

// Resolve returns the members of the run's content set a capture with use
// u is evaluated and exported from. A run-level or member failure is
// returned first, unchanged, so the package is a Diagnostic with its
// reason. Otherwise, by role:
//
//   - ContentApplied: every reference must name an applied member and
//     every applied member must be referenced. It returns the applied
//     members, distinct per bundle name and digest, so overlapping applied
//     revisions keep their own content. When nothing was applied it returns
//     the desired member the plan names.
//   - ContentSelected: the run must have frozen exactly its selection, one
//     member that is not applied and is the desired bundle recorded when
//     the run started. A run with applied content, or with no or another
//     selection, is a mismatch: applied content is never read as a
//     reporting-only selection, and a selection is never invented.
//
// Members are returned in content-set order (by manifest digest). Every
// other problem is a ContentMismatch.
func (rc *RunContent) Resolve(u ContentUse) ([]*ContentMember, error) {
	if f := rc.failure(); f != nil {
		return nil, f
	}
	var out []*ContentMember
	switch u.Role {
	case ContentApplied:
		applied := map[v1alpha1.BundleReference]bool{}
		for _, m := range rc.Members {
			if m.Applied {
				applied[m.Ref] = true
			}
		}
		named := map[v1alpha1.BundleReference]bool{}
		for _, r := range u.References {
			if !applied[r.Ref] {
				return nil, contentFailure(ReasonContentMismatch, "%s references %s@%s, which the run did not freeze", r.By, r.Ref.Name, r.Ref.Digest)
			}
			named[r.Ref] = true
		}
		for ref := range applied {
			if !named[ref] {
				return nil, contentFailure(ReasonContentMismatch, "the run froze %s@%s, but the capture assesses nothing applied from it", ref.Name, ref.Digest)
			}
		}
		for i := range rc.Members {
			if m := &rc.Members[i]; m.Applied || len(applied) == 0 {
				out = append(out, m)
			}
		}
	case ContentSelected:
		if len(u.References) > 0 {
			return nil, contentFailure(ReasonContentMismatch, "a reporting-only capture names no applied content, but this one references %s@%s", u.References[0].Ref.Name, u.References[0].Ref.Digest)
		}
		for _, m := range rc.Members {
			if m.Applied {
				return nil, contentFailure(ReasonContentMismatch, "a reporting-only capture assesses no applied content, but the run froze %s@%s as applied", m.Ref.Name, m.Ref.Digest)
			}
		}
		if len(rc.Members) != 1 {
			return nil, contentFailure(ReasonContentMismatch, "a reporting-only capture is evaluated from exactly one frozen selection; the run froze %d", len(rc.Members))
		}
		m := &rc.Members[0]
		if rc.Desired == nil || *rc.Desired != m.Ref {
			return nil, contentFailure(ReasonContentMismatch, "the run froze %s@%s, which is not the selection it recorded when it started", m.Ref.Name, m.Ref.Digest)
		}
		out = append(out, m)
	default:
		return nil, contentFailure(ReasonContentMismatch, "the capture's content role %q is not supported", u.Role)
	}
	if len(out) == 0 {
		return nil, contentFailure(ReasonContentMismatch, "the run's content set has no content to export")
	}
	return out, nil
}

// PackageContent is the content set of a retained package, read from the
// package alone: every member is the copy packaged under its recorded path,
// never the cache, a registry, the image's vendored content or another
// bundle of the same digest. Replay after cache eviction or source removal
// therefore reads exactly the content the run was exported from.
//
// A package without a content record (a vendored run) returns nil: its
// content is its own content/ tree. Packaged members must verify against
// the descriptor's record (VerifyContent: identity, name and digest);
// otherwise the content is ContentLost. A recorded bundle that was not
// packaged (a Diagnostic package) is a member failure, ContentUnavailable,
// and is never re-resolved.
func PackageContent(dir string, d publication.Descriptor) (*RunContent, error) {
	rec := d.Revisions.Content
	if rec == nil {
		return nil, nil
	}
	if err := VerifyContent(dir, rec); err != nil {
		return nil, contentFailure(ReasonContentLost, "the packaged content does not verify against its record; content is never re-resolved: %v", err)
	}
	rc := &RunContent{}
	if des := rec.Desired; des != nil {
		rc.Desired = &v1alpha1.BundleReference{Name: des.Bundle, Digest: des.ManifestDigest}
		rc.DesiredVendored = des.Vendored
	}
	member := func(r publication.ContentRevision, applied bool) (ContentMember, error) {
		m := ContentMember{Ref: v1alpha1.BundleReference{Name: r.Bundle, Digest: r.ManifestDigest}, Applied: applied, Vendored: r.Vendored}
		if !r.Frozen {
			m.Failure = contentFailure(ReasonContentUnavailable, "%s@%s was not packaged with the run; content is never re-resolved", r.Bundle, r.ManifestDigest)
			return m, nil
		}
		root := filepath.Join(dir, filepath.FromSlash(r.Path))
		if r.Vendored {
			// The vendored content the run packaged, verified by its
			// SHA256SUMS in VerifyContent: never this image's.
			m.Root = root
			return m, nil
		}
		f, err := bundle.ReadFrozen(root)
		if err != nil {
			return m, contentFailure(ReasonContentLost, "the packaged copy of %s@%s no longer verifies: %v", r.Bundle, r.ManifestDigest, err)
		}
		m.Root, m.Frozen = root, f
		return m, nil
	}
	for _, r := range rec.Applied {
		m, err := member(r, true)
		if err != nil {
			return nil, err
		}
		rc.Members = append(rc.Members, m)
	}
	if des := rec.Desired; des != nil && len(rec.Applied) == 0 {
		m, err := member(*des, false)
		if err != nil {
			return nil, err
		}
		rc.Members = append(rc.Members, m)
	}
	return rc, nil
}
