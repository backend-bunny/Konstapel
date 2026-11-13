package collector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Diagnostic reasons for content that cannot back an assessment export. A
// run that is not purely vendored never exports OSCAL from any content but
// its own content set (each applied bundle's frozen copy); these reasons
// replace it with an explicit diagnostic.
const (
	// ReasonContentUnavailable: the run's bundle could not be resolved and
	// frozen when the run started or while it collected (not configured,
	// untrusted, incompatible, missing from cache and registry, ...).
	ReasonContentUnavailable = "ContentUnavailable"
	// ReasonContentLost: the frozen copy was lost or no longer verifies
	// before export; it is never re-resolved under later configuration.
	ReasonContentLost = "ContentLost"
	// ReasonContentIncompatible: the frozen bundle cannot be exported by this
	// controller (different OSCAL schemas, no component definition, ...).
	ReasonContentIncompatible = "ContentIncompatible"
	// ReasonContentMismatch: the capture references a bundle the run did
	// not freeze, or the run froze an applied bundle the capture does not
	// assess.
	ReasonContentMismatch = "ContentMismatch"
)

// ContentFailure is a content problem that makes a run's package a
// Diagnostic with Reason.
type ContentFailure struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func (c *ContentFailure) Error() string { return c.Reason + ": " + c.Message }

func contentFailure(reason, format string, a ...any) *ContentFailure {
	return &ContentFailure{Reason: reason, Message: fmt.Sprintf(format, a...)}
}

// trustedSchemas are the OSCAL schemas a frozen bundle must carry
// byte-identical to the image's own: they validate the bundle's documents
// and every exported document, here and in every downstream verifier that
// reads them from the package.
var trustedSchemas = []string{"content/schemas/oscal-1.1.3.json", "content/schemas/oscal-1.2.3.json"}

// RunContent is the content set of a run that is not purely vendored
// (see publication.RunContent): one member per applied bundle, or the
// desired bundle alone when nothing was applied. Desired is recorded beside
// the members and never stands in for them.
type RunContent struct {
	Desired *v1alpha1.BundleReference
	// DesiredVendored marks Desired as the image's vendored bundle.
	DesiredVendored bool
	// Members are sorted by manifest digest.
	Members []ContentMember
	// Failure is a run-level content failure (an unreadable content
	// record). It, or any member's failure, makes the package a Diagnostic.
	Failure *ContentFailure
}

// ContentMember is one bundle of a run's content set.
type ContentMember struct {
	Ref v1alpha1.BundleReference
	// Applied: contributions the run assesses were applied from it.
	// Otherwise it is the desired bundle the plan names (nothing applied).
	Applied bool
	// Vendored: the image's vendored content tree at Root (Shipped set).
	Vendored bool
	// Root is the member's content root: its frozen directory (Frozen set),
	// or the image's content root for the vendored member. Empty on failure.
	Root   string
	Frozen *bundle.Frozen
	// Failure is why the member's content is unavailable or lost.
	Failure *ContentFailure
}

// Path is the member's package directory.
func (m ContentMember) Path() string { return publication.ContentPath(m.Ref.Digest) }

// failure is the run's content failure: the run-level one, or every
// failed member's, reported under the first member's reason.
func (rc *RunContent) failure() *ContentFailure {
	if rc.Failure != nil {
		return rc.Failure
	}
	var first *ContentFailure
	var msgs []string
	for _, m := range rc.Members {
		if m.Failure == nil {
			continue
		}
		if first == nil {
			first = m.Failure
		}
		msgs = append(msgs, m.Failure.Message)
	}
	if first == nil {
		return nil
	}
	return &ContentFailure{Reason: first.Reason, Message: strings.Join(msgs, "; ")}
}

// memberContent returns a member's content set and checks that a frozen
// bundle carries the controller's own OSCAL schemas.
func memberContent(m ContentMember, trustedRoot string) (assessment.ContentSet, error) {
	if m.Vendored {
		return assessment.Shipped, nil
	}
	id := m.Frozen.Identity
	for _, p := range trustedSchemas {
		want, err := os.ReadFile(filepath.Join(trustedRoot, filepath.FromSlash(p)))
		if err != nil {
			return assessment.ContentSet{}, err
		}
		got, err := os.ReadFile(filepath.Join(m.Root, filepath.FromSlash(p)))
		if err != nil || !bytes.Equal(got, want) {
			return assessment.ContentSet{}, contentFailure(ReasonContentIncompatible, "%s@%s: %s is missing or differs from the controller's schema", id.Name, id.Version, p)
		}
	}
	return FrozenContentSet(m.Frozen)
}

// captureUses requires every subject and contribution of c to name an
// applied member, and every applied member to be named by one: the run's
// content is exactly the content its contributions were applied from.
func captureUses(c CaptureV2, applied map[v1alpha1.BundleReference]bool) error {
	named := map[v1alpha1.BundleReference]bool{}
	check := func(what, n, d string) error {
		ref := v1alpha1.BundleReference{Name: n, Digest: d}
		if !applied[ref] {
			return contentFailure(ReasonContentMismatch, "%s references %s@%s, which the run did not freeze", what, n, d)
		}
		named[ref] = true
		return nil
	}
	for _, s := range c.Subjects {
		if err := check("subject "+s.EnginePolicy, s.BundleName, s.BundleDigest); err != nil {
			return err
		}
	}
	for _, x := range c.Contributions {
		if err := check("contribution "+x.Policy, x.BundleName, x.BundleDigest); err != nil {
			return err
		}
	}
	for ref := range applied {
		if !named[ref] {
			return contentFailure(ReasonContentMismatch, "the run froze %s@%s, but the capture assesses nothing applied from it", ref.Name, ref.Digest)
		}
	}
	return nil
}

// FrozenContentSet is a frozen bundle's content set: the component
// definitions it declares as OSCAL entry points, in declaration order, and
// each declared check's policy manifest.
func FrozenContentSet(f *bundle.Frozen) (assessment.ContentSet, error) {
	d := f.Descriptor
	set := assessment.ContentSet{Policies: map[string]string{}}
	for _, o := range d.OSCAL {
		raw, err := fs.ReadFile(f.Payload, o.Path)
		if err != nil {
			return set, contentFailure(ReasonContentIncompatible, "%s@%s: %s: %v", d.Name, d.Version, o.Path, err)
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(raw, &doc); err != nil {
			return set, contentFailure(ReasonContentIncompatible, "%s@%s: %s is not an OSCAL document", d.Name, d.Version, o.Path)
		}
		if _, ok := doc["component-definition"]; ok {
			set.Definitions = append(set.Definitions, o.Path)
		}
	}
	for _, p := range d.Policies {
		for _, c := range p.Checks {
			set.Policies[c.RuleID] = p.Path
		}
	}
	if len(set.Definitions) == 0 {
		return set, contentFailure(ReasonContentIncompatible, "%s@%s declares no component definition", d.Name, d.Version)
	}
	return set, nil
}

// contentRevision is the descriptor's record of the run's content set; nil
// for vendored runs. Members are packaged (Frozen, with their path) only
// in an assessment package.
func contentRevision(req ExportRequest, kind publication.PackageKind) *publication.RunContent {
	rc := req.Content
	if rc == nil {
		return nil
	}
	out := &publication.RunContent{Applied: []publication.ContentRevision{}}
	var plan *publication.ContentRevision
	for _, m := range rc.Members {
		r := publication.ContentRevision{Bundle: m.Ref.Name, ManifestDigest: m.Ref.Digest, Vendored: m.Vendored}
		if kind == publication.KindAssessment {
			r.Frozen, r.Path = true, m.Path()
		}
		if f := m.Frozen; f != nil {
			id := f.Identity
			r.Version, r.ContentDigest, r.ArchiveDigest, r.SourceRevision = id.Version, id.Digests.Content, id.Digests.Archive, id.Digests.Revision
			r.SourceRule, r.TrustRevision = id.Receipt.SourceRule, id.Receipt.TrustRevision
			if !id.Receipt.VerifiedAt.IsZero() {
				at := id.Receipt.VerifiedAt.UTC()
				r.VerifiedAt = &at
			}
		}
		if m.Applied {
			out.Applied = append(out.Applied, r)
		} else {
			plan = &r
		}
	}
	if d := rc.Desired; d != nil {
		if plan != nil && plan.Bundle == d.Name && plan.ManifestDigest == d.Digest {
			out.Desired = plan
		} else {
			out.Desired = &publication.ContentRevision{Bundle: d.Name, ManifestDigest: d.Digest, Vendored: rc.DesiredVendored}
		}
	}
	out.Differences = publication.ContentDifferences(out.Applied, out.Desired)
	return out
}
