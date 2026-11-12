package collector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Diagnostic reasons for content that cannot back an assessment export. A
// run of an OCI bundle never exports OSCAL from any content but its frozen
// bundle; these reasons replace it with an explicit diagnostic.
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
	// ReasonContentMismatch: the capture references a bundle other than the
	// frozen one.
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

// contentFor returns the content set to export from and the root whose
// schemas validate the outputs. For a frozen bundle it also checks that the
// capture assessed exactly that bundle.
func contentFor(req ExportRequest) (assessment.ContentSet, string, error) {
	if req.Bundle == nil {
		return assessment.Shipped, req.Root, nil
	}
	if req.TrustedRoot == "" {
		return assessment.ContentSet{}, "", contentFailure(ReasonContentIncompatible, "no trusted content root is configured to validate frozen bundle content")
	}
	id := req.Bundle.Identity
	if err := captureUses(req.Capture, id.Name, id.Digests.OCI); err != nil {
		return assessment.ContentSet{}, "", err
	}
	for _, p := range trustedSchemas {
		want, err := os.ReadFile(filepath.Join(req.TrustedRoot, filepath.FromSlash(p)))
		if err != nil {
			return assessment.ContentSet{}, "", err
		}
		got, err := os.ReadFile(filepath.Join(req.Root, filepath.FromSlash(p)))
		if err != nil || !bytes.Equal(got, want) {
			return assessment.ContentSet{}, "", contentFailure(ReasonContentIncompatible, "%s@%s: %s is missing or differs from the controller's schema", id.Name, id.Version, p)
		}
	}
	set, err := FrozenContentSet(req.Bundle)
	if err != nil {
		return assessment.ContentSet{}, "", err
	}
	return set, req.TrustedRoot, nil
}

// captureUses requires every subject and contribution of c to name exactly
// bundle name@digest.
func captureUses(c CaptureV2, name, digest string) error {
	check := func(what, n, d string) error {
		if n != name || d != digest {
			return contentFailure(ReasonContentMismatch, "%s references %s@%s, but the run froze %s@%s", what, n, d, name, digest)
		}
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

// contentRevision is the descriptor's record of the run's OCI bundle; nil
// for vendored runs.
func contentRevision(req ExportRequest, kind publication.PackageKind) *publication.ContentRevision {
	if b := req.Bundle; b != nil {
		id := b.Identity
		r := &publication.ContentRevision{Bundle: id.Name, ManifestDigest: id.Digests.OCI, Frozen: kind == publication.KindAssessment,
			Version: id.Version, ContentDigest: id.Digests.Content, ArchiveDigest: id.Digests.Archive, SourceRevision: id.Digests.Revision,
			SourceRule: id.Receipt.SourceRule, TrustRevision: id.Receipt.TrustRevision}
		if !id.Receipt.VerifiedAt.IsZero() {
			at := id.Receipt.VerifiedAt.UTC()
			r.VerifiedAt = &at
		}
		return r
	}
	if ref := req.ContentRef; ref != nil {
		return &publication.ContentRevision{Bundle: ref.Name, ManifestDigest: ref.Digest}
	}
	return nil
}
