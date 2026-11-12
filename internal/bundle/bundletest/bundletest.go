// Package bundletest builds OCI bundles whose OSCAL content deliberately
// differs from the vendored content, for tests that must prove a consumer
// used a bundle's own catalog and mappings rather than substituting the
// image's vendored content. Only tests import it.
package bundletest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing/fstest"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// Markers that exist only in the crafted bundle. A consumer that falls back
// to vendored content cannot produce them.
const (
	// Name and Version identify the crafted bundle.
	Name    = "konstapel-privileged-containers"
	Version = "0.9.0"
	// Control and Statement are the crafted mapping of the privileged
	// container check (vendored content maps it to ac-6/ac-6_smt).
	Control   = "cm-7"
	Statement = "cm-7_smt.b"
	// Rationale is the crafted Rule_Description.
	Rationale = "CRAFTED-BUNDLE-MAPPING: prohibiting privileged containers restricts unneeded functions (partial cm-7.b evidence only)."
	// CatalogTitle replaces the catalog's metadata title.
	CatalogTitle = "CRAFTED-BUNDLE-CATALOG: NIST SP 800-53 Rev 5 as shipped in the crafted bundle"
	// VendoredStatement is what the vendored content maps the check to.
	VendoredStatement = "ac-6_smt"
)

const catalogPath = assessment.NIST + "NIST_SP-800-53_rev5_catalog.json"
const profilePath = assessment.NIST + "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"

// Options adjust the crafted bundle.
type Options struct {
	// Version defaults to Version.
	Version string
	// Schema113 replaces the packaged OSCAL 1.1.3 schema bytes when set.
	Schema113 []byte
}

// Differing builds a valid bundle (it passes bundle.ValidateContent) around
// the repository's privileged-container policy whose component definition
// maps the check to Control/Statement with Rationale and whose catalog
// carries CatalogTitle. repo is the repository root.
func Differing(repo string, o Options) (*bundle.Archive, error) {
	read := func(p string) ([]byte, error) { return os.ReadFile(filepath.Join(repo, filepath.FromSlash(p))) }
	src := fstest.MapFS{}
	add := func(from string, data []byte) { src[from] = &fstest.MapFile{Data: data} }
	for _, p := range []string{assessment.SourcePolicy, profilePath, "content/schemas/oscal-1.1.3.json", "content/schemas/oscal-1.2.3.json",
		"content/provenance.json", "content/upstream/nist/LICENSE.md", "content/upstream/kyverno/LICENSE", "LICENSE"} {
		b, err := read(p)
		if err != nil {
			return nil, err
		}
		add(p, b)
	}
	if o.Schema113 != nil {
		add("content/schemas/oscal-1.1.3.json", o.Schema113)
	}
	catalog, err := read(catalogPath)
	if err != nil {
		return nil, err
	}
	var c map[string]any
	if err := json.Unmarshal(catalog, &c); err != nil {
		return nil, err
	}
	assessment.Map(assessment.At(c, "catalog", "metadata"))["title"] = CatalogTitle
	if catalog, err = json.MarshalIndent(c, "", "  "); err != nil {
		return nil, err
	}
	add(catalogPath, catalog)

	cd, err := read("content/component-definition.json")
	if err != nil {
		return nil, err
	}
	vendoredDesc := "Partial AC-6 technical evidence: prohibiting privileged containers reduces unnecessary process privileges; does not assess authorization, all process privileges, organizational procedures, or full AC-6/Moderate satisfaction."
	if !bytes.Contains(cd, []byte(vendoredDesc)) || !bytes.Contains(cd, []byte(`"control-id": "ac-6"`)) || !bytes.Contains(cd, []byte(`"statement-id": "ac-6_smt"`)) {
		return nil, fmt.Errorf("vendored component definition changed; update bundletest")
	}
	s := strings.ReplaceAll(string(cd), vendoredDesc, Rationale)
	s = strings.Replace(s, `"control-id": "ac-6"`, `"control-id": "`+Control+`"`, 1)
	s = strings.Replace(s, `"statement-id": "ac-6_smt"`, `"statement-id": "`+Statement+`"`, 1)
	s = strings.Replace(s, `"title": "Konstapel privileged-container check"`, `"title": "Crafted privileged-container mapping"`, 1)
	add("content/component-definition.json", []byte(s))

	version := o.Version
	if version == "" {
		version = Version
	}
	def := bundle.Definition{
		Name: Name, Version: version,
		Source: bundle.Source{Repository: "https://github.com/backend-bunny/Konstapel", Revision: strings.Repeat("d", 40)},
		Policies: []bundle.Policy{{Name: assessment.PolicyName, Path: assessment.SourcePolicy,
			Checks: []bundle.Check{{RuleID: assessment.PolicyName, CheckID: assessment.PolicyName}}}},
		Scope:         bundle.Scope{Workloads: []string{"Pod", "Deployment"}, OS: []string{"linux"}},
		Compatibility: bundle.Compatibility{Provider: "konstapel-kyverno/v1", Konstapel: "0.1.0"},
		OSCAL: []bundle.OSCALDocument{{Path: "content/component-definition.json", Version: "1.1.3"},
			{Path: catalogPath, Version: "1.2.3"}, {Path: profilePath, Version: "1.2.3"}},
		Include: []bundle.Include{
			{From: assessment.SourcePolicy, To: assessment.SourcePolicy, Role: bundle.RolePolicy},
			{From: "content/component-definition.json", To: "content/component-definition.json", Role: bundle.RoleComponentDefinition},
			{From: "content/provenance.json", To: "content/provenance.json", Role: bundle.RoleProvenance},
			{Generate: bundle.GenerateSHA256Sums, To: "content/SHA256SUMS", Role: bundle.RoleChecksums},
			{From: "content/schemas/oscal-1.1.3.json", To: "content/schemas/oscal-1.1.3.json", Role: bundle.RoleSchema},
			{From: "content/schemas/oscal-1.2.3.json", To: "content/schemas/oscal-1.2.3.json", Role: bundle.RoleSchema},
			{From: catalogPath, To: catalogPath, Role: bundle.RoleUpstream},
			{From: profilePath, To: profilePath, Role: bundle.RoleUpstream},
			{From: "content/upstream/nist/LICENSE.md", To: "content/upstream/nist/LICENSE.md", Role: bundle.RoleLicense},
			{From: "content/upstream/kyverno/LICENSE", To: "content/upstream/kyverno/LICENSE", Role: bundle.RoleLicense},
			{From: "LICENSE", To: "LICENSE", Role: bundle.RoleLicense},
		},
	}
	return bundle.Build(def, src, time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC))
}

// Identity is the frozen identity of a crafted archive, with a synthetic
// verification receipt naming the given source rule and trust revision.
func Identity(a *bundle.Archive, sourceRule, trustRevision string, verifiedAt time.Time) bundle.FrozenIdentity {
	d := a.Descriptor
	id := bundle.FrozenIdentity{FrozenVersion: bundle.FrozenVersion, Name: d.Name, Version: d.Version, Source: d.Source,
		Digests: bundle.Digests{Revision: d.Source.Revision, Content: d.ContentDigest(), Archive: a.LayerDigest, OCI: a.ManifestDigest}}
	id.Receipt.Version = bundle.HandleVersion
	id.Receipt.VerifiedAt = verifiedAt
	id.Receipt.SourceRule, id.Receipt.TrustRevision = sourceRule, trustRevision
	id.Receipt.Subject.Name, id.Receipt.Subject.Version, id.Receipt.Subject.Digest = d.Name, d.Version, a.ManifestDigest
	return id
}
