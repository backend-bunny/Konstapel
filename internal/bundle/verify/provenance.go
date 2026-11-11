package verify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

// The Konstapel bundle provenance contract (docs/policy-bundles.md, "Bundle
// provenance v1") is a SLSA provenance v1 predicate with a Konstapel build
// type. Field names are SLSA's; the content of externalParameters,
// internalParameters and resolvedDependencies is defined here, because SLSA
// leaves it to each build type and `cosign attest --type slsaprovenance1`
// signs whatever predicate the publisher supplies.
const (
	// ProvenanceBuildType is the only accepted buildDefinition.buildType.
	ProvenanceBuildType = "https://github.com/backend-bunny/Konstapel/blob/main/docs/policy-bundles.md#bundle-provenance-v1"

	// Names of resolvedDependencies entries.
	MaterialSource     = "source"            // the source repository at the content commit
	MaterialDefinition = "bundle-definition" // bundles/<name>/definition.json at that commit
	MaterialContent    = "bundle-content"    // the canonical file inventory of the payload
	MaterialTest       = "test"              // a payload test file the release ran
	MaterialTool       = "tool"              // a build tool and its version

	// URI forms of the checked materials.
	sourceURIPrefix  = "git+"
	contentURIPrefix = "bundle-content:"
	testURIPrefix    = "bundle-file:"

	// Parsing bounds of the predicate.
	MaxPredicateBytes   = 1 << 20
	MaxProvenanceString = 2048
	MaxMaterials        = 1024
)

var (
	commitPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	provenanceVersion = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$`)
)

// Material is one recorded resolvedDependencies entry. Digest is
// "sha256:<hex>", or empty for a tool recorded without a digest.
type Material struct {
	URI    string
	Digest string
}

// Workflow is the pipeline definition that ran the release, recorded apart
// from the content source: a retry from a newer workflow revision packaging an
// older source commit stays distinguishable. It is never a substitute for the
// source commit.
type Workflow struct {
	Repository string
	Path       string
	Ref        string
	Commit     string
}

// VerifiedProvenance is the outcome of checking a verified provenance
// statement against the central rule and the pinned bundle's descriptor. It
// holds public identifiers and digests only.
type VerifiedProvenance struct {
	// Subject is the pinned manifest digest; StatementDigest identifies the
	// signed statement the claims come from.
	Subject         string
	StatementDigest string
	BuildType       string
	Builder         string
	// SourceRepository and SourceRevision are the attested content source.
	SourceRepository string
	SourceRevision   string
	BundleName       string
	BundleVersion    string
	// ContentDigest is the attested canonical inventory digest, equal to the
	// descriptor's ContentDigest.
	ContentDigest string
	// Definition is the recorded bundle definition input (not shipped in the
	// payload, so recorded rather than checked against it).
	Definition Material
	// Tests are the payload test files the release declared it ran; each was
	// checked against the payload inventory.
	Tests []Material
	// Tools are the declared build tools, recorded only.
	Tools []Material
	// Workflow is the release pipeline revision, recorded only.
	Workflow     Workflow
	InvocationID string
}

// predicate is the parsed contract.
type predicate struct {
	buildType                      string
	bundleName, bundleVersion      string
	sourceRepository, sourceCommit string
	workflow                       Workflow
	source, definition, content    *material
	tests, tools                   []material
	builder                        string
	invocationID                   string
	startedOn, finishedOn          string
	builderVersion                 map[string]string
	materialCount                  int
}

type material struct {
	name, uri string
	digest    map[string]string
}

// CheckProvenance applies the provenance policy to proofs verified by
// VerifyProofs: the attestation must follow the Konstapel provenance contract,
// name exactly the pinned subject, have been signed under the same publisher
// rule and trust snapshot as the signature, name the rule's builder and source
// repository, and attest the descriptor's source, release identity and
// content. It reads only the verified statement; it never parses unverified
// bytes. Every failure is fatal and wraps a typed sentinel.
func CheckProvenance(src bundle.BundleSource, d *bundle.Descriptor, pinned string, proofs *Proofs) (*VerifiedProvenance, error) {
	if proofs == nil || proofs.Signature == nil || proofs.Provenance == nil {
		return nil, &registry.MissingProofsError{Digest: pinned, Missing: missingKinds(proofs)}
	}
	if d == nil {
		return nil, fail(ErrProvenanceContract, "no bundle descriptor to check provenance against")
	}
	sig, prov := proofs.Signature, proofs.Provenance
	if err := checkSameSigner(sig, prov); err != nil {
		return nil, err
	}
	// Defensive: VerifyProofs already bound both statements to the subject.
	for _, p := range []*VerifiedProof{sig, prov} {
		if p.Subject != pinned || len(p.Statement.Subjects) != 1 || p.Statement.Subjects[0].Digest != pinned {
			return nil, fail(ErrSubject, "%s proof is for %s, not the pinned %s", p.Kind, p.Subject, pinned)
		}
	}
	if prov.Statement.PredicateType != bundle.PredicateSLSAProvenanceV1 {
		return nil, fail(ErrPredicateType, "provenance predicate type %q", prov.Statement.PredicateType)
	}
	p, err := parsePredicate(prov.Statement.Predicate)
	if err != nil {
		return nil, err
	}

	rule := src.Publisher.Provenance
	if p.builder != rule.Builder {
		return nil, fail(ErrProvenanceBuilder, "builder %q is not the configured %q", p.builder, rule.Builder)
	}

	// Source: the requested release's repository and commit, the source
	// material, the rule and the descriptor must all agree. The workflow
	// revision is never consulted here.
	switch {
	case p.sourceRepository != rule.SourceRepository:
		return nil, fail(ErrProvenanceSource, "source repository %q is not the configured %q", p.sourceRepository, rule.SourceRepository)
	case d.Source.Repository != rule.SourceRepository:
		return nil, fail(ErrProvenanceSource, "the bundle declares source repository %q, the rule allows %q", d.Source.Repository, rule.SourceRepository)
	case p.source.uri != sourceURIPrefix+p.sourceRepository:
		return nil, fail(ErrProvenanceSource, "source material %q is not %s%s", p.source.uri, sourceURIPrefix, p.sourceRepository)
	case p.source.digest["gitCommit"] != p.sourceCommit:
		return nil, fail(ErrProvenanceSource, "source material commit %s differs from the requested commit %s", p.source.digest["gitCommit"], p.sourceCommit)
	case p.sourceCommit != d.Source.Revision:
		return nil, fail(ErrProvenanceSource, "attested source commit %s is not the bundle's source revision %s", p.sourceCommit, d.Source.Revision)
	}

	// Release identity: attestation, descriptor and requested name.
	switch {
	case d.Name != src.Name:
		return nil, fail(ErrProvenanceRelease, "the bundle is named %q, the source serves %q", d.Name, src.Name)
	case p.bundleName != d.Name:
		return nil, fail(ErrProvenanceRelease, "attested bundle %q is not %q", p.bundleName, d.Name)
	case p.bundleVersion != d.Version:
		return nil, fail(ErrProvenanceRelease, "attested version %q is not the bundle's version %q", p.bundleVersion, d.Version)
	}

	// Materials.
	content := d.ContentDigest()
	if got := "sha256:" + p.content.digest["sha256"]; got != content {
		return nil, fail(ErrProvenanceMaterial, "attested content digest %s is not the payload's %s", got, content)
	}
	if want := contentURIPrefix + d.Name + "@" + d.Version; p.content.uri != want {
		return nil, fail(ErrProvenanceMaterial, "content material %q is not %q", p.content.uri, want)
	}
	if want := sourceURIPrefix + d.Source.Repository + "@" + d.Source.Revision + "#bundles/" + d.Name + "/definition.json"; p.definition.uri != want {
		return nil, fail(ErrProvenanceMaterial, "definition material %q is not %q", p.definition.uri, want)
	}
	files := map[string]bundle.File{}
	for _, f := range d.Files {
		files[f.Path] = f
	}
	vp := &VerifiedProvenance{
		Subject: pinned, StatementDigest: prov.StatementDigest, BuildType: p.buildType, Builder: p.builder,
		SourceRepository: p.sourceRepository, SourceRevision: p.sourceCommit,
		BundleName: p.bundleName, BundleVersion: p.bundleVersion, ContentDigest: content,
		Definition: Material{URI: p.definition.uri, Digest: "sha256:" + p.definition.digest["sha256"]},
		Workflow:   p.workflow, InvocationID: p.invocationID,
	}
	for _, t := range p.tests {
		path := strings.TrimPrefix(t.uri, testURIPrefix)
		f, ok := files[path]
		switch {
		case !ok:
			return nil, fail(ErrProvenanceMaterial, "test material %q is not in the payload", path)
		case f.Role != bundle.RoleTest:
			return nil, fail(ErrProvenanceMaterial, "test material %q has payload role %q, not %q", path, f.Role, bundle.RoleTest)
		case f.SHA256 != t.digest["sha256"]:
			return nil, fail(ErrProvenanceMaterial, "test material %q digest differs from the payload", path)
		}
		vp.Tests = append(vp.Tests, Material{URI: t.uri, Digest: "sha256:" + t.digest["sha256"]})
	}
	for _, t := range p.tools {
		m := Material{URI: t.uri}
		if h, ok := t.digest["sha256"]; ok {
			m.Digest = "sha256:" + h
		}
		vp.Tools = append(vp.Tools, m)
	}
	return vp, nil
}

func missingKinds(p *Proofs) []registry.ProofKind {
	var out []registry.ProofKind
	if p == nil || p.Signature == nil {
		out = append(out, registry.ProofSignature)
	}
	if p == nil || p.Provenance == nil {
		out = append(out, registry.ProofProvenance)
	}
	return out
}

// checkSameSigner refuses a signature and an attestation that were not
// verified under the same signer and trust root. VerifyProofs guarantees this
// by construction (one rule, one snapshot); the check keeps a caller that
// combines results of separate calls from mixing publishers.
func checkSameSigner(sig, prov *VerifiedProof) error {
	switch {
	case sig.Kind != registry.ProofSignature || prov.Kind != registry.ProofProvenance:
		return fail(ErrMixedSigner, "proof kinds %q and %q are not a signature and a provenance attestation", sig.Kind, prov.Kind)
	case sig.Signer != prov.Signer:
		return fail(ErrMixedSigner, "the signature and the provenance were verified for different signers")
	case sig.TrustRootID != prov.TrustRootID || sig.TrustRootSource != prov.TrustRootSource:
		return fail(ErrMixedSigner, "the signature and the provenance were verified under different trusted roots")
	case sig.Subject != prov.Subject:
		return fail(ErrMixedSigner, "the signature and the provenance are for different subjects")
	}
	return nil
}

// ---- strict predicate parsing ---------------------------------------------

func contractErr(format string, a ...any) error { return fail(ErrProvenanceContract, format, a...) }

type jsonObject map[string]json.RawMessage

// object decodes raw as a JSON object with exactly the allowed keys (exact
// case: encoding/json would otherwise match struct fields case-insensitively).
func object(raw json.RawMessage, path string, required, optional []string) (jsonObject, error) {
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return nil, contractErr("%s must be an object", path)
	}
	var m jsonObject
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, contractErr("%s: %v", path, err)
	}
	for k := range m {
		if !slices.Contains(required, k) && !slices.Contains(optional, k) {
			return nil, contractErr("%s has unexpected field %q", path, k)
		}
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return nil, contractErr("%s.%s is required", path, k)
		}
	}
	return m, nil
}

// str reads a required non-empty JSON string: no null, number or other
// coercion, bounded, valid UTF-8 without control characters.
func (o jsonObject) str(key, path string) (string, error) {
	raw, ok := o[key]
	if !ok {
		return "", contractErr("%s.%s is required", path, key)
	}
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte(`"`)) {
		return "", contractErr("%s.%s must be a string", path, key)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", contractErr("%s.%s: %v", path, key, err)
	}
	switch {
	case s == "":
		return "", contractErr("%s.%s must not be empty", path, key)
	case len(s) > MaxProvenanceString:
		return "", contractErr("%s.%s exceeds %d bytes", path, key, MaxProvenanceString)
	case !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return "", contractErr("%s.%s contains control characters", path, key)
	}
	return s, nil
}

func (o jsonObject) optStr(key, path string) (string, error) {
	if _, ok := o[key]; !ok {
		return "", nil
	}
	return o.str(key, path)
}

func (o jsonObject) obj(key, path string, required, optional []string) (jsonObject, error) {
	raw, ok := o[key]
	if !ok {
		return nil, contractErr("%s.%s is required", path, key)
	}
	return object(raw, path+"."+key, required, optional)
}

func parsePredicate(raw json.RawMessage) (*predicate, error) {
	if len(raw) > MaxPredicateBytes {
		return nil, fail(ErrProvenanceContract, "predicate exceeds %d bytes", MaxPredicateBytes)
	}
	if err := checkJSON(raw); err != nil {
		return nil, contractErr("predicate: %v", err)
	}
	top, err := object(raw, "predicate", []string{"buildDefinition", "runDetails"}, nil)
	if err != nil {
		return nil, err
	}
	p := &predicate{}

	bd, err := top.obj("buildDefinition", "predicate", []string{"buildType", "externalParameters", "internalParameters", "resolvedDependencies"}, nil)
	if err != nil {
		return nil, err
	}
	if p.buildType, err = bd.str("buildType", "buildDefinition"); err != nil {
		return nil, err
	}
	if p.buildType != ProvenanceBuildType {
		return nil, contractErr("buildType %q is not the Konstapel bundle build type %q", p.buildType, ProvenanceBuildType)
	}

	ext, err := bd.obj("externalParameters", "buildDefinition", []string{"bundle", "source"}, nil)
	if err != nil {
		return nil, err
	}
	b, err := ext.obj("bundle", "externalParameters", []string{"name", "version"}, nil)
	if err != nil {
		return nil, err
	}
	if p.bundleName, err = b.str("name", "externalParameters.bundle"); err != nil {
		return nil, err
	}
	if p.bundleVersion, err = b.str("version", "externalParameters.bundle"); err != nil {
		return nil, err
	}
	if !provenanceVersion.MatchString(p.bundleVersion) {
		return nil, contractErr("externalParameters.bundle.version %q is not SemVer", p.bundleVersion)
	}
	s, err := ext.obj("source", "externalParameters", []string{"repository", "commit"}, nil)
	if err != nil {
		return nil, err
	}
	if p.sourceRepository, err = s.str("repository", "externalParameters.source"); err != nil {
		return nil, err
	}
	if p.sourceCommit, err = s.str("commit", "externalParameters.source"); err != nil {
		return nil, err
	}
	if !commitPattern.MatchString(p.sourceCommit) {
		return nil, contractErr("externalParameters.source.commit must be a full 40-character lowercase commit")
	}

	in, err := bd.obj("internalParameters", "buildDefinition", []string{"workflow"}, nil)
	if err != nil {
		return nil, err
	}
	wf, err := in.obj("workflow", "internalParameters", []string{"repository", "path", "commit"}, []string{"ref"})
	if err != nil {
		return nil, err
	}
	for _, f := range []struct {
		key string
		out *string
	}{{"repository", &p.workflow.Repository}, {"path", &p.workflow.Path}, {"commit", &p.workflow.Commit}} {
		if *f.out, err = wf.str(f.key, "internalParameters.workflow"); err != nil {
			return nil, err
		}
	}
	if p.workflow.Ref, err = wf.optStr("ref", "internalParameters.workflow"); err != nil {
		return nil, err
	}
	if !commitPattern.MatchString(p.workflow.Commit) {
		return nil, contractErr("internalParameters.workflow.commit must be a full 40-character lowercase commit")
	}

	if err := p.parseMaterials(bd["resolvedDependencies"]); err != nil {
		return nil, err
	}

	rd, err := top.obj("runDetails", "predicate", []string{"builder"}, []string{"metadata"})
	if err != nil {
		return nil, err
	}
	bl, err := rd.obj("builder", "runDetails", []string{"id"}, []string{"version"})
	if err != nil {
		return nil, err
	}
	if p.builder, err = bl.str("id", "runDetails.builder"); err != nil {
		return nil, err
	}
	if v, ok := bl["version"]; ok {
		if err := stringMap(v, "runDetails.builder.version", &p.builderVersion); err != nil {
			return nil, err
		}
	}
	if _, ok := rd["metadata"]; ok {
		md, err := rd.obj("metadata", "runDetails", nil, []string{"invocationId", "startedOn", "finishedOn"})
		if err != nil {
			return nil, err
		}
		if p.invocationID, err = md.optStr("invocationId", "runDetails.metadata"); err != nil {
			return nil, err
		}
		for _, k := range []struct {
			key string
			out *string
		}{{"startedOn", &p.startedOn}, {"finishedOn", &p.finishedOn}} {
			if *k.out, err = md.optStr(k.key, "runDetails.metadata"); err != nil {
				return nil, err
			}
			if *k.out != "" {
				if _, err := time.Parse(time.RFC3339, *k.out); err != nil {
					return nil, contractErr("runDetails.metadata.%s is not an RFC 3339 time", k.key)
				}
			}
		}
	}
	return p, nil
}

// stringMap decodes an object whose values are all non-empty strings.
func stringMap(raw json.RawMessage, path string, out *map[string]string) error {
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return contractErr("%s must be an object of strings", path)
	}
	var o jsonObject
	if err := json.Unmarshal(raw, &o); err != nil {
		return contractErr("%s: %v", path, err)
	}
	*out = map[string]string{}
	for k := range o {
		v, err := o.str(k, path)
		if err != nil {
			return err
		}
		(*out)[k] = v
	}
	return nil
}

// parseMaterials parses resolvedDependencies: exactly one source, definition
// and content material, any number of tests, at least one tool, nothing else.
func (p *predicate) parseMaterials(raw json.RawMessage) error {
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) {
		return contractErr("buildDefinition.resolvedDependencies must be a list")
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		return contractErr("buildDefinition.resolvedDependencies: %v", err)
	}
	if len(list) > MaxMaterials {
		return contractErr("more than %d resolvedDependencies", MaxMaterials)
	}
	p.materialCount = len(list)
	seen := map[string]bool{}
	for i, r := range list {
		path := fmt.Sprintf("resolvedDependencies[%d]", i)
		o, err := object(r, path, []string{"name", "uri"}, []string{"digest"})
		if err != nil {
			return err
		}
		var m material
		if m.name, err = o.str("name", path); err != nil {
			return err
		}
		if m.uri, err = o.str("uri", path); err != nil {
			return err
		}
		if d, ok := o["digest"]; ok {
			if err := stringMap(d, path+".digest", &m.digest); err != nil {
				return err
			}
		}
		if seen[m.name+"\x00"+m.uri] {
			return contractErr("%s repeats material %s %q", path, m.name, m.uri)
		}
		seen[m.name+"\x00"+m.uri] = true
		one := func(slot **material) error {
			if *slot != nil {
				return contractErr("%s: more than one %q material", path, m.name)
			}
			*slot = &m
			return nil
		}
		switch m.name {
		case MaterialSource:
			if err := digestSet(m, "gitCommit", commitPattern, path); err != nil {
				return err
			}
			if err := one(&p.source); err != nil {
				return err
			}
		case MaterialDefinition:
			if err := digestSet(m, "sha256", hexDigest, path); err != nil {
				return err
			}
			if err := one(&p.definition); err != nil {
				return err
			}
		case MaterialContent:
			if err := digestSet(m, "sha256", hexDigest, path); err != nil {
				return err
			}
			if err := one(&p.content); err != nil {
				return err
			}
		case MaterialTest:
			if err := digestSet(m, "sha256", hexDigest, path); err != nil {
				return err
			}
			if !strings.HasPrefix(m.uri, testURIPrefix) {
				return contractErr("%s: test uri %q must start with %q", path, m.uri, testURIPrefix)
			}
			p.tests = append(p.tests, m)
		case MaterialTool:
			if m.digest != nil {
				if err := digestSet(m, "sha256", hexDigest, path); err != nil {
					return err
				}
			}
			p.tools = append(p.tools, m)
		default:
			return contractErr("%s: unknown material name %q", path, m.name)
		}
	}
	switch {
	case p.source == nil:
		return contractErr("resolvedDependencies has no %q material", MaterialSource)
	case p.definition == nil:
		return contractErr("resolvedDependencies has no %q material", MaterialDefinition)
	case p.content == nil:
		return contractErr("resolvedDependencies has no %q material", MaterialContent)
	case len(p.tools) == 0:
		return contractErr("resolvedDependencies has no %q material", MaterialTool)
	}
	return nil
}

// digestSet requires a digest set of exactly one algorithm with a valid value.
func digestSet(m material, algo string, pattern *regexp.Regexp, path string) error {
	if len(m.digest) != 1 {
		return contractErr("%s: digest must hold exactly one %s value", path, algo)
	}
	v, ok := m.digest[algo]
	if !ok || !pattern.MatchString(v) {
		return contractErr("%s: digest must be a lowercase %s", path, algo)
	}
	return nil
}
