// Package bundle defines Konstapel's policy bundle payload contract: the
// versioned bundle.json descriptor, its file inventory, and the OCI manifest
// shape that carries it. OCI supplies distribution and OSCAL supplies the
// compliance document formats; the payload layout is a Konstapel contract.
//
// The enclosing OCI digest authenticates bundle.json, so the descriptor never
// carries a checksum of itself.
package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	// FormatV1 is the only supported descriptor format.
	FormatV1 = "konstapel.policy.bundle/v1"
	// DescriptorPath is the fixed location of the descriptor in the archive.
	DescriptorPath = "bundle.json"
	// ArtifactType is the OCI artifact type of a bundle manifest.
	ArtifactType = "application/vnd.konstapel.policy.bundle.v1+json"
	// LayerMediaType is the single deterministic filesystem layer.
	LayerMediaType = "application/vnd.oci.image.layer.v1.tar+gzip"
	// EmptyConfigMediaType and EmptyConfigDigest identify the OCI empty config.
	EmptyConfigMediaType = "application/vnd.oci.empty.v1+json"
	EmptyConfigDigest    = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	manifestMediaType    = "application/vnd.oci.image.manifest.v1+json"
)

// Roles classify payload files. Every inventoried file has exactly one.
const (
	RoleComponentDefinition = "component-definition"
	RoleUpstream            = "upstream"
	RolePolicy              = "policy"
	RoleSchema              = "schema"
	RoleProvenance          = "provenance"
	RoleChecksums           = "checksums"
	RoleTest                = "test"
	RoleLicense             = "license"
)

var roles = map[string]bool{
	RoleComponentDefinition: true, RoleUpstream: true, RolePolicy: true, RoleSchema: true,
	RoleProvenance: true, RoleChecksums: true, RoleTest: true, RoleLicense: true,
}

// Source identifies the immutable origin of the bundle contents.
type Source struct {
	Repository string `json:"repository"`
	Revision   string `json:"revision"`
}

// Check is a logical check provided by a policy. IDs follow the C2P
// Rule_Id/Check_Id convention and are never renamed by the bundle.
type Check struct {
	RuleID  string `json:"ruleID"`
	CheckID string `json:"checkID"`
}

// Policy is a logical policy in the bundle inventory. Path names the policy
// source file; it is recorded rather than inferred from its filename.
type Policy struct {
	Name   string  `json:"name"`
	Path   string  `json:"path"`
	Checks []Check `json:"checks"`
	// ParameterSchema is the path of the policy's parameter schema, if any.
	ParameterSchema string `json:"parameterSchema,omitempty"`
}

// Scope bounds where the bundle's policies apply.
type Scope struct {
	Workloads []string `json:"workloads"`
	OS        []string `json:"os"`
}

// Compatibility states the platform contract the content requires.
type Compatibility struct {
	// Provider is the policy provider contract, e.g. "kyverno/v1".
	Provider string `json:"provider"`
	// Konstapel is a minimum Konstapel release (SemVer).
	Konstapel string `json:"konstapel"`
}

// OSCALDocument is a declared OSCAL entry point and its OSCAL version.
type OSCALDocument struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

// File is one inventoried payload file.
type File struct {
	Path   string `json:"path"`
	Role   string `json:"role"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Descriptor is the decoded bundle.json.
type Descriptor struct {
	Format        string          `json:"format"`
	Name          string          `json:"name"`
	Version       string          `json:"version"`
	Source        Source          `json:"source"`
	Policies      []Policy        `json:"policies"`
	Scope         Scope           `json:"scope"`
	Compatibility Compatibility   `json:"compatibility"`
	OSCAL         []OSCALDocument `json:"oscal"`
	Files         []File          `json:"files"`
}

var (
	namePattern    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	semverPattern  = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	revisionPat    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	oscalVerPat    = regexp.MustCompile(`^1\.\d+\.\d+$`)
	providerPat    = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*/v[0-9]+$`)
	workloadPat    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)
	knownOS        = map[string]bool{"linux": true, "windows": true}
	reservedPrefix = []string{"content/", "tests/", "licenses/"}
)

// ParseDescriptor strictly decodes bundle.json: unknown fields, trailing data
// and unsupported formats are rejected, then the descriptor is validated.
func ParseDescriptor(data []byte) (*Descriptor, error) {
	if err := noDuplicateJSONKeys(data); err != nil {
		return nil, fmt.Errorf("decode %s: %w", DescriptorPath, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var d Descriptor
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("decode %s: %w", DescriptorPath, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode %s: unexpected data after the descriptor", DescriptorPath)
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// ValidPayloadPath reports whether p is a clean relative archive path in a
// known payload location (content/, tests/, licenses/, LICENSE or NOTICE).
// bundle.json is the descriptor, not a payload path, and is rejected here.
// Consumers that materialize an archive outside this package use it so the
// payload location rules exist once.
func ValidPayloadPath(p string) error { return validPayloadPath(p) }

// validPayloadPath reports whether p is a clean relative archive path in a
// known payload location.
func validPayloadPath(p string) error {
	if p == "" || path.IsAbs(p) || path.Clean(p) != p || strings.Contains(p, `\`) || p == DescriptorPath {
		return fmt.Errorf("path %q must be a clean relative payload path", p)
	}
	for _, pre := range reservedPrefix {
		if strings.HasPrefix(p, pre) {
			return nil
		}
	}
	if p == "LICENSE" || p == "NOTICE" {
		return nil
	}
	return fmt.Errorf("path %q is outside content/, tests/, licenses/, LICENSE and NOTICE", p)
}

// Validate checks the descriptor without reading any payload bytes.
func (d *Descriptor) Validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if d.Format != FormatV1 {
		fail("unsupported format %q: want %q", d.Format, FormatV1)
	}
	if !namePattern.MatchString(d.Name) {
		fail("name %q must be a DNS label", d.Name)
	}
	if !semverPattern.MatchString(d.Version) {
		fail("version %q must be SemVer", d.Version)
	}
	if !strings.HasPrefix(d.Source.Repository, "https://") {
		fail("source.repository %q must be an https URL", d.Source.Repository)
	}
	if !revisionPat.MatchString(d.Source.Revision) {
		fail("source.revision %q must be a full 40-character commit", d.Source.Revision)
	}
	if !providerPat.MatchString(d.Compatibility.Provider) {
		fail("compatibility.provider %q must look like name/vN", d.Compatibility.Provider)
	}
	if !semverPattern.MatchString(d.Compatibility.Konstapel) {
		fail("compatibility.konstapel %q must be SemVer", d.Compatibility.Konstapel)
	}
	if len(d.Scope.Workloads) == 0 {
		fail("scope.workloads must not be empty")
	}
	for _, w := range d.Scope.Workloads {
		if !workloadPat.MatchString(w) {
			fail("scope.workloads entry %q must be a Kubernetes kind", w)
		}
	}
	if len(d.Scope.OS) == 0 {
		fail("scope.os must not be empty")
	}
	for _, o := range d.Scope.OS {
		if !knownOS[o] {
			fail("scope.os entry %q is not supported", o)
		}
	}

	// File inventory: unique clean paths, a known role, a real digest.
	byPath := map[string]File{}
	for i, f := range d.Files {
		if err := validPayloadPath(f.Path); err != nil {
			fail("files[%d]: %v", i, err)
			continue
		}
		if _, dup := byPath[f.Path]; dup {
			fail("files[%d]: duplicate path %q", i, f.Path)
			continue
		}
		byPath[f.Path] = f
		if !roles[f.Role] {
			fail("files[%d] %q: unknown role %q", i, f.Path, f.Role)
		}
		if !sha256Pattern.MatchString(f.SHA256) {
			fail("files[%d] %q: sha256 must be 64 lowercase hex characters", i, f.Path)
		}
		if f.Size < 0 {
			fail("files[%d] %q: negative size", i, f.Path)
		}
	}
	needRole := func(p, role, what string) {
		f, ok := byPath[p]
		switch {
		case !ok:
			fail("%s %q is not in the file inventory", what, p)
		case f.Role != role:
			fail("%s %q has role %q, want %q", what, p, f.Role, role)
		}
	}

	if len(d.Policies) == 0 {
		fail("policies must not be empty")
	}
	policyNames, ruleIDs, checkIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, p := range d.Policies {
		if !namePattern.MatchString(p.Name) {
			fail("policies[%d]: name %q must be a DNS label", i, p.Name)
		}
		if policyNames[p.Name] {
			fail("policies[%d]: duplicate policy name %q", i, p.Name)
		}
		policyNames[p.Name] = true
		needRole(p.Path, RolePolicy, fmt.Sprintf("policies[%d].path", i))
		if p.ParameterSchema != "" {
			needRole(p.ParameterSchema, RoleSchema, fmt.Sprintf("policies[%d].parameterSchema", i))
		}
		if len(p.Checks) == 0 {
			fail("policies[%d] %q: checks must not be empty", i, p.Name)
		}
		for j, c := range p.Checks {
			if c.RuleID == "" || c.CheckID == "" {
				fail("policies[%d].checks[%d]: ruleID and checkID are required", i, j)
				continue
			}
			if ruleIDs[c.RuleID] {
				fail("policies[%d].checks[%d]: duplicate ruleID %q", i, j, c.RuleID)
			}
			if checkIDs[c.CheckID] {
				fail("policies[%d].checks[%d]: duplicate checkID %q", i, j, c.CheckID)
			}
			ruleIDs[c.RuleID], checkIDs[c.CheckID] = true, true
		}
	}

	if len(d.OSCAL) == 0 {
		fail("oscal must declare at least one entry point")
	}
	oscalPaths := map[string]bool{}
	hasCD := false
	for i, o := range d.OSCAL {
		if oscalPaths[o.Path] {
			fail("oscal[%d]: duplicate path %q", i, o.Path)
		}
		oscalPaths[o.Path] = true
		if !oscalVerPat.MatchString(o.Version) {
			fail("oscal[%d]: version %q must be an OSCAL 1.x.y version", i, o.Version)
		}
		f, ok := byPath[o.Path]
		if !ok {
			fail("oscal[%d]: %q is not in the file inventory", i, o.Path)
		} else if f.Role == RoleComponentDefinition {
			hasCD = true
		}
	}
	if !hasCD && len(d.OSCAL) > 0 {
		fail("oscal must declare a %s entry point", RoleComponentDefinition)
	}
	for _, role := range []string{RoleProvenance, RoleChecksums} {
		n := 0
		for _, f := range d.Files {
			if f.Role == role {
				n++
			}
		}
		if n != 1 {
			fail("file inventory must contain exactly one %s file, found %d", role, n)
		}
	}
	if f, ok := byPath["LICENSE"]; !ok || f.Role != RoleLicense {
		fail("file inventory must include LICENSE with role %s", RoleLicense)
	}
	return errors.Join(errs...)
}

// VerifyPayload checks an unpacked archive against the descriptor: every
// regular file except bundle.json is inventoried with the recorded size and
// digest, and nothing else is present.
func (d *Descriptor) VerifyPayload(fsys fs.FS) error {
	var errs []error
	want := map[string]File{}
	for _, f := range d.Files {
		want[f.Path] = f
	}
	seen := map[string]bool{}
	err := fs.WalkDir(fsys, ".", func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return nil
		}
		if !e.Type().IsRegular() {
			errs = append(errs, fmt.Errorf("%s: not a regular file", p))
			return nil
		}
		if p == DescriptorPath {
			return nil
		}
		f, ok := want[p]
		if !ok {
			errs = append(errs, fmt.Errorf("%s: present in the payload but not inventoried", p))
			return nil
		}
		seen[p] = true
		fh, err := fsys.Open(p)
		if err != nil {
			return err
		}
		defer fh.Close()
		h := sha256.New()
		n, err := io.Copy(h, fh)
		if err != nil {
			return err
		}
		if n != f.Size {
			errs = append(errs, fmt.Errorf("%s: size %d does not match inventory %d", p, n, f.Size))
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != f.SHA256 {
			errs = append(errs, fmt.Errorf("%s: sha256 %s does not match inventory %s", p, got, f.SHA256))
		}
		return nil
	})
	if err != nil {
		errs = append(errs, err)
	}
	var missing []string
	for p := range want {
		if !seen[p] {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)
	for _, p := range missing {
		errs = append(errs, fmt.Errorf("%s: inventoried but missing from the payload", p))
	}
	return errors.Join(errs...)
}

// Descriptor and manifest shapes for ValidateManifest.
type ociDescriptor struct {
	MediaType    string `json:"mediaType"`
	Digest       string `json:"digest"`
	Size         int64  `json:"size"`
	ArtifactType string `json:"artifactType,omitempty"`
}

type ociManifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType"`
	Config        ociDescriptor     `json:"config"`
	Layers        []ociDescriptor   `json:"layers"`
	Subject       *ociDescriptor    `json:"subject,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
	// Manifests is only present on an index; its presence is rejected.
	Manifests json.RawMessage `json:"manifests,omitempty"`
}

// ValidateManifest enforces the bundle's OCI layout: an image manifest with the
// bundle artifact type, the OCI empty config, and exactly one tar+gzip layer.
// Indexes and any other layer layout are rejected in this format version. It
// returns the layer descriptor so callers can fetch and verify the content.
func ValidateManifest(raw []byte) (digest string, size int64, err error) {
	var m ociManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", 0, fmt.Errorf("decode manifest: %w", err)
	}
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if m.Manifests != nil {
		fail("image indexes are not supported")
	}
	if m.SchemaVersion != 2 {
		fail("schemaVersion %d: want 2", m.SchemaVersion)
	}
	if m.MediaType != manifestMediaType {
		fail("mediaType %q: want %q", m.MediaType, manifestMediaType)
	}
	if m.ArtifactType != ArtifactType {
		fail("artifactType %q: want %q", m.ArtifactType, ArtifactType)
	}
	if m.Config.MediaType != EmptyConfigMediaType || m.Config.Digest != EmptyConfigDigest || m.Config.Size != 2 {
		fail("config must be the OCI empty descriptor")
	}
	if len(m.Layers) != 1 {
		fail("want exactly one layer, found %d", len(m.Layers))
	} else {
		l := m.Layers[0]
		if l.MediaType != LayerMediaType {
			fail("layer mediaType %q: want %q", l.MediaType, LayerMediaType)
		}
		if !strings.HasPrefix(l.Digest, "sha256:") || !sha256Pattern.MatchString(strings.TrimPrefix(l.Digest, "sha256:")) {
			fail("layer digest %q must be sha256", l.Digest)
		}
		if l.Size <= 0 {
			fail("layer size must be positive")
		}
		digest, size = l.Digest, l.Size
	}
	if err := errors.Join(errs...); err != nil {
		return "", 0, err
	}
	return digest, size, nil
}
