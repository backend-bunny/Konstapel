package bundle

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// SourcesVersion is the only supported version of the source configuration.
const SourcesVersion = 1

// SourcesConfigKey is the ConfigMap data key that holds the document. The
// ConfigMap lives in the controller's namespace and is writable only by
// platform administrators; it holds no secret material.
const SourcesConfigKey = "sources.yaml"

const maxSources = 256

// Reference kinds for custom CA and trust-root objects.
const (
	KindConfigMap = "ConfigMap"
	KindSecret    = "Secret"
)

// Default data keys when a reference omits one.
const (
	DefaultCredentialKey = ".dockerconfigjson"
	DefaultCAKey         = "ca.crt"
	DefaultTrustRootKey  = "trusted_root.json"
	DefaultPublicKey     = "cosign.pub"
)

// ObjectRef names an object in the controller's namespace. It deliberately has
// no namespace field: a source can only reference objects the controller owns,
// never an application namespace.
type ObjectRef struct {
	// Kind is ConfigMap or Secret. It is required for CA, trust-root and
	// public-key references; a credential reference is always a Secret.
	Kind string `json:"kind,omitempty"`
	Name string `json:"name"`
	// Key is the data key; a default applies when empty.
	Key string `json:"key,omitempty"`
}

// Publisher is the central rule deciding who may publish this bundle. The
// bundle and application teams cannot supply or alter it. Exactly one signing
// method is configured; the same rule authorizes the signature and provenance.
type Publisher struct {
	// Type is "keyless" or "public-key".
	Type string `json:"type"`

	// Keyless: the exact OIDC issuer and signing identity, and an optional
	// reference to a Sigstore trusted root (default: the documented public-good
	// root pinned in the controller configuration).
	Issuer    string     `json:"issuer,omitempty"`
	Identity  string     `json:"identity,omitempty"`
	TrustRoot *ObjectRef `json:"trustRoot,omitempty"`

	// Public key: a referenced public key and its expected fingerprint.
	PublicKey      *ObjectRef `json:"publicKey,omitempty"`
	KeyFingerprint string     `json:"keyFingerprint,omitempty"`

	// Provenance constrains the attested origin for either method.
	Provenance ProvenanceRule `json:"provenance"`
}

// ProvenanceRule fixes the source repository and builder the SLSA provenance
// must name. Both are exact: no wildcards or patterns. Provenance is required
// for every publisher. The builder also selects the build record the
// provenance must carry (docs/policy-bundles.md, "Bundle provenance v1"): a
// GitHub Actions workflow builder (GitHubWorkflowBuilder) requires the
// workflow record, whose repository, path and ref must be the builder's; any
// other builder requires the builder record (its own revision) and refuses a
// workflow record.
type ProvenanceRule struct {
	SourceRepository string `json:"sourceRepository"`
	Builder          string `json:"builder"`
}

// GitHubActionsIssuer is the OIDC issuer of GitHub Actions tokens. A keyless
// rule with this issuer is a GitHub publisher: its builder must be a GitHub
// Actions workflow builder, so its provenance carries the workflow record.
const GitHubActionsIssuer = "https://token.actions.githubusercontent.com"

// GitHubWorkflow is a GitHub Actions workflow named by a builder ID.
type GitHubWorkflow struct {
	// Repository is https://github.com/<owner>/<repo>.
	Repository string
	// Path is .github/workflows/<file>.
	Path string
	// Ref is the fully qualified ref the workflow ran from.
	Ref string
}

var (
	githubWorkflowBuilder = regexp.MustCompile(`^(https://github\.com/[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+)/(\.github/workflows/[A-Za-z0-9._-]+\.ya?ml)@(refs/[\x21-\x7e]+)$`)
)

// GitHubWorkflowBuilder reports whether a provenance builder ID names a
// GitHub Actions workflow on github.com, in the form of the workflow's keyless
// certificate identity: https://github.com/<owner>/<repo>/.github/workflows/
// <file>@<ref>. Only such a builder requires (and allows) the workflow record.
func GitHubWorkflowBuilder(id string) (GitHubWorkflow, bool) {
	m := githubWorkflowBuilder.FindStringSubmatch(id)
	if m == nil || strings.Contains(m[1], "/../") || strings.HasSuffix(m[1], "/..") || strings.HasSuffix(m[1], "/.") {
		return GitHubWorkflow{}, false
	}
	return GitHubWorkflow{Repository: m[1], Path: m[2], Ref: m[3]}, true
}

// BundleSource maps one bundle name to one exact OCI repository and its trust.
type BundleSource struct {
	// Name is the logical bundle name, as in ComplianceProfile.spec.bundle.name.
	Name string `json:"name"`
	// Repository is host[:port]/path with no scheme, tag or digest. A mirror
	// replaces this value; the pinned digest and publisher rule do not change.
	Repository string `json:"repository"`
	// CredentialSecret references a dockerconfigjson Secret in the controller
	// namespace. Omit it for an anonymous repository.
	CredentialSecret *ObjectRef `json:"credentialSecret,omitempty"`
	// CA references additional trusted roots for the registry's TLS. TLS
	// verification is never disabled.
	CA        *ObjectRef `json:"ca,omitempty"`
	Publisher Publisher  `json:"publisher"`
}

// Sources is the versioned central configuration document.
type Sources struct {
	Version int            `json:"version"`
	Sources []BundleSource `json:"sources"`
}

var (
	// sourceNamePattern is the ComplianceProfile.spec.bundle.name pattern, so
	// every name a profile can carry can be configured (or reported missing).
	sourceNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)
	objectNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	dataKeyPattern    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`)
	repoPathPattern   = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
	hostPattern       = regexp.MustCompile(`^([a-z0-9]([-a-z0-9]*[a-z0-9])?)(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*(:[0-9]{1,5})?$`)
	fingerprintPat    = regexp.MustCompile(`^(sha256:)?[0-9a-f]{64}$`)
)

// ValidateRepository checks a repository reference: host[:port]/path only. A
// tag or digest embedded here would let a source select content on its own,
// bypassing the profile's pinned digest, so both are rejected.
func ValidateRepository(repo string) error {
	switch {
	case repo == "" || len(repo) > 255:
		return fmt.Errorf("repository %q must be 1-255 characters", repo)
	case strings.Contains(repo, "://"):
		return fmt.Errorf("repository %q must not include a scheme; TLS is always used", repo)
	case strings.Contains(repo, "@"):
		return fmt.Errorf("repository %q must not embed a digest; the profile pins it", repo)
	case strings.ContainsAny(repo, " \t\n?#\\"):
		return fmt.Errorf("repository %q contains illegal characters", repo)
	}
	host, path, ok := strings.Cut(repo, "/")
	if !ok {
		return fmt.Errorf("repository %q must be host[:port]/path", repo)
	}
	if strings.Contains(path, ":") {
		return fmt.Errorf("repository %q must not embed a tag; the profile pins the digest", repo)
	}
	if !hostPattern.MatchString(host) {
		return fmt.Errorf("repository %q has an invalid registry host %q", repo, host)
	}
	if !repoPathPattern.MatchString(path) {
		return fmt.Errorf("repository %q has an invalid path %q (lowercase OCI name components only)", repo, path)
	}
	return nil
}

func validateRef(what string, r *ObjectRef, kinds ...string) error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(what+": "+format, a...)) }
	if !objectNamePattern.MatchString(r.Name) {
		fail("name %q must be a DNS-1123 object name", r.Name)
	}
	if r.Key != "" && !dataKeyPattern.MatchString(r.Key) {
		fail("key %q is not a valid data key", r.Key)
	}
	allowed := false
	for _, k := range kinds {
		allowed = allowed || r.Kind == k
	}
	if !allowed {
		fail("kind %q must be one of %s", r.Kind, strings.Join(kinds, ", "))
	}
	return errors.Join(errs...)
}

func noWildcards(what, v string) error {
	if strings.ContainsAny(v, "*?[]{}()|^$\\") || strings.TrimSpace(v) != v || v == "" {
		return fmt.Errorf("%s %q must be an exact value: no wildcards, patterns or surrounding space", what, v)
	}
	return nil
}

func httpsURL(what, v string) error {
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s %q must be a plain https URL", what, v)
	}
	return nil
}

// Validate checks one publisher rule.
func (p Publisher) Validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	switch p.Type {
	case SignerKeyless:
		if err := httpsURL("publisher.issuer", p.Issuer); err != nil {
			errs = append(errs, err)
		}
		if err := noWildcards("publisher.issuer", p.Issuer); err != nil {
			errs = append(errs, err)
		}
		if err := noWildcards("publisher.identity", p.Identity); err != nil {
			errs = append(errs, err)
		}
		// A GitHub publisher's provenance must carry the workflow record, so
		// its builder must be a GitHub Actions workflow.
		if _, ok := GitHubWorkflowBuilder(p.Provenance.Builder); p.Issuer == GitHubActionsIssuer && !ok {
			fail("publisher.provenance.builder %q: a keyless rule with issuer %s needs a GitHub Actions workflow builder (https://github.com/<owner>/<repo>/.github/workflows/<file>@<ref>)", p.Provenance.Builder, GitHubActionsIssuer)
		}
		if p.PublicKey != nil || p.KeyFingerprint != "" {
			fail("a keyless publisher must not set publicKey or keyFingerprint")
		}
		if p.TrustRoot != nil {
			if err := validateRef("publisher.trustRoot", p.TrustRoot, KindConfigMap, KindSecret); err != nil {
				errs = append(errs, err)
			}
		}
	case SignerPublicKey:
		if p.PublicKey == nil {
			fail("a public-key publisher needs publisher.publicKey")
		} else if err := validateRef("publisher.publicKey", p.PublicKey, KindConfigMap, KindSecret); err != nil {
			errs = append(errs, err)
		}
		if !fingerprintPat.MatchString(p.KeyFingerprint) {
			fail("publisher.keyFingerprint %q must be a lowercase SHA-256 hex fingerprint", p.KeyFingerprint)
		}
		if p.Issuer != "" || p.Identity != "" || p.TrustRoot != nil {
			fail("a public-key publisher must not set issuer, identity or trustRoot")
		}
	default:
		fail("publisher.type %q must be %q or %q", p.Type, SignerKeyless, SignerPublicKey)
	}
	if err := httpsURL("publisher.provenance.sourceRepository", p.Provenance.SourceRepository); err != nil {
		errs = append(errs, err)
	}
	if err := noWildcards("publisher.provenance.builder", p.Provenance.Builder); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Validate checks a single source entry.
func (s BundleSource) Validate() error {
	var errs []error
	fail := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf("source %q: "+format, append([]any{s.Name}, a...)...))
	}
	if !sourceNamePattern.MatchString(s.Name) || len(s.Name) > 253 {
		fail("name must match the profile bundle name pattern")
	}
	if err := ValidateRepository(s.Repository); err != nil {
		fail("%v", err)
	}
	if s.CredentialSecret != nil {
		c := *s.CredentialSecret
		if c.Kind != "" && c.Kind != KindSecret {
			fail("credentialSecret must be a Secret, not a %s", c.Kind)
		}
		c.Kind = KindSecret
		if err := validateRef("credentialSecret", &c, KindSecret); err != nil {
			fail("%v", err)
		}
	}
	if s.CA != nil {
		if err := validateRef("ca", s.CA, KindConfigMap, KindSecret); err != nil {
			fail("%v", err)
		}
	}
	if err := s.Publisher.Validate(); err != nil {
		fail("%v", err)
	}
	return errors.Join(errs...)
}

// Validate checks the whole document: a supported version, valid entries, and
// no duplicate names. A repository may serve more than one name only if each
// has its own entry; duplicate names are never merged.
func (c Sources) Validate() error {
	var errs []error
	if c.Version != SourcesVersion {
		errs = append(errs, fmt.Errorf("version %d is unsupported: want %d", c.Version, SourcesVersion))
	}
	if len(c.Sources) > maxSources {
		errs = append(errs, fmt.Errorf("more than %d sources", maxSources))
	}
	seen := map[string]bool{}
	for _, s := range c.Sources {
		if seen[s.Name] {
			errs = append(errs, fmt.Errorf("duplicate source name %q", s.Name))
		}
		seen[s.Name] = true
		if err := s.Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ErrUnconfigured reports a bundle name with no configured source. Resolution
// of such a bundle is unavailable; there is no default registry.
var ErrUnconfigured = errors.New("no source is configured for the bundle")

// Select returns the source for a profile's bundle name. There is no prefix
// matching and no fallback: an unknown name is unresolved.
func (c Sources) Select(name string) (BundleSource, error) {
	for _, s := range c.Sources {
		if s.Name == name {
			return s, nil
		}
	}
	return BundleSource{}, fmt.Errorf("%w: %q", ErrUnconfigured, name)
}

// CheckPayload requires the fetched bundle's own name to be the name the
// profile asked for, so a source cannot answer with a different bundle.
func (s BundleSource) CheckPayload(d *Descriptor) error {
	if d.Name != s.Name {
		return fmt.Errorf("source %q returned a bundle named %q: the payload name must equal the requested name", s.Name, d.Name)
	}
	return nil
}

// CheckPublisher requires the verified provenance to name exactly the source
// repository and builder the rule allows.
func (s BundleSource) CheckPublisher(p Provenance) error {
	r := s.Publisher.Provenance
	if p.Repository != r.SourceRepository || p.Builder != r.Builder {
		return fmt.Errorf("source %q: provenance names repository %q and builder %q, but the publisher rule allows %q and %q",
			s.Name, p.Repository, p.Builder, r.SourceRepository, r.Builder)
	}
	return nil
}

// ParseSources decodes a sources document strictly (unknown fields, repeated
// keys and trailing documents are rejected) and validates it. Credentials,
// private keys and inline key material do not belong here and are rejected.
func ParseSources(raw []byte) (Sources, error) {
	var c Sources
	for _, marker := range [][]byte{[]byte("-----BEGIN"), []byte(`"auths"`), []byte("auths:")} {
		if bytes.Contains(raw, marker) {
			return c, errors.New("sources: key material and credentials belong in referenced Secrets, not in this ConfigMap")
		}
	}
	if err := yaml.UnmarshalStrict(raw, &c); err != nil {
		return Sources{}, fmt.Errorf("sources: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Sources{}, err
	}
	sort.Slice(c.Sources, func(i, j int) bool { return c.Sources[i].Name < c.Sources[j].Name })
	return c, nil
}

// ParseConfigMapData extracts and parses the document from a ConfigMap's data.
// Any other key is rejected, so an unexpected entry is never silently ignored.
func ParseConfigMapData(data map[string]string) (Sources, error) {
	raw, ok := data[SourcesConfigKey]
	if !ok {
		return Sources{}, fmt.Errorf("sources ConfigMap has no %q key", SourcesConfigKey)
	}
	for k := range data {
		if k != SourcesConfigKey {
			return Sources{}, fmt.Errorf("sources ConfigMap has unexpected key %q", k)
		}
	}
	return ParseSources([]byte(raw))
}
