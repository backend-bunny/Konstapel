// Package publication defines the producer/publisher contract shared by the
// continuous-assessment controller and evidence storage backends.
//
// The assessment controller owns these types. A backend consumes a frozen
// package directory described by a Descriptor and reports durable state through
// Status and Receipt values. None of these types carry bulk evidence or
// credential material; packages hold evidence and status holds references.
package publication

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	// APIVersion and DescriptorKind version the descriptor document.
	APIVersion     = "compliance.erenius.io/v1alpha1"
	DescriptorKind = "PackageDescriptor"
	// DescriptorFile is the descriptor's fixed path in a package directory.
	// It is not listed in its own file inventory.
	DescriptorFile = "descriptor.json"
)

// PackageKind distinguishes assessment packages from diagnostic packages.
type PackageKind string

const (
	// KindAssessment contains schema-valid OSCAL assessment results, which may
	// describe incomplete evidence.
	KindAssessment PackageKind = "Assessment"
	// KindDiagnostic records a run whose valid OSCAL export was impossible. It
	// never contains assessment results presented as a successful export.
	KindDiagnostic PackageKind = "Diagnostic"
)

// ScopeKind distinguishes namespace-request packages from platform packages.
type ScopeKind string

const (
	// ScopeNamespace is an application-team request bounded to one namespace.
	ScopeNamespace ScopeKind = "Namespace"
	// ScopeBinding is a platform full-binding run; it remains platform-scoped
	// even if it happened to select one namespace.
	ScopeBinding ScopeKind = "Binding"
)

// FileRole declares what a packaged file is so publishers can enforce the
// allowed file kinds for each package kind.
type FileRole string

const (
	RoleAssessmentResults   FileRole = "oscal-assessment-results"
	RoleAssessmentPlan      FileRole = "oscal-assessment-plan"
	RoleSystemSecurityPlan  FileRole = "oscal-system-security-plan"
	RoleComponentDefinition FileRole = "oscal-component-definition"
	RoleSummary             FileRole = "summary"
	RoleEvidenceExtract     FileRole = "evidence-extract"
	RoleCapture             FileRole = "capture"
	RoleContent             FileRole = "content"
	RoleProvenance          FileRole = "provenance"
	RoleDiagnostic          FileRole = "diagnostic"
)

var roles = []FileRole{RoleAssessmentResults, RoleAssessmentPlan, RoleSystemSecurityPlan, RoleComponentDefinition, RoleSummary, RoleEvidenceExtract, RoleCapture, RoleContent, RoleProvenance, RoleDiagnostic}

// oscalRoles may only appear in assessment packages.
var oscalRoles = []FileRole{RoleAssessmentResults, RoleAssessmentPlan, RoleSystemSecurityPlan}

// Completeness describes evidence coverage only, never check outcomes.
type Completeness string

const (
	// Complete means every expected check is attributable and fresh. Complete
	// evidence may still contain failures.
	Complete Completeness = "Complete"
	// Incomplete means some expected observations are missing, rejected, or
	// unresolved; they remain in the denominator.
	Incomplete Completeness = "Incomplete"
	// NoTargets is explicit zero-target coverage. It is not a pass.
	NoTargets Completeness = "NoTargets"
)

// RunRef is the durable identity of an assessment run.
type RunRef struct {
	ClusterID  string `json:"clusterID"`
	BindingUID string `json:"bindingUID"`
	RunUID     string `json:"runUID"`
}

// PublicationID is the deterministic, opaque publication identity of a run.
// Every retry and leader of the same run derives the same value.
func (r RunRef) PublicationID() string {
	h := sha256.Sum256([]byte(r.ClusterID + "\x00" + r.BindingUID + "\x00" + r.RunUID))
	return "pub-" + hex.EncodeToString(h[:16])
}

func (r RunRef) validate() error {
	if r.ClusterID == "" || r.BindingUID == "" || r.RunUID == "" {
		return errors.New("run reference requires clusterID, bindingUID, and runUID")
	}
	return nil
}

// RequestRef identifies the namespaced request that defines a namespace scope.
// Downloads are addressed through these UIDs, never through names alone.
type RequestRef struct {
	Namespace    string `json:"namespace"`
	Name         string `json:"name"`
	UID          string `json:"uid"`
	NamespaceUID string `json:"namespaceUID"`
}

// Scope is the frozen scope captured at run start.
type Scope struct {
	Kind       ScopeKind   `json:"kind"`
	ClusterID  string      `json:"clusterID"`
	BindingUID string      `json:"bindingUID"`
	Request    *RequestRef `json:"request,omitempty"`
	// NamespaceUIDs lists the selected namespaces, sorted and unique. A
	// namespace scope contains exactly the request's namespace UID.
	NamespaceUIDs []string `json:"namespaceUIDs"`
	// Revision is the opaque scope revision recorded when scope was frozen.
	Revision string `json:"revision"`
}

// Digest is the SHA-256 of the scope's JSON encoding.
func (s Scope) Digest() string { return digest(s) }

// Revisions records the configuration identities the run evaluated against.
type Revisions struct {
	// BindingConfiguration is the binding's observed configuration revision,
	// which also selects retention at publication.
	BindingConfiguration string   `json:"bindingConfiguration"`
	Enforcement          []string `json:"enforcement"`
	MappingSHA256        string   `json:"mappingSha256"`
	// Content records the bundles the run's content came from: every
	// applied bundle, the desired one and their differences. It is absent
	// for runs whose contributions were all applied from the image's
	// vendored content while it was also desired (or no profile was
	// selected), whose identity is the packaged content/SHA256SUMS, so their
	// descriptors are unchanged.
	Content *RunContent `json:"content,omitempty"`
}

// RunContent is the content set of a run. Each applied bundle is packaged
// separately under its own directory (ContentPath) and is never collapsed
// into another bundle's identity; desired content is recorded beside it and
// is never substituted for applied content.
type RunContent struct {
	// Applied lists every bundle a contribution assessed by the run was
	// applied from (its engine policies' bundle and bundle-digest), sorted
	// by manifest digest. It is empty when nothing was applied.
	Applied []ContentRevision `json:"applied"`
	// Desired is the bundle the binding's profile selected when the run
	// started; nil without a profile. Its content is packaged (Frozen) only
	// when nothing was applied: it is then the content the plan names.
	Desired *ContentRevision `json:"desired,omitempty"`
	// Differences are the explicit desired/applied differences: the desired
	// bundle when no assessed contribution was applied from it, and every
	// applied bundle that is not the desired one. They are derived from
	// Applied and Desired and must match them.
	Differences []ContentDifference `json:"differences,omitempty"`
}

// ContentDifference kinds.
const (
	// DesiredNotApplied: the profile selects this bundle, but no assessed
	// contribution was applied from it (for example the update is not yet
	// delivered or ready, or it could not be resolved).
	DesiredNotApplied = "DesiredNotApplied"
	// AppliedNotDesired: assessed contributions were applied from this
	// bundle, which the profile no longer selects (for example the previous
	// revision still enforcing while an update rolls out).
	AppliedNotDesired = "AppliedNotDesired"
)

// ContentDifference is one difference between desired and applied content.
type ContentDifference struct {
	Kind           string `json:"kind"`
	Bundle         string `json:"bundle"`
	ManifestDigest string `json:"manifestDigest"`
}

// ContentRevision identifies one bundle of a run and the verification
// context its content was frozen under. Frozen content is packaged under
// its Path (bundle/ proofs and content/); an assessment package always has
// it for every applied bundle, and a diagnostic package records which
// bundle could not be frozen.
type ContentRevision struct {
	Bundle string `json:"bundle"`
	// ManifestDigest is the OCI manifest digest, the enforcement identity;
	// for the vendored bundle it is the sha256 of its content/SHA256SUMS.
	ManifestDigest string `json:"manifestDigest"`
	// Vendored marks the image's vendored content: it is packaged as its
	// content/ tree (no bundle/ proofs) and verified by its SHA256SUMS.
	Vendored bool `json:"vendored,omitempty"`
	// Frozen reports that the content is packaged under Path (always for
	// an applied bundle of an assessment package). The fields below are
	// recorded whenever OCI content was frozen, packaged or not.
	Frozen bool `json:"frozen"`
	// Path is the package directory of the content, ContentPath of the
	// manifest digest; set exactly when Frozen.
	Path           string `json:"path,omitempty"`
	Version        string `json:"version,omitempty"`
	ContentDigest  string `json:"contentDigest,omitempty"`
	ArchiveDigest  string `json:"archiveDigest,omitempty"`
	SourceRevision string `json:"sourceRevision,omitempty"`
	// SourceRule and TrustRevision are the publisher rule and trust input
	// revisions of the verification the content was resolved under, and
	// VerifiedAt when it happened. Verification is not proof of compliance.
	SourceRule    string     `json:"sourceRule,omitempty"`
	TrustRevision string     `json:"trustRevision,omitempty"`
	VerifiedAt    *time.Time `json:"verifiedAt,omitempty"`
}

// ContentPath is the package directory of a bundle's content:
// "bundles/<hex of the manifest digest>".
func ContentPath(manifestDigest string) string {
	return "bundles/" + strings.TrimPrefix(manifestDigest, "sha256:")
}

var ociDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (c *ContentRevision) validate(what string) error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(what+": "+format, a...)) }
	if c.Bundle == "" || !ociDigest.MatchString(c.ManifestDigest) {
		fail("content revision requires a bundle name and manifest digest")
	}
	switch {
	case c.Frozen && c.Path != ContentPath(c.ManifestDigest):
		fail("frozen content of %s must be packaged at %s", c.ManifestDigest, ContentPath(c.ManifestDigest))
	case !c.Frozen && c.Path != "":
		fail("content that is not packaged has no path")
	}
	if c.Frozen && !c.Vendored && (c.Version == "" || !ociDigest.MatchString(c.ContentDigest) || !ociDigest.MatchString(c.ArchiveDigest)) {
		fail("frozen content requires its version, content and archive digests")
	}
	return errors.Join(errs...)
}

// ContentDifferences derives the desired/applied differences.
func ContentDifferences(applied []ContentRevision, desired *ContentRevision) []ContentDifference {
	var out []ContentDifference
	same := func(a ContentRevision) bool {
		return desired != nil && a.Bundle == desired.Bundle && a.ManifestDigest == desired.ManifestDigest
	}
	if desired != nil && !slices.ContainsFunc(applied, same) {
		out = append(out, ContentDifference{Kind: DesiredNotApplied, Bundle: desired.Bundle, ManifestDigest: desired.ManifestDigest})
	}
	for _, a := range applied {
		if !same(a) {
			out = append(out, ContentDifference{Kind: AppliedNotDesired, Bundle: a.Bundle, ManifestDigest: a.ManifestDigest})
		}
	}
	return out
}

func (c *RunContent) validate(kind PackageKind) error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	for i := range c.Applied {
		a := &c.Applied[i]
		if err := a.validate("applied " + a.Bundle); err != nil {
			errs = append(errs, err)
		}
		if i > 0 && c.Applied[i-1].ManifestDigest >= a.ManifestDigest {
			fail("applied content must be unique and sorted by manifest digest")
		}
		if kind == KindAssessment && !a.Frozen {
			fail("an assessment package requires the content of every applied bundle to be frozen (%s@%s is not)", a.Bundle, a.ManifestDigest)
		}
	}
	if d := c.Desired; d != nil {
		if err := d.validate("desired " + d.Bundle); err != nil {
			errs = append(errs, err)
		}
		if d.Frozen && len(c.Applied) > 0 {
			fail("desired content is packaged only when nothing was applied")
		}
	}
	if kind == KindAssessment && len(c.Applied) == 0 && (c.Desired == nil || !c.Desired.Frozen) {
		fail("an assessment package with nothing applied requires the desired bundle's content to be frozen")
	}
	if c.Applied == nil {
		fail("applied content must be listed (empty when nothing was applied)")
	}
	want := ContentDifferences(c.Applied, c.Desired)
	if !slices.Equal(want, c.Differences) {
		fail("content differences %v do not match the applied and desired content (%v)", c.Differences, want)
	}
	return errors.Join(errs...)
}

// Window is the bounded observation window, not an atomic cluster snapshot.
type Window struct {
	Started time.Time `json:"started"`
	Closed  time.Time `json:"closed"`
}

// EvidenceSummary counts expected checks by evidence state.
type EvidenceSummary struct {
	Completeness Completeness `json:"completeness"`
	Expected     int          `json:"expected"`
	Attributable int          `json:"attributable"`
	Missing      int          `json:"missing"`
	Rejected     int          `json:"rejected"`
	Unresolved   int          `json:"unresolved"`
	// StaleScopes counts bindings or policies whose current configuration did
	// not resolve, so their expected checks are unknown. Any stale scope makes
	// evidence Incomplete.
	StaleScopes int `json:"staleScopes,omitempty"`
}

// OutcomeCounts preserves check dispositions separately from completeness.
// There is deliberately no aggregate "passed" field: accepted risk,
// non-applicable subjects, and repeated contributions do not add to passes.
type OutcomeCounts struct {
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	Error         int `json:"error"`
	Skip          int `json:"skip"`
	AcceptedRisk  int `json:"acceptedRisk"`
	NotApplicable int `json:"notApplicable"`
	Unknown       int `json:"unknown"`
}

// Diagnostic explains why a package is diagnostic rather than an assessment.
type Diagnostic struct {
	Reason         string     `json:"reason"`
	MissingExports []FileRole `json:"missingExports"`
	Message        string     `json:"message"`
}

// Producer records the trusted producer and the validations it performed.
type Producer struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	ValidatedAt time.Time `json:"validatedAt"`
	Checks      []string  `json:"checks"`
}

// File is one inventoried package file.
type File struct {
	Path   string   `json:"path"`
	Role   FileRole `json:"role"`
	SHA256 string   `json:"sha256"`
	Size   int64    `json:"size"`
}

// Descriptor describes one frozen package.
type Descriptor struct {
	APIVersion  string          `json:"apiVersion"`
	Kind        string          `json:"kind"`
	Run         RunRef          `json:"run"`
	PackageKind PackageKind     `json:"packageKind"`
	Scope       Scope           `json:"scope"`
	ScopeSHA256 string          `json:"scopeSha256"`
	Revisions   Revisions       `json:"revisions"`
	Window      Window          `json:"window"`
	Evidence    EvidenceSummary `json:"evidence"`
	Outcomes    OutcomeCounts   `json:"outcomes"`
	Diagnostic  *Diagnostic     `json:"diagnostic,omitempty"`
	Producer    Producer        `json:"producer"`
	Files       []File          `json:"files"`
}

// Digest is the SHA-256 of the descriptor's JSON encoding.
func (d Descriptor) Digest() string { return digest(d) }

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate checks the descriptor's internal consistency. It does not read
// package bytes; VerifyDir checks a directory against the descriptor.
func (d Descriptor) Validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if d.APIVersion != APIVersion || d.Kind != DescriptorKind {
		fail("unsupported descriptor %s/%s", d.APIVersion, d.Kind)
	}
	if err := d.Run.validate(); err != nil {
		errs = append(errs, err)
	}
	if err := d.Scope.validate(d.Run); err != nil {
		errs = append(errs, err)
	}
	if d.ScopeSHA256 != d.Scope.Digest() {
		fail("scope digest does not match frozen scope")
	}
	if d.Revisions.BindingConfiguration == "" || d.Revisions.MappingSHA256 == "" {
		fail("revisions require bindingConfiguration and mappingSha256")
	}
	if c := d.Revisions.Content; c != nil {
		if err := c.validate(d.PackageKind); err != nil {
			errs = append(errs, err)
		}
	}
	if d.Window.Started.IsZero() || d.Window.Closed.Before(d.Window.Started) {
		fail("capture window must start and close in order")
	}
	if err := d.Evidence.Validate(); err != nil {
		errs = append(errs, err)
	}
	if d.Producer.Name == "" || d.Producer.Version == "" || d.Producer.ValidatedAt.IsZero() || len(d.Producer.Checks) == 0 {
		fail("producer identity and validation checks are required")
	}
	present := map[FileRole]bool{}
	seen := map[string]bool{}
	for _, f := range d.Files {
		if err := safePath(f.Path); err != nil {
			errs = append(errs, err)
		}
		if seen[f.Path] {
			fail("duplicate file %q", f.Path)
		}
		seen[f.Path] = true
		if !slices.Contains(roles, f.Role) {
			fail("file %q has unknown role %q", f.Path, f.Role)
		}
		if !sha256Hex.MatchString(f.SHA256) || f.Size < 0 {
			fail("file %q requires a lowercase SHA-256 and non-negative size", f.Path)
		}
		present[f.Role] = true
	}
	if !slices.IsSortedFunc(d.Files, func(a, b File) int { return strings.Compare(a.Path, b.Path) }) {
		fail("files must be sorted by path")
	}
	switch d.PackageKind {
	case KindAssessment:
		if d.Diagnostic != nil {
			fail("assessment package cannot carry a diagnostic")
		}
		if !present[RoleAssessmentResults] {
			fail("assessment package requires %s", RoleAssessmentResults)
		}
	case KindDiagnostic:
		if d.Diagnostic == nil || d.Diagnostic.Reason == "" || len(d.Diagnostic.MissingExports) == 0 {
			fail("diagnostic package requires a reason and missing exports")
		}
		if !present[RoleDiagnostic] {
			fail("diagnostic package requires %s", RoleDiagnostic)
		}
		for _, r := range oscalRoles {
			if present[r] {
				fail("diagnostic package cannot contain %s", r)
			}
		}
	default:
		fail("unknown package kind %q", d.PackageKind)
	}
	return errors.Join(errs...)
}

func (s Scope) validate(run RunRef) error {
	if s.ClusterID != run.ClusterID || s.BindingUID != run.BindingUID {
		return errors.New("scope cluster and binding must match the run")
	}
	if s.Revision == "" {
		return errors.New("scope requires a frozen revision")
	}
	if !slices.IsSorted(s.NamespaceUIDs) || len(slices.Compact(slices.Clone(s.NamespaceUIDs))) != len(s.NamespaceUIDs) || slices.Contains(s.NamespaceUIDs, "") {
		return errors.New("scope namespace UIDs must be non-empty, sorted, and unique")
	}
	switch s.Kind {
	case ScopeNamespace:
		r := s.Request
		if r == nil || r.Namespace == "" || r.Name == "" || r.UID == "" || r.NamespaceUID == "" {
			return errors.New("namespace scope requires a complete request reference")
		}
		if len(s.NamespaceUIDs) != 1 || s.NamespaceUIDs[0] != r.NamespaceUID {
			return errors.New("namespace scope must contain exactly the request namespace")
		}
	case ScopeBinding:
		if s.Request != nil {
			return errors.New("binding scope cannot reference a namespace request")
		}
	default:
		return fmt.Errorf("unknown scope kind %q", s.Kind)
	}
	return nil
}

// Validate checks that the counts and completeness are consistent.
func (e EvidenceSummary) Validate() error {
	if e.Expected < 0 || e.Attributable < 0 || e.Missing < 0 || e.Rejected < 0 || e.Unresolved < 0 || e.StaleScopes < 0 {
		return errors.New("evidence counts cannot be negative")
	}
	if e.Attributable+e.Missing+e.Rejected+e.Unresolved != e.Expected {
		return errors.New("evidence counts must account for every expected check")
	}
	gaps := e.Attributable < e.Expected || e.StaleScopes > 0
	switch e.Completeness {
	case NoTargets:
		if e.Expected != 0 || e.StaleScopes != 0 {
			return errors.New("NoTargets requires zero expected checks and no stale scope")
		}
	case Complete:
		if e.Expected == 0 || gaps {
			return errors.New("Complete requires every expected check to be attributable and no stale scope")
		}
	case Incomplete:
		if !gaps {
			return errors.New("Incomplete requires unattributable expected checks or stale scope")
		}
	default:
		return fmt.Errorf("unknown completeness %q", e.Completeness)
	}
	return nil
}

// safePath accepts clean, relative, slash-separated paths inside the package.
func safePath(p string) error {
	if p == "" || p == DescriptorFile || strings.Contains(p, "\\") || path.IsAbs(p) || path.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../") {
		return fmt.Errorf("unsafe package path %q", p)
	}
	return nil
}

func digest(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // contract types always marshal
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
