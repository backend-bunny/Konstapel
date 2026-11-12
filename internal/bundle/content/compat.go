package content

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// DefaultProvider is the only provider contract Konstapel installs: the
// bounded Kyverno evidence provider. Bundle data names a contract; it can
// never name an executable, and only an allowlisted contract is accepted.
const DefaultProvider = assessment.ProviderID + "/v1"

// SupportedOSCAL are the OSCAL versions the installed validation handles:
// C2P-compatible authored component definitions (1.1.3) and the official
// NIST documents (1.2.3), matching the pinned schemas in content/schemas.
var SupportedOSCAL = []string{"1.1.3", "1.2.3"}

// compatRules versions the rules Check implements. Change it whenever the
// rules change, so acceptances recorded under the old rules are not reused.
const compatRules = "konstapel.compatibility/v1"

// supportedOS is the only workload OS the initial provider path evaluates.
const supportedOS = "linux"

var (
	providerPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*/v[0-9]+$`)
	// The SemVer 2.0.0 grammar, as bundle.json requires it.
	semverPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
)

// Compatibility is the running controller's compatibility contract. Its
// Check method is the resolve.Compatible function and Revision is the value
// for resolve.Revisions.Compatibility.
//
// Rules (all must hold; every failure is a reason):
//
//   - compatibility.provider is in Providers, the installed allowlist
//     (DefaultProvider). A bundle cannot choose its own provider or
//     executable; the provider identity is only looked up here.
//   - compatibility.konstapel, a minimum release, is at most Controller under
//     SemVer 2.0.0 precedence. Build metadata is ignored. A pre-release
//     controller (0.2.0-rc.1) satisfies minimums up to and including its own
//     pre-release and every lower release (0.1.x), but not the release it
//     precedes (0.2.0): a pre-release is older than its release.
//   - every declared OSCAL version is in SupportedOSCAL.
//   - scope.os is exactly linux: the initial provider path evaluates only
//     namespaced Linux workloads, so content that claims another OS (alone
//     or besides linux) makes a claim Konstapel cannot honour.
//
// Whether each policy is a supported namespaced ValidatingPolicy is reported
// per policy by the content source (targeting.PolicyScopeOf), not here, so
// one unsupported policy does not reject the bundle's other policies.
type Compatibility struct {
	// Controller is the running controller's release version (SemVer).
	Controller string
	// Providers is the installed provider allowlist; nil means
	// []string{DefaultProvider}.
	Providers []string
}

func (c Compatibility) providers() []string {
	if c.Providers == nil {
		return []string{DefaultProvider}
	}
	p := slices.Clone(c.Providers)
	slices.Sort(p)
	return slices.Compact(p)
}

// Validate checks the configuration itself.
func (c Compatibility) Validate() error {
	if !semverPattern.MatchString(c.Controller) {
		return fmt.Errorf("controller version %q is not SemVer", c.Controller)
	}
	for _, p := range c.providers() {
		if !providerPattern.MatchString(p) {
			return fmt.Errorf("provider %q must look like name/vN", p)
		}
	}
	return nil
}

// Revision identifies the contract Check implements: the rules version,
// the controller version, the sorted provider allowlist and the supported
// OSCAL versions and OS. It changes when any of them changes and not
// otherwise (in particular not with the allowlist's order or duplicates).
func (c Compatibility) Revision() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(struct {
		Rules      string   `json:"rules"`
		Controller string   `json:"controller"`
		Providers  []string `json:"providers"`
		OSCAL      []string `json:"oscal"`
		OS         string   `json:"os"`
	}{compatRules, c.Controller, c.providers(), SupportedOSCAL, supportedOS})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Check judges a verified descriptor. It has the resolve.Compatible
// signature. Reasons are bounded: one per failed rule, built from the
// descriptor's validated fields.
func (c Compatibility) Check(d *bundle.Descriptor) bundle.ContentCompatibility {
	out := bundle.ContentCompatibility{Provider: d.Compatibility.Provider, Konstapel: d.Compatibility.Konstapel}
	for _, o := range d.OSCAL {
		out.OSCAL = append(out.OSCAL, o.Version)
	}
	slices.Sort(out.OSCAL)
	out.OSCAL = slices.Compact(out.OSCAL)

	if err := c.Validate(); err != nil {
		out.Reasons = append(out.Reasons, "controller compatibility configuration: "+err.Error())
	}
	if !slices.Contains(c.providers(), d.Compatibility.Provider) {
		out.Reasons = append(out.Reasons, fmt.Sprintf("provider contract %q is not installed (installed: %s)", d.Compatibility.Provider, strings.Join(c.providers(), ", ")))
	}
	switch {
	case !semverPattern.MatchString(d.Compatibility.Konstapel):
		out.Reasons = append(out.Reasons, fmt.Sprintf("compatibility.konstapel %q is not SemVer", d.Compatibility.Konstapel))
	case semverPattern.MatchString(c.Controller) && semver.Compare("v"+d.Compatibility.Konstapel, "v"+c.Controller) > 0:
		out.Reasons = append(out.Reasons, fmt.Sprintf("requires Konstapel %s or later; this controller is %s", d.Compatibility.Konstapel, c.Controller))
	}
	for _, v := range out.OSCAL {
		if !slices.Contains(SupportedOSCAL, v) {
			out.Reasons = append(out.Reasons, fmt.Sprintf("OSCAL version %s is not supported (supported: %s)", v, strings.Join(SupportedOSCAL, ", ")))
		}
	}
	if len(d.Scope.OS) == 0 || slices.ContainsFunc(d.Scope.OS, func(o string) bool { return o != supportedOS }) {
		out.Reasons = append(out.Reasons, fmt.Sprintf("scope.os %v: only %s workloads are supported", d.Scope.OS, supportedOS))
	}
	out.Compatible = len(out.Reasons) == 0
	return out
}
