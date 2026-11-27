package providerkit

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"slices"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
)

// ProtocolVersion is the revision of protocol major version 1
// (konstapel.provider.v1) this kit speaks and serves, and the only one.
// Revision 2 made the host-frozen Inventory and the CollectionResult
// attribution envelope mandatory. A revision 1 peer would silently ignore
// both, so the kit rejects every other revision in both directions rather
// than serving two.
const ProtocolVersion uint32 = 2

// Default bounds. The host applies the stricter of these and a provider's
// advertised Limits; an advertised limit never raises them.
const (
	// DefaultMaxResultBytes bounds one result or evaluated payload. It is
	// the host's collection byte budget (512 MiB).
	DefaultMaxResultBytes uint64 = 512 << 20
	// DefaultMaxChunkBytes bounds one chunk, well below gRPC's default
	// 4 MiB message size.
	DefaultMaxChunkBytes uint32 = 1 << 20
	// DefaultMaxObservations bounds one evaluation's observations. It is
	// the host's collection object budget.
	DefaultMaxObservations uint32 = 100_000
	// DefaultMaxSubjects bounds one inventory's subjects, and separately a
	// result's supplements. It is the host's collection object budget.
	DefaultMaxSubjects uint32 = 100_000
	// DefaultMaxEvidence bounds one result's evidence items, and separately
	// its limitations. It is the host's collection object budget.
	DefaultMaxEvidence uint32 = 100_000
)

// Text bounds of provider-written diagnostics.
const (
	// MaxLimitations bounds a result's limitations.
	MaxLimitations = 64
	// MaxTextBytes bounds one limitation, operation message or identifier.
	MaxTextBytes = 1024
	// MaxNameBytes bounds an inventory subject's name, a Kubernetes object
	// name.
	MaxNameBytes = 253
	// MaxSubjectChecks bounds the checks expected for one subject.
	MaxSubjectChecks = 256
	// MaxAttributions bounds the attributions of one evidence item.
	MaxAttributions = 1024
)

var (
	namePattern   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	kindPattern   = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?/v[0-9][a-z0-9]*/[A-Z][A-Za-z0-9]*$`)
	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	// resourcePattern is "<group>/<version>/<resource>", the core group
	// empty.
	resourcePattern = regexp.MustCompile(`^([a-z0-9]([-a-z0-9.]*[a-z0-9])?)?/v[0-9][a-z0-9]*/[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
)

// Digest is "sha256:" and the lowercase hex SHA-256 of b, the digest form
// every protocol message uses.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Compatibility is what a host's provider registration expects of an
// endpoint. Each dimension is compared separately; none implies another.
type Compatibility struct {
	// Provider is the expected identity and capability contract version.
	Provider string
	// ContractVersion is the expected provider contract version.
	ContractVersion uint32
	// PayloadVersion is the payload version the host stores for new
	// evidence: it must be the provider's payload.write when collection or
	// scans are allowed, and one it reads when evaluation is.
	PayloadVersion uint32
	// EvaluatorVersion is the expected evaluation semantics.
	EvaluatorVersion uint32
	// Capabilities are the operation groups the registration allows. The
	// provider must serve each; the client sends no request outside them.
	Capabilities []providerv1.Capability
}

// Validate checks the expectation on its own.
func (c Compatibility) Validate() error {
	switch {
	case !validName(c.Provider):
		return Errorf(providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST, "expected provider %q must be a lowercase DNS label", c.Provider)
	case c.ContractVersion < 1 || c.PayloadVersion < 1 || c.EvaluatorVersion < 1:
		return Errorf(providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST, "expected contract, payload and evaluator versions must be at least 1")
	case len(c.Capabilities) == 0:
		return Errorf(providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST, "expectation allows no capability")
	}
	for i, capability := range c.Capabilities {
		if !knownCapability(capability) || slices.Contains(c.Capabilities[:i], capability) {
			return Errorf(providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST, "expected capability %s is unknown or repeated", capability)
		}
	}
	return nil
}

// Header is the request header for the expected contract.
func (c Compatibility) Header() *providerv1.RequestHeader {
	return &providerv1.RequestHeader{ProtocolVersion: ProtocolVersion,
		Provider: &providerv1.ProviderContract{Name: c.Provider, Version: c.ContractVersion}}
}

func (c Compatibility) allows(capability providerv1.Capability) bool {
	return slices.Contains(c.Capabilities, capability)
}

// ValidateDescription checks a DescribeResponse on its own: a well-formed
// identity, at least one protocol revision, evaluator and payload versions
// of at least 1 with read including write, known unrepeated capabilities,
// unrepeated check kinds and bounded text. A violation is
// ERROR_REASON_INVALID_RESPONSE.
func ValidateDescription(d *providerv1.DescribeResponse) error {
	invalid := func(format string, args ...any) error {
		return Errorf(providerv1.ErrorReason_ERROR_REASON_INVALID_RESPONSE, "description: "+format, args...)
	}
	switch {
	case d == nil:
		return invalid("missing")
	case !validName(d.GetProvider().GetName()) || d.GetProvider().GetVersion() < 1:
		return invalid("provider %q/v%d must be a lowercase DNS label at a version of at least 1", d.GetProvider().GetName(), d.GetProvider().GetVersion())
	case len(d.GetProtocolVersions()) == 0:
		return invalid("serves no protocol version")
	case d.GetEvaluatorVersion() < 1:
		return invalid("evaluator version %d must be at least 1", d.GetEvaluatorVersion())
	case d.GetPayload().GetWrite() < 1:
		return invalid("payload write version %d must be at least 1", d.GetPayload().GetWrite())
	case !slices.Contains(d.GetPayload().GetRead(), d.GetPayload().GetWrite()):
		return invalid("payload read versions %v must include write version %d: readers ship before writers", d.GetPayload().GetRead(), d.GetPayload().GetWrite())
	case len(d.GetCapabilities()) == 0:
		return invalid("declares no capability")
	case len(d.GetChecks()) == 0:
		return invalid("declares no check kind")
	case len(d.GetImplementation()) > MaxTextBytes:
		return invalid("implementation is longer than %d bytes", MaxTextBytes)
	}
	for i, v := range d.GetProtocolVersions() {
		if v < 1 || slices.Contains(d.GetProtocolVersions()[:i], v) {
			return invalid("protocol version %d is invalid or repeated", v)
		}
	}
	for i, v := range d.GetPayload().GetRead() {
		if v < 1 || slices.Contains(d.GetPayload().GetRead()[:i], v) {
			return invalid("payload read version %d is invalid or repeated", v)
		}
	}
	for i, capability := range d.GetCapabilities() {
		if !knownCapability(capability) || slices.Contains(d.GetCapabilities()[:i], capability) {
			return invalid("capability %s is unknown or repeated", capability)
		}
	}
	seen := map[string]bool{}
	for _, k := range d.GetChecks() {
		if !kindPattern.MatchString(k.GetKind()) || seen[k.GetKind()] {
			return invalid("check kind %q must look like group/version/Kind and be unique", k.GetKind())
		}
		seen[k.GetKind()] = true
	}
	return nil
}

// CheckCompatibility checks a validated description against an
// expectation, one dimension at a time and in this order: protocol
// revision, provider name, contract version, evaluator version, payload
// version, capabilities. The first mismatch is returned with its own
// reason; nothing is adapted.
func CheckCompatibility(want Compatibility, d *providerv1.DescribeResponse) error {
	if err := want.Validate(); err != nil {
		return err
	}
	if err := ValidateDescription(d); err != nil {
		return err
	}
	switch {
	case !slices.Contains(d.GetProtocolVersions(), ProtocolVersion):
		return Errorf(providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PROTOCOL_VERSION,
			"provider serves protocol revisions %v of konstapel.provider.v1, not %d", d.GetProtocolVersions(), ProtocolVersion)
	case d.GetProvider().GetName() != want.Provider:
		return Errorf(providerv1.ErrorReason_ERROR_REASON_PROVIDER_MISMATCH,
			"endpoint serves provider %q, the registration expects %q", d.GetProvider().GetName(), want.Provider)
	case d.GetProvider().GetVersion() != want.ContractVersion:
		return Errorf(providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CONTRACT_VERSION,
			"endpoint serves contract %s/v%d, the registration expects v%d", want.Provider, d.GetProvider().GetVersion(), want.ContractVersion)
	case d.GetEvaluatorVersion() != want.EvaluatorVersion:
		return Errorf(providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_EVALUATOR_VERSION,
			"endpoint evaluates with evaluator version %d, the registration expects %d", d.GetEvaluatorVersion(), want.EvaluatorVersion)
	}
	writes := want.allows(providerv1.Capability_CAPABILITY_COLLECT) || want.allows(providerv1.Capability_CAPABILITY_SCAN)
	if writes && d.GetPayload().GetWrite() != want.PayloadVersion {
		return Errorf(providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PAYLOAD_VERSION,
			"endpoint writes payload version %d, the registration stores %d", d.GetPayload().GetWrite(), want.PayloadVersion)
	}
	if !slices.Contains(d.GetPayload().GetRead(), want.PayloadVersion) {
		return Errorf(providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PAYLOAD_VERSION,
			"endpoint reads payload versions %v, not %d", d.GetPayload().GetRead(), want.PayloadVersion)
	}
	for _, capability := range want.Capabilities {
		if !slices.Contains(d.GetCapabilities(), capability) {
			return Errorf(providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CAPABILITY,
				"endpoint does not serve %s, which the registration allows", capability)
		}
	}
	return nil
}

// NegotiateLimits returns the stricter of each host bound and the
// provider's advertised bound. A zero advertised bound keeps the host's.
func NegotiateLimits(host, advertised *providerv1.Limits) *providerv1.Limits {
	out := &providerv1.Limits{
		MaxResultBytes:  stricter(host.GetMaxResultBytes(), DefaultMaxResultBytes),
		MaxChunkBytes:   stricter(host.GetMaxChunkBytes(), DefaultMaxChunkBytes),
		MaxObservations: stricter(host.GetMaxObservations(), DefaultMaxObservations),
		MaxSubjects:     stricter(host.GetMaxSubjects(), DefaultMaxSubjects),
		MaxEvidence:     stricter(host.GetMaxEvidence(), DefaultMaxEvidence),
	}
	out.MaxResultBytes = stricter(advertised.GetMaxResultBytes(), out.MaxResultBytes)
	out.MaxChunkBytes = stricter(advertised.GetMaxChunkBytes(), out.MaxChunkBytes)
	out.MaxObservations = stricter(advertised.GetMaxObservations(), out.MaxObservations)
	out.MaxSubjects = stricter(advertised.GetMaxSubjects(), out.MaxSubjects)
	out.MaxEvidence = stricter(advertised.GetMaxEvidence(), out.MaxEvidence)
	return out
}

// stricter is the smaller of a positive bound and a fallback.
func stricter[T uint32 | uint64](bound, fallback T) T {
	if bound > 0 && bound < fallback {
		return bound
	}
	return fallback
}

func validName(s string) bool { return len(s) <= 63 && namePattern.MatchString(s) }

func knownCapability(c providerv1.Capability) bool {
	switch c {
	case providerv1.Capability_CAPABILITY_COLLECT, providerv1.Capability_CAPABILITY_SCAN, providerv1.Capability_CAPABILITY_EVALUATE:
		return true
	}
	return false
}
