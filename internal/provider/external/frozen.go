package external

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

// DefaultTrustKey is the serverTrust ConfigMap key used when the
// registration names none (the CRD default).
const DefaultTrustKey = "ca.crt"

// Frozen is the registration identity one run or operation is frozen to
// when it starts (design.md section 6): the registration's UID, its
// configuration revision and the implementation identity the endpoint
// was observed to serve, with the endpoint configuration of that revision.
// It holds identities, versions and object names only, never credentials
// or certificates, and its JSON encoding is stable so the host can record
// it with the work.
type Frozen struct {
	// Registration is the AssessmentProvider's name.
	Registration string `json:"registration"`
	// UID is the registration's UID. A registration deleted and created
	// again under the same name is another registration.
	UID string `json:"uid"`
	// Revision is the registration's configuration revision, its
	// metadata.generation, at freezing.
	Revision int64 `json:"revision"`
	// Provider and ContractVersion are the contract "<name>/v<version>".
	Provider        string `json:"provider"`
	ContractVersion int32  `json:"contractVersion"`
	// ReleaseDigest is the implementation the endpoint reported, equal to
	// the registration's immutable release digest.
	ReleaseDigest string `json:"releaseDigest"`
	// Protocol and ProtocolRevision are the protocol major and the revision
	// of it the host speaks.
	Protocol         v1alpha1.ProviderProtocol `json:"protocol"`
	ProtocolRevision int32                     `json:"protocolRevision"`
	EvaluatorVersion int32                     `json:"evaluatorVersion"`
	PayloadVersion   int32                     `json:"payloadVersion"`
	// Capabilities are the capabilities the revision allows, sorted.
	Capabilities []v1alpha1.AssessmentProviderCapability `json:"capabilities"`
	Endpoint     Endpoint                                `json:"endpoint"`
}

// Endpoint is a revision's endpoint configuration: the Service, the server
// name the provider's certificate must carry, and the serverTrust
// ConfigMap in the controller namespace whose current roots authenticate
// it. The trust ConfigMap's contents are read at each connection, so its
// rotation applies to frozen work too; which ConfigMap is frozen.
type Endpoint struct {
	Namespace      string `json:"namespace"`
	Service        string `json:"service"`
	Port           int32  `json:"port"`
	ServerName     string `json:"serverName"`
	TrustConfigMap string `json:"trustConfigMap"`
	TrustKey       string `json:"trustKey"`
}

// Address is the Service's cluster DNS address, "<name>.<namespace>.svc:<port>".
// The registration has no URL, so the controller never dials anything else.
func (e Endpoint) Address() string {
	return e.Service + "." + e.Namespace + ".svc:" + strconv.Itoa(int(e.Port))
}

// Contract is "<provider>/v<contractVersion>".
func (f Frozen) Contract() string { return f.Provider + "/v" + strconv.Itoa(int(f.ContractVersion)) }

// Allows reports whether the frozen revision allows the capability.
func (f Frozen) Allows(c v1alpha1.AssessmentProviderCapability) bool {
	return slices.Contains(f.Capabilities, c)
}

// Compatibility is the kit expectation of the frozen identity.
func (f Frozen) Compatibility() providerkit.Compatibility {
	caps := make([]providerv1.Capability, 0, len(f.Capabilities))
	for _, c := range f.Capabilities {
		caps = append(caps, protoCapability(c))
	}
	return providerkit.Compatibility{Provider: f.Provider, ContractVersion: uint32(f.ContractVersion),
		PayloadVersion: uint32(f.PayloadVersion), EvaluatorVersion: uint32(f.EvaluatorVersion), Capabilities: caps}
}

// Expected is the identity and endpoint configuration a registration's
// current revision expects. It reads the spec only: whether the endpoint
// serves it is what probing observes.
func Expected(ap *v1alpha1.AssessmentProvider) Frozen {
	s := ap.Spec
	key := s.Endpoint.ServerTrust.Key
	if key == "" {
		key = DefaultTrustKey
	}
	caps := slices.Clone(s.Capabilities)
	slices.Sort(caps)
	caps = slices.Compact(caps)
	return Frozen{
		Registration: ap.Name, UID: string(ap.UID), Revision: ap.Generation,
		Provider: s.Provider.Name, ContractVersion: s.Compatibility.ContractVersion, ReleaseDigest: s.Provider.ReleaseDigest,
		Protocol: s.Compatibility.Protocol, ProtocolRevision: int32(providerkit.ProtocolVersion),
		EvaluatorVersion: s.Compatibility.EvaluatorVersion, PayloadVersion: s.Compatibility.PayloadVersion,
		Capabilities: caps,
		Endpoint: Endpoint{Namespace: s.Endpoint.Service.Namespace, Service: s.Endpoint.Service.Name, Port: s.Endpoint.Service.Port,
			ServerName: s.Endpoint.ServerName, TrustConfigMap: s.Endpoint.ServerTrust.Name, TrustKey: key},
	}
}

// FrozenReason is a bounded reason frozen work cannot continue.
type FrozenReason string

const (
	// FrozenRegistrationRemoved: the registration no longer exists.
	FrozenRegistrationRemoved FrozenReason = "RegistrationRemoved"
	// FrozenRegistrationReplaced: a registration of the same name has
	// another UID; it is never adopted by work frozen to the old one.
	FrozenRegistrationReplaced FrozenReason = "RegistrationReplaced"
	// FrozenRegistrationChanged: an immutable identity field differs from
	// the frozen one. The API rejects such edits; this is the host's own
	// check.
	FrozenRegistrationChanged FrozenReason = "RegistrationChanged"
	// FrozenCapabilityNotFrozen: the work needs a capability its frozen
	// revision did not allow. A later revision never widens frozen work.
	FrozenCapabilityNotFrozen FrozenReason = "CapabilityNotFrozen"
	// FrozenImplementationChanged: the endpoint no longer reports the
	// frozen implementation or compatibility; old work is rejected rather
	// than reinterpreted.
	FrozenImplementationChanged FrozenReason = "ImplementationChanged"
)

// FrozenError is why frozen work cannot continue.
type FrozenError struct {
	Reason  FrozenReason
	Message string
}

func (e *FrozenError) Error() string { return string(e.Reason) + ": " + e.Message }

// Continue reports whether work frozen to f may continue with the
// registration as it is now; current is nil when it is gone. Newer
// revisions do not stop it: the work keeps f's configuration, and
// newRequests Disabled lets it drain (bounded polling, cancellation and
// result handoff). Removal, replacement, a changed immutable identity, or
// a capability f does not allow end it.
func (f Frozen) Continue(current *v1alpha1.AssessmentProvider, need v1alpha1.AssessmentProviderCapability) error {
	switch {
	case current == nil:
		return &FrozenError{Reason: FrozenRegistrationRemoved,
			Message: fmt.Sprintf("registration %s (uid %s) of %s no longer exists", f.Registration, f.UID, f.Contract())}
	case string(current.UID) != f.UID:
		return &FrozenError{Reason: FrozenRegistrationReplaced,
			Message: fmt.Sprintf("registration %s is now uid %s; the work is frozen to uid %s", f.Registration, current.UID, f.UID)}
	}
	now := Expected(current)
	if now.Provider != f.Provider || now.ContractVersion != f.ContractVersion || now.ReleaseDigest != f.ReleaseDigest ||
		now.Protocol != f.Protocol || now.EvaluatorVersion != f.EvaluatorVersion || now.PayloadVersion != f.PayloadVersion {
		return &FrozenError{Reason: FrozenRegistrationChanged,
			Message: fmt.Sprintf("registration %s no longer names the frozen %s release %s", f.Registration, f.Contract(), f.ReleaseDigest)}
	}
	if need != "" && !f.Allows(need) {
		return &FrozenError{Reason: FrozenCapabilityNotFrozen,
			Message: fmt.Sprintf("revision %d of registration %s allows %v, not %s", f.Revision, f.Registration, f.Capabilities, need)}
	}
	return nil
}

// CheckDescription checks a description against the frozen identity: the
// kit's compatibility dimensions and the implementation. A compatible
// endpoint that reports another implementation is FrozenImplementationChanged.
func (f Frozen) CheckDescription(d *providerv1.DescribeResponse) error {
	if err := providerkit.CheckCompatibility(f.Compatibility(), d); err != nil {
		return err
	}
	if d.GetImplementation() != f.ReleaseDigest {
		return &FrozenError{Reason: FrozenImplementationChanged,
			Message: fmt.Sprintf("endpoint reports implementation %q, not the registered release %s", bound(d.GetImplementation(), 80), f.ReleaseDigest)}
	}
	return nil
}

func protoCapability(c v1alpha1.AssessmentProviderCapability) providerv1.Capability {
	switch c {
	case v1alpha1.ProviderCapabilityCollect:
		return providerv1.Capability_CAPABILITY_COLLECT
	case v1alpha1.ProviderCapabilityScan:
		return providerv1.Capability_CAPABILITY_SCAN
	case v1alpha1.ProviderCapabilityEvaluate:
		return providerv1.Capability_CAPABILITY_EVALUATE
	}
	return providerv1.Capability_CAPABILITY_UNSPECIFIED
}

// bound truncates s to at most n bytes on a rune boundary.
func bound(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "..."
}
