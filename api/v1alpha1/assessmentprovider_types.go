package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AssessmentProvider registers one independently installed external
// assessment provider service (add-external-assessment-providers). It is
// administrator configuration: registrations are written only through the
// dedicated, non-aggregated konstapel-assessment-provider-admin role, never
// by bundles, namespace teams or the controller. The platform installs the
// provider workload itself; a registration only tells Konstapel where the
// already installed service is, which server identity and release to
// expect, and which compatibility and capabilities it may use.
//
// The registration is a claim checked against the endpoint, not proof of
// the running container: verifying and installing the digest-pinned image
// is the installation boundary. Nothing here carries credentials. The
// controller's own client certificate is deployment configuration, not
// part of any registration.

// AssessmentProviderCapability is one operation group of the
// konstapel.provider.v1 protocol that a registration allows. The endpoint
// must serve every allowed capability; the controller sends nothing outside
// them.
// +kubebuilder:validation:Enum=Collect;Scan;Evaluate
type AssessmentProviderCapability string

const (
	// ProviderCapabilityCollect allows read-only collection of existing
	// evidence for a host-frozen scope. It never starts a scan.
	ProviderCapabilityCollect AssessmentProviderCapability = "Collect"
	// ProviderCapabilityScan allows optional scan operations
	// (Start/Get/Cancel). Allowing it is the administrator's authorization
	// for fresh-evidence requests to this provider.
	ProviderCapabilityScan AssessmentProviderCapability = "Scan"
	// ProviderCapabilityEvaluate allows pure evaluation of frozen inputs,
	// including replay of retained captures.
	ProviderCapabilityEvaluate AssessmentProviderCapability = "Evaluate"
)

// ProviderProtocol is the major version of the external provider wire
// protocol: its protobuf package. A breaking protocol change is a new
// package and a new value here; revisions within a major are not
// registration configuration.
// +kubebuilder:validation:Enum=konstapel.provider.v1
type ProviderProtocol string

// ProviderProtocolV1 is the protocol published as
// proto/konstapel/provider/v1 and pkg/providerapi/v1.
const ProviderProtocolV1 ProviderProtocol = "konstapel.provider.v1"

// ProviderNewRequests says whether new work may use a registration.
// +kubebuilder:validation:Enum=Enabled;Disabled
type ProviderNewRequests string

const (
	// ProviderNewRequestsEnabled lets new runs select the registration and
	// new operations start on it. It is the default.
	ProviderNewRequestsEnabled ProviderNewRequests = "Enabled"
	// ProviderNewRequestsDisabled blocks new work: no new run selects the
	// registration and no new operation starts. Operations already frozen
	// to it can still be polled, cancelled and hand off their results,
	// within their bounds, so a provider can be drained before it is
	// uninstalled.
	ProviderNewRequestsDisabled ProviderNewRequests = "Disabled"
)

// ProviderServiceReference names the Kubernetes Service in front of the
// installed provider. The controller connects only to
// <name>.<namespace>.svc:<port>; there is no URL, so a registration can
// never point the controller at an arbitrary address.
type ProviderServiceReference struct {
	// namespace of the Service (a DNS label).
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Namespace string `json:"namespace"`

	// name of the Service (a DNS-1035 label).
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// port is the Service port serving the protocol.
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// ProviderEndpoint is where and how the controller reaches the provider:
// mutual TLS to the Service, with an explicit server name and trust. No
// assessment payload is sent before the server is authenticated, TLS
// verification is never disabled, and there is no plaintext mode.
type ProviderEndpoint struct {
	// service is the Service in front of the provider.
	// +required
	Service ProviderServiceReference `json:"service"`

	// serverName is the DNS name the provider's serving certificate must
	// carry as a DNS subject alternative name: the one server name the
	// controller authorizes, whatever address it connects to. Common
	// names, URIs, IP addresses and wildcard names in the certificate never
	// match it. It is explicit, never derived from the Service, and a
	// lowercase RFC 1123 DNS name without a wildcard, trailing dot or IP
	// address. A URI (for example SPIFFE) server identity, if one is ever
	// supported, will be a separate optional field; serverName stays a DNS
	// name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$`
	// +kubebuilder:validation:XValidation:rule="!self.matches('^[0-9.]+$')",message="serverName must be a DNS name, not an IP address"
	ServerName string `json:"serverName"`

	// serverTrust names the ConfigMap in the controller namespace whose PEM
	// roots alone verify the provider's serving certificate; system roots
	// are never used. Rotatable: replace the roots, or point at another
	// ConfigMap.
	// +required
	ServerTrust CATrust `json:"serverTrust"`
}

// ExpectedProvider is the identity the endpoint must report.
type ExpectedProvider struct {
	// name is the provider identity: the name bundles select as
	// compatibility.provider "<name>/v<contractVersion>", a lowercase DNS
	// label. konstapel and konstapel-* are reserved for providers built
	// into Konstapel, so a registration never shadows one. Immutable.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]+(-[a-z0-9]+)*$`
	// +kubebuilder:validation:XValidation:rule="self != 'konstapel' && !self.startsWith('konstapel-')",message="provider names konstapel and konstapel-* are reserved for built-in providers"
	Name string `json:"name"`

	// releaseDigest ("sha256:" and 64 lowercase hex digits) identifies the
	// provider release the platform verified and installed, as the endpoint
	// reports it (its implementation). It is a content digest, never a
	// tag. Immutable: a new release, compatible or not, is registered as a
	// new AssessmentProvider, so every operation's frozen registration
	// names exactly one release.
	// +required
	// +kubebuilder:validation:MaxLength=71
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	ReleaseDigest string `json:"releaseDigest"`
}

// ProviderCompatibility is what the endpoint must serve, one dimension at
// a time; none implies another and nothing is negotiated downward. It is
// immutable: an incompatible release is registered as a new
// AssessmentProvider (and served from its own endpoint), so no operation
// is ever silently reinterpreted.
type ProviderCompatibility struct {
	// protocol is the wire protocol's major version.
	// +required
	Protocol ProviderProtocol `json:"protocol"`

	// contractVersion is the provider contract version bundles select
	// ("<name>/v<contractVersion>").
	// +required
	// +kubebuilder:validation:Minimum=1
	ContractVersion int32 `json:"contractVersion"`

	// evaluatorVersion is the evaluation semantics the endpoint must have.
	// +required
	// +kubebuilder:validation:Minimum=1
	EvaluatorVersion int32 `json:"evaluatorVersion"`

	// payloadVersion is the evidence payload version Konstapel stores for
	// this provider: the endpoint must write it when Collect or Scan is
	// allowed, and read it.
	// +required
	// +kubebuilder:validation:Minimum=1
	PayloadVersion int32 `json:"payloadVersion"`
}

// AssessmentProviderSpec is the administrator's registration. The provider
// name, release digest and compatibility are immutable; the endpoint, trust,
// capabilities and newRequests can change, and each change is a new
// configuration revision (metadata.generation) that only new work uses.
// +kubebuilder:validation:XValidation:rule="self.provider.name == oldSelf.provider.name && self.compatibility == oldSelf.compatibility",message="provider.name and compatibility are immutable; register an incompatible release as a new AssessmentProvider"
// +kubebuilder:validation:XValidation:rule="self.provider.releaseDigest == oldSelf.provider.releaseDigest",message="provider.releaseDigest is immutable; register a new release as a new AssessmentProvider"
type AssessmentProviderSpec struct {
	// provider is the identity the endpoint must report.
	// +required
	Provider ExpectedProvider `json:"provider"`

	// endpoint is the Service, server name and trust of the provider.
	// +required
	Endpoint ProviderEndpoint `json:"endpoint"`

	// compatibility is the protocol, contract, evaluator and payload the
	// endpoint must serve. Immutable.
	// +required
	Compatibility ProviderCompatibility `json:"compatibility"`

	// capabilities are the operation groups this registration allows, at
	// least one. Scan is the administrator's authorization for
	// fresh-evidence requests; without it no scan is ever started.
	// +required
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=3
	Capabilities []AssessmentProviderCapability `json:"capabilities"`

	// newRequests is Enabled (the default) or Disabled. Disabled blocks new
	// work but lets operations already frozen to the registration finish,
	// cancel and hand off their results.
	// +optional
	// +kubebuilder:default=Enabled
	NewRequests ProviderNewRequests `json:"newRequests,omitempty"`
}

// ObservedProviderIdentity is the identity the endpoint presented when the
// controller last found it compatible with the registration. It holds
// identities and versions only, never credentials or certificates.
type ObservedProviderIdentity struct {
	// name is the provider identity the endpoint reported.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]+(-[a-z0-9]+)*$`
	Name string `json:"name"`

	// releaseDigest is the implementation the endpoint reported.
	// +required
	// +kubebuilder:validation:MaxLength=71
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	ReleaseDigest string `json:"releaseDigest"`

	// protocol and protocolRevision are the protocol major and the
	// revision of it the controller speaks to the endpoint.
	// +required
	Protocol ProviderProtocol `json:"protocol"`
	// +required
	// +kubebuilder:validation:Minimum=1
	ProtocolRevision int32 `json:"protocolRevision"`

	// contractVersion, evaluatorVersion and payloadVersion are the
	// compatible versions the endpoint serves.
	// +required
	// +kubebuilder:validation:Minimum=1
	ContractVersion int32 `json:"contractVersion"`
	// +required
	// +kubebuilder:validation:Minimum=1
	EvaluatorVersion int32 `json:"evaluatorVersion"`
	// +required
	// +kubebuilder:validation:Minimum=1
	PayloadVersion int32 `json:"payloadVersion"`

	// capabilities are the allowed capabilities the endpoint serves.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=3
	Capabilities []AssessmentProviderCapability `json:"capabilities,omitempty"`

	// observedAt is when the controller checked the endpoint.
	// +required
	ObservedAt metav1.Time `json:"observedAt"`
}

// Condition types reported on AssessmentProvider status
// (add-external-assessment-providers 2.2). They describe the endpoint's
// availability and compatibility, never an assessment's findings, and their
// messages never carry credentials, keys or certificate contents.
const (
	// ProviderConditionAvailable is True when the controller reached the
	// Service, authenticated the provider over mutual TLS with the
	// registration's server name and trust, and the endpoint described
	// itself within the probe deadline.
	ProviderConditionAvailable = "Available"
	// ProviderConditionCompatible is True when the description matches the
	// registration in every dimension: provider name, release digest,
	// protocol, contract, evaluator and payload versions and the allowed
	// capabilities. It is Unknown while the endpoint is not available.
	ProviderConditionCompatible = "Compatible"
	// ProviderConditionReady is True when new work may select the
	// registration: it is available, compatible, newRequests is Enabled and
	// no other Enabled registration names the same provider contract.
	ProviderConditionReady = "Ready"
)

// Condition reasons reported on AssessmentProvider status. The set is
// closed: every condition uses one of these.
const (
	// ProviderReasonAvailable: the endpoint was authenticated and described.
	ProviderReasonAvailable = "Available"
	// ProviderReasonTrustUnavailable: the serverTrust ConfigMap, its key or
	// its PEM roots are missing or invalid. Nothing is sent.
	ProviderReasonTrustUnavailable = "TrustUnavailable"
	// ProviderReasonClientCredentialsUnavailable: the controller's own
	// client certificate or key is missing, invalid or expired. Nothing is
	// sent.
	ProviderReasonClientCredentialsUnavailable = "ClientCredentialsUnavailable"
	// ProviderReasonEndpointUnavailable: the Service did not accept a
	// connection or did not answer within the probe deadline.
	ProviderReasonEndpointUnavailable = "EndpointUnavailable"
	// ProviderReasonAuthenticationFailed: the endpoint did not complete a
	// mutually authenticated TLS 1.3 handshake for serverName: an untrusted
	// or expired certificate, another server name, or a rejected client.
	ProviderReasonAuthenticationFailed = "AuthenticationFailed"
	// ProviderReasonInvalidDescription: the endpoint's description violates
	// the protocol.
	ProviderReasonInvalidDescription = "InvalidDescription"
	// ProviderReasonNotChecked: compatibility was not checked because the
	// endpoint is not available.
	ProviderReasonNotChecked = "NotChecked"
	// ProviderReasonCompatible: the description matches the registration.
	ProviderReasonCompatible = "Compatible"
	// ProviderReasonProviderMismatch: the endpoint serves another provider.
	ProviderReasonProviderMismatch = "ProviderMismatch"
	// ProviderReasonReleaseMismatch: the endpoint reports another
	// implementation than spec.provider.releaseDigest.
	ProviderReasonReleaseMismatch = "ReleaseMismatch"
	// ProviderReasonUnsupportedProtocolVersion: the endpoint does not serve
	// the protocol revision the controller speaks.
	ProviderReasonUnsupportedProtocolVersion = "UnsupportedProtocolVersion"
	// ProviderReasonUnsupportedContractVersion: the endpoint serves another
	// contract version.
	ProviderReasonUnsupportedContractVersion = "UnsupportedContractVersion"
	// ProviderReasonUnsupportedEvaluatorVersion: the endpoint evaluates with
	// another evaluator version.
	ProviderReasonUnsupportedEvaluatorVersion = "UnsupportedEvaluatorVersion"
	// ProviderReasonUnsupportedPayloadVersion: the endpoint does not write
	// or read the registration's payload version.
	ProviderReasonUnsupportedPayloadVersion = "UnsupportedPayloadVersion"
	// ProviderReasonUnsupportedCapability: the endpoint does not serve a
	// capability the registration allows.
	ProviderReasonUnsupportedCapability = "UnsupportedCapability"
	// ProviderReasonBuiltInProvider: the registration names a provider built
	// into Konstapel. It is never contacted or selected; built-in providers
	// are never shadowed.
	ProviderReasonBuiltInProvider = "BuiltInProvider"
	// ProviderReasonReady: new work may select the registration.
	ProviderReasonReady = "Ready"
	// ProviderReasonUnavailable: Ready is False because Available is.
	ProviderReasonUnavailable = "Unavailable"
	// ProviderReasonIncompatible: Ready is False because Compatible is.
	ProviderReasonIncompatible = "Incompatible"
	// ProviderReasonNewRequestsDisabled: newRequests is Disabled. Work
	// already frozen to the registration may still drain.
	ProviderReasonNewRequestsDisabled = "NewRequestsDisabled"
	// ProviderReasonAmbiguousRegistration: another Enabled registration
	// names the same provider contract, so neither is selected for new
	// work until all but one are Disabled.
	ProviderReasonAmbiguousRegistration = "AmbiguousRegistration"
)

// AssessmentProviderStatus is written only by the Konstapel controller
// (RBAC, and the konstapel-assessment-provider-status-writer admission
// policy). It never holds credentials, keys, certificates or Secret
// contents.
type AssessmentProviderStatus struct {
	// observedGeneration is the registration generation the status
	// describes.
	// +optional
	// +kubebuilder:validation:Minimum=0
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions report the registration's availability and compatibility,
	// separately from any assessment's findings.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// identity is the observed compatible identity; absent while none has
	// been observed for observedGeneration.
	// +optional
	Identity *ObservedProviderIdentity `json:"identity,omitempty"`
}

// AssessmentProvider is an administrator's registration of one external
// assessment provider service.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=aprovider
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=`.spec.provider.name`
// +kubebuilder:printcolumn:name="Contract",type=integer,JSONPath=`.spec.compatibility.contractVersion`
// +kubebuilder:printcolumn:name="Service",type=string,JSONPath=`.spec.endpoint.service.name`
// +kubebuilder:printcolumn:name="New Requests",type=string,JSONPath=`.spec.newRequests`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="!has(self.status) || !has(self.status.identity) || (self.status.identity.name == self.spec.provider.name && self.status.identity.protocol == self.spec.compatibility.protocol && self.status.identity.contractVersion == self.spec.compatibility.contractVersion && self.status.identity.evaluatorVersion == self.spec.compatibility.evaluatorVersion && self.status.identity.payloadVersion == self.spec.compatibility.payloadVersion)",message="status.identity must have the registration's provider name and compatibility"
type AssessmentProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec AssessmentProviderSpec `json:"spec"`

	// +optional
	Status AssessmentProviderStatus `json:"status,omitzero"`
}

// AssessmentProviderList contains a list of AssessmentProvider.
// +kubebuilder:object:root=true
type AssessmentProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AssessmentProvider `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AssessmentProvider{}, &AssessmentProviderList{})
}
