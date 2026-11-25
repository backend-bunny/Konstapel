package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EvidenceSigningRequest asks the controller to finish the signed
// publication of one retained SigningFailed AssessmentRun with its staged
// archive and original signing intent (add-evidence-signing-recovery). It is
// an administrator action and the audit record of that action: requests are
// created through the dedicated konstapel-evidence-signing-recoverer role,
// attributed by admission, never owned by the run, and kept after the run is
// deleted. Deleting one needs a separate cluster-administrator grant.

// SigningRequestPhase is an EvidenceSigningRequest's lifecycle. Succeeded and
// Failed are terminal: a terminal request is never re-evaluated and its
// status never changes again.
// +kubebuilder:validation:Enum=Pending;Running;Succeeded;Failed
type SigningRequestPhase string

const (
	SigningRequestPending   SigningRequestPhase = "Pending"
	SigningRequestRunning   SigningRequestPhase = "Running"
	SigningRequestSucceeded SigningRequestPhase = "Succeeded"
	SigningRequestFailed    SigningRequestPhase = "Failed"
)

// Terminal reports whether p is a terminal phase.
func (p SigningRequestPhase) Terminal() bool {
	return p == SigningRequestSucceeded || p == SigningRequestFailed
}

// SigningRecoveryReason is the fixed reason vocabulary of an
// EvidenceSigningRequest; SigningRecoveryReasons maps each phase to the
// reasons allowed with it. None of them changes the run's evidence summary,
// completeness, outcomes, or export kind.
// +kubebuilder:validation:Enum=Accepted;Waiting;Signing;Committing;Recovered;AlreadyRecovered;RunNotFound;RunDeleting;NotRecoverable;Expired;Orphaned;EvidenceLost;KeyConfirmationRequired;KeyMismatch;SigningFailed;Conflict
type SigningRecoveryReason string

const (
	// RecoveryAccepted: the controller accepted the request and recorded its
	// requester and run.
	RecoveryAccepted SigningRecoveryReason = "Accepted"
	// RecoveryWaiting: another request holds the run's recovery claim.
	RecoveryWaiting SigningRecoveryReason = "Waiting"
	// RecoverySigning and RecoveryCommitting: the request holds the claim and
	// is signing (or reusing a stored signature) or committing.
	RecoverySigning    SigningRecoveryReason = "Signing"
	RecoveryCommitting SigningRecoveryReason = "Committing"
	// RecoveryRecovered: this request committed (or adopted) the signed
	// publication. RecoveryAlreadyRecovered: the run was already recovered;
	// the request references that publication and wrote nothing to storage.
	RecoveryRecovered        SigningRecoveryReason = "Recovered"
	RecoveryAlreadyRecovered SigningRecoveryReason = "AlreadyRecovered"
	// RecoveryRunNotFound: no run has the requested name and UID.
	RecoveryRunNotFound SigningRecoveryReason = "RunNotFound"
	// RecoveryRunDeleting: the run is being deleted.
	RecoveryRunDeleting SigningRecoveryReason = "RunDeleting"
	// RecoveryNotRecoverable: the run is not a retained SigningFailed run
	// with a Required signing intent.
	RecoveryNotRecoverable SigningRecoveryReason = "NotRecoverable"
	// RecoveryExpired: the run's recorded expiry has passed (or a new commit
	// landed at or after it).
	RecoveryExpired SigningRecoveryReason = "Expired"
	// RecoveryOrphaned: the pinned destination is gone, replaced, or handed
	// off.
	RecoveryOrphaned SigningRecoveryReason = "Orphaned"
	// RecoveryEvidenceLost: the staged archive is missing or has a digest
	// other than the intent's.
	RecoveryEvidenceLost SigningRecoveryReason = "EvidenceLost"
	// RecoveryKeyConfirmationRequired: the intent never pinned a key and the
	// request states no expectedKeyFingerprint.
	RecoveryKeyConfirmationRequired SigningRecoveryReason = "KeyConfirmationRequired"
	// RecoveryKeyMismatch: the intent's Secret holds a key other than the
	// pinned (or confirmed) one.
	RecoveryKeyMismatch SigningRecoveryReason = "KeyMismatch"
	// RecoverySigningFailed: the attempt deadline passed without a durable
	// recovery; the run keeps its retained failure and a new request can try.
	RecoverySigningFailed SigningRecoveryReason = "SigningFailed"
	// RecoveryConflict: storage holds a conflicting commit or a stored
	// signature that does not verify; nothing is overwritten.
	RecoveryConflict SigningRecoveryReason = "Conflict"
)

// SigningRecoveryReasons is the reason vocabulary of each phase. The CRD
// enforces the same pairs.
var SigningRecoveryReasons = map[SigningRequestPhase][]SigningRecoveryReason{
	SigningRequestPending:   {RecoveryAccepted, RecoveryWaiting},
	SigningRequestRunning:   {RecoverySigning, RecoveryCommitting},
	SigningRequestSucceeded: {RecoveryRecovered, RecoveryAlreadyRecovered},
	SigningRequestFailed: {RecoveryRunNotFound, RecoveryRunDeleting, RecoveryNotRecoverable, RecoveryExpired, RecoveryOrphaned,
		RecoveryEvidenceLost, RecoveryKeyConfirmationRequired, RecoveryKeyMismatch, RecoverySigningFailed, RecoveryConflict},
}

// ConditionSigningRequestComplete is True exactly when an
// EvidenceSigningRequest reached a terminal phase, with that phase's reason.
const ConditionSigningRequestComplete = "Complete"

// ExactRunReference names an AssessmentRun and the UID it must have. A run
// recreated under the same name has another UID and never matches.
type ExactRunReference struct {
	// name is the AssessmentRun's name (a DNS subdomain).
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	Name string `json:"name"`
	// uid is the run's metadata.uid.
	// +required
	// +kubebuilder:validation:MaxLength=36
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
	UID string `json:"uid"`
}

// EvidenceSigningRequestSpec is immutable: a corrected request is a new
// EvidenceSigningRequest.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable; create a new EvidenceSigningRequest"
type EvidenceSigningRequestSpec struct {
	// run is the retained SigningFailed AssessmentRun to recover, by name and
	// UID. Admission does not look it up; the controller reports RunNotFound.
	// +required
	Run ExactRunReference `json:"run"`

	// reason is free text for the audit trail. It must not be blank.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	// +kubebuilder:validation:XValidation:rule="self.trim().size() > 0",message="reason must not be blank"
	Reason string `json:"reason"`

	// expectedKeyFingerprint ("sha256:" and 64 lowercase hex digits)
	// confirms the key in the intent's recorded Secret when the intent never
	// pinned one. It authorizes initial key selection; it does not prove a
	// previously established key identity. A pinned intent ignores it: only
	// the pinned key is ever used.
	// +optional
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	ExpectedKeyFingerprint string `json:"expectedKeyFingerprint,omitempty"`

	// requestedBy is the authenticated identity that created the request.
	// The konstapel-evidence-signing-requester admission policies set it
	// from the API server's user info on create; user-supplied values are
	// overwritten and mismatches are rejected.
	// +optional
	RequestedBy *Requester `json:"requestedBy,omitempty"`
}

// SigningRecoveryPublication is the signed publication a successful request
// committed or adopted.
type SigningRecoveryPublication struct {
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	PublicationID string `json:"publicationID"`
	// packageSha256 and signatureSha256 are the lowercase hex digests of the
	// committed archive and its signature bundle.
	// +required
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	PackageSHA256 string `json:"packageSha256"`
	// +required
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	SignatureSHA256 string `json:"signatureSha256"`
	// publishedAt is the storage commit time; expiresAt the commit's fixed
	// expiry.
	// +required
	PublishedAt metav1.Time `json:"publishedAt"`
	// +required
	ExpiresAt metav1.Time `json:"expiresAt"`
}

// EvidenceSigningRequestStatus is written only by the Konstapel controller
// (RBAC and the konstapel-evidence-signing-status-writer admission policy).
// It never holds key bytes, Secret names, or Secret contents. Once the phase
// is terminal the status never changes; the recorded requester and run are
// set once.
// +kubebuilder:validation:XValidation:rule="has(self.phase) == has(self.reason)",message="phase and reason are set together"
// +kubebuilder:validation:XValidation:rule="!has(self.phase) || !has(self.reason) || (self.phase == 'Pending' && self.reason in ['Accepted', 'Waiting']) || (self.phase == 'Running' && self.reason in ['Signing', 'Committing']) || (self.phase == 'Succeeded' && self.reason in ['Recovered', 'AlreadyRecovered']) || (self.phase == 'Failed' && self.reason in ['RunNotFound', 'RunDeleting', 'NotRecoverable', 'Expired', 'Orphaned', 'EvidenceLost', 'KeyConfirmationRequired', 'KeyMismatch', 'SigningFailed', 'Conflict'])",message="reason is not in the phase's vocabulary"
// +kubebuilder:validation:XValidation:rule="!has(self.phase) || !(self.phase in ['Succeeded', 'Failed']) || has(self.completedAt)",message="a terminal phase records completedAt"
// +kubebuilder:validation:XValidation:rule="!has(self.phase) || self.phase != 'Succeeded' || (has(self.publication) && has(self.keyFingerprint))",message="a successful request records its publication and key fingerprint"
// +kubebuilder:validation:XValidation:rule="(has(self.phase) && self.phase in ['Succeeded', 'Failed']) == (has(self.conditions) && self.conditions.exists(c, c.type == 'Complete' && c.status == 'True'))",message="the Complete condition is True exactly on a terminal phase"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.phase) || !(oldSelf.phase in ['Succeeded', 'Failed']) || self == oldSelf",message="a terminal outcome is never rewritten"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.requestedBy) || (has(self.requestedBy) && self.requestedBy == oldSelf.requestedBy)",message="the recorded requester is set once"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.run) || (has(self.run) && self.run == oldSelf.run)",message="the recorded run is set once"
type EvidenceSigningRequestStatus struct {
	// +optional
	Phase SigningRequestPhase `json:"phase,omitempty"`
	// reason is the phase's fixed reason (see SigningRecoveryReasons).
	// +optional
	Reason SigningRecoveryReason `json:"reason,omitempty"`
	// message explains the reason. It never holds key or Secret bytes.
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	Message string `json:"message,omitempty"`
	// requestedBy is spec.requestedBy, copied at acceptance.
	// +optional
	RequestedBy *Requester `json:"requestedBy,omitempty"`
	// run is spec.run as observed at acceptance.
	// +optional
	Run *ExactRunReference `json:"run,omitempty"`
	// keyFingerprint is the intent key used or confirmed, never the Secret
	// name.
	// +optional
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	KeyFingerprint string `json:"keyFingerprint,omitempty"`
	// publication is the committed or adopted signed publication (Succeeded
	// only).
	// +optional
	Publication *SigningRecoveryPublication `json:"publication,omitempty"`
	// acceptedAt, startedAt and completedAt are controller times.
	// +optional
	AcceptedAt *metav1.Time `json:"acceptedAt,omitempty"`
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`
	// +optional
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// EvidenceSigningRequest is an administrator's attributed request to finish
// the signed publication of one retained SigningFailed AssessmentRun with its
// existing archive and original signing intent. It never recollects
// evidence, changes outcomes, extends expiry, or substitutes a key.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=esreq
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Run",type=string,JSONPath=`.spec.run.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Reason",type=string,JSONPath=`.status.reason`
// +kubebuilder:printcolumn:name="Requested By",type=string,JSONPath=`.spec.requestedBy.username`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="!has(self.status) || !has(self.status.run) || (self.status.run.name == self.spec.run.name && self.status.run.uid == self.spec.run.uid)",message="status.run must be spec.run"
// +kubebuilder:validation:XValidation:rule="!has(self.status) || !has(self.status.requestedBy) || (has(self.spec.requestedBy) && self.status.requestedBy.username == self.spec.requestedBy.username && (has(self.status.requestedBy.uid) && self.status.requestedBy.uid.size() > 0) == (has(self.spec.requestedBy.uid) && self.spec.requestedBy.uid.size() > 0) && (!has(self.status.requestedBy.uid) || self.status.requestedBy.uid.size() == 0 || self.status.requestedBy.uid == self.spec.requestedBy.uid))",message="status.requestedBy must be spec.requestedBy"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.status) || ((!has(oldSelf.status.phase) || !(oldSelf.status.phase in ['Succeeded', 'Failed'])) && !has(oldSelf.status.requestedBy) && !has(oldSelf.status.run)) || has(self.status)",message="a recorded request status is never removed"
type EvidenceSigningRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec EvidenceSigningRequestSpec `json:"spec"`
	// +optional
	Status EvidenceSigningRequestStatus `json:"status,omitzero"`
}

// EvidenceSigningRequestList contains a list of EvidenceSigningRequest.
// +kubebuilder:object:root=true
type EvidenceSigningRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EvidenceSigningRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EvidenceSigningRequest{}, &EvidenceSigningRequestList{})
}
