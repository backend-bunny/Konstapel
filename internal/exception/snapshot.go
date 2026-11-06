package exception

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// SnapshotVersion versions the snapshot document format.
const SnapshotVersion = 1

// Snapshot is the immutable record of one acceptance revision (design §3).
// It is copied from the admission-protected acceptance record and the
// exception spec at that revision; it is never re-resolved, so later
// configuration cannot change what was accepted.
type Snapshot struct {
	Version   int    `json:"version"`
	Cluster   string `json:"cluster"`
	Exception struct {
		Name      string    `json:"name"`
		Namespace string    `json:"namespace"`
		UID       types.UID `json:"uid"`
	} `json:"exception"`
	AcceptanceRevision int64                  `json:"acceptanceRevision"`
	Namespace          targeting.NamespaceRef `json:"namespace"`
	Policy             string                 `json:"policy"`
	WorkloadSelector   metav1.LabelSelector   `json:"workloadSelector"`
	Reason             string                 `json:"reason"`
	Actor              Actor                  `json:"actor"`
	Claim              string                 `json:"claim,omitempty"`
	AcceptedAt         metav1.Time            `json:"acceptedAt"`
	ExpiresAt          metav1.Time            `json:"expiresAt"`
	// Eligibility is the accepted contribution/revision set.
	Eligibility targeting.Eligibility `json:"eligibility"`
}

// Labels and keys on snapshot ConfigMaps. Labels support selection by the
// assessment collector without listing every ConfigMap.
const (
	SnapshotDataKey          = "acceptance.json"
	LabelComponent           = "app.kubernetes.io/component"
	ComponentSnapshot        = "acceptance-snapshot"
	LabelExceptionUID        = "compliance.erenius.io/exception-uid"
	LabelNamespaceUID        = "compliance.erenius.io/namespace-uid"
	LabelAcceptanceRevision  = "compliance.erenius.io/acceptance-revision"
	AnnotationSnapshotDigest = "compliance.erenius.io/snapshot-digest"
	// RevisionLabelPrefix + RevisionLabel(rev) is set to "true" for every
	// accepted contribution revision.
	RevisionLabelPrefix = "revision.compliance.erenius.io/"
)

// RevisionLabel is the label key, under RevisionLabelPrefix, for a
// contribution revision ("sha256:<hex>"): the first 40 hex characters,
// matching targeting.LabelPolicyHash.
func RevisionLabel(revision string) string {
	h := strings.TrimPrefix(revision, "sha256:")
	if len(h) > 40 {
		h = h[:40]
	}
	return RevisionLabelPrefix + h
}

// ParseAcceptance reads the protected acceptance record of an exception.
func ParseAcceptance(ex *v1alpha1.ComplianceException) (Acceptance, bool, error) {
	raw, ok := ex.Annotations[AcceptanceAnnotation]
	if !ok {
		return Acceptance{}, false, nil
	}
	var a Acceptance
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		return Acceptance{}, true, err
	}
	return a, true, nil
}

// NewSnapshot builds the snapshot of the exception's current acceptance. The
// record must belong to the spec's acceptance revision and carry a resolved
// set; admission guarantees both.
func NewSnapshot(ex *v1alpha1.ComplianceException, a Acceptance) (*Snapshot, error) {
	switch {
	case a.Revision != ex.Spec.AcceptanceRevision:
		return nil, fmt.Errorf("acceptance record is for revision %d, spec is at %d", a.Revision, ex.Spec.AcceptanceRevision)
	case a.Eligibility == nil:
		return nil, fmt.Errorf("acceptance record has no resolved contribution set")
	case a.Namespace.Name != ex.Namespace || a.Policy != ex.Spec.Policy:
		return nil, fmt.Errorf("acceptance record does not match the exception's namespace or policy")
	case ex.Spec.WorkloadSelector == nil:
		return nil, fmt.Errorf("exception has no workload selector")
	}
	s := &Snapshot{Version: SnapshotVersion, Cluster: a.Cluster, AcceptanceRevision: a.Revision, Namespace: a.Namespace,
		Policy: a.Policy, WorkloadSelector: *ex.Spec.WorkloadSelector.DeepCopy(), Reason: ex.Spec.Reason, Actor: a.Actor,
		Claim: a.Claim, AcceptedAt: a.AcceptedAt, ExpiresAt: ex.Spec.ExpiresAt, Eligibility: *a.Eligibility}
	s.Exception.Name, s.Exception.Namespace, s.Exception.UID = ex.Name, ex.Namespace, ex.UID
	return s, nil
}

// Document returns the snapshot's canonical JSON and its sha256 digest.
func (s *Snapshot) Document() ([]byte, string, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, "sha256:" + hex.EncodeToString(sum[:]), nil
}

// SnapshotName is the ConfigMap name for one acceptance revision of an
// exception. Exception UIDs are unique, so a recreated exception never
// reuses a name.
func SnapshotName(exceptionUID types.UID, revision int64) string {
	return "acceptance-" + string(exceptionUID) + "-" + strconv.FormatInt(revision, 10)
}

// ConfigMap renders the immutable snapshot ConfigMap in namespace.
func (s *Snapshot) ConfigMap(namespace string) (*corev1.ConfigMap, string, error) {
	raw, digest, err := s.Document()
	if err != nil {
		return nil, "", err
	}
	labels := map[string]string{
		targeting.LabelManagedBy:  targeting.ManagedByValue,
		LabelComponent:            ComponentSnapshot,
		LabelExceptionUID:         string(s.Exception.UID),
		LabelNamespaceUID:         string(s.Namespace.UID),
		LabelAcceptanceRevision:   strconv.FormatInt(s.AcceptanceRevision, 10),
		targeting.LabelPolicyHash: targeting.PolicyHash(s.Policy),
	}
	for _, c := range s.Eligibility.Contributors {
		labels[RevisionLabel(c.Revision)] = "true"
	}
	immutable := true
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: SnapshotName(s.Exception.UID, s.AcceptanceRevision), Namespace: namespace,
			Labels: labels, Annotations: map[string]string{AnnotationSnapshotDigest: digest}},
		Immutable: &immutable,
		Data:      map[string]string{SnapshotDataKey: string(raw)},
	}, digest, nil
}

// SnapshotFrom reads and verifies a snapshot ConfigMap: its document must
// match the digest it was written with.
func SnapshotFrom(cm *corev1.ConfigMap) (*Snapshot, string, error) {
	raw, ok := cm.Data[SnapshotDataKey]
	if !ok {
		return nil, "", fmt.Errorf("configmap %s/%s has no %s", cm.Namespace, cm.Name, SnapshotDataKey)
	}
	sum := sha256.Sum256([]byte(raw))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if want := cm.Annotations[AnnotationSnapshotDigest]; want != digest {
		return nil, digest, fmt.Errorf("configmap %s/%s: snapshot digest %s does not match recorded %s", cm.Namespace, cm.Name, digest, want)
	}
	s := &Snapshot{}
	if err := json.Unmarshal([]byte(raw), s); err != nil {
		return nil, digest, err
	}
	return s, digest, nil
}
