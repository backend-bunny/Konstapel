package exception

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// RevocationRecordVersion versions the revocation record document.
const RevocationRecordVersion = 1

// Keys on revocation record ConfigMaps. They share the snapshot labels, so
// the records of one exception, or of one namespace instance, are selected
// the same way as its acceptance snapshots.
const (
	RevocationRecordDataKey  = "revocation.json"
	ComponentRevocation      = "revocation-record"
	AnnotationRecordDigest   = "compliance.erenius.io/record-digest"
	revocationRecordNamePref = "revocation-"
)

// RevocationRecord is the independent, immutable lifecycle record of one
// revoked acceptance revision (design §3, task 3.6). The controller copies
// it from the protected revocation record admission wrote on the exception,
// and from the acceptance record of the same revision, before it releases
// RevocationFinalizer. It is never rewritten: a later renewal, deletion of
// the exception or of its namespace, a restart or a leadership change leaves
// it as written. It records when revocation was requested; it says nothing
// about when an engine stopped granting.
type RevocationRecord struct {
	Version   int    `json:"version"`
	Cluster   string `json:"cluster,omitempty"`
	Exception struct {
		Name      string    `json:"name"`
		Namespace string    `json:"namespace"`
		UID       types.UID `json:"uid"`
	} `json:"exception"`
	AcceptanceRevision int64 `json:"acceptanceRevision"`
	// Namespace is the namespace instance of the acceptance; its UID is empty
	// when no acceptance record of this revision is available.
	Namespace targeting.NamespaceRef `json:"namespace"`
	Policy    string                 `json:"policy"`
	// Revocation is the admission-written record, copied unchanged: the
	// authenticated revoking actor, the request time and the unverified
	// claim.
	Revocation Revocation `json:"revocation"`
	// Acceptance references the immutable snapshot of the revoked revision
	// and the digest its acceptance record produces. It is a reference, not
	// a copy: the snapshot itself is never rewritten.
	Acceptance *v1alpha1.AcceptanceSnapshotReference `json:"acceptance,omitempty"`
	// AcceptanceUnavailable says why there is no acceptance reference.
	AcceptanceUnavailable string `json:"acceptanceUnavailable,omitempty"`
}

// RevocationRecordName is the ConfigMap name of the record of one revoked
// acceptance revision. Exception UIDs are unique, so a recreated exception
// never reuses a name, and every revoked revision has its own record.
func RevocationRecordName(exceptionUID types.UID, revision int64) string {
	return revocationRecordNamePref + string(exceptionUID) + "-" + strconv.FormatInt(revision, 10)
}

// ErrNoRevocation reports an exception without a revocation to record.
var ErrNoRevocation = errors.New("the exception records no revocation")

// NewRevocationRecord builds the record of the exception's current, revoked
// acceptance revision. Every field comes from the stored resource: the
// admission-written revocation and acceptance records, and the immutable
// identity, policy and revision. Nothing is resolved from the cluster, so a
// revocation of an expired, Forbidden or unresolvable acceptance gets the
// same record, and two controllers build identical ones.
func NewRevocationRecord(ex *v1alpha1.ComplianceException, snapshotNamespace string) (*RevocationRecord, error) {
	rv, present, err := ParseRevocation(ex)
	switch {
	case !present:
		return nil, ErrNoRevocation
	case err != nil:
		return nil, fmt.Errorf("%s is unreadable: %w", RevocationAnnotation, err)
	case !ex.Spec.Revoked:
		return nil, fmt.Errorf("%s is present but spec.revoked is false", RevocationAnnotation)
	case rv.ExceptionUID != ex.UID:
		return nil, fmt.Errorf("%s records exception UID %q, not %q", RevocationAnnotation, rv.ExceptionUID, ex.UID)
	case rv.Revision != ex.Spec.AcceptanceRevision:
		return nil, fmt.Errorf("%s records revision %d, not the current %d", RevocationAnnotation, rv.Revision, ex.Spec.AcceptanceRevision)
	case rv.Actor.Username == "" || rv.RequestedAt.IsZero():
		return nil, fmt.Errorf("%s has no authenticated actor or request time", RevocationAnnotation)
	}
	r := &RevocationRecord{Version: RevocationRecordVersion, AcceptanceRevision: rv.Revision, Policy: ex.Spec.Policy,
		Namespace: targeting.NamespaceRef{Name: ex.Namespace}, Revocation: rv}
	r.Exception.Name, r.Exception.Namespace, r.Exception.UID = ex.Name, ex.Namespace, ex.UID
	a, present, err := ParseAcceptance(ex)
	switch {
	case !present:
		r.AcceptanceUnavailable = "no acceptance record was admitted"
	case err != nil:
		r.AcceptanceUnavailable = "the acceptance record is unreadable"
	default:
		snap, err := NewSnapshot(ex, a)
		if err != nil {
			r.AcceptanceUnavailable = err.Error()
			break
		}
		cm, digest, err := snap.ConfigMap(snapshotNamespace)
		if err != nil {
			return nil, err
		}
		r.Cluster, r.Namespace = a.Cluster, a.Namespace
		r.Acceptance = &v1alpha1.AcceptanceSnapshotReference{Revision: a.Revision, Snapshot: snapshotNamespace + "/" + cm.Name, Digest: digest}
	}
	return r, nil
}

// Document returns the record's canonical JSON and its sha256 digest.
func (r *RevocationRecord) Document() ([]byte, string, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ConfigMap renders the immutable record ConfigMap in namespace. It has no
// owner reference, so neither deleting the exception nor deleting its
// namespace garbage-collects it.
func (r *RevocationRecord) ConfigMap(namespace string) (*corev1.ConfigMap, string, error) {
	raw, digest, err := r.Document()
	if err != nil {
		return nil, "", err
	}
	labels := map[string]string{
		targeting.LabelManagedBy:  targeting.ManagedByValue,
		LabelComponent:            ComponentRevocation,
		LabelExceptionUID:         string(r.Exception.UID),
		LabelAcceptanceRevision:   strconv.FormatInt(r.AcceptanceRevision, 10),
		targeting.LabelPolicyHash: targeting.PolicyHash(r.Policy),
	}
	if r.Namespace.UID != "" {
		labels[LabelNamespaceUID] = string(r.Namespace.UID)
	}
	immutable := true
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: RevocationRecordName(r.Exception.UID, r.AcceptanceRevision), Namespace: namespace,
			Labels: labels, Annotations: map[string]string{AnnotationRecordDigest: digest}},
		Immutable: &immutable,
		Data:      map[string]string{RevocationRecordDataKey: string(raw)},
	}, digest, nil
}

// RevocationRecordFrom reads and verifies a record ConfigMap: it must be an
// immutable Konstapel record whose document matches the digest it was
// written with.
func RevocationRecordFrom(cm *corev1.ConfigMap) (*RevocationRecord, string, error) {
	if cm.Labels[targeting.LabelManagedBy] != targeting.ManagedByValue || cm.Labels[LabelComponent] != ComponentRevocation ||
		cm.Immutable == nil || !*cm.Immutable {
		return nil, "", fmt.Errorf("configmap %s/%s is not an immutable Konstapel revocation record", cm.Namespace, cm.Name)
	}
	raw, ok := cm.Data[RevocationRecordDataKey]
	if !ok {
		return nil, "", fmt.Errorf("configmap %s/%s has no %s", cm.Namespace, cm.Name, RevocationRecordDataKey)
	}
	sum := sha256.Sum256([]byte(raw))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if want := cm.Annotations[AnnotationRecordDigest]; want != digest {
		return nil, digest, fmt.Errorf("configmap %s/%s: record digest %s does not match recorded %s", cm.Namespace, cm.Name, digest, want)
	}
	r := &RevocationRecord{}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(r); err != nil {
		return nil, digest, fmt.Errorf("configmap %s/%s: %w", cm.Namespace, cm.Name, err)
	}
	if r.Version != RevocationRecordVersion {
		return nil, digest, fmt.Errorf("configmap %s/%s: unknown revocation record version %d", cm.Namespace, cm.Name, r.Version)
	}
	return r, digest, nil
}

// Matches reports whether the persisted record holds exactly this
// revocation: the same exception UID, revision, authenticated actor,
// request time and claim, under the name and labels of that revision.
func (r *RevocationRecord) Matches(cm *corev1.ConfigMap, want Revocation) error {
	got, err := json.Marshal(r.Revocation)
	if err != nil {
		return err
	}
	expected, err := json.Marshal(want)
	if err != nil {
		return err
	}
	switch {
	case cm.Name != RevocationRecordName(want.ExceptionUID, want.Revision):
		return fmt.Errorf("configmap %s/%s is not the record of exception %s revision %d", cm.Namespace, cm.Name, want.ExceptionUID, want.Revision)
	case r.Exception.UID != want.ExceptionUID || r.AcceptanceRevision != want.Revision ||
		cm.Labels[LabelExceptionUID] != string(want.ExceptionUID) || cm.Labels[LabelAcceptanceRevision] != strconv.FormatInt(want.Revision, 10):
		return fmt.Errorf("configmap %s/%s records exception %s revision %d", cm.Namespace, cm.Name, r.Exception.UID, r.AcceptanceRevision)
	case !bytes.Equal(got, expected):
		return fmt.Errorf("configmap %s/%s records revocation %s, the exception records %s", cm.Namespace, cm.Name, got, expected)
	}
	return nil
}

// ErrHistoryPending reports a revocation without a durable independent
// record yet.
var ErrHistoryPending = errors.New("revocation history pending")

// HistoryConflict reports an object at a record's name that is not the
// matching record. It is never overwritten.
type HistoryConflict struct{ error }

func (c HistoryConflict) Unwrap() error { return c.error }

// VerifyHistory checks that the revocation recorded on ex has a durable,
// matching independent record in namespace. It returns nil when it does,
// an error wrapping ErrHistoryPending when no record exists yet, a
// HistoryConflict when the object at the record's name does not hold this
// revocation, and any read error as is. A caller treats every non-nil
// result as "not durable" and keeps the intent and its finalizer.
func VerifyHistory(ctx context.Context, reader client.Reader, namespace string, ex *v1alpha1.ComplianceException) error {
	rv, present, err := ParseRevocation(ex)
	switch {
	case !present:
		return HistoryConflict{fmt.Errorf("spec.revoked is true at revision %d, but admission recorded no revocation", ex.Spec.AcceptanceRevision)}
	case err != nil:
		return HistoryConflict{fmt.Errorf("%s is unreadable: %w", RevocationAnnotation, err)}
	case rv.ExceptionUID != ex.UID || rv.Revision != ex.Spec.AcceptanceRevision:
		return HistoryConflict{fmt.Errorf("%s records exception %s revision %d, not %s revision %d", RevocationAnnotation, rv.ExceptionUID, rv.Revision, ex.UID, ex.Spec.AcceptanceRevision)}
	}
	key := client.ObjectKey{Namespace: namespace, Name: RevocationRecordName(rv.ExceptionUID, rv.Revision)}
	cm := &corev1.ConfigMap{}
	if err := reader.Get(ctx, key, cm); apierrors.IsNotFound(err) {
		return fmt.Errorf("%w: no independent revocation record %s exists yet", ErrHistoryPending, key)
	} else if err != nil {
		return fmt.Errorf("read revocation record %s: %w", key, err)
	}
	rec, _, err := RevocationRecordFrom(cm)
	if err != nil {
		return HistoryConflict{err}
	}
	if err := rec.Matches(cm, rv); err != nil {
		return HistoryConflict{err}
	}
	return nil
}
