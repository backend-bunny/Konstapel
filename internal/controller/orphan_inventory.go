package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// The orphan inventory is written as immutable ConfigMaps in the controller
// namespace.
// +kubebuilder:rbac:groups="",namespace=konstapel-system,resources=configmaps,verbs=get;list;create

const (
	// OrphanInventoryVersion versions the inventory documents.
	OrphanInventoryVersion = "konstapel.erenius.io/orphan-inventory/v1"
	// LabelOrphanHandoff identifies every ConfigMap of one handoff.
	LabelOrphanHandoff = "compliance.erenius.io/orphan-handoff"
	inventoryKey       = "inventory.json"
)

// orphanChunkBytes keeps each ConfigMap well below the 1 MiB object limit.
var orphanChunkBytes = 512 << 10

// OrphanInventoryHeader is the handoff's identity and audit record.
type OrphanInventoryHeader struct {
	APIVersion  string              `json:"apiVersion"`
	HandoffID   string              `json:"handoffID"`
	Destination OrphanDestination   `json:"destination"`
	Reason      string              `json:"reason"`
	Actor       string              `json:"actor"`
	ActorUID    string              `json:"actorUID,omitempty"`
	AcceptedAt  time.Time           `json:"acceptedAt"`
	FencedAt    time.Time           `json:"fencedAt"`
	Drained     bool                `json:"drained"`
	Uncertain   []string            `json:"uncertainOperations,omitempty"`
	RemoteState string              `json:"remoteState"`
	RemoteNote  string              `json:"remoteStateNote"`
	Runs        int                 `json:"runs"`
	Chunks      []OrphanChunkDigest `json:"chunks"`
}

// OrphanDestination is the location snapshot. It holds no credentials.
type OrphanDestination struct {
	Name     string `json:"name"`
	UID      string `json:"uid"`
	Endpoint string `json:"endpoint"`
	Bucket   string `json:"bucket"`
	Region   string `json:"region"`
	Prefix   string `json:"prefix,omitempty"`
}

// OrphanChunkDigest names a run-list ConfigMap and its content digest.
type OrphanChunkDigest struct {
	ConfigMap string `json:"configMap"`
	SHA256    string `json:"sha256"`
	Runs      int    `json:"runs"`
}

// OrphanRun is one run whose storage is handed off.
type OrphanRun struct {
	Name         string `json:"name"`
	UID          string `json:"uid"`
	BindingUID   string `json:"bindingUID,omitempty"`
	ClusterID    string `json:"clusterID,omitempty"`
	NamespaceUID string `json:"namespaceUID,omitempty"`
	Phase        string `json:"phase,omitempty"`
	// PendingDeletion is true when the run record was already being deleted.
	PendingDeletion bool `json:"pendingDeletion,omitempty"`
	// OwnedPrefix holds every object, version, and incomplete upload of the
	// run at this destination; nothing outside it belongs to the run.
	OwnedPrefix string `json:"ownedPrefix,omitempty"`
	// Publication is the original receipt and cleanup state, if any.
	Publication *v1alpha1.PublicationStatus `json:"publication,omitempty"`
}

func inventoryName(uid string, i int) string {
	if i < 0 {
		return "konstapel-orphan-" + uid
	}
	return fmt.Sprintf("konstapel-orphan-%s-%d", uid, i)
}

// saveOrphanInventory durably records the handoff before any finalizer may
// be released. It reads only Kubernetes state: under the fence the backend
// is not contacted, so remote objects are described by their owned prefixes
// and the inventory says the remote state was not enumerated. Chunks are
// written first and the header last; existing ConfigMaps (immutable) are
// verified rather than replaced, so retries are idempotent.
func (r *DestinationReconciler) saveOrphanInventory(ctx context.Context, ed *v1alpha1.EvidenceDestination, status *v1alpha1.EvidenceDestinationStatus) (*v1alpha1.OrphanInventoryRef, error) {
	ns := controllerNamespace(r.Namespace)
	var runs v1alpha1.AssessmentRunList
	if err := r.Reader.List(ctx, &runs, client.MatchingLabels{LabelRunDestination: string(ed.UID)}); err != nil {
		return nil, err
	}
	d := s3store.Destination{Prefix: ed.Spec.S3.Prefix}
	var records []OrphanRun
	for _, run := range runs.Items {
		rec := OrphanRun{Name: run.Name, UID: string(run.UID), Phase: string(run.Status.Phase), PendingDeletion: !run.DeletionTimestamp.IsZero()}
		if p := run.Status.Publication; p != nil {
			// The receipt keeps its owned keys, versions, and upload IDs;
			// no reference to credentials leaves the cluster with it.
			rec.Publication = p.DeepCopy()
			if rec.Publication.Destination != nil {
				rec.Publication.Destination.CredentialRef = nil
			}
		}
		if run.Status.Binding != nil {
			rec.BindingUID = run.Status.Binding.UID
		}
		if sc := run.Status.Scope; sc != nil {
			rec.ClusterID, rec.NamespaceUID = sc.ClusterID, sc.NamespaceUID
			if run.Status.Binding != nil {
				rec.OwnedPrefix = s3store.RunPrefix(d, publication.RunRef{ClusterID: sc.ClusterID, BindingUID: run.Status.Binding.UID, RunUID: string(run.UID)})
			}
		}
		records = append(records, rec)
	}
	slices.SortFunc(records, func(a, b OrphanRun) int { return strings.Compare(a.UID, b.UID) })

	// Split the run list so each ConfigMap stays within object limits.
	var chunks [][]OrphanRun
	var cur []OrphanRun
	size := 0
	for _, rec := range records {
		b, _ := json.Marshal(rec)
		if len(cur) > 0 && size+len(b) > orphanChunkBytes {
			chunks = append(chunks, cur)
			cur, size = nil, 0
		}
		cur = append(cur, rec)
		size += len(b) + 1
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	uid := string(ed.UID)
	header := OrphanInventoryHeader{APIVersion: OrphanInventoryVersion, HandoffID: uid + "/" + status.OrphanIntent.AcceptedAt.UTC().Format(time.RFC3339),
		Destination: OrphanDestination{Name: ed.Name, UID: uid, Endpoint: ed.Spec.S3.Endpoint, Bucket: ed.Spec.S3.Bucket, Region: ed.Spec.S3.Region, Prefix: ed.Spec.S3.Prefix},
		Reason:      status.OrphanIntent.Reason, Actor: status.OrphanIntent.Actor, ActorUID: status.OrphanIntent.ActorUID,
		AcceptedAt: status.OrphanIntent.AcceptedAt.Time, FencedAt: status.OrphanHandoff.FencedAt.Time, Drained: status.OrphanHandoff.Drained,
		Uncertain: status.OrphanHandoff.UncertainOperations, RemoteState: "NotEnumerated", Runs: len(records),
		RemoteNote: "the backend was not contacted after the fence; each run's ownedPrefix holds all of its objects, versions, and incomplete uploads, which must be listed at the destination"}
	for i, c := range chunks {
		body, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		digest := hex.EncodeToString(sum[:])
		name := inventoryName(uid, i)
		if err := r.putImmutable(ctx, ns, name, uid, body, digest); err != nil {
			return nil, err
		}
		header.Chunks = append(header.Chunks, OrphanChunkDigest{ConfigMap: name, SHA256: digest, Runs: len(c)})
	}
	body, err := json.MarshalIndent(header, "", "  ")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if err := r.putImmutable(ctx, ns, inventoryName(uid, -1), uid, body, hex.EncodeToString(sum[:])); err != nil {
		return nil, err
	}
	return &v1alpha1.OrphanInventoryRef{Header: inventoryName(uid, -1), Chunks: int32(len(chunks)), Runs: int32(len(records)), SavedAt: metav1.NewTime(r.now())}, nil
}

// putImmutable creates an immutable ConfigMap, or accepts an existing one
// for the same handoff. An existing ConfigMap is never overwritten: if a
// retry computed different content (the fenced runs changed), the first
// saved record stands.
func (r *DestinationReconciler) putImmutable(ctx context.Context, ns, name, handoff string, body []byte, digest string) error {
	yes := true
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name,
		Labels:      map[string]string{LabelOrphanHandoff: handoff, "app.kubernetes.io/part-of": "konstapel"},
		Annotations: map[string]string{"compliance.erenius.io/sha256": digest}},
		Immutable: &yes, Data: map[string]string{inventoryKey: string(body)}}
	err := r.Client.Create(ctx, cm)
	if apierrors.IsAlreadyExists(err) {
		existing := &corev1.ConfigMap{}
		if err := r.Reader.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, existing); err != nil {
			return err
		}
		if existing.Labels[LabelOrphanHandoff] != handoff {
			return fmt.Errorf("ConfigMap %s/%s exists but belongs to another handoff", ns, name)
		}
		return nil
	}
	return err
}
