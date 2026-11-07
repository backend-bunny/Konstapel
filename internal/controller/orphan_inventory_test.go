package controller

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// failingCreates fails ConfigMap creation while fail is set.
type failingCreates struct {
	client.Client
	fail bool
}

func (f *failingCreates) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if _, ok := obj.(*corev1.ConfigMap); ok && f.fail {
		return errors.New("etcdserver: request timed out")
	}
	return f.Client.Create(ctx, obj, opts...)
}

// orphanedEnv has two pinned runs on primary — one completed with a
// receipt and one collecting whose record is pending deletion — and an
// accepted Orphan deletion of primary.
func orphanedEnv(t *testing.T) (*pinEnv, []string) {
	e := newPinEnv(t)
	e.deliver("audit-prod")
	e.assess("audit-prod")
	first := e.schedule("audit-prod").ActiveRun.Name
	e.step(first)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(first)
	r := e.run(first)
	if r.Status.Publication == nil || r.Status.Publication.Destination == nil {
		t.Fatal("setup: no receipt")
	}
	r.Status.Publication.Destination.CredentialRef = &v1alpha1.SecretReference{Namespace: "konstapel-system", Name: "s3-writer-creds"}
	if err := e.c.Status().Update(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	ed := e.destination("primary")
	ed.Spec.DeletionPolicy = v1alpha1.DeletionOrphan
	ed.Spec.Orphan = &v1alpha1.OrphanRequest{Reason: "handed to the archive team", Actor: "platform-admin", ActorUID: "uid-admin"}
	if err := e.c.Update(context.Background(), ed); err != nil {
		t.Fatal(err)
	}
	_ = e.c.Delete(context.Background(), e.destination("primary"))
	return e, []string{first}
}

// pinnedCopy adds another run pinned to the same destination, collecting.
func (e *pinEnv) pinnedCopy(t *testing.T, from, name string) string {
	t.Helper()
	src := e.run(from)
	r := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: src.Namespace, UID: types.UID("uid-" + name),
		Labels: src.Labels, Finalizers: src.Finalizers}, Spec: src.Spec}
	if err := e.c.Create(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	r.Status = *src.Status.DeepCopy()
	r.Status.Phase, r.Status.Publication = v1alpha1.RunCollecting, nil
	if err := e.c.Status().Update(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	return name
}

func (e *pinEnv) destinationReconciler(c client.Client) *DestinationReconciler {
	return &DestinationReconciler{Client: c, Reader: e.c, Namespace: "konstapel-system", Destinations: e.rr.Runtime.Destinations, DrainTimeout: 10 * time.Millisecond,
		Now: func() time.Time { return e.now }, Probe: func(context.Context, s3store.Destination, client.Reader, string) error { return nil }}
}

func reconcileDestination(t *testing.T, dr *DestinationReconciler, name string) ctrl.Result {
	t.Helper()
	res, err := dr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (e *pinEnv) inventory(t *testing.T, uid string) (OrphanInventoryHeader, []OrphanRun, string) {
	t.Helper()
	var cms corev1.ConfigMapList
	if err := e.c.List(context.Background(), &cms, client.InNamespace("konstapel-system"), client.MatchingLabels{LabelOrphanHandoff: uid}); err != nil {
		t.Fatal(err)
	}
	byName := map[string]corev1.ConfigMap{}
	raw := ""
	for _, cm := range cms.Items {
		if cm.Immutable == nil || !*cm.Immutable || len(cm.OwnerReferences) != 0 {
			t.Fatalf("inventory ConfigMap %s is mutable or owned", cm.Name)
		}
		byName[cm.Name] = cm
		raw += cm.Data[inventoryKey]
	}
	var h OrphanInventoryHeader
	if err := json.Unmarshal([]byte(byName[inventoryName(uid, -1)].Data[inventoryKey]), &h); err != nil {
		t.Fatalf("header: %v", err)
	}
	var runs []OrphanRun
	for _, c := range h.Chunks {
		var part []OrphanRun
		if err := json.Unmarshal([]byte(byName[c.ConfigMap].Data[inventoryKey]), &part); err != nil {
			t.Fatalf("chunk %s: %v", c.ConfigMap, err)
		}
		runs = append(runs, part...)
	}
	return h, runs, raw
}

// The handoff is recorded durably, once, with the audit identity, original
// receipts, owned prefixes, and runs pending deletion — and without
// contacting the backend or recording credentials.
func TestOrphanInventoryIsSavedOnce(t *testing.T) {
	e, names := orphanedEnv(t)
	// The second run is still collecting and its record is being deleted.
	second := e.pinnedCopy(t, names[0], "second")
	if err := e.c.Delete(context.Background(), e.run(second)); err != nil {
		t.Fatal(err)
	}
	before := e.storageCalls()
	dr := e.destinationReconciler(e.c)
	reconcileDestination(t, dr, "primary")
	got := e.destination("primary")
	inv := got.Status.OrphanHandoff.Inventory
	if inv == nil || inv.Runs != 2 || inv.Chunks != 1 || inv.Header != "konstapel-orphan-uid-primary" {
		t.Fatalf("inventory ref %+v", inv)
	}
	h, runs, raw := e.inventory(t, "uid-primary")
	if h.Actor != "platform-admin" || h.ActorUID != "uid-admin" || h.Reason != "handed to the archive team" || h.RemoteState != "NotEnumerated" ||
		h.Destination.Bucket != "evidence" || h.Destination.Prefix != "primary" || !h.Drained {
		t.Fatalf("header %+v", h)
	}
	byName := map[string]OrphanRun{}
	for _, r := range runs {
		byName[r.Name] = r
		if !strings.HasPrefix(r.OwnedPrefix, "primary/evidence/") || !strings.HasSuffix(r.OwnedPrefix, r.UID+"/") {
			t.Fatalf("owned prefix %q", r.OwnedPrefix)
		}
	}
	if p := byName[names[0]].Publication; p == nil || p.PublicationID == "" || p.Commit == nil || p.Commit.ArchiveVersionID == "" || p.PackageSHA256 == "" || p.ExpiresAt == nil {
		t.Fatalf("original receipt missing: %s", mustJSON(byName[names[0]].Publication))
	}
	if !byName[second].PendingDeletion {
		t.Fatal("run pending deletion not recorded")
	}
	if strings.Contains(raw, "s3-writer-creds") || strings.Contains(raw, "credentialRef") || strings.Contains(strings.ToLower(raw), "secret") {
		t.Fatalf("inventory references credentials: %s", raw)
	}
	if e.storageCalls() != before {
		t.Fatal("inventory contacted the backend")
	}
	// Idempotent: a later reconcile keeps the saved record.
	e.now = e.now.Add(time.Hour)
	reconcileDestination(t, dr, "primary")
	if again := e.destination("primary").Status.OrphanHandoff.Inventory; !again.SavedAt.Equal(&inv.SavedAt) {
		t.Fatalf("inventory rewritten: %+v", again)
	}
	// A crash after the ConfigMaps but before the status update recovers.
	got = e.destination("primary")
	got.Status.OrphanHandoff.Inventory = nil
	if err := e.c.Status().Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	reconcileDestination(t, dr, "primary")
	if e.destination("primary").Status.OrphanHandoff.Inventory == nil {
		t.Fatal("existing inventory not recovered")
	}
}

// A failure to persist the inventory keeps the fence and the finalizer,
// reports why, and retries until it succeeds.
func TestOrphanInventoryFailureKeepsFence(t *testing.T) {
	e, _ := orphanedEnv(t)
	fc := &failingCreates{Client: e.c, fail: true}
	dr := e.destinationReconciler(fc)
	if res := reconcileDestination(t, dr, "primary"); res.RequeueAfter == 0 {
		t.Fatal("failed inventory not retried")
	}
	got := e.destination("primary")
	c := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionDestinationRetiring)
	if got.Status.OrphanHandoff == nil || got.Status.OrphanHandoff.Inventory != nil || c == nil || c.Reason != "OrphanInventoryPending" {
		t.Fatalf("status %+v / %+v", got.Status.OrphanHandoff, c)
	}
	if strings.Contains(c.Message, "s3") && strings.Contains(c.Message, "secret") {
		t.Fatalf("condition exposes credentials: %s", c.Message)
	}
	if !controllerutil.ContainsFinalizer(got, DestinationFinalizer) {
		t.Fatal("finalizer released without an inventory")
	}
	pin := &v1alpha1.DestinationPin{DestinationReference: v1alpha1.DestinationReference{Name: "primary", UID: string(got.UID)}}
	if _, err := e.rr.Runtime.Destinations.For(context.Background(), pin); !errors.Is(err, publication.ErrOrphaned) {
		t.Fatalf("fence lifted: %v", err)
	}
	fc.fail = false
	reconcileDestination(t, dr, "primary")
	if e.destination("primary").Status.OrphanHandoff.Inventory == nil {
		t.Fatal("inventory not saved on retry")
	}
}

// Large handoffs are split into chunks that each stay under the size bound,
// and the header lists every chunk with its digest.
func TestOrphanInventoryChunks(t *testing.T) {
	defer func(n int) { orphanChunkBytes = n }(orphanChunkBytes)
	orphanChunkBytes = 64
	e, names := orphanedEnv(t)
	e.pinnedCopy(t, names[0], "second")
	e.pinnedCopy(t, names[0], "third")
	reconcileDestination(t, e.destinationReconciler(e.c), "primary")
	inv := e.destination("primary").Status.OrphanHandoff.Inventory
	h, runs, _ := e.inventory(t, "uid-primary")
	if inv == nil || int(inv.Chunks) != len(h.Chunks) || len(h.Chunks) != len(runs) || len(runs) < 2 {
		t.Fatalf("chunks %+v header %d runs %d", inv, len(h.Chunks), len(runs))
	}
	for _, c := range h.Chunks {
		if len(c.SHA256) != 64 || c.Runs != 1 {
			t.Fatalf("chunk %+v", c)
		}
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
