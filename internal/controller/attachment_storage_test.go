package controller

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
)

// add-supporting-evidence-attachments 2.3/2.4: destination pinning, the
// recorded commitment, and the retention finalizer gated on commitment and
// expiry, against an in-memory store.

type memStore struct {
	mu        sync.Mutex
	dest      attachments.Destination
	committed map[attachments.Ref]attachments.Receipt
	attempts  map[attachments.Ref]int
	deleteErr error
	cleanups  int
	deleted   []attachments.Ref
}

func newMemStore(id string) *memStore {
	return &memStore{dest: attachments.Destination{ID: id, Endpoint: "https://s3.example", Bucket: "b"},
		committed: map[attachments.Ref]attachments.Receipt{}, attempts: map[attachments.Ref]int{}}
}

func (m *memStore) Destination() attachments.Destination { return m.dest }
func (m *memStore) Stage(context.Context, attachments.StageRequest) (attachments.Staged, error) {
	return attachments.Staged{}, nil
}
func (m *memStore) Commit(context.Context, attachments.CommitRequest) (attachments.Receipt, error) {
	return attachments.Receipt{}, nil
}
func (m *memStore) Committed(_ context.Context, ref attachments.Ref) (attachments.Receipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.committed[ref]
	if !ok {
		return attachments.Receipt{}, attachments.ErrNotFound
	}
	return r, nil
}
func (m *memStore) Open(context.Context, attachments.Receipt) (io.ReadCloser, error) { return nil, nil }
func (m *memStore) Health(context.Context, attachments.Receipt) (*attachments.Problem, error) {
	return nil, nil
}
func (m *memStore) CleanupAttempts(context.Context, attachments.Ref, time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanups++
	return nil
}
func (m *memStore) DeleteUncommitted(_ context.Context, ref attachments.Ref) (attachments.Cleanup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.committed[ref]; ok {
		return attachments.Cleanup{}, attachments.ErrConflict
	}
	delete(m.attempts, ref)
	m.deleted = append(m.deleted, ref)
	return attachments.Cleanup{State: attachments.CleanupDeleted}, nil
}
func (m *memStore) Delete(_ context.Context, r attachments.Receipt, now time.Time) (attachments.Cleanup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if now.Before(r.ExpiresAt) {
		return attachments.Cleanup{}, attachments.ErrRetentionActive
	}
	if m.deleteErr != nil {
		return attachments.Cleanup{State: attachments.CleanupRetentionBlocked, Message: m.deleteErr.Error()}, attachments.ErrRetentionBlocked
	}
	delete(m.committed, r.Ref)
	m.deleted = append(m.deleted, r.Ref)
	return attachments.Cleanup{State: attachments.CleanupDeleted}, nil
}

type memStores struct {
	stores map[string]*memStore // destination UID
	down   bool
}

func (s *memStores) Store(_ context.Context, ref v1alpha1.DestinationReference) (attachments.Store, error) {
	if s.down {
		return nil, attachments.ErrUnavailable
	}
	return s.stores[ref.UID], nil
}

type storageFixture struct {
	*attachmentFixture
	stores *memStores
	now    time.Time
}

func readyDestination(name, uid string) *v1alpha1.EvidenceDestination {
	return &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: name, UID: ktypes.UID(uid), Generation: 1},
		Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{Endpoint: "https://s3.example", Bucket: "b", Region: "r"}},
		Status: v1alpha1.EvidenceDestinationStatus{Conditions: []metav1.Condition{{Type: v1alpha1.ConditionDestinationReady, Status: metav1.ConditionTrue,
			Reason: "Ready", LastTransitionTime: metav1.Now()}}}}
}

func defaultAttachmentDestination(name, uid string) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "konstapel-system", Name: DefaultDestinationConfigMap},
		Data: map[string]string{DefaultDestinationNameKey: name, DefaultDestinationUIDKey: uid}}
}

func newStorageFixture(t *testing.T, objs ...client.Object) *storageFixture {
	t.Helper()
	f := newAttachmentFixture(t)
	c := fake.NewClientBuilder().WithScheme(Scheme()).WithObjects(objs...).
		WithStatusSubresource(&v1alpha1.EvidenceAttachment{}, &v1alpha1.EvidenceDestination{}).
		WithIndex(&v1alpha1.EvidenceAttachment{}, AttachmentBindingIndex, attachmentBindingNames).
		Build()
	f.c = c
	f.r.Client = c
	sf := &storageFixture{attachmentFixture: f, stores: &memStores{stores: map[string]*memStore{"dest-1": newMemStore("dest-1"), "dest-2": newMemStore("dest-2")}},
		now: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	f.r.Storage = &AttachmentStorage{Reader: c, Namespace: "konstapel-system", Cluster: "kube-system:cluster", Stores: sf.stores,
		Now: func() time.Time { return sf.now }}
	return sf
}

func (f *storageFixture) get(name string) *v1alpha1.EvidenceAttachment {
	f.t.Helper()
	a := &v1alpha1.EvidenceAttachment{}
	if err := f.c.Get(context.Background(), client.ObjectKey{Name: name}, a); err != nil {
		f.t.Fatal(err)
	}
	return a
}

func (f *storageFixture) commit(name, destUID string, edit func(*attachments.Receipt)) attachments.Receipt {
	f.t.Helper()
	a := f.get(name)
	ref := attachments.Ref{ClusterID: "kube-system:cluster", UID: string(a.UID)}
	committed := f.now.Add(-time.Hour)
	r := attachments.Receipt{Ref: ref, Destination: f.stores.stores[destUID].dest, ManifestKey: "m", DocumentKey: "d",
		Document: attachments.Expected(a.Spec), SpecDigest: attachments.SpecDigest(a.Spec), Uploader: attachments.Principal{Username: "uploader"},
		CommittedAt: committed, ValidUntil: a.Spec.Validity.ValidUntil.UTC(), Retention: attachments.DefaultRetention}
	if edit != nil {
		edit(&r)
	}
	r.ExpiresAt = attachments.ExpiresAt(r.CommittedAt, r.ValidUntil, r.Retention)
	f.stores.stores[destUID].committed[ref] = r
	return r
}

func committedCondition(a *v1alpha1.EvidenceAttachment) string {
	c := meta.FindStatusCondition(a.Status.Conditions, v1alpha1.ConditionDocumentCommitted)
	if c == nil {
		return ""
	}
	return string(c.Status) + "/" + c.Reason
}

func TestAttachmentPinsDefaultDestinationOnce(t *testing.T) {
	f := newStorageFixture(t, readyDestination("primary", "dest-1"), readyDestination("secondary", "dest-2"), defaultAttachmentDestination("primary", "dest-1"))
	f.create("dc", f.association("a", "uid-a"))
	res, a := f.reconcile("dc")
	if a.Labels[v1alpha1.LabelAttachmentDestination] != "dest-1" || a.Status.Storage == nil || a.Status.Storage.Destination.UID != "dest-1" || res.RequeueAfter == 0 {
		t.Fatalf("pin: labels %v storage %+v", a.Labels, a.Status.Storage)
	}
	ed := &v1alpha1.EvidenceDestination{}
	_ = f.c.Get(context.Background(), client.ObjectKey{Name: "primary"}, ed)
	if !controllerutil.ContainsFinalizer(ed, DestinationFinalizer) {
		t.Fatal("pinned destination is not protected")
	}
	_, a = f.reconcile("dc")
	if got := committedCondition(a); got != "False/"+v1alpha1.ReasonAwaitingUpload {
		t.Fatalf("condition %s", got)
	}
	if a.Status.Storage.DestinationID != "dest-1" || f.stores.stores["dest-1"].cleanups == 0 {
		t.Fatalf("destination ID %q, cleanups %d", a.Status.Storage.DestinationID, f.stores.stores["dest-1"].cleanups)
	}
	// A changed default never relocates the document.
	cm := defaultAttachmentDestination("secondary", "dest-2")
	if err := f.c.Update(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
	_, a = f.reconcile("dc")
	if a.Status.Storage.Destination.UID != "dest-1" {
		t.Fatal("pin moved to the new default")
	}
	f.create("later", f.association("a", "uid-a"))
	_, later := f.reconcile("later")
	if later.Status.Storage.Destination.UID != "dest-2" {
		t.Fatal("a new record does not use the new default")
	}
}

func TestAttachmentWithoutDestinationPinsNothing(t *testing.T) {
	notReady := readyDestination("primary", "dest-1")
	notReady.Status.Conditions[0].Status = metav1.ConditionFalse
	for name, objs := range map[string][]client.Object{
		"no default":     nil,
		"replaced":       {readyDestination("primary", "dest-other"), defaultAttachmentDestination("primary", "dest-1")},
		"not ready":      {notReady, defaultAttachmentDestination("primary", "dest-1")},
		"missing object": {defaultAttachmentDestination("primary", "dest-1")},
	} {
		t.Run(name, func(t *testing.T) {
			f := newStorageFixture(t, objs...)
			f.create("dc", f.association("a", "uid-a"))
			res, a := f.reconcile("dc")
			if a.Status.Storage != nil || a.Labels[v1alpha1.LabelAttachmentDestination] != "" {
				t.Fatalf("pinned: %+v %v", a.Status.Storage, a.Labels)
			}
			if got := committedCondition(a); got != "False/"+v1alpha1.ReasonNoDestination || res.RequeueAfter == 0 {
				t.Fatalf("condition %s, requeue %v", got, res)
			}
			// Withdrawal of a never-pinned record releases it at once.
			if err := f.c.Delete(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			if _, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: "dc"}}); err != nil {
				t.Fatal(err)
			}
			if err := f.c.Get(context.Background(), client.ObjectKey{Name: "dc"}, a); !apierrors.IsNotFound(err) {
				t.Fatalf("unpinned record kept: %v", err)
			}
		})
	}
}

func TestAttachmentRecordsMatchingCommitmentOnly(t *testing.T) {
	f := newStorageFixture(t, readyDestination("primary", "dest-1"), defaultAttachmentDestination("primary", "dest-1"))
	f.create("dc", f.association("a", "uid-a"))
	f.create("foreign", f.association("a", "uid-a"))
	f.reconcile("dc")
	f.reconcile("foreign")
	r := f.commit("dc", "dest-1", nil)
	_, a := f.reconcile("dc")
	c := a.Status.Storage.Commitment
	if c == nil || c.SHA256 != r.Document.SHA256 || c.Uploader.Username != "uploader" || !c.ExpiresAt.Time.Equal(r.ExpiresAt) || c.Retention.Duration != attachments.DefaultRetention {
		t.Fatalf("commitment %+v", c)
	}
	if got := committedCondition(a); got != "True/"+v1alpha1.ReasonCommitted {
		t.Fatalf("condition %s", got)
	}
	// A year-long document stays beyond a 90-day package retention.
	if want := a.Spec.Validity.ValidUntil.Add(2160 * time.Hour); !c.ExpiresAt.Time.Equal(want) {
		t.Fatalf("expiry %s, want %s", c.ExpiresAt, want)
	}
	for name, edit := range map[string]func(*attachments.Receipt){
		"other bytes":    func(r *attachments.Receipt) { r.Document.SHA256 = "sha256:" + strings.Repeat("f", 64) },
		"other spec":     func(r *attachments.Receipt) { r.SpecDigest = "sha256:" + strings.Repeat("e", 64) },
		"other validity": func(r *attachments.Receipt) { r.ValidUntil = r.ValidUntil.Add(time.Hour) },
	} {
		f.commit("foreign", "dest-1", edit)
		_, b := f.reconcile("foreign")
		if b.Status.Storage.Commitment != nil || committedCondition(b) != "False/"+v1alpha1.ReasonStorageConflict {
			t.Fatalf("%s recorded: %+v %s", name, b.Status.Storage.Commitment, committedCondition(b))
		}
	}
	// Unavailable storage keeps the recorded commitment.
	f.stores.down = true
	_, a = f.reconcile("dc")
	if a.Status.Storage.Commitment == nil || committedCondition(a) != "True/"+v1alpha1.ReasonCommitted {
		t.Fatal("storage outage changed a recorded commitment")
	}
}

func TestAttachmentFinalizerWaitsForExpiryAndCleanup(t *testing.T) {
	f := newStorageFixture(t, readyDestination("primary", "dest-1"), defaultAttachmentDestination("primary", "dest-1"))
	ctx := context.Background()
	f.create("dc", f.association("a", "uid-a"))
	f.reconcile("dc")
	r := f.commit("dc", "dest-1", nil)
	f.reconcile("dc")
	if err := f.c.Delete(ctx, f.get("dc")); err != nil {
		t.Fatal(err)
	}
	res, a := f.reconcile("dc")
	if a.Status.Storage.Cleanup == nil || a.Status.Storage.Cleanup.State != "NotDue" || res.RequeueAfter <= 0 || res.RequeueAfter > MaxRetentionRequeue {
		t.Fatalf("retained: %+v %v", a.Status.Storage.Cleanup, res)
	}
	if c := meta.FindStatusCondition(a.Status.Conditions, v1alpha1.ConditionAssociationsValid); c == nil || c.Reason != v1alpha1.ReasonWithdrawn {
		t.Fatalf("not withdrawn: %+v", c)
	}
	if c := meta.FindStatusCondition(a.Status.Conditions, v1alpha1.ConditionSourceRetained); c == nil || c.Reason != v1alpha1.ReasonRetentionActive {
		t.Fatalf("retention: %+v", c)
	}
	// A restart or leader change sees the same state.
	again, _ := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "dc"}})
	if again.RequeueAfter <= 0 || len(f.stores.stores["dest-1"].deleted) != 0 {
		t.Fatal("deleted before expiry")
	}
	// Expired, but storage refuses deletion: ownership is kept.
	f.now = r.ExpiresAt
	f.stores.stores["dest-1"].deleteErr = errBlocked
	_, a = f.reconcile("dc")
	if a.Status.Storage.Cleanup.State != string(attachments.CleanupRetentionBlocked) || a.Status.Storage.Commitment == nil {
		t.Fatalf("blocked: %+v", a.Status.Storage)
	}
	f.stores.stores["dest-1"].deleteErr = nil
	if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "dc"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Get(ctx, client.ObjectKey{Name: "dc"}, a); !apierrors.IsNotFound(err) {
		t.Fatalf("expired, cleaned record kept: %v", err)
	}
}

var errBlocked = apierrors.NewForbidden(v1alpha1.GroupVersion.WithResource("x").GroupResource(), "x", nil)

func TestAttachmentWithdrawalBeforeCommitment(t *testing.T) {
	f := newStorageFixture(t, readyDestination("primary", "dest-1"), defaultAttachmentDestination("primary", "dest-1"))
	ctx := context.Background()
	f.create("uncommitted", f.association("a", "uid-a"))
	f.create("lost-status", f.association("a", "uid-a"))
	f.reconcile("uncommitted")
	f.reconcile("lost-status")
	// The commit landed but its status write never happened.
	r := f.commit("lost-status", "dest-1", nil)
	for _, n := range []string{"uncommitted", "lost-status"} {
		if err := f.c.Delete(ctx, f.get(n)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "uncommitted"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Get(ctx, client.ObjectKey{Name: "uncommitted"}, &v1alpha1.EvidenceAttachment{}); !apierrors.IsNotFound(err) {
		t.Fatalf("uncommitted record kept: %v", err)
	}
	if len(f.stores.stores["dest-1"].deleted) != 1 {
		t.Fatal("owned attempts were not removed")
	}
	_, a := f.reconcile("lost-status")
	if a.Status.Storage.Commitment == nil || !a.Status.Storage.Commitment.ExpiresAt.Time.Equal(r.ExpiresAt) {
		t.Fatalf("a commitment found at withdrawal was not recorded: %+v", a.Status.Storage)
	}
	if a.Status.Storage.Cleanup.State != "NotDue" {
		t.Fatalf("withdrawal shortened retention: %+v", a.Status.Storage.Cleanup)
	}
	// Unreachable storage keeps the record and its ownership.
	f.stores.down = true
	f.now = r.ExpiresAt.Add(time.Hour)
	_, a = f.reconcile("lost-status")
	if a.Status.Storage.Cleanup.State != string(attachments.CleanupDeletionFailed) {
		t.Fatalf("outage: %+v", a.Status.Storage.Cleanup)
	}
}

func TestDestinationObligationsCountAttachments(t *testing.T) {
	f := newStorageFixture(t, readyDestination("primary", "dest-1"), defaultAttachmentDestination("primary", "dest-1"))
	f.create("committed", f.association("a", "uid-a"))
	f.create("pending", f.association("a", "uid-a"))
	f.reconcile("committed")
	f.reconcile("pending")
	r := f.commit("committed", "dest-1", nil)
	f.reconcile("committed")
	dr := &DestinationReconciler{Client: f.c, Reader: f.c, Namespace: "konstapel-system"}
	ed := &v1alpha1.EvidenceDestination{}
	_ = f.c.Get(context.Background(), client.ObjectKey{Name: "primary"}, ed)
	o, err := dr.obligations(context.Background(), ed)
	if err != nil {
		t.Fatal(err)
	}
	if o.packages != 1 || o.cleanup != 1 || o.empty() || o.latest == nil || !o.latest.Time.Equal(r.ExpiresAt) {
		t.Fatalf("obligations %+v", o)
	}
}
