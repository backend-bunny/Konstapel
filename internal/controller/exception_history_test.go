package controller

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/exception"
)

// Independent revocation records (add-self-service-policy-exceptions task
// 3.6), with injected API faults at each step: the record write, its
// response, the finalizer release and its response, a restart between
// them, and two controllers racing. Cases follow
// testdata/exceptions/lifecycle-matrix.yaml
// revocation-history-before-renewal-or-deletion.

var exRevokedAt = exT0.Add(30 * time.Hour)

// revoke returns ex as admission stores it after actor revoked its current
// revision at at: the protected record, spec.revoked and the finalizer.
func revoke(t *testing.T, ex *v1alpha1.ComplianceException, actor string, at time.Time) *v1alpha1.ComplianceException {
	t.Helper()
	r := exception.Revocation{ExceptionUID: ex.UID, Revision: ex.Spec.AcceptanceRevision, RequestedAt: metav1.NewTime(at),
		Actor: exception.Actor{Username: actor, UID: "u-" + actor, Groups: []string{"team-a-editors", "system:authenticated"}}, Claim: "ticket SEC-7"}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	out := ex.DeepCopy()
	out.Spec.Revoked = true
	out.Annotations[exception.RevocationAnnotation] = string(raw)
	out.Finalizers = append(out.Finalizers, exception.RevocationFinalizer)
	return out
}

// historyFaults injects API failures into the controller's client.
type historyFaults struct {
	mu sync.Mutex
	// recordCreate fails record creation before anything is stored.
	recordCreate error
	// loseRecordCreate stores the record and then reports a failure, as a
	// lost response does.
	loseRecordCreate bool
	// snapshotCreate fails snapshot creation.
	snapshotCreate error
	// release fails the finalizer release before anything is stored.
	release error
	// loseRelease stores the release and then reports a failure.
	loseRelease bool
	// beforeRelease runs before each release attempt.
	beforeRelease func()
	recordCreates int
}

var errLostResponse = errors.New("connection reset by peer (the request was applied)")

func (f *historyFaults) funcs() interceptor.Funcs {
	return interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if cm, ok := obj.(*corev1.ConfigMap); ok {
				switch {
				case strings.HasPrefix(cm.Name, "revocation-"):
					f.recordCreates++
					if f.recordCreate != nil {
						return f.recordCreate
					}
					if f.loseRecordCreate {
						if err := c.Create(ctx, obj, opts...); err != nil {
							return err
						}
						return errLostResponse
					}
				case strings.HasPrefix(cm.Name, "acceptance-") && f.snapshotCreate != nil:
					return f.snapshotCreate
				}
			}
			return c.Create(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			f.mu.Lock()
			before, fail, lose := f.beforeRelease, f.release, f.loseRelease
			f.mu.Unlock()
			if _, ok := obj.(*v1alpha1.ComplianceException); ok {
				if before != nil {
					before()
				}
				if fail != nil {
					return fail
				}
				if lose {
					if err := c.Patch(ctx, obj, patch, opts...); err != nil {
						return err
					}
					return errLostResponse
				}
			}
			return c.Patch(ctx, obj, patch, opts...)
		},
	}
}

func (f *historyFaults) set(edit func(f *historyFaults)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	edit(f)
}

func historyEnv(t *testing.T, f *historyFaults, objs ...client.Object) (client.Client, *ExceptionReconciler) {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(Scheme()).WithObjects(objs...).WithStatusSubresource(&v1alpha1.ComplianceException{}).
		WithInterceptorFuncs(f.funcs()).Build()
	return c, &ExceptionReconciler{Client: c, Reader: c, Namespace: DefaultSnapshotNamespace}
}

// step reconciles priv once and returns the result and the stored
// exception, nil once it is gone.
func step(t *testing.T, c client.Client, r *ExceptionReconciler) (ctrl.Result, error, *v1alpha1.ComplianceException) {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "team-a", Name: "priv"}})
	ex := &v1alpha1.ComplianceException{}
	if gerr := c.Get(context.Background(), client.ObjectKey{Namespace: "team-a", Name: "priv"}, ex); apierrors.IsNotFound(gerr) {
		return res, err, nil
	} else if gerr != nil {
		t.Fatal(gerr)
	}
	return res, err, ex
}

func revocationRecord(t *testing.T, c client.Client, uid types.UID, rev int64) *corev1.ConfigMap {
	t.Helper()
	cm := &corev1.ConfigMap{}
	err := c.Get(context.Background(), client.ObjectKey{Namespace: DefaultSnapshotNamespace, Name: exception.RevocationRecordName(uid, rev)}, cm)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return cm
}

func historyCondition(ex *v1alpha1.ComplianceException) *metav1.Condition {
	return meta.FindStatusCondition(ex.Status.Conditions, v1alpha1.ConditionRevocationRecorded)
}

func holds(ex *v1alpha1.ComplianceException) bool {
	return ex != nil && slices.Contains(ex.Finalizers, exception.RevocationFinalizer)
}

func TestRevocationIsRecordedBeforeTheFinalizerIsReleased(t *testing.T) {
	for name, ex := range map[string]*v1alpha1.ComplianceException{
		"active": acceptedException(t, 1, "alice", revA),
		"expired": func() *v1alpha1.ComplianceException {
			e := acceptedException(t, 1, "alice", revA)
			e.Spec.ExpiresAt = metav1.NewTime(exT0)
			return e
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			f := &historyFaults{}
			c, r := historyEnv(t, f, revoke(t, ex, "dave", exRevokedAt))
			// The release must find the record already stored.
			f.beforeRelease = func() {
				if revocationRecord(t, c, "ex-1", 1) == nil {
					t.Error("finalizer release attempted before the record was persisted")
				}
			}
			res, err, got := step(t, c, r)
			if err != nil || res.RequeueAfter != 0 {
				t.Fatalf("reconcile = %+v %v", res, err)
			}
			cm := revocationRecord(t, c, "ex-1", 1)
			if cm == nil {
				t.Fatal("no revocation record")
			}
			rec, _, err := exception.RevocationRecordFrom(cm)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case rec.Revocation.Actor.Username != "dave" || !rec.Revocation.RequestedAt.Time.Equal(exRevokedAt) || rec.Revocation.Claim != "ticket SEC-7":
				t.Errorf("record attribution = %+v", rec.Revocation)
			case rec.Exception.UID != "ex-1" || rec.AcceptanceRevision != 1 || rec.Namespace.UID != "ns-a-1" || rec.Cluster != "kube-system:test":
				t.Errorf("record identity = %+v", rec)
			case rec.Acceptance == nil || got.Status.Acceptance == nil || *rec.Acceptance != *got.Status.Acceptance:
				t.Errorf("acceptance reference %+v, status %+v", rec.Acceptance, got.Status.Acceptance)
			case len(cm.OwnerReferences) != 0 || cm.Immutable == nil || !*cm.Immutable:
				t.Errorf("record owners %v immutable %v", cm.OwnerReferences, cm.Immutable)
			case holds(got) || !got.Spec.Revoked || got.Annotations[exception.RevocationAnnotation] == "":
				t.Errorf("after recording: finalizers %v revoked %v", got.Finalizers, got.Spec.Revoked)
			}
			if cond := historyCondition(got); cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != v1alpha1.ReasonRevocationRecorded ||
				!strings.Contains(cond.Message, "konstapel-system/revocation-ex-1-1") {
				t.Errorf("condition = %+v", cond)
			}
			// The acceptance snapshot is unchanged by revocation.
			snap, _, err := exception.SnapshotFrom(&snapshotConfigMaps(t, c, client.MatchingLabels{exception.LabelComponent: exception.ComponentSnapshot})[0])
			if err != nil || snap.Actor.Username != "alice" {
				t.Errorf("snapshot after revocation: %+v %v", snap, err)
			}
			// A restart re-verifies and rewrites nothing.
			restarted := &ExceptionReconciler{Client: c, Reader: c, Namespace: DefaultSnapshotNamespace}
			if _, err, _ := step(t, c, restarted); err != nil {
				t.Fatal(err)
			}
			if again := revocationRecord(t, c, "ex-1", 1); again.ResourceVersion != cm.ResourceVersion || f.recordCreates != 1 {
				t.Errorf("record rewritten after restart (creates %d)", f.recordCreates)
			}
		})
	}
}

// Revoke-then-delete before the controller ever ran: the acceptance was
// never activated, yet finalization keeps its snapshot and the revocation.
func TestRevokedNeverActivatedExceptionKeepsItsHistory(t *testing.T) {
	ex := revoke(t, acceptedException(t, 1, "alice", revA), "alice", exT0.Add(time.Minute))
	now := metav1.NewTime(exT0.Add(2 * time.Minute))
	ex.DeletionTimestamp = &now
	c, r := historyEnv(t, &historyFaults{}, ex)
	if _, err, got := step(t, c, r); err != nil || got != nil {
		t.Fatalf("finalization: %v, exception %v", err, got != nil)
	}
	rec, _, err := exception.RevocationRecordFrom(revocationRecord(t, c, "ex-1", 1))
	if err != nil {
		t.Fatal(err)
	}
	snaps := snapshotConfigMaps(t, c, client.MatchingLabels{exception.LabelComponent: exception.ComponentSnapshot, exception.LabelExceptionUID: "ex-1"})
	if len(snaps) != 1 || rec.Acceptance == nil || rec.Acceptance.Snapshot != DefaultSnapshotNamespace+"/"+snaps[0].Name ||
		rec.Acceptance.Digest != snaps[0].Annotations[exception.AnnotationSnapshotDigest] {
		t.Errorf("record %+v, snapshots %d", rec.Acceptance, len(snaps))
	}
}

// Matrix case revocation-history-before-renewal-or-deletion: while the
// record cannot be written, the intent and its finalizer stay through
// deletion and restart, the rest of reconciliation continues, and the
// record is written once writes are restored.
func TestRevocationHistoryPersistenceFailure(t *testing.T) {
	f := &historyFaults{recordCreate: apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, "revocation-ex-1-1", errors.New("denied"))}
	c, r := historyEnv(t, f, revoke(t, acceptedException(t, 1, "alice", revA), "alice", exRevokedAt))
	res, err, got := step(t, c, r)
	if err != nil || res.RequeueAfter != historyRetry {
		t.Fatalf("reconcile = %+v %v", res, err)
	}
	cond := historyCondition(got)
	switch {
	case cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != v1alpha1.ReasonRevocationHistoryPending:
		t.Errorf("condition = %+v", cond)
	case !holds(got) || revocationRecord(t, c, "ex-1", 1) != nil:
		t.Error("finalizer released, or a record written, while persistence fails")
	case recorded(t, got).Status != metav1.ConditionTrue:
		// Independent work continues: the snapshot is recorded.
		t.Errorf("snapshot condition = %+v", recorded(t, got))
	}
	// Delete: the finalizer holds the object and the last copy of the intent.
	if err := c.Delete(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	for _, rr := range []*ExceptionReconciler{r, {Client: c, Reader: c, Namespace: DefaultSnapshotNamespace}} {
		_, err, got = step(t, c, rr)
		if err != nil || !holds(got) || got.DeletionTimestamp.IsZero() || got.Annotations[exception.RevocationAnnotation] == "" {
			t.Fatalf("terminating while persistence fails: err %v, exception %+v", err, got)
		}
	}
	f.set(func(f *historyFaults) { f.recordCreate = nil })
	if _, err, got = step(t, c, r); err != nil || got != nil {
		t.Fatalf("after writes are restored: %v, exception still present %v", err, got != nil)
	}
	if revocationRecord(t, c, "ex-1", 1) == nil {
		t.Error("no record after finalization")
	}
}

// The record was stored but the response was lost: the retry finds it,
// verifies it and does not write again.
func TestLostRecordCreateResponse(t *testing.T) {
	f := &historyFaults{loseRecordCreate: true}
	c, r := historyEnv(t, f, revoke(t, acceptedException(t, 1, "alice", revA), "alice", exRevokedAt))
	res, err, got := step(t, c, r)
	if err != nil || res.RequeueAfter != historyRetry || !holds(got) {
		t.Fatalf("lost response: %+v %v, holds %v", res, err, holds(got))
	}
	stored := revocationRecord(t, c, "ex-1", 1)
	if stored == nil {
		t.Fatal("the lost write was not stored")
	}
	f.set(func(f *historyFaults) { f.loseRecordCreate = false })
	if _, err, got = step(t, c, r); err != nil || holds(got) {
		t.Fatalf("retry: %v holds %v", err, holds(got))
	}
	if after := revocationRecord(t, c, "ex-1", 1); after.ResourceVersion != stored.ResourceVersion || f.recordCreates != 1 {
		t.Errorf("record rewritten (creates %d)", f.recordCreates)
	}
}

// A crash between persisting and releasing: a new controller verifies the
// stored record, rewrites nothing and releases.
func TestRestartBetweenPersistAndRelease(t *testing.T) {
	f := &historyFaults{release: errors.New("controller stopped")}
	ex := revoke(t, acceptedException(t, 1, "alice", revA), "alice", exRevokedAt)
	c, r := historyEnv(t, f, ex)
	if _, err, got := step(t, c, r); err == nil || !holds(got) {
		t.Fatalf("failed release: %v holds %v", err, holds(got))
	}
	stored := revocationRecord(t, c, "ex-1", 1)
	if stored == nil {
		t.Fatal("record not persisted before the release")
	}
	f.set(func(f *historyFaults) { f.release = nil })
	restarted := &ExceptionReconciler{Client: c, Reader: c, Namespace: DefaultSnapshotNamespace}
	_, err, got := step(t, c, restarted)
	if err != nil || holds(got) {
		t.Fatalf("after restart: %v holds %v", err, holds(got))
	}
	if after := revocationRecord(t, c, "ex-1", 1); after.ResourceVersion != stored.ResourceVersion || f.recordCreates != 1 {
		t.Errorf("record rewritten after restart (creates %d)", f.recordCreates)
	}
	if cond := historyCondition(got); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Errorf("condition = %+v", cond)
	}
}

// The release was applied but its response was lost: the next reconcile
// finds nothing to release and reports the record.
func TestLostReleaseResponse(t *testing.T) {
	f := &historyFaults{loseRelease: true}
	c, r := historyEnv(t, f, revoke(t, acceptedException(t, 1, "alice", revA), "alice", exRevokedAt))
	if _, err, got := step(t, c, r); err == nil || holds(got) {
		t.Fatalf("lost release response: err %v holds %v", err, holds(got))
	}
	f.set(func(f *historyFaults) { f.loseRelease = false })
	_, err, got := step(t, c, r)
	if err != nil || holds(got) {
		t.Fatalf("retry: %v", err)
	}
	if cond := historyCondition(got); cond == nil || cond.Status != metav1.ConditionTrue || f.recordCreates != 1 {
		t.Errorf("condition %+v, creates %d", cond, f.recordCreates)
	}
}

// racingRecordReader reports the record missing once, as a lagging view would,
// running other first: two controllers (an old and a new leader) race.
type racingRecordReader struct {
	client.Reader
	once  sync.Once
	other func()
}

func (s *racingRecordReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	stale := false
	if strings.HasPrefix(key.Name, "revocation-") {
		s.once.Do(func() { s.other(); stale = true })
	}
	if stale {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "configmaps"}, key.Name)
	}
	return s.Reader.Get(ctx, key, obj, opts...)
}

func TestConcurrentControllersRecordOnce(t *testing.T) {
	f := &historyFaults{}
	c, a := historyEnv(t, f, revoke(t, acceptedException(t, 1, "alice", revA), "alice", exRevokedAt))
	b := &ExceptionReconciler{Client: c, Namespace: DefaultSnapshotNamespace}
	b.Reader = &racingRecordReader{Reader: c, other: func() {
		if _, err, _ := step(t, c, a); err != nil {
			t.Errorf("controller a: %v", err)
		}
	}}
	// b read the exception before a ran, so its release is stale and the
	// optimistic lock rejects it.
	if _, err, _ := step(t, c, b); !apierrors.IsConflict(err) {
		t.Fatalf("controller b: want a conflict, got %v", err)
	}
	if _, err, got := step(t, c, b); err != nil || holds(got) {
		t.Fatalf("controller b retry: %v holds %v", err, holds(got))
	}
	cms := snapshotConfigMaps(t, c, client.MatchingLabels{exception.LabelComponent: exception.ComponentRevocation})
	if len(cms) != 1 || f.recordCreates != 2 {
		t.Fatalf("records %d, creates %d", len(cms), f.recordCreates)
	}
	if rec, _, err := exception.RevocationRecordFrom(&cms[0]); err != nil || rec.Revocation.Actor.Username != "alice" {
		t.Errorf("record = %+v %v", rec, err)
	}
}

// An object at the record's name that is not this revocation's record is
// never overwritten, and the intent and finalizer stay until it is gone.
func TestExistingRevocationRecordIsNeverOverwritten(t *testing.T) {
	ex := revoke(t, acceptedException(t, 1, "alice", revA), "alice", exRevokedAt)
	rec, err := exception.NewRevocationRecord(ex, DefaultSnapshotNamespace)
	if err != nil {
		t.Fatal(err)
	}
	good, _, _ := rec.ConfigMap(DefaultSnapshotNamespace)
	forged := *rec
	forged.Revocation.Actor = exception.Actor{Username: "platform-admin"}
	forgedCM, _, _ := forged.ConfigMap(DefaultSnapshotNamespace)
	later := *rec
	later.Revocation.RequestedAt = metav1.NewTime(exRevokedAt.Add(time.Hour))
	laterCM, _, _ := later.ConfigMap(DefaultSnapshotNamespace)
	for name, squatter := range map[string]*corev1.ConfigMap{
		"mutable copy": func() *corev1.ConfigMap { cm := good.DeepCopy(); cm.Immutable = nil; return cm }(),
		"unmanaged":    {ObjectMeta: metav1.ObjectMeta{Name: good.Name, Namespace: DefaultSnapshotNamespace}, Data: map[string]string{"x": "y"}},
		"no document":  func() *corev1.ConfigMap { cm := good.DeepCopy(); cm.Data = map[string]string{}; return cm }(),
		"tampered": func() *corev1.ConfigMap {
			cm := good.DeepCopy()
			cm.Data[exception.RevocationRecordDataKey] += " "
			return cm
		}(),
		"other actor":      forgedCM,
		"other time":       laterCM,
		"partially copied": func() *corev1.ConfigMap { cm := good.DeepCopy(); cm.Annotations = nil; return cm }(),
	} {
		t.Run(name, func(t *testing.T) {
			f := &historyFaults{}
			c, r := historyEnv(t, f, ex.DeepCopy(), squatter.DeepCopy())
			before := revocationRecord(t, c, "ex-1", 1)
			res, err, got := step(t, c, r)
			if err != nil || res.RequeueAfter != historyConflictRetry {
				t.Fatalf("reconcile = %+v %v", res, err)
			}
			if cond := historyCondition(got); cond == nil || cond.Reason != v1alpha1.ReasonRevocationRecordConflict || !holds(got) {
				t.Errorf("condition %+v holds %v", cond, holds(got))
			}
			if after := revocationRecord(t, c, "ex-1", 1); after.ResourceVersion != before.ResourceVersion || f.recordCreates != 0 {
				t.Error("the existing object was overwritten")
			}
			// An operator removes it: the record is written and released.
			if err := c.Delete(context.Background(), before); err != nil {
				t.Fatal(err)
			}
			if _, err, got := step(t, c, r); err != nil || holds(got) {
				t.Fatalf("after removal: %v holds %v", err, holds(got))
			}
		})
	}
}

// spec.revoked with a protected record that does not belong to the
// current revision cannot be recorded, and nothing is released.
func TestInvalidRevocationHoldsTheFinalizer(t *testing.T) {
	ex := revoke(t, acceptedException(t, 1, "alice", revA), "alice", exRevokedAt)
	r := exception.Revocation{ExceptionUID: "ex-1", Revision: 2, RequestedAt: metav1.NewTime(exRevokedAt), Actor: exception.Actor{Username: "alice"}}
	raw, _ := json.Marshal(r)
	ex.Annotations[exception.RevocationAnnotation] = string(raw)
	c, rec := historyEnv(t, &historyFaults{}, ex)
	_, err, got := step(t, c, rec)
	if err != nil {
		t.Fatal(err)
	}
	if cond := historyCondition(got); cond == nil || cond.Reason != v1alpha1.ReasonRevocationInvalid || !holds(got) ||
		len(snapshotConfigMaps(t, c, client.MatchingLabels{exception.LabelComponent: exception.ComponentRevocation})) != 0 {
		t.Errorf("condition %+v holds %v", cond, holds(got))
	}
}

// The record does not wait for the snapshot, but the finalizer does: while
// the snapshot cannot be written, the acceptance record on the resource is
// the last copy of the acceptance.
func TestSnapshotProblemsHoldTheFinalizerNotTheRecord(t *testing.T) {
	t.Run("transient", func(t *testing.T) {
		f := &historyFaults{snapshotCreate: errors.New("etcdserver: request timed out")}
		c, r := historyEnv(t, f, revoke(t, acceptedException(t, 1, "alice", revA), "alice", exRevokedAt))
		if _, err, got := step(t, c, r); err == nil || !holds(got) || revocationRecord(t, c, "ex-1", 1) == nil {
			t.Fatalf("err %v holds %v", err, holds(got))
		}
		f.set(func(f *historyFaults) { f.snapshotCreate = nil })
		if _, err, got := step(t, c, r); err != nil || holds(got) {
			t.Fatalf("after recovery: %v holds %v", err, holds(got))
		}
	})
	t.Run("conflict while deleting", func(t *testing.T) {
		ex := revoke(t, acceptedException(t, 1, "alice", revA), "alice", exRevokedAt)
		now := metav1.NewTime(exRevokedAt)
		ex.DeletionTimestamp = &now
		squatter := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "acceptance-ex-1-1", Namespace: DefaultSnapshotNamespace}, Data: map[string]string{"x": "y"}}
		c, r := historyEnv(t, &historyFaults{}, ex, squatter)
		_, err, got := step(t, c, r)
		if err != nil || !holds(got) || revocationRecord(t, c, "ex-1", 1) == nil {
			t.Fatalf("err %v holds %v", err, holds(got))
		}
		if cond := recorded(t, got); cond.Reason != v1alpha1.ReasonSnapshotConflict {
			t.Errorf("snapshot condition = %+v", cond)
		}
	})
}

// Rapid renewal and revocation: each revoked revision keeps its own record,
// attributed to its own revoker, and a renewal never rewrites an earlier
// one.
func TestEachRevokedRevisionKeepsItsRecord(t *testing.T) {
	f := &historyFaults{}
	c, r := historyEnv(t, f, revoke(t, acceptedException(t, 1, "alice", revA), "alice", exRevokedAt))
	if _, err, got := step(t, c, r); err != nil || holds(got) {
		t.Fatalf("revision 1: %v", err)
	}
	first := revocationRecord(t, c, "ex-1", 1)

	// Renewal (as admission stores it once the record is durable): revision
	// 2, unrevoked, the revocation record cleared.
	ex := &v1alpha1.ComplianceException{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "team-a", Name: "priv"}, ex); err != nil {
		t.Fatal(err)
	}
	renewed := acceptedException(t, 2, "dave", revA)
	ex.Spec, ex.Annotations = renewed.Spec, renewed.Annotations
	if err := c.Update(context.Background(), ex); err != nil {
		t.Fatal(err)
	}
	_, err, got := step(t, c, r)
	if err != nil || historyCondition(got) != nil || got.Status.Acceptance.Revision != 2 {
		t.Fatalf("renewal: %v %+v", err, got.Status)
	}
	// Revoke revision 2 and delete at once.
	revoked2 := revoke(t, got, "erin", exRevokedAt.Add(time.Hour))
	if err := c.Update(context.Background(), revoked2); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(context.Background(), revoked2); err != nil {
		t.Fatal(err)
	}
	if _, err, got := step(t, c, r); err != nil || got != nil {
		t.Fatalf("revision 2 revoke-then-delete: %v present %v", err, got != nil)
	}
	records := snapshotConfigMaps(t, c, client.MatchingLabels{exception.LabelComponent: exception.ComponentRevocation, exception.LabelExceptionUID: "ex-1"})
	if len(records) != 2 {
		t.Fatalf("records = %d", len(records))
	}
	for _, cm := range records {
		rec, _, err := exception.RevocationRecordFrom(&cm)
		if err != nil {
			t.Fatal(err)
		}
		want := map[int64]string{1: "alice", 2: "erin"}[rec.AcceptanceRevision]
		if rec.Revocation.Actor.Username != want || rec.Acceptance == nil || rec.Acceptance.Revision != rec.AcceptanceRevision {
			t.Errorf("record %d = %+v", rec.AcceptanceRevision, rec)
		}
	}
	if after := revocationRecord(t, c, "ex-1", 1); after.ResourceVersion != first.ResourceVersion {
		t.Error("revision 1's record changed")
	}
	if n := len(snapshotConfigMaps(t, c, client.MatchingLabels{exception.LabelComponent: exception.ComponentSnapshot})); n != 2 {
		t.Errorf("snapshots = %d", n)
	}
}
