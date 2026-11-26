package controller

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// add-evidence-signing-recovery 2.4: the recovery attempt through the run
// path's signingRequirement and the commit gate under the destination fence.

// recordedSecret is the fixture intent's recorded key Secret name.
const recordedSecret = "never-installed"

// secretReads records every Secret read through the recovery and run paths'
// API clients and the destinations' uncached reader.
type secretReads struct {
	mu    sync.Mutex
	names []string
}

func (s *secretReads) add(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.names = append(s.names, name)
}

func (s *secretReads) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.names...)
}

// recordSecretReads routes the recovery reconciler and the destinations'
// reader through a client that records Secret reads (a list counts as a
// read of every Secret).
func (e *recoveryEnv) recordSecretReads() *secretReads {
	e.t.Helper()
	reads := &secretReads{}
	c := interceptor.NewClient(e.c.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Secret); ok {
				reads.add(key.Name)
			}
			return cl.Get(ctx, key, obj, opts...)
		},
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*corev1.SecretList); ok {
				reads.add("*")
			}
			return cl.List(ctx, list, opts...)
		}})
	e.rec.Client, e.rec.Reader = c, c
	e.rr.Runtime.Destinations.Reader = c
	return reads
}

// successor replaces the recovery reconciler with a new leader's (nothing
// in memory) over the same clients.
func (e *recoveryEnv) successor() {
	e.rec = &SigningRecoveryReconciler{Client: e.rec.Client, Reader: e.rec.Reader, Runtime: e.rr.Runtime, Now: func() time.Time { return e.now }}
}

// installKey installs a runtime-generated key under the intent's recorded
// Secret name and returns it with its fingerprint.
func (e *recoveryEnv) installKey(password string) (*corev1.Secret, string) {
	e.t.Helper()
	key, fp := signingKeySecret(e.t, recordedSecret, password)
	e.putSecret(key)
	cur := &corev1.Secret{}
	if err := e.c.Get(context.Background(), client.ObjectKeyFromObject(key), cur); err != nil {
		e.t.Fatal(err)
	}
	return cur, fp
}

// wantEnded checks a request that ended with reason, released its claim,
// and names no Secret.
func (e *recoveryEnv) wantEnded(name string, reason v1alpha1.SigningRecoveryReason, contains string) {
	e.t.Helper()
	st := e.esr(name).Status
	if st.Phase != v1alpha1.SigningRequestFailed || st.Reason != reason || !strings.Contains(st.Message, contains) || st.CompletedAt == nil ||
		st.KeyFingerprint != "" || st.Publication != nil || !meta.IsStatusConditionTrue(st.Conditions, v1alpha1.ConditionSigningRequestComplete) {
		e.t.Fatalf("%s: want Failed/%s (%q): %s", name, reason, contains, js(st))
	}
	if strings.Contains(js(st), recordedSecret) {
		e.t.Fatalf("%s: the request status names the key Secret: %s", name, js(st))
	}
	if c := claimOf(e.run_()); c != nil && c.Name == name {
		e.t.Fatalf("%s ended but kept its claim", name)
	}
}

// wantRunning checks the holder's Running reason and message.
func (e *recoveryEnv) wantRunning(name string, reason v1alpha1.SigningRecoveryReason, contains string) {
	e.t.Helper()
	esr := e.esr(name)
	st := esr.Status
	if st.Phase != v1alpha1.SigningRequestRunning || st.Reason != reason || !strings.Contains(st.Message, contains) || st.CompletedAt != nil ||
		meta.IsStatusConditionTrue(st.Conditions, v1alpha1.ConditionSigningRequestComplete) || !holdsClaim(claimOf(e.run_()), esr) {
		e.t.Fatalf("%s: want the holder Running/%s (%q): %s claim %s", name, reason, contains, js(st), js(claimOf(e.run_())))
	}
	if strings.Contains(js(st), recordedSecret) {
		e.t.Fatalf("%s: the request status names the key Secret: %s", name, js(st))
	}
}

// wantCommitted checks the run's single commit: signed under fp with the
// stored signature, which verifies for the intent's archive under the
// intent's pinned key, and carrying the run's recorded retention bounded by
// its recorded expiry.
func (e *recoveryEnv) wantCommitted(fp string) publication.Status {
	e.t.Helper()
	ctx := context.Background()
	run := e.run_()
	st, err := e.store().Inspect(ctx, e.ref())
	if err != nil || st.Commit == nil || st.Signature == nil || st.Signature.KeyFingerprint != fp || e.store().Commits() != 1 {
		e.t.Fatalf("want one commit signed under %s: %+v commits %d %v", fp, st, e.store().Commits(), err)
	}
	in := run.Status.SigningIntent
	if in.Key == nil || in.Key.Fingerprint != fp || st.PackageSHA256 != in.ArchiveSHA256 {
		e.t.Fatalf("the commit is not the intent's: %s", js(in))
	}
	bundle, ref, err := e.store().ReadSignature(ctx, e.ref())
	if err != nil || ref.SHA256 != st.Signature.SHA256 {
		e.t.Fatalf("the committed signature %s is not the stored bundle %s: %v", st.Signature.SHA256, ref.SHA256, err)
	}
	pub, err := evidencesign.ParsePublicKey([]byte(in.Key.PublicKey))
	if err != nil {
		e.t.Fatal(err)
	}
	d, _ := evidencesign.ParseArchiveDigest(in.ArchiveSHA256)
	if _, err := evidencesign.Verify(bundle, d, pub); err != nil {
		e.t.Fatalf("the committed signature does not verify under the pinned key: %v", err)
	}
	recorded := e.failed.Publication.ExpiresAt.Time
	if r := st.Retention; r == nil || r.Duration != string(e.failed.Retention) || r.NotAfter == nil || !r.NotAfter.Equal(recorded) || !st.ExpiresAt.Equal(recorded) {
		e.t.Fatalf("want the recorded retention %s bounded by the recorded expiry %s: %s expires %s", e.failed.Retention, recorded, js(st.Retention), st.ExpiresAt)
	}
	return st
}

// An intent that never pinned a key pins one only as a request confirms it:
// no confirmation is decided before any Secret is read, and a Secret holding
// another key pins nothing. A confirmed key is pinned once and signs; the
// commit carries the run's recorded retention and expiry, not the binding's
// current retention, with its real (late) commit time.
func TestSigningRecoveryUnpinnedKeyConfirmation(t *testing.T) {
	e := newRecoveryEnv(t)
	if e.run_().Status.Retention == "" {
		t.Fatal("fixture: the run recorded no retention at closure")
	}
	reads := e.recordSecretReads()
	pre, writes := js(e.run_().Status), storageWrites(e.store())
	unchanged := func(what string) {
		t.Helper()
		if js(e.run_().Status) != pre || storageWrites(e.store()) != writes {
			t.Fatalf("%s changed the run or wrote storage:\n%s\n%s", what, pre, js(e.run_().Status))
		}
	}

	e.requestKey("unconfirmed", e.name, e.uid(), "")
	e.reconcile("unconfirmed")
	e.reconcile("unconfirmed")
	e.wantEnded("unconfirmed", v1alpha1.RecoveryKeyConfirmationRequired, "expectedKeyFingerprint")
	unchanged("KeyConfirmationRequired")
	if got := reads.all(); len(got) != 0 {
		t.Fatalf("KeyConfirmationRequired read Secrets: %v", got)
	}

	key, fp := e.installKey("pw-b")
	_, other := signingKeySecret(t, "elsewhere", "pw-other")
	e.request("other-key", e.name, e.uid())
	e.requestKey("wrong", e.name, e.uid(), other)
	e.reconcile("other-key")
	e.reconcile("wrong")
	e.reconcile("other-key")
	e.wantEnded("other-key", v1alpha1.RecoveryKeyMismatch, "not the confirmed "+absentKeyFingerprint)
	e.reconcile("wrong")
	e.reconcile("wrong")
	e.wantEnded("wrong", v1alpha1.RecoveryKeyMismatch, "holds key "+fp)
	unchanged("KeyMismatch")

	// The binding's retention changed after the failure: never used.
	b := &v1alpha1.ComplianceBinding{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: "audit-prod"}, b); err != nil {
		t.Fatal(err)
	}
	if b.Spec.Assessment == nil {
		b.Spec.Assessment = &v1alpha1.BindingAssessment{}
	}
	b.Spec.Assessment.Retention = "720h"
	if err := e.c.Update(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Hour)
	e.requestKey("confirmed", e.name, e.uid(), fp)
	e.reconcile("confirmed")
	e.reconcile("confirmed")
	e.wantRecovered("confirmed", v1alpha1.RecoveryRecovered, "confirmed")
	st := e.wantCommitted(fp)
	if !st.PublishedAt.Equal(e.now.UTC().Truncate(time.Second)) {
		t.Fatalf("publishedAt %s is not the late commit time %s", st.PublishedAt, e.now)
	}
	run := e.run_()
	k := run.Status.SigningIntent.Key
	if k.SecretUID != string(key.UID) || k.SecretResourceVersion != key.ResourceVersion || !k.PinnedAt.Equal(&metav1.Time{Time: e.now.Truncate(time.Second)}) {
		t.Fatalf("the confirmed key's pin: %s", js(k))
	}
	if e.store().Calls(fake.OpStoreSignature) != 1 {
		t.Fatalf("signature stored %d times", e.store().Calls(fake.OpStoreSignature))
	}
	// Besides the pin, only the recovered publication changed the run
	// (wantRecovered); a later reconcile of the ended request and a later
	// request write no storage and leave the run as recovered.
	writes, again := storageWrites(e.store()), js(e.esr("confirmed").Status)
	e.now = e.now.Add(time.Minute)
	e.reconcile("confirmed")
	e.request("later", e.name, e.uid())
	e.reconcile("later")
	e.wantSucceeded("later", v1alpha1.RecoveryAlreadyRecovered)
	if storageWrites(e.store()) != writes || js(e.esr("confirmed").Status) != again || js(e.run_()) != js(run) {
		t.Fatal("a later reconcile wrote storage, the run, or the ended request")
	}
}

// A stored signature that verifies under the pinned key is committed
// without reading any private key: here, after a failed commit, the
// recorded Secret holds another key and the destination no longer requires
// signing, and a successor never reads a Secret, never re-signs, and never
// commits unsigned.
func TestSigningRecoveryStoredSignatureNeedsNoKey(t *testing.T) {
	e := newRecoveryEnv(t)
	_, fp := e.installKey("pw-b")
	e.requestKey("holder", e.name, e.uid(), fp)
	e.store().Fail(fake.OpPublish, publication.ErrUnavailable)
	e.store().Fail(fake.OpPublish, publication.ErrUnavailable)
	e.reconcile("holder")
	e.reconcile("holder")
	e.wantRunning("holder", v1alpha1.RecoveryCommitting, "retrying")
	// A retried attempt with the same outcome rewrites nothing.
	if rv := e.esr("holder").ResourceVersion; e.reconcile("holder").ResourceVersion != rv {
		t.Fatal("a retried commit rewrote the request")
	}
	stored, _, err := e.store().ReadSignature(context.Background(), e.ref())
	if err != nil || e.store().Commits() != 0 {
		t.Fatalf("fixture: want a stored signature and no commit: %v commits %d", err, e.store().Commits())
	}

	e.installKey("pw-rotated")
	e.setSigning(nil)
	reads := e.recordSecretReads()
	e.successor()
	e.now = e.now.Add(time.Minute)
	e.reconcile("holder")
	if got := reads.all(); len(got) != 0 {
		t.Fatalf("the stored-signature path read Secrets: %v", got)
	}
	e.wantRecovered("holder", v1alpha1.RecoveryRecovered, "holder")
	e.wantCommitted(fp)
	again, _, _ := e.store().ReadSignature(context.Background(), e.ref())
	if string(again) != string(stored) || e.store().Calls(fake.OpStoreSignature) != 1 {
		t.Fatal("the stored signature was replaced or re-made")
	}
}

// A pinned intent accepts only its pinned key: a rotated key in the
// recorded Secret is KeyMismatch (nothing signed or committed, the intent
// unchanged), even when the destination now names another Secret holding
// the pinned key and the request states the rotated key's fingerprint. Once
// the pinned key is back, a new request commits with it.
func TestSigningRecoveryPinnedKeyMismatch(t *testing.T) {
	e := newRecoveryEnv(t)
	key, fp := e.installKey("pw-b")
	e.requestKey("first", e.name, e.uid(), fp)
	e.store().Fail(fake.OpStoreSignature, publication.ErrUnavailable)
	e.reconcile("first")
	e.reconcile("first")
	e.wantRunning("first", v1alpha1.RecoverySigning, "retrying")
	if k := e.run_().Status.SigningIntent.Key; k == nil || k.Fingerprint != fp {
		t.Fatalf("fixture: want the intent pinned to %s: %s", fp, js(k))
	}
	pinned := js(e.run_().Status.SigningIntent)

	_, rotated := e.installKey("pw-rotated")
	elsewhere := key.DeepCopy()
	elsewhere.ObjectMeta = metav1.ObjectMeta{Namespace: key.Namespace, Name: "rotated"}
	e.putSecret(elsewhere)
	e.setSigning(requiredSigning("rotated"))
	writes := storageWrites(e.store())
	e.reconcile("first")
	e.wantEnded("first", v1alpha1.RecoveryKeyMismatch, "requires "+fp)
	e.requestKey("rotated-key", e.name, e.uid(), rotated)
	e.reconcile("rotated-key")
	e.reconcile("rotated-key")
	e.wantEnded("rotated-key", v1alpha1.RecoveryKeyMismatch, "now holds key "+rotated)
	if _, _, err := e.store().ReadSignature(context.Background(), e.ref()); err == nil || storageWrites(e.store()) != writes || js(e.run_().Status.SigningIntent) != pinned {
		t.Fatalf("a mismatch signed, committed, or changed the intent: %v", err)
	}

	e.putSecret(key)
	e.request("restored", e.name, e.uid())
	e.reconcile("restored")
	e.reconcile("restored")
	e.wantRecovered("restored", v1alpha1.RecoveryRecovered, "restored")
	e.wantCommitted(fp)
	if js(e.run_().Status.SigningIntent) != pinned {
		t.Fatal("the recovery changed the pinned intent")
	}
}

// A stored signature that does not verify under the pinned key is never
// replaced: Conflict, with no private key read and no commit.
func TestSigningRecoveryInvalidStoredSignature(t *testing.T) {
	e := newRecoveryEnv(t)
	ctx := context.Background()
	key, fp := e.installKey("pw-b")
	signer, err := evidencesign.NewSecretSigner(key.Data)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()
	e.patchRun(func(r *v1alpha1.AssessmentRun) {
		r.Status.SigningIntent.Key = &v1alpha1.SigningKey{Fingerprint: fp, Algorithm: pub.Algorithm, PublicKey: string(pub.PEM), PinnedAt: metav1.NewTime(e.now)}
	})
	otherKey, _ := signingKeySecret(t, "other", "pw-other")
	other, err := evidencesign.NewSecretSigner(otherKey.Data)
	if err != nil {
		t.Fatal(err)
	}
	staged, _ := e.store().Recover(ctx, e.ref())
	d, _ := evidencesign.ParseArchiveDigest(staged.PackageSHA256)
	sig, err := other.Sign(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	e.store().SetSignature(e.ref(), sig.Bundle)
	reads := e.recordSecretReads()
	e.request("holder", e.name, e.uid())
	e.reconcile("holder")
	e.reconcile("holder")
	e.wantEnded("holder", v1alpha1.RecoveryConflict, "never replaced")
	stored, _, _ := e.store().ReadSignature(ctx, e.ref())
	if string(stored) != string(sig.Bundle) || e.store().Commits() != 0 || e.store().Calls(fake.OpStoreSignature) != 0 {
		t.Fatal("the invalid stored signature was replaced or committed")
	}
	if got := reads.all(); len(got) != 0 {
		t.Fatalf("verifying the stored signature read Secrets: %v", got)
	}
}

// A commit whose response was lost is adopted unchanged by the next
// attempt within the deadline: no second commit and no Publish, the
// original publication time kept, and no key read.
func TestSigningRecoveryLostCommitAdopts(t *testing.T) {
	e := newRecoveryEnv(t)
	_, fp := e.installKey("pw-b")
	e.requestKey("holder", e.name, e.uid(), fp)
	e.store().LoseResponse(fake.OpPublish)
	e.reconcile("holder")
	e.reconcile("holder")
	e.wantRunning("holder", v1alpha1.RecoveryCommitting, "retrying")
	first := e.wantCommitted(fp)

	reads := e.recordSecretReads()
	e.successor()
	e.now = e.now.Add(time.Minute)
	writes, publishes := storageWrites(e.store()), e.store().Calls(fake.OpPublish)
	e.reconcile("holder")
	e.wantRecovered("holder", v1alpha1.RecoveryRecovered, "holder")
	if pub := e.run_().Status.Publication; !pub.PublishedAt.Time.Equal(*first.PublishedAt) {
		t.Fatalf("the recorded publication is not the adopted commit's: %s", js(pub))
	}
	if got := e.wantCommitted(fp); !got.PublishedAt.Equal(*first.PublishedAt) || !got.ExpiresAt.Equal(*first.ExpiresAt) {
		t.Fatalf("the adopted commit changed: %s -> %s", js(first), js(got))
	}
	if storageWrites(e.store()) != writes || e.store().Calls(fake.OpPublish) != publishes {
		t.Fatal("adoption wrote storage or published again")
	}
	if got := reads.all(); len(got) != 0 {
		t.Fatalf("adoption read Secrets: %v", got)
	}
}

// Concurrent requests reconciled by overlapping reconcilers (as leaders
// would) converge on one pin, one stored signature, and one commit; exactly
// one request holds the run and the others wait.
func TestSigningRecoveryConcurrentRequestsConverge(t *testing.T) {
	e := newRecoveryEnv(t)
	_, fp := e.installKey("pw-b")
	names := []string{"a", "b", "c", "d", "e"}
	for _, n := range names {
		e.requestKey(n, e.name, e.uid(), fp)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 4 {
		rec := &SigningRecoveryReconciler{Client: e.c, Reader: e.c, Runtime: e.rr.Runtime, Now: e.rec.Now}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 6 {
				for _, n := range names {
					if _, err := reconcileErr(rec, n); err != nil && !apierrors.IsConflict(err) {
						t.Errorf("%s: %v", n, err)
					}
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	for range 2 {
		for _, n := range names {
			e.reconcile(n)
		}
	}
	// Exactly one request recovered the run; every other ended
	// AlreadyRecovered from the recovered run, all referencing the one commit.
	sr := e.run_().Status.SigningRecovery
	if sr == nil || sr.Recovered == nil || sr.Active != nil {
		t.Fatalf("the run records no single recovery: %s", js(sr))
	}
	holder := sr.Recovered.Name
	for _, n := range names {
		if n == holder {
			e.wantRecovered(n, v1alpha1.RecoveryRecovered, holder)
		} else {
			e.wantSucceeded(n, v1alpha1.RecoveryAlreadyRecovered)
		}
	}
	e.wantCommitted(fp)
	t.Logf("holder %s; signature stores %d, publishes %d, one commit", holder, e.store().Calls(fake.OpStoreSignature), e.store().Calls(fake.OpPublish))
}

// A holder deleted after storing its signature but before its commit, and a
// leader change: the waiting request takes the claim and the successor
// commits the stored signature without reading the key or signing again.
func TestSigningRecoveryHolderDeletedAfterSigning(t *testing.T) {
	e := newRecoveryEnv(t)
	_, fp := e.installKey("pw-b")
	e.requestKey("holder", e.name, e.uid(), fp)
	e.requestKey("waiter", e.name, e.uid(), fp)
	e.store().Fail(fake.OpPublish, publication.ErrUnavailable)
	e.reconcile("holder")
	e.reconcile("waiter")
	e.reconcile("holder")
	e.wantRunning("holder", v1alpha1.RecoveryCommitting, "retrying")
	e.wantWaiting("waiter", "holder")
	if err := e.c.Delete(context.Background(), e.esr("holder")); err != nil {
		t.Fatal(err)
	}
	reads := e.recordSecretReads()
	e.successor()
	e.reconcile("waiter")
	e.wantHolder("waiter")
	e.reconcile("waiter")
	e.wantRecovered("waiter", v1alpha1.RecoveryRecovered, "waiter")
	e.wantCommitted(fp)
	if got := reads.all(); len(got) != 0 || e.store().Calls(fake.OpStoreSignature) != 1 {
		t.Fatalf("the successor read Secrets %v or signed again (%d stores)", got, e.store().Calls(fake.OpStoreSignature))
	}
}

// The commit's storage clock: a commit landing at or after the recorded
// expiry is Expired at once and never served; a storage clock so far behind
// the controller's that the bounded record would be invalid fails closed as
// Conflict (the existing ErrUnsupportedRecord), never committing anything
// else.
func TestSigningRecoveryCommitClock(t *testing.T) {
	e := newRecoveryEnv(t)
	_, fp := e.installKey("pw-b")
	e.store().ServerSkew = -24 * time.Hour
	e.requestKey("behind", e.name, e.uid(), fp)
	e.reconcile("behind")
	e.reconcile("behind")
	e.wantEnded("behind", v1alpha1.RecoveryConflict, "never overwritten")
	if e.store().Commits() != 0 {
		t.Fatal("an invalid bounded commit was made")
	}

	e.store().ServerSkew = e.run_().Status.Publication.ExpiresAt.Sub(e.now)
	e.requestKey("late", e.name, e.uid(), fp)
	e.reconcile("late")
	e.reconcile("late")
	e.wantEnded("late", v1alpha1.RecoveryExpired, "never served")
	st, err := e.store().Inspect(context.Background(), e.ref())
	if err != nil || st.Commit == nil || st.Phase != publication.PhaseExpired || st.Signature == nil || st.Signature.KeyFingerprint != fp {
		t.Fatalf("want the late commit expired at once: %+v %v", st, err)
	}
	if !retainedSigningFailure(e.run_()) {
		t.Fatal("an expired recovery changed the retained failure")
	}
}

// fencingStore runs fence once, as the attempt's commit starts.
type fencingStore struct {
	publication.Publisher
	fence func()
}

func (s *fencingStore) Publish(ctx context.Context, req publication.PublishRequest) (publication.Receipt, error) {
	if f := s.fence; f != nil {
		s.fence = nil
		f()
	}
	return s.Publisher.Publish(ctx, req)
}

// The attempt is fenced work of the pinned destination, registered as
// "run <name> signature recovery": an orphan handoff fence as the commit
// starts cancels it, nothing is committed, and no attempt begins afterwards.
func TestSigningRecoveryAttemptIsFenced(t *testing.T) {
	e := newRecoveryEnv(t)
	_, fp := e.installKey("pw-b")
	e.requestKey("holder", e.name, e.uid(), fp)
	e.store().Fail(fake.OpPublish, publication.ErrUnavailable)
	e.reconcile("holder")
	e.reconcile("holder")
	e.wantRunning("holder", v1alpha1.RecoveryCommitting, "retrying")

	dp, uid := e.rr.Runtime.Destinations, e.run_().Status.Destination.UID
	var inflight []string
	dp.New = func(_ context.Context, d s3store.Destination, _ client.Reader, _ string) (publication.Publisher, error) {
		return &fencingStore{Publisher: e.stores[d.ID], fence: func() { inflight = dp.Fence(uid, 0) }}, nil
	}
	e.setSigning(requiredSigning(recordedSecret)) // a new generation: the publisher is rebuilt
	stores := e.store().Calls(fake.OpStoreSignature)
	if _, err := reconcileErr(e.rec, "holder"); err != nil {
		t.Fatal(err)
	}
	if want := "run " + e.name + " signature recovery"; !slices.Contains(inflight, want) {
		t.Fatalf("the attempt was not fenced work %q: %v", want, inflight)
	}
	if e.store().Commits() != 0 || e.store().Calls(fake.OpStoreSignature) != stores {
		t.Fatal("a fenced attempt committed or signed again")
	}
	e.reconcile("holder")
	e.wantEnded("holder", v1alpha1.RecoveryOrphaned, "fenced")
	if e.store().Commits() != 0 {
		t.Fatal("an attempt began after the fence")
	}
}
