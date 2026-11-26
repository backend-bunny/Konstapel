package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/download"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
)

// add-evidence-signing-recovery 2.5 (the bounded attempt) and 2.6 (the
// recorded success and its crash-safe repair).

// evidenceOf is a run status without what a successful recovery records:
// the publication, the phase, the Published condition, the recovery state,
// and the intent's key pin. Everything else is the run's assessment
// evidence and must be untouched by recovery.
func evidenceOf(st *v1alpha1.AssessmentRunStatus) string {
	c := st.DeepCopy()
	c.Publication, c.Phase, c.SigningRecovery = nil, "", nil
	if c.SigningIntent != nil {
		c.SigningIntent.Key = nil
	}
	meta.RemoveStatusCondition(&c.Conditions, v1alpha1.ConditionPublished)
	return js(c)
}

// wantRecovered checks that request name ended Succeeded with reason and
// that the run records the recovery by holder as task 2.6 writes it: the
// committed publication exactly as storage holds it, Completed, Published
// True naming the holder, signingRecovery.recovered (no claim), and every
// evidence field unchanged from the retained failure.
func (e *recoveryEnv) wantRecovered(name string, reason v1alpha1.SigningRecoveryReason, holder string) {
	e.t.Helper()
	e.wantSucceeded(name, reason)
	run, h := e.run_(), e.esr(holder)
	st := run.Status
	sr := st.SigningRecovery
	if sr == nil || sr.Active != nil || sr.Recovered == nil || sr.Recovered.Name != holder || sr.Recovered.UID != string(h.UID) ||
		sr.Recovered.RequestedBy != *h.Spec.RequestedBy || sr.Recovered.At.IsZero() {
		e.t.Fatalf("want the run recovered by %s, without a claim: %s", holder, js(sr))
	}
	c := meta.FindStatusCondition(st.Conditions, v1alpha1.ConditionPublished)
	if st.Phase != v1alpha1.RunCompleted || c == nil || c.Status != metav1.ConditionTrue || c.Reason != "Committed" || !strings.Contains(c.Message, holder) || retainedSigningFailure(run) {
		e.t.Fatalf("want the run Completed and Published by %s: %s %s", holder, st.Phase, js(c))
	}
	got, err := e.store().Inspect(context.Background(), e.ref())
	if err != nil || got.Phase != publication.PhaseCommitted {
		e.t.Fatalf("storage holds no commit: %+v %v", got, err)
	}
	if want := publication.ToAPI(got); js(st.Publication) != js(&want) || st.Publication.Signature == nil || st.Publication.Commit == nil {
		e.t.Fatalf("the run's publication is not the stored commit:\n%s\n%s", js(st.Publication), js(&want))
	}
	if evidenceOf(&st) != evidenceOf(e.failed) {
		e.t.Fatalf("recovery changed the run's evidence:\n%s\n%s", evidenceOf(e.failed), evidenceOf(&st))
	}
	if strings.Contains(js(e.esr(name).Status), recordedSecret) {
		e.t.Fatalf("%s: the request status names the key Secret", name)
	}
}

// statusFaults fails the status updates its predicate selects, before they
// reach the API server, as a controller that stops at that point would;
// when counted is set it records the run updates that record a recovery.
type statusFaults struct {
	mu   sync.Mutex
	fail func(client.Object) bool
	// recorded counts run status updates that write any part of a success
	// (a commit, Completed, or signingRecovery.recovered); whole counts
	// those that carried all of it in the same object.
	recorded, whole int
}

func (f *statusFaults) set(fail func(client.Object) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = fail
}

func (f *statusFaults) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.recorded, f.whole
}

// faulty routes the recovery reconciler through a client with f's faults.
func (e *recoveryEnv) faulty(f *statusFaults) {
	c := interceptor.NewClient(e.c.(client.WithWatch), interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, cl client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			f.mu.Lock()
			fail := f.fail != nil && f.fail(obj)
			f.mu.Unlock()
			if fail {
				return apierrors.NewServiceUnavailable("test fault: the controller stopped before this write")
			}
			if err := cl.SubResource(sub).Update(ctx, obj, opts...); err != nil {
				return err
			}
			if run, ok := obj.(*v1alpha1.AssessmentRun); ok {
				sr, pub := run.Status.SigningRecovery, run.Status.Publication
				recovered, committed := sr != nil && sr.Recovered != nil, pub != nil && pub.Commit != nil
				if recovered || committed || run.Status.Phase == v1alpha1.RunCompleted {
					f.mu.Lock()
					f.recorded++
					if recovered && committed && run.Status.Phase == v1alpha1.RunCompleted && sr.Active == nil && pub.Signature != nil &&
						meta.IsStatusConditionTrue(run.Status.Conditions, v1alpha1.ConditionPublished) {
						f.whole++
					}
					f.mu.Unlock()
				}
			}
			return nil
		}})
	e.rec.Client, e.rec.Reader = c, c
}

func recordsRecovery(o client.Object) bool {
	run, ok := o.(*v1alpha1.AssessmentRun)
	return ok && run.Status.SigningRecovery != nil && run.Status.SigningRecovery.Recovered != nil
}

func isAssessmentRequest(o client.Object) bool {
	_, ok := o.(*v1alpha1.AssessmentRequest)
	return ok
}

func succeeds(o client.Object) bool {
	esr, ok := o.(*v1alpha1.EvidenceSigningRequest)
	return ok && esr.Status.Phase == v1alpha1.SigningRequestSucceeded
}

// namespaceRun makes the fixture a namespace run whose AssessmentRequest
// shows the signing failure as the run path projected it.
func (e *recoveryEnv) namespaceRun() *v1alpha1.AssessmentRequest {
	e.t.Helper()
	ctx := context.Background()
	req := e.runEnv.request("prod", "nightly")
	run := e.run_()
	run.Spec.Scope, run.Spec.Request = v1alpha1.RunScopeNamespace, &v1alpha1.RequestReference{Namespace: "prod", Name: "nightly", UID: string(req.UID)}
	if err := e.c.Update(ctx, run); err != nil {
		e.t.Fatal(err)
	}
	if err := finishRequestStatus(ctx, e.c, e.run_(), v1alpha1.ReasonSigningFailed); err != nil {
		e.t.Fatal(err)
	}
	if st := e.requestStatus("prod", "nightly"); st.Phase != v1alpha1.RequestFailed || js(e.run_().Status) != js(e.failed) {
		e.t.Fatalf("fixture: want the namespace request Failed and the run unchanged: %s", js(st))
	}
	return req
}

// wantProjected checks the namespace request shows the recovered run
// through the existing sanitized projection only.
func (e *recoveryEnv) wantProjected() *v1alpha1.AssessmentRequest {
	e.t.Helper()
	cur := &v1alpha1.AssessmentRequest{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Namespace: "prod", Name: "nightly"}, cur); err != nil {
		e.t.Fatal(err)
	}
	st, run := cur.Status, e.run_()
	c := meta.FindStatusCondition(st.Conditions, v1alpha1.ConditionPublished)
	if st.Phase != v1alpha1.RequestCompleted || st.ArtifactRef != run.Status.Publication.PublicationID || st.Run == nil || st.Run.UID != string(run.UID) ||
		js(st.Summary) != js(run.Status.Summary) || c == nil || c.Status != metav1.ConditionTrue || c.Message != "the evidence package was published" {
		e.t.Fatalf("want the namespace request Completed from the recovered run: %s", js(st))
	}
	for _, private := range []string{"platform-admin", "key restored", recordedSecret, "EvidenceSigningRequest", "recovery"} {
		if strings.Contains(js(st), private) {
			e.t.Fatalf("the namespace request status names %q: %s", private, js(st))
		}
	}
	return cur
}

// allowAll authenticates any token and authorizes everything, so the
// download routes exercise only their publication checks here.
type allowAll struct{}

func (allowAll) Authenticate(context.Context, string) (authnv1.UserInfo, error) {
	return authnv1.UserInfo{Username: "platform-operator"}, nil
}

func (allowAll) Authorize(context.Context, authnv1.UserInfo, authzv1.ResourceAttributes) (bool, error) {
	return true, nil
}

// download fetches artifact ("download" or "signature") of the run through
// the unchanged platform route of the download server.
func (e *recoveryEnv) download(artifact string) (int, []byte) {
	e.t.Helper()
	srv := &download.Server{Reader: e.c, Reviews: allowAll{}, TempDir: e.t.TempDir(), Now: func() time.Time { return e.now },
		PublisherFor: func(context.Context, *v1alpha1.AssessmentRun) (publication.Publisher, error) { return e.store(), nil }}
	r := httptest.NewRequest(http.MethodGet, "/v1/assessmentruns/"+e.uid()+"/"+artifact, nil)
	r.Header.Set("Authorization", "Bearer opaque-test-credential")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w.Code, w.Body.Bytes()
}

// wantDownloads checks both routes serve the pair: the archive is the
// intent's, and the signature verifies for it under the pinned key.
func (e *recoveryEnv) wantDownloads() {
	e.t.Helper()
	code, archive := e.download("download")
	sigCode, bundle := e.download("signature")
	if code != http.StatusOK || sigCode != http.StatusOK {
		e.t.Fatalf("downloads of the recovered run: archive %d signature %d %s", code, sigCode, bundle)
	}
	in := e.run_().Status.SigningIntent
	sum := sha256.Sum256(archive)
	if hex.EncodeToString(sum[:]) != in.ArchiveSHA256 {
		e.t.Fatal("the downloaded archive is not the intent's")
	}
	pk, err := evidencesign.ParsePublicKey([]byte(in.Key.PublicKey))
	if err != nil {
		e.t.Fatal(err)
	}
	d, _ := evidencesign.ParseArchiveDigest(in.ArchiveSHA256)
	if _, err := evidencesign.Verify(bundle, d, pk); err != nil {
		e.t.Fatalf("the downloaded signature does not verify under the pinned key: %v", err)
	}
}

// 2.5: a holder that cannot recover by its claim's deadline ends
// SigningFailed, decided before any storage access; it polls no later than
// the deadline; the run keeps its retained failure record, expiry, and
// destination accounting byte for byte; a waiting request is untouched until
// then, and a new attempt can succeed.
func TestSigningRecoveryAttemptDeadline(t *testing.T) {
	e := newRecoveryEnv(t)
	before := e.reconcileDestination().Status
	if before.OutstandingPackages != 1 || before.LatestRetainedExpiry == nil {
		t.Fatalf("fixture: want the retained failure counted: %s", js(before))
	}
	key, fp := signingKeySecret(t, recordedSecret, "pw-later")
	e.request("holder", e.name, e.uid())
	e.requestKey("waiter", e.name, e.uid(), fp)
	e.reconcile("holder")
	claim := *e.wantHolder("holder")
	if claim.Deadline.Sub(claim.ClaimedAt.Time) != e.rec.publishTimeout() {
		t.Fatalf("the claim's deadline is not claimedAt + PublishTimeout: %s", js(claim))
	}
	e.reconcile("waiter")
	e.wantWaiting("waiter", "holder")

	// The key stays absent: the holder retries, polling no later than its
	// deadline.
	poll := e.rec.poll()
	for _, left := range []time.Duration{claim.Deadline.Sub(e.now), poll / 2, time.Second / 2} {
		e.now = claim.Deadline.Add(-left)
		res, err := reconcileErr(e.rec, "holder")
		want := min(poll, max(left, time.Second))
		if err != nil || res.RequeueAfter != want {
			t.Fatalf("%s before the deadline: requeue %s (want %s) %v", left, res.RequeueAfter, want, err)
		}
		e.wantRunning("holder", v1alpha1.RecoverySigning, "retrying")
	}
	e.reconcile("waiter")
	e.wantWaiting("waiter", "holder")

	// At the deadline: SigningFailed without touching storage, even while it
	// is unavailable; the claim is released and the run is exactly the
	// retained failure.
	e.now = claim.Deadline.Time
	e.store().Fail(fake.OpInspect, publication.ErrUnavailable)
	inspects, writes := e.store().Calls(fake.OpInspect), storageWrites(e.store())
	e.reconcile("holder")
	e.wantEnded("holder", v1alpha1.RecoverySigningFailed, "attempt deadline")
	if st := e.esr("holder").Status; !strings.Contains(st.Message, "last: retrying") || !strings.Contains(st.Message, "a new request can try again") {
		t.Fatalf("the deadline outcome does not explain itself: %s", st.Message)
	}
	if e.store().Calls(fake.OpInspect) != inspects || storageWrites(e.store()) != writes {
		t.Fatal("the deadline was decided with storage access")
	}
	if got := js(e.run_().Status); got != js(e.failed) {
		t.Fatalf("the run is not exactly its retained failure:\n%s\n%s", js(e.failed), got)
	}
	after := e.reconcileDestination().Status
	if after.OutstandingPackages != before.OutstandingPackages || !after.LatestRetainedExpiry.Equal(before.LatestRetainedExpiry) {
		t.Fatalf("destination accounting changed: %s -> %s", js(before), js(after))
	}
	e.expectTerminal("holder", v1alpha1.RecoverySigningFailed, "attempt deadline", nil)

	// The waiting request claims with its own deadline and recovers once the
	// key is restored; it meets the outage the holder's deadline never read.
	e.putSecret(key)
	if _, err := reconcileErr(e.rec, "waiter"); err == nil {
		t.Fatal("the storage outage was consumed before the waiter")
	}
	e.reconcile("waiter")
	next := *e.wantHolder("waiter")
	if !next.ClaimedAt.Time.Equal(e.now.UTC().Truncate(time.Second)) || next.Deadline.Sub(next.ClaimedAt.Time) != e.rec.publishTimeout() {
		t.Fatalf("the new holder's claim: %s", js(next))
	}
	e.now = e.now.Add(time.Minute)
	e.reconcile("waiter")
	e.wantRecovered("waiter", v1alpha1.RecoveryRecovered, "waiter")
	e.wantCommitted(fp)
	if st := e.esr("holder").Status; st.Phase != v1alpha1.SigningRequestFailed || st.Reason != v1alpha1.RecoverySigningFailed {
		t.Fatalf("the ended holder was rewritten: %s", js(st))
	}
	recovered := e.reconcileDestination().Status
	if recovered.OutstandingPackages != 1 || !recovered.LatestRetainedExpiry.Equal(before.LatestRetainedExpiry) {
		t.Fatalf("the recovered package is not counted once with its recorded expiry: %s", js(recovered))
	}
}

// 2.5: a commit made by an attempt whose run update never landed is not a
// recorded recovery. Within the deadline the holder's successor adopts and
// records it; past the deadline the holder ends SigningFailed with the run
// still its retained failure, and a new request adopts the same commit
// unchanged (no second Publish, its original publication time).
func TestSigningRecoveryCommitWithoutRunRecord(t *testing.T) {
	for _, late := range []bool{false, true} {
		e := newRecoveryEnv(t)
		_, fp := e.installKey("pw-b")
		e.requestKey("holder", e.name, e.uid(), fp)
		f := &statusFaults{}
		e.faulty(f)
		f.set(recordsRecovery)
		e.reconcile("holder")
		if _, err := reconcileErr(e.rec, "holder"); err == nil {
			t.Fatal("the failed run update was not retried")
		}
		first := e.wantCommitted(fp)
		claim := *e.wantHolder("holder")
		e.wantRunning("holder", v1alpha1.RecoveryCommitting, "committing")
		if !retainedSigningFailure(e.run_()) {
			t.Fatal("the run records a recovery its update never wrote")
		}
		pinned := js(e.run_().Status.SigningIntent)
		publishes := e.store().Calls(fake.OpPublish)
		e.successor()
		e.rec.Client, e.rec.Reader = e.c, e.c
		if !late {
			e.now = claim.Deadline.Add(-time.Second)
			e.reconcile("holder")
			e.wantRecovered("holder", v1alpha1.RecoveryRecovered, "holder")
		} else {
			e.now = claim.Deadline.Add(time.Hour)
			e.reconcile("holder")
			e.wantEnded("holder", v1alpha1.RecoverySigningFailed, "attempt deadline")
			want := e.failed.DeepCopy()
			want.SigningIntent = e.run_().Status.SigningIntent
			if js(e.run_().Status) != js(want) || js(e.run_().Status.SigningIntent) != pinned {
				t.Fatalf("the late holder changed the run beyond its pin: %s", js(e.run_().Status))
			}
			e.request("retry", e.name, e.uid())
			e.reconcile("retry")
			e.reconcile("retry")
			e.wantRecovered("retry", v1alpha1.RecoveryRecovered, "retry")
		}
		if got := e.wantCommitted(fp); e.store().Calls(fake.OpPublish) != publishes || !got.PublishedAt.Equal(*first.PublishedAt) ||
			!e.run_().Status.Publication.PublishedAt.Time.Equal(*first.PublishedAt) {
			t.Fatalf("late=%v: the commit was not adopted unchanged: publishes %d -> %d, %s", late, publishes, e.store().Calls(fake.OpPublish), js(got))
		}
	}
}

// 2.6: success is one run status update carrying the committed publication,
// Completed, Published True, and signingRecovery.recovered; then the
// sanitized namespace projection; then the request. The recovered run keeps
// its evidence, window, and original times; publishedAt is the true (late)
// commit time and the expiry the one recorded at the failure. The unchanged
// download routes serve the pair-verified archive and signature only after
// recovery, the run path keeps the recovered run as it is, and the
// destination counts the package once.
func TestSigningRecoveryRecordsSuccess(t *testing.T) {
	e := newRecoveryEnv(t)
	e.namespaceRun()
	if code, _ := e.download("download"); code == http.StatusOK {
		t.Fatal("a retained SigningFailed run was downloadable")
	}
	if code, _ := e.download("signature"); code == http.StatusOK {
		t.Fatal("the signature of a retained SigningFailed run was downloadable")
	}
	_, fp := e.installKey("pw-b")
	f := &statusFaults{}
	e.faulty(f)
	e.requestKey("holder", e.name, e.uid(), fp)
	e.reconcile("holder")
	e.now = e.now.Add(2 * time.Minute)
	e.reconcile("holder")
	e.wantRecovered("holder", v1alpha1.RecoveryRecovered, "holder")
	if recorded, whole := f.counts(); recorded != 1 || whole != 1 {
		t.Fatalf("want one run update recording the whole success, got %d (%d whole)", recorded, whole)
	}
	e.wantCommitted(fp)
	run := e.run_()
	pub, w := run.Status.Publication, run.Status.Window
	if !pub.PublishedAt.Equal(&metav1.Time{Time: e.now.UTC().Truncate(time.Second)}) || !pub.PublishedAt.After(e.failed.Publication.Failure.At.Time) ||
		!pub.PublishedAt.After(w.Closed.Time) || !pub.ExpiresAt.Equal(e.failed.Publication.ExpiresAt) || js(w) != js(e.failed.Window) {
		t.Fatalf("publishedAt must be the late commit time and the expiry and window the recorded ones: %s window %s", js(pub), js(w))
	}
	if js(run.Status.Summary) != js(e.failed.Summary) || run.Status.Summary.Export != e.failed.Summary.Export {
		t.Fatalf("recovery changed the summary: %s", js(run.Status.Summary))
	}
	if !run.Status.SigningRecovery.Recovered.At.Equal(pub.PublishedAt) {
		t.Fatalf("the recovery time %s is not the recording time %s", run.Status.SigningRecovery.Recovered.At, pub.PublishedAt)
	}
	e.wantProjected()
	e.wantDownloads()

	// The run path keeps the recovered run: retention, attempt cleanup, and
	// integrity checks leave its publication, recovery, and projection as
	// they are, and the destination counts one package with its expiry.
	nsBefore, recovered := js(e.requestStatus("prod", "nightly")), run.Status.DeepCopy()
	e.step(e.name)
	got := e.run_().Status
	if got.Phase != v1alpha1.RunCompleted || js(got.SigningRecovery) != js(recovered.SigningRecovery) || got.Publication.Phase != recovered.Publication.Phase ||
		js(got.Publication.Commit) != js(recovered.Publication.Commit) || js(got.Publication.Signature) != js(recovered.Publication.Signature) || js(got.Summary) != js(recovered.Summary) {
		t.Fatalf("the run path changed the recovered run:\n%s\n%s", js(recovered), js(got))
	}
	if js(e.requestStatus("prod", "nightly")) != nsBefore {
		t.Fatal("the run path rewrote the namespace projection")
	}
	if ed := e.reconcileDestination().Status; ed.OutstandingPackages != 1 || !ed.LatestRetainedExpiry.Equal(e.failed.Publication.ExpiresAt) {
		t.Fatalf("destination accounting after recovery: %s", js(ed))
	}
	e.wantDownloads()
}

// 2.6: the separate status writes are repaired from the recovered run after a
// crash at every point between them, by a successor and even long past the
// attempt deadline, in any order with other requests: never signing,
// committing, or rewriting the run, never writing an unchanged projection,
// and never recreating or overwriting a missing or recreated namespace
// request.
func TestSigningRecoveryStatusCrashPoints(t *testing.T) {
	type crash struct {
		name string
		at   func(client.Object) bool
		// between runs after the crash and before the successor.
		between func(e *recoveryEnv)
		// projected is whether the namespace request must end Completed,
		// and already whether it did before the successor.
		projected, already bool
	}
	for _, c := range []crash{
		{name: "after the run update", at: isAssessmentRequest, projected: true},
		{name: "after the namespace request update", at: succeeds, projected: true, already: true},
		{name: "after the run update, a late request first", at: isAssessmentRequest, projected: true, already: true, between: func(e *recoveryEnv) {
			e.request("late", e.name, e.uid())
			e.reconcile("late")
			e.wantSucceeded("late", v1alpha1.RecoveryAlreadyRecovered)
			e.wantProjected()
		}},
		{name: "after the run update, the namespace request deleted", at: isAssessmentRequest, between: func(e *recoveryEnv) {
			cur := &v1alpha1.AssessmentRequest{}
			if err := e.c.Get(context.Background(), client.ObjectKey{Namespace: "prod", Name: "nightly"}, cur); err != nil {
				e.t.Fatal(err)
			}
			if err := e.c.Delete(context.Background(), cur); err != nil {
				e.t.Fatal(err)
			}
		}},
		{name: "after the run update, the namespace request recreated", at: isAssessmentRequest, between: func(e *recoveryEnv) {
			cur := &v1alpha1.AssessmentRequest{}
			if err := e.c.Get(context.Background(), client.ObjectKey{Namespace: "prod", Name: "nightly"}, cur); err != nil {
				e.t.Fatal(err)
			}
			if err := e.c.Delete(context.Background(), cur); err != nil {
				e.t.Fatal(err)
			}
			recreated := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "nightly", UID: "uid-nightly-recreated"},
				Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: "audit-all"}}}
			if err := e.c.Create(context.Background(), recreated); err != nil {
				e.t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newRecoveryEnv(t)
			e.namespaceRun()
			_, fp := e.installKey("pw-b")
			e.requestKey("holder", e.name, e.uid(), fp)
			f := &statusFaults{}
			e.faulty(f)
			e.reconcile("holder")
			claim := *e.wantHolder("holder")
			f.set(c.at)
			if _, err := reconcileErr(e.rec, "holder"); err == nil {
				t.Fatal("the failed status write was not retried")
			}
			if sr := e.run_().Status.SigningRecovery; sr == nil || sr.Recovered == nil {
				t.Fatalf("the crash came before the run update: %s", js(sr))
			}
			if st := e.esr("holder").Status; st.Phase.Terminal() {
				t.Fatalf("the request ended before its namespace projection and its own update: %s", js(st))
			}
			f.set(nil)
			if c.between != nil {
				c.between(e)
			}
			// The successor runs long past the attempt deadline; repeated
			// transient failures of the remaining writes are retried, never
			// turned into SigningFailed.
			e.successor()
			e.faulty(f)
			f.set(func(o client.Object) bool { return isAssessmentRequest(o) || succeeds(o) })
			e.now = claim.Deadline.Add(3 * time.Hour)
			for range 2 {
				if _, err := reconcileErr(e.rec, "holder"); err == nil {
					t.Fatal("the failed status write was not retried")
				}
				if st := e.esr("holder").Status; st.Phase.Terminal() {
					t.Fatalf("a transient failure past the deadline decided the request: %s", js(st))
				}
				e.now = e.now.Add(time.Hour)
			}
			f.set(nil)
			ns := &v1alpha1.AssessmentRequest{}
			nsErr := e.c.Get(context.Background(), client.ObjectKey{Namespace: "prod", Name: "nightly"}, ns)
			writes, run, publishes := storageWrites(e.store()), js(e.run_()), e.store().Calls(fake.OpPublish)
			e.reconcile("holder")
			e.wantRecovered("holder", v1alpha1.RecoveryRecovered, "holder")
			if storageWrites(e.store()) != writes || e.store().Calls(fake.OpPublish) != publishes || js(e.run_()) != run {
				t.Fatal("the repair wrote storage or rewrote the run")
			}
			after := &v1alpha1.AssessmentRequest{}
			afterErr := e.c.Get(context.Background(), client.ObjectKey{Namespace: "prod", Name: "nightly"}, after)
			switch {
			case c.projected:
				e.wantProjected()
				if c.already && after.ResourceVersion != ns.ResourceVersion {
					t.Fatal("an unchanged namespace projection was written again")
				}
			case apierrors.IsNotFound(nsErr) || apierrors.IsNotFound(afterErr):
				if !apierrors.IsNotFound(afterErr) {
					t.Fatalf("a deleted namespace request was recreated: %s", js(after))
				}
			default:
				if after.UID != "uid-nightly-recreated" || js(after.Status) != js(ns.Status) || after.Status.Phase != "" {
					t.Fatalf("a recreated namespace request was overwritten: %s", js(after.Status))
				}
			}
			if e.store().Commits() != 1 || e.store().Calls(fake.OpStoreSignature) != 1 {
				t.Fatalf("signed or committed again: %d commits, %d signature stores", e.store().Commits(), e.store().Calls(fake.OpStoreSignature))
			}
		})
	}
}

// 2.6: the recovery record carries the admission-recorded requester, so a
// request without one is never attempted (no Secret read, no storage
// write) and decides nothing; the commit gate's receipt is recorded only as
// the intent's signed commit of its archive.
func TestSigningRecoveryRecordGuards(t *testing.T) {
	e := newRecoveryEnv(t)
	_, fp := e.installKey("pw-b")
	esr := &v1alpha1.EvidenceSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: "unattributed"}, Spec: v1alpha1.EvidenceSigningRequestSpec{
		Run: v1alpha1.ExactRunReference{Name: e.name, UID: e.uid()}, Reason: "no admission", ExpectedKeyFingerprint: fp}}
	if err := e.c.Create(context.Background(), esr); err != nil {
		t.Fatal(err)
	}
	reads := e.recordSecretReads()
	writes := storageWrites(e.store())
	if _, err := reconcileErr(e.rec, "unattributed"); err != nil {
		t.Fatal(err)
	}
	if _, err := reconcileErr(e.rec, "unattributed"); err == nil || !strings.Contains(err.Error(), "requester") {
		t.Fatalf("an unattributed request was attempted: %v", err)
	}
	if got := reads.all(); len(got) != 0 || storageWrites(e.store()) != writes || e.esr("unattributed").Status.Phase.Terminal() {
		t.Fatalf("an unattributed request read Secrets %v, wrote storage, or was decided", got)
	}

	// The record is refused for anything but the intent's signed commit.
	e = newRecoveryEnv(t)
	_, fp = e.installKey("pw-b")
	e.requestKey("holder", e.name, e.uid(), fp)
	e.store().Fail(fake.OpPublish, publication.ErrUnavailable)
	e.reconcile("holder")
	e.reconcile("holder")
	holder, run := e.esr("holder"), e.run_()
	good := publication.Status{Phase: publication.PhaseCommitted, PublicationID: "pub-x", PackageSHA256: run.Status.SigningIntent.ArchiveSHA256,
		Commit: &publication.Commit{ManifestKey: "m", ArchiveKey: "a"}, PublishedAt: &e.now, ExpiresAt: &e.now,
		Signature: &publication.Signature{KeyFingerprint: fp, SHA256: strings.Repeat("a", 64)}}
	for name, bad := range map[string]func(*publication.Status){
		"another key": func(s *publication.Status) {
			s.Signature = &publication.Signature{KeyFingerprint: absentKeyFingerprint}
		},
		"unsigned":        func(s *publication.Status) { s.Signature = nil },
		"another archive": func(s *publication.Status) { s.PackageSHA256 = strings.Repeat("b", 64) },
		"not committed":   func(s *publication.Status) { s.Phase, s.Commit = publication.PhaseFailed, nil },
		"expired":         func(s *publication.Status) { s.Phase = publication.PhaseExpired },
	} {
		st := good
		bad(&st)
		before := js(e.run_())
		if _, err := e.rec.committed(context.Background(), holder, e.run_(), st); err == nil || !strings.Contains(err.Error(), "not the signing intent's signed commit") {
			t.Fatalf("%s: recorded: %v", name, err)
		}
		if js(e.run_()) != before {
			t.Fatalf("%s: the run changed", name)
		}
	}
}

// 2.6: coverage selects runs by window closure, so a recovered run published
// late never displaces a newer published run, and is the binding's current
// run only while nothing newer is.
func TestSigningRecoveryCoverageOrderedByClosure(t *testing.T) {
	e := newRecoveryEnv(t)
	ctx := context.Background()
	b := &v1alpha1.ComplianceBinding{}
	if err := e.c.Get(ctx, client.ObjectKey{Name: "audit-prod"}, b); err != nil {
		t.Fatal(err)
	}
	if e.run_().Spec.Scope != v1alpha1.RunScopeBinding {
		t.Fatalf("fixture: want a binding run, got %s", e.run_().Spec.Scope)
	}
	current := func() string {
		t.Helper()
		got, err := e.ar.currentCoverage(ctx, b, e.now, "in")
		if err != nil {
			t.Fatal(err)
		}
		if got.Run == nil {
			return ""
		}
		return got.Run.Name
	}
	if got := current(); got != "" {
		t.Fatalf("a retained SigningFailed run is current: %s", got)
	}
	// A newer run, closed after the failed run and published before its
	// recovery.
	newer := e.scheduledRun("audit-prod-newer", "audit-prod", string(b.UID), v1alpha1.TriggerScheduled, e.failed.Window.Closed.Add(time.Hour), "")
	closed := metav1.NewTime(e.failed.Window.Closed.Add(time.Hour))
	published := metav1.NewTime(closed.Add(time.Minute))
	newer.Status = v1alpha1.AssessmentRunStatus{Phase: v1alpha1.RunCompleted, Window: &v1alpha1.CaptureWindow{Started: e.failed.Window.Started, Closed: &closed},
		Publication: &v1alpha1.PublicationStatus{Phase: v1alpha1.PublicationPhase(publication.PhaseCommitted), PublicationID: "pub-newer", PublishedAt: &published}}
	if err := e.c.Status().Update(ctx, newer); err != nil {
		t.Fatal(err)
	}
	_, fp := e.installKey("pw-b")
	e.requestKey("holder", e.name, e.uid(), fp)
	e.now = published.Add(time.Hour)
	e.reconcile("holder")
	e.reconcile("holder")
	e.wantRecovered("holder", v1alpha1.RecoveryRecovered, "holder")
	if pub := e.run_().Status.Publication; !pub.PublishedAt.After(published.Time) {
		t.Fatalf("fixture: the recovery must be published after the newer run: %s", js(pub))
	}
	if got := current(); got != newer.Name {
		t.Fatalf("the late recovered run displaced the newer run: current %s", got)
	}
	if err := e.c.Delete(ctx, newer); err != nil {
		t.Fatal(err)
	}
	if got := current(); got != e.name {
		t.Fatalf("the recovered run is not current without a newer run: %s", got)
	}
}
