package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
)

// add-evidence-signing-recovery 2.3: the per-run claim.

func (e *recoveryEnv) esr(name string) *v1alpha1.EvidenceSigningRequest {
	e.t.Helper()
	esr := &v1alpha1.EvidenceSigningRequest{}
	if err := e.c.Get(context.Background(), ctrl.ObjectKey{Name: name}, esr); err != nil {
		e.t.Fatal(err)
	}
	return esr
}

// reconcileErr reconciles one request with rec and returns its result.
func reconcileErr(rec *SigningRecoveryReconciler, name string) (reconcile.Result, error) {
	return rec.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: name}})
}

// wantHolder checks that the run's claim names exactly the request and the
// request is Pending/Accepted as its holder, with the attempt bounded by
// PublishTimeout from the claim.
func (e *recoveryEnv) wantHolder(name string) *v1alpha1.SigningRecoveryClaim {
	e.t.Helper()
	esr, run := e.esr(name), e.run_()
	c := claimOf(run)
	if !holdsClaim(c, esr) || run.Status.SigningRecovery.Recovered != nil {
		e.t.Fatalf("the claim is not %s's: %s", name, js(run.Status.SigningRecovery))
	}
	if got := c.Deadline.Sub(c.ClaimedAt.Time); got != e.rec.publishTimeout() {
		e.t.Fatalf("claim deadline is %s after the claim, want PublishTimeout %s", got, e.rec.publishTimeout())
	}
	st := esr.Status
	if st.Phase != v1alpha1.SigningRequestPending || st.Reason != v1alpha1.RecoveryAccepted || !strings.Contains(st.Message, "holds the signing recovery") ||
		st.CompletedAt != nil || st.AcceptedAt == nil || meta.IsStatusConditionTrue(st.Conditions, v1alpha1.ConditionSigningRequestComplete) {
		e.t.Fatalf("holder %s: want Pending/Accepted: %s", name, js(st))
	}
	return c
}

// wantWaiting checks that a request waits for holder.
func (e *recoveryEnv) wantWaiting(name, holder string) {
	e.t.Helper()
	st := e.esr(name).Status
	if st.Phase != v1alpha1.SigningRequestPending || st.Reason != v1alpha1.RecoveryWaiting || !strings.Contains(st.Message, "EvidenceSigningRequest "+holder+" holds") ||
		st.CompletedAt != nil || st.AcceptedAt == nil || st.Run == nil || st.RequestedBy == nil {
		e.t.Fatalf("%s: want Pending/Waiting on %s: %s", name, holder, js(st))
	}
}

// Concurrent requests for one run: exactly one claims it, the others wait;
// repeated reconciles change nothing and no request writes storage.
func TestSigningRecoveryClaimOneHolder(t *testing.T) {
	e := newRecoveryEnv(t)
	pre, writes := js(e.run_().Status), storageWrites(e.store())
	for _, n := range []string{"first", "second", "third"} {
		e.request(n, e.name, e.uid())
	}
	e.reconcile("first")
	claim := e.wantHolder("first")
	for _, n := range []string{"second", "third"} {
		res, err := reconcileErr(e.rec, n)
		if err != nil || res.RequeueAfter != e.rec.poll() {
			t.Fatalf("%s: a waiting request must poll: %+v %v", n, res, err)
		}
		e.wantWaiting(n, "first")
	}
	run, reqs := js(e.run_()), js([]any{e.esr("first"), e.esr("second"), e.esr("third")})
	for range 2 {
		for _, n := range []string{"third", "first", "second"} {
			e.reconcile(n)
		}
	}
	if js(e.run_()) != run || js([]any{e.esr("first"), e.esr("second"), e.esr("third")}) != reqs {
		t.Fatal("repeated reconciles rewrote the run or a request")
	}
	if got := e.wantHolder("first"); *got != *claim {
		t.Fatalf("the claim changed: %s -> %s", js(claim), js(got))
	}
	if storageWrites(e.store()) != writes {
		t.Fatal("claiming wrote storage")
	}
	// The claim is the only change to the run's status.
	unclaimed := e.run_()
	unclaimed.Status.SigningRecovery = nil
	if js(unclaimed.Status) != pre {
		t.Fatalf("claiming changed more than signingRecovery.active:\n%s\n%s", pre, js(unclaimed.Status))
	}
}

// Many requests reconciled at the same time by separate reconcilers (as
// overlapping leaders would): the resourceVersion-conditional claim lets
// exactly one win; every loser re-reads and waits for it.
func TestSigningRecoveryClaimRace(t *testing.T) {
	e := newRecoveryEnv(t)
	const n = 8
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("racer-%d", i)
		e.request(names[i], e.name, e.uid())
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	conflicts := 0
	start := make(chan struct{})
	for _, name := range names {
		rec := &SigningRecoveryReconciler{Client: e.c, Reader: e.c, Runtime: e.rr.Runtime, Now: e.rec.Now}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 20 {
				_, err := reconcileErr(rec, name)
				if err == nil {
					return
				}
				if !apierrors.IsConflict(err) {
					t.Errorf("%s: %v", name, err)
					return
				}
				mu.Lock()
				conflicts++
				mu.Unlock()
			}
			t.Errorf("%s never settled", name)
		}()
	}
	close(start)
	wg.Wait()
	holder := claimOf(e.run_())
	if holder == nil {
		t.Fatal("no request claimed the run")
	}
	for _, name := range names {
		if name == holder.Name {
			e.wantHolder(name)
		} else {
			e.wantWaiting(name, holder.Name)
		}
	}
	t.Logf("%d racing requests, %d conflicting writes retried, holder %s", n, conflicts, holder.Name)
}

// A claim write that loses to a concurrent claim fails with a conflict and
// never overwrites the winner; the loser re-reads and waits, and the winner
// resumes its claim unchanged.
func TestSigningRecoveryClaimConflictingWrite(t *testing.T) {
	e := newRecoveryEnv(t)
	e.request("loser", e.name, e.uid())
	e.request("winner", e.name, e.uid())
	winner := e.esr("winner")
	injected := false
	c := interceptor.NewClient(e.c.(ctrl.WithWatch), interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, cl ctrl.Client, sub string, obj ctrl.Object, opts ...ctrl.SubResourceUpdateOption) error {
			if run, ok := obj.(*v1alpha1.AssessmentRun); ok && !injected && claimOf(run) != nil && claimOf(run).Name == "loser" {
				injected = true
				// The winner's claim lands between the loser's read and write.
				cur := &v1alpha1.AssessmentRun{}
				if err := cl.Get(ctx, ctrl.ObjectKeyFromObject(run), cur); err != nil {
					return err
				}
				at := metav1.NewTime(e.now.UTC().Truncate(time.Second))
				cur.Status.SigningRecovery = &v1alpha1.SigningRecoveryStatus{Active: &v1alpha1.SigningRecoveryClaim{Name: winner.Name, UID: string(winner.UID),
					ClaimedAt: at, Deadline: metav1.NewTime(at.Add(e.rec.publishTimeout()))}}
				if err := cl.Status().Update(ctx, cur); err != nil {
					return err
				}
			}
			return cl.SubResource(sub).Update(ctx, obj, opts...)
		}})
	rec := &SigningRecoveryReconciler{Client: c, Reader: c, Runtime: e.rr.Runtime, Now: e.rec.Now}
	if _, err := reconcileErr(rec, "loser"); !injected || !apierrors.IsConflict(err) {
		t.Fatalf("the losing claim write: injected %v, err %v; want a conflict", injected, err)
	}
	if st := e.esr("loser").Status; st.Phase != "" {
		t.Fatalf("the loser recorded an outcome for a claim it lost: %s", js(st))
	}
	if _, err := reconcileErr(rec, "loser"); err != nil {
		t.Fatal(err)
	}
	e.wantWaiting("loser", "winner")
	claim := *claimOf(e.run_())
	e.reconcile("winner")
	if got := e.wantHolder("winner"); *got != claim {
		t.Fatalf("the winner's resumed claim changed: %s -> %s", js(claim), js(got))
	}
}

// A claim whose request is gone, recreated, or terminal is stale: a waiting
// request clears it after a fresh read and claims the run. A recreated
// request with the holder's name never inherits its claim.
func TestSigningRecoveryStaleClaim(t *testing.T) {
	e := newRecoveryEnv(t)
	ctx := context.Background()
	for _, n := range []string{"deleted", "next", "after"} {
		e.request(n, e.name, e.uid())
	}
	e.reconcile("deleted")
	e.wantHolder("deleted")
	e.reconcile("next")
	e.wantWaiting("next", "deleted")

	// Deleted while holding the claim.
	if err := e.c.Delete(ctx, e.esr("deleted")); err != nil {
		t.Fatal(err)
	}
	e.reconcile("next")
	e.wantHolder("next")
	e.reconcile("after")
	e.wantWaiting("after", "next")

	// Recreated under the holder's name: a new UID never inherits.
	old := e.esr("next")
	if err := e.c.Delete(ctx, old); err != nil {
		t.Fatal(err)
	}
	again := old.DeepCopy()
	again.ResourceVersion, again.UID, again.Status = "", "uid-next-recreated", v1alpha1.EvidenceSigningRequestStatus{}
	if err := e.c.Create(ctx, again); err != nil {
		t.Fatal(err)
	}
	if e.esr("next").UID == old.UID {
		t.Fatal("fixture: the recreated request kept its UID")
	}
	e.reconcile("next")
	if c := e.wantHolder("next"); c.UID == string(old.UID) {
		t.Fatalf("the recreated request inherited the old claim: %s", js(c))
	}
	e.reconcile("after")
	e.wantWaiting("after", "next")

	// Terminal (a holder-specific outcome such as SigningFailed or
	// KeyMismatch) without its release.
	holder := e.esr("next")
	now := metav1.NewTime(e.now)
	holder.Status.Phase, holder.Status.Reason, holder.Status.Message, holder.Status.CompletedAt = v1alpha1.SigningRequestFailed, v1alpha1.RecoverySigningFailed, "attempt deadline", &now
	meta.SetStatusCondition(&holder.Status.Conditions, metav1.Condition{Type: v1alpha1.ConditionSigningRequestComplete, Status: metav1.ConditionTrue, Reason: "SigningFailed", LastTransitionTime: now})
	if err := e.c.Status().Update(ctx, holder); err != nil {
		t.Fatal(err)
	}
	e.reconcile("after")
	e.wantHolder("after")
	if st := e.esr("next").Status; st.Reason != v1alpha1.RecoverySigningFailed {
		t.Fatalf("clearing a stale claim rewrote its terminal request: %s", js(st))
	}
}

// A holder that ends terminally records its outcome and then releases the
// claim; a crash in between is repaired by the terminal request's next
// reconcile, which writes only the run and leaves its status bytes exactly
// as before the claim. A terminal request reads no storage.
func TestSigningRecoveryTerminalHolderReleases(t *testing.T) {
	e := newRecoveryEnv(t)
	pre := js(e.run_().Status)
	e.request("holder", e.name, e.uid())
	e.reconcile("holder")
	e.wantHolder("holder")

	e.now = e.run_().Status.Publication.ExpiresAt.Time
	crash := true
	c := interceptor.NewClient(e.c.(ctrl.WithWatch), interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, cl ctrl.Client, sub string, obj ctrl.Object, opts ...ctrl.SubResourceUpdateOption) error {
			if _, ok := obj.(*v1alpha1.AssessmentRun); ok && crash {
				return errors.New("controller stopped before releasing the claim")
			}
			return cl.SubResource(sub).Update(ctx, obj, opts...)
		}})
	rec := &SigningRecoveryReconciler{Client: c, Reader: c, Runtime: e.rr.Runtime, Now: e.rec.Now}
	writes := storageWrites(e.store())
	if _, err := reconcileErr(rec, "holder"); err == nil {
		t.Fatal("the failed release was not retried")
	}
	terminal := e.esr("holder")
	if terminal.Status.Phase != v1alpha1.SigningRequestFailed || terminal.Status.Reason != v1alpha1.RecoveryExpired || !holdsClaim(claimOf(e.run_()), terminal) {
		t.Fatalf("want a terminal Expired holder whose claim is still recorded: %s %s", js(terminal.Status), js(e.run_().Status.SigningRecovery))
	}
	crash = false
	inspects := e.store().Calls(fake.OpInspect)
	if _, err := reconcileErr(rec, "holder"); err != nil {
		t.Fatal(err)
	}
	if got := js(e.run_().Status); got != pre {
		t.Fatalf("the released run is not as before the claim:\n%s\n%s", pre, got)
	}
	if js(e.esr("holder")) != js(terminal) {
		t.Fatal("releasing the claim rewrote the terminal request")
	}
	if e.store().Calls(fake.OpInspect) != inspects || storageWrites(e.store()) != writes {
		t.Fatal("a terminal request read or wrote storage")
	}
}

// The claim is durable in the run's status: a successor (a new leader with
// an empty cache) resumes the holder's request with the same claim, and the
// waiting request keeps waiting.
func TestSigningRecoveryClaimSurvivesLeaderChange(t *testing.T) {
	e := newRecoveryEnv(t)
	e.request("holder", e.name, e.uid())
	e.request("waiter", e.name, e.uid())
	e.reconcile("holder")
	e.reconcile("waiter")
	claim, rv := *e.wantHolder("holder"), e.run_().ResourceVersion

	e.now = e.now.Add(time.Minute)
	e.rec = &SigningRecoveryReconciler{Client: e.c, Reader: e.c, Runtime: e.rr.Runtime, Now: func() time.Time { return e.now }}
	e.reconcile("waiter")
	e.reconcile("holder")
	if got := e.wantHolder("holder"); *got != claim || e.run_().ResourceVersion != rv {
		t.Fatalf("the successor re-claimed the run: %s -> %s", js(claim), js(got))
	}
	e.wantWaiting("waiter", "holder")
}

// recover records a successful recovery by holder as task 2.6 commits it: the
// staged archive committed with a stored signature under the pinned key, the
// run Completed, and signingRecovery.recovered (the claim cleared).
func (e *recoveryEnv) recover(holder *v1alpha1.EvidenceSigningRequest) {
	e.t.Helper()
	ctx := context.Background()
	key, fp := signingKeySecret(e.t, "restored", "pw-restored")
	signer, err := evidencesign.NewSecretSigner(key.Data)
	if err != nil {
		e.t.Fatal(err)
	}
	staged, err := e.store().Recover(ctx, e.ref())
	if err != nil {
		e.t.Fatal(err)
	}
	d, _ := evidencesign.ParseArchiveDigest(staged.PackageSHA256)
	sig, err := signer.Sign(ctx, d)
	if err != nil {
		e.t.Fatal(err)
	}
	pk := signer.PublicKey()
	e.store().SetSignature(e.ref(), sig.Bundle)
	receipt, err := e.store().Publish(ctx, publication.PublishRequest{Staged: staged, Retention: retentionOf("2160h"),
		Signing: &publication.Signing{Mode: publication.SigningRequired, PublicKeyPEM: pk.PEM, KeyFingerprint: fp}})
	if err != nil {
		e.t.Fatal(err)
	}
	e.patchRun(func(r *v1alpha1.AssessmentRun) {
		r.Status.SigningIntent.Key = &v1alpha1.SigningKey{Fingerprint: fp, Algorithm: pk.Algorithm, PublicKey: string(pk.PEM), PinnedAt: metav1.NewTime(e.now)}
		p := publication.ToAPI(publication.Committed(receipt))
		r.Status.Publication = &p
		r.Status.Phase = v1alpha1.RunCompleted
		r.Status.SigningRecovery = &v1alpha1.SigningRecoveryStatus{Recovered: &v1alpha1.SigningRecoveryRecord{
			Name: holder.Name, UID: string(holder.UID), RequestedBy: *holder.Spec.RequestedBy, At: metav1.NewTime(e.now)}}
	})
}

// wantSucceeded checks a request that ended from the recovered run.
func (e *recoveryEnv) wantSucceeded(name string, reason v1alpha1.SigningRecoveryReason) {
	e.t.Helper()
	st, pub := e.esr(name).Status, e.run_().Status.Publication
	want := v1alpha1.SigningRecoveryPublication{PublicationID: pub.PublicationID, PackageSHA256: pub.PackageSHA256, SignatureSHA256: pub.Signature.SHA256,
		PublishedAt: *pub.PublishedAt, ExpiresAt: *pub.ExpiresAt}
	if st.Phase != v1alpha1.SigningRequestSucceeded || st.Reason != reason || st.CompletedAt == nil || st.Publication == nil || js(*st.Publication) != js(want) ||
		st.KeyFingerprint != pub.Signature.KeyFingerprint || !meta.IsStatusConditionTrue(st.Conditions, v1alpha1.ConditionSigningRequestComplete) {
		e.t.Fatalf("%s: want Succeeded/%s referencing %s: %s", name, reason, js(want), js(st))
	}
}

// A request evaluated after the run records its recovery ends from the
// recovered run without a storage write: the namespace AssessmentRequest
// projection is finished first (a missing or recreated one is never
// recreated or overwritten), then the request succeeds. The recorded
// request resuming after its run update ends Recovered; every other
// AlreadyRecovered, referencing the same commit and signature.
func TestSigningRecoveryAlreadyRecovered(t *testing.T) {
	e := newRecoveryEnv(t)
	ctx := context.Background()
	e.request("first", e.name, e.uid())
	e.request("late", e.name, e.uid())
	e.request("later", e.name, e.uid())
	// A namespace run whose AssessmentRequest still shows the failure.
	nsReq := e.runEnv.request("prod", "nightly")
	nsReq.Status = v1alpha1.AssessmentRequestStatus{Phase: v1alpha1.RequestFailed}
	if err := e.c.Status().Update(ctx, nsReq); err != nil {
		t.Fatal(err)
	}
	run := e.run_()
	run.Spec.Scope, run.Spec.Request = v1alpha1.RunScopeNamespace, &v1alpha1.RequestReference{Namespace: "prod", Name: "nightly", UID: string(nsReq.UID)}
	if err := e.c.Update(ctx, run); err != nil {
		t.Fatal(err)
	}
	e.recover(e.esr("first"))
	writes, recovered := storageWrites(e.store()), js(e.run_())

	// The projection write fails: the request is not decided.
	failing := true
	c := interceptor.NewClient(e.c.(ctrl.WithWatch), interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, cl ctrl.Client, sub string, obj ctrl.Object, opts ...ctrl.SubResourceUpdateOption) error {
			if _, ok := obj.(*v1alpha1.AssessmentRequest); ok && failing {
				return apierrors.NewServiceUnavailable("API server unavailable")
			}
			return cl.SubResource(sub).Update(ctx, obj, opts...)
		}})
	rec := &SigningRecoveryReconciler{Client: c, Reader: c, Runtime: e.rr.Runtime, Now: e.rec.Now}
	if _, err := reconcileErr(rec, "late"); err == nil {
		t.Fatal("a failed namespace projection was not retried")
	}
	if st := e.esr("late").Status; st.Phase.Terminal() {
		t.Fatalf("the request succeeded before the namespace projection: %s", js(st))
	}
	failing = false
	if _, err := reconcileErr(rec, "late"); err != nil {
		t.Fatal(err)
	}
	e.wantSucceeded("late", v1alpha1.RecoveryAlreadyRecovered)
	ns := e.requestStatus("prod", "nightly")
	if ns.Phase != v1alpha1.RequestCompleted || ns.ArtifactRef != e.run_().Status.Publication.PublicationID || !meta.IsStatusConditionTrue(ns.Conditions, v1alpha1.ConditionPublished) {
		t.Fatalf("namespace request not completed from the recovered run: %s", js(ns))
	}
	e.reconcile("first")
	e.wantSucceeded("first", v1alpha1.RecoveryRecovered)

	// A recreated namespace request is never overwritten.
	cur := &v1alpha1.AssessmentRequest{}
	if err := e.c.Get(ctx, ctrl.ObjectKey{Namespace: "prod", Name: "nightly"}, cur); err != nil {
		t.Fatal(err)
	}
	if err := e.c.Delete(ctx, cur); err != nil {
		t.Fatal(err)
	}
	recreated := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "nightly", UID: "uid-nightly-recreated"},
		Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: "audit-all"}}}
	if err := e.c.Create(ctx, recreated); err != nil {
		t.Fatal(err)
	}
	before := js(e.requestStatus("prod", "nightly"))
	e.reconcile("later")
	e.wantSucceeded("later", v1alpha1.RecoveryAlreadyRecovered)
	if js(e.requestStatus("prod", "nightly")) != before || recreated.UID == nsReq.UID {
		t.Fatalf("a recreated namespace request was overwritten: %s", js(e.requestStatus("prod", "nightly")))
	}
	if storageWrites(e.store()) != writes || js(e.run_()) != recovered {
		t.Fatal("ending from the recovered run wrote storage or the run")
	}
}

// A recorded recovery without a Completed run and a committed signed
// publication is never a state recovery writes: the request is not decided.
func TestSigningRecoveryRecoveredWithoutCommitDecidesNothing(t *testing.T) {
	e := newRecoveryEnv(t)
	e.request("first", e.name, e.uid())
	e.request("late", e.name, e.uid())
	e.recover(e.esr("first"))
	good := e.run_().Status.DeepCopy()
	for name, edit := range map[string]func(*v1alpha1.AssessmentRunStatus){
		"run not Completed": func(s *v1alpha1.AssessmentRunStatus) { s.Phase = v1alpha1.RunFailed },
		"no commit":         func(s *v1alpha1.AssessmentRunStatus) { s.Publication.Commit = nil },
		"unsigned":          func(s *v1alpha1.AssessmentRunStatus) { s.Publication.Signature = nil },
		"no publication":    func(s *v1alpha1.AssessmentRunStatus) { s.Publication = nil },
	} {
		e.patchRun(func(r *v1alpha1.AssessmentRun) {
			r.Status = *good.DeepCopy()
			edit(&r.Status)
		})
		if _, err := reconcileErr(e.rec, "late"); err == nil || !strings.Contains(err.Error(), "without a committed signed publication") {
			t.Fatalf("%s: want a transient error, got %v", name, err)
		}
		if st := e.esr("late").Status; st.Phase != "" {
			t.Fatalf("%s: decided: %s", name, js(st))
		}
	}
	e.patchRun(func(r *v1alpha1.AssessmentRun) { r.Status = *good.DeepCopy() })
	e.reconcile("late")
	e.wantSucceeded("late", v1alpha1.RecoveryAlreadyRecovered)
}

// Run events reach the requests naming the run, and only recovery-state or
// deletion changes pass the update predicate.
func TestSigningRequestsForRun(t *testing.T) {
	e := newRecoveryEnv(t)
	e.request("mine", e.name, e.uid())
	e.request("other", "another-run", "0b7c2b5e-8f0e-4a8e-9d55-1f2a3b4c5d6e")
	q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer q.ShutDown()
	signingRequestsForRun(e.c).Create(context.Background(), event.CreateEvent{Object: e.run_()}, q)
	if q.Len() != 1 {
		t.Fatalf("enqueued %d requests, want only the one naming the run", q.Len())
	}
	if r, _ := q.Get(); r.Name != "mine" {
		t.Fatalf("enqueued %s", r.Name)
	}
	p, old := signingRecoveryChanged(), e.run_()
	same := old.DeepCopy()
	same.Status.Conditions = nil
	claimed := old.DeepCopy()
	claimed.Status.SigningRecovery = &v1alpha1.SigningRecoveryStatus{Active: &v1alpha1.SigningRecoveryClaim{Name: "mine", UID: "u"}}
	deleting := old.DeepCopy()
	deleting.DeletionTimestamp = &metav1.Time{Time: e.now}
	if p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: same}) || !p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: claimed}) ||
		!p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: deleting}) {
		t.Fatal("signingRecoveryChanged predicate")
	}
}
