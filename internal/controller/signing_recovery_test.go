package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
)

// recoveryEnv is a pinned run that ended SigningFailed with its staged
// archive retained (its Required intent never had a key), and a recovery
// reconciler over the same fake API and storage.
type recoveryEnv struct {
	*signEnv
	rec *SigningRecoveryReconciler
}

func newRecoveryEnv(t *testing.T) *recoveryEnv {
	t.Helper()
	e := newSignEnv(t, requiredWithoutKey("never-installed"))
	e.step(e.name)
	e.now = a0.Add(11 * time.Minute)
	e.step(e.name)
	if !retainedSigningFailure(e.run_()) {
		t.Fatalf("fixture is not a retained SigningFailed run: %s", js(e.run_().Status))
	}
	return &recoveryEnv{signEnv: e, rec: &SigningRecoveryReconciler{Client: e.c, Reader: e.c, Runtime: e.rr.Runtime, Now: func() time.Time { return e.now }}}
}

// request creates an EvidenceSigningRequest for run name/uid.
func (e *recoveryEnv) request(name, run, uid string) {
	e.t.Helper()
	esr := &v1alpha1.EvidenceSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.EvidenceSigningRequestSpec{
		Run: v1alpha1.ExactRunReference{Name: run, UID: uid}, Reason: "key restored after the incident",
		RequestedBy: &v1alpha1.Requester{Username: "platform-admin", UID: "uid-platform-admin"}}}
	if err := e.c.Create(context.Background(), esr); err != nil {
		e.t.Fatal(err)
	}
}

func (e *recoveryEnv) reconcile(name string) *v1alpha1.EvidenceSigningRequest {
	e.t.Helper()
	if _, err := e.rec.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
		e.t.Fatalf("reconcile %s: %v", name, err)
	}
	esr := &v1alpha1.EvidenceSigningRequest{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, esr); err != nil {
		e.t.Fatal(err)
	}
	return esr
}

func (e *recoveryEnv) patchRun(f func(*v1alpha1.AssessmentRun)) {
	e.t.Helper()
	r := e.run_()
	f(r)
	if err := e.c.Status().Update(context.Background(), r); err != nil {
		e.t.Fatal(err)
	}
}

// storageWrites counts every write-capable publisher call and commit.
func storageWrites(s *fake.Publisher) [6]int {
	return [6]int{s.Calls(fake.OpStage), s.Calls(fake.OpPublish), s.Calls(fake.OpDelete), s.Calls(fake.OpCleanup), s.Calls(fake.OpStoreSignature), s.Commits()}
}

// expectTerminal reconciles a request and checks that it failed with want,
// issued no storage write, left the run byte for byte unchanged, and is
// never evaluated again: a later reconcile reads no storage and rewrites
// nothing, even after the cause is gone.
func (e *recoveryEnv) expectTerminal(name string, want v1alpha1.SigningRecoveryReason, contains string, undo func()) {
	e.t.Helper()
	store := e.store()
	writes, run := storageWrites(store), js(e.run_())
	esr := e.reconcile(name)
	st := esr.Status
	c := meta.FindStatusCondition(st.Conditions, v1alpha1.ConditionSigningRequestComplete)
	if st.Phase != v1alpha1.SigningRequestFailed || st.Reason != want || !strings.Contains(st.Message, contains) || st.CompletedAt == nil || st.AcceptedAt == nil ||
		c == nil || c.Status != metav1.ConditionTrue || c.Reason != string(want) || st.Run == nil || *st.Run != esr.Spec.Run ||
		st.RequestedBy == nil || *st.RequestedBy != *esr.Spec.RequestedBy || st.Publication != nil || st.KeyFingerprint != "" {
		e.t.Fatalf("want Failed/%s (%q): %s", want, contains, js(st))
	}
	if strings.Contains(js(st), "never-installed") {
		e.t.Fatalf("request status names the signing Secret: %s", js(st))
	}
	if got := storageWrites(store); got != writes {
		e.t.Fatalf("%s issued storage writes: %v -> %v", want, writes, got)
	}
	if got := js(e.run_()); got != run {
		e.t.Fatalf("%s changed the run:\n%s\n%s", want, run, got)
	}
	if undo != nil {
		undo()
	}
	inspects, before := store.Calls(fake.OpInspect), js(esr)
	if again := e.reconcile(name); js(again) != before || store.Calls(fake.OpInspect) != inspects {
		e.t.Fatalf("a terminal %s request was evaluated again:\n%s\n%s", want, before, js(again))
	}
}

func (e *recoveryEnv) uid() string { return string(e.run_().UID) }

// add-evidence-signing-recovery 2.2: the run is missing or recreated.
func TestSigningRecoveryRunNotFound(t *testing.T) {
	e := newRecoveryEnv(t)
	e.request("missing", "no-such-run", "0b7c2b5e-8f0e-4a8e-9d55-1f2a3b4c5d6e")
	e.expectTerminal("missing", v1alpha1.RecoveryRunNotFound, "does not exist", nil)
	e.request("recreated", e.name, "0b7c2b5e-8f0e-4a8e-9d55-1f2a3b4c5d6f")
	e.expectTerminal("recreated", v1alpha1.RecoveryRunNotFound, "a recreated run never matches", nil)
}

func TestSigningRecoveryRunDeleting(t *testing.T) {
	e := newRecoveryEnv(t)
	if err := e.c.Delete(context.Background(), e.run_()); err != nil { // held by the retention finalizer
		t.Fatal(err)
	}
	if e.run_().DeletionTimestamp.IsZero() {
		t.Fatal("fixture: the run is not being deleted")
	}
	e.request("deleting", e.name, e.uid())
	e.expectTerminal("deleting", v1alpha1.RecoveryRunDeleting, "being deleted", nil)
}

func TestSigningRecoveryNotRecoverable(t *testing.T) {
	// A published run, unsigned.
	plain := newSignEnv(t, nil)
	plain.step(plain.name)
	if plain.run_().Status.Phase != v1alpha1.RunCompleted {
		t.Fatalf("fixture: %s", plain.run_().Status.Phase)
	}
	pe := &recoveryEnv{signEnv: plain, rec: &SigningRecoveryReconciler{Client: plain.c, Reader: plain.c, Runtime: plain.rr.Runtime, Now: func() time.Time { return plain.now }}}
	pe.request("published", plain.name, pe.uid())
	pe.expectTerminal("published", v1alpha1.RecoveryNotRecoverable, "not a retained SigningFailed run", nil)

	for name, c := range map[string]struct {
		edit     func(*v1alpha1.AssessmentRun)
		contains string
	}{
		"other-failure": {func(r *v1alpha1.AssessmentRun) { r.Status.Publication.Failure.Reason = "BackendUnavailable" }, "not a retained SigningFailed run"},
		"disabled-intent": {func(r *v1alpha1.AssessmentRun) {
			r.Status.SigningIntent.Mode, r.Status.SigningIntent.SecretName = v1alpha1.SigningDisabled, ""
		}, "no Required signing intent"},
		"other-destination": {func(r *v1alpha1.AssessmentRun) { r.Status.SigningIntent.DestinationUID = "uid-secondary" }, "not pinned"},
		"no-expiry":         {func(r *v1alpha1.AssessmentRun) { r.Status.Publication.ExpiresAt = nil }, "no retention expiry"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newRecoveryEnv(t)
			e.patchRun(c.edit)
			e.request(name, e.name, e.uid())
			e.expectTerminal(name, v1alpha1.RecoveryNotRecoverable, c.contains, nil)
		})
	}

	t.Run("destination-gone", func(t *testing.T) {
		e := newRecoveryEnv(t)
		ed := e.destination("primary")
		ed.Finalizers = nil
		if err := e.c.Update(context.Background(), ed); err != nil {
			t.Fatal(err)
		}
		if err := e.c.Delete(context.Background(), ed); err != nil {
			t.Fatal(err)
		}
		e.request("gone", e.name, e.uid())
		e.expectTerminal("gone", v1alpha1.RecoveryNotRecoverable, "no longer exists", nil)
	})
}

// At or after the recorded expiry, or once retention cleanup began, nothing
// is recovered: the request ends Expired.
func TestSigningRecoveryExpired(t *testing.T) {
	e := newRecoveryEnv(t)
	expires := e.run_().Status.Publication.ExpiresAt.Time
	e.now = expires
	e.request("at-expiry", e.name, e.uid())
	e.expectTerminal("at-expiry", v1alpha1.RecoveryExpired, "expired at", func() { e.now = expires.Add(-time.Hour) })

	e = newRecoveryEnv(t)
	e.patchRun(func(r *v1alpha1.AssessmentRun) {
		r.Status.Publication.Cleanup.State = v1alpha1.CleanupState(publication.CleanupDeleted)
	})
	e.request("cleaned", e.name, e.uid())
	e.expectTerminal("cleaned", v1alpha1.RecoveryExpired, "cleanup Deleted", nil)
}

// An orphan handoff, recorded on the run, accepted on the destination, or
// fencing this process, ends the request Orphaned.
func TestSigningRecoveryOrphaned(t *testing.T) {
	e := newRecoveryEnv(t)
	e.patchRun(func(r *v1alpha1.AssessmentRun) { orphanPublication(r.Status.Publication) })
	e.request("run-orphaned", e.name, e.uid())
	e.expectTerminal("run-orphaned", v1alpha1.RecoveryOrphaned, "orphan handoff", nil)

	e = newRecoveryEnv(t)
	ed := e.destination("primary")
	ed.Status.OrphanIntent = &v1alpha1.OrphanIntent{Reason: "migration", Actor: "admin", AcceptedAt: metav1.NewTime(e.now)}
	if err := e.c.Status().Update(context.Background(), ed); err != nil {
		t.Fatal(err)
	}
	e.request("intent", e.name, e.uid())
	e.expectTerminal("intent", v1alpha1.RecoveryOrphaned, "accepted orphan handoff", func() {
		ed := e.destination("primary")
		ed.Status.OrphanIntent = nil
		_ = e.c.Status().Update(context.Background(), ed)
	})

	e = newRecoveryEnv(t)
	e.rr.Runtime.Destinations.Fence("uid-primary", 0)
	e.request("fenced", e.name, e.uid())
	e.expectTerminal("fenced", v1alpha1.RecoveryOrphaned, "fenced", nil)
}

// A missing staged archive, or one with another digest, ends the request
// EvidenceLost; nothing is re-staged or recollected.
func TestSigningRecoveryEvidenceLost(t *testing.T) {
	e := newRecoveryEnv(t)
	if err := e.store().CleanupAttempts(context.Background(), e.ref()); err != nil { // the staging is lost
		t.Fatal(err)
	}
	e.request("lost", e.name, e.uid())
	e.expectTerminal("lost", v1alpha1.RecoveryEvidenceLost, "missing", nil)

	e = newRecoveryEnv(t)
	other := strings.Repeat("e", 64)
	e.patchRun(func(r *v1alpha1.AssessmentRun) {
		r.Status.SigningIntent.ArchiveSHA256, r.Status.Publication.PackageSHA256 = other, other
	})
	e.request("replaced", e.name, e.uid())
	e.expectTerminal("replaced", v1alpha1.RecoveryEvidenceLost, "not the intent's", nil)
}

// An existing commit that is not the intent's signed commit of its archive
// ends the request Conflict and is never overwritten.
func TestSigningRecoveryConflict(t *testing.T) {
	ctx := context.Background()
	e := newRecoveryEnv(t)
	staged, err := e.store().Recover(ctx, e.ref())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store().Publish(ctx, publication.PublishRequest{Staged: staged, Retention: retentionOf("2160h")}); err != nil {
		t.Fatal(err)
	}
	e.request("unsigned", e.name, e.uid())
	e.expectTerminal("unsigned", v1alpha1.RecoveryConflict, "unsigned", nil)

	// Signed with a key the intent never pinned, and with another key than
	// the pinned one.
	key, _ := signingKeySecret(t, "other", "pw-other")
	signer, err := evidencesign.NewSecretSigner(key.Data)
	if err != nil {
		t.Fatal(err)
	}
	e = newRecoveryEnv(t)
	staged, err = e.store().Recover(ctx, e.ref())
	if err != nil {
		t.Fatal(err)
	}
	d, _ := evidencesign.ParseArchiveDigest(staged.PackageSHA256)
	sig, err := signer.Sign(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()
	e.store().SetSignature(e.ref(), sig.Bundle)
	if _, err := e.store().Publish(ctx, publication.PublishRequest{Staged: staged, Retention: retentionOf("2160h"),
		Signing: &publication.Signing{Mode: publication.SigningRequired, PublicKeyPEM: pub.PEM, KeyFingerprint: pub.Fingerprint}}); err != nil {
		t.Fatal(err)
	}
	e.request("never-pinned", e.name, e.uid())
	e.expectTerminal("never-pinned", v1alpha1.RecoveryConflict, "never pinned a key", nil)

	pinned := "sha256:" + strings.Repeat("a", 64)
	e.patchRun(func(r *v1alpha1.AssessmentRun) {
		r.Status.SigningIntent.Key = &v1alpha1.SigningKey{Fingerprint: pinned, Algorithm: pub.Algorithm, PublicKey: string(pub.PEM), PinnedAt: metav1.NewTime(e.now)}
	})
	e.request("other-key", e.name, e.uid())
	e.expectTerminal("other-key", v1alpha1.RecoveryConflict, "not the pinned "+pinned, nil)
}

// An eligible request is accepted once and waits for the claim (task 2.3);
// eligibility issues no storage write and leaves the run unchanged. This
// includes a matching signed commit whose response was lost (adopted
// unchanged by recovery) and a run already recovered (AlreadyRecovered).
func TestSigningRecoveryEligibleRequestIsAccepted(t *testing.T) {
	e := newRecoveryEnv(t)
	accepted := func(name string) {
		t.Helper()
		writes, run := storageWrites(e.store()), js(e.run_())
		esr := e.reconcile(name)
		st := esr.Status
		if st.Phase != v1alpha1.SigningRequestPending || st.Reason != v1alpha1.RecoveryAccepted || st.CompletedAt != nil || st.AcceptedAt == nil ||
			st.Run == nil || st.RequestedBy == nil || meta.IsStatusConditionTrue(st.Conditions, v1alpha1.ConditionSigningRequestComplete) {
			t.Fatalf("%s: want Pending/Accepted: %s", name, js(st))
		}
		if storageWrites(e.store()) != writes || js(e.run_()) != run {
			t.Fatalf("%s: eligibility wrote storage or the run", name)
		}
		if again := e.reconcile(name); js(again.Status) != js(st) {
			t.Fatalf("%s: acceptance rewritten:\n%s\n%s", name, js(st), js(again.Status))
		}
	}
	e.request("eligible", e.name, e.uid())
	accepted("eligible")
	// Eligibility is re-checked while the request is not terminal.
	e.now = e.run_().Status.Publication.ExpiresAt.Time
	e.expectTerminal("eligible", v1alpha1.RecoveryExpired, "expired at", nil)

	// A matching signed commit from before the signing failure.
	ctx := context.Background()
	key, fp := signingKeySecret(t, "lost", "pw-lost")
	signer, err := evidencesign.NewSecretSigner(key.Data)
	if err != nil {
		t.Fatal(err)
	}
	e = newRecoveryEnv(t)
	staged, _ := e.store().Recover(ctx, e.ref())
	d, _ := evidencesign.ParseArchiveDigest(staged.PackageSHA256)
	sig, err := signer.Sign(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()
	e.store().SetSignature(e.ref(), sig.Bundle)
	if _, err := e.store().Publish(ctx, publication.PublishRequest{Staged: staged, Retention: retentionOf("2160h"),
		Signing: &publication.Signing{Mode: publication.SigningRequired, PublicKeyPEM: pub.PEM, KeyFingerprint: fp}}); err != nil {
		t.Fatal(err)
	}
	e.patchRun(func(r *v1alpha1.AssessmentRun) {
		r.Status.SigningIntent.Key = &v1alpha1.SigningKey{Fingerprint: fp, Algorithm: pub.Algorithm, PublicKey: string(pub.PEM), PinnedAt: metav1.NewTime(e.now)}
	})
	e.request("adopt", e.name, e.uid())
	accepted("adopt")
	el, err := e.rec.eligibility(ctx, e.reconcile("adopt"))
	if err != nil || el.reason != "" || el.committed == nil || el.committed.Signature == nil || el.committed.Signature.KeyFingerprint != fp {
		t.Fatalf("adoption eligibility: %+v %v", el, err)
	}

	// Already recovered: not a failure, whatever the run's phase.
	e = newRecoveryEnv(t)
	e.patchRun(func(r *v1alpha1.AssessmentRun) {
		r.Status.Phase = v1alpha1.RunCompleted
		r.Status.SigningRecovery = &v1alpha1.SigningRecoveryStatus{Recovered: &v1alpha1.SigningRecoveryRecord{Name: "first", UID: "uid-first", At: metav1.NewTime(e.now)}}
	})
	e.request("late", e.name, e.uid())
	accepted("late")
	if el, err := e.rec.eligibility(ctx, e.reconcile("late")); err != nil || !el.recovered {
		t.Fatalf("already recovered: %+v %v", el, err)
	}
}

// Transient API or storage failures decide nothing: the request is left as
// it was and retried.
func TestSigningRecoveryTransientFailureDecidesNothing(t *testing.T) {
	e := newRecoveryEnv(t)
	e.request("outage", e.name, e.uid())
	e.store().Fail(fake.OpInspect, publication.ErrUnavailable)
	if _, err := e.rec.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "outage"}}); err == nil {
		t.Fatal("a storage outage was not retried")
	}
	esr := &v1alpha1.EvidenceSigningRequest{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: "outage"}, esr); err != nil || esr.Status.Phase != "" {
		t.Fatalf("an outage decided the request: %s %v", js(esr.Status), err)
	}
}

func retentionOf(d string) publication.Retention {
	return publication.Retention{Duration: d, BindingConfiguration: "test", SelectedAt: time.Now().UTC().Truncate(time.Second)}
}
