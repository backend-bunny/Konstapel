package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

func requiredWithKey(t *testing.T, secret string) (func(e *pinEnv), string) {
	key, fp := signingKeySecret(t, secret, "pw-"+secret)
	return func(e *pinEnv) {
		_ = e.c.Create(context.Background(), key)
		ed := e.destination("primary")
		ed.Spec.Signing = requiredSigning(secret)
		_ = e.c.Update(context.Background(), ed)
	}, fp
}

func requiredWithoutKey(secret string) func(e *pinEnv) {
	return func(e *pinEnv) {
		ed := e.destination("primary")
		ed.Spec.Signing = requiredSigning(secret)
		_ = e.c.Update(context.Background(), ed)
	}
}

// 3.4: a signed publication finishes on a new leader after its private key
// was retired, with the original archive bytes, signature bytes, run
// identity, and expiry; later reconciles never change the receipt.
func TestSignedPublicationSurvivesLeaderChangeAndKeyRetirement(t *testing.T) {
	setup, fp := requiredWithKey(t, "signing-2026")
	e := newSignEnv(t, setup)
	e.store().Fail(fake.OpPublish, publication.ErrUnavailable)
	e.step(e.name) // leader 1 signs and stores; the commit fails
	staged, err := e.store().Recover(context.Background(), e.ref())
	if err != nil {
		t.Fatal(err)
	}
	bundle, ref, err := e.store().ReadSignature(context.Background(), e.ref())
	if err != nil {
		t.Fatal(err)
	}
	runUID := e.run_().UID

	e.deleteSecret("signing-2026") // the private key is retired
	e.restart()                    // leader 2: a fresh reconciler, no in-memory state
	e.now = e.now.Add(30 * time.Second)
	e.step(e.name)
	r := e.expectSigned(fp)
	p := r.Status.Publication
	if p.PackageSHA256 != staged.PackageSHA256 || p.Signature.SHA256 != ref.SHA256 || r.UID != runUID || p.PublicationID != e.ref().PublicationID() ||
		p.ExpiresAt == nil || !p.ExpiresAt.Time.Equal(p.PublishedAt.Add(2160*time.Hour)) {
		t.Fatalf("identity changed across the leader change: %s", js(p))
	}
	got, _, _ := e.store().ReadSignature(context.Background(), e.ref())
	if string(got) != string(bundle) {
		t.Fatal("signature bytes changed")
	}
	before := js(p)
	e.restart()
	e.now = e.now.Add(time.Hour)
	e.step(e.name)
	if after := js(e.run_().Status.Publication); after != before {
		t.Fatalf("a later reconcile changed the receipt:\n%s\n%s", before, after)
	}
}

// 3.5: a signing failure never costs evidence. The run fails with
// SigningFailed (bounded by the publish timeout), releases its binding's
// slot, keeps its evidence summary, and retains the staged archive with the
// run until the run's retention expiry: not abandoned-attempt cleanup, not
// released by deleting the run record, counted by its destination. Expiry
// then deletes it like a retained package.
func TestSigningFailureRetainsStagedEvidenceUntilExpiry(t *testing.T) {
	e := newSignEnv(t, requiredWithoutKey("never-installed"))
	e.step(e.name)
	e.expectSigningPending("never-installed")
	pending := e.run_()
	summary := js(pending.Status.Summary)
	// Bounded: retries continue until the publish timeout, then stop.
	if res := e.step(e.name); res.RequeueAfter != e.rr.Runtime.Poll {
		t.Fatalf("pending requeue %s", res.RequeueAfter)
	}
	e.now = a0.Add(11 * time.Minute)
	e.step(e.name)
	r := e.run_()
	p := r.Status.Publication
	closed := r.Status.Window.Closed.Time
	if r.Status.Phase != v1alpha1.RunFailed || e.published().Reason != v1alpha1.ReasonSigningFailed || p == nil ||
		p.Phase != v1alpha1.PublicationPhase(publication.PhaseFailed) || p.Failure == nil || p.Failure.Reason != v1alpha1.ReasonSigningFailed ||
		p.Commit != nil || p.Signature != nil || p.PackageSHA256 != r.Status.SigningIntent.ArchiveSHA256 ||
		p.ExpiresAt == nil || !p.ExpiresAt.Time.Equal(closed.Add(2160*time.Hour)) || p.Cleanup.State != v1alpha1.CleanupState(publication.CleanupNotDue) {
		t.Fatalf("SigningFailed run: %s %s", r.Status.Phase, js(p))
	}
	if err := publication.FromAPI(*p).Validate(); err != nil {
		t.Fatalf("retained failure status is invalid: %v", err)
	}
	// Evidence meaning is unchanged; nothing is recollected.
	if js(r.Status.Summary) != summary || r.Status.Summary.Export == v1alpha1.ExportState(publication.ExportCaptureLost) {
		t.Fatalf("summary changed:\n%s\n%s", summary, js(r.Status.Summary))
	}
	// The slot is released: the next scheduled run can start.
	e.assess("audit-prod")
	if s := e.schedule("audit-prod"); s.ActiveRun != nil && s.ActiveRun.Name == e.name {
		t.Fatalf("slot still held: %s", js(s))
	}

	// Terminal reconciles keep the staged archive: no attempt cleanup.
	for i := 0; i < 3; i++ {
		e.now = e.now.Add(time.Hour)
		e.step(e.name)
	}
	if _, err := e.store().Recover(context.Background(), e.ref()); err != nil || e.store().Calls(fake.OpCleanup) != 0 {
		t.Fatalf("staged evidence removed after a signing failure: %v (cleanups %d)", err, e.store().Calls(fake.OpCleanup))
	}
	if !controllerutil.ContainsFinalizer(e.run_(), RetentionFinalizer) {
		t.Fatal("retention finalizer released")
	}
	// The destination counts it as a retained package with that expiry.
	dr := &DestinationReconciler{Client: e.c, Reader: e.c, Probe: func(context.Context, s3store.Destination, client.Reader, string) error { return nil }}
	if _, err := dr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "primary"}}); err != nil {
		t.Fatal(err)
	}
	if ed := e.destination("primary"); ed.Status.OutstandingPackages != 1 || ed.Status.LatestRetainedExpiry == nil || !ed.Status.LatestRetainedExpiry.Equal(p.ExpiresAt) {
		t.Fatalf("destination obligations: %s", js(ed.Status))
	}
	// Deleting the run record does not delete the evidence before expiry.
	if err := e.c.Delete(context.Background(), e.run_()); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Hour)
	e.step(e.name)
	if _, err := e.store().Recover(context.Background(), e.ref()); err != nil || e.store().Calls(fake.OpDelete) != 0 {
		t.Fatalf("deleting the run removed retained evidence early: %v", err)
	}
	// At expiry it is deleted and the record released.
	e.now = p.ExpiresAt.Add(time.Second)
	e.step(e.name)
	if e.store().Calls(fake.OpDelete) != 1 {
		t.Fatalf("expiry deletion calls: %d", e.store().Calls(fake.OpDelete))
	}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: e.name}, &v1alpha1.AssessmentRun{}); err == nil {
		t.Fatal("run record kept after retention deletion")
	}
}

// 3.5: if the frozen package itself is lost while signing is pending, the
// run ends with CaptureLost (explicit capture loss), not SigningFailed, and
// nothing is recollected under its identity.
func TestCaptureLostWhileSigningPending(t *testing.T) {
	e := newSignEnv(t, func(p *pinEnv) {
		requiredWithoutKey("never-installed")(p)
		p.stores["uid-primary"].DurableStaging = false
	})
	e.step(e.name)
	e.expectSigningPending("never-installed")
	e.store().Restart() // undurable staging lost
	if err := os.RemoveAll(e.rr.staging(e.run_())); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(10 * time.Second)
	e.step(e.name)
	r := e.run_()
	if r.Status.Phase != v1alpha1.RunFailed || e.published().Reason != v1alpha1.ReasonCaptureLost || r.Status.Publication != nil ||
		r.Status.Summary.Export != v1alpha1.ExportState(publication.ExportCaptureLost) || e.store().Commits() != 0 {
		t.Fatalf("want CaptureLost: %s %s", r.Status.Phase, js(e.published()))
	}
}

// 3.6: incomplete and diagnostic packages are signed like complete ones,
// with the same assessment meaning as their unsigned counterparts.
func TestSigningKeepsAssessmentMeaning(t *testing.T) {
	diagnostic := func(e *signEnv) {
		if err := os.WriteFile(filepath.Join(e.rr.staging(e.run_()), runContentFile), []byte("{corrupt"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, c := range map[string]struct {
		prepare    func(e *signEnv)
		completion string
		export     publication.ExportState
	}{
		"incomplete": {nil, "Incomplete", publication.ExportAssessment},
		"diagnostic": {diagnostic, "Incomplete", publication.ExportDiagnostic},
	} {
		t.Run(name, func(t *testing.T) {
			summaries := map[bool]string{}
			for _, signed := range []bool{false, true} {
				var setup func(*pinEnv)
				fp := ""
				if signed {
					setup, fp = requiredWithKey(t, "signing-a")
				}
				e := newSignEnv(t, setup)
				if c.prepare != nil {
					c.prepare(e)
				}
				e.step(e.name)
				r := e.run_()
				if signed {
					r = e.expectSigned(fp)
				} else if r.Status.Phase != v1alpha1.RunCompleted || r.Status.Publication.Signature != nil {
					t.Fatalf("unsigned control: %s", js(r.Status))
				}
				if string(r.Status.Summary.Evidence.Completeness) != c.completion || r.Status.Summary.Export != v1alpha1.ExportState(c.export) {
					t.Fatalf("signed=%v summary %s", signed, js(r.Status.Summary))
				}
				summaries[signed] = js(r.Status.Summary)
			}
			if summaries[true] != summaries[false] {
				t.Fatalf("signing changed the assessment summary:\nunsigned %s\nsigned   %s", summaries[false], summaries[true])
			}
		})
	}
}

// A retained signing failure handed off by an orphan handoff becomes an
// operator-owned, still valid record.
func TestRetainedSigningFailureCanBeOrphaned(t *testing.T) {
	e := newSignEnv(t, requiredWithoutKey("never-installed"))
	e.step(e.name)
	e.now = a0.Add(11 * time.Minute)
	e.step(e.name)
	p := e.run_().Status.Publication
	orphanPublication(p)
	if err := publication.FromAPI(*p).Validate(); err != nil || p.Phase != v1alpha1.PublicationPhase(publication.PhaseOrphaned) || p.Failure == nil {
		t.Fatalf("orphaned retained failure: %v %s", err, js(p))
	}
}
