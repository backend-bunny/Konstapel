package controller

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

func (e *signEnv) reconcileDestination() *v1alpha1.EvidenceDestination {
	e.t.Helper()
	dr := &DestinationReconciler{Client: e.c, Reader: e.c, Namespace: "konstapel-system", Now: func() time.Time { return e.now },
		Probe: func(context.Context, s3store.Destination, client.Reader, string) error { return nil }}
	if _, err := dr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "primary"}}); err != nil {
		e.t.Fatal(err)
	}
	return e.destination("primary")
}

// 5.1: the keys that runs still waiting to be signed depend on are listed on
// their destination, by Secret and pinned fingerprint, independent of the
// destination's current policy; old intents use the previous key while new
// intents use the next one; the list empties once they finish.
func TestPendingSigningKeysAreInspectable(t *testing.T) {
	e := newSignEnv(t, requiredWithoutKey("signing-2026"))
	if ed := e.reconcileDestination(); ed.Status.PendingSigningKeys != nil {
		t.Fatalf("pending keys before any intent: %s", js(ed.Status.PendingSigningKeys))
	}
	e.step(e.name)
	e.expectSigningPending("signing-2026 was not found")
	if got := e.reconcileDestination().Status.PendingSigningKeys; len(got) != 1 || got[0].SecretName != "signing-2026" || got[0].KeyFingerprint != "" || got[0].Runs != 1 {
		t.Fatalf("keyless dependency: %s", js(got))
	}
	// Installing the key pins it; the upload fails, so the run still waits.
	old, oldFP := signingKeySecret(t, "signing-2026", "pw")
	e.putSecret(old)
	e.store().Fail(fake.OpStoreSignature, publication.ErrUnavailable)
	e.now = e.now.Add(10 * time.Second)
	e.step(e.name)
	// Rotation and even removing the policy do not hide the dependency.
	next, nextFP := signingKeySecret(t, "signing-2027", "pw")
	e.putSecret(next)
	e.setSigning(nil)
	if got := e.reconcileDestination().Status.PendingSigningKeys; len(got) != 1 || got[0].SecretName != "signing-2026" || got[0].KeyFingerprint != oldFP {
		t.Fatalf("pinned dependency: %s", js(got))
	}
	e.setSigning(requiredSigning("signing-2027"))
	e.now = e.now.Add(10 * time.Second)
	e.step(e.name)
	e.expectSigned(oldFP) // the old intent used the previous key
	if got := e.reconcileDestination().Status.PendingSigningKeys; got != nil {
		t.Fatalf("dependency kept after signing: %s", js(got))
	}
	// A new run is prepared under the next key.
	e.now = a0.Add(24*time.Hour + time.Second)
	e.assess("audit-prod")
	second := e.schedule("audit-prod").ActiveRun
	if second == nil || second.Name == e.name {
		t.Fatal("setup: no second run")
	}
	e.step(second.Name)
	e.now = e.now.Add(5*time.Minute + time.Second)
	e.step(second.Name)
	if r := e.pinEnv.run(second.Name); r.Status.Publication == nil || r.Status.Publication.Signature == nil || r.Status.Publication.Signature.KeyFingerprint != nextFP {
		t.Fatalf("new intent not signed with the next key: %s", js(r.Status))
	}
}

// 5.2: a signed package whose signature object is damaged or lost before
// expiry is reported Unavailable by the integrity check, without changing
// its receipt, expiry, or assessment summary.
func TestSignatureDamageMarksPackageUnavailable(t *testing.T) {
	for name, damage := range map[string]func(e *signEnv){
		"tampered": func(e *signEnv) {
			d, _ := evidencesign.ParseArchiveDigest(e.run_().Status.Publication.PackageSHA256)
			ok, _ := signingKeySecret(t, "k", "pw")
			other, _ := evidencesign.NewSecretSigner(ok.Data)
			b, _ := other.Sign(context.Background(), d)
			e.store().SetSignature(e.ref(), b.Bundle)
		},
		"missing": func(e *signEnv) { e.store().SetSignature(e.ref(), nil) },
	} {
		t.Run(name, func(t *testing.T) {
			setup, fp := requiredWithKey(t, "signing-a")
			e := newSignEnv(t, setup)
			e.step(e.name)
			before := e.expectSigned(fp)
			damage(e)
			e.now = e.now.Add(25 * time.Hour) // past the integrity interval, before expiry
			e.step(e.name)
			r := e.run_()
			p := r.Status.Publication
			if p.Availability != v1alpha1.Availability(publication.AvailabilityUnavailable) || p.Failure == nil || !strings.Contains(p.Failure.Message, "signature") ||
				!p.ExpiresAt.Equal(before.Status.Publication.ExpiresAt) || js(r.Status.Summary) != js(before.Status.Summary) || p.Signature == nil {
				t.Fatalf("damaged signature: %s", js(p))
			}
		})
	}
}

// 5.2: a signature stored for a run that never committed (publication
// failed) is removed with its abandoned attempts; a committed signed
// package's signature is removed by retention deletion at expiry.
func TestSignatureObjectsFollowAttemptCleanupAndRetention(t *testing.T) {
	t.Run("uncommitted", func(t *testing.T) {
		setup, _ := requiredWithKey(t, "signing-a")
		e := newSignEnv(t, setup)
		for i := 0; i < 64; i++ {
			e.store().Fail(fake.OpPublish, publication.ErrUnavailable)
		}
		e.step(e.name)
		if _, _, err := e.store().ReadSignature(context.Background(), e.ref()); err != nil {
			t.Fatalf("setup: no stored signature: %v", err)
		}
		e.now = a0.Add(11 * time.Minute)
		e.step(e.name) // PublicationFailed (not a signing failure)
		e.step(e.name) // terminal: attempt cleanup
		if c := e.published(); e.run_().Status.Phase != v1alpha1.RunFailed || c.Reason != v1alpha1.ReasonPublicationFailed {
			t.Fatalf("setup: %s", js(c))
		}
		if _, _, err := e.store().ReadSignature(context.Background(), e.ref()); err == nil {
			t.Fatal("an uncommitted run's signature survived attempt cleanup")
		}
	})
	t.Run("retention", func(t *testing.T) {
		setup, fp := requiredWithKey(t, "signing-a")
		e := newSignEnv(t, setup)
		e.step(e.name)
		r := e.expectSigned(fp)
		e.step(e.name) // attempt cleanup keeps the committed signature
		if _, _, err := e.store().ReadSignature(context.Background(), e.ref()); err != nil {
			t.Fatalf("attempt cleanup removed the committed signature: %v", err)
		}
		e.now = r.Status.Publication.ExpiresAt.Add(time.Second)
		e.step(e.name)
		if _, _, err := e.store().ReadSignature(context.Background(), e.ref()); err == nil || e.store().Calls(fake.OpDelete) != 1 {
			t.Fatalf("retention kept the signature: %v", err)
		}
	})
}

// blockingStore delays signature uploads, ignoring cancellation for a
// while, to model an upload in flight when the orphan fence closes.
type blockingStore struct {
	*fake.Publisher
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingStore) StoreSignature(ctx context.Context, run publication.RunRef, bundle []byte) ([]byte, publication.Signature, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return b.Publisher.StoreSignature(ctx, run, bundle)
}

// 5.3: after an orphan handoff no signing work starts; an upload in flight
// is cancelled, reported as uncertain if it does not stop in time, and its
// late response never commits or completes the run.
func TestOrphanFenceCoversSigningWork(t *testing.T) {
	setup, _ := requiredWithKey(t, "signing-a")
	e := newSignEnv(t, setup)
	b := &blockingStore{Publisher: e.store(), started: make(chan struct{}), release: make(chan struct{})}
	dp := e.rr.Runtime.Destinations
	inner := dp.New
	dp.New = func(ctx context.Context, d s3store.Destination, r client.Reader, ns string) (publication.Publisher, error) {
		if d.ID == "uid-primary" {
			return b, nil
		}
		return inner(ctx, d, r, ns)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = e.rr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: e.name}})
	}()
	<-b.started
	uncertain := dp.Fence("uid-primary", 50*time.Millisecond)
	if !strings.Contains(strings.Join(uncertain, ";"), "run "+e.name+" signature upload") {
		t.Fatalf("uncertain operations %v", uncertain)
	}
	close(b.release) // the late response arrives after the fence
	<-done
	if e.store().Commits() != 0 || e.run_().Status.Phase == v1alpha1.RunCompleted {
		t.Fatalf("a late signature response reactivated publication: commits %d phase %s", e.store().Commits(), e.run_().Status.Phase)
	}
	// No new signing work begins after the fence.
	stores := e.store().Calls(fake.OpStoreSignature)
	if _, _, err := dp.Begin(context.Background(), "uid-primary", "late"); err == nil {
		t.Fatal("work began after the fence")
	}
	e.now = e.now.Add(10 * time.Second)
	_, _ = e.rr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: e.name}})
	if e.store().Calls(fake.OpStoreSignature) != stores {
		t.Fatal("a signature upload started after the fence")
	}
}

// 5.3: the durable handoff inventory records each run's signing intent and
// signature object, with public material only.
func TestOrphanInventoryRecordsSigningWithoutPrivateMaterial(t *testing.T) {
	key, fp := signingKeySecret(t, "signing-a", "inventory-password")
	e := newSignEnv(t, func(p *pinEnv) {
		_ = p.c.Create(context.Background(), key)
		ed := p.destination("primary")
		ed.Spec.Signing = requiredSigning("signing-a")
		_ = p.c.Update(context.Background(), ed)
	})
	e.step(e.name)
	r := e.expectSigned(fp)
	ed := e.destination("primary")
	ed.Spec.DeletionPolicy = v1alpha1.DeletionOrphan
	ed.Spec.Orphan = &v1alpha1.OrphanRequest{Reason: "handed to the archive team", Actor: "platform-admin"}
	if err := e.c.Update(context.Background(), ed); err != nil {
		t.Fatal(err)
	}
	_ = e.c.Delete(context.Background(), e.destination("primary"))
	reconcileDestination(t, e.destinationReconciler(e.c), "primary")
	_, runs, raw := e.inventory(t, "uid-primary")
	var rec *OrphanRun
	for i := range runs {
		if runs[i].Name == e.name {
			rec = &runs[i]
		}
	}
	if rec == nil || rec.SigningIntent == nil || rec.SigningIntent.Key == nil || rec.SigningIntent.Key.Fingerprint != fp ||
		rec.Publication == nil || rec.Publication.Signature == nil || rec.Publication.Signature.SHA256 != r.Status.Publication.Signature.SHA256 {
		t.Fatalf("inventory record: %s", js(rec))
	}
	for _, secret := range []string{"inventory-password", "PRIVATE KEY", string(key.Data[evidencesign.SecretPrivateKey][40:80])} {
		if strings.Contains(raw, secret) {
			t.Fatalf("inventory holds private material %q", secret)
		}
	}
}

// 5.5: signing status uses fixed vocabularies, and the guide documents
// exactly those values; a reason derived from any key-loading error is one
// of them, so status (and anything projected from it) stays bounded.
func TestSigningReasonsAreBoundedAndDocumented(t *testing.T) {
	ready := []string{v1alpha1.SigningReasonDisabled, v1alpha1.SigningReasonKeyLoaded, v1alpha1.SigningReasonSecretNotFound, v1alpha1.SigningReasonSecretUnreadable,
		v1alpha1.SigningReasonKeyUnavailable, v1alpha1.SigningReasonKeyMalformed, v1alpha1.SigningReasonKeyPassword, v1alpha1.SigningReasonKeyMismatch, v1alpha1.SigningReasonUnsupportedKey}
	allowed := map[string]bool{}
	for _, r := range ready {
		allowed[r] = true
	}
	for _, err := range []error{evidencesign.ErrKeyPassword, evidencesign.ErrKeyMismatch, evidencesign.ErrUnsupportedKey, evidencesign.ErrKeyMalformed,
		evidencesign.ErrKeyUnavailable, evidencesign.ErrSignature, context.Canceled, nil} {
		if r := signingReason(err); !allowed[r] {
			t.Errorf("signingReason(%v) = %q is outside the documented set", err, r)
		}
	}
	raw, err := os.ReadFile("../../docs/integration/evidence-signing.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	_, readiness, _ := strings.Cut(doc, "### Signing readiness")
	readiness, _, _ = strings.Cut(readiness, "### Who can read")
	documented := map[string]bool{}
	for _, line := range strings.Split(readiness, "\n") {
		cells := strings.Split(line, "|")
		if len(cells) > 3 && strings.HasPrefix(strings.TrimSpace(cells[2]), "`") {
			documented[strings.Trim(strings.TrimSpace(cells[2]), "`")] = true
		}
	}
	if len(documented) != len(ready) {
		t.Errorf("documented SigningReady reasons %v, implemented %v", documented, ready)
	}
	for _, r := range ready {
		if !documented[r] {
			t.Errorf("SigningReady reason %s is not documented", r)
		}
	}
	for _, r := range []string{v1alpha1.ReasonSigningPending, v1alpha1.ReasonSigningFailed, publication.FailureObjectMissing, publication.FailureIntegrityFailed} {
		if !strings.Contains(doc, "`"+r+"`") {
			t.Errorf("run reason %s is not documented", r)
		}
	}
}
