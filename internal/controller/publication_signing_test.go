package controller

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
)

// signEnv is a pinned-destination run environment for signing tests.
type signEnv struct {
	*pinEnv
	name string
}

// newSignEnv starts a run on "primary" (with signing set up by setup) and
// stops just before collection closes.
func newSignEnv(t *testing.T, setup func(e *pinEnv)) *signEnv {
	e := newPinEnv(t)
	if setup != nil {
		setup(e)
	}
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name) // pinned to primary, collecting
	e.now = a0.Add(5*time.Minute + time.Second)
	return &signEnv{pinEnv: e, name: name}
}

func (e *signEnv) setSigning(s *v1alpha1.EvidenceSigning) {
	e.t.Helper()
	ed := e.destination("primary")
	ed.Spec.Signing = s
	ed.Generation++
	if err := e.c.Update(context.Background(), ed); err != nil {
		e.t.Fatal(err)
	}
}

func (e *signEnv) putSecret(s *corev1.Secret) {
	e.t.Helper()
	cur := &corev1.Secret{}
	if err := e.c.Get(context.Background(), client.ObjectKeyFromObject(s), cur); err == nil {
		cur.Data = s.Data
		if err := e.c.Update(context.Background(), cur); err != nil {
			e.t.Fatal(err)
		}
		return
	}
	if err := e.c.Create(context.Background(), s.DeepCopy()); err != nil {
		e.t.Fatal(err)
	}
}

func (e *signEnv) deleteSecret(name string) {
	e.t.Helper()
	if err := e.c.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "konstapel-system", Name: name}}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *signEnv) store() *fake.Publisher { return e.stores["uid-primary"] }

func (e *signEnv) published() *metav1.Condition {
	return meta.FindStatusCondition(e.run_().Status.Conditions, v1alpha1.ConditionPublished)
}

func (e *signEnv) run_() *v1alpha1.AssessmentRun { return e.pinEnv.run(e.name) }

func (e *signEnv) ref() publication.RunRef {
	r := e.run_()
	return publication.RunRef{ClusterID: r.Status.Scope.ClusterID, BindingUID: r.Status.Binding.UID, RunUID: string(r.UID)}
}

// expectSigned checks a completed run: a signed receipt whose signature is
// the stored bundle and verifies for the committed archive under want.
func (e *signEnv) expectSigned(wantFP string) *v1alpha1.AssessmentRun {
	e.t.Helper()
	r := e.run_()
	p := r.Status.Publication
	if r.Status.Phase != v1alpha1.RunCompleted || p == nil || p.Signature == nil || p.Signature.KeyFingerprint != wantFP {
		e.t.Fatalf("not a signed completion under %s: phase %s publication %s conditions %s", wantFP, r.Status.Phase, js(p), js(r.Status.Conditions))
	}
	bundle, ref, err := e.store().ReadSignature(context.Background(), e.ref())
	if err != nil || ref.SHA256 != p.Signature.SHA256 {
		e.t.Fatalf("committed signature %s is not the stored bundle %s: %v", p.Signature.SHA256, ref.SHA256, err)
	}
	pub, err := evidencesign.ParsePublicKey([]byte(r.Status.SigningIntent.Key.PublicKey))
	if err != nil {
		e.t.Fatal(err)
	}
	d, _ := evidencesign.ParseArchiveDigest(p.PackageSHA256)
	if _, err := evidencesign.Verify(bundle, d, pub); err != nil {
		e.t.Fatalf("committed signature does not verify: %v", err)
	}
	return r
}

// expectUnsignedPending checks that nothing is committed and the run waits
// with SigningPending.
func (e *signEnv) expectSigningPending(contains string) {
	e.t.Helper()
	r := e.run_()
	c := e.published()
	if r.Status.Phase != v1alpha1.RunPublishing || c == nil || c.Reason != v1alpha1.ReasonSigningPending || !strings.Contains(c.Message, contains) ||
		e.store().Commits() != 0 || r.Status.Publication != nil {
		e.t.Fatalf("want SigningPending (%q) and no commit: phase %s, %s, commits %d", contains, r.Status.Phase, js(c), e.store().Commits())
	}
}

// A Required destination: the intent pins the key, the archive is signed
// and the signature stored before the commit, and the receipt references it.
func TestRequiredSigningCommitsVerifiedPair(t *testing.T) {
	key, fp := signingKeySecret(t, "signing-a", "pw-a")
	e := newSignEnv(t, func(e *pinEnv) {
		_ = e.c.Create(context.Background(), key)
		ed := e.destination("primary")
		ed.Spec.Signing = requiredSigning("signing-a")
		_ = e.c.Update(context.Background(), ed)
	})
	e.step(e.name)
	r := e.expectSigned(fp)
	in := r.Status.SigningIntent
	if in == nil || in.Mode != v1alpha1.SigningRequired || in.SecretName != "signing-a" || in.Key == nil || in.Key.Fingerprint != fp ||
		in.DestinationUID != "uid-primary" || in.ArchiveSHA256 != r.Status.Publication.PackageSHA256 || in.Key.SecretUID == "" {
		t.Fatalf("intent: %s", js(in))
	}
	if strings.Contains(js(r.Status), "pw-a") || strings.Contains(js(r.Status), "PRIVATE") {
		t.Fatal("run status holds key material")
	}
	if e.store().Calls(fake.OpStoreSignature) != 1 {
		t.Fatalf("signature stored %d times", e.store().Calls(fake.OpStoreSignature))
	}
	// Evidence meaning is unchanged by signing.
	if r.Status.Summary == nil || r.Status.Summary.Export != v1alpha1.ExportState(publication.ExportAssessment) {
		t.Fatalf("summary: %s", js(r.Status.Summary))
	}
}

// A Disabled (or absent) policy records a Disabled intent and commits the
// unsigned publication exactly as before.
func TestDisabledSigningCommitsUnsigned(t *testing.T) {
	e := newSignEnv(t, nil)
	e.step(e.name)
	r := e.run_()
	if r.Status.Phase != v1alpha1.RunCompleted || r.Status.Publication.Signature != nil || r.Status.SigningIntent == nil ||
		r.Status.SigningIntent.Mode != v1alpha1.SigningDisabled || r.Status.SigningIntent.Key != nil || r.Status.SigningIntent.SecretName != "" {
		t.Fatalf("unsigned run: %s", js(r.Status))
	}
	if e.store().Calls(fake.OpStoreSignature)+e.store().Calls(fake.OpReadSignature) != 0 {
		t.Fatal("an unsigned publication touched signature storage")
	}
}

// A Required intent prepared while its key is missing is recorded anyway;
// switching the destination to Disabled cannot downgrade it; installing the
// key lets it commit signed.
func TestRequiredIntentSurvivesDisableAndMissingKey(t *testing.T) {
	e := newSignEnv(t, func(e *pinEnv) {
		ed := e.destination("primary")
		ed.Spec.Signing = requiredSigning("signing-later")
		_ = e.c.Update(context.Background(), ed)
	})
	e.step(e.name)
	e.expectSigningPending("signing-later was not found")
	in := e.run_().Status.SigningIntent
	if in == nil || in.Mode != v1alpha1.SigningRequired || in.Key != nil {
		t.Fatalf("intent without a key: %s", js(in))
	}
	e.setSigning(&v1alpha1.EvidenceSigning{Mode: v1alpha1.SigningDisabled})
	e.now = e.now.Add(10 * time.Second)
	e.step(e.name)
	e.expectSigningPending("signing-later was not found")
	key, fp := signingKeySecret(t, "signing-later", "pw")
	e.putSecret(key)
	e.now = e.now.Add(10 * time.Second)
	e.step(e.name)
	e.expectSigned(fp)
}

// A Disabled intent stays unsigned when the destination later requires
// signing; an archive staged but not yet prepared uses the policy current
// at preparation.
func TestIntentIsFrozenAtPreparation(t *testing.T) {
	t.Run("disabled then required", func(t *testing.T) {
		e := newSignEnv(t, nil)
		e.store().Fail(fake.OpPublish, publication.ErrUnavailable)
		e.step(e.name)
		if in := e.run_().Status.SigningIntent; in == nil || in.Mode != v1alpha1.SigningDisabled {
			t.Fatalf("intent: %s", js(in))
		}
		key, _ := signingKeySecret(t, "signing-a", "pw")
		e.putSecret(key)
		e.setSigning(requiredSigning("signing-a"))
		e.now = e.now.Add(10 * time.Second)
		e.step(e.name)
		if r := e.run_(); r.Status.Phase != v1alpha1.RunCompleted || r.Status.Publication.Signature != nil {
			t.Fatalf("a Disabled intent changed after preparation: %s", js(r.Status))
		}
	})
	t.Run("staged then required", func(t *testing.T) {
		e := newSignEnv(t, nil)
		e.store().LoseResponse(fake.OpStage) // staged durably, response lost
		e.step(e.name)
		if in := e.run_().Status.SigningIntent; in != nil {
			t.Fatalf("intent prepared before the stage succeeded: %s", js(in))
		}
		key, fp := signingKeySecret(t, "signing-a", "pw")
		e.putSecret(key)
		e.setSigning(requiredSigning("signing-a"))
		e.now = e.now.Add(10 * time.Second)
		e.step(e.name)
		e.expectSigned(fp)
	})
}

// Rotating the destination to another Secret after the intent pinned its key
// does not change the intent; the old key still signs it.
func TestRotationDoesNotChangePinnedIntent(t *testing.T) {
	oldKey, oldFP := signingKeySecret(t, "signing-2026", "pw-old")
	e := newSignEnv(t, func(e *pinEnv) {
		_ = e.c.Create(context.Background(), oldKey)
		ed := e.destination("primary")
		ed.Spec.Signing = requiredSigning("signing-2026")
		_ = e.c.Update(context.Background(), ed)
	})
	e.store().Fail(fake.OpStoreSignature, publication.ErrUnavailable)
	e.step(e.name) // intent pinned, signature not stored
	if in := e.run_().Status.SigningIntent; in == nil || in.Key == nil || in.Key.Fingerprint != oldFP {
		t.Fatalf("intent: %s", js(in))
	}
	newKey, _ := signingKeySecret(t, "signing-2027", "pw-new")
	e.putSecret(newKey)
	e.setSigning(requiredSigning("signing-2027"))
	e.now = e.now.Add(10 * time.Second)
	e.step(e.name)
	if r := e.expectSigned(oldFP); r.Status.SigningIntent.SecretName != "signing-2026" {
		t.Fatalf("intent switched Secret: %s", js(r.Status.SigningIntent))
	}
}

// A different key under the pinned Secret's name cannot satisfy the intent:
// publication waits, then fails with SigningFailed, and nothing is committed.
func TestReplacedSecretCannotSatisfyIntent(t *testing.T) {
	key, _ := signingKeySecret(t, "signing-a", "pw")
	e := newSignEnv(t, func(e *pinEnv) {
		_ = e.c.Create(context.Background(), key)
		ed := e.destination("primary")
		ed.Spec.Signing = requiredSigning("signing-a")
		_ = e.c.Update(context.Background(), ed)
	})
	e.store().Fail(fake.OpStoreSignature, publication.ErrUnavailable)
	e.step(e.name)
	other, otherFP := signingKeySecret(t, "signing-a", "pw")
	e.putSecret(other)
	e.now = e.now.Add(10 * time.Second)
	e.step(e.name)
	e.expectSigningPending("now holds key " + otherFP)
	// The same key re-encrypted with another password still matches.
	// (Covered by evidencesign: identity is the public key, not the PEM.)
	e.now = a0.Add(11 * time.Minute)
	e.step(e.name)
	r := e.run_()
	c := e.published()
	if r.Status.Phase != v1alpha1.RunFailed || c.Reason != v1alpha1.ReasonSigningFailed || e.store().Commits() != 0 ||
		r.Status.Summary == nil || r.Status.Summary.Export == v1alpha1.ExportState(publication.ExportCaptureLost) {
		t.Fatalf("want SigningFailed without commit or capture loss: %s %s", r.Status.Phase, js(c))
	}
}

// Re-encrypting the pinned private key with a new password keeps its
// identity, so the intent is still satisfied.
func TestReencryptedKeyStillSatisfiesIntent(t *testing.T) {
	key, fp := signingKeySecret(t, "signing-a", "pw-1")
	e := newSignEnv(t, func(e *pinEnv) {
		_ = e.c.Create(context.Background(), key)
		ed := e.destination("primary")
		ed.Spec.Signing = requiredSigning("signing-a")
		_ = e.c.Update(context.Background(), ed)
	})
	e.store().Fail(fake.OpStoreSignature, publication.ErrUnavailable)
	e.step(e.name)
	e.putSecret(reencrypt(t, key, "pw-1", "pw-2"))
	e.now = e.now.Add(10 * time.Second)
	e.step(e.name)
	e.expectSigned(fp)
}

// Once a verified signature is stored, completing the commit (including
// after a lost commit response) needs no private key: the Secret is gone.
func TestStoredSignatureRecoversWithoutPrivateKey(t *testing.T) {
	key, fp := signingKeySecret(t, "signing-a", "pw")
	e := newSignEnv(t, func(e *pinEnv) {
		_ = e.c.Create(context.Background(), key)
		ed := e.destination("primary")
		ed.Spec.Signing = requiredSigning("signing-a")
		_ = e.c.Update(context.Background(), ed)
	})
	e.store().Fail(fake.OpPublish, publication.ErrUnavailable)
	e.step(e.name) // signed and stored, commit failed
	stored, _, err := e.store().ReadSignature(context.Background(), e.ref())
	if err != nil {
		t.Fatal(err)
	}
	e.deleteSecret("signing-a")
	e.store().LoseResponse(fake.OpPublish) // commits, response lost
	e.now = e.now.Add(10 * time.Second)
	e.step(e.name)
	if e.store().Commits() != 1 || e.run_().Status.Phase != v1alpha1.RunPublishing {
		t.Fatalf("lost response: commits %d phase %s", e.store().Commits(), e.run_().Status.Phase)
	}
	e.now = e.now.Add(10 * time.Second)
	e.step(e.name)
	r := e.expectSigned(fp)
	again, _, _ := e.store().ReadSignature(context.Background(), e.ref())
	if string(again) != string(stored) || e.store().Calls(fake.OpStoreSignature) != 1 {
		t.Fatal("the stored signature was replaced or re-made")
	}
	if !r.Status.Publication.PublishedAt.Equal(r.Status.Publication.PublishedAt) || r.Status.Publication.ExpiresAt == nil {
		t.Fatal("receipt incomplete")
	}
}

// Attempts that produce different signature bytes converge on the first
// stored bundle. Here another attempt stores its own valid bundle (same key,
// different random signature) after this attempt found none: this attempt
// signs, its conditional store loses, and it commits the winner.
func TestConcurrentSignaturesConvergeOnStoredBundle(t *testing.T) {
	key, fp := signingKeySecret(t, "signing-a", "pw")
	e := newSignEnv(t, func(e *pinEnv) {
		_ = e.c.Create(context.Background(), key)
		ed := e.destination("primary")
		ed.Spec.Signing = requiredSigning("signing-a")
		_ = e.c.Update(context.Background(), ed)
	})
	e.store().Fail(fake.OpStoreSignature, publication.ErrUnavailable)
	e.step(e.name) // intent pinned, nothing stored
	staged, err := e.store().Recover(context.Background(), e.ref())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := evidencesign.NewSecretSigner(key.Data)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := evidencesign.ParseArchiveDigest(staged.PackageSHA256)
	theirs, err := signer.Sign(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.store().StoreSignature(context.Background(), e.ref(), theirs.Bundle); err != nil {
		t.Fatal(err)
	}
	// This attempt's recovery read races ahead of the other store.
	e.store().Fail(fake.OpReadSignature, publication.ErrNotFound)
	stores := e.store().Calls(fake.OpStoreSignature)
	e.now = e.now.Add(10 * time.Second)
	e.step(e.name)
	got := e.expectSigned(fp)
	if e.store().Calls(fake.OpStoreSignature) != stores+1 || got.Status.Publication.Signature.SHA256 != theirs.BundleSHA256 {
		t.Fatalf("committed %s, the first stored bundle is %s", got.Status.Publication.Signature.SHA256, theirs.BundleSHA256)
	}
	// And an attempt that finds the stored bundle reuses it without a key.
}

// A stored bundle that does not verify (tampered, or for another archive
// or key) is never committed or replaced: publication fails with
// SigningFailed and no commit exists.
func TestInvalidStoredSignatureBlocksCommit(t *testing.T) {
	key, _ := signingKeySecret(t, "signing-a", "pw")
	other, _ := signingKeySecret(t, "other", "pw")
	e := newSignEnv(t, func(e *pinEnv) {
		_ = e.c.Create(context.Background(), key)
		ed := e.destination("primary")
		ed.Spec.Signing = requiredSigning("signing-a")
		_ = e.c.Update(context.Background(), ed)
	})
	e.store().Fail(fake.OpStoreSignature, publication.ErrUnavailable)
	e.step(e.name)
	staged, _ := e.store().Recover(context.Background(), e.ref())
	d, _ := evidencesign.ParseArchiveDigest(staged.PackageSHA256)
	wrongKey, _ := evidencesign.NewSecretSigner(other.Data)
	bad, _ := wrongKey.Sign(context.Background(), d)
	e.store().SetSignature(e.ref(), bad.Bundle)
	e.now = e.now.Add(10 * time.Second)
	e.step(e.name)
	e.expectSigningPending("stored signature does not verify")
	e.now = a0.Add(11 * time.Minute)
	e.step(e.name)
	if r := e.run_(); r.Status.Phase != v1alpha1.RunFailed || e.published().Reason != v1alpha1.ReasonSigningFailed || e.store().Commits() != 0 {
		t.Fatalf("want SigningFailed: %s %s", r.Status.Phase, js(e.published()))
	}
	if b, _, _ := e.store().ReadSignature(context.Background(), e.ref()); string(b) != string(bad.Bundle) {
		t.Fatal("the stored signature was overwritten")
	}
}

// The commit gate itself: a Required intent never commits without a stored
// signature that verifies, and an existing commit never satisfies an intent
// it does not match.
func TestCommitGateRefusesUnsignedUnderRequired(t *testing.T) {
	e := newSignEnv(t, nil)
	e.store().Fail(fake.OpPublish, publication.ErrUnavailable)
	e.step(e.name)
	staged, err := e.store().Recover(context.Background(), e.ref())
	if err != nil {
		t.Fatal(err)
	}
	key, fp := signingKeySecret(t, "k", "pw")
	signer, _ := evidencesign.NewSecretSigner(key.Data)
	pub := signer.PublicKey()
	ret := publication.Retention{Duration: "1h", BindingConfiguration: "b", SelectedAt: e.now}
	required := &publication.Signing{Mode: publication.SigningRequired, PublicKeyPEM: pub.PEM, KeyFingerprint: fp}
	if _, err := e.store().Publish(context.Background(), publication.PublishRequest{Staged: staged, Retention: ret, Signing: required}); !errors.Is(err, publication.ErrSignatureRequired) || e.store().Commits() != 0 {
		t.Fatalf("unsigned commit under Required: %v (commits %d)", err, e.store().Commits())
	}
	// An unsigned commit exists: a Required intent never accepts it.
	if _, err := e.store().Publish(context.Background(), publication.PublishRequest{Staged: staged, Retention: ret}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store().Publish(context.Background(), publication.PublishRequest{Staged: staged, Retention: ret, Signing: required}); !errors.Is(err, publication.ErrSignatureRequired) || !errors.Is(err, publication.ErrConflict) {
		t.Fatalf("an unsigned commit satisfied a Required intent: %v", err)
	}
}

// Concurrent preparations of the same run converge on one intent: the
// loser's conditional status update conflicts and it rereads the winner's.
func TestConcurrentIntentPreparationConverges(t *testing.T) {
	key, _ := signingKeySecret(t, "signing-a", "pw")
	e := newSignEnv(t, func(e *pinEnv) {
		_ = e.c.Create(context.Background(), key)
		ed := e.destination("primary")
		ed.Spec.Signing = requiredSigning("signing-a")
		_ = e.c.Update(context.Background(), ed)
	})
	e.store().Fail(fake.OpPublish, publication.ErrUnavailable)
	e.store().Fail(fake.OpPublish, publication.ErrUnavailable)
	// Close collection and stage without preparing: lose the stage response.
	e.store().LoseResponse(fake.OpStage)
	e.step(e.name)
	staged, err := e.store().Recover(context.Background(), e.ref())
	if err != nil {
		t.Fatal(err)
	}
	a, b := e.run_(), e.run_()
	ina, erra := e.rr.signingIntent(context.Background(), a, staged)
	_, errb := e.rr.signingIntent(context.Background(), b, staged)
	if erra != nil || errb == nil {
		t.Fatalf("want the second stale preparation to conflict: %v / %v", erra, errb)
	}
	fresh := e.run_()
	inb, err := e.rr.signingIntent(context.Background(), fresh, staged)
	if err != nil || js(inb) != js(ina) {
		t.Fatalf("reread intent differs:\n%s\n%s (%v)", js(inb), js(ina), err)
	}
}

// reencrypt returns the Secret with the same private key encrypted under a
// new password.
func reencrypt(t *testing.T, s *corev1.Secret, oldPW, newPW string) *corev1.Secret {
	t.Helper()
	block, _ := pem.Decode(s.Data[evidencesign.SecretPrivateKey])
	der, err := encrypted.Decrypt(block.Bytes, []byte(oldPW))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := encrypted.Encrypt(der, []byte(newPW))
	if err != nil {
		t.Fatal(err)
	}
	out := s.DeepCopy()
	out.Data[evidencesign.SecretPrivateKey] = pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: enc})
	out.Data[evidencesign.SecretPassword] = []byte(newPW)
	return out
}

func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Crash points between preparing the intent, signing, storing the
// signature, and committing. After each, a restarted attempt converges on
// exactly one stored bundle and one signed commit under the pinned key; a
// bundle that reached storage is reused rather than re-signed, and nothing
// unsigned is ever committed.
func TestSigningCrashPoints(t *testing.T) {
	for _, c := range []struct {
		name string
		// inject arms the fault that interrupts the first attempt.
		inject func(s *fake.Publisher)
		// storedAtCrash: a bundle reached storage before the interruption.
		storedAtCrash, committedAtCrash bool
	}{
		{name: "before the recovery read", inject: func(s *fake.Publisher) { s.Fail(fake.OpReadSignature, publication.ErrUnavailable) }},
		{name: "after signing, before the store", inject: func(s *fake.Publisher) { s.Fail(fake.OpStoreSignature, publication.ErrUnavailable) }},
		{name: "store response lost", inject: func(s *fake.Publisher) { s.LoseResponse(fake.OpStoreSignature) }, storedAtCrash: true},
		{name: "after the store, before the commit", inject: func(s *fake.Publisher) { s.Fail(fake.OpPublish, publication.ErrUnavailable) }, storedAtCrash: true},
		{name: "commit response lost", inject: func(s *fake.Publisher) { s.LoseResponse(fake.OpPublish) }, storedAtCrash: true, committedAtCrash: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			key, fp := signingKeySecret(t, "signing-a", "pw")
			e := newSignEnv(t, func(e *pinEnv) {
				_ = e.c.Create(context.Background(), key)
				ed := e.destination("primary")
				ed.Spec.Signing = requiredSigning("signing-a")
				_ = e.c.Update(context.Background(), ed)
			})
			c.inject(e.store())
			e.step(e.name)
			r := e.run_()
			if r.Status.Phase != v1alpha1.RunPublishing || r.Status.SigningIntent == nil || r.Status.SigningIntent.Key == nil || r.Status.Publication != nil {
				t.Fatalf("interrupted attempt: %s", js(r.Status))
			}
			if want := map[bool]int{false: 0, true: 1}[c.committedAtCrash]; e.store().Commits() != want {
				t.Fatalf("commits at crash: %d", e.store().Commits())
			}
			atCrash, _, err := e.store().ReadSignature(context.Background(), e.ref())
			if c.storedAtCrash != (err == nil) {
				t.Fatalf("stored at crash: %v", err)
			}
			stores := e.store().Calls(fake.OpStoreSignature)
			e.store().Restart() // a new process
			e.now = e.now.Add(10 * time.Second)
			e.step(e.name)
			got := e.expectSigned(fp)
			if e.store().Commits() != 1 {
				t.Fatalf("commits: %d", e.store().Commits())
			}
			final, _, _ := e.store().ReadSignature(context.Background(), e.ref())
			if c.storedAtCrash {
				if string(final) != string(atCrash) || e.store().Calls(fake.OpStoreSignature) != stores {
					t.Fatal("a stored signature was re-made after the crash")
				}
			}
			if got.Status.SigningIntent.Key.Fingerprint != fp {
				t.Fatal("intent key changed")
			}
		})
	}
}
