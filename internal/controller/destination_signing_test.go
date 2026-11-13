package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// signingKeySecret is a disposable Cosign-format key pair Secret in the
// controller namespace, generated per test.
func signingKeySecret(t *testing.T, name, password string) (*corev1.Secret, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	enc, err := encrypted.Encrypt(der, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	sum := sha256.Sum256(pubDER)
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "konstapel-system", Name: name}, Data: map[string][]byte{
		evidencesign.SecretPrivateKey: pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED SIGSTORE PRIVATE KEY", Bytes: enc}),
		evidencesign.SecretPublicKey:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}),
		evidencesign.SecretPassword:   []byte(password),
	}}, "sha256:" + hex.EncodeToString(sum[:])
}

func requiredSigning(secret string) *v1alpha1.EvidenceSigning {
	return &v1alpha1.EvidenceSigning{Mode: v1alpha1.SigningRequired, SecretRef: &v1alpha1.ControllerNamespaceReference{Name: secret}}
}

type signingHarness struct {
	t     *testing.T
	e     *assessEnv
	r     *DestinationReconciler
	loads int
}

func newSigningHarness(t *testing.T, objs ...client.Object) *signingHarness {
	h := &signingHarness{t: t, e: newAssessEnv(t, objs...)}
	h.r = &DestinationReconciler{Client: h.e.c, Reader: h.e.c,
		Probe: func(context.Context, s3store.Destination, client.Reader, string) error { return nil },
		loadSigner: func(d map[string][]byte) (*evidencesign.SecretSigner, error) {
			h.loads++
			return evidencesign.NewSecretSigner(d)
		}}
	return h
}

func (h *signingHarness) reconcile(name string) (ctrl.Result, *v1alpha1.EvidenceDestination) {
	h.t.Helper()
	res, err := h.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}})
	if err != nil {
		h.t.Fatal(err)
	}
	ed := &v1alpha1.EvidenceDestination{}
	if err := h.e.c.Get(context.Background(), client.ObjectKey{Name: name}, ed); err != nil && !apierrors.IsNotFound(err) {
		h.t.Fatal(err)
	} else if err != nil {
		return res, nil
	}
	return res, ed
}

func (h *signingHarness) edit(name string, f func(*v1alpha1.EvidenceDestination)) {
	h.t.Helper()
	ed := &v1alpha1.EvidenceDestination{}
	if err := h.e.c.Get(context.Background(), client.ObjectKey{Name: name}, ed); err != nil {
		h.t.Fatal(err)
	}
	f(ed)
	ed.Generation++
	if err := h.e.c.Update(context.Background(), ed); err != nil {
		h.t.Fatal(err)
	}
}

func signingCond(ed *v1alpha1.EvidenceDestination) *metav1.Condition {
	return meta.FindStatusCondition(ed.Status.Conditions, v1alpha1.ConditionDestinationSigningReady)
}

// Without spec.signing the destination's status keeps its previous shape:
// no signing status and no SigningReady condition.
func TestDestinationWithoutSigningKeepsItsStatusShape(t *testing.T) {
	ed := evidenceDestination("primary", false)
	ed.Status = v1alpha1.EvidenceDestinationStatus{}
	h := newSigningHarness(t, ed)
	res, got := h.reconcile("primary")
	raw, _ := json.Marshal(got.Status)
	if res.RequeueAfter != DestinationProbeInterval || got.Status.Signing != nil || signingCond(got) != nil || strings.Contains(string(raw), "igning") {
		t.Fatalf("status without signing: %s (requeue %s)", raw, res.RequeueAfter)
	}
	types := []string{}
	for _, c := range got.Status.Conditions {
		types = append(types, c.Type)
	}
	if strings.Join(types, ",") != v1alpha1.ConditionDestinationReady {
		t.Fatalf("conditions: %v", types)
	}
	if h.loads != 0 {
		t.Fatal("a key was loaded without signing configuration")
	}
}

// Readiness follows the referenced key through missing, valid, broken,
// rotated, disabled and removed configuration, separately from Ready.
func TestDestinationSigningReadiness(t *testing.T) {
	ctx := context.Background()
	ed := evidenceDestination("primary", false)
	ed.Status = v1alpha1.EvidenceDestinationStatus{}
	ed.Spec.Signing = requiredSigning("signing-2026-11")
	h := newSigningHarness(t, ed)
	expect := func(step string, status metav1.ConditionStatus, reason string, requeue time.Duration) *v1alpha1.EvidenceDestination {
		t.Helper()
		res, got := h.reconcile("primary")
		c := signingCond(got)
		if c == nil || c.Status != status || c.Reason != reason || c.ObservedGeneration != got.Generation || res.RequeueAfter != requeue {
			t.Fatalf("%s: condition %+v, requeue %s", step, c, res.RequeueAfter)
		}
		if !meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionDestinationReady) {
			t.Fatalf("%s: signing changed backend readiness: %+v", step, got.Status.Conditions)
		}
		return got
	}

	got := expect("missing Secret", metav1.ConditionFalse, v1alpha1.SigningReasonSecretNotFound, SigningRecheckInterval)
	if s := got.Status.Signing; s == nil || s.Mode != v1alpha1.SigningRequired || s.SecretName != "signing-2026-11" || s.KeyFingerprint != "" {
		t.Fatalf("missing Secret status: %+v", s)
	}

	key, fp := signingKeySecret(t, "signing-2026-11", "pw-2026-11")
	if err := h.e.c.Create(ctx, key); err != nil {
		t.Fatal(err)
	}
	got = expect("installed key", metav1.ConditionTrue, v1alpha1.SigningReasonKeyLoaded, DestinationProbeInterval)
	if s := got.Status.Signing; s.KeyFingerprint != fp || s.Algorithm != evidencesign.Algorithm || !strings.Contains(signingCond(got).Message, fp) {
		t.Fatalf("loaded key status: %+v %q", s, signingCond(got).Message)
	}
	// The unchanged Secret is not decrypted again.
	loads := h.loads
	expect("unchanged key", metav1.ConditionTrue, v1alpha1.SigningReasonKeyLoaded, DestinationProbeInterval)
	if h.loads != loads {
		t.Fatalf("unchanged Secret decrypted again (%d loads)", h.loads)
	}

	// Broken Secrets in place: each reason is bounded and the message never
	// carries key material.
	other, _ := signingKeySecret(t, "unused", "other-pw")
	for _, c := range []struct {
		name   string
		edit   func(d map[string][]byte)
		reason string
	}{
		{"wrong password", func(d map[string][]byte) { d[evidencesign.SecretPassword] = []byte("wrong-password") }, v1alpha1.SigningReasonKeyPassword},
		{"mismatched public key", func(d map[string][]byte) { d[evidencesign.SecretPublicKey] = other.Data[evidencesign.SecretPublicKey] }, v1alpha1.SigningReasonKeyMismatch},
		{"no password entry", func(d map[string][]byte) { delete(d, evidencesign.SecretPassword) }, v1alpha1.SigningReasonKeyUnavailable},
		{"malformed key", func(d map[string][]byte) { d[evidencesign.SecretPrivateKey] = []byte("not a key") }, v1alpha1.SigningReasonKeyMalformed},
		{"unencrypted key", func(d map[string][]byte) {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			der, _ := x509.MarshalPKCS8PrivateKey(k)
			d[evidencesign.SecretPrivateKey] = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		}, v1alpha1.SigningReasonUnsupportedKey},
	} {
		fresh, _ := signingKeySecret(t, "signing-2026-11", "pw-2026-11")
		current := &corev1.Secret{}
		_ = h.e.c.Get(ctx, client.ObjectKeyFromObject(fresh), current)
		current.Data = fresh.Data
		c.edit(current.Data)
		secrets := []string{string(current.Data[evidencesign.SecretPassword]), string(fresh.Data[evidencesign.SecretPassword])}
		if b, _ := pem.Decode(fresh.Data[evidencesign.SecretPrivateKey]); b != nil {
			body := base64.StdEncoding.EncodeToString(b.Bytes)
			for i := 0; i+12 <= len(body); i += 6 {
				secrets = append(secrets, body[i:i+12])
			}
		}
		if err := h.e.c.Update(ctx, current); err != nil {
			t.Fatal(err)
		}
		got = expect(c.name, metav1.ConditionFalse, c.reason, SigningRecheckInterval)
		raw, _ := json.Marshal(got.Status)
		for _, s := range secrets {
			if len(s) >= 3 && strings.Contains(string(raw), s) {
				t.Fatalf("%s: status leaks %q: %s", c.name, s, raw)
			}
		}
		if got.Status.Signing.KeyFingerprint != "" {
			t.Fatalf("%s: fingerprint reported for an unusable key", c.name)
		}
	}

	// Recovery in place.
	if err := h.e.c.Get(ctx, client.ObjectKeyFromObject(key), key); err != nil {
		t.Fatal(err)
	}
	fixed, fixedFP := signingKeySecret(t, key.Name, "pw-2026-11")
	key.Data = fixed.Data
	if err := h.e.c.Update(ctx, key); err != nil {
		t.Fatal(err)
	}
	if got = expect("recovered", metav1.ConditionTrue, v1alpha1.SigningReasonKeyLoaded, DestinationProbeInterval); got.Status.Signing.KeyFingerprint != fixedFP {
		t.Fatalf("recovered fingerprint %s, want %s", got.Status.Signing.KeyFingerprint, fixedFP)
	}

	// Rotation to a new versioned Secret.
	next, nextFP := signingKeySecret(t, "signing-2027-05", "pw-2027-05")
	if err := h.e.c.Create(ctx, next); err != nil {
		t.Fatal(err)
	}
	h.edit("primary", func(ed *v1alpha1.EvidenceDestination) { ed.Spec.Signing = requiredSigning(next.Name) })
	if got = expect("rotated", metav1.ConditionTrue, v1alpha1.SigningReasonKeyLoaded, DestinationProbeInterval); got.Status.Signing.KeyFingerprint != nextFP || got.Status.Signing.SecretName != next.Name {
		t.Fatalf("rotated status: %+v", got.Status.Signing)
	}

	// Disabled: ready, no key read; then absent: signing status removed.
	loads = h.loads
	h.edit("primary", func(ed *v1alpha1.EvidenceDestination) {
		ed.Spec.Signing = &v1alpha1.EvidenceSigning{Mode: v1alpha1.SigningDisabled}
	})
	if got = expect("disabled", metav1.ConditionTrue, v1alpha1.SigningReasonDisabled, DestinationProbeInterval); got.Status.Signing.Mode != v1alpha1.SigningDisabled ||
		got.Status.Signing.KeyFingerprint != "" || h.loads != loads {
		t.Fatalf("disabled status: %+v (loads %d→%d)", got.Status.Signing, loads, h.loads)
	}
	h.edit("primary", func(ed *v1alpha1.EvidenceDestination) { ed.Spec.Signing = nil })
	if _, got = h.reconcile("primary"); got.Status.Signing != nil || signingCond(got) != nil {
		t.Fatalf("signing status kept after removing spec.signing: %+v", got.Status)
	}
}

// One destination's unusable key does not affect another destination, and
// an unreadable Secret (for example a revoked permission) is reported as such.
func TestDestinationSigningIsPerDestination(t *testing.T) {
	broken := evidenceDestination("broken", false)
	broken.Status = v1alpha1.EvidenceDestinationStatus{}
	broken.Spec.Signing = requiredSigning("missing-key")
	good := evidenceDestination("good", false)
	good.Status = v1alpha1.EvidenceDestinationStatus{}
	good.Spec.Signing = requiredSigning("present-key")
	plain := evidenceDestination("plain", false)
	plain.Status = v1alpha1.EvidenceDestinationStatus{}
	key, fp := signingKeySecret(t, "present-key", "")
	h := newSigningHarness(t, broken, good, plain, key)
	for _, c := range []struct {
		name, reason string
		fp           string
	}{{"broken", v1alpha1.SigningReasonSecretNotFound, ""}, {"good", v1alpha1.SigningReasonKeyLoaded, fp}} {
		_, got := h.reconcile(c.name)
		if sc := signingCond(got); sc == nil || sc.Reason != c.reason || got.Status.Signing.KeyFingerprint != c.fp {
			t.Fatalf("%s: %+v %+v", c.name, sc, got.Status.Signing)
		}
	}
	if _, got := h.reconcile("plain"); signingCond(got) != nil {
		t.Fatalf("plain destination got signing status: %+v", got.Status)
	}

	h.r.Reader = forbiddenSecrets{h.e.c}
	h.r.signingSeen = signingObservations{}
	_, got := h.reconcile("good")
	if sc := signingCond(got); sc == nil || sc.Reason != v1alpha1.SigningReasonSecretUnreadable || !strings.Contains(sc.Message, "Forbidden") {
		t.Fatalf("unreadable Secret: %+v", sc)
	}
}

type forbiddenSecrets struct{ client.Reader }

func (f forbiddenSecrets) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.Secret); ok {
		return apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, key.Name, nil)
	}
	return f.Reader.Get(ctx, key, obj, opts...)
}

// An unavailable signer never holds retirement: a deleted destination whose
// Required key is missing is released once its obligations are done.
func TestDestinationRetiresWithSignerUnavailable(t *testing.T) {
	ed := evidenceDestination("primary", false)
	ed.Status = v1alpha1.EvidenceDestinationStatus{}
	ed.Spec.Signing = requiredSigning("removed-key")
	ed.Finalizers = []string{DestinationFinalizer}
	h := newSigningHarness(t, ed)
	_, got := h.reconcile("primary")
	if sc := signingCond(got); sc == nil || sc.Status != metav1.ConditionFalse {
		t.Fatalf("setup: %+v", sc)
	}
	if err := h.e.c.Delete(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	if _, got = h.reconcile("primary"); got != nil && controllerutil.ContainsFinalizer(got, DestinationFinalizer) {
		t.Fatalf("retirement held by the unavailable signer: %+v", got.Status)
	}
}

// A committed package stays downloadable from its pinned destination after
// that destination starts requiring a signature whose key is unavailable;
// retention cleanup and the destination's storage readiness are unaffected.
func TestHistoricalReadsIgnoreCurrentSigner(t *testing.T) {
	e := newPinEnv(t)
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted || r.Status.Publication == nil {
		t.Fatalf("setup: %s", r.Status.Phase)
	}
	ed := e.destination("primary")
	ed.Spec.Signing = requiredSigning("removed-key")
	ed.Generation++
	if err := e.c.Update(context.Background(), ed); err != nil {
		t.Fatal(err)
	}
	dr := &DestinationReconciler{Client: e.c, Reader: e.c, Probe: func(context.Context, s3store.Destination, client.Reader, string) error { return nil }}
	if _, err := dr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "primary"}}); err != nil {
		t.Fatal(err)
	}
	ed = e.destination("primary")
	if c := signingCond(ed); c == nil || c.Status != metav1.ConditionFalse || !meta.IsStatusConditionTrue(ed.Status.Conditions, v1alpha1.ConditionDestinationReady) ||
		ed.Status.OutstandingPackages != 1 {
		t.Fatalf("destination status: %+v", ed.Status)
	}
	if _, err := e.rr.publisherFor(context.Background(), e.run(name)); err != nil {
		t.Fatalf("historical download blocked by the unavailable signer: %v", err)
	}
	// Expiry cleanup proceeds.
	e.now = r.Status.Publication.ExpiresAt.Add(time.Second)
	e.step(name)
	if got := e.run(name); got.Status.Publication == nil || got.Status.Publication.Phase != v1alpha1.PublicationPhase("Deleted") || e.stores["uid-primary"].Calls(fake.OpDelete) == 0 {
		t.Fatalf("expiry cleanup held by the unavailable signer: %+v", got.Status.Publication)
	}
}
