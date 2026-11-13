package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
)

// The signing key Secret named by spec.signing.secretRef is read with the
// controller's existing namespace-scoped Secret get (evidence.go): one
// uncached read by name per evaluation, never a list or a watch.

// SigningRecheckInterval is how soon a destination whose Required signing
// key cannot be used is evaluated again, so that installing or fixing the
// Secret is noticed without a Secret watch. A usable key is re-read with
// the regular DestinationProbeInterval; publication rereads the policy and
// the Secret itself when it records a signing intent, so this observation is
// advisory.
const SigningRecheckInterval = 30 * time.Second

// signingObservations remembers, per destination, the outcome of the last
// key load for one Secret version, so that an unchanged Secret is not
// decrypted again on every reconcile. It holds only public results (status
// and condition), never key material.
type signingObservations struct {
	mu sync.Mutex
	m  map[types.UID]signingObservation
}

type signingObservation struct {
	secretUID       types.UID
	resourceVersion string
	status          v1alpha1.SigningStatus
	reason, message string
	ready           bool
}

// maxSigningObservations bounds the memo; it is cleared when full.
const maxSigningObservations = 1024

func (o *signingObservations) get(ed types.UID, s *corev1.Secret) (signingObservation, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	got, ok := o.m[ed]
	return got, ok && got.secretUID == s.UID && got.resourceVersion == s.ResourceVersion && s.ResourceVersion != ""
}

func (o *signingObservations) put(ed types.UID, obs signingObservation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.m == nil || len(o.m) >= maxSigningObservations {
		o.m = map[types.UID]signingObservation{}
	}
	o.m[ed] = obs
}

// observeSigning evaluates a destination's signing policy. It returns nil
// status and condition when spec.signing is absent, so destinations without
// signing configuration keep their previous status shape. The result never
// affects Ready, obligations, retirement, or downloads.
func (r *DestinationReconciler) observeSigning(ctx context.Context, ed *v1alpha1.EvidenceDestination) (*v1alpha1.SigningStatus, *metav1.Condition) {
	sp := ed.Spec.Signing
	if sp == nil {
		return nil, nil
	}
	cond := &metav1.Condition{Type: v1alpha1.ConditionDestinationSigningReady, ObservedGeneration: ed.Generation}
	if sp.Mode != v1alpha1.SigningRequired {
		cond.Status, cond.Reason, cond.Message = metav1.ConditionTrue, v1alpha1.SigningReasonDisabled, "signing is disabled; new publications are unsigned"
		return &v1alpha1.SigningStatus{Mode: v1alpha1.SigningDisabled}, cond
	}
	status := &v1alpha1.SigningStatus{Mode: v1alpha1.SigningRequired}
	notReady := func(reason, msg string) (*v1alpha1.SigningStatus, *metav1.Condition) {
		cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, reason, truncate(msg+"; new publications to this destination cannot be signed")
		return status, cond
	}
	if sp.SecretRef == nil || sp.SecretRef.Name == "" {
		return notReady(v1alpha1.SigningReasonKeyUnavailable, "signing mode Required has no secretRef")
	}
	status.SecretName = sp.SecretRef.Name
	secret := &corev1.Secret{}
	if err := r.Reader.Get(ctx, client.ObjectKey{Namespace: controllerNamespace(r.Namespace), Name: sp.SecretRef.Name}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return notReady(v1alpha1.SigningReasonSecretNotFound, fmt.Sprintf("signing Secret %s was not found in the controller namespace", sp.SecretRef.Name))
		}
		return notReady(v1alpha1.SigningReasonSecretUnreadable, fmt.Sprintf("signing Secret %s cannot be read: %s", sp.SecretRef.Name, apiReason(err)))
	}
	if obs, ok := r.signingSeen.get(ed.UID, secret); ok {
		clearSecret(secret)
		s := obs.status
		cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, obs.reason, obs.message
		if obs.ready {
			cond.Status = metav1.ConditionTrue
		}
		return &s, cond
	}
	load := r.loadSigner
	if load == nil {
		load = evidencesign.NewSecretSigner
	}
	signer, err := load(secret.Data)
	clearSecret(secret)
	obs := signingObservation{secretUID: secret.UID, resourceVersion: secret.ResourceVersion}
	if err != nil {
		st, c := notReady(signingReason(err), fmt.Sprintf("signing Secret %s: %v", sp.SecretRef.Name, err))
		obs.status, obs.reason, obs.message = *st, c.Reason, c.Message
		r.signingSeen.put(ed.UID, obs)
		return st, c
	}
	pub := signer.PublicKey()
	status.KeyFingerprint, status.Algorithm = pub.Fingerprint, pub.Algorithm
	cond.Status, cond.Reason = metav1.ConditionTrue, v1alpha1.SigningReasonKeyLoaded
	cond.Message = truncate(fmt.Sprintf("key %s (%s) from Secret %s can sign new publications", pub.Fingerprint, pub.Algorithm, sp.SecretRef.Name))
	obs.status, obs.reason, obs.message, obs.ready = *status, cond.Reason, cond.Message, true
	r.signingSeen.put(ed.UID, obs)
	return status, cond
}

// signingReason maps a sanitized key-loading error to its bounded reason.
func signingReason(err error) string {
	switch {
	case errors.Is(err, evidencesign.ErrKeyPassword):
		return v1alpha1.SigningReasonKeyPassword
	case errors.Is(err, evidencesign.ErrKeyMismatch):
		return v1alpha1.SigningReasonKeyMismatch
	case errors.Is(err, evidencesign.ErrUnsupportedKey):
		return v1alpha1.SigningReasonUnsupportedKey
	case errors.Is(err, evidencesign.ErrKeyMalformed):
		return v1alpha1.SigningReasonKeyMalformed
	default:
		return v1alpha1.SigningReasonKeyUnavailable
	}
}

// apiReason is the bounded API status reason of a read error (Forbidden,
// Timeout, ...), not its full text.
func apiReason(err error) string {
	if r := apierrors.ReasonForError(err); r != metav1.StatusReasonUnknown {
		return string(r)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "request timed out"
	}
	return "request failed"
}

// clearSecret overwrites the private key and password bytes read from the
// API so they do not outlive the evaluation in this process's memory.
func clearSecret(s *corev1.Secret) {
	for _, k := range []string{evidencesign.SecretPrivateKey, evidencesign.SecretPassword} {
		clear(s.Data[k])
	}
	s.Data = nil
}
