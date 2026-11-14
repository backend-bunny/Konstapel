package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Publication signing (add-evidence-signing group 3, design section 4a).
//
// The run's signing intent is frozen once, from an authoritative read of
// its pinned destination, after the archive is staged and before any
// commit. A Required intent commits only through the publisher's commit
// gate with a stored signature that verifies under the intent's pinned key;
// there is no unsigned fallback and no downgrade. A stored signature is
// recovered and verified before any private key is loaded.

// errSigning marks publication errors caused by signing, so that retries
// report SigningPending and a timeout ends the run with SigningFailed.
var errSigning = errors.New("evidence signing")

func signingError(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errSigning, fmt.Sprintf(format, a...))
}

// isSigningError reports whether a publication error is a signing failure,
// including the publisher's commit gate refusing an unsigned commit.
func isSigningError(err error) bool {
	return errors.Is(err, errSigning) || errors.Is(err, publication.ErrSignatureRequired)
}

// signingReader returns the uncached reader and namespace used for
// destinations and signing Secrets.
func (r *AssessmentRunReconciler) signingReader() (client.Reader, string) {
	if d := r.Runtime.Destinations; d != nil && d.Reader != nil {
		return d.Reader, controllerNamespace(d.Namespace)
	}
	return r.Client, controllerNamespace(r.Runtime.ControllerNamespace)
}

// signingIntent returns the run's frozen signing intent, recording it first
// when absent. A Required intent whose key cannot be loaded yet is still
// recorded (without a key) and the load error returned, so a later policy
// change can never downgrade it.
func (r *AssessmentRunReconciler) signingIntent(ctx context.Context, run *v1alpha1.AssessmentRun, staged publication.Staged) (*v1alpha1.SigningIntent, error) {
	if in := run.Status.SigningIntent; in != nil {
		if in.ArchiveSHA256 != staged.PackageSHA256 {
			return nil, fmt.Errorf("the signing intent covers archive %s, not the staged %s: %w", in.ArchiveSHA256, staged.PackageSHA256, publication.ErrConflict)
		}
		return in, nil
	}
	in := &v1alpha1.SigningIntent{Mode: v1alpha1.SigningDisabled, ArchiveSHA256: staged.PackageSHA256, PreparedAt: metav1.NewTime(r.now())}
	if pin := run.Status.Destination; pin != nil {
		reader, _ := r.signingReader()
		ed := &v1alpha1.EvidenceDestination{}
		if err := reader.Get(ctx, client.ObjectKey{Name: pin.Name}, ed); err != nil {
			return nil, fmt.Errorf("%w: read the pinned destination's signing policy: %v", publication.ErrUnavailable, apiReason(err))
		}
		if string(ed.UID) != pin.UID {
			return nil, fmt.Errorf("%w: the pinned destination %s was replaced; its signing policy cannot be read", publication.ErrUnavailable, pin.Name)
		}
		in.DestinationUID, in.DestinationGeneration = pin.UID, ed.Generation
		if sp := ed.Spec.Signing; sp != nil && sp.Mode == v1alpha1.SigningRequired {
			in.Mode = v1alpha1.SigningRequired
			if sp.SecretRef == nil || sp.SecretRef.Name == "" {
				return nil, signingError("destination %s requires signing but names no key Secret", pin.Name)
			}
			in.SecretName = sp.SecretRef.Name
		}
	}
	var loadErr error
	if in.Mode == v1alpha1.SigningRequired {
		var signer *evidencesign.SecretSigner
		var secret *corev1.Secret
		signer, secret, loadErr = r.loadSigningKey(ctx, in)
		if loadErr == nil {
			in.Key = pinnedKey(signer.PublicKey(), secret, r.now())
		}
	}
	// Recorded with a resourceVersion-conditional update: a concurrent
	// preparation loses with a conflict and rereads the winner's intent.
	run.Status.SigningIntent = in
	if err := r.Client.Status().Update(ctx, run); err != nil {
		run.Status.SigningIntent = nil
		return nil, err
	}
	if loadErr != nil {
		return nil, loadErr
	}
	return in, nil
}

func pinnedKey(pub evidencesign.PublicKey, s *corev1.Secret, now time.Time) *v1alpha1.SigningKey {
	return &v1alpha1.SigningKey{Fingerprint: pub.Fingerprint, Algorithm: pub.Algorithm, PublicKey: string(pub.PEM),
		SecretUID: string(s.UID), SecretResourceVersion: s.ResourceVersion, PinnedAt: metav1.NewTime(now)}
}

// loadSigningKey reads the intent's key Secret by name in the controller
// namespace and loads it. A pinned intent accepts only its pinned key: a
// replaced or rotated Secret under the same name is a mismatch, never a
// substitute. The Secret's private bytes are cleared before returning.
func (r *AssessmentRunReconciler) loadSigningKey(ctx context.Context, in *v1alpha1.SigningIntent) (*evidencesign.SecretSigner, *corev1.Secret, error) {
	reader, ns := r.signingReader()
	secret := &corev1.Secret{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: ns, Name: in.SecretName}, secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil, signingError("signing Secret %s was not found in the controller namespace", in.SecretName)
		}
		return nil, nil, signingError("signing Secret %s cannot be read: %s", in.SecretName, apiReason(err))
	}
	signer, err := evidencesign.NewSecretSigner(secret.Data)
	clearSecret(secret)
	if err != nil {
		return nil, nil, signingError("signing Secret %s: %v", in.SecretName, err)
	}
	if k := in.Key; k != nil && signer.PublicKey().Fingerprint != k.Fingerprint {
		return nil, nil, signingError("signing Secret %s now holds key %s; this publication's intent requires %s", in.SecretName, signer.PublicKey().Fingerprint, k.Fingerprint)
	}
	return signer, secret, nil
}

// signingRequirement satisfies a run's frozen intent before commit and
// returns what the publisher's commit gate checks. A Required intent's
// stored signature is recovered and verified before any private key is
// loaded; only when none is stored is the key loaded, the archive signed,
// and the bundle stored once (the first stored bundle wins and is reverified).
func (r *AssessmentRunReconciler) signingRequirement(ctx context.Context, run *v1alpha1.AssessmentRun, store publication.Publisher, staged publication.Staged, in *v1alpha1.SigningIntent) (*publication.Signing, error) {
	if in.Mode != v1alpha1.SigningRequired {
		return &publication.Signing{Mode: publication.SigningDisabled}, nil
	}
	digest, err := evidencesign.ParseArchiveDigest(staged.PackageSHA256)
	if err != nil {
		return nil, err
	}
	if in.Key == nil {
		// Prepared while the key was unavailable: pin it now, durably,
		// before anything is signed with it.
		signer, secret, err := r.loadSigningKey(ctx, in)
		if err != nil {
			return nil, err
		}
		in.Key = pinnedKey(signer.PublicKey(), secret, r.now())
		run.Status.SigningIntent = in
		if err := r.Client.Status().Update(ctx, run); err != nil {
			in.Key = nil
			return nil, err
		}
	}
	pub, err := evidencesign.ParsePublicKey([]byte(in.Key.PublicKey))
	if err != nil || pub.Fingerprint != in.Key.Fingerprint {
		return nil, signingError("the intent's public key does not match its fingerprint")
	}
	req := &publication.Signing{Mode: publication.SigningRequired, PublicKeyPEM: pub.PEM, KeyFingerprint: pub.Fingerprint}
	// Recover first: a stored signature needs no private key.
	bundle, _, err := store.ReadSignature(ctx, staged.Run)
	switch {
	case err == nil:
		if _, verr := evidencesign.Verify(bundle, digest, pub); verr != nil {
			return nil, signingError("the stored signature does not verify for this archive under %s: %v", pub.Fingerprint, verr)
		}
		return req, nil
	case !errors.Is(err, publication.ErrNotFound):
		return nil, err
	}
	// Signing and the signature upload are fenced work of the pinned
	// destination: after an orphan handoff no new upload starts, one in
	// flight is cancelled, and one that does not stop in time is reported
	// as an uncertain operation in the handoff inventory.
	if pin := run.Status.Destination; pin != nil && r.Runtime.Destinations != nil {
		fenced, done, err := r.Runtime.Destinations.Begin(ctx, pin.UID, "run "+run.Name+" signature upload")
		if err != nil {
			return nil, err
		}
		defer done()
		ctx = fenced
	}
	signer, _, err := r.loadSigningKey(ctx, in)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(ctx, digest)
	if err != nil {
		return nil, signingError("%v", err)
	}
	stored, _, err := store.StoreSignature(ctx, staged.Run, sig.Bundle)
	if err != nil {
		return nil, err
	}
	// Another attempt may have stored first: its bundle is the one used,
	// and it must verify under the same pinned key.
	if _, err := evidencesign.Verify(stored, digest, pub); err != nil {
		return nil, signingError("the stored signature does not verify for this archive under %s: %v", pub.Fingerprint, err)
	}
	return req, nil
}

// DefaultRetention is the binding default retention (bindingDurations),
// used for a signing failure whose run recorded none at closure.
const DefaultRetention = 2160 * time.Hour

// retainAfterSigningFailure records, on a run that ends with SigningFailed,
// the frozen package it keeps: the staged archive (and any stored
// signature) stays in storage with the run until the run's retention
// expiry, counted as a retained package of its destination, and is removed
// only by that retention deletion (or an orphan handoff). It is never
// abandoned-attempt cleanup, so a signing failure never costs evidence; the
// signing intent stays recorded for an authorized recovery.
func retainAfterSigningFailure(run *v1alpha1.AssessmentRun, msg string, now time.Time) {
	in := run.Status.SigningIntent
	if in == nil || run.Status.Publication != nil {
		return
	}
	closed := now
	if w := run.Status.Window; w != nil && w.Closed != nil {
		closed = w.Closed.Time
	}
	retention, err := time.ParseDuration(string(run.Status.Retention))
	if err != nil || retention <= 0 {
		retention = DefaultRetention
	}
	expires := metav1.NewTime(closed.Add(retention))
	pub := &v1alpha1.PublicationStatus{
		Phase:            v1alpha1.PublicationPhase(publication.PhaseFailed),
		PublicationID:    publication.RunRef{ClusterID: scopeCluster(run), BindingUID: bindingUID(run), RunUID: string(run.UID)}.PublicationID(),
		DescriptorSHA256: run.Status.DescriptorSHA256, PackageSHA256: in.ArchiveSHA256,
		ExpiresAt: &expires, Availability: v1alpha1.Availability(publication.AvailabilityUnavailable),
		Cleanup: v1alpha1.PublicationCleanup{State: v1alpha1.CleanupState(publication.CleanupNotDue),
			Message: "staged evidence is retained with the run until its retention expiry after the signing failure"},
		Failure: &v1alpha1.PublicationFailure{Reason: v1alpha1.ReasonSigningFailed, Message: truncateStatus(msg), Retryable: true, At: metav1.NewTime(now)},
	}
	if pin := run.Status.Destination; pin != nil {
		pub.Destination = &v1alpha1.PublicationDestination{ID: pin.UID, Endpoint: pin.Endpoint, Bucket: pin.Bucket, Prefix: pin.Prefix}
	}
	run.Status.Publication = pub
}

// retainedSigningFailure reports whether a terminal run keeps staged
// evidence after a signing failure.
func retainedSigningFailure(run *v1alpha1.AssessmentRun) bool {
	pub := run.Status.Publication
	return run.Status.Phase == v1alpha1.RunFailed && pub != nil && pub.Commit == nil && pub.Failure != nil && pub.Failure.Reason == v1alpha1.ReasonSigningFailed
}

func scopeCluster(run *v1alpha1.AssessmentRun) string {
	if run.Status.Scope != nil {
		return run.Status.Scope.ClusterID
	}
	return ""
}

func bindingUID(run *v1alpha1.AssessmentRun) string {
	if run.Status.Binding != nil {
		return run.Status.Binding.UID
	}
	return ""
}

func truncateStatus(s string) string {
	if len(s) > publication.MaxMessageLength {
		return s[:publication.MaxMessageLength-3] + "..."
	}
	return s
}
