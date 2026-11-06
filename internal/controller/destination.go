package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// The controller probes destinations with credentials and CA trust from its
// own namespace, and reads the central default from a ConfigMap there.
// +kubebuilder:rbac:groups="",namespace=konstapel-system,resources=configmaps,verbs=get

const (
	// DefaultDestinationConfigMap in the controller namespace holds the
	// central default evidence destination reference. Only platform
	// administrators may write it. Editing it affects subsequent runs only.
	DefaultDestinationConfigMap = "konstapel-evidence-destination"
	// DefaultDestinationNameKey and DefaultDestinationUIDKey are its keys.
	DefaultDestinationNameKey = "defaultDestinationName"
	DefaultDestinationUIDKey  = "defaultDestinationUID"
	// DestinationProbeInterval is how often a destination's backend is
	// re-probed while nothing changes.
	DestinationProbeInterval = 5 * time.Minute
)

// controllerNamespace is where credentials, trust, and the default live.
func controllerNamespace(ns string) string {
	if ns == "" {
		return "konstapel-system"
	}
	return ns
}

// DestinationFromAPI converts an EvidenceDestination into the S3 adapter's
// destination, reading CA trust from the controller namespace. The
// destination's UID is its stable identity.
func DestinationFromAPI(ctx context.Context, r client.Reader, namespace string, ed *v1alpha1.EvidenceDestination) (s3store.Destination, error) {
	s := ed.Spec.S3
	d := s3store.Destination{ID: string(ed.UID), Endpoint: s.Endpoint, Bucket: s.Bucket, Region: s.Region, Prefix: s.Prefix,
		Addressing: s3store.Addressing(s.Addressing), WorkloadIdentity: s.WorkloadIdentity, DevelopmentFixture: s.DevelopmentFixture}
	if d.Addressing == "" {
		d.Addressing = s3store.AddressingPath
	}
	if s.CredentialSecret != nil {
		d.CredentialSecret = &s3store.SecretRef{Name: s.CredentialSecret.Name, AccessKeyIDKey: s.CredentialSecret.AccessKeyIDKey, SecretAccessKeyKey: s.CredentialSecret.SecretAccessKeyKey}
	}
	if s.CATrust != nil {
		cm := &corev1.ConfigMap{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: controllerNamespace(namespace), Name: s.CATrust.Name}, cm); err != nil {
			return d, fmt.Errorf("CA trust ConfigMap %s: %w", s.CATrust.Name, err)
		}
		key := s.CATrust.Key
		if key == "" {
			key = "ca.crt"
		}
		pem, ok := cm.Data[key]
		if !ok || pem == "" {
			return d, fmt.Errorf("CA trust ConfigMap %s has no key %s", s.CATrust.Name, key)
		}
		d.CAPEM = []byte(pem)
	}
	return d, d.Validate()
}

// DestinationReconciler probes each EvidenceDestination's backend and
// records readiness. It never moves or deletes evidence.
type DestinationReconciler struct {
	Client    client.Client
	Reader    client.Reader // uncached: Secrets and ConfigMaps in the controller namespace
	Namespace string
	Now       func() time.Time
	// Probe checks a destination; tests replace it.
	Probe func(ctx context.Context, d s3store.Destination, r client.Reader, namespace string) error
}

// ProbeDestination builds a publisher with the destination's current
// credentials and trust and runs the compatibility probe.
func ProbeDestination(ctx context.Context, d s3store.Destination, r client.Reader, namespace string) error {
	p, err := s3store.NewPublisher(ctx, d, r, controllerNamespace(namespace))
	if err != nil {
		return err
	}
	_, err = p.Ready(ctx)
	return err
}

func (r *DestinationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ed := &v1alpha1.EvidenceDestination{}
	if err := r.Client.Get(ctx, req.NamespacedName, ed); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	cond := metav1.Condition{Type: v1alpha1.ConditionDestinationReady, Status: metav1.ConditionTrue, Reason: "Ready", Message: "backend passed the compatibility probe", ObservedGeneration: ed.Generation}
	d, err := DestinationFromAPI(ctx, r.Reader, r.Namespace, ed)
	if err == nil {
		probe := r.Probe
		if probe == nil {
			probe = ProbeDestination
		}
		err = probe(ctx, d, r.Reader, r.Namespace)
	}
	if err != nil {
		cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, "NotReady", truncate(err.Error())
	}
	old := meta.FindStatusCondition(ed.Status.Conditions, cond.Type)
	if ed.Status.ObservedGeneration != ed.Generation || old == nil || old.Status != cond.Status || old.Message != cond.Message || old.ObservedGeneration != cond.ObservedGeneration {
		ed.Status.ObservedGeneration = ed.Generation
		meta.SetStatusCondition(&ed.Status.Conditions, cond)
		if err := r.Client.Status().Update(ctx, ed); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: DestinationProbeInterval}, nil
}

// selectDestination resolves a binding's evidence destination: its own
// spec.assessment.destinationRef, otherwise the central default. A missing,
// replaced (UID mismatch), retiring, or unready destination is reported with
// its reason and never replaced by another destination.
func selectDestination(ctx context.Context, r client.Reader, namespace string, b *v1alpha1.ComplianceBinding) *v1alpha1.DestinationSelection {
	sel := &v1alpha1.DestinationSelection{Source: v1alpha1.DestinationFromBinding}
	if b.Spec.Assessment != nil && b.Spec.Assessment.DestinationRef != nil {
		ref := *b.Spec.Assessment.DestinationRef
		sel.Ref = &ref
	} else {
		sel.Source = v1alpha1.DestinationFromDefault
		cm := &corev1.ConfigMap{}
		err := r.Get(ctx, client.ObjectKey{Namespace: controllerNamespace(namespace), Name: DefaultDestinationConfigMap}, cm)
		switch {
		case apierrors.IsNotFound(err):
			sel.Source, sel.Reason, sel.Message = v1alpha1.DestinationNone, v1alpha1.ReasonNoDefaultDestination, "no default evidence destination is configured and the binding selects none"
			return sel
		case err != nil:
			sel.Reason, sel.Message = v1alpha1.ReasonInvalidDefault, truncate("default destination configuration: "+err.Error())
			return sel
		}
		name, uid := cm.Data[DefaultDestinationNameKey], cm.Data[DefaultDestinationUIDKey]
		if name == "" || uid == "" {
			sel.Reason, sel.Message = v1alpha1.ReasonInvalidDefault, fmt.Sprintf("ConfigMap %s needs both %s and %s", DefaultDestinationConfigMap, DefaultDestinationNameKey, DefaultDestinationUIDKey)
			return sel
		}
		sel.Ref = &v1alpha1.DestinationReference{Name: name, UID: uid}
	}
	ed := &v1alpha1.EvidenceDestination{}
	err := r.Get(ctx, client.ObjectKey{Name: sel.Ref.Name}, ed)
	switch {
	case apierrors.IsNotFound(err):
		sel.Reason, sel.Message = v1alpha1.ReasonDestinationNotFound, "EvidenceDestination "+sel.Ref.Name+" does not exist"
	case err != nil:
		sel.Reason, sel.Message = v1alpha1.ReasonDestinationNotReady, truncate(err.Error())
	case string(ed.UID) != sel.Ref.UID:
		sel.Reason, sel.Message = v1alpha1.ReasonDestinationUIDMismatch, "EvidenceDestination "+sel.Ref.Name+" was replaced (different UID); the replacement is never selected implicitly"
	case !ed.DeletionTimestamp.IsZero():
		sel.Reason, sel.Message = v1alpha1.ReasonDestinationRetiring, "EvidenceDestination "+sel.Ref.Name+" is retiring and accepts no new runs"
	case !meta.IsStatusConditionTrue(ed.Status.Conditions, v1alpha1.ConditionDestinationReady):
		sel.Reason, sel.Message = v1alpha1.ReasonDestinationNotReady, "EvidenceDestination "+sel.Ref.Name+" is not ready"
		if c := meta.FindStatusCondition(ed.Status.Conditions, v1alpha1.ConditionDestinationReady); c != nil && c.Message != "" {
			sel.Message = truncate(sel.Message + ": " + c.Message)
		}
	default:
		sel.Ready, sel.Reason, sel.Message = true, v1alpha1.ReasonDestinationSelected, ""
	}
	return sel
}
