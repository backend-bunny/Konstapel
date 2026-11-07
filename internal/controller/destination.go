package controller

import (
	"context"
	"fmt"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"k8s.io/apimachinery/pkg/api/equality"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"strings"
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
	// DestinationProbeTimeout bounds one compatibility probe.
	DestinationProbeTimeout = 30 * time.Second
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
	// Destinations is the process's publisher registry; an accepted orphan
	// handoff fences and drains its in-flight work.
	Destinations *DestinationPublishers
	// ProbeTimeout bounds one compatibility probe (default 30s).
	ProbeTimeout time.Duration
	// DrainTimeout bounds the wait for fenced in-flight work (default 30s).
	DrainTimeout time.Duration
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
	status := ed.Status.DeepCopy()
	acceptOrphan(ed, status, r.now())
	handedOff := status.OrphanIntent != nil
	var err, inventoryErr error
	if handedOff {
		// No remote operation of any kind after an accepted handoff, not
		// even a probe.
		cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, "HandedOff", "storage responsibility was handed off to an operator; the backend is no longer contacted"
		uncertain := []string(nil)
		if r.Destinations != nil {
			wait := r.DrainTimeout
			if wait <= 0 {
				wait = 30 * time.Second
			}
			if status.OrphanHandoff != nil {
				wait = 0 // a restarted process re-fences; nothing of ours is in flight
			}
			uncertain = r.Destinations.Fence(string(ed.UID), wait)
		}
		if status.OrphanHandoff == nil {
			if len(uncertain) > 64 {
				uncertain = uncertain[:64]
			}
			status.OrphanHandoff = &v1alpha1.OrphanHandoff{FencedAt: metav1.NewTime(r.now()), Drained: len(uncertain) == 0, UncertainOperations: uncertain}
		}
		// Persist the ownership inventory before anything may be released.
		// A failure keeps the fence and every finalizer and is retried.
		if status.OrphanHandoff.Inventory == nil {
			if inv, err := r.saveOrphanInventory(ctx, ed, status); err != nil {
				inventoryErr = err
			} else {
				status.OrphanHandoff.Inventory = inv
			}
		}
	}
	d, err := DestinationFromAPI(ctx, r.Reader, r.Namespace, ed)
	if err == nil && !handedOff {
		probe := r.Probe
		if probe == nil {
			probe = ProbeDestination
		}
		// An unreachable backend must not stall the reconciler (every S3
		// request would otherwise wait out its own timeout and retries), or
		// retirement and orphan handoff could not proceed.
		timeout := r.ProbeTimeout
		if timeout <= 0 {
			timeout = DestinationProbeTimeout
		}
		pctx, cancel := context.WithTimeout(ctx, timeout)
		err = probe(pctx, d, r.Reader, r.Namespace)
		cancel()
	}
	if err != nil && !handedOff {
		cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, "NotReady", truncate(err.Error())
	}
	ob, err := r.obligations(ctx, ed)
	if err != nil {
		return ctrl.Result{}, err
	}
	status.ObservedGeneration = ed.Generation
	meta.SetStatusCondition(&status.Conditions, cond)
	ob.apply(status)
	if !ed.DeletionTimestamp.IsZero() {
		meta.SetStatusCondition(&status.Conditions, ob.retiring(ed, status))
	}
	if inventoryErr != nil {
		meta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: v1alpha1.ConditionDestinationRetiring, Status: metav1.ConditionTrue,
			Reason: "OrphanInventoryPending", Message: truncate("the orphan inventory could not be saved; the fence and finalizers remain: " + inventoryErr.Error()), ObservedGeneration: ed.Generation})
	}
	if !equality.Semantic.DeepEqual(&ed.Status, status) {
		ed.Status = *status
		if err := r.Client.Status().Update(ctx, ed); err != nil {
			return ctrl.Result{}, err
		}
	}
	if inventoryErr != nil {
		return ctrl.Result{RequeueAfter: AttemptCleanupRetry}, nil
	}
	// Retirement finishes only when no accepted run, upload, retained
	// package, or cleanup still needs this destination. The count comes
	// from an uncached list of runs labelled with its UID, so a pin accepted
	// before deletion (labelled before the finalizer was confirmed) is seen.
	if !ed.DeletionTimestamp.IsZero() && ob.empty() && controllerutil.ContainsFinalizer(ed, DestinationFinalizer) {
		controllerutil.RemoveFinalizer(ed, DestinationFinalizer)
		if err := r.Client.Update(ctx, ed); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	return ctrl.Result{RequeueAfter: DestinationProbeInterval}, nil
}

// acceptOrphan records the orphan handoff once, when a destination with
// deletionPolicy Orphan is deleted. The request's actor must have been
// recorded by admission; without it nothing is accepted. An accepted intent
// is never changed or cleared.
func acceptOrphan(ed *v1alpha1.EvidenceDestination, status *v1alpha1.EvidenceDestinationStatus, now time.Time) {
	o := ed.Spec.Orphan
	if status.OrphanIntent != nil || ed.DeletionTimestamp.IsZero() || ed.Spec.DeletionPolicy != v1alpha1.DeletionOrphan || o == nil || o.Actor == "" || strings.TrimSpace(o.Reason) == "" {
		return
	}
	status.OrphanIntent = &v1alpha1.OrphanIntent{Reason: o.Reason, Actor: o.Actor, ActorUID: o.ActorUID, AcceptedAt: metav1.NewTime(now)}
}

func (r *DestinationReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// obligations are what a destination still owes its pinned runs.
type obligations struct {
	runs, packages, unknownExpiry, cleanup int32
	latest                                 *metav1.Time
	blockers                               []string
}

func (o obligations) empty() bool {
	return o.runs == 0 && o.packages == 0 && o.cleanup == 0
}

func (o obligations) apply(s *v1alpha1.EvidenceDestinationStatus) {
	s.OutstandingRuns, s.OutstandingPackages, s.UnknownExpiryRuns = o.runs, o.packages, o.unknownExpiry
	s.LatestRetainedExpiry, s.CleanupBlockers = o.latest, o.blockers
}

func (o obligations) retiring(ed *v1alpha1.EvidenceDestination, status *v1alpha1.EvidenceDestinationStatus) metav1.Condition {
	c := metav1.Condition{Type: v1alpha1.ConditionDestinationRetiring, Status: metav1.ConditionTrue, ObservedGeneration: ed.Generation}
	note := ""
	switch {
	case status.OrphanIntent != nil:
		note = " (orphan handoff accepted for " + status.OrphanIntent.Actor + "; fencing and inventory are not available yet, so it retires normally)"
	case ed.Spec.DeletionPolicy == v1alpha1.DeletionOrphan:
		note = " (orphan request has no admission-recorded actor and is not accepted; install the konstapel-destination-orphan admission policy)"
	}
	switch {
	case o.empty():
		c.Reason, c.Message = "Retired", "no outstanding runs, packages, or cleanup"+note
	case len(o.blockers) > 0:
		c.Reason = "RetirementBlocked"
		c.Message = truncate(fmt.Sprintf("%d runs, %d packages, %d cleanups outstanding (%d with unknown expiry); blocked: %s%s", o.runs, o.packages, o.cleanup, o.unknownExpiry, o.blockers[0], note))
	default:
		c.Reason = "Retiring"
		c.Message = truncate(fmt.Sprintf("waiting for %d runs, %d packages, %d cleanups (%d with unknown expiry)%s", o.runs, o.packages, o.cleanup, o.unknownExpiry, note))
	}
	return c
}

// obligations counts the destination's outstanding work from the runs that
// recorded it as their pin. A run still starting (labelled, not yet pinned)
// is outstanding: it may still be accepted. Unfinished publication has no
// known expiry and is never treated as an empty destination.
func (r *DestinationReconciler) obligations(ctx context.Context, ed *v1alpha1.EvidenceDestination) (obligations, error) {
	var runs v1alpha1.AssessmentRunList
	if err := r.Reader.List(ctx, &runs, client.MatchingLabels{LabelRunDestination: string(ed.UID)}); err != nil {
		return obligations{}, err
	}
	var o obligations
	block := func(run, msg string) {
		if len(o.blockers) < 16 {
			o.blockers = append(o.blockers, truncate(run+": "+msg))
		}
	}
	for i := range runs.Items {
		run := &runs.Items[i]
		if pin := run.Status.Destination; pin != nil && pin.OrphanedAt != nil {
			continue // handed off: recorded in the inventory, owned by an operator
		}
		pub := run.Status.Publication
		switch {
		case !runDone(run):
			o.runs++
			o.unknownExpiry++
		case run.Status.Phase == v1alpha1.RunCompleted && pub != nil && pub.Cleanup.State != v1alpha1.CleanupState(publication.CleanupDeleted):
			o.packages++
			if pub.ExpiresAt != nil && (o.latest == nil || pub.ExpiresAt.After(o.latest.Time)) {
				t := *pub.ExpiresAt
				o.latest = &t
			}
			if pub.Cleanup.State == v1alpha1.CleanupState(publication.CleanupRetentionBlocked) || pub.Cleanup.State == v1alpha1.CleanupState(publication.CleanupDeletionFailed) {
				block(run.Name, string(pub.Cleanup.State)+": "+pub.Cleanup.Message)
			}
		case controllerutil.ContainsFinalizer(run, RetentionFinalizer):
			// Terminal without a retained package, but attempt cleanup or
			// release is still pending.
			o.cleanup++
			if c := meta.FindStatusCondition(run.Status.Conditions, v1alpha1.ConditionAttemptsCleaned); c != nil && c.Status == metav1.ConditionFalse {
				block(run.Name, c.Reason+": "+c.Message)
			}
		}
	}
	return o, nil
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
