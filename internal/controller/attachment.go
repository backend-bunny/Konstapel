package controller

// EvidenceAttachment reconciliation (add-supporting-evidence-attachments
// 1.1-1.2, 4.1-4.2): the retention finalizer and four separately reconciled
// states. There is no combined verdict.
//
//   - Association. Admission records the registrant and the CRD keeps the
//     spec immutable; this reconciler resolves each association before it
//     applies. An association is Valid only when the named binding still
//     has the registered UID, has resolved a profile revision, and that
//     revision's verified bundle content has the registered catalog digest
//     and selects every referenced control in its baseline, with every
//     statement a statement part of its control. A recreated binding, a
//     changed catalog, or a control that leaves the baseline makes it
//     Mismatched; it is never re-pointed. While the binding or its content
//     is still resolving it is Pending. The binding's resolved revision is
//     what it enforces, so a binding edit or a newer revision of the same
//     profile content (reporting-only, policy-parameter or exception-setting
//     edits) leaves the association as it was; a revision with other content
//     is validated once the binding resolves it. Associations never change a
//     binding, its enforcement, or its assessments.
//   - Validity. validFrom <= now < validUntil, from the immutable spec and
//     the controller clock only; the reconciler requeues at the next
//     declared boundary, so expiry needs no other event.
//   - Content. Pending until a commitment is known; then Available while
//     the committed version is present and intact, Unavailable when it is
//     missing, damaged, unreachable, handed off, or past its source expiry
//     (attachment_storage.go).
//   - Withdrawal. Deleting a record withdraws it at once and permanently
//     (status.withdrawal). The retention finalizer then keeps the record
//     until owned source cleanup is confirmed (attachment_storage.go): a
//     record that never pinned a destination owns no bytes and is released
//     immediately. Associations are kept as last resolved.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
	"github.com/backend-bunny/Konstapel/internal/coverage"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// +kubebuilder:rbac:groups=compliance.erenius.io,resources=evidenceattachments,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=evidenceattachments/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=evidenceattachments/finalizers,verbs=update

// AttachmentBindingIndex indexes EvidenceAttachments by associated binding name.
const AttachmentBindingIndex = "spec.associations.binding.name"

// attachmentPendingRequeue re-checks pending associations whose binding or
// content is still resolving even without a watch event.
const attachmentPendingRequeue = time.Minute

// BaselineSource resolves the catalog and selected baseline of bundle content.
type BaselineSource interface {
	Baseline(ctx context.Context, ref v1alpha1.BundleReference) (*attachments.Baseline, error)
}

// AttachmentReconciler reconciles EvidenceAttachments.
type AttachmentReconciler struct {
	Client    client.Client
	Baselines BaselineSource
	// Storage pins destinations and records commitments; nil pins nothing.
	Storage *AttachmentStorage
	// Now is the controller clock for validity, content and cleanup
	// decisions (default: Storage's clock, else time.Now).
	Now func() time.Time
}

func (r *AttachmentReconciler) now() time.Time {
	switch {
	case r.Now != nil:
		return r.Now()
	case r.Storage != nil:
		return r.Storage.now()
	}
	return time.Now()
}

// soonest returns the shortest positive wait (zero when none is positive).
func soonest(waits ...time.Duration) time.Duration {
	var out time.Duration
	for _, w := range waits {
		if w > 0 && (out == 0 || w < out) {
			out = w
		}
	}
	return out
}

// setValidity records the declared validity at now and returns the wait
// until its next boundary (zero once expired), capped so a long period is
// still re-evaluated periodically.
func setValidity(status *v1alpha1.EvidenceAttachmentStatus, v v1alpha1.AttachmentValidity, now time.Time) time.Duration {
	state, next := attachments.Temporal(v, now)
	vs := &v1alpha1.AttachmentValidityStatus{State: state}
	if next.IsZero() {
		status.Validity = vs
		return 0
	}
	t := metav1.NewTime(next)
	vs.NextTransition = &t
	status.Validity = vs
	return min(next.Sub(now), MaxRetentionRequeue)
}

func (r *AttachmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	a := &v1alpha1.EvidenceAttachment{}
	if err := r.Client.Get(ctx, req.NamespacedName, a); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	now := r.now()
	if !a.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, a, now)
	}
	if !controllerutil.ContainsFinalizer(a, v1alpha1.EvidenceAttachmentFinalizer) {
		base := a.DeepCopy()
		controllerutil.AddFinalizer(a, v1alpha1.EvidenceAttachmentFinalizer)
		if err := r.Client.Patch(ctx, a, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
			return ctrl.Result{}, err
		}
	}
	status := a.Status.DeepCopy()
	status.ObservedGeneration = a.Generation
	status.Associations = make([]v1alpha1.AttachmentAssociationStatus, 0, len(a.Spec.Associations))
	pending, mismatched := 0, 0
	for _, as := range a.Spec.Associations {
		s, err := r.resolve(ctx, as)
		if err != nil {
			return ctrl.Result{}, err
		}
		switch s.State {
		case v1alpha1.AssociationPending:
			pending++
		case v1alpha1.AssociationMismatched:
			mismatched++
		}
		status.Associations = append(status.Associations, s)
	}
	cond := metav1.Condition{Type: v1alpha1.ConditionAssociationsValid, ObservedGeneration: a.Generation}
	switch {
	case mismatched > 0:
		cond.Status, cond.Reason = metav1.ConditionFalse, v1alpha1.ReasonAssociationMismatch
		cond.Message = fmt.Sprintf("%d of %d associations do not apply; register a new EvidenceAttachment to correct them", mismatched, len(a.Spec.Associations))
	case pending > 0:
		cond.Status, cond.Reason = metav1.ConditionUnknown, v1alpha1.ReasonAssociationPending
		cond.Message = fmt.Sprintf("%d of %d associations are waiting for their binding or its content to resolve", pending, len(a.Spec.Associations))
	default:
		cond.Status, cond.Reason = metav1.ConditionTrue, v1alpha1.ReasonAssociationsValid
		cond.Message = "every association applies to its binding's current catalog and selected baseline; this is supporting material, not a control verdict"
	}
	meta.SetStatusCondition(&status.Conditions, cond)
	validityWait := setValidity(status, a.Spec.Validity, now)
	var storageRequeue time.Duration
	if r.Storage != nil {
		var err error
		if storageRequeue, err = r.Storage.reconcile(ctx, r.Client, a, status, now); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		setContent(status, v1alpha1.ContentPending, v1alpha1.ReasonNoDestination, "attachment storage is not configured; nothing can be stored", now)
	}
	if !equality.Semantic.DeepEqual(status, &a.Status) {
		base := a.DeepCopy()
		a.Status = *status
		if err := r.Client.Status().Patch(ctx, a, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
			return ctrl.Result{}, err
		}
	}
	pendingWait := time.Duration(0)
	if pending > 0 {
		pendingWait = attachmentPendingRequeue
	}
	return ctrl.Result{RequeueAfter: soonest(storageRequeue, pendingWait, validityWait)}, nil
}

// resolve validates one association. Only API errors other than NotFound are
// returned; every other outcome is a state.
func (r *AttachmentReconciler) resolve(ctx context.Context, as v1alpha1.AttachmentAssociation) (v1alpha1.AttachmentAssociationStatus, error) {
	s := v1alpha1.AttachmentAssociationStatus{Binding: as.Binding}
	set := func(state v1alpha1.AssociationState, reason, msg string) (v1alpha1.AttachmentAssociationStatus, error) {
		s.State, s.Reason, s.Message = state, reason, truncateMsg(msg)
		return s, nil
	}
	b := &v1alpha1.ComplianceBinding{}
	switch err := r.Client.Get(ctx, client.ObjectKey{Name: as.Binding.Name}, b); {
	case apierrors.IsNotFound(err):
		// UIDs are never reused: the registered binding is gone for good.
		return set(v1alpha1.AssociationMismatched, v1alpha1.ReasonBindingNotFound,
			fmt.Sprintf("binding %s (UID %s) does not exist", as.Binding.Name, as.Binding.UID))
	case err != nil:
		return s, err
	}
	if string(b.UID) != as.Binding.UID {
		return set(v1alpha1.AssociationMismatched, v1alpha1.ReasonBindingReplaced,
			fmt.Sprintf("binding %s was recreated (UID %s, registered %s); associations are never inherited", b.Name, b.UID, as.Binding.UID))
	}
	// The binding's resolved profile revision is the content it enforces;
	// an unobserved binding edit leaves that revision in force.
	resolved := meta.FindStatusCondition(b.Status.Conditions, v1alpha1.ConditionResolved)
	if b.Status.Profile == nil || resolved == nil || resolved.Status != metav1.ConditionTrue {
		return set(v1alpha1.AssociationPending, v1alpha1.ReasonBindingUnresolved,
			fmt.Sprintf("binding %s has not resolved a profile", b.Name))
	}
	p := &v1alpha1.ComplianceProfile{}
	switch err := r.Client.Get(ctx, client.ObjectKey{Name: b.Status.Profile.Name}, p); {
	case apierrors.IsNotFound(err):
		return set(v1alpha1.AssociationPending, v1alpha1.ReasonBindingUnresolved,
			fmt.Sprintf("profile %s of binding %s does not exist", b.Status.Profile.Name, b.Name))
	case err != nil:
		return s, err
	}
	// The resolved revision's content is identified by its bundle digest. A
	// newer revision of the same profile with the same digest (a
	// policy-parameter or exception-setting edit) selects the same catalog
	// and baseline; other content is validated once the binding resolves it.
	if p.UID != b.Status.Profile.UID || p.Spec.Bundle.Digest != b.Status.Profile.BundleDigest {
		return set(v1alpha1.AssociationPending, v1alpha1.ReasonBindingUnresolved,
			fmt.Sprintf("binding %s is resolving changed content of profile %s", b.Name, p.Name))
	}
	base, err := r.Baselines.Baseline(ctx, p.Spec.Bundle)
	if err != nil {
		if ctx.Err() != nil {
			return s, ctx.Err()
		}
		return set(v1alpha1.AssociationPending, v1alpha1.ReasonBaselineUnavailable,
			fmt.Sprintf("catalog and baseline of %s@%s are unavailable: %v", p.Spec.Bundle.Name, p.Spec.Bundle.Digest, err))
	}
	s.ObservedCatalogDigest = base.CatalogDigest
	if m := base.Check(as); m != nil {
		return set(v1alpha1.AssociationMismatched, m.Reason, m.Message)
	}
	return set(v1alpha1.AssociationValid, v1alpha1.ReasonAssociationsValid,
		fmt.Sprintf("applies to binding %s with catalog %s", b.Name, base.CatalogDigest))
}

// finalize records the withdrawal and releases the record once no owned
// storage remains. A record that pinned a destination is kept while storage
// is disabled. Associations are kept as last resolved.
func (r *AttachmentReconciler) finalize(ctx context.Context, a *v1alpha1.EvidenceAttachment, now time.Time) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(a, v1alpha1.EvidenceAttachmentFinalizer) {
		return ctrl.Result{}, nil
	}
	status := a.Status.DeepCopy()
	if status.Withdrawal == nil {
		status.Withdrawal = &v1alpha1.AttachmentWithdrawal{WithdrawnAt: *a.DeletionTimestamp}
	}
	validityWait := setValidity(status, a.Spec.Validity, now)
	release, requeue := true, time.Duration(0)
	pinned := a.Status.Storage != nil && a.Status.Storage.Destination != nil
	switch {
	case r.Storage != nil:
		var err error
		if release, requeue, err = r.Storage.finalize(ctx, a, status, now); err != nil {
			return ctrl.Result{}, err
		}
	case pinned:
		release, requeue = false, attachmentCleanupRetry
	}
	if !release {
		if !equality.Semantic.DeepEqual(status, &a.Status) {
			base := a.DeepCopy()
			a.Status = *status
			if err := r.Client.Status().Patch(ctx, a, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
				return ctrl.Result{}, client.IgnoreNotFound(err)
			}
		}
		return ctrl.Result{RequeueAfter: soonest(requeue, validityWait)}, nil
	}
	base := a.DeepCopy()
	controllerutil.RemoveFinalizer(a, v1alpha1.EvidenceAttachmentFinalizer)
	err := r.Client.Patch(ctx, a, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
	if err == nil && r.Storage != nil {
		r.Storage.forget(a.UID)
	}
	return ctrl.Result{}, client.IgnoreNotFound(err)
}

// attachmentsForBinding enqueues every attachment associated with a binding
// of that name, so recreation, profile resolution and deletion are noticed.
func attachmentsForBinding(c client.Client) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		var l v1alpha1.EvidenceAttachmentList
		if err := c.List(ctx, &l, client.MatchingFields{AttachmentBindingIndex: o.GetName()}); err != nil {
			return nil
		}
		out := make([]reconcile.Request, 0, len(l.Items))
		for _, a := range l.Items {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKey{Name: a.Name}})
		}
		return out
	}
}

func attachmentBindingNames(o client.Object) []string {
	a := o.(*v1alpha1.EvidenceAttachment)
	seen := map[string]bool{}
	var out []string
	for _, as := range a.Spec.Associations {
		if !seen[as.Binding.Name] {
			seen[as.Binding.Name] = true
			out = append(out, as.Binding.Name)
		}
	}
	return out
}

func setupAttachments(mgr manager.Manager, baselines BaselineSource, storage *AttachmentStorage) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.EvidenceAttachment{}, AttachmentBindingIndex, attachmentBindingNames); err != nil {
		return err
	}
	return builder.ControllerManagedBy(mgr).Named("evidenceattachment").
		For(&v1alpha1.EvidenceAttachment{}).
		// Binding status carries the resolved profile revision, so status
		// changes matter as well as recreation and deletion.
		Watches(&v1alpha1.ComplianceBinding{}, handler.EnqueueRequestsFromMapFunc(attachmentsForBinding(mgr.GetClient()))).
		Complete(&AttachmentReconciler{Client: mgr.GetClient(), Baselines: baselines, Storage: storage})
}

// ContentBaselines reads baselines from the same verified content
// assessments use, with the coverage owner's baseline reader
// (coverage.ReadBaseline): the image's vendored content tree for its own
// digest (its Moderate profile), and a frozen copy of verified OCI content
// otherwise (the bundle's declared baseline profile). Documents are checked
// against the controller's own OSCAL schemas. Content that does not resolve
// keeps associations pending. Bundle content is immutable per digest, so
// results are cached (bounded).
type ContentBaselines struct {
	// Freezer freezes OCI content; nil serves only vendored content.
	Freezer ContentFreezer
	// VendoredName is the vendored bundle's name; ContentRoot is the parent
	// of its content/ tree. Empty serves no vendored content.
	VendoredName, ContentRoot string
	// Scratch is a writable directory for frozen copies; empty serves no
	// OCI content.
	Scratch string

	mu    sync.Mutex
	cache map[string]*attachments.Baseline
}

const maxCachedBaselines = 16

func (c *ContentBaselines) Baseline(ctx context.Context, ref v1alpha1.BundleReference) (*attachments.Baseline, error) {
	key := ref.Name + "@" + ref.Digest
	c.mu.Lock()
	if b, ok := c.cache[key]; ok {
		c.mu.Unlock()
		return b, nil
	}
	c.mu.Unlock()
	b, err := c.read(ctx, ref)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil || len(c.cache) >= maxCachedBaselines {
		c.cache = map[string]*attachments.Baseline{}
	}
	c.cache[key] = b
	return b, nil
}

func (c *ContentBaselines) read(ctx context.Context, ref v1alpha1.BundleReference) (*attachments.Baseline, error) {
	if c.ContentRoot == "" {
		return nil, fmt.Errorf("%w: no content root holds the controller's trusted OSCAL schemas", targeting.ErrContentUnavailable)
	}
	if c.VendoredName != "" && ref.Name == c.VendoredName {
		content, opts, err := attachments.VendoredContent(os.DirFS(c.ContentRoot), ref.Name)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", targeting.ErrContentUnavailable, err)
		}
		if content.Bundle.Digest != ref.Digest {
			return nil, fmt.Errorf("%w: vendored content is %s, not %s; other content is never substituted", targeting.ErrContentUnavailable, content.Bundle.Digest, ref.Digest)
		}
		return attachments.ReadBaseline(content, opts)
	}
	if c.Freezer == nil || c.Scratch == "" {
		return nil, fmt.Errorf("%w: %s@%s cannot be read for attachment validation", targeting.ErrContentUnavailable, ref.Name, ref.Digest)
	}
	schemas, err := trustedOSCALSchemas(c.ContentRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: the controller's OSCAL schemas: %v", targeting.ErrContentUnavailable, err)
	}
	if err := os.MkdirAll(c.Scratch, 0o700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(c.Scratch, "baseline-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	frozen, vendored, err := c.Freezer.Freeze(ctx, ref, filepath.Join(dir, "bundle"))
	switch {
	case err != nil:
		return nil, err
	case vendored || frozen == nil:
		return nil, fmt.Errorf("%w: %s@%s is not frozen OCI content", targeting.ErrContentUnavailable, ref.Name, ref.Digest)
	}
	content, err := coverage.FromFrozen(frozen)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", targeting.ErrContentUnavailable, err)
	}
	// The bundle's single declared baseline profile entry point.
	return attachments.ReadBaseline(content, coverage.Options{Schemas: schemas})
}

// attachmentBaselines validates associations against the manager's content
// source: the vendored tree under the assessment runtime's content root, and
// frozen OCI content in a scratch directory under its staging directory.
// Without either, associations to that content stay pending.
func attachmentBaselines(src targeting.ContentSource, rt AssessmentRuntime) *ContentBaselines {
	b := &ContentBaselines{Freezer: freezerFor(src), VendoredName: vendoredName(src), ContentRoot: rt.ContentRoot}
	if rt.StagingDir != "" {
		b.Scratch = filepath.Join(rt.StagingDir, "attachment-baselines")
	}
	return b
}
