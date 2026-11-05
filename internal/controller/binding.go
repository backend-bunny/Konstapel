// Package controller runs the targeting reconcilers: it resolves
// ComplianceProfiles and ComplianceBindings, delivers engine policies through
// internal/targeting, and reports status. Konstapel does not evaluate
// workload admission itself; the engine does.
package controller

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Condition reasons added by the controller.
const (
	ReasonEngineUnavailable = "EngineUnavailable"
	ReasonEngineReady       = "Ready"
	ReasonNoContributions   = "NoContributions"
)

// TransitionRequeue is how often a binding is re-checked while engine
// policies are not ready, are being replaced, or the engine is unavailable.
const TransitionRequeue = 5 * time.Second

// maxMessage bounds condition messages so status stays small.
const maxMessage = 1024

// EngineAvailable reports whether the engine API is served. It is checked on
// every reconcile so a late or returning engine is picked up without restart.
type EngineAvailable func(context.Context) (bool, error)

// RBAC for the targeting reconcilers (controller-gen reads package-level markers).
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=compliancebindings;complianceprofiles,verbs=get;list;watch
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=compliancebindings/status;complianceprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=policies.kyverno.io,resources=validatingpolicies,verbs=get;list;watch;create;update;patch;delete

// BindingReconciler converges one ComplianceBinding's engine policies and status.
type BindingReconciler struct {
	Client  client.Client
	Reader  client.Reader // uncached reads of engine policies; defaults to Client
	Content targeting.ContentSource
	Engine  EngineAvailable
	Cluster string // assessment-loop cluster identity, "kube-system:<uid>"
	Ready   targeting.ReadyFunc
}

func (r *BindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	b := &v1alpha1.ComplianceBinding{}
	if err := r.Client.Get(ctx, req.NamespacedName, b); err != nil {
		// A deleted binding's engine policies carry its controller owner
		// reference, so the garbage collector removes them, including
		// superseded revisions, and nothing else.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !b.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	in, profile, err := r.input(ctx, b)
	if err != nil {
		return ctrl.Result{}, err
	}
	res := targeting.Resolve(in)
	var br targeting.BindingResult
	for _, x := range res.Bindings {
		if x.Binding.UID == b.UID {
			br = x
		}
	}

	status := v1alpha1.ComplianceBindingStatus{
		ObservedGeneration: b.Generation,
		TargetCount:        ptr(int32(br.TargetCount)),
		Conditions:         slices.Clone(b.Status.Conditions),
	}
	if profile != nil {
		status.Profile = &v1alpha1.ResolvedProfile{Name: profile.Name, UID: profile.UID, Generation: profile.Generation, BundleDigest: profile.Spec.Bundle.Digest}
	}
	resolved := metav1.Condition{Type: v1alpha1.ConditionResolved, Status: metav1.ConditionTrue, Reason: v1alpha1.ReasonResolutionSucceeded, ObservedGeneration: b.Generation,
		Message: fmt.Sprintf("%d contributions for %d namespaces", len(br.Contributions), br.TargetCount)}
	if len(br.Errors) > 0 {
		resolved.Status, resolved.Reason, resolved.Message = metav1.ConditionFalse, string(br.Errors[0].Reason), errorsMessage(br.Errors)
	}
	meta.SetStatusCondition(&status.Conditions, resolved)

	engine := metav1.Condition{Type: v1alpha1.ConditionEngineReady, ObservedGeneration: b.Generation}
	requeue := time.Duration(0)
	available, err := r.Engine(ctx)
	switch {
	case err != nil || !available:
		// Leave whatever is applied in place; it cannot be inspected or changed.
		msg := "policies.kyverno.io/v1 ValidatingPolicy is not served"
		if err != nil {
			msg = err.Error()
		}
		engine.Status, engine.Reason, engine.Message = metav1.ConditionFalse, ReasonEngineUnavailable, msg
		requeue = TransitionRequeue
	default:
		desired, hold, renderErrs := r.desired(ctx, b, br)
		reader := r.Reader
		if reader == nil {
			reader = r.Client
		}
		d := &targeting.Delivery{Client: readThrough{Client: r.Client, reader: reader}, Ready: r.Ready}
		sync, err := d.Sync(ctx, b.UID, desired, hold)
		if err != nil {
			return ctrl.Result{}, err
		}
		status.ConfigurationRevision = revisionSummary(br.Contributions)
		engine.Status, engine.Reason, engine.Message, requeue = engineCondition(sync, len(desired), len(br.Errors)+len(renderErrs) > 0, br.TargetCount)
		if len(renderErrs) > 0 {
			resolved.Status, resolved.Reason, resolved.Message = metav1.ConditionFalse, v1alpha1.ReasonInvalidConfiguration, truncate(strings.Join(renderErrs, "; "))
			meta.SetStatusCondition(&status.Conditions, resolved)
		}
		logger.V(1).Info("synced", "current", sync.Current, "notReady", sync.NotReady, "retained", sync.Retained, "removed", sync.Removed, "conflicts", sync.Conflicts)
	}
	meta.SetStatusCondition(&status.Conditions, engine)

	if !equality.Semantic.DeepEqual(b.Status, status) {
		b.Status = status
		if err := r.Client.Status().Update(ctx, b); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

// input builds the resolver snapshot for one binding: its profile, that
// profile's content and every namespace.
func (r *BindingReconciler) input(ctx context.Context, b *v1alpha1.ComplianceBinding) (targeting.Input, *v1alpha1.ComplianceProfile, error) {
	in := targeting.Input{Cluster: r.Cluster, Bindings: []v1alpha1.ComplianceBinding{*b}}
	var nss corev1.NamespaceList
	if err := r.Client.List(ctx, &nss); err != nil {
		return in, nil, err
	}
	for _, ns := range nss.Items {
		if ns.DeletionTimestamp.IsZero() {
			in.Namespaces = append(in.Namespaces, targeting.Namespace{Name: ns.Name, UID: ns.UID, Labels: ns.Labels})
		}
	}
	p := &v1alpha1.ComplianceProfile{}
	err := r.Client.Get(ctx, client.ObjectKey{Name: b.Spec.ProfileRef.Name}, p)
	if apierrors.IsNotFound(err) {
		return in, nil, nil
	}
	if err != nil {
		return in, nil, err
	}
	in.Profiles = []v1alpha1.ComplianceProfile{*p}
	content, err := r.Content.Content(ctx, p.Spec.Bundle)
	switch {
	case errors.Is(err, targeting.ErrContentUnavailable):
		// The resolver reports ContentUnavailable for a missing bundle.
	case err != nil:
		return in, p, err
	default:
		in.Bundles = []targeting.Bundle{content.Bundle}
	}
	return in, p, nil
}

// desired renders the binding's contributions. Policies that failed to
// resolve or render are held: what is applied for them stays in place. A
// binding-level error holds everything the binding currently owns.
func (r *BindingReconciler) desired(ctx context.Context, b *v1alpha1.ComplianceBinding, br targeting.BindingResult) ([]*unstructured.Unstructured, []string, []string) {
	var hold, renderErrs []string
	bindingLevel := false
	for _, e := range br.Errors {
		if e.Policy == "" {
			bindingLevel = true
		} else {
			hold = append(hold, e.Policy)
		}
	}
	if bindingLevel {
		return nil, r.ownedPolicies(ctx, b.UID), nil
	}
	var content *targeting.Content
	if len(br.Contributions) > 0 {
		c, err := r.Content.Content(ctx, v1alpha1.BundleReference{Name: br.Contributions[0].BundleName, Digest: br.Contributions[0].BundleDigest})
		if err != nil {
			return nil, r.ownedPolicies(ctx, b.UID), []string{err.Error()}
		}
		content = c
	}
	var desired []*unstructured.Unstructured
	for _, c := range br.Contributions {
		obj, err := targeting.Render(c, content.Policies[c.Policy])
		if err != nil {
			hold = append(hold, c.Policy)
			renderErrs = append(renderErrs, err.Error())
			continue
		}
		desired = append(desired, obj)
	}
	return desired, hold, renderErrs
}

// ownedPolicies lists the logical policies the binding currently has applied.
func (r *BindingReconciler) ownedPolicies(ctx context.Context, uid types.UID) []string {
	reader := r.Reader
	if reader == nil {
		reader = r.Client
	}
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(targeting.ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
	if err := reader.List(ctx, list, client.MatchingLabels{targeting.LabelManagedBy: targeting.ManagedByValue, targeting.LabelBindingUID: string(uid)}); err != nil {
		return nil
	}
	var out []string
	for _, o := range list.Items {
		if p := o.GetAnnotations()[targeting.AnnotationPolicy]; p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// engineCondition maps a delivery outcome to EngineReady. Ready means every
// desired policy is applied at the current revision and accepted by the
// engine, and nothing stale is being kept. It never asserts compliance.
func engineCondition(s targeting.DeliveryResult, desired int, unresolved bool, targets int) (metav1.ConditionStatus, string, string, time.Duration) {
	switch {
	case len(s.Conflicts) > 0:
		return metav1.ConditionFalse, v1alpha1.ReasonOwnershipConflict, truncate("unmanaged resources hold desired names: " + strings.Join(s.Conflicts, ", ")), 0
	case unresolved && len(s.Retained) > 0:
		return metav1.ConditionFalse, v1alpha1.ReasonStaleRevision, truncate("configuration did not resolve; last applied policies kept: " + strings.Join(s.Retained, ", ")), 0
	case unresolved:
		return metav1.ConditionFalse, v1alpha1.ReasonStaleRevision, "configuration did not resolve; no current policies applied", 0
	case len(s.NotReady) > 0 || len(s.Retained) > 0:
		return metav1.ConditionFalse, v1alpha1.ReasonReplacementPending, truncate(fmt.Sprintf("waiting for engine readiness: %s; retained until ready: %s", strings.Join(s.NotReady, ", "), strings.Join(s.Retained, ", "))), TransitionRequeue
	case desired == 0:
		return metav1.ConditionFalse, ReasonNoContributions, "no policies to deliver", 0
	default:
		return metav1.ConditionTrue, ReasonEngineReady, fmt.Sprintf("%d policies ready at the current revision for %d namespaces; this is not a compliance result", desired, targets), 0
	}
}

// revisionSummary identifies the full set of current contribution revisions.
func revisionSummary(cs []targeting.Contribution) string {
	if len(cs) == 0 {
		return ""
	}
	revs := make([]string, 0, len(cs))
	for _, c := range cs {
		revs = append(revs, c.Revision)
	}
	slices.Sort(revs)
	if len(revs) == 1 {
		return revs[0]
	}
	return "sha256:" + sha256Hex(strings.Join(revs, "\n"))
}

// errorsMessage explains resolution errors. A single error's reason is
// already the condition reason, so only its message is repeated.
func errorsMessage(errs []targeting.ResolutionError) string {
	if len(errs) == 1 {
		return truncate(errs[0].Message)
	}
	slices.SortFunc(errs, func(a, b targeting.ResolutionError) int { return cmp.Compare(a.Reason, b.Reason) })
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, fmt.Sprintf("%s: %s", e.Reason, e.Message))
	}
	return truncate(strings.Join(parts, "; "))
}

func truncate(s string) string {
	if len(s) <= maxMessage {
		return s
	}
	return s[:maxMessage-3] + "..."
}

func ptr[T any](v T) *T { return &v }

// readThrough sends engine-policy reads to an uncached reader, so delivery
// never needs a Kyverno informer.
type readThrough struct {
	client.Client
	reader client.Reader
}

func (r readThrough) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return r.reader.Get(ctx, key, obj, opts...)
}

func (r readThrough) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return r.reader.List(ctx, list, opts...)
}
