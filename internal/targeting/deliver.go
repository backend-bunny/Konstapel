package targeting

import (
	"context"
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FieldOwner identifies Konstapel's writes to engine policies.
const FieldOwner = client.FieldOwner("konstapel")

// ReadyFunc reports whether the engine has accepted a delivered policy.
type ReadyFunc func(*unstructured.Unstructured) bool

// KyvernoReady matches the assessment loop's readiness rule. A ValidatingPolicy
// is ready when Kyverno reports RBACPermissionsGranted and WebhookConfigured.
func KyvernoReady(o *unstructured.Unstructured) bool {
	conditions, _, _ := unstructured.NestedSlice(o.Object, "status", "conditionStatus", "conditions")
	ready := map[string]bool{}
	for _, c := range conditions {
		m, _ := c.(map[string]any)
		if m["status"] == "True" {
			t, _ := m["type"].(string)
			ready[t] = true
		}
	}
	return ready["RBACPermissionsGranted"] && ready["WebhookConfigured"]
}

// Delivery writes one binding's engine policies and retires superseded ones.
type Delivery struct {
	Client client.Client
	Ready  ReadyFunc
}

// DeliveryResult is the observable outcome of one Sync. Names are sorted.
type DeliveryResult struct {
	// Current lists the desired policies that exist and are owned by the binding.
	Current []string
	// NotReady lists current policies the engine has not accepted yet.
	NotReady []string
	// Retained lists superseded or held owned policies that are still
	// enforcing, because their replacement is not ready or their policy
	// failed to resolve.
	Retained []string
	// Removed lists owned policies deleted by this Sync.
	Removed []string
	// Conflicts lists desired names held by resources Konstapel does not own.
	// They are left untouched.
	Conflicts []string
}

// Ready reports whether every desired policy is current and engine-ready.
func (r DeliveryResult) Ready(desired int) bool {
	return len(r.Conflicts) == 0 && len(r.NotReady) == 0 && len(r.Current) == desired
}

// Sync converges the binding's owned engine policies to desired. It is
// idempotent. Owned policies whose logical policy is in hold are never
// removed: hold carries policies that failed to resolve, so working
// enforcement is not withdrawn because of a configuration error. A superseded
// policy is removed only when every desired instance of the same logical
// policy is ready. Policies owned by other bindings, and unmanaged resources,
// are never modified.
func (d *Delivery) Sync(ctx context.Context, bindingUID types.UID, desired []*unstructured.Unstructured, hold []string) (DeliveryResult, error) {
	ready := d.Ready
	if ready == nil {
		ready = KyvernoReady
	}
	var res DeliveryResult
	desiredNames := map[string]bool{}
	// Per policy hash: whether every desired instance is current and ready.
	replacementReady := map[string]bool{}
	for _, want := range desired {
		if want.GetLabels()[LabelBindingUID] != string(bindingUID) {
			return res, fmt.Errorf("desired policy %s does not belong to binding %s", want.GetName(), bindingUID)
		}
		name, hash := want.GetName(), want.GetLabels()[LabelPolicyHash]
		desiredNames[name] = true
		if _, seen := replacementReady[hash]; !seen {
			replacementReady[hash] = true
		}
		current, err := d.apply(ctx, bindingUID, want)
		switch {
		case err == errConflict:
			res.Conflicts = append(res.Conflicts, name)
			replacementReady[hash] = false
			continue
		case err != nil:
			return res, err
		}
		res.Current = append(res.Current, name)
		if !ready(current) {
			res.NotReady = append(res.NotReady, name)
			replacementReady[hash] = false
		}
	}

	held := map[string]bool{}
	for _, p := range hold {
		held[PolicyHash(p)] = true
	}
	owned, err := d.owned(ctx, bindingUID)
	if err != nil {
		return res, err
	}
	for _, o := range owned {
		if desiredNames[o.GetName()] {
			continue
		}
		hash := o.GetLabels()[LabelPolicyHash]
		replaced, stillDesired := replacementReady[hash]
		switch {
		case held[hash], stillDesired && !replaced:
			res.Retained = append(res.Retained, o.GetName())
		default:
			if err := d.Client.Delete(ctx, &o); err != nil && !apierrors.IsNotFound(err) {
				return res, err
			}
			res.Removed = append(res.Removed, o.GetName())
		}
	}
	for _, l := range [][]string{res.Current, res.NotReady, res.Retained, res.Removed, res.Conflicts} {
		slices.Sort(l)
	}
	return res, nil
}

// Withdraw deletes every engine policy owned by the binding, including
// superseded revisions. Use it when the binding is deleted.
func (d *Delivery) Withdraw(ctx context.Context, bindingUID types.UID) ([]string, error) {
	owned, err := d.owned(ctx, bindingUID)
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, o := range owned {
		if err := d.Client.Delete(ctx, &o); err != nil && !apierrors.IsNotFound(err) {
			return removed, err
		}
		removed = append(removed, o.GetName())
	}
	slices.Sort(removed)
	return removed, nil
}

var errConflict = fmt.Errorf("ownership conflict")

// apply creates want, or repairs drift on an existing policy the binding owns.
func (d *Delivery) apply(ctx context.Context, bindingUID types.UID, want *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	current := &unstructured.Unstructured{}
	current.SetGroupVersionKind(ValidatingPolicyGVK)
	err := d.Client.Get(ctx, client.ObjectKey{Name: want.GetName()}, current)
	if apierrors.IsNotFound(err) {
		obj := want.DeepCopy()
		if err := d.Client.Create(ctx, obj, FieldOwner); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return nil, errConflict
			}
			return nil, err
		}
		return obj, nil
	}
	if err != nil {
		return nil, err
	}
	if !ownedBy(current, bindingUID) || current.GetAnnotations()[AnnotationRevision] != want.GetAnnotations()[AnnotationRevision] {
		return nil, errConflict
	}
	if equality.Semantic.DeepEqual(current.Object["spec"], want.Object["spec"]) &&
		equality.Semantic.DeepEqual(current.GetOwnerReferences(), want.GetOwnerReferences()) &&
		subset(want.GetLabels(), current.GetLabels()) && subset(want.GetAnnotations(), current.GetAnnotations()) {
		return current, nil
	}
	repaired := current.DeepCopy()
	repaired.Object["spec"] = want.DeepCopy().Object["spec"]
	repaired.SetOwnerReferences(want.GetOwnerReferences())
	repaired.SetLabels(merge(current.GetLabels(), want.GetLabels()))
	repaired.SetAnnotations(merge(current.GetAnnotations(), want.GetAnnotations()))
	if err := d.Client.Update(ctx, repaired, FieldOwner); err != nil {
		return nil, err
	}
	return repaired, nil
}

func (d *Delivery) owned(ctx context.Context, bindingUID types.UID) ([]unstructured.Unstructured, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(ValidatingPolicyGVK.GroupVersion().WithKind(ValidatingPolicyGVK.Kind + "List"))
	if err := d.Client.List(ctx, list, client.MatchingLabels{LabelManagedBy: ManagedByValue, LabelBindingUID: string(bindingUID)}); err != nil {
		return nil, err
	}
	out := list.Items[:0]
	for _, o := range list.Items {
		if ownedBy(&o, bindingUID) {
			out = append(out, o)
		}
	}
	return out, nil
}

// ownedBy requires both the ownership labels and a controller reference to
// the binding UID, so a copied label alone does not confer ownership.
func ownedBy(o *unstructured.Unstructured, bindingUID types.UID) bool {
	l := o.GetLabels()
	if l[LabelManagedBy] != ManagedByValue || l[LabelBindingUID] != string(bindingUID) {
		return false
	}
	for _, ref := range o.GetOwnerReferences() {
		if ref.UID == bindingUID && ref.Controller != nil && *ref.Controller {
			return true
		}
	}
	return false
}

func subset(want, have map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

func merge(base, over map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}
