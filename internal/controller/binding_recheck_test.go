package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

func rbacGranted() map[string]any {
	return map[string]any{"conditionStatus": map[string]any{"conditions": []any{
		map[string]any{"type": "RBACPermissionsGranted", "status": "True", "reason": "Succeeded"},
		map[string]any{"type": "WebhookConfigured", "status": "True"},
	}}}
}

// TestBindingRechecksPermissionFailureWithinBackoff covers the repair path of
// issue #358: a current policy that reports RBACPermissionsGranted False is
// rechecked through ordinary reconciliation, at most once per backoff step,
// with only the recheck annotation written; rechecks stop once the policy is
// ready, and ownership, revision and the binding diagnostic are unchanged.
func TestBindingRechecksPermissionFailureWithinBackoff(t *testing.T) {
	e := newEnv(t, nsObj("prod"), profileObj(t, "baseline", pol), bindingObj("all", "baseline", v1alpha1.ModeDeny, nil))
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	e.r.Now = func() time.Time { return now }
	e.reconcile("all")
	policy := e.policies()[0]
	if policy.GetAnnotations()[targeting.AnnotationReadinessRecheck] != "" {
		t.Fatal("a policy Kyverno has not evaluated was rechecked")
	}
	setPolicyStatus(t, e, policy.GetName(), rbacDenied(ephemeralMessage))
	recheck := func() string { return e.policies()[0].GetAnnotations()[targeting.AnnotationReadinessRecheck] }

	if res := e.reconcile("all"); res.RequeueAfter != TransitionRequeue {
		t.Fatalf("pending binding must requeue: %+v", res)
	}
	if got := recheck(); got != "1@2026-11-27T12:00:00Z" {
		t.Fatalf("first recheck %q", got)
	}
	b := e.binding("all")
	requireNotCurrent(t, b, v1alpha1.ReasonReplacementPending)
	msg := cond(b, v1alpha1.ConditionEngineReady).Message

	// Reconciles inside the backoff write neither the policy nor status.
	rv, brv := e.policies()[0].GetResourceVersion(), b.ResourceVersion
	for _, step := range []time.Duration{5 * time.Second, 30 * time.Second, 59 * time.Second} {
		now = time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC).Add(step)
		e.reconcile("all")
	}
	if e.policies()[0].GetResourceVersion() != rv || e.binding("all").ResourceVersion != brv {
		t.Fatal("a reconcile inside the backoff wrote the policy or the binding")
	}
	now = now.Add(time.Second)
	e.reconcile("all")
	if got := recheck(); got != "2@2026-11-27T12:01:00Z" {
		t.Fatalf("second recheck %q", got)
	}
	if got := cond(e.binding("all"), v1alpha1.ConditionEngineReady).Message; got != msg {
		t.Fatalf("a recheck changed the diagnostic:\n got %s\nwant %s", got, msg)
	}

	after := e.policies()[0]
	if after.GetUID() != policy.GetUID() || !equality.Semantic.DeepEqual(after.Object["spec"], policy.Object["spec"]) ||
		!equality.Semantic.DeepEqual(after.GetOwnerReferences(), policy.GetOwnerReferences()) || !equality.Semantic.DeepEqual(after.GetLabels(), policy.GetLabels()) ||
		after.GetAnnotations()[targeting.AnnotationRevision] != policy.GetAnnotations()[targeting.AnnotationRevision] {
		t.Fatal("a recheck changed the policy's identity, ownership or revision")
	}

	// Kyverno reports the grant: the binding becomes ready and rechecks stop.
	setPolicyStatus(t, e, policy.GetName(), rbacGranted())
	e.markAllReady()
	e.reconcile("all")
	if c := cond(e.binding("all"), v1alpha1.ConditionEngineReady); c.Status != metav1.ConditionTrue {
		t.Fatalf("EngineReady %+v", c)
	}
	rv = e.policies()[0].GetResourceVersion()
	for _, step := range []time.Duration{time.Minute, time.Hour, 24 * time.Hour} {
		now = now.Add(step)
		e.reconcile("all")
	}
	if e.policies()[0].GetResourceVersion() != rv || recheck() != "2@2026-11-27T12:01:00Z" {
		t.Fatal("a ready policy was rechecked")
	}
}

// A recheck failure surfaces after the diagnostic is written: a stale
// snapshot resolves again, other errors retry the binding. Nothing is
// written to the policy either way.
func TestBindingRecheckFailuresKeepTheDiagnostic(t *testing.T) {
	forbidden := apierrors.NewForbidden(schema.GroupResource{Group: "policies.kyverno.io", Resource: "validatingpolicies"}, "p", errors.New("no"))
	for _, stale := range []bool{true, false} {
		e := newEnv(t, nsObj("prod"), profileObj(t, "baseline", pol), bindingObj("all", "baseline", v1alpha1.ModeDeny, nil))
		e.reconcile("all")
		setPolicyStatus(t, e, e.policies()[0].GetName(), rbacDenied(ephemeralMessage))
		statusWritten := false
		e.r.Client = interceptor.NewClient(e.c.(client.WithWatch), interceptor.Funcs{
			// Once status is written, the binding reads as a newer
			// generation: the recheck's snapshot check sees a change.
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				err := c.Get(ctx, key, obj, opts...)
				if b, ok := obj.(*v1alpha1.ComplianceBinding); ok && err == nil && stale && statusWritten {
					b.Generation++
				}
				return err
			},
			SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				err := c.SubResource(sub).Update(ctx, obj, opts...)
				statusWritten = statusWritten || err == nil
				return err
			},
			Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
				return forbidden
			},
		})
		res, err := e.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "all"}})
		if !statusWritten {
			t.Fatal("the diagnostic was not written before the recheck")
		}
		requireNotCurrent(t, e.binding("all"), v1alpha1.ReasonReplacementPending)
		if stale && (err != nil || res.RequeueAfter != time.Second) {
			t.Fatalf("stale snapshot: %+v %v", res, err)
		}
		if !stale && !apierrors.IsForbidden(err) {
			t.Fatalf("error %v", err)
		}
		if got := e.policies()[0].GetAnnotations()[targeting.AnnotationReadinessRecheck]; got != "" {
			t.Fatalf("recheck written: %q", got)
		}
	}
}
