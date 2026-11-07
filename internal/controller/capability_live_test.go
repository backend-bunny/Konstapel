//go:build live

package controller

// Live engine capability recovery (add-helm-oci-distribution 4.2, 4.4) in
// its own acceptance group, because it removes and restores Kyverno's
// ValidatingPolicy API. The manager runs as an identity bound to the
// generated controller RBAC:
//   - started while the API is not served, a Deny binding reports the
//     precise reason; once the API is restored (and Kyverno restarted to
//     serve it) the binding delivers and enforces without a restart;
//   - revoking the controller's engine and report permissions reports
//     EngineAccessDenied and "policy reports unavailable" while the applied
//     policy keeps enforcing; restoring them recovers;
//   - a Kyverno rollout keeps the existing policy and readiness recovers;
//   - the API removed while Konstapel runs is reported, and once restored
//     the policy is delivered again without a restart.
// Run through scripts/targeting-live.sh.

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func TestLiveEngineCapabilityRecovery(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	const controllerUser = "konstapel-live-controller"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "konstapel-system"}})
	l.applyManifests("../../config/rbac/controller/role.yaml", nil)
	l.bind("konstapel-live-controller", controllerUser, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-controller"}, "")
	l.bind("konstapel-live-controller", controllerUser, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "konstapel-controller"}, "konstapel-system")

	// 1. Kyverno's ValidatingPolicy API is not served when Konstapel starts.
	const vpCRD = "validatingpolicies.policies.kyverno.io"
	saved := &apiextensionsv1.CustomResourceDefinition{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: vpCRD}, saved); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		got := &apiextensionsv1.CustomResourceDefinition{}
		if l.c.Get(l.ctx, client.ObjectKey{Name: vpCRD}, got) == nil {
			return
		}
		crd := &apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: saved.Name, Labels: saved.Labels, Annotations: saved.Annotations}, Spec: saved.Spec}
		if err := l.c.Create(l.ctx, crd); err != nil {
			t.Fatalf("restore %s: %v", vpCRD, err)
		}
	}
	t.Cleanup(restore)
	if err := l.c.Delete(l.ctx, saved); err != nil {
		t.Fatal(err)
	}
	l.eventually("ValidatingPolicy API removed", func() (bool, string) {
		err := l.c.Get(l.ctx, client.ObjectKey{Name: vpCRD}, &apiextensionsv1.CustomResourceDefinition{})
		return apierrors.IsNotFound(err), fmt.Sprint(err)
	})
	l.setNamespace("cr-prod", "cr-production")
	p := profileObj(t, "cr-baseline", pol)
	b := bindingObj("cr-deny", p.Name, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{envLabel: "cr-production"})
	for _, o := range []client.Object{p, b} {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = l.c.Delete(l.ctx, b)
		_ = l.c.Delete(l.ctx, p)
		l.eventually("capability test policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
	})
	stop := l.startManagerAs(controllerUser)
	defer func() { stop() }()
	engineReason := func() (string, string) {
		c := meta.FindStatusCondition(l.binding(b.Name).Status.Conditions, v1alpha1.ConditionEngineReady)
		if c == nil {
			return "", ""
		}
		return c.Reason, c.Message
	}
	l.eventually("missing engine API reported", func() (bool, string) {
		r, m := engineReason()
		return r == ReasonEngineResourceMissing || r == ReasonEngineAPINotServed, r + ": " + m
	})
	missing, _ := engineReason()
	l.record("engine-missing", map[string]any{"reason": missing})

	// 2. The API returns; Kyverno is restarted to serve it. Konstapel
	// recovers without a restart, delivers, and enforces.
	restore()
	l.eventually("ValidatingPolicy API established", func() (bool, string) {
		got := &apiextensionsv1.CustomResourceDefinition{}
		_ = l.c.Get(l.ctx, client.ObjectKey{Name: vpCRD}, got)
		for _, c := range got.Status.Conditions {
			if c.Type == apiextensionsv1.Established && c.Status == apiextensionsv1.ConditionTrue {
				return true, ""
			}
		}
		return false, toJSON(got.Status)
	})
	for _, d := range []string{"kyverno-admission-controller", "kyverno-background-controller", "kyverno-reports-controller"} {
		l.scaleKyverno(d, 0)
		l.scaleKyverno(d, 1)
	}
	l.waitReady(b.Name, 1)
	l.eventually("restored engine enforces", func() (bool, string) { return l.denied("cr-prod") })
	applied := l.policiesFor(b.Name)
	l.record("engine-recovered", map[string]any{"policies": applied})

	// 3. Permission loss: the controller may no longer use engine policies
	// or reports. Readiness says so; the applied policy keeps enforcing.
	role := &rbacv1.ClusterRole{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: "konstapel-controller"}, role); err != nil {
		t.Fatal(err)
	}
	full := role.DeepCopy().Rules
	role.Rules = slices.DeleteFunc(role.Rules, func(r rbacv1.PolicyRule) bool {
		return slices.Contains(r.APIGroups, "policies.kyverno.io") || slices.Contains(r.APIGroups, "wgpolicyk8s.io")
	})
	if err := l.c.Update(l.ctx, role); err != nil {
		t.Fatal(err)
	}
	l.eventually("lost permissions reported", func() (bool, string) {
		r, m := engineReason()
		return r == ReasonEngineAccessDenied, r + ": " + m
	})
	l.eventually("assessment reports lost access", func() (bool, string) {
		s := l.binding(b.Name).Status.Assessment
		if s == nil || s.Current == nil {
			return false, "no current assessment"
		}
		joined := strings.Join(s.Current.Limitations, ";")
		return strings.Contains(joined, "policy reports unavailable") || strings.Contains(joined, "AccessDenied") || strings.Contains(joined, "may not"), joined
	})
	if got := l.policiesFor(b.Name); !slices.Equal(got, applied) {
		t.Fatalf("permission loss changed applied policies: %v, want %v", got, applied)
	}
	if ok, msg := l.denied("cr-prod"); !ok {
		t.Fatalf("enforcement lost with the controller's permissions: %s", msg)
	}
	l.record("permissions-lost", map[string]any{"engineReady": ReasonEngineAccessDenied, "enforcement": "retained"})

	// 4. Permissions return: recovery without a restart.
	_ = l.c.Get(l.ctx, client.ObjectKey{Name: "konstapel-controller"}, role)
	role.Rules = full
	if err := l.c.Update(l.ctx, role); err != nil {
		t.Fatal(err)
	}
	l.waitReady(b.Name, 1)
	l.record("permissions-restored", map[string]any{"engineReady": "Ready"})

	// 5. A Kyverno rollout keeps the existing policy; readiness recovers.
	l.scaleKyverno("kyverno-admission-controller", 0)
	l.scaleKyverno("kyverno-admission-controller", 1)
	if got := l.policiesFor(b.Name); !slices.Equal(got, applied) {
		t.Fatalf("engine rollout changed applied policies: %v", got)
	}
	l.eventually("enforcement after the rollout", func() (bool, string) { return l.denied("cr-prod") })
	l.waitReady(b.Name, 1)
	l.record("engine-rollout", map[string]any{"policies": applied})

	// 6. The API is removed while Konstapel runs (deleting the CRD deletes
	// its policies; Konstapel itself deletes nothing) and restored again:
	// the binding reports it, then re-delivers without a restart.
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: vpCRD}, saved); err != nil {
		t.Fatal(err)
	}
	if err := l.c.Delete(l.ctx, saved); err != nil {
		t.Fatal(err)
	}
	l.eventually("removal while running reported", func() (bool, string) {
		r, m := engineReason()
		return r == ReasonEngineResourceMissing || r == ReasonEngineAPINotServed, r + ": " + m
	})
	restore()
	for _, d := range []string{"kyverno-admission-controller", "kyverno-background-controller", "kyverno-reports-controller"} {
		l.scaleKyverno(d, 0)
		l.scaleKyverno(d, 1)
	}
	l.waitReady(b.Name, 1)
	l.eventually("re-delivered policy enforces", func() (bool, string) { return l.denied("cr-prod") })
	l.record("engine-removed-and-restored", map[string]any{"policies": l.policiesFor(b.Name)})
}
