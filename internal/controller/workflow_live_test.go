//go:build live

package controller

// Live targeting workflow (add-compliance-targeting-api task 5.1): dynamic
// namespace membership, cumulative Audit-everywhere + Deny-in-production
// enforcement through Kyverno, evidence attribution, and removal of one
// overlapping binding while the other stays effective. Profile updates and
// relabels of existing namespaces are covered by TestLiveManager. Run through
// scripts/targeting-live.sh.

import (
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// liveNamespaces counts namespaces that are not being deleted, the set an
// empty selector targets.
func (l *live) liveNamespaces() int32 {
	list := &corev1.NamespaceList{}
	if err := l.c.List(l.ctx, list); err != nil {
		l.t.Fatal(err)
	}
	var n int32
	for _, ns := range list.Items {
		if ns.DeletionTimestamp == nil {
			n++
		}
	}
	return n
}

// waitTargets waits for a ready binding whose target count equals want(),
// re-evaluated on each poll (namespace deletion is asynchronous).
func (l *live) waitTargets(name string, want func() int32) {
	l.t.Helper()
	l.eventually(name+" target count", func() (bool, string) {
		b := l.binding(name)
		w := want()
		ok := b.Status.TargetCount != nil && *b.Status.TargetCount == w && b.Status.ObservedGeneration == b.Generation
		return ok, toJSON(map[string]any{"want": w, "status": b.Status})
	})
	l.waitReady(name, *l.binding(name).Status.TargetCount)
}

func TestLiveTargetingWorkflow(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	l.setNamespace("wf-prod", "wf-production")
	l.setNamespace("wf-dev", "wf-development")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "wf-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	// An explicit empty selector selects every namespace, including later ones.
	auditAll := bindingObj("wf-audit-all", p.Name, v1alpha1.ModeAudit, nil)
	denyProd := bindingObj("wf-deny-prod", p.Name, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{envLabel: "wf-production"})
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "wf-dev"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	t.Cleanup(func() {
		_ = l.c.Delete(l.ctx, pod)
		for _, n := range []string{auditAll.Name, denyProd.Name} {
			_ = l.c.Delete(l.ctx, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: n}})
		}
		_ = l.c.Delete(l.ctx, p)
		_ = l.c.Delete(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "wf-new"}})
		l.eventually("workflow policies removed", func() (bool, string) {
			got := l.policiesFor(auditAll.Name, denyProd.Name)
			return len(got) == 0, toJSON(got)
		})
	})
	for _, o := range []client.Object{p, auditAll, denyProd} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	if b := l.binding(auditAll.Name); b.Spec.NamespaceSelector == nil || len(b.Spec.NamespaceSelector.MatchLabels) != 0 {
		t.Fatalf("audit-all selector is not the explicit empty selector: %+v", b.Spec.NamespaceSelector)
	}
	stop := l.startManager()
	defer stop()

	// 1. Audit everywhere and deny in production.
	l.waitReady(denyProd.Name, 1)
	l.waitTargets(auditAll.Name, l.liveNamespaces)
	l.eventually("production denied", func() (bool, string) { ok, msg := l.denied("wf-prod"); return ok, msg })
	if ok, msg := l.denied("wf-dev"); ok {
		t.Fatalf("audit relaxed nothing but development was denied: %s", msg)
	}
	// An otherwise-valid non-production request is admitted and audited.
	if err := l.c.Create(l.ctx, pod); err != nil {
		t.Fatalf("development pod not admitted under Audit: %v", err)
	}
	l.eventually("audit evidence attributed to the audit binding", func() (bool, string) {
		b := l.binding(auditAll.Name)
		if b.Status.Assessment == nil || b.Status.Assessment.Current == nil {
			return false, toJSON(b.Status.Assessment)
		}
		return b.Status.Assessment.Current.Outcomes.Fail >= 1, toJSON(b.Status.Assessment.Current)
	})
	// Both contributions are separately owned and identifiable.
	auditPolicies, denyPolicies := l.policiesFor(auditAll.Name), l.policiesFor(denyProd.Name)
	if len(auditPolicies) == 0 || len(denyPolicies) == 0 || slices.ContainsFunc(auditPolicies, func(n string) bool { return slices.Contains(denyPolicies, n) }) {
		t.Fatalf("contributions not separately identifiable: audit %v deny %v", auditPolicies, denyPolicies)
	}
	l.record("workflow-overlap", map[string]any{"audit": auditPolicies, "deny": denyPolicies})

	// 2. A new namespace enters the empty selector and, by label, production.
	l.setNamespace("wf-new", "wf-production")
	l.waitReady(denyProd.Name, 2)
	l.waitTargets(auditAll.Name, l.liveNamespaces)
	l.eventually("new production namespace denied", func() (bool, string) { ok, msg := l.denied("wf-new"); return ok, msg })
	l.record("workflow-namespace-created", map[string]any{"deny": 2})

	// 3. It leaves production; audit still applies there.
	l.setNamespace("wf-new", "wf-development")
	l.waitReady(denyProd.Name, 1)
	l.eventually("relabelled namespace admitted", func() (bool, string) { ok, msg := l.denied("wf-new"); return !ok, msg })
	l.waitTargets(auditAll.Name, l.liveNamespaces)

	// 4. Deleting it removes it from every binding's membership.
	before := l.liveNamespaces()
	if err := l.c.Delete(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "wf-new"}}); err != nil {
		t.Fatal(err)
	}
	l.waitTargets(auditAll.Name, func() int32 { return before - 1 })
	l.record("workflow-namespace-deleted", map[string]any{"audit": before - 1})

	// 5. Removing the overlapping audit binding withdraws only its policies.
	denyIdentity := l.enforcementIdentity(denyProd.Name)
	if err := l.c.Delete(l.ctx, l.binding(auditAll.Name)); err != nil {
		t.Fatal(err)
	}
	l.eventually("audit policies withdrawn", func() (bool, string) {
		got := l.policiesFor(auditAll.Name)
		return len(got) == 0, toJSON(got)
	})
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: auditAll.Name}, &v1alpha1.ComplianceBinding{}); !apierrors.IsNotFound(err) {
		t.Fatalf("audit binding still present: %v", err)
	}
	if got := l.enforcementIdentity(denyProd.Name); toJSON(got) != toJSON(denyIdentity) {
		t.Fatalf("surviving binding's policies changed:\nbefore %v\nafter  %v", denyIdentity, got)
	}
	if ok, msg := l.denied("wf-prod"); !ok {
		t.Fatalf("surviving deny contribution no longer effective: %s", msg)
	}
	l.waitReady(denyProd.Name, 1)
	l.record("workflow-passed", map[string]any{"surviving": denyProd.Name})
}
