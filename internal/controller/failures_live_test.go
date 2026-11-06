//go:build live

package controller

// Live targeting failure modes (add-compliance-targeting-api task 5.2):
// missing content, an ownership conflict found after a controller restart,
// and an engine outage during a replacement. Status must stay truthful, owned
// enforcement is retained where it was working, and no assessment is reported
// Complete for configuration that did not resolve. Run through
// scripts/targeting-live.sh.

import (
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

func (l *live) condition(name, typ string) metav1.Condition {
	c := meta.FindStatusCondition(l.binding(name).Status.Conditions, typ)
	if c == nil {
		return metav1.Condition{}
	}
	return *c
}

func (l *live) waitCondition(name, typ string, status metav1.ConditionStatus, reason string) {
	l.t.Helper()
	l.eventually(name+" "+typ+"="+string(status)+" "+reason, func() (bool, string) {
		b := l.binding(name)
		c := meta.FindStatusCondition(b.Status.Conditions, typ)
		return c != nil && c.Status == status && c.Reason == reason && c.ObservedGeneration == b.Generation, toJSON(b.Status)
	})
}

// notComplete fails when a binding claims Complete current evidence.
func (l *live) notComplete(name string) {
	l.t.Helper()
	if a := l.binding(name).Status.Assessment; a != nil && a.Current != nil && a.Current.Evidence.Completeness == "Complete" {
		l.t.Fatalf("%s reports Complete evidence while its configuration is not current: %s", name, toJSON(a.Current))
	}
}

func (l *live) setProfileDigest(name, digest string) {
	l.t.Helper()
	p := &v1alpha1.ComplianceProfile{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, p); err != nil {
		l.t.Fatal(err)
	}
	p.Spec.Bundle.Digest = digest
	if err := l.c.Update(l.ctx, p); err != nil {
		l.t.Fatal(err)
	}
}

func (l *live) scaleEngine(replicas int32) { l.scaleKyverno("kyverno-admission-controller", replicas) }

// scaleKyverno scales one Kyverno deployment and waits for it.
func (l *live) scaleKyverno(name string, replicas int32) {
	l.t.Helper()
	d := &appsv1.Deployment{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: "kyverno", Name: name}, d); err != nil {
		l.t.Fatal(err)
	}
	d.Spec.Replicas = &replicas
	if err := l.c.Update(l.ctx, d); err != nil {
		l.t.Fatal(err)
	}
	l.eventually(name+" scaled", func() (bool, string) {
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(d), d)
		return d.Status.ReadyReplicas == replicas && d.Status.Replicas == replicas, toJSON(d.Status)
	})
}

func TestLiveTargetingFailures(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	l.setNamespace("fm-prod", "fm-production")
	good := digest(t)
	bad := "sha256:" + strings.Repeat("0", 64)
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "fm-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: good}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	missing := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "fm-missing"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: bad}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	deny := bindingObj("fm-deny", p.Name, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{envLabel: "fm-production"})
	orphan := bindingObj("fm-missing-content", missing.Name, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{envLabel: "fm-production"})
	var squatter string
	t.Cleanup(func() {
		l.scaleEngine(1)
		if squatter != "" {
			u := &unstructured.Unstructured{}
			u.SetGroupVersionKind(targeting.ValidatingPolicyGVK)
			u.SetName(squatter)
			_ = l.c.Delete(l.ctx, u)
		}
		for _, n := range []string{deny.Name, orphan.Name} {
			_ = l.c.Delete(l.ctx, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: n}})
		}
		_ = l.c.Delete(l.ctx, p)
		_ = l.c.Delete(l.ctx, missing)
		l.eventually("failure-test policies removed", func() (bool, string) {
			got := l.policiesFor(deny.Name, orphan.Name)
			return len(got) == 0, toJSON(got)
		})
	})
	for _, o := range []client.Object{p, missing, deny, orphan} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	stop := l.startManager()
	l.waitReady(deny.Name, 1)
	l.eventually("production denied", func() (bool, string) { ok, msg := l.denied("fm-prod"); return ok, msg })

	// 1. Missing content: a binding whose pinned bundle is unavailable
	// delivers nothing and is neither resolved nor ready.
	l.waitCondition(orphan.Name, v1alpha1.ConditionResolved, metav1.ConditionFalse, v1alpha1.ReasonContentUnavailable)
	l.waitCondition(orphan.Name, v1alpha1.ConditionEngineReady, metav1.ConditionFalse, v1alpha1.ReasonStaleRevision)
	if got := l.policiesFor(orphan.Name); len(got) != 0 {
		t.Fatalf("unresolved binding delivered policies: %v", got)
	}
	l.notComplete(orphan.Name)
	l.record("missing-content", map[string]any{"resolved": l.condition(orphan.Name, v1alpha1.ConditionResolved).Message})

	// 2. Content becomes unavailable for a working binding: its last applied
	// policies stay enforced and status says so instead of claiming readiness.
	identity := l.enforcementIdentity(deny.Name)
	l.setProfileDigest(p.Name, bad)
	l.waitCondition(deny.Name, v1alpha1.ConditionResolved, metav1.ConditionFalse, v1alpha1.ReasonContentUnavailable)
	l.waitCondition(deny.Name, v1alpha1.ConditionEngineReady, metav1.ConditionFalse, v1alpha1.ReasonStaleRevision)
	if msg := l.condition(deny.Name, v1alpha1.ConditionEngineReady).Message; !strings.Contains(msg, "last applied policies kept") {
		t.Fatalf("retained enforcement not reported: %s", msg)
	}
	if got := l.enforcementIdentity(deny.Name); toJSON(got) != toJSON(identity) {
		t.Fatalf("unresolved configuration changed owned policies:\nbefore %v\nafter  %v", identity, got)
	}
	if ok, msg := l.denied("fm-prod"); !ok {
		t.Fatalf("retained enforcement stopped denying: %s", msg)
	}
	l.notComplete(deny.Name)
	l.record("content-lost-retained", map[string]any{"engine": l.condition(deny.Name, v1alpha1.ConditionEngineReady).Message})
	l.setProfileDigest(p.Name, good)
	// Restoring content is a new profile generation, hence a new revision;
	// the binding becomes ready at it and keeps enforcing.
	l.waitReady(deny.Name, 1)
	if ok, msg := l.denied("fm-prod"); !ok {
		t.Fatalf("restored binding stopped denying: %s", msg)
	}

	// 3. Ownership conflict found after a restart: an unmanaged policy holding
	// the desired name is reported and never adopted or modified.
	stop()
	names := l.policiesFor(deny.Name)
	if len(names) != 1 {
		t.Fatalf("expected one owned policy, got %v", names)
	}
	squatter = names[0]
	owned := &unstructured.Unstructured{}
	owned.SetGroupVersionKind(targeting.ValidatingPolicyGVK)
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: squatter}, owned); err != nil {
		t.Fatal(err)
	}
	if err := l.c.Delete(l.ctx, owned); err != nil {
		t.Fatal(err)
	}
	l.eventually("owned policy deleted", func() (bool, string) {
		err := l.c.Get(l.ctx, client.ObjectKey{Name: squatter}, owned.DeepCopy())
		return apierrors.IsNotFound(err), ""
	})
	unmanaged := &unstructured.Unstructured{Object: map[string]any{"spec": owned.Object["spec"]}}
	unmanaged.SetGroupVersionKind(targeting.ValidatingPolicyGVK)
	unmanaged.SetName(squatter)
	unmanaged.SetLabels(map[string]string{"owner": "someone-else"})
	if err := l.c.Create(l.ctx, unmanaged); err != nil {
		t.Fatal(err)
	}
	// Kyverno writes status on it, so compare what an owner would change.
	identityOf := func(u *unstructured.Unstructured) string {
		return toJSON([]any{u.GetGeneration(), u.GetLabels(), u.GetAnnotations(), u.GetOwnerReferences(), u.Object["spec"]})
	}
	unmanagedIdentity := identityOf(unmanaged)
	stop = l.startManager()
	l.waitCondition(deny.Name, v1alpha1.ConditionEngineReady, metav1.ConditionFalse, v1alpha1.ReasonOwnershipConflict)
	time.Sleep(10 * time.Second) // further reconcile rounds must not touch it either
	got := &unstructured.Unstructured{}
	got.SetGroupVersionKind(targeting.ValidatingPolicyGVK)
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: squatter}, got); err != nil || identityOf(got) != unmanagedIdentity {
		t.Fatalf("unmanaged policy adopted or modified: %v\nbefore %s\nafter  %s", err, unmanagedIdentity, identityOf(got))
	}
	l.notComplete(deny.Name)
	l.record("ownership-conflict", map[string]any{"policy": squatter, "engine": l.condition(deny.Name, v1alpha1.ConditionEngineReady).Message})
	if err := l.c.Delete(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	squatter = ""
	l.waitReady(deny.Name, 1)

	// 4. Engine outage during a replacement: the new revision cannot become
	// ready, so the old one is retained and status reports the pending
	// replacement; recovery completes it.
	before := l.policiesFor(deny.Name)
	l.scaleEngine(0)
	_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(p), p)
	p.Spec.Policies[0].Exceptions = v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: time.Hour}}
	if err := l.c.Update(l.ctx, p); err != nil {
		t.Fatal(err)
	}
	var outage string
	l.eventually("replacement pending during engine outage", func() (bool, string) {
		b := l.binding(deny.Name)
		c := meta.FindStatusCondition(b.Status.Conditions, v1alpha1.ConditionEngineReady)
		outage = toJSON(b.Status)
		return b.Status.Profile != nil && b.Status.Profile.Generation == p.Generation && c != nil && c.Status == metav1.ConditionFalse && c.Reason == v1alpha1.ReasonReplacementPending, outage
	})
	for _, n := range before {
		if !strings.Contains(strings.Join(l.policiesFor(deny.Name), ","), n) {
			t.Fatalf("old revision %s withdrawn before its replacement was ready", n)
		}
	}
	l.notComplete(deny.Name)
	l.record("engine-outage", map[string]any{"status": outage, "policies": l.policiesFor(deny.Name)})
	l.scaleEngine(1)
	l.eventually("replacement completes after recovery", func() (bool, string) {
		cur := l.policiesFor(deny.Name)
		c := l.condition(deny.Name, v1alpha1.ConditionEngineReady)
		return len(cur) == 1 && cur[0] != before[0] && c.Status == metav1.ConditionTrue, toJSON(cur)
	})
	l.eventually("production denied after recovery", func() (bool, string) { ok, msg := l.denied("fm-prod"); return ok, msg })
	stop()
	l.record("failures-passed", map[string]any{})
}
