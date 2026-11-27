//go:build live

package controller

// Live Kyverno permission repair (improve-kyverno-readiness-diagnostics
// 3.1), in the capabilities group because it removes and restores Kyverno's
// ephemeral-container grants. The environment applies the upstream
// ephemeral-rbac.yaml fixture (scripts/environment.sh); this test deletes it
// so the installation starts with the chart's RBAC only, and the manager
// runs as an identity bound to the generated controller RBAC:
//   - without the grant every delivered policy reports
//     RBACPermissionsGranted=False; both bindings stay EngineReady=False
//     ReplacementPending, naming the missing pods/ephemeralcontainers verbs
//     and the policy, while Resolved stays True and Deny keeps enforcing;
//   - a revision change while the grant is missing keeps the earlier
//     revision enforcing (retained until ready);
//   - the administrator applies the documented example
//     (docs/examples/kyverno/reports-controller-ephemeralcontainers.yaml);
//     the same manager, without a restart, rechecks readiness with the
//     readiness-recheck annotation only, and both bindings become ready with
//     the same policy UIDs, ownership and revisions; the retained revision
//     is removed only then, and Deny enforced throughout;
//   - rechecks stop once the policies are ready, and the Audit binding's
//     evidence is attributable to the current revision;
//   - removing the grant again is recorded: Kyverno 1.19 does not
//     re-evaluate a ready policy, so it is expected to stay unnoticed.
// Konstapel cannot change RBAC at all; the test, acting as the Kyverno
// administrator, removes and restores only the fixture and its own example.
// Run through scripts/targeting-live.sh.

import (
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const (
	ephemeralFixture = "../../content/upstream/kyverno/disallow-privileged-containers/.chainsaw-test/ephemeral-rbac.yaml"
	ephemeralExample = "../../docs/examples/kyverno/reports-controller-ephemeralcontainers.yaml"
	reportsSA        = "system:serviceaccount:kyverno:kyverno-reports-controller"
	admissionSA      = "system:serviceaccount:kyverno:kyverno-admission-controller"
)

// policyIdentity is what a readiness recheck must leave unchanged.
type policyIdentity struct {
	UID        string            `json:"uid"`
	Generation int64             `json:"generation"`
	Revision   string            `json:"revision"`
	Labels     map[string]string `json:"labels"`
	Owners     string            `json:"owners"`
	Spec       string            `json:"spec"`
	Recheck    string            `json:"recheck,omitempty"`
	RBAC       string            `json:"rbacPermissionsGranted"`
	Webhook    string            `json:"webhookConfigured"`
}

// attempt is the recorded recheck attempt, 0 without one.
func (id policyIdentity) attempt() int {
	n, _, _ := strings.Cut(id.Recheck, "@")
	a, _ := strconv.Atoi(n)
	return a
}

func (l *live) enginePolicy(name string) (*unstructured.Unstructured, bool) {
	o := &unstructured.Unstructured{}
	o.SetGroupVersionKind(targeting.ValidatingPolicyGVK)
	err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, o)
	if apierrors.IsNotFound(err) {
		return nil, false
	}
	if err != nil {
		l.t.Fatal(err)
	}
	return o, true
}

func identityOf(o *unstructured.Unstructured) policyIdentity {
	id := policyIdentity{UID: string(o.GetUID()), Generation: o.GetGeneration(), Revision: o.GetAnnotations()[targeting.AnnotationRevision],
		Labels: o.GetLabels(), Owners: toJSON(o.GetOwnerReferences()), Spec: toJSON(o.Object["spec"]),
		Recheck: o.GetAnnotations()[targeting.AnnotationReadinessRecheck], RBAC: "True", Webhook: "True"}
	for _, d := range targeting.KyvernoReadiness(o) {
		switch d.Condition {
		case targeting.RecheckCondition:
			id.RBAC = string(d.State)
		case "WebhookConfigured":
			id.Webhook = string(d.State)
		}
	}
	return id
}

func (l *live) identities(bindings ...string) map[string]policyIdentity {
	out := map[string]policyIdentity{}
	for _, name := range l.policiesFor(bindings...) {
		if o, ok := l.enginePolicy(name); ok {
			out[name] = identityOf(o)
		}
	}
	return out
}

// ephemeralAccess is the effective access of a Kyverno service account to
// pods/ephemeralcontainers, as `kubectl auth can-i` reports it.
func (l *live) ephemeralAccess(user string) map[string]bool {
	out := map[string]bool{}
	for _, verb := range []string{"get", "list", "watch", "update", "patch"} {
		out[verb] = l.can(user, authzv1.ResourceAttributes{Verb: verb, Resource: "pods", Subresource: "ephemeralcontainers"})
	}
	return out
}

func readManifests(t *testing.T, path string) []*unstructured.Unstructured {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []*unstructured.Unstructured
	for _, doc := range strings.Split(string(raw), "\n---") {
		u := &unstructured.Unstructured{}
		if err := yaml.Unmarshal([]byte(doc), &u.Object); err == nil && len(u.Object) > 0 {
			out = append(out, u)
		}
	}
	return out
}

func TestLiveKyvernoPermissionRecovery(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	const controllerUser = "konstapel-live-controller"

	// 0. The Kyverno administrator removes the acceptance fixture's
	// grants; they are restored, and their effect awaited, at the end.
	var removed []*unstructured.Unstructured
	t.Cleanup(func() {
		for _, u := range removed {
			u := u.DeepCopy()
			u.SetResourceVersion("")
			u.SetUID("")
			u.SetCreationTimestamp(metav1.Time{})
			u.SetManagedFields(nil)
			if err := l.c.Create(l.ctx, u); err != nil && !apierrors.IsAlreadyExists(err) {
				t.Errorf("restore %s: %v", u.GetName(), err)
			}
		}
		if len(removed) > 0 {
			l.eventually("fixture grants restored", func() (bool, string) {
				a, r := l.ephemeralAccess(admissionSA), l.ephemeralAccess(reportsSA)
				return a["get"] && a["list"] && a["watch"] && a["update"] && r["get"] && r["list"] && r["watch"], toJSON(map[string]any{"admission": a, "reports": r})
			})
		}
	})
	for _, want := range readManifests(t, ephemeralFixture) {
		live := &unstructured.Unstructured{}
		live.SetGroupVersionKind(want.GroupVersionKind())
		err := l.c.Get(l.ctx, client.ObjectKey{Name: want.GetName()}, live)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := l.c.Delete(l.ctx, live); err != nil {
			t.Fatal(err)
		}
		removed = append(removed, live)
	}
	none := map[string]bool{"get": false, "list": false, "watch": false, "update": false, "patch": false}
	l.eventually("chart RBAC only", func() (bool, string) {
		a, r := l.ephemeralAccess(admissionSA), l.ephemeralAccess(reportsSA)
		return toJSON(a) == toJSON(none) && toJSON(r) == toJSON(none), toJSON(map[string]any{"admission": a, "reports": r})
	})
	l.record("grants-removed", map[string]any{"fixtureRoles": len(removed), "reports": l.ephemeralAccess(reportsSA)})

	// The manager runs with the generated controller RBAC, which cannot
	// change any RBAC object.
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "konstapel-system"}})
	l.applyManifests("../../config/rbac/controller/role.yaml", nil)
	l.bind("konstapel-live-controller", controllerUser, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-controller"}, "")
	l.bind("konstapel-live-controller", controllerUser, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "konstapel-controller"}, "konstapel-system")
	for _, verb := range []string{"create", "update", "patch", "delete", "escalate", "bind"} {
		for _, res := range []string{"clusterroles", "clusterrolebindings"} {
			if l.can(controllerUser, authzv1.ResourceAttributes{Verb: verb, Group: rbacv1.GroupName, Resource: res}) {
				t.Fatalf("the controller may %s %s", verb, res)
			}
		}
	}

	// 1. Bindings delivered without the grant.
	l.setNamespace("kp-audit", "kp-audit")
	l.setNamespace("kp-deny", "kp-deny")
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "kp-audit"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	p := profileObj(t, "kp-baseline", pol)
	audit := bindingObj("kp-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "kp-audit"})
	deny := bindingObj("kp-deny", p.Name, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{envLabel: "kp-deny"})
	t.Cleanup(func() {
		_ = l.c.Delete(l.ctx, pod)
		for _, n := range []string{audit.Name, deny.Name} {
			_ = l.c.Delete(l.ctx, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: n}})
		}
		_ = l.c.Delete(l.ctx, p)
		l.eventually("permission test policies removed", func() (bool, string) {
			got := l.policiesFor(audit.Name, deny.Name)
			return len(got) == 0, toJSON(got)
		})
	})
	for _, o := range []client.Object{pod, p, audit, deny} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	mgr := l.candidateWith(controllerUser, "kp-controller", func(o *Options) { o.LeaderElection = false })
	defer mgr.stop()

	engine := func(name string) metav1.Condition {
		c := meta.FindStatusCondition(l.binding(name).Status.Conditions, v1alpha1.ConditionEngineReady)
		if c == nil {
			return metav1.Condition{}
		}
		return *c
	}
	// pending waits until the binding names the missing verbs for each of
	// its current policies, and returns the message.
	pending := func(name string, retained ...string) string {
		var msg string
		l.eventually(name+" reports the missing grant", func() (bool, string) {
			b := l.binding(name)
			c, r := engine(name), meta.FindStatusCondition(b.Status.Conditions, v1alpha1.ConditionResolved)
			current := l.policiesFor(name)
			msg = c.Message
			ok := c.Status == metav1.ConditionFalse && c.Reason == v1alpha1.ReasonReplacementPending && r != nil && r.Status == metav1.ConditionTrue &&
				strings.Contains(msg, "RBACPermissionsGranted=False") && strings.Contains(msg, "pods/ephemeralcontainers") && len(current) == 1+len(retained)
			for _, n := range current {
				ok = ok && strings.Contains(msg, n)
			}
			for _, n := range retained {
				ok = ok && strings.Contains(msg, "retained until ready: "+n)
			}
			return ok, toJSON(b.Status.Conditions)
		})
		requireDisplaySafe(t, msg)
		return msg
	}
	auditMsg, denyMsg := pending(audit.Name), pending(deny.Name)
	for _, verb := range []string{"get", "list", "watch"} {
		if !strings.Contains(denyMsg, verb+" /v1, Resource=pods/ephemeralcontainers") {
			t.Fatalf("diagnostic lacks the missing %s verb: %s", verb, denyMsg)
		}
	}
	l.eventually("Deny enforces while not ready", func() (bool, string) { return l.denied("kp-deny") })
	if ok, msg := l.denied("kp-audit"); ok {
		t.Fatalf("Audit namespace denied: %s", msg)
	}
	first := l.identities(audit.Name, deny.Name)
	for n, id := range first {
		if id.RBAC != string(targeting.ReadinessFalse) {
			t.Fatalf("%s RBACPermissionsGranted %s, want False", n, id.RBAC)
		}
	}
	evidenceBefore := l.binding(audit.Name).Status.Assessment
	l.record("missing-grant", map[string]any{"audit": auditMsg, "deny": denyMsg, "policies": first, "auditEvidence": evidenceBefore})

	// 2. A revision change while the grant is missing: the earlier
	// revision keeps enforcing.
	old := slices.Sorted(maps.Keys(first))
	oldAudit, oldDeny := l.policiesFor(audit.Name), l.policiesFor(deny.Name)
	_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(p), p)
	p.Spec.Policies[0].Exceptions = v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: time.Hour}}
	if err := l.c.Update(l.ctx, p); err != nil {
		t.Fatal(err)
	}
	pending(audit.Name, oldAudit...)
	denyMsg = pending(deny.Name, oldDeny...)
	if ok, msg := l.denied("kp-deny"); !ok {
		t.Fatalf("enforcement withdrawn during the replacement: %s", msg)
	}
	replaced := map[string]policyIdentity{}
	for n, id := range l.identities(audit.Name, deny.Name) {
		if prev, ok := first[n]; ok {
			if prev.UID != id.UID || prev.Spec != id.Spec || prev.Revision != id.Revision {
				t.Fatalf("retained revision %s changed: %+v, was %+v", n, id, prev)
			}
			continue
		}
		replaced[n] = id
	}
	if len(replaced) != 2 {
		t.Fatalf("replacements %v", replaced)
	}
	l.record("retained-while-missing", map[string]any{"deny": denyMsg, "retained": old, "replacements": replaced})

	// Kyverno evaluates a new policy again once its webhook is configured;
	// a grant applied before that would be noticed without a recheck. Wait
	// for that, and for the first recheck (30 seconds after creation),
	// which leaves the condition False while the grant is missing.
	replacements := func() map[string]policyIdentity {
		out := map[string]policyIdentity{}
		for n, id := range l.identities(audit.Name, deny.Name) {
			if _, ok := replaced[n]; ok {
				out[n] = id
			}
		}
		return out
	}
	l.eventually("first rechecks without the grant", func() (bool, string) {
		ids := replacements()
		ok := len(ids) == len(replaced)
		for _, id := range ids {
			ok = ok && id.Webhook == "True" && id.attempt() >= 1
		}
		return ok, toJSON(ids)
	})
	time.Sleep(5 * time.Second)
	for n, id := range replacements() {
		if id.RBAC != string(targeting.ReadinessFalse) || id.UID != replaced[n].UID {
			t.Fatalf("a recheck without the grant changed %s: %+v", n, id)
		}
	}
	unrepaired := replacements()
	l.record("rechecked-without-grant", map[string]any{"policies": unrepaired})

	// 3. The administrator applies the documented example. The same
	// manager recovers through ordinary reconciliation.
	l.applyManifests(ephemeralExample, nil)
	granted := map[string]bool{"get": true, "list": true, "watch": true, "update": false, "patch": false}
	l.eventually("documented grant effective", func() (bool, string) {
		r := l.ephemeralAccess(reportsSA)
		return toJSON(r) == toJSON(granted), toJSON(r)
	})
	if a := l.ephemeralAccess(admissionSA); toJSON(a) != toJSON(none) {
		t.Fatalf("the example granted the admission controller %v", a)
	}
	applied := time.Now()
	deadline := applied.Add(6 * time.Minute)
	for {
		if ok, msg := l.denied("kp-deny"); !ok {
			t.Fatalf("enforcement lost during recovery: %s", msg)
		}
		a, d := engine(audit.Name), engine(deny.Name)
		if a.Status == metav1.ConditionTrue && d.Status == metav1.ConditionTrue {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no recovery %s after the grant: audit %s, deny %s; policies %s", time.Since(applied), a.Message, d.Message, toJSON(l.identities(audit.Name, deny.Name)))
		}
		time.Sleep(2 * time.Second)
	}
	recovered := time.Since(applied)
	l.waitReady(audit.Name, 1)
	l.waitReady(deny.Name, 1)
	now := l.identities(audit.Name, deny.Name)
	if len(now) != len(replaced) {
		t.Fatalf("after recovery %v, want the replacements %v", slices.Sorted(maps.Keys(now)), slices.Sorted(maps.Keys(replaced)))
	}
	for n, id := range now {
		want, ok := replaced[n]
		if !ok {
			t.Fatalf("unexpected policy %s after recovery", n)
		}
		if id.UID != want.UID || id.Generation != want.Generation || id.Revision != want.Revision || id.Owners != want.Owners ||
			id.Spec != want.Spec || toJSON(id.Labels) != toJSON(want.Labels) {
			t.Fatalf("recovery changed %s: %+v, was %+v", n, id, want)
		}
		// Kyverno does not notice the grant by itself: a recheck written
		// after it was applied made the policy ready.
		if id.RBAC != "True" || id.attempt() <= unrepaired[n].attempt() {
			t.Fatalf("%s recovered without a recheck after the grant: %+v, before the grant %+v", n, id, unrepaired[n])
		}
	}
	for _, n := range old {
		if _, ok := l.enginePolicy(n); ok {
			t.Fatalf("retained revision %s kept after the replacement was ready", n)
		}
	}
	l.eventually("Deny enforces after recovery", func() (bool, string) { return l.denied("kp-deny") })
	l.record("recovered", map[string]any{"afterGrant": recovered.Round(time.Second).String(), "policies": now})

	// 4. Evidence is attributable to the current revision, and no further
	// recheck is written once the policies are ready.
	l.eventually("attributable evidence after recovery", func() (bool, string) {
		s := l.binding(audit.Name).Status.Assessment
		if s == nil || s.Current == nil {
			return false, "no current assessment"
		}
		c := s.Current
		return c.Evidence.Completeness == "Complete" && c.Evidence.Expected == 1 && c.Outcomes.Fail == 1, toJSON(c)
	})
	evidence := l.binding(audit.Name).Status.Assessment.Current
	// Wait past the step at which each policy's next recheck would be due
	// if it were still failing (DefaultRecheckBackoff: 30s doubled per
	// attempt, at most 15m).
	var quiet time.Time
	for _, id := range now {
		n, stamp, _ := strings.Cut(id.Recheck, "@")
		attempt, _ := strconv.Atoi(n)
		at, err := time.Parse(time.RFC3339, stamp)
		if err != nil {
			t.Fatalf("recheck annotation %q: %v", id.Recheck, err)
		}
		if next := at.Add(min(targeting.DefaultRecheckBackoff.Initial<<attempt, targeting.DefaultRecheckBackoff.Max) + 15*time.Second); next.After(quiet) {
			quiet = next
		}
	}
	time.Sleep(time.Until(quiet))
	for n, id := range l.identities(audit.Name, deny.Name) {
		if id.Recheck != now[n].Recheck || id.UID != now[n].UID {
			t.Fatalf("%s was rechecked after it was ready: %q, was %q", n, id.Recheck, now[n].Recheck)
		}
	}
	l.record("rechecks-stopped", map[string]any{"evidence": evidence.Evidence, "outcomes": evidence.Outcomes, "policies": l.identities(audit.Name, deny.Name)})

	// 5. Removing the grant again, recorded: Kyverno 1.19 does not
	// re-evaluate a ready policy, so the binding is expected to stay ready.
	for _, u := range readManifests(t, ephemeralExample) {
		if err := l.c.Delete(l.ctx, u); err != nil && !apierrors.IsNotFound(err) {
			t.Fatal(err)
		}
	}
	l.eventually("grant removed again", func() (bool, string) {
		r := l.ephemeralAccess(reportsSA)
		return toJSON(r) == toJSON(none), toJSON(r)
	})
	time.Sleep(time.Minute)
	stale := l.identities(audit.Name, deny.Name)
	visible := false
	for _, id := range stale {
		visible = visible || id.RBAC != "True"
	}
	l.record("grant-removed-after-recovery", map[string]any{"removalVisible": visible, "engineReady": map[string]string{
		audit.Name: string(engine(audit.Name).Status), deny.Name: string(engine(deny.Name).Status)}, "policies": stale})
	if ok, msg := l.denied("kp-deny"); !ok {
		t.Fatalf("enforcement lost after removing the grant: %s", msg)
	}
}
