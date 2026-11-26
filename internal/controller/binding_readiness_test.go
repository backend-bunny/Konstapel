package controller

import (
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const ephemeralMessage = "failed to check permissions: missing verbs [update] on pods/ephemeralcontainers"

func rbacFalse(policy, message string) targeting.ReadinessDetail {
	return targeting.ReadinessDetail{Policy: policy, Condition: "RBACPermissionsGranted", State: targeting.ReadinessFalse, Reason: "RBACNotGranted", Message: message}
}

func requireDisplaySafe(t *testing.T, msg string) {
	t.Helper()
	if len(msg) > maxMessage || !utf8.ValidString(msg) {
		t.Fatalf("message %d bytes (max %d), valid UTF-8 %v", len(msg), maxMessage, utf8.ValidString(msg))
	}
	for _, r := range msg {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			t.Fatalf("message contains %U: %q", r, msg)
		}
	}
}

func hintFor(uid types.UID) string {
	return "inspect: kubectl get validatingpolicies -l " + targeting.LabelBindingUID + "=" + string(uid) + " -o yaml"
}

// TestEngineConditionIgnoresReadinessDetails pins EngineReady status, reason
// and requeue for every delivery outcome, with and without details.
func TestEngineConditionIgnoresReadinessDetails(t *testing.T) {
	details := []targeting.ReadinessDetail{rbacFalse("new", ephemeralMessage)}
	cases := []struct {
		name       string
		s          targeting.DeliveryResult
		desired    int
		unresolved bool
		status     metav1.ConditionStatus
		reason     string
		requeue    time.Duration
	}{
		{"conflict", targeting.DeliveryResult{Conflicts: []string{"x"}, NotReady: []string{"new"}}, 1, false, metav1.ConditionFalse, v1alpha1.ReasonOwnershipConflict, ConflictRequeue},
		{"unresolved retained", targeting.DeliveryResult{Retained: []string{"old"}, NotReady: []string{"new"}}, 1, true, metav1.ConditionFalse, v1alpha1.ReasonStaleRevision, 0},
		{"unresolved", targeting.DeliveryResult{NotReady: []string{"new"}}, 1, true, metav1.ConditionFalse, v1alpha1.ReasonStaleRevision, 0},
		{"not ready", targeting.DeliveryResult{Current: []string{"new"}, NotReady: []string{"new"}}, 1, false, metav1.ConditionFalse, v1alpha1.ReasonReplacementPending, TransitionRequeue},
		{"retained", targeting.DeliveryResult{Current: []string{"new"}, NotReady: []string{"new"}, Retained: []string{"old"}}, 1, false, metav1.ConditionFalse, v1alpha1.ReasonReplacementPending, TransitionRequeue},
		{"retained only", targeting.DeliveryResult{Current: []string{"new"}, Retained: []string{"old"}}, 1, false, metav1.ConditionFalse, v1alpha1.ReasonReplacementPending, TransitionRequeue},
		{"nothing", targeting.DeliveryResult{}, 0, false, metav1.ConditionFalse, ReasonNoContributions, 0},
		{"ready", targeting.DeliveryResult{Current: []string{"new"}}, 1, false, metav1.ConditionTrue, ReasonEngineReady, 0},
	}
	for _, tc := range cases {
		for _, with := range []bool{false, true} {
			s := tc.s
			if with {
				s.Readiness = details
			}
			status, reason, msg, requeue := engineCondition(s, "uid-b", tc.desired, tc.unresolved, 3)
			if status != tc.status || reason != tc.reason || requeue != tc.requeue {
				t.Fatalf("%s (details %v): %s/%s requeue %v, want %s/%s requeue %v", tc.name, with, status, reason, requeue, tc.status, tc.reason, tc.requeue)
			}
			requireDisplaySafe(t, msg)
		}
	}
}

func TestPendingMessageAttributesFailingCondition(t *testing.T) {
	s := targeting.DeliveryResult{NotReady: []string{"konstapel-new"}, Retained: []string{"konstapel-old"},
		Readiness: []targeting.ReadinessDetail{
			rbacFalse("konstapel-new", ephemeralMessage),
			{Policy: "konstapel-new", Condition: "WebhookConfigured", State: targeting.ReadinessMissing},
		}}
	got := pendingMessage(s, "uid-b")
	want := `waiting for engine readiness: RBACPermissionsGranted=False RBACNotGranted: "` + ephemeralMessage + `" on konstapel-new; ` +
		`WebhookConfigured=Unknown (condition missing) on konstapel-new; retained until ready: konstapel-old`
	if got != want {
		t.Fatalf("message\n got %s\nwant %s", got, want)
	}
}

func TestPendingMessageStatesStayUnknown(t *testing.T) {
	for state, want := range map[targeting.ReadinessState]string{
		targeting.ReadinessFalse:     "WebhookConfigured=False on p",
		targeting.ReadinessUnknown:   "WebhookConfigured=Unknown on p",
		targeting.ReadinessMissing:   "WebhookConfigured=Unknown (condition missing) on p",
		targeting.ReadinessMalformed: "WebhookConfigured=Unknown (condition malformed) on p",
		"Bogus":                      "WebhookConfigured=Unknown on p",
	} {
		s := targeting.DeliveryResult{NotReady: []string{"p"}, Readiness: []targeting.ReadinessDetail{{Policy: "p", Condition: "WebhookConfigured", State: state}}}
		if got := pendingMessage(s, "u"); got != "waiting for engine readiness: "+want {
			t.Fatalf("%s: %s", state, got)
		}
	}
	// A NotReady policy without details is still named, as unknown.
	got := pendingMessage(targeting.DeliveryResult{NotReady: []string{"p"}}, "u")
	if got != "waiting for engine readiness: not ready (no failing readiness condition reported) on p" {
		t.Fatalf("unattributed: %s", got)
	}
}

func TestPendingMessageDeduplicatesEquivalentFailures(t *testing.T) {
	var s targeting.DeliveryResult
	for i := range 50 {
		name := fmt.Sprintf("konstapel-p%02d", i)
		s.NotReady = append(s.NotReady, name)
		// Equivalent after sanitization: whitespace and line breaks differ.
		s.Readiness = append(s.Readiness, rbacFalse(name, strings.Repeat(" ", i%3)+"missing verbs\n[update]"))
	}
	got := pendingMessage(s, "uid-b")
	want := `waiting for engine readiness: RBACPermissionsGranted=False RBACNotGranted: "missing verbs [update]" on konstapel-p00, konstapel-p01 and 48 more; ` + hintFor("uid-b")
	if got != want {
		t.Fatalf("message\n got %s\nwant %s", got, want)
	}
}

func TestPendingMessageManyPoliciesIsBoundedAndDeterministic(t *testing.T) {
	var s targeting.DeliveryResult
	for i := range 300 {
		name := fmt.Sprintf("konstapel-policy-%03d-0123456789abcdef", i)
		s.NotReady = append(s.NotReady, name)
		s.Readiness = append(s.Readiness, rbacFalse(name, fmt.Sprintf("%s for policy %d", ephemeralMessage, i)),
			targeting.ReadinessDetail{Policy: name, Condition: "WebhookConfigured", State: targeting.ReadinessUnknown, Reason: "Pending"})
		s.Retained = append(s.Retained, name+"-old")
	}
	first := pendingMessage(s, "0f6c3a9e-1111-2222-3333-444455556666")
	requireDisplaySafe(t, first)
	for _, part := range []string{
		`waiting for engine readiness: RBACPermissionsGranted=False RBACNotGranted: "` + ephemeralMessage + ` for policy 0" on konstapel-policy-000-0123456789abcdef; `,
		" more diagnostics not shown; " + hintFor("0f6c3a9e-1111-2222-3333-444455556666") + "; retained until ready: konstapel-policy-000-0123456789abcdef-old, ",
	} {
		if !strings.Contains(first, part) {
			t.Fatalf("message lacks %q:\n%s", part, first)
		}
	}
	if !strings.HasSuffix(first, " more") {
		t.Fatalf("retained list must end with its omitted count: %s", first)
	}
	r := rand.New(rand.NewPCG(1, 2))
	for range 20 {
		shuffled := s
		shuffled.Readiness = slices.Clone(s.Readiness)
		r.Shuffle(len(shuffled.Readiness), func(i, j int) {
			shuffled.Readiness[i], shuffled.Readiness[j] = shuffled.Readiness[j], shuffled.Readiness[i]
		})
		if got := pendingMessage(shuffled, "0f6c3a9e-1111-2222-3333-444455556666"); got != first {
			t.Fatalf("detail order changed the message:\n%s\n%s", got, first)
		}
	}
}

func TestPendingMessageSanitizesHostileEngineText(t *testing.T) {
	hostile := "line1\nline2\r\n\t\x1b[31mred\x1b[0m \u202eevil\u202c \"quoted\" \xff\xfe bad" + strings.Repeat("é", 2000)
	s := targeting.DeliveryResult{NotReady: []string{"p\nq"}, Retained: []string{"old"},
		Readiness: []targeting.ReadinessDetail{{Policy: "p\nq", Condition: "RBACPermissionsGranted\x00", State: targeting.ReadinessFalse,
			Reason: strings.Repeat("R\t", 500), Message: hostile}}}
	got := pendingMessage(s, "uid-b")
	requireDisplaySafe(t, got)
	for _, part := range []string{
		`RBACPermissionsGranted=False R R R`,
		`: "line1 line2 [31mred [0m evil 'quoted' ` + "\uFFFD bad",
		`..." on p q; ` + hintFor("uid-b") + "; retained until ready: old",
	} {
		if !strings.Contains(got, part) {
			t.Fatalf("message lacks %q:\n%q", part, got)
		}
	}
}

// TestPendingMessageWorstCaseFits proves the display bounds: maximal engine
// fields, names and UID still show the first diagnostic in full, the omitted
// count, the inspection command and the start of the retained list without
// the final truncation cutting anything.
func TestPendingMessageWorstCaseFits(t *testing.T) {
	name := func(i int) string { return fmt.Sprintf("%s%03d", strings.Repeat("n", 60), i) }
	uid := types.UID(strings.Repeat("u", maxDiagUID))
	var s targeting.DeliveryResult
	for i := range 20 {
		s.NotReady = append(s.NotReady, name(i))
		s.Retained = append(s.Retained, name(100+i))
		for _, cond := range targeting.KyvernoReadinessConditions {
			s.Readiness = append(s.Readiness, targeting.ReadinessDetail{Policy: name(i), Condition: cond, State: targeting.ReadinessMalformed,
				Reason: strings.Repeat("r", 1000), Message: fmt.Sprintf("%d%s", i, strings.Repeat("\"", 2000))})
		}
	}
	// Every policy also shares one failure, so the first group lists the
	// maximum number of policies.
	for i := range 20 {
		s.Readiness = append(s.Readiness, targeting.ReadinessDetail{Policy: name(i), Condition: strings.Repeat("A", 1000), State: targeting.ReadinessMalformed,
			Reason: strings.Repeat("r", 1000), Message: strings.Repeat("m", 2000)})
	}
	got := pendingMessage(s, uid)
	requireDisplaySafe(t, got)
	if strings.HasSuffix(got, "...") || !strings.Contains(got, " more diagnostics not shown; "+hintFor(uid)+"; retained until ready: "+name(100)) {
		t.Fatalf("bounded parts did not fit:\n%s", got)
	}
	if !strings.HasPrefix(got, "waiting for engine readiness: "+clipText(strings.Repeat("A", 1000), maxDiagReason)+"=Unknown (condition malformed) ") ||
		!strings.Contains(got, " on "+name(0)+", "+name(1)+" and 18 more; ") {
		t.Fatalf("first diagnostic not shown in full:\n%s", got)
	}
}

func setPolicyStatus(t *testing.T, e *env, name string, status map[string]any) {
	t.Helper()
	live := &unstructured.Unstructured{}
	live.SetGroupVersionKind(targeting.ValidatingPolicyGVK)
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, live); err != nil {
		t.Fatal(err)
	}
	live.Object["status"] = status
	if err := e.c.Update(context.Background(), live); err != nil {
		t.Fatal(err)
	}
}

func rbacDenied(message string) map[string]any {
	return map[string]any{"conditionStatus": map[string]any{"conditions": []any{
		map[string]any{"type": "RBACPermissionsGranted", "status": "False", "reason": "RBACNotGranted", "message": message},
		map[string]any{"type": "WebhookConfigured", "status": "True"},
	}}}
}

// TestBindingExposesMissingEnginePermission covers the issue #358 scenario
// at the binding: Resolved stays True, EngineReady stays False with the
// failing condition attributed to the policy, the retained revision keeps
// enforcing, and an unchanged engine state does not rewrite status.
func TestBindingExposesMissingEnginePermission(t *testing.T) {
	p := profileObj(t, "baseline", pol)
	e := newEnv(t, nsObj("prod"), p, bindingObj("all", "baseline", v1alpha1.ModeAudit, nil))
	e.reconcile("all")
	e.markAllReady()
	e.reconcile("all")
	old := e.policies()[0].GetName()

	_ = e.c.Get(context.Background(), client.ObjectKeyFromObject(p), p)
	p.Spec.Policies[0].Exceptions = v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: time.Hour}}
	p.Generation = 2
	if err := e.c.Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	e.reconcile("all")
	var replacement string
	for _, o := range e.policies() {
		if o.GetName() != old {
			replacement = o.GetName()
		}
	}
	setPolicyStatus(t, e, replacement, rbacDenied(ephemeralMessage+"\nfor kyverno-admission-controller"))

	if res := e.reconcile("all"); res.RequeueAfter != TransitionRequeue {
		t.Fatalf("pending replacement must requeue: %+v", res)
	}
	b := e.binding("all")
	if c := cond(b, v1alpha1.ConditionResolved); c.Status != metav1.ConditionTrue {
		t.Fatalf("Resolved %+v", c)
	}
	requireNotCurrent(t, b, v1alpha1.ReasonReplacementPending)
	engine := cond(b, v1alpha1.ConditionEngineReady)
	requireDisplaySafe(t, engine.Message)
	want := `waiting for engine readiness: RBACPermissionsGranted=False RBACNotGranted: "` + ephemeralMessage + ` for kyverno-admission-controller" on ` +
		replacement + "; retained until ready: " + old
	if engine.Message != want {
		t.Fatalf("EngineReady message\n got %s\nwant %s", engine.Message, want)
	}
	if names := e.policies(); len(names) != 2 {
		t.Fatalf("retained revision withdrawn: %v", names)
	}
	rv := b.ResourceVersion
	e.reconcile("all")
	if b = e.binding("all"); b.ResourceVersion != rv {
		t.Fatal("unchanged engine state rewrote binding status")
	}

	// The ReadyFunc alone decides: once it accepts the replacement, stale
	// diagnostic conditions on the object do not hold the old revision.
	e.markAllReady()
	e.reconcile("all")
	if c := cond(e.binding("all"), v1alpha1.ConditionEngineReady); c.Status != metav1.ConditionTrue {
		t.Fatalf("EngineReady %+v", c)
	}
	if names := e.policies(); len(names) != 1 || names[0].GetName() != replacement {
		t.Fatalf("policies %v", names)
	}
}
