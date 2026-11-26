package targeting

import (
	"context"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func withStatus(name string, status any) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]any{}}
	o.SetName(name)
	if status != nil {
		o.Object["status"] = status
	}
	return o
}

func conds(cs ...any) map[string]any {
	return map[string]any{"conditionStatus": map[string]any{"conditions": cs}}
}

func c(typ, status, reason, message string) map[string]any {
	return map[string]any{"type": typ, "status": status, "reason": reason, "message": message}
}

const ephemeral = `failed to check permissions: missing verbs [update] on pods/ephemeralcontainers for system:serviceaccount:kyverno:kyverno-admission-controller`

// TestKyvernoReadinessPinsReadyRule pins KyvernoReady's decision for every
// status shape and checks that the diagnostic agrees with it.
func TestKyvernoReadinessPinsReadyRule(t *testing.T) {
	type want struct {
		cond  string
		state ReadinessState
		why   string
	}
	rbacOK, hookOK := c("RBACPermissionsGranted", "True", "", ""), c("WebhookConfigured", "True", "", "")
	cases := []struct {
		name   string
		status any
		ready  bool
		want   []want
	}{
		{"ready", conds(rbacOK, hookOK), true, nil},
		{"ready with extra conditions", conds(c("Other", "False", "", ""), rbacOK, hookOK), true, nil},
		{"rbac false", conds(c("RBACPermissionsGranted", "False", "RBACNotGranted", ephemeral), hookOK), false,
			[]want{{"RBACPermissionsGranted", ReadinessFalse, ephemeral}}},
		{"webhook unknown", conds(rbacOK, c("WebhookConfigured", "Unknown", "Pending", "")), false,
			[]want{{"WebhookConfigured", ReadinessUnknown, ""}}},
		{"both false", conds(c("WebhookConfigured", "False", "R", "w"), c("RBACPermissionsGranted", "False", "R", "r")), false,
			[]want{{"RBACPermissionsGranted", ReadinessFalse, "r"}, {"WebhookConfigured", ReadinessFalse, "w"}}},
		{"no status", nil, false, []want{{"RBACPermissionsGranted", ReadinessMissing, ""}, {"WebhookConfigured", ReadinessMissing, ""}}},
		{"empty conditions", conds(), false, []want{{"RBACPermissionsGranted", ReadinessMissing, ""}, {"WebhookConfigured", ReadinessMissing, ""}}},
		{"one missing", conds(rbacOK), false, []want{{"WebhookConfigured", ReadinessMissing, ""}}},
		{"conditions not a list", map[string]any{"conditionStatus": map[string]any{"conditions": "True"}}, false,
			[]want{{"RBACPermissionsGranted", ReadinessMalformed, ""}, {"WebhookConfigured", ReadinessMalformed, ""}}},
		{"status not an object", "ready", false,
			[]want{{"RBACPermissionsGranted", ReadinessMalformed, ""}, {"WebhookConfigured", ReadinessMalformed, ""}}},
		{"unreadable entry", conds("RBACPermissionsGranted=True", hookOK), false,
			[]want{{"RBACPermissionsGranted", ReadinessMalformed, ""}}},
		{"untyped entry", conds(map[string]any{"type": int64(7), "status": "True"}, rbacOK, hookOK), true, nil},
		{"non-string status", conds(map[string]any{"type": "RBACPermissionsGranted", "status": true}, hookOK), false,
			[]want{{"RBACPermissionsGranted", ReadinessMalformed, ""}}},
		{"unexpected status value", conds(c("RBACPermissionsGranted", "true", "", "lower case"), hookOK), false,
			[]want{{"RBACPermissionsGranted", ReadinessMalformed, "lower case"}}},
		{"duplicate with one true", conds(c("RBACPermissionsGranted", "False", "", "x"), rbacOK, hookOK), true, nil},
		{"duplicate prefers false", conds(c("RBACPermissionsGranted", "Unknown", "", "u"), c("RBACPermissionsGranted", "False", "", "f"), hookOK), false,
			[]want{{"RBACPermissionsGranted", ReadinessFalse, "f"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := withStatus("konstapel-p-0123456789abcdef", tc.status)
			if got := KyvernoReady(o); got != tc.ready {
				t.Fatalf("KyvernoReady = %v, want %v", got, tc.ready)
			}
			ds := KyvernoReadiness(o)
			if (len(ds) == 0) != tc.ready || len(ds) != len(tc.want) {
				t.Fatalf("details %+v, want %+v", ds, tc.want)
			}
			for i, w := range tc.want {
				d := ds[i]
				if d.Policy != o.GetName() || d.Condition != w.cond || d.State != w.state || d.Message != w.why {
					t.Fatalf("detail %d = %+v, want %+v", i, d, w)
				}
			}
		})
	}
}

func TestKyvernoReadinessBoundsEngineText(t *testing.T) {
	long := strings.Repeat("é", 4*maxReadinessMessage) // two bytes per rune
	o := withStatus("p", conds(c("RBACPermissionsGranted", "False", strings.Repeat("R", 10*maxReadinessReason), "x"+long), c("WebhookConfigured", "True", "", "")))
	ds := KyvernoReadiness(o)
	if len(ds) != 1 {
		t.Fatalf("details %+v", ds)
	}
	if d := ds[0]; len(d.Reason) > maxReadinessReason || len(d.Message) > maxReadinessMessage || len(d.Message) < maxReadinessMessage-utf8.UTFMax ||
		!utf8.ValidString(d.Message) || !strings.HasPrefix(d.Message, "xé") {
		t.Fatalf("unbounded or split detail: reason %d, message %d bytes, valid %v", len(d.Reason), len(d.Message), utf8.ValidString(d.Message))
	}
}

// setStatus records Kyverno's view of an existing engine policy.
func setStatus(t *testing.T, cl client.Client, name string, status any) {
	t.Helper()
	live := &unstructured.Unstructured{}
	live.SetGroupVersionKind(ValidatingPolicyGVK)
	if err := cl.Get(context.Background(), client.ObjectKey{Name: name}, live); err != nil {
		t.Fatal(err)
	}
	if status == nil {
		delete(live.Object, "status")
	} else {
		live.Object["status"] = status
	}
	if err := cl.Update(context.Background(), live); err != nil {
		t.Fatal(err)
	}
}

// TestSyncReadinessDetailsKeepRetainedRevision runs the default Kyverno rule
// through a replacement whose new revision is False, Unknown, missing and
// malformed in turn. The previous revision stays retained throughout and is
// removed only once the replacement is ready; details only ever describe the
// NotReady replacement.
func TestSyncReadinessDetailsKeepRetainedRevision(t *testing.T) {
	ctx := context.Background()
	cl := fakeClient()
	d := &Delivery{Client: cl}
	v1 := desiredFor(t, "b1", pol, "sha256:r1", v1alpha1.ModeAudit)
	v2 := desiredFor(t, "b1", pol, "sha256:r2", v1alpha1.ModeDeny)
	ready := conds(c("RBACPermissionsGranted", "True", "", ""), c("WebhookConfigured", "True", "", ""))

	res, err := d.Sync(ctx, "b1", []*unstructured.Unstructured{v1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Ready(1) || !slices.Equal(res.NotReady, []string{v1.GetName()}) || len(res.Readiness) != 2 || res.Readiness[0].State != ReadinessMissing {
		t.Fatalf("fresh policy without status: %+v", res)
	}
	setStatus(t, cl, v1.GetName(), ready)
	if res, err = d.Sync(ctx, "b1", []*unstructured.Unstructured{v1}, nil); err != nil || !res.Ready(1) || len(res.Readiness) != 0 {
		t.Fatalf("ready policy: %+v, %v", res, err)
	}

	steps := []struct {
		name   string
		status any
		state  ReadinessState
	}{
		{"missing", nil, ReadinessMissing},
		{"false", conds(c("RBACPermissionsGranted", "False", "RBACNotGranted", ephemeral), c("WebhookConfigured", "True", "", "")), ReadinessFalse},
		{"unknown", conds(c("RBACPermissionsGranted", "Unknown", "", ""), c("WebhookConfigured", "True", "", "")), ReadinessUnknown},
		{"malformed", map[string]any{"conditionStatus": []any{"broken"}}, ReadinessMalformed},
	}
	for i, step := range steps {
		if i > 0 {
			setStatus(t, cl, v2.GetName(), step.status)
		}
		for range 2 {
			res, err = d.Sync(ctx, "b1", []*unstructured.Unstructured{v2}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if res.Ready(1) || !slices.Equal(res.Current, []string{v2.GetName()}) || !slices.Equal(res.NotReady, []string{v2.GetName()}) ||
				!slices.Equal(res.Retained, []string{v1.GetName()}) || len(res.Removed)+len(res.Conflicts) != 0 {
				t.Fatalf("%s: decision changed: %+v", step.name, res)
			}
			if len(res.Readiness) == 0 || res.Readiness[0].Policy != v2.GetName() || res.Readiness[0].State != step.state {
				t.Fatalf("%s: details %+v", step.name, res.Readiness)
			}
		}
	}
	if got := policyNames(t, cl); len(got) != 2 {
		t.Fatalf("retained revision withdrawn: %v", got)
	}

	setStatus(t, cl, v2.GetName(), ready)
	if res, err = d.Sync(ctx, "b1", []*unstructured.Unstructured{v2}, nil); err != nil {
		t.Fatal(err)
	}
	if !res.Ready(1) || !slices.Equal(res.Removed, []string{v1.GetName()}) || len(res.Retained)+len(res.Readiness) != 0 {
		t.Fatalf("ready replacement: %+v", res)
	}
}

// A stricter ReadyFunc decides readiness; delivery still attributes the
// policy even though every expected condition is True.
func TestSyncAttributesPolicyRejectedByReadyFunc(t *testing.T) {
	cl := fakeClient()
	v1 := desiredFor(t, "b1", pol, "sha256:r1", v1alpha1.ModeDeny)
	d := &Delivery{Client: cl, Ready: readyNames()}
	if _, err := d.Sync(context.Background(), "b1", []*unstructured.Unstructured{v1}, nil); err != nil {
		t.Fatal(err)
	}
	setStatus(t, cl, v1.GetName(), conds(c("RBACPermissionsGranted", "True", "", ""), c("WebhookConfigured", "True", "", "")))
	res, err := d.Sync(context.Background(), "b1", []*unstructured.Unstructured{v1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Ready(1) || !slices.Equal(res.NotReady, []string{v1.GetName()}) ||
		!slices.Equal(res.Readiness, []ReadinessDetail{{Policy: v1.GetName(), State: ReadinessUnknown}}) {
		t.Fatalf("result %+v", res)
	}
}
