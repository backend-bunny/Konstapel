package targeting

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

var recheckNow = time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

func rbacStatus(status string) map[string]any {
	return conds(c("RBACPermissionsGranted", status, "Failed", "Policy is not ready for reporting, missing permissions: get /v1, Resource=pods/ephemeralcontainers"),
		c("WebhookConfigured", "True", "Succeeded", "Webhook configured."))
}

// recheckEnv delivers one owned policy whose RBACPermissionsGranted is
// status and returns the client, the desired policy and the Sync result.
func recheckEnv(t *testing.T, status string, funcs *interceptor.Funcs) (client.Client, *unstructured.Unstructured, DeliveryResult) {
	t.Helper()
	c := fakeClient()
	if funcs != nil {
		c = interceptor.NewClient(c.(client.WithWatch), *funcs)
	}
	want := desiredFor(t, "b1", pol, "sha256:r1", v1alpha1.ModeDeny)
	d := &Delivery{Client: c}
	ctx := context.Background()
	if _, err := d.Sync(ctx, "b1", []*unstructured.Unstructured{want}, nil); err != nil {
		t.Fatal(err)
	}
	setStatus(t, c, want.GetName(), rbacStatus(status))
	res, err := d.Sync(ctx, "b1", []*unstructured.Unstructured{want}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, want, res
}

func get(t *testing.T, c client.Client, name string) *unstructured.Unstructured {
	t.Helper()
	o := &unstructured.Unstructured{}
	o.SetGroupVersionKind(ValidatingPolicyGVK)
	if err := c.Get(context.Background(), client.ObjectKey{Name: name}, o); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestRecheckCandidatesArePermissionFailuresOfCurrentPolicies(t *testing.T) {
	res := DeliveryResult{
		Current: []string{"p-false", "p-unknown", "p-missing", "p-malformed", "p-webhook", "p-both"},
		Readiness: []ReadinessDetail{
			{Policy: "p-both", Condition: "RBACPermissionsGranted", State: ReadinessFalse},
			{Policy: "p-both", Condition: "WebhookConfigured", State: ReadinessFalse},
			{Policy: "p-false", Condition: "RBACPermissionsGranted", State: ReadinessFalse},
			{Policy: "p-malformed", Condition: "RBACPermissionsGranted", State: ReadinessMalformed},
			{Policy: "p-missing", Condition: "RBACPermissionsGranted", State: ReadinessMissing},
			{Policy: "p-unknown", Condition: "RBACPermissionsGranted", State: ReadinessUnknown},
			{Policy: "p-webhook", Condition: "WebhookConfigured", State: ReadinessFalse},
			{Policy: "p-gone", Condition: "RBACPermissionsGranted", State: ReadinessFalse},
			{Policy: "p-unattributed", State: ReadinessUnknown},
		},
	}
	if got := RecheckCandidates(res); !slices.Equal(got, []string{"p-both", "p-false", "p-unknown"}) {
		t.Fatalf("candidates %v", got)
	}
	if got := RecheckCandidates(DeliveryResult{Current: []string{"p"}}); got != nil {
		t.Fatalf("a ready Sync has candidates: %v", got)
	}
}

func TestRecheckBackoffIsBounded(t *testing.T) {
	created := recheckNow.Add(-time.Hour)
	at := func(d time.Duration) time.Time { return recheckNow.Add(d) }
	stamp := func(n int, d time.Duration) string { return formatRecheck(n, at(d)) }
	cases := []struct {
		name       string
		annotation string
		created    time.Time
		attempt    int
		due        bool
	}{
		{"first recheck waits after creation", "", recheckNow.Add(-29 * time.Second), 1, false},
		{"first recheck due after creation", "", recheckNow.Add(-30 * time.Second), 1, true},
		{"second waits a minute", stamp(1, -59*time.Second), created, 2, false},
		{"second due after a minute", stamp(1, -time.Minute), created, 2, true},
		{"third after two minutes", stamp(2, -2*time.Minute), created, 3, true},
		{"fifth not before eight minutes", stamp(4, -8*time.Minute+time.Second), created, 5, false},
		{"capped at fifteen minutes", stamp(5, -15*time.Minute), created, 6, true},
		{"cap holds", stamp(5, -15*time.Minute+time.Second), created, 6, false},
		{"large counters stay capped", stamp(maxRecheckAttempt, -15*time.Minute), created, maxRecheckAttempt, true},
		{"a long gap starts again", stamp(9, -31*time.Minute), created, 1, true},
		{"just inside the gap keeps counting", stamp(9, -30*time.Minute), created, 10, true},
		{"a future time counts from creation", stamp(3, time.Hour), recheckNow.Add(-10 * time.Second), 1, false},
		{"unreadable counts from creation", "soon", created, 1, true},
		{"zero attempts are unreadable", "0@" + at(0).Format(time.RFC3339), created, 1, true},
		{"overflowing attempts are unreadable", fmt.Sprintf("%d@%s", maxRecheckAttempt+1, at(0).Format(time.RFC3339)), created, 1, true},
		{"unreadable time", "2@yesterday", recheckNow.Add(-time.Second), 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := &unstructured.Unstructured{}
			o.SetCreationTimestamp(metav1.NewTime(tc.created))
			if tc.annotation != "" {
				o.SetAnnotations(map[string]string{AnnotationReadinessRecheck: tc.annotation})
			}
			attempt, due := DefaultRecheckBackoff.due(o, recheckNow)
			if attempt != tc.attempt || due != tc.due {
				t.Fatalf("attempt %d due %v, want %d %v", attempt, due, tc.attempt, tc.due)
			}
		})
	}
	var total time.Duration
	for n := range 6 {
		total += DefaultRecheckBackoff.delay(n)
	}
	if want := 30*time.Second + time.Minute + 2*time.Minute + 4*time.Minute + 8*time.Minute + 15*time.Minute; total != want {
		t.Fatalf("documented schedule: %v, want %v", total, want)
	}
	for _, b := range []RecheckBackoff{{}, {Initial: time.Minute, Max: time.Second}, {Initial: -time.Second, Max: time.Minute}} {
		if _, err := (&Delivery{Client: fakeClient()}).Recheck(context.Background(), "b1", nil, DeliveryResult{}, recheckNow, b); err == nil {
			t.Fatalf("backoff %+v accepted", b)
		}
	}
}

// A recheck writes exactly one annotation and nothing else, once per backoff
// step, and stops when the policy is ready.
func TestRecheckWritesOnlyTheAnnotationWithinTheBackoff(t *testing.T) {
	c, want, res := recheckEnv(t, "False", nil)
	ctx := context.Background()
	d := &Delivery{Client: c}
	if got := RecheckCandidates(res); !slices.Equal(got, []string{want.GetName()}) {
		t.Fatalf("candidates %v from %+v", got, res)
	}
	before := get(t, c, want.GetName())
	out, err := d.Recheck(ctx, "b1", []*unstructured.Unstructured{want}, res, recheckNow, DefaultRecheckBackoff)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(out.Rechecked, []RecheckAttempt{{Policy: want.GetName(), Attempt: 1}}) || len(out.Conflicted) != 0 {
		t.Fatalf("recheck %+v", out)
	}
	after := get(t, c, want.GetName())
	annotations := after.GetAnnotations()
	if annotations[AnnotationReadinessRecheck] != "1@2026-11-27T12:00:00Z" {
		t.Fatalf("annotation %q", annotations[AnnotationReadinessRecheck])
	}
	delete(annotations, AnnotationReadinessRecheck)
	after.SetAnnotations(annotations)
	for _, field := range []string{"spec", "status"} {
		if !equalJSON(before.Object[field], after.Object[field]) {
			t.Fatalf("recheck changed %s", field)
		}
	}
	if !equalJSON(before.GetLabels(), after.GetLabels()) || !equalJSON(before.GetAnnotations(), after.GetAnnotations()) ||
		!equalJSON(before.GetOwnerReferences(), after.GetOwnerReferences()) || before.GetUID() != after.GetUID() || before.GetGeneration() != after.GetGeneration() {
		t.Fatal("recheck changed metadata other than its annotation")
	}

	// Not again before the next step, which is due a minute later.
	rv := get(t, c, want.GetName()).GetResourceVersion()
	for _, at := range []time.Duration{0, 5 * time.Second, 59 * time.Second} {
		if out, err := d.Recheck(ctx, "b1", []*unstructured.Unstructured{want}, res, recheckNow.Add(at), DefaultRecheckBackoff); err != nil || len(out.Rechecked) != 0 {
			t.Fatalf("recheck at +%v: %+v %v", at, out, err)
		}
	}
	if get(t, c, want.GetName()).GetResourceVersion() != rv {
		t.Fatal("a recheck that was not due wrote the policy")
	}
	out, err = d.Recheck(ctx, "b1", []*unstructured.Unstructured{want}, res, recheckNow.Add(time.Minute), DefaultRecheckBackoff)
	if err != nil || !slices.Equal(out.Rechecked, []RecheckAttempt{{Policy: want.GetName(), Attempt: 2}}) {
		t.Fatalf("second recheck %+v %v", out, err)
	}

	// Ready: delivery reports no candidates, and a stale result writes
	// nothing either, because the policy is read again first.
	setStatus(t, c, want.GetName(), rbacStatus("True"))
	ready, err := d.Sync(ctx, "b1", []*unstructured.Unstructured{want}, nil)
	if err != nil || !ready.Ready(1) || RecheckCandidates(ready) != nil {
		t.Fatalf("ready sync %+v %v", ready, err)
	}
	rv = get(t, c, want.GetName()).GetResourceVersion()
	if out, err := d.Recheck(ctx, "b1", []*unstructured.Unstructured{want}, res, recheckNow.Add(time.Hour), DefaultRecheckBackoff); err != nil || len(out.Rechecked) != 0 {
		t.Fatalf("recheck of a ready policy: %+v %v", out, err)
	}
	if get(t, c, want.GetName()).GetResourceVersion() != rv {
		t.Fatal("a ready policy was written")
	}
}

// Only the failure a recheck can address is rechecked.
func TestRecheckIgnoresOtherReadinessFailures(t *testing.T) {
	for name, status := range map[string]any{
		"webhook not configured": conds(c("RBACPermissionsGranted", "True", "", ""), c("WebhookConfigured", "False", "Failed", "")),
		"not evaluated yet":      nil,
		"unreadable conditions":  map[string]any{"conditionStatus": map[string]any{"conditions": "broken"}},
	} {
		t.Run(name, func(t *testing.T) {
			c, want, _ := recheckEnv(t, "False", nil)
			setStatus(t, c, want.GetName(), status)
			d := &Delivery{Client: c}
			res, err := d.Sync(context.Background(), "b1", []*unstructured.Unstructured{want}, nil)
			if err != nil || len(res.NotReady) != 1 || RecheckCandidates(res) != nil {
				t.Fatalf("sync %+v %v", res, err)
			}
			// Also when handed a result that claims a permission failure.
			stale := DeliveryResult{Current: res.Current, NotReady: res.NotReady,
				Readiness: []ReadinessDetail{{Policy: want.GetName(), Condition: RecheckCondition, State: ReadinessFalse}}}
			rv := get(t, c, want.GetName()).GetResourceVersion()
			if out, err := d.Recheck(context.Background(), "b1", []*unstructured.Unstructured{want}, stale, recheckNow, DefaultRecheckBackoff); err != nil || len(out.Rechecked) != 0 {
				t.Fatalf("recheck %+v %v", out, err)
			}
			if get(t, c, want.GetName()).GetResourceVersion() != rv {
				t.Fatal("policy written")
			}
		})
	}
}

// Policies Konstapel does not own, another binding's, another revision under
// the same name and superseded revisions are never written.
func TestRecheckNeverWritesPoliciesItShouldNot(t *testing.T) {
	ctx := context.Background()
	t.Run("unowned", func(t *testing.T) {
		c, want, res := recheckEnv(t, "False", nil)
		o := get(t, c, want.GetName())
		o.SetOwnerReferences(nil)
		if err := c.Update(ctx, o); err != nil {
			t.Fatal(err)
		}
		requireNoRecheck(t, c, want, res, "b1")
	})
	t.Run("another binding", func(t *testing.T) {
		c, want, res := recheckEnv(t, "False", nil)
		requireNoRecheck(t, c, want, res, "b2")
	})
	t.Run("another revision under the name", func(t *testing.T) {
		c, want, res := recheckEnv(t, "False", nil)
		o := get(t, c, want.GetName())
		annotations := o.GetAnnotations()
		annotations[AnnotationRevision] = "sha256:newer"
		o.SetAnnotations(annotations)
		if err := c.Update(ctx, o); err != nil {
			t.Fatal(err)
		}
		requireNoRecheck(t, c, want, res, "b1")
	})
	t.Run("not desired", func(t *testing.T) {
		c, _, res := recheckEnv(t, "False", nil)
		other := desiredFor(t, "b1", pol, "sha256:r2", v1alpha1.ModeDeny)
		if out, err := (&Delivery{Client: c}).Recheck(ctx, "b1", []*unstructured.Unstructured{other}, res, recheckNow, DefaultRecheckBackoff); err != nil || len(out.Rechecked) != 0 {
			t.Fatalf("recheck %+v %v", out, err)
		}
	})
	t.Run("deleted", func(t *testing.T) {
		c, want, res := recheckEnv(t, "False", nil)
		if err := c.Delete(ctx, get(t, c, want.GetName())); err != nil {
			t.Fatal(err)
		}
		if out, err := (&Delivery{Client: c}).Recheck(ctx, "b1", []*unstructured.Unstructured{want}, res, recheckNow, DefaultRecheckBackoff); err != nil || len(out.Rechecked)+len(out.Conflicted) != 0 {
			t.Fatalf("recheck %+v %v", out, err)
		}
	})
	t.Run("superseded revision", func(t *testing.T) {
		c, v1, _ := recheckEnv(t, "False", nil)
		v2 := desiredFor(t, "b1", pol, "sha256:r2", v1alpha1.ModeDeny)
		d := &Delivery{Client: c}
		if _, err := d.Sync(ctx, "b1", []*unstructured.Unstructured{v2}, nil); err != nil {
			t.Fatal(err)
		}
		setStatus(t, c, v2.GetName(), rbacStatus("False"))
		res, err := d.Sync(ctx, "b1", []*unstructured.Unstructured{v2}, nil)
		if err != nil || !slices.Equal(res.Retained, []string{v1.GetName()}) {
			t.Fatalf("sync %+v %v", res, err)
		}
		rv := get(t, c, v1.GetName()).GetResourceVersion()
		out, err := d.Recheck(ctx, "b1", []*unstructured.Unstructured{v2}, res, recheckNow, DefaultRecheckBackoff)
		if err != nil || !slices.Equal(out.Rechecked, []RecheckAttempt{{Policy: v2.GetName(), Attempt: 1}}) {
			t.Fatalf("recheck %+v %v", out, err)
		}
		if get(t, c, v1.GetName()).GetResourceVersion() != rv {
			t.Fatal("the retained revision was written")
		}
	})
}

func requireNoRecheck(t *testing.T, c client.Client, want *unstructured.Unstructured, res DeliveryResult, binding types.UID) {
	t.Helper()
	rv := get(t, c, want.GetName()).GetResourceVersion()
	out, err := (&Delivery{Client: c}).Recheck(context.Background(), binding, []*unstructured.Unstructured{want}, res, recheckNow, DefaultRecheckBackoff)
	if err != nil || len(out.Rechecked)+len(out.Conflicted) != 0 {
		t.Fatalf("recheck %+v %v", out, err)
	}
	if get(t, c, want.GetName()).GetResourceVersion() != rv {
		t.Fatal("policy written")
	}
}

// A conflicting write (Kyverno updating status, another replica) is never
// overwritten: the policy is read and judged again, a bounded number of times.
func TestRecheckRereadsAfterConflicts(t *testing.T) {
	ctx := context.Background()
	var concurrent func(client.WithWatch) error
	patches := 0
	funcs := &interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
		patches++
		if concurrent != nil {
			if err := concurrent(c); err != nil {
				return err
			}
		}
		return c.Patch(ctx, obj, patch, opts...)
	}}
	touch := func(key, value string) func(client.WithWatch) error {
		return func(c client.WithWatch) error {
			o := &unstructured.Unstructured{}
			o.SetGroupVersionKind(ValidatingPolicyGVK)
			list := &unstructured.UnstructuredList{}
			list.SetGroupVersionKind(ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
			if err := c.List(ctx, list); err != nil || len(list.Items) != 1 {
				return fmt.Errorf("list: %v", err)
			}
			*o = list.Items[0]
			annotations := o.GetAnnotations()
			annotations[key] = value
			o.SetAnnotations(annotations)
			return c.Update(ctx, o)
		}
	}

	t.Run("status written meanwhile", func(t *testing.T) {
		c, want, res := recheckEnv(t, "False", funcs)
		patches, concurrent = 0, nil
		once := touch("kyverno.io/other", "x")
		concurrent = func(c client.WithWatch) error { concurrent = nil; return once(c) }
		out, err := (&Delivery{Client: c}).Recheck(ctx, "b1", []*unstructured.Unstructured{want}, res, recheckNow, DefaultRecheckBackoff)
		if err != nil || !slices.Equal(out.Rechecked, []RecheckAttempt{{Policy: want.GetName(), Attempt: 1}}) || patches != 2 {
			t.Fatalf("recheck %+v %v after %d patches", out, err, patches)
		}
		a := get(t, c, want.GetName()).GetAnnotations()
		if a["kyverno.io/other"] != "x" || a[AnnotationReadinessRecheck] == "" {
			t.Fatalf("concurrent write lost or recheck missing: %v", a)
		}
	})
	t.Run("another replica rechecked meanwhile", func(t *testing.T) {
		c, want, res := recheckEnv(t, "False", funcs)
		patches = 0
		concurrent = func(c client.WithWatch) error {
			concurrent = nil
			return touch(AnnotationReadinessRecheck, formatRecheck(1, recheckNow))(c)
		}
		out, err := (&Delivery{Client: c}).Recheck(ctx, "b1", []*unstructured.Unstructured{want}, res, recheckNow.Add(time.Second), DefaultRecheckBackoff)
		if err != nil || len(out.Rechecked)+len(out.Conflicted) != 0 || patches != 1 {
			t.Fatalf("recheck %+v %v after %d patches", out, err, patches)
		}
		if got := get(t, c, want.GetName()).GetAnnotations()[AnnotationReadinessRecheck]; got != formatRecheck(1, recheckNow) {
			t.Fatalf("the other replica's recheck was overwritten: %q", got)
		}
	})
	t.Run("ready meanwhile", func(t *testing.T) {
		c, want, res := recheckEnv(t, "False", funcs)
		patches = 0
		concurrent = func(c client.WithWatch) error {
			concurrent = nil
			o := &unstructured.Unstructured{}
			o.SetGroupVersionKind(ValidatingPolicyGVK)
			if err := c.Get(ctx, client.ObjectKey{Name: want.GetName()}, o); err != nil {
				return err
			}
			o.Object["status"] = rbacStatus("True")
			return c.Update(ctx, o)
		}
		out, err := (&Delivery{Client: c}).Recheck(ctx, "b1", []*unstructured.Unstructured{want}, res, recheckNow, DefaultRecheckBackoff)
		if err != nil || len(out.Rechecked)+len(out.Conflicted) != 0 {
			t.Fatalf("recheck %+v %v", out, err)
		}
		if got := get(t, c, want.GetName()).GetAnnotations()[AnnotationReadinessRecheck]; got != "" {
			t.Fatalf("a ready policy was rechecked: %q", got)
		}
	})
	t.Run("conflicts persist", func(t *testing.T) {
		c, want, res := recheckEnv(t, "False", funcs)
		patches = 0
		n := 0
		concurrent = func(c client.WithWatch) error { n++; return touch("kyverno.io/other", fmt.Sprint(n))(c) }
		defer func() { concurrent = nil }()
		out, err := (&Delivery{Client: c}).Recheck(ctx, "b1", []*unstructured.Unstructured{want}, res, recheckNow, DefaultRecheckBackoff)
		if err != nil || len(out.Rechecked) != 0 || !slices.Equal(out.Conflicted, []string{want.GetName()}) || patches != recheckConflictRetries {
			t.Fatalf("recheck %+v %v after %d patches", out, err, patches)
		}
		if got := get(t, c, want.GetName()).GetAnnotations()[AnnotationReadinessRecheck]; got != "" {
			t.Fatalf("written despite conflicts: %q", got)
		}
	})
	t.Run("other errors stop", func(t *testing.T) {
		c, want, res := recheckEnv(t, "False", funcs)
		concurrent = func(client.WithWatch) error {
			return apierrors.NewForbidden(schema.GroupResource{Group: ValidatingPolicyGVK.Group, Resource: "validatingpolicies"}, want.GetName(), errors.New("no"))
		}
		defer func() { concurrent = nil }()
		if _, err := (&Delivery{Client: c}).Recheck(ctx, "b1", []*unstructured.Unstructured{want}, res, recheckNow, DefaultRecheckBackoff); !apierrors.IsForbidden(err) {
			t.Fatalf("error %v", err)
		}
	})
}

// A stale snapshot (a newer binding or profile, a former leader) writes
// nothing; the snapshot is only checked when a recheck is due.
func TestRecheckConfirmsTheSnapshotBeforeWriting(t *testing.T) {
	c, want, res := recheckEnv(t, "False", nil)
	calls := 0
	stale := &Delivery{Client: c, Current: func(context.Context) error { calls++; return ErrStaleSnapshot }}
	if _, err := stale.Recheck(context.Background(), "b1", []*unstructured.Unstructured{want}, res, recheckNow, DefaultRecheckBackoff); !errors.Is(err, ErrStaleSnapshot) || calls != 1 {
		t.Fatalf("error %v after %d checks", err, calls)
	}
	if got := get(t, c, want.GetName()).GetAnnotations()[AnnotationReadinessRecheck]; got != "" {
		t.Fatalf("written from a stale snapshot: %q", got)
	}
	o := get(t, c, want.GetName())
	o.SetCreationTimestamp(metav1.NewTime(recheckNow))
	annotations := o.GetAnnotations()
	annotations[AnnotationReadinessRecheck] = formatRecheck(1, recheckNow)
	o.SetAnnotations(annotations)
	if err := c.Update(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	calls = 0
	if _, err := stale.Recheck(context.Background(), "b1", []*unstructured.Unstructured{want}, res, recheckNow.Add(time.Second), DefaultRecheckBackoff); err != nil || calls != 0 {
		t.Fatalf("snapshot checked without a due recheck: %v, %d checks", err, calls)
	}
}
