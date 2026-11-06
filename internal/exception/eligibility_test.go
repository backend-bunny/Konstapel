package exception

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// Cases follow testdata/exceptions/lifecycle-matrix.yaml: forbidden-overlap-blocks,
// unresolved-mapping-blocks, lifetime-limits and renewal-rechecks-eligibility.

func expiring(ns string, d time.Duration) *v1alpha1.ComplianceException {
	ex := exceptionObj(ns, 1, nil)
	ex.Spec.ExpiresAt = metav1.NewTime(t0.Add(d))
	return ex
}

func wantDenied(t *testing.T, err error, reason string, mentions ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("admitted, want %s", reason)
	}
	if !strings.HasPrefix(err.Error(), reason+": ") {
		t.Fatalf("got %q, want reason %s", err, reason)
	}
	for _, m := range mentions {
		if !strings.Contains(err.Error(), m) {
			t.Errorf("%q does not mention %q", err, m)
		}
	}
}

func TestForbiddenOverlapRejectsAcceptance(t *testing.T) {
	c := world(t)
	m, v := newHandlers(t, c, t0)
	_, err := admit(t, m, v, request(t, admissionv1.Create, alice, exceptionObj("team-prod", 1, nil), nil))
	wantDenied(t, err, ReasonForbidden, `"pci"`, "team-prod")
	if strings.Contains(err.Error(), `"baseline"`) {
		t.Errorf("the permissive contribution is named as restrictive: %v", err)
	}
	// Elsewhere the same policy remains self-service.
	if _, err := admit(t, m, v, request(t, admissionv1.Create, alice, exceptionObj("team-a", 1, nil), nil)); err != nil {
		t.Fatalf("team-a: %v", err)
	}
}

func TestUnresolvedOrUnappliedPolicyRejectsAcceptance(t *testing.T) {
	c := world(t)
	m, v := newHandlers(t, c, t0)
	ex := exceptionObj("team-a", 1, nil)
	ex.Spec.Policy = "no-such-policy"
	_, err := admit(t, m, v, request(t, admissionv1.Create, alice, ex, nil))
	wantDenied(t, err, ReasonNotApplicable, "no-such-policy")

	// The bound profile's content becomes unavailable: configuration is
	// unresolved, which never permits an exception.
	p := &v1alpha1.ComplianceProfile{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "self-service"}, p); err != nil {
		t.Fatal(err)
	}
	p.Spec.Bundle.Digest = "sha256:" + strings.Repeat("2", 64)
	if err := c.Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	_, err = admit(t, m, v, request(t, admissionv1.Create, alice, exceptionObj("team-a", 1, nil), nil))
	wantDenied(t, err, ReasonUnresolved, "ContentUnavailable")
}

func TestLifetimeLimits(t *testing.T) {
	c := world(t)
	// A second self-service binding with a shorter limit overlaps team-a.
	short := profile("short", v1alpha1.ExceptionsSelfService, 24*time.Hour)
	if err := c.Create(context.Background(), short); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(context.Background(), binding("strict", "short", nil)); err != nil {
		t.Fatal(err)
	}
	m, v := newHandlers(t, c, t0)
	cases := []struct {
		name   string
		expiry time.Duration
		reason string
	}{
		{"already elapsed", -time.Second, ReasonExpiryElapsed},
		{"at the acceptance time", 0, ReasonExpiryElapsed},
		{"beyond the shorter overlapping maximum", 24*time.Hour + time.Second, ReasonLifetimeExceeded},
		{"beyond the longer maximum", 721 * time.Hour, ReasonLifetimeExceeded},
		{"exactly the shortest maximum", 24 * time.Hour, ""},
		{"within the shortest maximum", time.Hour, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := admit(t, m, v, request(t, admissionv1.Create, alice, expiring("team-a", tc.expiry), nil))
			if tc.reason == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantDenied(t, err, tc.reason)
		})
	}
}

func TestRenewalRechecksEligibilityAndLifetime(t *testing.T) {
	c := world(t)
	m, v := newHandlers(t, c, t0)
	created, err := admit(t, m, v, request(t, admissionv1.Create, alice, expiring("team-a", 7*24*time.Hour), nil))
	if err != nil {
		t.Fatal(err)
	}
	later := t0.Add(6 * 24 * time.Hour)
	m.Now = func() time.Time { return later }
	v.Now = m.Now
	renew := func(expiry time.Time) *v1alpha1.ComplianceException {
		r := created.DeepCopy()
		r.Spec.AcceptanceRevision = 2
		r.Spec.Reason = "renewed"
		r.Spec.ExpiresAt = metav1.NewTime(expiry)
		return r
	}
	// The lifetime is measured from the renewal, not the original acceptance.
	if _, err := admit(t, m, v, request(t, admissionv1.Update, dave, renew(later.Add(720*time.Hour+time.Second)), created)); err == nil {
		t.Fatal("renewal beyond the maximum lifetime was admitted")
	} else {
		wantDenied(t, err, ReasonLifetimeExceeded)
	}

	// Central eligibility becomes Forbidden before the renewal.
	p := &v1alpha1.ComplianceProfile{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "self-service"}, p); err != nil {
		t.Fatal(err)
	}
	p.Spec.Policies[0].Exceptions = v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsForbidden}
	p.Generation++
	if err := c.Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	_, err = admit(t, m, v, request(t, admissionv1.Update, dave, renew(later.Add(24*time.Hour)), created))
	wantDenied(t, err, ReasonForbidden, `"baseline"`)

	// A metadata edit is not an acceptance and is not re-checked.
	edited := created.DeepCopy()
	edited.Labels = map[string]string{"x": "y"}
	if _, err := admit(t, m, v, request(t, admissionv1.Update, dave, edited, created)); err != nil {
		t.Fatalf("metadata edit: %v", err)
	}
}

// Without the mutating webhook, a caller-written record that claims an
// ineligible or over-long acceptance is still rejected.
func TestValidatorChecksTheRecordItself(t *testing.T) {
	m, v := newHandlers(t, world(t), t0)
	good, err := m.record(context.Background(), request(t, admissionv1.Create, alice, exceptionObj("team-a", 1, nil), nil))
	if err != nil {
		t.Fatal(err)
	}
	a := acceptanceOf(t, good)
	a.Eligibility.Effective = v1alpha1.ExceptionsForbidden
	a.Eligibility.MaxLifetime = nil
	raw, _ := json.Marshal(a)
	ex := exceptionObj("team-a", 1, map[string]string{AcceptanceAnnotation: string(raw)})
	resp := v.Handle(context.Background(), request(t, admissionv1.Create, alice, ex, nil))
	if resp.Allowed || !strings.HasPrefix(resp.Result.Message, ReasonForbidden) {
		t.Errorf("forbidden record: allowed=%v %q", resp.Allowed, resp.Result.Message)
	}

	a = acceptanceOf(t, good)
	raw, _ = json.Marshal(a)
	long := exceptionObj("team-a", 1, map[string]string{AcceptanceAnnotation: string(raw)})
	long.Spec.ExpiresAt = metav1.NewTime(t0.Add(721 * time.Hour))
	resp = v.Handle(context.Background(), request(t, admissionv1.Create, alice, long, nil))
	if resp.Allowed || !strings.HasPrefix(resp.Result.Message, ReasonLifetimeExceeded) {
		t.Errorf("over-long record: allowed=%v %q", resp.Allowed, resp.Result.Message)
	}
}
