package exception

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// Revocation admission (task 2.6). Cases follow
// testdata/exceptions/lifecycle-matrix.yaml: revocation-authentication-and-idempotence,
// revoke-retains-resource-and-renewal-is-explicit, create-and-renew-must-start-unrevoked,
// revoke-expired-forbidden-acceptance, revoke-with-unresolved-contributions and
// revocation-history-before-renewal-or-deletion.

const exceptionUID = types.UID("ex-1")

// accepted returns the exception as stored after alice created it at t0.
func accepted(t *testing.T, m *Mutator, v *Validator) *v1alpha1.ComplianceException {
	t.Helper()
	created, err := admit(t, m, v, request(t, admissionv1.Create, alice, exceptionObj("team-a", 1, nil), nil))
	if err != nil {
		t.Fatal(err)
	}
	created.UID, created.ResourceVersion = exceptionUID, "10"
	return created
}

// revoked returns a copy of stored with spec.revoked set, as a client would
// send it, optionally with extra annotations.
func revokedCopy(stored *v1alpha1.ComplianceException, annotations map[string]string) *v1alpha1.ComplianceException {
	ex := stored.DeepCopy()
	ex.Spec.Revoked = true
	for k, val := range annotations {
		if ex.Annotations == nil {
			ex.Annotations = map[string]string{}
		}
		ex.Annotations[k] = val
	}
	return ex
}

func revocationOf(t *testing.T, ex *v1alpha1.ComplianceException) Revocation {
	t.Helper()
	r, present, err := ParseRevocation(ex)
	if !present || err != nil {
		t.Fatalf("revocation record: present=%v err=%v", present, err)
	}
	return r
}

func denied(t *testing.T, what string, err error, reason string) {
	t.Helper()
	if err == nil || !strings.HasPrefix(err.Error(), reason+":") {
		t.Errorf("%s: want a %s denial, got %v", what, reason, err)
	}
}

func TestRevocationRecordsTheAuthenticatedCaller(t *testing.T) {
	m, v := newHandlers(t, world(t), t0)
	stored := accepted(t, m, v)
	acceptanceRecord := stored.Annotations[AcceptanceAnnotation]

	// A GitOps revocation with a forged record and a claimed human.
	at := t0.Add(time.Hour)
	m.Now = func() time.Time { return at }
	v.Now = m.Now
	forged, _ := json.Marshal(Revocation{ExceptionUID: "other", Revision: 1, Actor: Actor{Username: "platform-admin"}, RequestedAt: metav1.NewTime(t0)})
	req := revokedCopy(stored, map[string]string{RevocationAnnotation: string(forged), ClaimAnnotation: "carol, ticket SEC-7"})
	req.UID = "" // the request body need not carry the UID
	got, err := admit(t, m, v, request(t, admissionv1.Update, argo, req, stored))
	if err != nil {
		t.Fatal(err)
	}
	r := revocationOf(t, got)
	want := Revocation{ExceptionUID: exceptionUID, Revision: 1, RequestedAt: metav1.NewTime(at), Actor: Actor{Username: argo.Username, UID: argo.UID, Groups: argo.Groups}, Claim: "carol, ticket SEC-7"}
	if r.ExceptionUID != want.ExceptionUID || r.Revision != want.Revision || !r.RequestedAt.Equal(&want.RequestedAt) ||
		r.Actor.Username != want.Actor.Username || r.Actor.UID != want.Actor.UID || !slices.Equal(r.Actor.Groups, want.Actor.Groups) || r.Claim != want.Claim {
		t.Errorf("revocation = %+v, want %+v", r, want)
	}
	if !slices.Contains(got.Finalizers, RevocationFinalizer) {
		t.Errorf("finalizers = %v, want %s", got.Finalizers, RevocationFinalizer)
	}
	// The acceptance and its risk reason and expiry are unchanged.
	if got.Annotations[AcceptanceAnnotation] != acceptanceRecord || acceptanceOf(t, got).Actor.Username != "alice" ||
		got.Spec.Reason != stored.Spec.Reason || !got.Spec.ExpiresAt.Equal(&stored.Spec.ExpiresAt) || got.Spec.AcceptanceRevision != 1 {
		t.Errorf("revocation changed the acceptance: %+v", got)
	}

	// Repeating the revocation later, as another editor, keeps the first
	// actor and time; so do unrelated edits.
	got.UID = exceptionUID
	m.Now = func() time.Time { return at.Add(time.Minute) }
	v.Now = m.Now
	again := got.DeepCopy()
	again.Labels = map[string]string{"re-applied": "true"}
	repeated, err := admit(t, m, v, request(t, admissionv1.Update, dave, again, got))
	if err != nil {
		t.Fatalf("repeat revoke: %v", err)
	}
	if repeated.Annotations[RevocationAnnotation] != got.Annotations[RevocationAnnotation] {
		t.Errorf("repeat revoke rewrote the record: %s", repeated.Annotations[RevocationAnnotation])
	}
}

// Revocation resolves nothing: an expired, Forbidden or unresolvable
// acceptance is revoked with the cluster unreadable.
func TestRevocationNeedsNoEligibilityOrFutureExpiry(t *testing.T) {
	m, v := newHandlers(t, world(t), t0)
	stored := accepted(t, m, v)
	m.Reader, m.Resolver = unreadable{}, failing{}
	// Long after expiresAt.
	m.Now = func() time.Time { return t0.Add(30 * 24 * time.Hour) }
	v.Now = m.Now
	got, err := admit(t, m, v, request(t, admissionv1.Update, alice, revokedCopy(stored, nil), stored))
	if err != nil {
		t.Fatalf("revoke of an expired, unresolvable acceptance: %v", err)
	}
	if r := revocationOf(t, got); r.Actor.Username != "alice" || r.Revision != 1 {
		t.Errorf("revocation = %+v", r)
	}

	// The same holds in a namespace whose policy is Forbidden today: the
	// exception was accepted earlier, before the restriction.
	prod := stored.DeepCopy()
	prod.Namespace = "team-prod"
	m2, v2 := newHandlers(t, world(t), t0)
	if _, err := admit(t, m2, v2, request(t, admissionv1.Update, alice, revokedCopy(prod, nil), prod)); err != nil {
		t.Errorf("revoke under a Forbidden contribution: %v", err)
	}
	if _, err := admit(t, m2, v2, request(t, admissionv1.Create, alice, exceptionObj("team-prod", 1, nil), nil)); err == nil || !strings.Contains(err.Error(), ReasonForbidden) {
		t.Errorf("a new acceptance in team-prod must be Forbidden: %v", err)
	}
}

func TestRevocationTransitions(t *testing.T) {
	m, v := newHandlers(t, world(t), t0)
	stored := accepted(t, m, v)
	revoked, err := admit(t, m, v, request(t, admissionv1.Update, alice, revokedCopy(stored, nil), stored))
	if err != nil {
		t.Fatal(err)
	}
	revoked.UID = exceptionUID
	later := t0.Add(2 * time.Hour)
	m.Now = func() time.Time { return later }
	v.Now = m.Now

	createRevoked := exceptionObj("team-a", 1, nil)
	createRevoked.Spec.Revoked = true
	renewAndRevoke := stored.DeepCopy()
	renewAndRevoke.Spec.AcceptanceRevision, renewAndRevoke.Spec.Revoked = 2, true
	renewAndRevoke.Spec.ExpiresAt = metav1.NewTime(later.Add(24 * time.Hour))
	cleared := revoked.DeepCopy()
	cleared.Spec.Revoked = false // an explicit false and an omitted field decode alike
	renewRevoked := revoked.DeepCopy()
	renewRevoked.Spec.AcceptanceRevision, renewRevoked.Spec.Revoked = 2, false
	renewRevoked.Spec.Reason, renewRevoked.Spec.ExpiresAt = "fresh acceptance", metav1.NewTime(later.Add(24*time.Hour))
	renewRevokedAgain := renewRevoked.DeepCopy()
	renewRevokedAgain.Spec.Revoked = true

	cases := []struct {
		name     string
		op       admissionv1.Operation
		obj, old *v1alpha1.ComplianceException
		reason   string
	}{
		{"create revoked", admissionv1.Create, createRevoked, nil, ReasonInvalidRevocationTransition},
		{"renew and revoke together", admissionv1.Update, renewAndRevoke, stored, ReasonInvalidRevocationTransition},
		{"same-revision reactivation", admissionv1.Update, cleared, revoked, ReasonRenewalRequired},
		// Until the revocation is persisted independently (task 3.6), this
		// resource holds its only copy.
		{"renew a revoked revision", admissionv1.Update, renewRevoked, revoked, ReasonRevocationHistoryPending},
		{"renew a revoked revision into revoked", admissionv1.Update, renewRevokedAgain, revoked, ReasonInvalidRevocationTransition},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := request(t, c.op, alice, c.obj, c.old)
			// Both webhooks deny on their own, before resolving anything.
			if resp := m.Handle(context.Background(), req); resp.Allowed || !strings.HasPrefix(resp.Result.Message, c.reason+":") {
				t.Errorf("mutating webhook: %+v", resp.Result)
			}
			if resp := v.Handle(context.Background(), req); resp.Allowed || !strings.HasPrefix(resp.Result.Message, c.reason+":") {
				t.Errorf("validating webhook: %+v", resp.Result)
			}
		})
	}
}

// Without the mutating webhook, a caller-written revocation record must
// still match the operation.
func TestValidatorRejectsRevocationRecordsOfOtherOperations(t *testing.T) {
	m, v := newHandlers(t, world(t), t0)
	stored := accepted(t, m, v)
	at := t0.Add(time.Hour)
	v.Now = func() time.Time { return at }
	good := Revocation{ExceptionUID: exceptionUID, Revision: 1, RequestedAt: metav1.NewTime(at), Actor: Actor{Username: alice.Username, UID: alice.UID, Groups: alice.Groups}}
	cases := map[string]func(r *Revocation, ex *v1alpha1.ComplianceException){
		"other actor": func(r *Revocation, _ *v1alpha1.ComplianceException) { r.Actor.Username = "platform-admin" },
		"other uid":   func(r *Revocation, _ *v1alpha1.ComplianceException) { r.Actor.UID = "u-admin" },
		"extra group": func(r *Revocation, _ *v1alpha1.ComplianceException) {
			r.Actor.Groups = append(r.Actor.Groups, "system:masters")
		},
		"other exception":   func(r *Revocation, _ *v1alpha1.ComplianceException) { r.ExceptionUID = "ex-0" },
		"other revision":    func(r *Revocation, _ *v1alpha1.ComplianceException) { r.Revision = 2 },
		"backdated":         func(r *Revocation, _ *v1alpha1.ComplianceException) { r.RequestedAt = metav1.NewTime(t0) },
		"claim mismatch":    func(_ *Revocation, ex *v1alpha1.ComplianceException) { ex.Annotations[ClaimAnnotation] = "ticket" },
		"missing finalizer": func(_ *Revocation, ex *v1alpha1.ComplianceException) { ex.Finalizers = nil },
		"missing record":    nil,
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ex := revokedCopy(stored, nil)
			ex.Finalizers = []string{RevocationFinalizer}
			if mutate != nil {
				r := good
				r.Actor.Groups = slices.Clone(good.Actor.Groups)
				mutate(&r, ex)
				raw, _ := json.Marshal(r)
				ex.Annotations[RevocationAnnotation] = string(raw)
			}
			resp := v.Handle(context.Background(), request(t, admissionv1.Update, alice, ex, stored))
			if resp.Allowed || !strings.HasPrefix(resp.Result.Message, ReasonProtectedField+":") {
				t.Errorf("want a %s denial, got %+v", ReasonProtectedField, resp.Result)
			}
		})
	}
	ex := revokedCopy(stored, nil)
	ex.Finalizers = []string{RevocationFinalizer}
	raw, _ := json.Marshal(good)
	ex.Annotations[RevocationAnnotation] = string(raw)
	if resp := v.Handle(context.Background(), request(t, admissionv1.Update, alice, ex, stored)); !resp.Allowed {
		t.Errorf("matching record rejected: %s", resp.Result.Message)
	}
}

// Outside the revoking operation, the record and the finalizer cannot be
// written, changed or removed.
func TestRevocationHistoryIsProtected(t *testing.T) {
	m, v := newHandlers(t, world(t), t0)
	stored := accepted(t, m, v)
	revoked, err := admit(t, m, v, request(t, admissionv1.Update, alice, revokedCopy(stored, nil), stored))
	if err != nil {
		t.Fatal(err)
	}
	revoked.UID = exceptionUID
	r := revocationOf(t, revoked)
	rewritten := r
	rewritten.Actor = Actor{Username: "platform-admin"}
	rewrittenRaw, _ := json.Marshal(rewritten)

	edits := map[string]struct {
		old  *v1alpha1.ComplianceException
		edit func(ex *v1alpha1.ComplianceException)
	}{
		"rewrite the record": {revoked, func(ex *v1alpha1.ComplianceException) { ex.Annotations[RevocationAnnotation] = string(rewrittenRaw) }},
		"remove the record":  {revoked, func(ex *v1alpha1.ComplianceException) { delete(ex.Annotations, RevocationAnnotation) }},
		"remove the finalizer": {revoked, func(ex *v1alpha1.ComplianceException) {
			ex.Finalizers = slices.DeleteFunc(ex.Finalizers, func(f string) bool { return f == RevocationFinalizer })
		}},
		"remove the finalizer while terminating": {terminating(revoked), func(ex *v1alpha1.ComplianceException) { ex.Finalizers = nil }},
		"add a record without revoking": {stored, func(ex *v1alpha1.ComplianceException) {
			ex.Annotations[RevocationAnnotation] = revoked.Annotations[RevocationAnnotation]
		}},
		"add the finalizer without revoking": {stored, func(ex *v1alpha1.ComplianceException) { ex.Finalizers = []string{RevocationFinalizer} }},
	}
	for name, c := range edits {
		t.Run(name, func(t *testing.T) {
			ex := c.old.DeepCopy()
			c.edit(ex)
			_, err := admit(t, m, v, request(t, admissionv1.Update, alice, ex, c.old))
			denied(t, name, err, ReasonProtectedField)
		})
	}
	// Creation never carries revocation history.
	forged := exceptionObj("team-a", 1, map[string]string{RevocationAnnotation: revoked.Annotations[RevocationAnnotation]})
	_, err = admit(t, m, v, request(t, admissionv1.Create, alice, forged, nil))
	denied(t, "create with a revocation record", err, ReasonProtectedField)
	withFinalizer := exceptionObj("team-a", 1, nil)
	withFinalizer.Finalizers = []string{RevocationFinalizer}
	_, err = admit(t, m, v, request(t, admissionv1.Create, alice, withFinalizer, nil))
	denied(t, "create with the revocation finalizer", err, ReasonProtectedField)
	// Other finalizers stay the caller's business.
	other := revoked.DeepCopy()
	other.Finalizers = append(other.Finalizers, "example.com/team")
	if _, err := admit(t, m, v, request(t, admissionv1.Update, alice, other, revoked)); err != nil {
		t.Errorf("another finalizer: %v", err)
	}
}

// unreadable fails every read, like an unavailable API server.
type unreadable struct{}

func (unreadable) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("api unavailable")
}

func (unreadable) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("api unavailable")
}

func terminating(ex *v1alpha1.ComplianceException) *v1alpha1.ComplianceException {
	out := ex.DeepCopy()
	now := metav1.NewTime(t0.Add(3 * time.Hour))
	out.DeletionTimestamp = &now
	return out
}

func TestRevocationDryRunWritesNothing(t *testing.T) {
	c := world(t)
	m, v := newHandlers(t, c, t0)
	stored := accepted(t, m, v)
	req := request(t, admissionv1.Update, alice, revokedCopy(stored, nil), stored)
	req.DryRun = ptr.To(true)
	before := snapshot(t, c)
	got, err := admit(t, m, v, req)
	if err != nil {
		t.Fatal(err)
	}
	if revocationOf(t, got).Actor.Username != "alice" || !slices.Contains(got.Finalizers, RevocationFinalizer) {
		t.Error("a dry run should show the revocation that would be recorded")
	}
	if after := snapshot(t, c); after != before {
		t.Error("revocation admission changed cluster state")
	}
}

// A resource stored before spec.revoked existed decodes as unrevoked; a
// metadata edit that omits the field neither renews nor revokes it.
func TestOmittedRevokedOnAStoredResourceDoesNotRenew(t *testing.T) {
	m, v := newHandlers(t, world(t), t0)
	stored := accepted(t, m, v)
	legacy := strip(t, stored, "revoked")
	edited := strip(t, stored, "revoked")
	edited.Labels = map[string]string{"edited": "true"}
	m.Now = func() time.Time { return t0.Add(time.Hour) }
	v.Now = m.Now
	req := request(t, admissionv1.Update, dave, edited, legacy)
	if resp := m.Handle(context.Background(), req); !resp.Allowed || len(resp.Patches) != 0 {
		t.Fatalf("metadata edit of a stored resource: allowed=%v patches=%v", resp.Allowed, resp.Patches)
	}
	got, err := admit(t, m, v, req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.Revoked || got.Annotations[AcceptanceAnnotation] != stored.Annotations[AcceptanceAnnotation] || got.Annotations[RevocationAnnotation] != "" {
		t.Errorf("omitted revoked changed the acceptance lifecycle: %+v", got)
	}
}

// strip returns ex as its JSON would be stored without the spec field.
func strip(t *testing.T, ex *v1alpha1.ComplianceException, field string) *v1alpha1.ComplianceException {
	t.Helper()
	raw, _ := json.Marshal(ex)
	var o map[string]any
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	delete(o["spec"].(map[string]any), field)
	raw, _ = json.Marshal(o)
	out := &v1alpha1.ComplianceException{}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatal(err)
	}
	return out
}

// The revocation denial reasons are the lifecycle fixture vocabulary.
func TestRevocationReasonsMatchTheFixtures(t *testing.T) {
	reasons := map[string]bool{}
	for _, c := range loadMatrix(t).Cases {
		for _, s := range c.Steps {
			if r, ok := s.Expect["reason"].(string); ok {
				reasons[r] = true
			}
		}
	}
	for _, r := range []string{ReasonInvalidRevocationTransition, ReasonRenewalRequired, ReasonRevocationHistoryPending, ReasonProtectedField} {
		if !reasons[r] {
			t.Errorf("reason %s is not used by testdata/exceptions/lifecycle-matrix.yaml", r)
		}
	}
}
