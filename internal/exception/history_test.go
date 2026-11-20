package exception

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Independent revocation records (task 3.6). Cases follow
// testdata/exceptions/lifecycle-matrix.yaml:
// revocation-history-before-renewal-or-deletion and
// revoke-retains-resource-and-renewal-is-explicit.

// revokedStored returns the exception as stored after alice created it at t0
// and argo revoked it an hour later with a claim, plus the time of the
// revocation.
func revokedStored(t *testing.T, m *Mutator, v *Validator) (*v1alpha1.ComplianceException, time.Time) {
	t.Helper()
	stored := accepted(t, m, v)
	at := t0.Add(time.Hour)
	m.Now = func() time.Time { return at }
	v.Now = m.Now
	got, err := admit(t, m, v, request(t, admissionv1.Update, argo, revokedCopy(stored, map[string]string{ClaimAnnotation: "carol, SEC-7"}), stored))
	if err != nil {
		t.Fatal(err)
	}
	got.UID, got.ResourceVersion = exceptionUID, "11"
	return got, at
}

// persist writes the record of ex's revocation as the controller does.
func persist(t *testing.T, c client.Client, ex *v1alpha1.ComplianceException) *corev1.ConfigMap {
	t.Helper()
	rec, err := NewRevocationRecord(ex, historyNamespace)
	if err != nil {
		t.Fatal(err)
	}
	cm, _, err := rec.ConfigMap(historyNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Create(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
	return cm
}

// released returns ex as stored after the controller released its finalizer.
func released(ex *v1alpha1.ComplianceException) *v1alpha1.ComplianceException {
	out := ex.DeepCopy()
	out.Finalizers = slices.DeleteFunc(out.Finalizers, func(f string) bool { return f == RevocationFinalizer })
	out.ResourceVersion = "12"
	return out
}

func TestRevocationRecordCopiesTheAdmissionRecord(t *testing.T) {
	m, v := newHandlers(t, world(t), t0)
	ex, at := revokedStored(t, m, v)
	// A later caller-owned claim edit does not reach the record: it copies
	// the claim admission recorded with the revocation.
	ex.Annotations[ClaimAnnotation] = "mallory"
	rec, err := NewRevocationRecord(ex, historyNamespace)
	if err != nil {
		t.Fatal(err)
	}
	stored := revocationOf(t, ex)
	switch {
	case rec.Version != RevocationRecordVersion || rec.Exception.UID != exceptionUID || rec.Exception.Name != "priv" || rec.Exception.Namespace != "team-a":
		t.Errorf("record identity = %+v", rec)
	case rec.AcceptanceRevision != 1 || rec.Policy != policy || rec.Cluster != cluster || rec.Namespace != (targeting.NamespaceRef{Name: "team-a", UID: "ns-a-1"}):
		t.Errorf("record scope = %+v", rec)
	case rec.Revocation.Actor.Username != argo.Username || rec.Revocation.Actor.UID != argo.UID || !slices.Equal(rec.Revocation.Actor.Groups, argo.Groups):
		t.Errorf("record actor = %+v", rec.Revocation.Actor)
	case !rec.Revocation.RequestedAt.Time.Equal(at) || rec.Revocation.Claim != "carol, SEC-7" || rec.Revocation.Claim != stored.Claim:
		t.Errorf("record request = %+v", rec.Revocation)
	case rec.AcceptanceUnavailable != "":
		t.Errorf("acceptance unavailable: %s", rec.AcceptanceUnavailable)
	}
	// The acceptance reference is the snapshot the acceptance record
	// produces; the record refers to it and copies nothing into it.
	snap, err := NewSnapshot(ex, acceptanceOf(t, ex))
	if err != nil {
		t.Fatal(err)
	}
	snapCM, snapDigest, _ := snap.ConfigMap(historyNamespace)
	want := v1alpha1.AcceptanceSnapshotReference{Revision: 1, Snapshot: historyNamespace + "/" + snapCM.Name, Digest: snapDigest}
	if rec.Acceptance == nil || *rec.Acceptance != want {
		t.Errorf("acceptance reference = %+v, want %+v", rec.Acceptance, want)
	}
	if snap.Actor.Username != "alice" {
		t.Errorf("the snapshot names the accepting actor, got %+v", snap.Actor)
	}

	cm, digest, err := rec.ConfigMap(historyNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if cm.Name != "revocation-ex-1-1" || cm.Namespace != historyNamespace || cm.Immutable == nil || !*cm.Immutable || len(cm.OwnerReferences) != 0 {
		t.Errorf("record configmap %s/%s immutable=%v owners=%v", cm.Namespace, cm.Name, cm.Immutable, cm.OwnerReferences)
	}
	for k, val := range map[string]string{
		targeting.LabelManagedBy: targeting.ManagedByValue, LabelComponent: ComponentRevocation, LabelExceptionUID: "ex-1",
		LabelAcceptanceRevision: "1", LabelNamespaceUID: "ns-a-1", targeting.LabelPolicyHash: targeting.PolicyHash(policy),
	} {
		if cm.Labels[k] != val {
			t.Errorf("label %s = %q, want %q", k, cm.Labels[k], val)
		}
	}
	back, gotDigest, err := RevocationRecordFrom(cm)
	if err != nil || gotDigest != digest {
		t.Fatalf("read back: %v, digest %s want %s", err, gotDigest, digest)
	}
	if err := back.Matches(cm, stored); err != nil {
		t.Errorf("record does not match its own revocation: %v", err)
	}
	// Two controllers build the same record from the same resource.
	again, _ := NewRevocationRecord(ex.DeepCopy(), historyNamespace)
	if _, d2, _ := again.Document(); d2 != digest {
		t.Errorf("records differ between builds: %s %s", digest, d2)
	}
}

// Revocation needs no current eligibility, so neither does its record: an
// expired acceptance and one without a usable acceptance record still get
// one, built from the stored resource alone.
func TestRevocationRecordWithoutCurrentAcceptance(t *testing.T) {
	m, v := newHandlers(t, world(t), t0)
	ex, _ := revokedStored(t, m, v)
	expired := ex.DeepCopy()
	expired.Spec.ExpiresAt = metav1.NewTime(t0.Add(-time.Hour))
	if rec, err := NewRevocationRecord(expired, historyNamespace); err != nil || rec.Acceptance == nil {
		t.Errorf("expired acceptance: %+v %v", rec, err)
	}
	missing := ex.DeepCopy()
	delete(missing.Annotations, AcceptanceAnnotation)
	rec, err := NewRevocationRecord(missing, historyNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Acceptance != nil || rec.AcceptanceUnavailable == "" || rec.Namespace.Name != "team-a" || rec.Namespace.UID != "" || rec.Revocation.Actor.Username != argo.Username {
		t.Errorf("record without an acceptance = %+v", rec)
	}
	if cm, _, _ := rec.ConfigMap(historyNamespace); cm.Labels[LabelNamespaceUID] != "" {
		t.Errorf("unknown namespace UID labelled %q", cm.Labels[LabelNamespaceUID])
	}
	unreadable := ex.DeepCopy()
	unreadable.Annotations[AcceptanceAnnotation] = "{"
	if rec, err := NewRevocationRecord(unreadable, historyNamespace); err != nil || rec.Acceptance != nil || rec.AcceptanceUnavailable == "" {
		t.Errorf("unreadable acceptance: %+v %v", rec, err)
	}
}

func TestRevocationRecordNeedsTheAdmissionRecord(t *testing.T) {
	m, v := newHandlers(t, world(t), t0)
	ex, _ := revokedStored(t, m, v)
	cases := map[string]func(ex *v1alpha1.ComplianceException){
		"no record":      func(ex *v1alpha1.ComplianceException) { delete(ex.Annotations, RevocationAnnotation) },
		"unreadable":     func(ex *v1alpha1.ComplianceException) { ex.Annotations[RevocationAnnotation] = "{" },
		"not revoked":    func(ex *v1alpha1.ComplianceException) { ex.Spec.Revoked = false },
		"other uid":      func(ex *v1alpha1.ComplianceException) { ex.UID = "ex-2" },
		"other revision": func(ex *v1alpha1.ComplianceException) { ex.Spec.AcceptanceRevision = 2 },
		"no actor": func(ex *v1alpha1.ComplianceException) {
			r := revocationOf(t, ex)
			r.Actor = Actor{}
			raw, _ := json.Marshal(r)
			ex.Annotations[RevocationAnnotation] = string(raw)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := ex.DeepCopy()
			mutate(e)
			if rec, err := NewRevocationRecord(e, historyNamespace); err == nil {
				t.Errorf("record built: %+v", rec)
			}
		})
	}
	if _, err := NewRevocationRecord(accepted(t, m, v), historyNamespace); !errors.Is(err, ErrNoRevocation) {
		t.Errorf("unrevoked exception: %v", err)
	}
}

// A record is accepted only as an immutable Konstapel record whose
// document matches its digest and holds exactly the stored revocation.
func TestRevocationRecordVerification(t *testing.T) {
	m, v := newHandlers(t, world(t), t0)
	ex, _ := revokedStored(t, m, v)
	rec, _ := NewRevocationRecord(ex, historyNamespace)
	good, _, _ := rec.ConfigMap(historyNamespace)
	want := revocationOf(t, ex)
	forge := func(edit func(r *RevocationRecord)) *corev1.ConfigMap {
		r := *rec
		edit(&r)
		cm, _, _ := r.ConfigMap(historyNamespace)
		return cm
	}
	cases := map[string]*corev1.ConfigMap{
		"mutable": func() *corev1.ConfigMap { cm := good.DeepCopy(); cm.Immutable = nil; return cm }(),
		"foreign": func() *corev1.ConfigMap {
			cm := good.DeepCopy()
			cm.Labels[targeting.LabelManagedBy] = "someone"
			return cm
		}(),
		"a snapshot": func() *corev1.ConfigMap {
			cm := good.DeepCopy()
			cm.Labels[LabelComponent] = ComponentSnapshot
			return cm
		}(),
		"no data": func() *corev1.ConfigMap { cm := good.DeepCopy(); cm.Data = nil; return cm }(),
		"tampered data": func() *corev1.ConfigMap {
			cm := good.DeepCopy()
			cm.Data[RevocationRecordDataKey] = strings.Replace(cm.Data[RevocationRecordDataKey], argo.Username, "platform-admin", 1)
			return cm
		}(),
		"unknown field": func() *corev1.ConfigMap {
			cm := good.DeepCopy()
			cm.Data[RevocationRecordDataKey] = strings.Replace(cm.Data[RevocationRecordDataKey], `{"version":1,`, `{"version":1,"extra":true,`, 1)
			return cm
		}(),
		"other actor":    forge(func(r *RevocationRecord) { r.Revocation.Actor = Actor{Username: "platform-admin"} }),
		"other time":     forge(func(r *RevocationRecord) { r.Revocation.RequestedAt = metav1.NewTime(t0) }),
		"other claim":    forge(func(r *RevocationRecord) { r.Revocation.Claim = "someone else" }),
		"other version":  forge(func(r *RevocationRecord) { r.Version = 2 }),
		"other revision": forge(func(r *RevocationRecord) { r.AcceptanceRevision = 2; r.Revocation.Revision = 2 }),
		"renamed": func() *corev1.ConfigMap {
			cm := good.DeepCopy()
			cm.Name = RevocationRecordName(exceptionUID, 2)
			return cm
		}(),
	}
	for name, cm := range cases {
		t.Run(name, func(t *testing.T) {
			r, _, err := RevocationRecordFrom(cm)
			if err == nil {
				err = r.Matches(cm, want)
			}
			if err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestVerifyHistory(t *testing.T) {
	c := world(t)
	m, v := newHandlers(t, c, t0)
	ex, _ := revokedStored(t, m, v)
	ctx := context.Background()
	if err := VerifyHistory(ctx, c, historyNamespace, ex); !errors.Is(err, ErrHistoryPending) {
		t.Errorf("no record: %v", err)
	}
	if err := VerifyHistory(ctx, unreadable{}, historyNamespace, ex); err == nil || errors.Is(err, ErrHistoryPending) {
		t.Errorf("unreadable store: %v", err)
	}
	persist(t, c, ex)
	if err := VerifyHistory(ctx, c, historyNamespace, ex); err != nil {
		t.Errorf("durable record: %v", err)
	}
	// A record in another namespace is not the protected one.
	if err := VerifyHistory(ctx, c, "team-a", ex); !errors.Is(err, ErrHistoryPending) {
		t.Errorf("record looked up outside the protected namespace: %v", err)
	}
	// The record must hold what the resource records.
	other := ex.DeepCopy()
	r := revocationOf(t, other)
	r.Actor = Actor{Username: "platform-admin"}
	raw, _ := json.Marshal(r)
	other.Annotations[RevocationAnnotation] = string(raw)
	var conflict HistoryConflict
	if err := VerifyHistory(ctx, c, historyNamespace, other); !errors.As(err, &conflict) {
		t.Errorf("mismatching record: %v", err)
	}
	none := ex.DeepCopy()
	delete(none.Annotations, RevocationAnnotation)
	if err := VerifyHistory(ctx, c, historyNamespace, none); !errors.As(err, &conflict) {
		t.Errorf("revoked without a record: %v", err)
	}
}

// Renewing a revoked revision (design §1, §3): admitted only once the
// controller has released the finalizer and the independent record is
// durable and matches; the renewal then clears the protected record and
// is validated as a new acceptance.
func TestRenewalOfARevokedRevisionNeedsDurableHistory(t *testing.T) {
	c := world(t)
	m, v := newHandlers(t, c, t0)
	revoked, _ := revokedStored(t, m, v)
	later := t0.Add(2 * time.Hour)
	m.Now = func() time.Time { return later }
	v.Now = m.Now
	renewal := func(old *v1alpha1.ComplianceException) *v1alpha1.ComplianceException {
		ex := old.DeepCopy()
		ex.Spec.AcceptanceRevision, ex.Spec.Revoked = 2, false
		ex.Spec.Reason, ex.Spec.ExpiresAt = "fresh acceptance", metav1.NewTime(later.Add(24*time.Hour))
		return ex
	}
	both := func(what string, old *v1alpha1.ComplianceException, reason string) {
		t.Helper()
		req := request(t, admissionv1.Update, dave, renewal(old), old)
		if resp := m.Handle(context.Background(), req); resp.Allowed || !strings.HasPrefix(resp.Result.Message, reason+":") {
			t.Errorf("%s: mutating webhook: %+v", what, resp.Result)
		}
		if resp := v.Handle(context.Background(), req); resp.Allowed || !strings.HasPrefix(resp.Result.Message, reason+":") {
			t.Errorf("%s: validating webhook: %+v", what, resp.Result)
		}
	}
	// Before the record exists, and while the finalizer is held after it
	// exists (the controller has not confirmed it yet).
	both("no record", revoked, ReasonRevocationHistoryPending)
	both("no record, finalizer released by hand", released(revoked), ReasonRevocationHistoryPending)
	persist(t, c, revoked)
	both("record, finalizer held", revoked, ReasonRevocationHistoryPending)

	// A record that does not hold this revocation does not count.
	forged := released(revoked)
	r := revocationOf(t, forged)
	r.RequestedAt = metav1.NewTime(t0)
	raw, _ := json.Marshal(r)
	forged.Annotations[RevocationAnnotation] = string(raw)
	both("mismatching record", forged, ReasonRevocationHistoryPending)

	// An unreadable store fails closed.
	ready := released(revoked)
	m.Reader, v.Reader = unreadable{}, unreadable{}
	req := request(t, admissionv1.Update, dave, renewal(ready), ready)
	if resp := m.Handle(context.Background(), req); resp.Allowed || resp.Result.Code != http.StatusInternalServerError {
		t.Errorf("unreadable store: mutating webhook %+v", resp.Result)
	}
	if resp := v.Handle(context.Background(), req); resp.Allowed {
		t.Error("unreadable store: validating webhook allowed the renewal")
	}
	m.Reader, v.Reader = c, c

	// A dry run shows the renewal and stores nothing.
	req = request(t, admissionv1.Update, dave, renewal(ready), ready)
	req.DryRun = ptr.To(true)
	before := snapshot(t, c)
	if _, err := admit(t, m, v, req); err != nil {
		t.Fatalf("dry-run renewal: %v", err)
	}
	if snapshot(t, c) != before {
		t.Error("a dry-run renewal changed cluster state")
	}

	// Durable and released: a new acceptance, freshly validated and
	// attributed, with the revocation record cleared from the resource.
	got, err := admit(t, m, v, request(t, admissionv1.Update, dave, renewal(ready), ready))
	if err != nil {
		t.Fatalf("renewal of a durably revoked revision: %v", err)
	}
	a := acceptanceOf(t, got)
	switch {
	case a.Revision != 2 || a.Actor.Username != "dave" || !a.AcceptedAt.Time.Equal(later) || a.Eligibility == nil:
		t.Errorf("renewed acceptance = %+v", a)
	case got.Spec.Revoked || got.Annotations[RevocationAnnotation] != "" || slices.Contains(got.Finalizers, RevocationFinalizer):
		t.Errorf("renewal kept revocation state: revoked=%v annotations=%v finalizers=%v", got.Spec.Revoked, got.Annotations, got.Finalizers)
	}
	// The record of revision 1 is untouched.
	if err := VerifyHistory(context.Background(), c, historyNamespace, ready); err != nil {
		t.Errorf("record of revision 1 after renewal: %v", err)
	}
	// Renewal still rechecks eligibility: in a namespace now Forbidden it is
	// rejected even with durable history.
	prod := ready.DeepCopy()
	prod.Namespace = "team-prod"
	persistAt := prod.DeepCopy()
	persistAt.UID = "ex-prod"
	r = revocationOf(t, persistAt)
	r.ExceptionUID = "ex-prod"
	raw, _ = json.Marshal(r)
	persistAt.Annotations[RevocationAnnotation] = string(raw)
	persist(t, c, persistAt)
	if _, err := admit(t, m, v, request(t, admissionv1.Update, dave, renewal(persistAt), persistAt)); err == nil || !strings.Contains(err.Error(), ReasonForbidden) {
		t.Errorf("renewal under a Forbidden contribution: %v", err)
	}

	// Without the mutating webhook, a renewal that keeps the record or the
	// finalizer is rejected.
	keep := renewal(ready)
	keep.Annotations[AcceptanceAnnotation] = got.Annotations[AcceptanceAnnotation]
	if resp := v.Handle(context.Background(), request(t, admissionv1.Update, dave, keep, ready)); resp.Allowed || !strings.HasPrefix(resp.Result.Message, ReasonProtectedField+":") {
		t.Errorf("renewal keeping the revocation record: %+v", resp.Result)
	}
	carry := renewal(ready)
	carry.Annotations[AcceptanceAnnotation] = got.Annotations[AcceptanceAnnotation]
	delete(carry.Annotations, RevocationAnnotation)
	carry.Finalizers = []string{RevocationFinalizer}
	if resp := v.Handle(context.Background(), request(t, admissionv1.Update, dave, carry, ready)); resp.Allowed || !strings.HasPrefix(resp.Result.Message, ReasonProtectedField+":") {
		t.Errorf("renewal carrying the finalizer: %+v", resp.Result)
	}
}

// Only the controller identity releases the finalizer, only once the
// record is durable, and it can do nothing else.
func TestOnlyTheControllerReleasesTheRevocationFinalizer(t *testing.T) {
	c := world(t)
	m, v := newHandlers(t, c, t0)
	revoked, _ := revokedStored(t, m, v)
	m.Now = func() time.Time { return t0.Add(2 * time.Hour) }
	v.Now = m.Now
	release := func(user string, old *v1alpha1.ComplianceException) admission.Response {
		ex := old.DeepCopy()
		ex.Finalizers = slices.DeleteFunc(ex.Finalizers, func(f string) bool { return f == RevocationFinalizer })
		info := alice
		if user == controllerUser.Username {
			info = controllerUser
		}
		return v.Handle(context.Background(), request(t, admissionv1.Update, info, ex, old))
	}
	want := func(what string, resp admission.Response, reason string) {
		t.Helper()
		switch {
		case reason == "" && !resp.Allowed:
			t.Errorf("%s: denied: %s", what, resp.Result.Message)
		case reason != "" && (resp.Allowed || !strings.HasPrefix(resp.Result.Message, reason+":")):
			t.Errorf("%s: want a %s denial, got %+v", what, reason, resp.Result)
		}
	}
	want("controller before the record exists", release(controllerUser.Username, revoked), ReasonRevocationHistoryPending)
	want("controller while terminating before the record exists", release(controllerUser.Username, terminating(revoked)), ReasonRevocationHistoryPending)
	cm := persist(t, c, revoked)
	want("an editor once the record is durable", release("alice", revoked), ReasonProtectedField)
	want("controller once the record is durable", release(controllerUser.Username, revoked), "")
	want("controller while terminating once the record is durable", release(controllerUser.Username, terminating(revoked)), "")

	// The controller changes nothing else, whatever the record.
	edits := map[string]func(ex *v1alpha1.ComplianceException){
		"label":      func(ex *v1alpha1.ComplianceException) { ex.Labels = map[string]string{"x": "y"} },
		"annotation": func(ex *v1alpha1.ComplianceException) { ex.Annotations["x"] = "y" },
		"claim":      func(ex *v1alpha1.ComplianceException) { ex.Annotations[ClaimAnnotation] = "controller" },
		"other finalizer": func(ex *v1alpha1.ComplianceException) {
			ex.Finalizers = append(ex.Finalizers, "example.com/team")
		},
		"owner": func(ex *v1alpha1.ComplianceException) {
			ex.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "x", UID: "u"}}
		},
	}
	for name, edit := range edits {
		ex := revoked.DeepCopy()
		ex.Finalizers = nil
		edit(ex)
		want("controller release with a "+name+" edit", v.Handle(context.Background(), request(t, admissionv1.Update, controllerUser, ex, revoked)), ReasonProtectedField)
	}
	stored := accepted(t, m, v)
	revoke := revokedCopy(stored, nil)
	if updated, err := m.record(context.Background(), request(t, admissionv1.Update, controllerUser, revoke, stored)); err != nil || updated == nil {
		t.Fatalf("mutating revocation as the controller: %v", err)
	} else {
		revoke = updated
	}
	want("controller revokes", v.Handle(context.Background(), request(t, admissionv1.Update, controllerUser, revoke, stored)), ReasonProtectedField)
	renew := stored.DeepCopy()
	renew.Spec.AcceptanceRevision, renew.Spec.ExpiresAt = 2, metav1.NewTime(t0.Add(30*time.Hour))
	want("controller renews", v.Handle(context.Background(), request(t, admissionv1.Update, controllerUser, renew, stored)), ReasonProtectedField)
	want("controller creates", v.Handle(context.Background(), request(t, admissionv1.Create, controllerUser, exceptionObj("team-a", 1, nil), nil)), ReasonProtectedField)
	want("controller no-op update", v.Handle(context.Background(), request(t, admissionv1.Update, controllerUser, stored.DeepCopy(), stored)), "")

	// A record that is not this revocation's does not release it.
	if err := c.Delete(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
	squatter := cm.DeepCopy()
	squatter.ResourceVersion = ""
	squatter.Immutable = nil
	if err := c.Create(context.Background(), squatter); err != nil {
		t.Fatal(err)
	}
	want("controller with a conflicting record", release(controllerUser.Username, revoked), ReasonRevocationHistoryPending)

	// Unknown controller identity: no release, by anyone; a revocation still
	// needs nothing from the cluster.
	m2, v2 := newHandlers(t, c, t0.Add(2*time.Hour))
	v2.Controller = &Identity{Lookup: func(context.Context) (string, error) { return "", errors.New("api unavailable") }}
	if err := c.Delete(context.Background(), squatter); err != nil {
		t.Fatal(err)
	}
	persist(t, c, revoked)
	ex := revoked.DeepCopy()
	ex.Finalizers = nil
	if resp := v2.Handle(context.Background(), request(t, admissionv1.Update, controllerUser, ex, revoked)); resp.Allowed {
		t.Error("finalizer released with an unknown controller identity")
	}
	m2.Reader, v2.Reader = unreadable{}, unreadable{}
	if _, err := admit(t, m2, v2, request(t, admissionv1.Update, alice, revokedCopy(stored, nil), stored)); err != nil {
		t.Errorf("revocation with an unknown controller identity and no store: %v", err)
	}
}

// The identity is looked up once and only when needed; failures are not
// cached.
func TestControllerIdentityLookup(t *testing.T) {
	calls := 0
	fail := true
	id := &Identity{Lookup: func(context.Context) (string, error) {
		calls++
		if fail {
			return "", apierrors.NewServiceUnavailable("down")
		}
		return controllerUser.Username, nil
	}}
	if id.Cached() != "" {
		t.Fatal("cached before any lookup")
	}
	if _, err := id.Get(context.Background()); err == nil {
		t.Fatal("failed lookup succeeded")
	}
	fail = false
	for range 3 {
		if name, err := id.Get(context.Background()); err != nil || name != controllerUser.Username {
			t.Fatalf("lookup = %q %v", name, err)
		}
	}
	if calls != 2 || id.Cached() != controllerUser.Username {
		t.Errorf("calls = %d cached %q", calls, id.Cached())
	}
	var none *Identity
	if _, err := none.Get(context.Background()); err == nil || none.Cached() != "" {
		t.Error("a nil identity resolved")
	}
	empty := &Identity{Lookup: func(context.Context) (string, error) { return "", nil }}
	if _, err := empty.Get(context.Background()); err == nil {
		t.Error("an empty username was accepted")
	}
}
