package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
)

// add-supporting-evidence-attachments 4.1-4.3 against an injected clock:
// validity, content, association and withdrawal are reconciled separately;
// validity changes at its exact boundaries without any object event; a
// withdrawn record leaves new coverage at once while its source ownership
// stays until the fixed expiry, across restarts, leader changes and failed
// deletions.

// newLifecycleFixture has a resolved binding "a" (UID uid-a) on the
// vendored content and a ready default destination.
func newLifecycleFixture(t *testing.T) *storageFixture {
	t.Helper()
	digest := vendoredDigest(t)
	f := newStorageFixture(t, readyDestination("primary", "dest-1"), defaultAttachmentDestination("primary", "dest-1"),
		baselineProfile(digest), resolvedBinding("a", "uid-a", 1, digest))
	f.r.Storage.ContentInterval = time.Hour
	return f
}

// settle reconciles until the record writes nothing more.
func (f *storageFixture) settle(name string) (ctrl.Result, *v1alpha1.EvidenceAttachment) {
	f.t.Helper()
	res, a := f.reconcile(name)
	for range 5 {
		again, b := f.reconcile(name)
		if b.ResourceVersion == a.ResourceVersion {
			return again, b
		}
		res, a = again, b
	}
	f.t.Fatalf("%s does not settle: %+v", name, a.Status)
	return res, a
}

func (f *storageFixture) store() *memStore { return f.stores.stores["dest-1"] }

func condition(a *v1alpha1.EvidenceAttachment, t string) string {
	c := meta.FindStatusCondition(a.Status.Conditions, t)
	if c == nil {
		return ""
	}
	return string(c.Status) + "/" + c.Reason
}

func contentOf(a *v1alpha1.EvidenceAttachment) string {
	if a.Status.Content == nil {
		return ""
	}
	return string(a.Status.Content.State) + "/" + a.Status.Content.Reason
}

func validityOf(a *v1alpha1.EvidenceAttachment) (v1alpha1.TemporalState, *metav1.Time) {
	if a.Status.Validity == nil {
		return "", nil
	}
	return a.Status.Validity.State, a.Status.Validity.NextTransition
}

// The controller requeues at the next declared boundary, so the timer alone
// (no object, binding or storage event) moves the validity at exactly
// validFrom and validUntil. Content and associations are unaffected.
func TestAttachmentValidityChangesWithoutAnEvent(t *testing.T) {
	f := newLifecycleFixture(t)
	from, until := f.now.Add(90*time.Second), f.now.Add(90*time.Second+10*time.Minute)
	f.createValid("dc", from, until, f.association("a", "uid-a"))
	f.settle("dc")
	f.commit("dc", "dest-1", nil)
	res, a := f.settle("dc")
	if state, next := validityOf(a); state != v1alpha1.TemporalNotYetValid || next == nil || !next.Time.Equal(from) {
		t.Fatalf("before validFrom: %s next %v", state, next)
	}
	if res.RequeueAfter != 90*time.Second {
		t.Fatalf("requeue %v, want exactly the time to validFrom", res.RequeueAfter)
	}
	// The timer fires; nothing else happened.
	f.now = f.now.Add(res.RequeueAfter)
	res, a = f.settle("dc")
	if state, next := validityOf(a); state != v1alpha1.TemporalCurrent || next == nil || !next.Time.Equal(until) || res.RequeueAfter != 10*time.Minute {
		t.Fatalf("at validFrom: %s next %v, requeue %v", state, next, res)
	}
	f.now = until.Add(-time.Nanosecond)
	res, a = f.settle("dc")
	if state, _ := validityOf(a); state != v1alpha1.TemporalCurrent || res.RequeueAfter != time.Nanosecond {
		t.Fatalf("just before validUntil: %s, requeue %v", state, res)
	}
	f.now = until
	_, a = f.settle("dc")
	if state, next := validityOf(a); state != v1alpha1.TemporalExpired || next != nil {
		t.Fatalf("at validUntil: %s next %v", state, next)
	}
	// The other axes are independent: the document is still committed and
	// available, and the association still applies.
	if contentOf(a) != "Available/Verified" || condition(a, v1alpha1.ConditionDocumentCommitted) != "True/Committed" ||
		condition(a, v1alpha1.ConditionAssociationsValid) != "True/Valid" || a.Status.Withdrawal != nil {
		t.Fatalf("expiry changed other axes: content %s, committed %s, associations %s", contentOf(a), condition(a, v1alpha1.ConditionDocumentCommitted),
			condition(a, v1alpha1.ConditionAssociationsValid))
	}
	obs := attachments.ForBinding([]v1alpha1.EvidenceAttachment{*a}, "uid-a", f.now)
	if len(obs) != 1 || obs[0].Temporal != v1alpha1.TemporalExpired || obs[0].Content != v1alpha1.ContentAvailable {
		t.Fatalf("coverage view: %+v", obs)
	}
}

// Content is checked separately from the commitment: missing, damaged,
// unreachable and handed-off bytes are Unavailable while the recorded
// commitment never changes; at the fixed source expiry the content is
// Unavailable without contacting storage.
func TestAttachmentContentTracksTheCommittedBytes(t *testing.T) {
	f := newLifecycleFixture(t)
	f.create("dc", f.association("a", "uid-a"))
	_, a := f.settle("dc")
	if contentOf(a) != "Pending/AwaitingUpload" {
		t.Fatalf("before upload: %s", contentOf(a))
	}
	r := f.commit("dc", "dest-1", nil)
	_, a = f.settle("dc")
	st := f.store()
	if contentOf(a) != "Available/Verified" || st.healthCalls != 1 {
		t.Fatalf("committed: %s, health checks %d", contentOf(a), st.healthCalls)
	}
	commitment := a.Status.Storage.Commitment.DeepCopy()
	available := a.Status.Content.LastTransitionTime
	// Available content is re-checked once per interval, not per reconcile.
	st.problem = &attachments.Problem{Reason: attachments.ProblemMissing, Message: "the document version is missing"}
	f.now = f.now.Add(59 * time.Minute)
	res, a := f.settle("dc")
	if contentOf(a) != "Available/Verified" || st.healthCalls != 1 || res.RequeueAfter != time.Minute {
		t.Fatalf("not yet due: %s, health checks %d, requeue %v", contentOf(a), st.healthCalls, res)
	}
	f.now = f.now.Add(time.Minute)
	res, a = f.settle("dc")
	if contentOf(a) != "Unavailable/ObjectMissing" || res.RequeueAfter != attachmentStorageRequeue {
		t.Fatalf("missing bytes: %s, requeue %v", contentOf(a), res)
	}
	if condition(a, v1alpha1.ConditionDocumentCommitted) != "True/Committed" || *a.Status.Storage.Commitment != *commitment ||
		condition(a, v1alpha1.ConditionAssociationsValid) != "True/Valid" || a.Status.Validity.State != v1alpha1.TemporalCurrent {
		t.Fatalf("unavailable bytes changed another axis: %+v", a.Status)
	}
	for _, c := range []struct {
		name string
		set  func()
		want string
	}{
		{"damaged", func() {
			st.problem = &attachments.Problem{Reason: attachments.ProblemIntegrity, Message: "different SHA-256"}
		}, "Unavailable/IntegrityFailed"},
		{"no answer", func() { st.problem, st.healthErr = nil, attachments.ErrUnavailable }, "Unavailable/StorageUnavailable"},
		{"unreachable", func() { st.healthErr, f.stores.down = nil, true }, "Unavailable/StorageUnavailable"},
		{"handed off", func() { f.stores.down, f.stores.orphaned = false, true }, "Unavailable/DestinationHandedOff"},
		{"restored", func() { f.stores.orphaned = false }, "Available/Verified"},
	} {
		c.set()
		// Unavailable content is re-checked on every reconcile.
		if _, a = f.settle("dc"); contentOf(a) != c.want {
			t.Fatalf("%s: %s, want %s", c.name, contentOf(a), c.want)
		}
		f.now = f.now.Add(time.Second)
	}
	if a.Status.Content.LastTransitionTime.Equal(available) {
		t.Fatal("the transition back to Available kept the old transition time")
	}
	// At the fixed source expiry: Unavailable, without a storage call.
	calls := st.healthCalls
	f.now = r.ExpiresAt
	res, a = f.settle("dc")
	if contentOf(a) != "Unavailable/SourceExpired" || st.healthCalls != calls || res.RequeueAfter != 0 {
		t.Fatalf("source expired: %s, health checks %d->%d, requeue %v", contentOf(a), calls, st.healthCalls, res)
	}
	if len(st.deleted) != 0 {
		t.Fatal("a live record's source was deleted at its expiry")
	}
}

// digestBaselines serves baselines by bundle digest.
type digestBaselines map[string]*attachments.Baseline

func (d digestBaselines) Baseline(_ context.Context, ref v1alpha1.BundleReference) (*attachments.Baseline, error) {
	if b, ok := d[ref.Digest]; ok {
		return b, nil
	}
	return nil, errors.New("unknown content")
}

// Edits that keep the binding's catalog and selected baseline (reporting
// settings, policy parameters, exception settings) never change the
// association, not even while the binding re-resolves. Content that removes
// a control, and binding recreation, stop it.
func TestAttachmentAssociationsAcrossBindingAndProfileEdits(t *testing.T) {
	digest := vendoredDigest(t)
	f := newAttachmentFixture(t, resolvedBinding("a", "uid-a", 1, digest))
	full, err := (&ContentBaselines{VendoredName: "linux-workload-hardening", ContentRoot: "../.."}).Baseline(context.Background(),
		v1alpha1.BundleReference{Name: "linux-workload-hardening", Digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	reduced := &attachments.Baseline{CatalogDigest: full.CatalogDigest, Controls: map[string]map[string]bool{}}
	for id, stmts := range full.Controls {
		if id != "pe-3" {
			reduced.Controls[id] = stmts
		}
	}
	otherDigest := "sha256:" + "2222222222222222222222222222222222222222222222222222222222222222"
	f.r.Baselines = digestBaselines{digest: full, otherDigest: reduced}
	f.create("dc", f.association("a", "uid-a"))
	_, a := f.reconcile("dc")
	wantAssociations(t, a, metav1.ConditionTrue, "Valid", "Valid")
	ctx := context.Background()
	unchanged := func(step string) {
		t.Helper()
		before := a.ResourceVersion
		_, a = f.reconcile("dc")
		wantAssociations(t, a, metav1.ConditionTrue, "Valid", "Valid")
		if a.ResourceVersion != before {
			t.Fatalf("%s rewrote the association status", step)
		}
	}
	binding := func() *v1alpha1.ComplianceBinding {
		b := &v1alpha1.ComplianceBinding{}
		if err := f.c.Get(ctx, client.ObjectKey{Name: "a"}, b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	profile := func() *v1alpha1.ComplianceProfile {
		p := &v1alpha1.ComplianceProfile{}
		if err := f.c.Get(ctx, client.ObjectKey{Name: "baseline"}, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	resolve := func() {
		b, p := binding(), profile()
		b.Status.ObservedGeneration = b.Generation
		b.Status.Profile = &v1alpha1.ResolvedProfile{Name: p.Name, UID: p.UID, Generation: p.Generation, BundleDigest: p.Spec.Bundle.Digest}
		if err := f.c.Status().Update(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	// Reporting-only binding edit, before and after the binding observes it.
	b := binding()
	b.Spec.Assessment = &v1alpha1.BindingAssessment{}
	b.Generation = 2
	if err := f.c.Update(ctx, b); err != nil {
		t.Fatal(err)
	}
	unchanged("an unobserved reporting-only edit")
	resolve()
	unchanged("a resolved reporting-only edit")
	// Policy-parameter and exception-setting edits: a newer profile
	// revision with the same content, before and after the binding resolves it.
	p := profile()
	p.Spec.Policies[0].Parameters = &apiextensionsv1.JSON{Raw: []byte(`{"allowPrivilegeEscalation":false}`)}
	p.Spec.Policies[0].Exceptions = v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: time.Hour}}
	p.Generation = 2
	if err := f.c.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	unchanged("an unresolved policy-parameter edit")
	resolve()
	unchanged("a resolved policy-parameter edit")
	// New content whose baseline drops pe-3: Pending while the binding
	// still enforces the old content, Mismatched once it resolves the new.
	p = profile()
	p.Spec.Bundle.Digest = otherDigest
	p.Generation = 3
	if err := f.c.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	_, a = f.reconcile("dc")
	wantAssociations(t, a, metav1.ConditionUnknown, "Pending", v1alpha1.ReasonBindingUnresolved)
	resolve()
	_, a = f.reconcile("dc")
	wantAssociations(t, a, metav1.ConditionFalse, "Mismatched", v1alpha1.ReasonControlNotInBaseline)
	// Recreation under the same name never inherits the association.
	if err := f.c.Delete(ctx, binding()); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Create(ctx, resolvedBinding("a", "uid-a2", 1, digest)); err != nil {
		t.Fatal(err)
	}
	_, a = f.reconcile("dc")
	wantAssociations(t, a, metav1.ConditionFalse, "Mismatched", v1alpha1.ReasonBindingReplaced)
	if a.Status.Validity == nil || a.Status.Validity.State != v1alpha1.TemporalCurrent {
		t.Fatalf("association changes moved the validity: %+v", a.Status.Validity)
	}
}

// Deleting a record withdraws it from new coverage at once and for good,
// keeps its associations as last resolved, and retains the committed source
// until its fixed expiry: across idle passes (which write nothing), a
// restart or leader change, and up to the exact expiry instant.
func TestAttachmentWithdrawalRetainsOwnershipUntilExpiry(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := context.Background()
	f.create("dc", f.association("a", "uid-a"))
	f.create("other", f.association("a", "uid-a"))
	f.settle("dc")
	f.settle("other")
	r := f.commit("dc", "dest-1", nil)
	f.commit("other", "dest-1", nil)
	f.settle("dc")
	f.settle("other")
	if err := f.c.Delete(ctx, f.get("dc")); err != nil {
		t.Fatal(err)
	}
	res, a := f.settle("dc")
	if a.Status.Withdrawal == nil || !a.Status.Withdrawal.WithdrawnAt.Equal(a.DeletionTimestamp) {
		t.Fatalf("withdrawal not recorded: %+v", a.Status.Withdrawal)
	}
	if condition(a, v1alpha1.ConditionAssociationsValid) != "True/Valid" || contentOf(a) != "Available/Verified" || a.Status.Validity.State != v1alpha1.TemporalCurrent {
		t.Fatalf("withdrawal changed another axis: associations %s, content %s, validity %s", condition(a, v1alpha1.ConditionAssociationsValid), contentOf(a), a.Status.Validity.State)
	}
	cl := a.Status.Storage.Cleanup
	if condition(a, v1alpha1.ConditionSourceRetained) != "True/RetentionActive" || cl == nil || cl.State != "NotDue" || cl.LastAttempt != nil || cl.Attempts != 0 {
		t.Fatalf("retention: %s %+v", condition(a, v1alpha1.ConditionSourceRetained), cl)
	}
	if res.RequeueAfter <= 0 || res.RequeueAfter > MaxRetentionRequeue {
		t.Fatalf("retained record requeue %v", res)
	}
	var list v1alpha1.EvidenceAttachmentList
	if err := f.c.List(ctx, &list); err != nil {
		t.Fatal(err)
	}
	if obs := attachments.ForBinding(list.Items, "uid-a", f.now); len(obs) != 1 || obs[0].Name != "other" {
		t.Fatalf("new coverage selects %+v, want only the live record", obs)
	}
	// Idle passes write nothing and contact storage only for the content
	// check; nothing is deleted.
	st := f.store()
	rv, calls := a.ResourceVersion, st.healthCalls
	f.now = f.now.Add(30 * time.Minute)
	if _, a = f.reconcile("dc"); a.ResourceVersion != rv || st.healthCalls != calls || st.deleteCalls != 0 {
		t.Fatalf("an idle retained pass wrote %v or called storage (health %d->%d, delete %d)", a.ResourceVersion != rv, calls, st.healthCalls, st.deleteCalls)
	}
	// A restart or another leader: fresh process state, same durable state.
	restarted := func() {
		f.r = &AttachmentReconciler{Client: f.c, Baselines: f.r.Baselines, Storage: &AttachmentStorage{Reader: f.c, Namespace: "konstapel-system",
			Cluster: "kube-system:cluster", Stores: f.stores, ContentInterval: time.Hour, Now: func() time.Time { return f.now }}}
	}
	restarted()
	if _, a = f.reconcile("dc"); a.ResourceVersion != rv || st.deleteCalls != 0 || a.Status.Withdrawal == nil {
		t.Fatalf("a new leader changed the retained record: %+v", a.Status)
	}
	// One second before the fixed expiry nothing is deleted; at it, every
	// owned version is removed and the record released.
	f.now = r.ExpiresAt.Add(-time.Second)
	if res, a = f.reconcile("dc"); res.RequeueAfter != time.Second || st.deleteCalls != 0 {
		t.Fatalf("before expiry: requeue %v, deletions %d", res, st.deleteCalls)
	}
	restarted()
	f.now = r.ExpiresAt
	if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "dc"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Get(ctx, client.ObjectKey{Name: "dc"}, &v1alpha1.EvidenceAttachment{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expired, cleaned record kept: %v", err)
	}
	if len(st.deletedAt) != 1 || st.deletedAt[0].Before(r.ExpiresAt) || st.deleted[0].UID != "dc-uid" {
		t.Fatalf("deletions %v at %v", st.deleted, st.deletedAt)
	}
	if _, err := st.Committed(ctx, attachments.Ref{ClusterID: "kube-system:cluster", UID: "other-uid"}); err != nil {
		t.Fatalf("another record's source was touched: %v", err)
	}
}

// A former leader that read the record before it was deleted cannot write
// its stale view over the new leader's withdrawal: the optimistic lock on
// every status write rejects it, and its next pass sees the withdrawal.
func TestAttachmentStaleLeaderCannotUndoAWithdrawal(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := context.Background()
	f.create("dc", f.association("a", "uid-a"))
	f.settle("dc")
	f.commit("dc", "dest-1", nil)
	f.settle("dc")
	newLeader := &AttachmentReconciler{Client: f.c, Baselines: f.r.Baselines, Storage: &AttachmentStorage{Reader: f.c, Namespace: "konstapel-system",
		Cluster: "kube-system:cluster", Stores: f.stores, ContentInterval: time.Hour, Now: func() time.Time { return f.now }}}
	raced := false
	stale := interceptor.NewClient(f.c.(client.WithWatch), interceptor.Funcs{
		SubResourcePatch: func(ctx context.Context, c client.Client, sub string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
			if !raced {
				raced = true
				// The record is withdrawn and the new leader records it
				// while the old one is about to write.
				if err := f.c.Delete(ctx, f.get("dc")); err != nil {
					t.Fatal(err)
				}
				if _, err := newLeader.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "dc"}}); err != nil {
					t.Fatal(err)
				}
			}
			return c.SubResource(sub).Patch(ctx, obj, patch, opts...)
		}})
	old := &AttachmentReconciler{Client: stale, Baselines: f.r.Baselines, Storage: &AttachmentStorage{Reader: f.c, Namespace: "konstapel-system",
		Cluster: "kube-system:cluster", Stores: f.stores, ContentInterval: time.Hour, Now: func() time.Time { return f.now }}}
	// The old leader's pass has something to write: the content check is
	// due and the bytes went missing.
	f.store().problem = &attachments.Problem{Reason: attachments.ProblemMissing, Message: "the document version is missing"}
	f.now = f.now.Add(2 * time.Hour)
	if _, err := old.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "dc"}}); !apierrors.IsConflict(err) || !raced {
		t.Fatalf("the stale write was not rejected: %v (raced %v)", err, raced)
	}
	a := f.get("dc")
	if a.Status.Withdrawal == nil || condition(a, v1alpha1.ConditionSourceRetained) != "True/RetentionActive" {
		t.Fatalf("withdrawal lost: %+v", a.Status)
	}
	// The old leader's retry runs the withdrawal path too.
	if _, err := old.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "dc"}}); err != nil {
		t.Fatal(err)
	}
	if a = f.get("dc"); a.Status.Withdrawal == nil || len(f.store().deleted) != 0 {
		t.Fatalf("after the old leader's retry: %+v", a.Status)
	}
}

// Failed or refused cleanup keeps the record, its pin, its commitment and
// the destination's finalizer; it is retried after a bounded backoff,
// without contacting storage or writing status in between, and recovers.
func TestAttachmentCleanupFailureIsBoundedAndRecoverable(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := context.Background()
	f.create("dc", f.association("a", "uid-a"))
	f.settle("dc")
	r := f.commit("dc", "dest-1", nil)
	f.settle("dc")
	if err := f.c.Delete(ctx, f.get("dc")); err != nil {
		t.Fatal(err)
	}
	f.settle("dc")
	st := f.store()
	f.now = r.ExpiresAt
	st.deleteErr = errors.New("AccessDenied: object lock (retention) on the committed document")
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour}
	for i, backoff := range want {
		res, a := f.reconcile("dc")
		cl := a.Status.Storage.Cleanup
		if cl.State != string(attachments.CleanupRetentionBlocked) || cl.Attempts != int32(i+1) || !cl.LastAttempt.Time.Equal(f.now) || res.RequeueAfter != backoff ||
			condition(a, v1alpha1.ConditionSourceRetained) != "True/"+v1alpha1.ReasonCleanupBlocked || len(cl.Message) > 1024 {
			t.Fatalf("attempt %d: %+v, requeue %v, want backoff %v", i+1, cl, res, backoff)
		}
		if a.Status.Storage.Commitment == nil || a.Status.Storage.Destination == nil || contentOf(a) != "Unavailable/SourceExpired" {
			t.Fatalf("attempt %d lost ownership: %+v", i+1, a.Status.Storage)
		}
		// In between, nothing is attempted and nothing is written.
		calls, rv := st.deleteCalls, a.ResourceVersion
		f.now = f.now.Add(backoff - time.Second)
		if res, a = f.reconcile("dc"); res.RequeueAfter != time.Second || st.deleteCalls != calls || a.ResourceVersion != rv {
			t.Fatalf("attempt %d retried early: requeue %v, deletions %d->%d", i+1, res, calls, st.deleteCalls)
		}
		f.now = f.now.Add(time.Second)
	}
	ed := &v1alpha1.EvidenceDestination{}
	if err := f.c.Get(ctx, client.ObjectKey{Name: "primary"}, ed); err != nil || !containsString(ed.Finalizers, DestinationFinalizer) {
		t.Fatalf("destination released while cleanup is blocked: %v", err)
	}
	// An unreachable or handed-off destination is a failed attempt too,
	// with the same backoff, and storage is never contacted.
	st.deleteErr = nil
	calls := st.deleteCalls
	for _, c := range []struct {
		name string
		set  func()
		msg  string
	}{
		{"unreachable", func() { f.stores.down = true }, "unavailable"},
		{"handed off", func() { f.stores.down, f.stores.orphaned = false, true }, "handed off to an operator"},
	} {
		c.set()
		_, a := f.reconcile("dc")
		cl := a.Status.Storage.Cleanup
		if cl.State != string(attachments.CleanupDeletionFailed) || !strings.Contains(cl.Message, c.msg) || st.deleteCalls != calls {
			t.Fatalf("%s: %+v (storage deletions %d->%d)", c.name, cl, calls, st.deleteCalls)
		}
		f.now = f.now.Add(time.Hour)
	}
	// Storage recovers: the next attempt removes the owned source.
	f.stores.orphaned = false
	if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "dc"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Get(ctx, client.ObjectKey{Name: "dc"}, &v1alpha1.EvidenceAttachment{}); !apierrors.IsNotFound(err) || len(st.deleted) != 1 {
		t.Fatalf("recovered cleanup: %v, deletions %v", err, st.deleted)
	}
}
