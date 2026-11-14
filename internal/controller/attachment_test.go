package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"testing/fstest"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// add-supporting-evidence-attachments 1.2: associations apply only to the
// exact binding identity, its current resolved catalog and selected baseline.

func vendoredDigest(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../content/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

func catalogDigest(t *testing.T) string {
	t.Helper()
	b, err := attachments.ReadBaseline(os.DirFS("../.."))
	if err != nil {
		t.Fatal(err)
	}
	return b.CatalogDigest
}

type attachmentFixture struct {
	t       *testing.T
	c       client.Client
	r       *AttachmentReconciler
	catalog string
}

func resolvedBinding(name, uid string, profileGen int64, digest string) *v1alpha1.ComplianceBinding {
	return &v1alpha1.ComplianceBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uid), Generation: 1},
		Spec:       v1alpha1.ComplianceBindingSpec{ProfileRef: v1alpha1.ProfileReference{Name: "baseline"}, Mode: v1alpha1.ModeAudit},
		Status: v1alpha1.ComplianceBindingStatus{ObservedGeneration: 1,
			Profile:    &v1alpha1.ResolvedProfile{Name: "baseline", UID: "profile-uid", Generation: profileGen, BundleDigest: digest},
			Conditions: []metav1.Condition{{Type: v1alpha1.ConditionResolved, Status: metav1.ConditionTrue, Reason: v1alpha1.ReasonResolutionSucceeded, LastTransitionTime: metav1.Now()}}},
	}
}

func newAttachmentFixture(t *testing.T, objs ...client.Object) *attachmentFixture {
	t.Helper()
	digest := vendoredDigest(t)
	profile := &v1alpha1.ComplianceProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "baseline", UID: "profile-uid", Generation: 1},
		Spec:       v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: "linux-workload-hardening", Digest: digest}, Policies: []v1alpha1.ProfilePolicy{{Name: "p"}}},
	}
	all := append([]client.Object{profile}, objs...)
	c := fake.NewClientBuilder().WithScheme(Scheme()).WithObjects(all...).
		WithStatusSubresource(&v1alpha1.ComplianceBinding{}, &v1alpha1.ComplianceProfile{}, &v1alpha1.EvidenceAttachment{}).
		WithIndex(&v1alpha1.EvidenceAttachment{}, AttachmentBindingIndex, attachmentBindingNames).
		Build()
	return &attachmentFixture{t: t, c: c, catalog: catalogDigest(t),
		r: &AttachmentReconciler{Client: c, Baselines: &ContentBaselines{VendoredName: "linux-workload-hardening", ContentRoot: "../.."}}}
}

func (f *attachmentFixture) association(binding, uid string, controls ...v1alpha1.AttachmentControl) v1alpha1.AttachmentAssociation {
	if len(controls) == 0 {
		controls = []v1alpha1.AttachmentControl{{ID: "pe-3", Statements: []string{"pe-3_smt.a"}}}
	}
	return v1alpha1.AttachmentAssociation{Binding: v1alpha1.ExactBindingReference{Name: binding, UID: uid}, CatalogDigest: f.catalog, Controls: controls}
}

func (f *attachmentFixture) create(name string, as ...v1alpha1.AttachmentAssociation) {
	f.t.Helper()
	a := &v1alpha1.EvidenceAttachment{ObjectMeta: metav1.ObjectMeta{Name: name, Generation: 1}, Spec: v1alpha1.EvidenceAttachmentSpec{
		Document:     v1alpha1.AttachmentDocument{Title: "DC audit", MediaType: "application/pdf", Size: 10, SHA256: "sha256:" + hex.EncodeToString(make([]byte, 32))},
		Source:       v1alpha1.AttachmentSource{Issuer: "Auditor"},
		Validity:     v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)), ValidUntil: metav1.NewTime(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))},
		Associations: as,
		Scope:        v1alpha1.AttachmentScope{Description: "DC North"},
		RegisteredBy: &v1alpha1.Requester{Username: "platform-operator"},
	}}
	if err := f.c.Create(context.Background(), a); err != nil {
		f.t.Fatal(err)
	}
}

func (f *attachmentFixture) reconcile(name string) (ctrl.Result, *v1alpha1.EvidenceAttachment) {
	f.t.Helper()
	res, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKey{Name: name}})
	if err != nil {
		f.t.Fatal(err)
	}
	a := &v1alpha1.EvidenceAttachment{}
	if err := f.c.Get(context.Background(), client.ObjectKey{Name: name}, a); err != nil {
		f.t.Fatal(err)
	}
	return res, a
}

func wantAssociations(t *testing.T, a *v1alpha1.EvidenceAttachment, cond metav1.ConditionStatus, states ...string) {
	t.Helper()
	if len(a.Status.Associations) != len(states)/2 {
		t.Fatalf("associations %+v, want %v", a.Status.Associations, states)
	}
	for i, s := range a.Status.Associations {
		if string(s.State) != states[2*i] || s.Reason != states[2*i+1] {
			t.Errorf("association %d: %s/%s (%s), want %s/%s", i, s.State, s.Reason, s.Message, states[2*i], states[2*i+1])
		}
	}
	c := meta.FindStatusCondition(a.Status.Conditions, v1alpha1.ConditionAssociationsValid)
	if c == nil || c.Status != cond {
		t.Fatalf("AssociationsValid %+v, want %s", c, cond)
	}
}

func TestAttachmentSharedFacilityEvidenceForTwoBindings(t *testing.T) {
	digest := vendoredDigest(t)
	f := newAttachmentFixture(t, resolvedBinding("a", "uid-a", 1, digest), resolvedBinding("b", "uid-b", 1, digest))
	f.create("dc", f.association("a", "uid-a"), f.association("b", "uid-b", v1alpha1.AttachmentControl{ID: "pe-6"}))
	res, a := f.reconcile("dc")
	wantAssociations(t, a, metav1.ConditionTrue, "Valid", "Valid", "Valid", "Valid")
	if res.RequeueAfter != 0 {
		t.Fatalf("valid associations requeue: %v", res)
	}
	if !containsString(a.Finalizers, v1alpha1.EvidenceAttachmentFinalizer) {
		t.Fatal("retention finalizer not added")
	}
	if a.Status.Associations[0].ObservedCatalogDigest != f.catalog {
		t.Fatalf("observed catalog %q", a.Status.Associations[0].ObservedCatalogDigest)
	}
	// Idempotent: another pass (a restart or another leader) writes nothing.
	rv := a.ResourceVersion
	if _, again := f.reconcile("dc"); again.ResourceVersion != rv {
		t.Fatal("an unchanged reconcile wrote the attachment")
	}
}

func TestAttachmentReferencesMustMatchBaseline(t *testing.T) {
	digest := vendoredDigest(t)
	f := newAttachmentFixture(t, resolvedBinding("a", "uid-a", 1, digest))
	wrongCatalog := f.association("a", "uid-a")
	wrongCatalog.CatalogDigest = "sha256:" + hex.EncodeToString(make([]byte, 32))
	for name, c := range map[string]struct {
		as     v1alpha1.AttachmentAssociation
		reason string
	}{
		"wrong-catalog":    {wrongCatalog, v1alpha1.ReasonCatalogMismatch},
		"foreign-stmt":     {f.association("a", "uid-a", v1alpha1.AttachmentControl{ID: "pe-3", Statements: []string{"pe-2_smt.a"}}), v1alpha1.ReasonStatementNotInControl},
		"not-in-baseline":  {f.association("a", "uid-a", v1alpha1.AttachmentControl{ID: "pe-3.1"}), v1alpha1.ReasonControlNotInBaseline},
		"stale-binding-id": {f.association("a", "uid-old"), v1alpha1.ReasonBindingReplaced},
		"missing-binding":  {f.association("gone", "uid-gone"), v1alpha1.ReasonBindingNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			f.create(name, c.as)
			res, a := f.reconcile(name)
			wantAssociations(t, a, metav1.ConditionFalse, "Mismatched", c.reason)
			if res.RequeueAfter != 0 {
				t.Fatal("a mismatch is final; it is not polled")
			}
		})
	}
}

func TestAttachmentPendingUntilBindingAndContentResolve(t *testing.T) {
	digest := vendoredDigest(t)
	unresolved := resolvedBinding("a", "uid-a", 1, digest)
	unresolved.Status.Conditions[0].Status = metav1.ConditionFalse
	stale := resolvedBinding("b", "uid-b", 1, digest)
	stale.Generation = 2 // a new spec not yet resolved
	newerProfile := resolvedBinding("c", "uid-c", 0, digest)
	otherContent := resolvedBinding("d", "uid-d", 1, digest)
	f := newAttachmentFixture(t, unresolved, stale, newerProfile, otherContent)
	f.create("unresolved", f.association("a", "uid-a"))
	f.create("stale", f.association("b", "uid-b"))
	f.create("newer-profile", f.association("c", "uid-c"))
	for name, reason := range map[string]string{"unresolved": v1alpha1.ReasonBindingUnresolved, "stale": v1alpha1.ReasonBindingUnresolved, "newer-profile": v1alpha1.ReasonBindingUnresolved} {
		res, a := f.reconcile(name)
		wantAssociations(t, a, metav1.ConditionUnknown, "Pending", reason)
		if res.RequeueAfter != attachmentPendingRequeue {
			t.Fatalf("%s: pending not requeued: %v", name, res)
		}
	}
	// Content of another digest than the vendored tree is never substituted.
	f.r.Baselines = &ContentBaselines{VendoredName: "linux-workload-hardening", ContentRoot: t.TempDir()}
	f.create("other-content", f.association("d", "uid-d"))
	_, a := f.reconcile("other-content")
	wantAssociations(t, a, metav1.ConditionUnknown, "Pending", v1alpha1.ReasonBaselineUnavailable)
	// OCI content without a freezer is unavailable, not guessed.
	f.r.Baselines = &ContentBaselines{VendoredName: "something-else", ContentRoot: "../.."}
	f.create("oci", f.association("d", "uid-d"))
	_, a = f.reconcile("oci")
	wantAssociations(t, a, metav1.ConditionUnknown, "Pending", v1alpha1.ReasonBaselineUnavailable)
}

// Binding recreation stops a valid association; a reporting-only edit (a
// new binding generation the binding has resolved) does not.
func TestAttachmentFollowsBindingIdentityNotName(t *testing.T) {
	digest := vendoredDigest(t)
	f := newAttachmentFixture(t, resolvedBinding("a", "uid-a", 1, digest))
	f.create("dc", f.association("a", "uid-a"))
	_, a := f.reconcile("dc")
	wantAssociations(t, a, metav1.ConditionTrue, "Valid", "Valid")

	ctx := context.Background()
	b := &v1alpha1.ComplianceBinding{}
	if err := f.c.Get(ctx, client.ObjectKey{Name: "a"}, b); err != nil {
		t.Fatal(err)
	}
	b.Spec.Assessment = &v1alpha1.BindingAssessment{}
	if err := f.c.Update(ctx, b); err != nil {
		t.Fatal(err)
	}
	b.Status.ObservedGeneration = b.Generation
	if err := f.c.Status().Update(ctx, b); err != nil {
		t.Fatal(err)
	}
	_, a = f.reconcile("dc")
	wantAssociations(t, a, metav1.ConditionTrue, "Valid", "Valid")

	if err := f.c.Delete(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Create(ctx, resolvedBinding("a", "uid-a2", 1, digest)); err != nil {
		t.Fatal(err)
	}
	_, a = f.reconcile("dc")
	wantAssociations(t, a, metav1.ConditionFalse, "Mismatched", v1alpha1.ReasonBindingReplaced)
	if reqs := attachmentsForBinding(f.c)(ctx, b); len(reqs) != 1 || reqs[0].Name != "dc" {
		t.Fatalf("binding events map to %v", reqs)
	}
}

func TestAttachmentDeletionReleasesRetentionFinalizer(t *testing.T) {
	f := newAttachmentFixture(t, resolvedBinding("a", "uid-a", 1, vendoredDigest(t)))
	f.create("dc", f.association("a", "uid-a"))
	f.reconcile("dc")
	ctx := context.Background()
	a := &v1alpha1.EvidenceAttachment{}
	_ = f.c.Get(ctx, client.ObjectKey{Name: "dc"}, a)
	if err := f.c.Delete(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Get(ctx, client.ObjectKey{Name: "dc"}, a); err != nil || a.DeletionTimestamp.IsZero() {
		t.Fatalf("finalizer did not hold the record: %v", err)
	}
	if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{Name: "dc"}}); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Get(ctx, client.ObjectKey{Name: "dc"}, a); !apierrors.IsNotFound(err) {
		t.Fatalf("record without stored bytes was not released: %v", err)
	}
}

func containsString(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

type stubFreezer struct {
	calls   int
	payload map[string][]byte
}

func (s *stubFreezer) Freeze(_ context.Context, _ v1alpha1.BundleReference, dir string) (*bundle.Frozen, bool, error) {
	s.calls++
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, err
	}
	fs := fstest.MapFS{}
	for k, v := range s.payload {
		fs[k] = &fstest.MapFile{Data: v}
	}
	return &bundle.Frozen{Payload: fs}, false, nil
}

// OCI content is read from a frozen verified copy in scratch space that is
// removed afterwards; results are cached per immutable digest.
func TestContentBaselinesReadFrozenOCIContent(t *testing.T) {
	payload := map[string][]byte{}
	for _, p := range []string{attachments.CatalogPath, attachments.BaselinePath} {
		raw, err := os.ReadFile("../../" + p)
		if err != nil {
			t.Fatal(err)
		}
		payload[p] = raw
	}
	fr := &stubFreezer{payload: payload}
	scratch := t.TempDir()
	c := &ContentBaselines{Freezer: fr, VendoredName: "vendored", Scratch: scratch}
	ref := v1alpha1.BundleReference{Name: "org-bundle", Digest: "sha256:" + hex.EncodeToString(make([]byte, 32))}
	for range 2 {
		b, err := c.Baseline(context.Background(), ref)
		if err != nil {
			t.Fatal(err)
		}
		if b.CatalogDigest != catalogDigest(t) {
			t.Fatalf("catalog %s", b.CatalogDigest)
		}
	}
	if fr.calls != 1 {
		t.Fatalf("froze %d times, want 1 (cached)", fr.calls)
	}
	if left, _ := os.ReadDir(scratch); len(left) != 0 {
		t.Fatalf("scratch copies left behind: %v", left)
	}
	// Content missing its catalog is unavailable, never an empty baseline.
	fr.payload = map[string][]byte{}
	ref.Digest = "sha256:" + hex.EncodeToString(append(make([]byte, 31), 1))
	if _, err := c.Baseline(context.Background(), ref); err == nil {
		t.Fatal("content without a catalog produced a baseline")
	}
}
