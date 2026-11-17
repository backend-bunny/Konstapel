package controller

// Supporting evidence in runs and packages (add-supporting-evidence-
// attachments 5.1, 5.2).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/attachments"
	attfake "github.com/backend-bunny/Konstapel/internal/attachments/fake"
	"github.com/backend-bunny/Konstapel/internal/coverage"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const supportCluster = "kube-system:cluster"

type oneStore struct{ s *attfake.Store }

func (o oneStore) Store(context.Context, v1alpha1.DestinationReference) (attachments.Store, error) {
	return o.s, nil
}

// supportEnv is a run environment whose controller reads committed
// supporting documents from one in-memory destination.
type supportEnv struct {
	*runEnv
	store   *attfake.Store
	catalog string
}

func newSupportEnv(t *testing.T, e *runEnv) *supportEnv {
	t.Helper()
	root, _ := filepath.Abs("../..")
	raw, err := os.ReadFile(filepath.Join(root, assessment.NIST+"NIST_SP-800-53_rev5_catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	st := attfake.New(func() time.Time { return e.now })
	e.rr.Attachments = &AttachmentStorage{Cluster: supportCluster, Stores: oneStore{st}}
	return &supportEnv{runEnv: e, store: st, catalog: "sha256:" + hex.EncodeToString(h[:])}
}

type attOpt func(*v1alpha1.EvidenceAttachment)

func validity(from, until time.Time) attOpt {
	return func(a *v1alpha1.EvidenceAttachment) {
		a.Spec.Validity = v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(from), ValidUntil: metav1.NewTime(until)}
	}
}

func withStatus(f func(*v1alpha1.EvidenceAttachmentStatus)) attOpt {
	return func(a *v1alpha1.EvidenceAttachment) { f(&a.Status) }
}

// attach registers, uploads and commits a document associated with
// binding (pe-3 statement a, pe-6), recorded Valid and Available, then
// applies opts.
func (e *supportEnv) attach(name, binding string, body []byte, opts ...attOpt) *v1alpha1.EvidenceAttachment {
	e.t.Helper()
	h := sha256.Sum256(body)
	uid := types.UID("att-" + name)
	a := &v1alpha1.EvidenceAttachment{ObjectMeta: metav1.ObjectMeta{Name: name, UID: uid, Finalizers: []string{v1alpha1.EvidenceAttachmentFinalizer}},
		Spec: v1alpha1.EvidenceAttachmentSpec{
			Document: v1alpha1.AttachmentDocument{Title: "Private title " + name, MediaType: "application/pdf", Size: int64(len(body)), SHA256: "sha256:" + hex.EncodeToString(h[:])},
			Source:   v1alpha1.AttachmentSource{Issuer: "Private issuer " + name, URL: "https://audit.example/" + name},
			Validity: v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(a0.Add(-24 * time.Hour)), ValidUntil: metav1.NewTime(a0.Add(365 * 24 * time.Hour))},
			Scope:    v1alpha1.AttachmentScope{Description: "Private hall " + name},
			Associations: []v1alpha1.AttachmentAssociation{{Binding: v1alpha1.ExactBindingReference{Name: binding, UID: string(e.bindingUID(binding))},
				CatalogDigest: e.catalog, Controls: []v1alpha1.AttachmentControl{{ID: "pe-3", Statements: []string{"pe-3_smt.a"}}, {ID: "pe-6"}}}},
			RegisteredBy: &v1alpha1.Requester{Username: "platform-registrar"}}}
	ctx := context.Background()
	ref := attachments.Ref{ClusterID: supportCluster, UID: string(uid)}
	doc := attachments.Expected(a.Spec)
	// Options apply before the commitment, which binds the validity.
	for _, o := range opts {
		o(a)
	}
	if _, err := e.store.Stage(ctx, attachments.StageRequest{Ref: ref, Document: doc, Uploader: attachments.Principal{Username: "uploader"}, Body: strings.NewReader(string(body))}); err != nil {
		e.t.Fatal(err)
	}
	rc, err := e.store.Commit(ctx, attachments.CommitRequest{Ref: ref, SpecDigest: attachments.SpecDigest(a.Spec), Document: doc, ValidUntil: a.Spec.Validity.ValidUntil.UTC(), Retention: 2160 * time.Hour})
	if err != nil {
		e.t.Fatal(err)
	}
	st := a.Status
	a.Status = v1alpha1.EvidenceAttachmentStatus{
		Associations: []v1alpha1.AttachmentAssociationStatus{{Binding: a.Spec.Associations[0].Binding, State: v1alpha1.AssociationValid, Reason: v1alpha1.ReasonAssociationsValid}},
		Content:      &v1alpha1.AttachmentContentStatus{State: v1alpha1.ContentAvailable, Reason: v1alpha1.ReasonContentVerified},
		Storage: &v1alpha1.AttachmentStorage{Destination: &v1alpha1.DestinationReference{Name: "primary", UID: "dest-1"},
			Commitment: &v1alpha1.AttachmentCommitment{ManifestKey: rc.ManifestKey, DocumentKey: rc.DocumentKey, DocumentVersionID: rc.DocumentVersionID,
				SHA256: rc.Document.SHA256, Size: rc.Document.Size, SpecDigest: rc.SpecDigest, Uploader: v1alpha1.Requester{Username: rc.Uploader.Username},
				CommittedAt: metav1.NewTime(rc.CommittedAt), Retention: metav1.Duration{Duration: rc.Retention}, ExpiresAt: metav1.NewTime(rc.ExpiresAt)}}}
	// Status options override the defaults.
	if st.Associations != nil {
		a.Status.Associations = st.Associations
	}
	if st.Content != nil {
		a.Status.Content = st.Content
	}
	if err := e.c.Create(ctx, a); err != nil {
		e.t.Fatal(err)
	}
	return a
}

func (e *supportEnv) withdraw(name string) {
	e.t.Helper()
	if err := e.c.Delete(context.Background(), &v1alpha1.EvidenceAttachment{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
		e.t.Fatal(err)
	}
}

// publish runs the binding's scheduled run to publication, calling during
// after the run started, and returns the run and its package directory.
func (e *supportEnv) publish(binding string, during func()) (*v1alpha1.AssessmentRun, string, []byte) {
	e.t.Helper()
	name := e.schedule(binding).ActiveRun.Name
	e.step(name)
	if during != nil {
		during()
	}
	e.report("prod", "pod-1", e.enginePolicy(), "fail", a0.Add(time.Minute))
	e.now = a0.Add(90 * time.Second)
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted {
		e.t.Fatalf("phase %s %+v", r.Status.Phase, r.Status.Conditions)
	}
	rc, _, err := e.pub.Open(context.Background(), e.ref(r))
	if err != nil {
		e.t.Fatal(err)
	}
	defer rc.Close()
	archive, _ := io.ReadAll(rc)
	return r, unpackFake(e.t, archive), archive
}

func entryBySource(t *testing.T, r *coverage.Report, uid types.UID) *coverage.SupportingRecord {
	t.Helper()
	for i := range r.SupportingEvidence.Entries {
		if r.SupportingEvidence.Entries[i].Source == string(uid) {
			return &r.SupportingEvidence.Entries[i]
		}
	}
	return nil
}

func TestPlatformPackageCarriesVerifiedSupportingCopies(t *testing.T) {
	_, _, baseDir := publishedPackage(t, nil)
	base, baseD := packagedCoverage(t, baseDir)

	e := newSupportEnv(t, newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"}))))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	cur := e.attach("current", "audit-prod", []byte("%PDF current audit"))
	expired := e.attach("expired", "audit-prod", []byte("%PDF expired audit"), validity(a0.Add(-400*24*time.Hour), a0.Add(-30*24*time.Hour)))
	future := e.attach("future", "audit-prod", []byte("%PDF future audit"), validity(a0.Add(30*24*time.Hour), a0.Add(400*24*time.Hour)))
	unavailable := e.attach("unavailable", "audit-prod", []byte("%PDF missing"), withStatus(func(s *v1alpha1.EvidenceAttachmentStatus) {
		s.Content = &v1alpha1.AttachmentContentStatus{State: v1alpha1.ContentUnavailable, Reason: v1alpha1.ReasonContentMissing}
	}))
	mismatched := e.attach("mismatched", "audit-prod", []byte("%PDF wrong catalog"), func(a *v1alpha1.EvidenceAttachment) {
		a.Status.Associations = []v1alpha1.AttachmentAssociationStatus{{Binding: a.Spec.Associations[0].Binding, State: v1alpha1.AssociationMismatched, Reason: v1alpha1.ReasonCatalogMismatch}}
	})
	damaged := e.attach("damaged", "audit-prod", []byte("%PDF damaged in storage"))
	e.store.Tamper(attachments.Ref{ClusterID: supportCluster, UID: string(damaged.UID)}, []byte("%PDF damaged in storaGE"))
	withdrawnLater := e.attach("withdrawn-later", "audit-prod", []byte("%PDF withdrawn later"))
	withdrawnBefore := e.attach("withdrawn-before", "audit-prod", []byte("%PDF withdrawn before"))
	e.withdraw(withdrawnBefore.Name)
	// Another binding's document is not part of this binding's context.
	other := e.attach("other", "audit-prod", []byte("%PDF other binding"))
	other.Spec.Associations[0].Binding.UID = "uid-another-binding"
	_ = e.c.Delete(context.Background(), other)
	o2 := other.DeepCopy()
	o2.ResourceVersion, o2.Finalizers, o2.Name, o2.UID = "", nil, "other-binding", "att-other-binding"
	if err := e.c.Create(context.Background(), o2); err != nil {
		t.Fatal(err)
	}

	changed := e.attach("changed", "audit-prod", []byte("%PDF lost during capture"))
	run, dir, archive := e.publish("audit-prod", func() {
		e.withdraw(withdrawnLater.Name)
		// Its content is lost during the capture (after it was copied).
		got := &v1alpha1.EvidenceAttachment{}
		if err := e.c.Get(context.Background(), client.ObjectKeyFromObject(changed), got); err != nil {
			t.Fatal(err)
		}
		got.Status.Content = &v1alpha1.AttachmentContentStatus{State: v1alpha1.ContentUnavailable, Reason: v1alpha1.ReasonContentMissing}
		if err := e.c.Update(context.Background(), got); err != nil {
			t.Fatal(err)
		}
	})
	r, d := packagedCoverage(t, dir) // ValidatePackage includes VerifySupportingPackage
	if !d.Protected() || !slices.Contains(d.Producer.Checks, "supporting-evidence") {
		t.Fatalf("protection %+v checks %v", d.Protection, d.Producer.Checks)
	}
	// Documents never change the technical evidence or automation.
	if d.Evidence != baseD.Evidence || d.Outcomes != baseD.Outcomes || *r.TechnicalEvidence.Evidence != *base.TechnicalEvidence.Evidence {
		t.Fatalf("technical evidence changed: %+v %+v vs %+v %+v", d.Evidence, d.Outcomes, baseD.Evidence, baseD.Outcomes)
	}
	for i := range r.Controls {
		if r.Controls[i].Automation != base.Controls[i].Automation || len(r.Controls[i].Checks) != len(base.Controls[i].Checks) {
			t.Fatalf("control %s changed", r.Controls[i].ID)
		}
	}
	if s, b := coverage.Summarize(r, ""), coverage.Summarize(base, ""); s.Automation != b.Automation || run.Status.Summary.Coverage == nil {
		t.Fatalf("coverage automation %+v vs %+v", s.Automation, b.Automation)
	}
	se := r.SupportingEvidence
	if se.Integration != coverage.IntegrationAvailable || se.Projection != coverage.ProjectionPlatform {
		t.Fatalf("supporting %+v", se)
	}
	want := map[types.UID]struct {
		access, content, reason, temporal, association string
		withdrawn, changed                             bool
	}{
		changed.UID:        {coverage.AccessIncluded, "available", "Verified", "current", "valid", false, true},
		cur.UID:            {coverage.AccessIncluded, "available", "Verified", "current", "valid", false, false},
		expired.UID:        {coverage.AccessIncluded, "available", "Verified", "expired", "valid", false, false},
		future.UID:         {coverage.AccessIncluded, "available", "Verified", "notYetValid", "valid", false, false},
		unavailable.UID:    {coverage.AccessNotIncluded, "unavailable", "ObjectMissing", "current", "valid", false, false},
		mismatched.UID:     {coverage.AccessNotIncluded, "available", "Verified", "current", "mismatched", false, false},
		damaged.UID:        {coverage.AccessNotIncluded, "unavailable", reasonNotRetrieved, "current", "valid", false, false},
		withdrawnLater.UID: {coverage.AccessIncluded, "available", "Verified", "current", "valid", true, false},
	}
	if len(se.Entries) != len(want) {
		t.Fatalf("entries %d, want %d: %+v", len(se.Entries), len(want), se.Entries)
	}
	for uid, w := range want {
		en := entryBySource(t, r, uid)
		if en == nil || en.Access != w.access || en.Content != w.content || en.ContentReason != w.reason || en.Temporal != w.temporal ||
			en.Association != w.association || en.Withdrawn != w.withdrawn || en.Changed != w.changed || en.Document == nil || en.BindingUID != run.Status.Binding.UID {
			t.Errorf("%s: %+v", uid, en)
			continue
		}
		if w.access == coverage.AccessIncluded {
			copyPath := filepath.Join(dir, filepath.FromSlash(en.Document.Copy))
			got, err := os.ReadFile(copyPath)
			h := sha256.Sum256(got)
			if err != nil || hex.EncodeToString(h[:]) != en.Document.SHA256 {
				t.Errorf("%s: copy %s: %v", uid, en.Document.Copy, err)
			}
		}
	}
	for _, uid := range []types.UID{withdrawnBefore.UID, o2.UID} {
		if entryBySource(t, r, uid) != nil || strings.Contains(string(archive), string(uid)) {
			t.Errorf("%s is in the package", uid)
		}
	}
	// pe-3 references the attributed entries; no row gains a check.
	for _, c := range r.Controls {
		if (c.ID == "pe-3" || c.ID == "pe-6") && len(c.SupportingEvidence) != len(want) {
			t.Errorf("%s references %d entries", c.ID, len(c.SupportingEvidence))
		}
	}
	// The source URL is never packaged or fetched.
	if strings.Contains(string(archive), "audit.example") {
		t.Fatal("the declared source URL is in the package")
	}
	// The packaged context is the one the report was built from.
	raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(publication.SupportingContextFile)))
	if err != nil {
		t.Fatal(err)
	}
	if err := coverage.VerifySupportingContext(raw, d); err != nil {
		t.Fatal(err)
	}
}

// Without any associated record, a platform package is unchanged: the
// integration is available with no entries, and nothing is protected.
func TestPlatformPackageWithoutDocumentsIsUnprotected(t *testing.T) {
	e := newSupportEnv(t, newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"}))))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	_, dir, _ := e.publish("audit-prod", nil)
	r, d := packagedCoverage(t, dir)
	if d.Protected() || r.SupportingEvidence.Integration != coverage.IntegrationAvailable || len(r.SupportingEvidence.Entries) != 0 {
		t.Fatalf("protection %+v supporting %+v", d.Protection, r.SupportingEvidence)
	}
	if _, err := os.Stat(filepath.Join(dir, "supporting-evidence")); !os.IsNotExist(err) {
		t.Fatal("an empty context left supporting files")
	}
}

// A namespace package never carries a document, its context, private
// metadata or a link: only restricted entries in its coverage.
func TestNamespacePackageHasSanitizedSupportingContextOnly(t *testing.T) {
	e := newSupportEnv(t, newTeamEnv(t))
	a := e.attach("dc-audit", "audit-all", []byte("%PDF team-visible? no"))
	e.request("dev", "nightly")
	e.assess("audit-all")
	st := e.requestStatus("dev", "nightly")
	run := e.run(st.Run.Name)
	e.step(run.Name)
	e.report("dev", "pod-dev", e.enginePolicy(), "fail", e.now.Add(time.Minute))
	e.now = e.now.Add(2 * time.Minute)
	e.step(run.Name)
	run = e.run(run.Name)
	if run.Status.Phase != v1alpha1.RunCompleted {
		t.Fatalf("phase %s %+v", run.Status.Phase, run.Status.Conditions)
	}
	rc, _, err := e.pub.Open(context.Background(), e.ref(run))
	if err != nil {
		t.Fatal(err)
	}
	archive, _ := io.ReadAll(rc)
	rc.Close()
	dir := unpackFake(t, archive)
	r, d := packagedCoverage(t, dir)
	if d.Protected() || d.Scope.Kind != publication.ScopeNamespace {
		t.Fatalf("namespace package protection %+v", d.Protection)
	}
	en := entryBySource(t, r, a.UID)
	if r.SupportingEvidence.Projection != coverage.ProjectionNamespace || en == nil || en.Access != coverage.AccessRestricted || en.Document != nil || en.Revision != "" ||
		en.Temporal != "current" || en.Content != "available" {
		t.Fatalf("namespace entry %+v", en)
	}
	for _, leak := range []string{"Private title", "Private issuer", "Private hall", "audit.example", a.Spec.Document.SHA256[7:], "supporting-evidence/", "team-visible"} {
		if strings.Contains(string(archive), leak) {
			t.Errorf("namespace package contains %q", leak)
		}
	}
	if calls := e.store.Calls(); slices.ContainsFunc(calls, func(c string) bool { return strings.HasPrefix(c, "Open") }) {
		t.Fatalf("a namespace run read a document: %v", calls)
	}
}

// A staged copy lost or changed after closure is capture loss: the run
// never re-reads a newer document under its identity.
func TestLostSupportingCopyIsCaptureLoss(t *testing.T) {
	e := newSupportEnv(t, newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"}))))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	a := e.attach("current", "audit-prod", []byte("%PDF current audit"))
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	e.report("prod", "pod-1", e.enginePolicy(), "fail", a0.Add(time.Minute))
	e.now = a0.Add(30 * time.Second)
	e.step(name) // collecting: copies the document
	run := e.run(name)
	p := e.rr.supportingCopy(run, string(a.UID))
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("not staged: %v", err)
	}
	// The closure is frozen, as before a crash, with the copy then replaced.
	c := e.staged(run)
	c.Window.Closed = e.now
	ev, err := c.Evaluate(nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b := e.binding("audit-prod")
	frozen := closedRun{Capture: c, Evaluation: ev, Supporting: e.rr.closeSupporting(context.Background(), run, b, c.Window.Closed)}
	if err := assessment.Write(filepath.Join(e.rr.staging(run), "closed.json"), frozen); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("%PDF newer bytes!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	opens := len(e.store.Calls())
	e.step(name)
	run = e.run(name)
	if run.Status.Phase != v1alpha1.RunFailed || !hasReason(run, v1alpha1.ReasonCaptureLost) {
		t.Fatalf("phase %s %+v", run.Status.Phase, run.Status.Conditions)
	}
	if len(e.store.Calls()) != opens {
		t.Fatal("the document was read again after closure")
	}
}

// Storage failure at capture and an expired source are documentary
// unavailability; the run still publishes its technical evidence.
func TestSupportingStorageFailureIsDocumentaryOnly(t *testing.T) {
	e := newSupportEnv(t, newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"}))))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	down := e.attach("down", "audit-prod", []byte("%PDF storage down"))
	e.store.Fail(attfake.OpOpen, attachments.ErrUnavailable)
	run, dir, _ := e.publish("audit-prod", nil)
	r, d := packagedCoverage(t, dir)
	en := entryBySource(t, r, down.UID)
	if en == nil || en.Access != coverage.AccessNotIncluded || en.Content != "unavailable" || en.ContentReason != reasonNotRetrieved {
		t.Fatalf("entry %+v", en)
	}
	if d.Evidence.Completeness != publication.Complete || run.Status.Summary.Outcomes.Fail != 1 {
		t.Fatalf("technical evidence %+v %+v", d.Evidence, run.Status.Summary.Outcomes)
	}
	// Protected still: the context names a private title.
	if !d.Protected() {
		t.Fatal("a package with private supporting metadata is unprotected")
	}
	for _, f := range d.Files {
		if f.Role == publication.RoleSupportingDocument {
			t.Fatalf("a copy was packaged: %s", f.Path)
		}
	}
}

func hasReason(r *v1alpha1.AssessmentRun, reason string) bool {
	return slices.ContainsFunc(r.Status.Conditions, func(c metav1.Condition) bool { return c.Reason == reason })
}

// The documented copy limits are the controller's.
func TestDocumentedSupportingCopyLimits(t *testing.T) {
	raw, err := os.ReadFile("../../docs/supporting-evidence.md")
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%d copies or %d MiB of copies", maxSupportingCopies, maxSupportingCopyBytes>>20)
	if !strings.Contains(strings.Join(strings.Fields(string(raw)), " "), want) {
		t.Fatalf("docs do not state %q", want)
	}
}

// Documents are read only within the collection window: once it has
// closed, a document not yet retrieved is reported NotRetrieved and storage
// is not contacted again, even if it has recovered.
func TestSupportingReadsStopAtTheCollectionWindow(t *testing.T) {
	e := newSupportEnv(t, newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"}))))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	a := e.attach("late", "audit-prod", []byte("%PDF late"))
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	e.store.Fail(attfake.OpOpen, attachments.ErrUnavailable)
	e.now = a0.Add(30 * time.Second)
	e.step(name) // incomplete evidence: keeps collecting, the read fails
	opens := func() int {
		n := 0
		for _, c := range e.store.Calls() {
			if strings.HasPrefix(c, "Open ") {
				n++
			}
		}
		return n
	}
	if opens() != 1 || e.run(name).Status.Phase != v1alpha1.RunCollecting {
		t.Fatalf("opens %d phase %s", opens(), e.run(name).Status.Phase)
	}
	e.store.Fail(attfake.OpOpen, nil)
	e.now = a0.Add(5*time.Minute + time.Second) // the window has closed
	e.step(name)
	run := e.run(name)
	if run.Status.Phase != v1alpha1.RunCompleted || opens() != 1 {
		t.Fatalf("phase %s, opens %d", run.Status.Phase, opens())
	}
	rc, _, err := e.pub.Open(context.Background(), e.ref(run))
	if err != nil {
		t.Fatal(err)
	}
	archive, _ := io.ReadAll(rc)
	rc.Close()
	r, _ := packagedCoverage(t, unpackFake(t, archive))
	if en := entryBySource(t, r, a.UID); en == nil || en.Access != coverage.AccessNotIncluded || en.ContentReason != reasonNotRetrieved {
		t.Fatalf("entry %+v", en)
	}
}

// A document whose stored bytes do not match its registration is never
// staged.
func TestFetchSupportingRefusesDamagedBytes(t *testing.T) {
	e := newSupportEnv(t, newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"}))))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	a := e.attach("damaged", "audit-prod", []byte("%PDF original bytes"))
	e.store.Tamper(attachments.Ref{ClusterID: supportCluster, UID: string(a.UID)}, []byte("%PDF tampered bytes"))
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	run := e.run(name)
	rec, err := e.rr.readSupporting(run)
	if err != nil || len(rec.Entries) != 1 {
		t.Fatalf("frozen %+v %v", rec, err)
	}
	if err := e.rr.fetchSupporting(context.Background(), run, rec.Entries[0]); !errors.Is(err, attachments.ErrIntegrity) {
		t.Fatalf("damaged bytes: %v", err)
	}
	if _, err := os.Stat(e.rr.supportingCopy(run, string(a.UID))); !os.IsNotExist(err) {
		t.Fatal("damaged bytes were staged")
	}
	if left, _ := os.ReadDir(filepath.Join(e.rr.staging(run), runSupportingDir)); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

// One datacenter document supports two explicitly named bindings: each
// binding's platform package carries its own verified copy and its own
// entry, while the technical counts, outcomes (including accepted risk) and
// enforcement revisions are exactly those of the same runs without it.
func TestSharedDocumentSupportsSeveralBindings(t *testing.T) {
	mk := func() *runEnv {
		e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})),
			shortTimeout(epochBinding("audit-prod-2", map[string]v1alpha1.LabelValue{"environment": "production"})))
		for _, b := range []string{"audit-prod", "audit-prod-2"} {
			e.deliver(b)
			e.assess(b)
		}
		return e
	}
	publishBoth := func(e *supportEnv) map[string]publication.Descriptor {
		out := map[string]publication.Descriptor{}
		names := map[string]string{"audit-prod": e.schedule("audit-prod").ActiveRun.Name, "audit-prod-2": e.schedule("audit-prod-2").ActiveRun.Name}
		for _, n := range names {
			e.step(n)
		}
		reportAll(t, e.runEnv, "prod", "pod-1", "fail", a0.Add(time.Minute))
		e.now = a0.Add(90 * time.Second)
		for b, n := range names {
			e.step(n)
			r := e.run(n)
			rc, _, err := e.pub.Open(context.Background(), e.ref(r))
			if err != nil {
				t.Fatalf("%s: %v (%s %+v)", b, err, r.Status.Phase, r.Status.Conditions)
			}
			archive, _ := io.ReadAll(rc)
			rc.Close()
			dir := unpackFake(t, archive)
			rep, d := packagedCoverage(t, dir)
			out[b] = d
			if en := entryBySource(t, rep, "att-shared"); e.store != nil && (en == nil || en.Access != coverage.AccessIncluded || en.BindingUID != r.Status.Binding.UID ||
				en.Attribution != coverage.SupportingAttributed) {
				t.Fatalf("%s entry %+v", b, en)
			}
		}
		return out
	}
	base := &supportEnv{runEnv: mk()}
	without := publishBoth(base)

	e := newSupportEnv(t, mk())
	e.attach("shared", "audit-prod", []byte("%PDF shared datacenter audit"), func(a *v1alpha1.EvidenceAttachment) {
		second := a.Spec.Associations[0]
		second.Binding = v1alpha1.ExactBindingReference{Name: "audit-prod-2", UID: string(e.bindingUID("audit-prod-2"))}
		a.Spec.Associations = append(a.Spec.Associations, second)
		a.Status.Associations = []v1alpha1.AttachmentAssociationStatus{
			{Binding: a.Spec.Associations[0].Binding, State: v1alpha1.AssociationValid, Reason: v1alpha1.ReasonAssociationsValid},
			{Binding: second.Binding, State: v1alpha1.AssociationValid, Reason: v1alpha1.ReasonAssociationsValid}}
	})
	with := publishBoth(e)
	for b, d := range with {
		w := without[b]
		if d.Evidence != w.Evidence || d.Outcomes != w.Outcomes || !slices.Equal(d.Revisions.Enforcement, w.Revisions.Enforcement) ||
			d.Revisions.BindingConfiguration != w.Revisions.BindingConfiguration || !d.Protected() || w.Protected() {
			t.Fatalf("%s: with %+v %+v %v, without %+v %+v %v", b, d.Evidence, d.Outcomes, d.Revisions.Enforcement, w.Evidence, w.Outcomes, w.Revisions.Enforcement)
		}
	}
	if with["audit-prod"].Run.BindingUID == with["audit-prod-2"].Run.BindingUID {
		t.Fatal("the two packages are for one binding")
	}
}

// reportAll writes one PolicyReport for pod with a result for every engine
// policy.
func reportAll(t *testing.T, e *runEnv, ns, podUID, outcome string, at time.Time) {
	t.Helper()
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(targeting.ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
	if err := e.c.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	var results []any
	for _, p := range list.Items {
		results = append(results, map[string]any{"policy": p.GetName(), "result": outcome, "source": "KyvernoValidatingPolicy",
			"properties": map[string]any{"cel.validationIndex": "0"}, "timestamp": map[string]any{"seconds": at.Unix(), "nanos": int64(0)}})
	}
	r := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "r-" + podUID, "namespace": ns},
		"scope":    map[string]any{"apiVersion": "v1", "kind": "Pod", "namespace": ns, "name": "web", "uid": podUID},
		"results":  results,
	}}
	r.SetGroupVersionKind(PolicyReportGVK)
	r.SetUID(types.UID("report-" + podUID))
	if err := e.c.Create(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}
