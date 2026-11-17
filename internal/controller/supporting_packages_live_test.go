//go:build live

package controller

// Live supporting evidence in assessment packages (add-supporting-evidence-
// attachments 5.1-5.4): a committed platform document in the RustFS
// fixture is copied into the binding's platform package and verified; the
// team's namespace package carries only the sanitized context; downloading
// the platform package needs the document-read grant in addition to run
// access, decided by the cluster's own SubjectAccessReview, and revoking it
// stops the next download. Run through scripts/targeting-live.sh
// (acceptance group "storage").

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
	"github.com/backend-bunny/Konstapel/internal/coverage"
	"github.com/backend-bunny/Konstapel/internal/download"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

func TestLiveSupportingEvidencePackages(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	ctx := l.ctx
	const (
		ns       = "konstapel-system"
		platform = "sp-platform"
		team     = "sp-team"
		suffix   = "-sp-live"
		svc      = "sp-download"
		title    = "DC West private physical access audit"
		issuer   = "Private Audit Firm AB"
		scope    = "DC West private hall C"
	)
	for _, n := range []string{ns, platform} {
		_ = l.c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
	}
	l.setNamespace(team, "sp-production")

	// Storage: the default destination on the RustFS fixture.
	s3secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "sp-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	if err := l.c.Create(ctx, s3secret); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(context.Background(), s3secret) })
	ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "sp-dest"}, Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{
		Endpoint: l.s3Endpoint, Bucket: pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/sp-dest", DevelopmentFixture: true,
		CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: s3secret.Name}}}}}
	if err := l.c.Create(ctx, ed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		got := &v1alpha1.EvidenceDestination{}
		if l.c.Get(context.Background(), client.ObjectKeyFromObject(ed), got) == nil {
			controllerutil.RemoveFinalizer(got, DestinationFinalizer)
			_ = l.c.Update(context.Background(), got)
			_ = l.c.Delete(context.Background(), got)
		}
	})
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: DefaultDestinationConfigMap},
		Data: map[string]string{DefaultDestinationNameKey: ed.Name, DefaultDestinationUIDKey: string(ed.UID)}}
	err := l.c.Create(ctx, cm)
	if apierrors.IsAlreadyExists(err) {
		err = l.c.Update(ctx, cm)
	} else if err == nil {
		t.Cleanup(func() { _ = l.c.Delete(context.Background(), cm) })
	}
	if err != nil {
		t.Fatal(err)
	}

	// The shipped roles under test-owned names.
	rename := func(u *unstructured.Unstructured) { u.SetName(u.GetName() + suffix) }
	for _, f := range []string{"evidence-attachments", "assessment-operator", "assessment-requester", "evidence-download"} {
		l.applyManifests("../../config/rbac/"+f+".yaml", rename)
	}
	cluster := func(role string) rbacv1.RoleRef {
		return rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role + suffix}
	}
	sas := map[string]string{"sp-auditor": platform, "sp-dev": team, svc: ns}
	for sa, n := range sas {
		o := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: n, Name: sa}}
		if err := l.c.Create(ctx, o); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(context.Background(), o) })
	}
	l.bindSA("sp-auditor-runs", platform, "sp-auditor", cluster("konstapel-assessment-operator"), "")
	l.bindSA("sp-team", team, "sp-dev", cluster("konstapel-assessment-requester"), team)
	l.bindSA("sp-download-service", ns, svc, cluster("konstapel-evidence-download"), "")
	l.bindSA("sp-download-credentials", ns, svc, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "konstapel-evidence-download-credentials" + suffix}, ns)
	l.applyManifests("../../config/admission/evidence-attachment-registrant.yaml", nil)

	// A binding selecting the team's namespace with one failing workload.
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: team},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "sp-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("sp-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "sp-production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "30s"}
	req := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: team, Name: "nightly"},
		Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}}}
	const recordName = "sp-dc-west-2026"
	t.Cleanup(func() {
		a := &v1alpha1.EvidenceAttachment{}
		if l.c.Get(context.Background(), client.ObjectKey{Name: recordName}, a) == nil {
			a.Finalizers = nil
			_ = l.c.Update(context.Background(), a)
			_ = l.c.Delete(context.Background(), a)
		}
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(context.Background(), &runs)
		for i := range runs.Items {
			if runs.Items[i].Spec.BindingRef.Name == b.Name {
				r := &runs.Items[i]
				r.Finalizers = nil
				_ = l.c.Update(context.Background(), r)
				_ = l.c.Delete(context.Background(), r)
			}
		}
		for _, o := range []client.Object{req, pod, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.Name}}, p} {
			_ = l.c.Delete(context.Background(), o)
		}
		l.eventually("supporting test policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
	})
	for _, o := range []client.Object{p, b, pod} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	// The only reader is this test's download server, this build: it
	// enforces document read (the chart's reader check is in
	// TestLiveHelmSupportingEvidence).
	ConfigureAssessments(AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: time.Minute, Workers: 2,
		ControllerNamespace: ns, Destinations: &DestinationPublishers{Reader: l.c, Namespace: ns}, ProtectedReaders: NoProtectedReaders})
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	stop := l.startManager()
	defer stop()
	l.waitReady(b.Name, 1)
	run := func(name string) *v1alpha1.AssessmentRun {
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(ctx, client.ObjectKey{Name: name}, r); err != nil {
			return nil
		}
		return r
	}
	// The first scheduled run finishes before the document exists.
	var first string
	l.eventually("first scheduled run published", func() (bool, string) {
		s := l.binding(b.Name).Status.Assessment
		if s == nil || s.Schedule == nil {
			return false, toJSON(s)
		}
		if s.Schedule.ActiveRun != nil {
			first = s.Schedule.ActiveRun.Name
		}
		r := run(first)
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted && s.Schedule.ActiveRun == nil, toJSON(s)
	})

	// Register the document; commit its bytes to the pinned destination as
	// an uploader would.
	catalog, err := attachments.ReadVendoredBaseline(os.DirFS(root))
	if err != nil {
		t.Fatal(err)
	}
	body := append([]byte("%PDF-1.7 "+title+"\n"), bytes.Repeat([]byte{0x5a}, 4<<10)...)
	sum := sha256.Sum256(body)
	bound := l.binding(b.Name)
	a := &v1alpha1.EvidenceAttachment{ObjectMeta: metav1.ObjectMeta{Name: recordName}, Spec: v1alpha1.EvidenceAttachmentSpec{
		Document: v1alpha1.AttachmentDocument{Title: title, MediaType: "application/pdf", Size: int64(len(body)), SHA256: "sha256:" + hex.EncodeToString(sum[:])},
		Source:   v1alpha1.AttachmentSource{Issuer: issuer, URL: "https://audit.invalid/private-report"},
		Validity: v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)), ValidUntil: metav1.NewTime(time.Now().Add(365 * 24 * time.Hour).UTC().Truncate(time.Second))},
		Associations: []v1alpha1.AttachmentAssociation{{Binding: v1alpha1.ExactBindingReference{Name: b.Name, UID: string(bound.UID)}, CatalogDigest: catalog.CatalogDigest,
			Controls: []v1alpha1.AttachmentControl{{ID: "pe-3", Statements: []string{"pe-3_smt.a"}}}}},
		Scope: v1alpha1.AttachmentScope{Description: scope}}}
	if err := l.c.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	l.eventually("document pinned", func() (bool, string) {
		_ = l.c.Get(ctx, client.ObjectKeyFromObject(a), a)
		return a.Status.Storage != nil && a.Status.Storage.Destination != nil, toJSON(a.Status)
	})
	ks := &corev1.Namespace{}
	if err := l.c.Get(ctx, client.ObjectKey{Name: "kube-system"}, ks); err != nil {
		t.Fatal(err)
	}
	st, err := NewAttachmentStores(l.c, ns).Store(ctx, *a.Status.Storage.Destination)
	if err != nil {
		t.Fatal(err)
	}
	ref := attachments.Ref{ClusterID: "kube-system:" + string(ks.UID), UID: string(a.UID)}
	if _, err := st.Stage(ctx, attachments.StageRequest{Ref: ref, Document: attachments.Expected(a.Spec), Uploader: attachments.Principal{Username: "sp-uploader"}, Body: bytes.NewReader(body)}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Commit(ctx, attachments.CommitRequest{Ref: ref, SpecDigest: attachments.SpecDigest(a.Spec), Document: attachments.Expected(a.Spec),
		ValidUntil: a.Spec.Validity.ValidUntil.UTC(), Retention: 2160 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	l.eventually("document committed, available and validly associated", func() (bool, string) {
		_ = l.c.Get(ctx, client.ObjectKeyFromObject(a), a)
		ok := a.Status.Storage.Commitment != nil && a.Status.Content != nil && a.Status.Content.State == v1alpha1.ContentAvailable &&
			len(a.Status.Associations) == 1 && a.Status.Associations[0].State == v1alpha1.AssociationValid
		return ok, toJSON(a.Status)
	})

	// A manual platform run and the team's request run, both after the
	// document became available.
	manual := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "sp-audit-manual"},
		Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}, Scope: v1alpha1.RunScopeBinding}}
	if err := l.c.Create(ctx, manual); err != nil {
		t.Fatal(err)
	}
	l.eventually("manual platform run published", func() (bool, string) {
		r := run(manual.Name)
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted && r.Status.Publication != nil && r.Status.Publication.Phase == v1alpha1.PublicationPhase(publication.PhaseCommitted), toJSON(r.Status)
	})
	if err := l.c.Create(ctx, req); err != nil {
		t.Fatal(err)
	}
	var rs v1alpha1.AssessmentRequestStatus
	l.eventually("team request published", func() (bool, string) {
		got := &v1alpha1.AssessmentRequest{}
		_ = l.c.Get(ctx, client.ObjectKeyFromObject(req), got)
		rs, req.UID = got.Status, got.UID
		return rs.Phase == v1alpha1.RequestCompleted && rs.ArtifactRef != "", toJSON(rs)
	})

	// The download service as its own service account.
	svcCfg := rest.AnonymousClientConfig(l.cfg)
	svcCfg.BearerToken = l.apiToken(ns, svc)
	svcC, err := client.New(svcCfg, client.Options{Scheme: l.c.Scheme()})
	if err != nil {
		t.Fatal(err)
	}
	dp := &DestinationPublishers{Reader: svcC, Namespace: ns}
	srv := &download.Server{Reader: svcC, Reviews: download.KubeReviewer{Client: svcC, Audience: downloadAudience}, TempDir: t.TempDir(),
		PublisherFor: func(ctx context.Context, r *v1alpha1.AssessmentRun) (publication.Publisher, error) {
			return dp.For(ctx, r.Status.Destination)
		}}
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()
	hc := ts.Client()
	auditor, dev := l.token(platform, "sp-auditor", downloadAudience), l.token(team, "sp-dev", downloadAudience)
	platformURL := ts.URL + "/v1/assessmentruns/" + string(run(manual.Name).UID) + "/download"
	teamURL := ts.URL + "/v1/namespaces/" + team + "/assessmentrequests/nightly/download?uid=" + string(req.UID)

	// 1. Run access alone does not reach the protected platform package.
	code, out := fetch(t, hc, platformURL, auditor)
	if code != http.StatusForbidden || bytes.Contains(out, []byte(title)) || bytes.Contains(out, []byte("%PDF")) {
		// Never log the body: it may be the protected package.
		t.Fatalf("run reader without document read: %d (%d bytes)", code, len(out))
	}
	// 2. With the cluster-wide document-read grant it is served, and the
	// package carries the verified copy and protected context.
	grant := l.bindSA("sp-auditor-documents", platform, "sp-auditor", cluster("konstapel-evidence-attachment-downloader"), "")
	l.eventually("document read granted", func() (bool, string) {
		code, out = fetch(t, hc, platformURL, auditor)
		return code == http.StatusOK, http.StatusText(code)
	})
	dir := t.TempDir()
	if err := publication.Extract(bytes.NewReader(out), dir); err != nil {
		t.Fatal(err)
	}
	d, err := s3store.ValidatePackage(dir) // includes coverage.VerifySupportingPackage
	if err != nil {
		t.Fatalf("platform package does not validate: %v", err)
	}
	copyBytes, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(coverage.SupportingCopyPath(string(a.UID)))))
	if err != nil || !bytes.Equal(copyBytes, body) || !d.Protected() {
		t.Fatalf("platform package copy (%v) or protection %+v", err, d.Protection)
	}
	repJSON, _ := os.ReadFile(filepath.Join(dir, coverage.JSONFile))
	rep, err := coverage.Parse(repJSON)
	if err != nil {
		t.Fatal(err)
	}
	var entry *coverage.SupportingRecord
	for i := range rep.SupportingEvidence.Entries {
		if rep.SupportingEvidence.Entries[i].Source == string(a.UID) {
			entry = &rep.SupportingEvidence.Entries[i]
		}
	}
	if entry == nil || entry.Access != coverage.AccessIncluded || entry.Temporal != coverage.SupportingCurrent || entry.Attribution != coverage.SupportingAttributed ||
		d.Evidence.Expected == 0 || d.Outcomes.Fail == 0 {
		t.Fatalf("platform entry %+v; evidence %+v outcomes %+v", entry, d.Evidence, d.Outcomes)
	}
	if bytes.Contains(out, []byte("audit.invalid")) {
		t.Fatal("the declared source URL is in the package")
	}
	l.record("platform-package", map[string]any{"protection": d.Protection, "copyBytes": len(copyBytes), "access": entry.Access, "temporal": entry.Temporal})

	// 3. The team's package: sanitized context only, no protected role.
	code, out = fetch(t, hc, teamURL, dev)
	if code != http.StatusOK {
		t.Fatalf("team download: %d (%d bytes)", code, len(out))
	}
	tdir := t.TempDir()
	if err := publication.Extract(bytes.NewReader(out), tdir); err != nil {
		t.Fatal(err)
	}
	td, err := s3store.ValidatePackage(tdir)
	if err != nil || td.Protected() || td.Scope.Kind != publication.ScopeNamespace {
		t.Fatalf("team package %v %+v", err, td.Protection)
	}
	var all []byte
	_ = filepath.WalkDir(tdir, func(p string, e os.DirEntry, err error) error {
		if err == nil && !e.IsDir() {
			b, _ := os.ReadFile(p)
			all = append(all, b...)
		}
		return nil
	})
	for _, leak := range []string{title, issuer, scope, "audit.invalid", strings.TrimPrefix(a.Spec.Document.SHA256, "sha256:"), "%PDF", "supporting-evidence/"} {
		if bytes.Contains(all, []byte(leak)) {
			t.Errorf("team package contains %q", leak)
		}
	}
	trep, _ := coverage.Parse(func() []byte { b, _ := os.ReadFile(filepath.Join(tdir, coverage.JSONFile)); return b }())
	if trep == nil || len(trep.SupportingEvidence.Entries) != 1 || trep.SupportingEvidence.Entries[0].Access != coverage.AccessRestricted {
		t.Fatalf("team supporting context %+v", trep)
	}
	// The team's credentials never reach the platform package.
	if code, _ := fetch(t, hc, platformURL, dev); code != http.StatusForbidden {
		t.Fatalf("team reached the platform package: %d", code)
	}
	l.record("team-package", map[string]any{"access": coverage.AccessRestricted, "protected": false})

	// 4. Revocation of the document-read grant stops the next download;
	// historical access never depends on the record: withdraw it.
	if err := l.c.Delete(ctx, grant); err != nil {
		t.Fatal(err)
	}
	l.eventually("document read revoked", func() (bool, string) {
		code, _ := fetch(t, hc, platformURL, auditor)
		return code == http.StatusForbidden, ""
	})
	if err := l.c.Delete(ctx, a); err != nil {
		t.Fatal(err)
	}
	l.eventually("record withdrawn", func() (bool, string) {
		_ = l.c.Get(ctx, client.ObjectKeyFromObject(a), a)
		return a.Status.Withdrawal != nil, toJSON(a.Status)
	})
	l.bindSA("sp-auditor-documents-2", platform, "sp-auditor", cluster("konstapel-evidence-attachment-downloader"), "")
	l.eventually("historical package served after withdrawal", func() (bool, string) {
		code, out := fetch(t, hc, platformURL, auditor)
		return code == http.StatusOK && bytes.Contains(out, []byte{0x1f, 0x8b}), ""
	})
	cond := meta.FindStatusCondition(run(manual.Name).Status.Conditions, v1alpha1.ConditionEvidenceComplete)
	l.record("revocation", map[string]any{"afterRevocation": 403, "afterWithdrawalWithGrant": 200, "evidenceComplete": cond != nil && cond.Status == metav1.ConditionTrue})
}
