//go:build live

package controller

// Integrated supporting-evidence acceptance (add-supporting-evidence-
// attachments 7.2): attachments, coverage and assessments together, against
// the real API server, the cluster's own TokenReview and SubjectAccessReview,
// and the pinned RustFS fixture, with platform and namespace credentials
// bound to the shipped roles. Nothing is written to storage except through
// the transfer service and the controller:
//   - `konstapel evidence register` registers one facility document for two
//     bindings (binding UIDs filled from the cluster, registrant recorded by
//     admission), and the uploader commits it through the transfer service;
//     expired, not-yet-valid and never-uploaded documents are registered
//     beside it. Registration changes no binding or engine policy;
//   - each binding's platform package carries the shared document, verified,
//     under the one record identity and declared facility scope; expired
//     and future copies carry their temporal state, and the unuploaded
//     document is reported pending and not included. The technical
//     evidence, outcomes, control rows and enforcement revisions equal those
//     of the run before any document existed;
//   - downloads are independently authorized: run access alone, document
//     read alone and namespace credentials reach no protected package or
//     source document; both grants together do. Each team's package lists
//     only its binding's documents as restricted entries, without document
//     bytes, private metadata or links;
//   - retention is independent: a package deleted at its expiry leaves the
//     source document, which a later run copies again; a source deleted at
//     its own expiry leaves the package that copied it readable and valid.
// Run through scripts/targeting-live.sh (acceptance group "assessments").

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
	"github.com/backend-bunny/Konstapel/internal/coverage"
	"github.com/backend-bunny/Konstapel/internal/download"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// unpackPackage extracts a downloaded package archive, validates it with
// s3store.ValidatePackage (which runs coverage.VerifySupportingPackage) and
// parses its coverage report.
func unpackPackage(t *testing.T, archive []byte) (string, publication.Descriptor, *coverage.Report) {
	t.Helper()
	dir := t.TempDir()
	if err := publication.Extract(bytes.NewReader(archive), dir); err != nil {
		t.Fatal(err)
	}
	d, err := s3store.ValidatePackage(dir)
	if err != nil {
		t.Fatalf("package does not validate: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, coverage.JSONFile))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := coverage.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return dir, d, rep
}

// supportingEntry returns the report's entry for a record UID, or nil.
func supportingEntry(rep *coverage.Report, source string) *coverage.SupportingRecord {
	for i := range rep.SupportingEvidence.Entries {
		if rep.SupportingEvidence.Entries[i].Source == source {
			return &rep.SupportingEvidence.Entries[i]
		}
	}
	return nil
}

// supportingSources lists the report's entry sources, sorted.
func supportingSources(rep *coverage.Report) []string {
	var out []string
	for _, e := range rep.SupportingEvidence.Entries {
		out = append(out, e.Source)
	}
	slices.Sort(out)
	return out
}

// packageCopy returns an extracted package's copy of a document, or nil.
func packageCopy(dir, source string) []byte {
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(coverage.SupportingCopyPath(source))))
	if err != nil {
		return nil
	}
	return b
}

// packageText concatenates every file of an extracted package, for leak
// checks.
func packageText(dir string) []byte {
	var all []byte
	_ = filepath.WalkDir(dir, func(p string, e os.DirEntry, err error) error {
		if err == nil && !e.IsDir() {
			b, _ := os.ReadFile(p)
			all = append(all, b...)
		}
		return nil
	})
	return all
}

// supportingDocument is one registered test document.
type supportingDocument struct {
	name, title, issuer, scope string
	body                       []byte
	record                     *v1alpha1.EvidenceAttachment
}

func (d *supportingDocument) uid() string { return string(d.record.UID) }

func (d *supportingDocument) sha() string {
	sum := sha256.Sum256(d.body)
	return hex.EncodeToString(sum[:])
}

func newSupportingDocument(name, title, issuer, scope string) *supportingDocument {
	pad := make([]byte, 4<<10)
	_, _ = rand.Read(pad)
	return &supportingDocument{name: name, title: title, issuer: issuer, scope: scope, body: append([]byte("%PDF-1.7 "+title+"\n"), pad...)}
}

func TestLiveSupportingEvidenceAcceptance(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	ctx := l.ctx
	const (
		ns       = "konstapel-system"
		platform = "sa-platform"
		teamA    = "sa-team-a"
		teamB    = "sa-team-b"
		suffix   = "-sa-live"
		svc      = "sa-download"
		// The transfer service's source retention, frozen into each
		// commitment: an expired document's source expires this long after
		// its commitment, a current one this long after its validUntil.
		sourceRetention = 4 * time.Minute
		// Binding A's package retention: its packages expire long before
		// the shared document's source.
		packageRetention = 2 * time.Minute
	)
	for _, n := range []string{ns, platform} {
		_ = l.c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
	}
	l.setNamespace(teamA, "sa-production-a")
	l.setNamespace(teamB, "sa-production-b")

	// Storage: the central default destination on the RustFS fixture, for
	// documents and packages alike.
	s3secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "sa-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	if err := l.c.Create(ctx, s3secret); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(context.Background(), s3secret) })
	ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "sa-dest"}, Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{
		Endpoint: l.s3Endpoint, Bucket: pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/sa-dest", DevelopmentFixture: true,
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

	// The shipped roles under test-owned names; their rules are unchanged.
	rename := func(u *unstructured.Unstructured) { u.SetName(u.GetName() + suffix) }
	for _, f := range []string{"evidence-attachments", "compliance-viewer", "assessment-operator", "assessment-requester", "evidence-download"} {
		l.applyManifests("../../config/rbac/"+f+".yaml", rename)
	}
	cluster := func(role string) rbacv1.RoleRef {
		return rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role + suffix}
	}
	sas := map[string]string{"sa-registrar": platform, "sa-uploader": platform, "sa-auditor": platform, "sa-docreader": platform,
		"sa-dev-a": teamA, "sa-dev-b": teamB, svc: ns}
	for sa, n := range sas {
		o := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: n, Name: sa}}
		if err := l.c.Create(ctx, o); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(context.Background(), o) })
	}
	l.bindSA("sa-registrar", platform, "sa-registrar", cluster("konstapel-evidence-attachment-registrar"), "")
	l.bindSA("sa-registrar-bindings", platform, "sa-registrar", cluster("konstapel-compliance-viewer"), "")
	l.bindSA("sa-uploader", platform, "sa-uploader", cluster("konstapel-evidence-attachment-uploader"), "")
	// The auditor reads runs; the document-read grant comes later.
	l.bindSA("sa-auditor-runs", platform, "sa-auditor", cluster("konstapel-assessment-operator"), "")
	// The document reader reads source documents, never runs.
	l.bindSA("sa-docreader", platform, "sa-docreader", cluster("konstapel-evidence-attachment-downloader"), "")
	l.bindSA("sa-team-a", teamA, "sa-dev-a", cluster("konstapel-assessment-requester"), teamA)
	l.bindSA("sa-team-b", teamB, "sa-dev-b", cluster("konstapel-assessment-requester"), teamB)
	l.bindSA("sa-download-service", ns, svc, cluster("konstapel-evidence-download"), "")
	l.bindSA("sa-download-credentials", ns, svc, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "konstapel-evidence-download-credentials" + suffix}, ns)
	l.applyManifests("../../config/admission/evidence-attachment-registrant.yaml", nil)

	// Two platform bindings, each selecting one team's namespace with one
	// failing workload. Binding A's packages expire after two minutes.
	yes := true
	pods := []client.Object{}
	for _, n := range []string{teamA, teamB} {
		pods = append(pods, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: n},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}})
	}
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "sa-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	bA := bindingObj("sa-audit-a", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "sa-production-a"})
	bA.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "30s", Retention: v1alpha1.Duration(packageRetention.String())}
	bB := bindingObj("sa-audit-b", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "sa-production-b"})
	bB.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "30s"}
	reqA := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: teamA, Name: "nightly"},
		Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: bA.Name}}}
	reqB := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: teamB, Name: "nightly"},
		Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: bB.Name}}}
	var docs []*supportingDocument
	t.Cleanup(func() {
		for _, d := range docs {
			a := &v1alpha1.EvidenceAttachment{}
			if l.c.Get(context.Background(), client.ObjectKey{Name: d.name}, a) == nil {
				a.Finalizers = nil
				_ = l.c.Update(context.Background(), a)
				_ = l.c.Delete(context.Background(), a)
			}
		}
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(context.Background(), &runs)
		for i := range runs.Items {
			if r := &runs.Items[i]; r.Spec.BindingRef.Name == bA.Name || r.Spec.BindingRef.Name == bB.Name {
				r.Finalizers = nil
				_ = l.c.Update(context.Background(), r)
				_ = l.c.Delete(context.Background(), r)
			}
		}
		for _, o := range append([]client.Object{reqA, reqB, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: bA.Name}},
			&v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: bB.Name}}, p}, pods...) {
			_ = l.c.Delete(context.Background(), o)
		}
		l.eventually("acceptance test policies removed", func() (bool, string) {
			got := l.policiesFor(bA.Name, bB.Name)
			return len(got) == 0, toJSON(got)
		})
	})
	for _, o := range append([]client.Object{p, bA, bB}, pods...) {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	// The only reader of protected packages is this test's download
	// service, built from this checkout (the chart's reader check is
	// TestLiveHelmSupportingEvidence).
	ConfigureAssessments(AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: time.Minute, Workers: 2,
		ControllerNamespace: ns, Destinations: &DestinationPublishers{Reader: l.c, Namespace: ns}, ProtectedReaders: NoProtectedReaders})
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	stop := l.startManager()
	defer stop()
	l.eventually("destination ready", func() (bool, string) {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(ctx, client.ObjectKeyFromObject(ed), got)
		return meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionDestinationReady), toJSON(got.Status)
	})
	for _, b := range []*v1alpha1.ComplianceBinding{bA, bB} {
		l.waitReady(b.Name, 1)
	}
	run := func(name string) *v1alpha1.AssessmentRun {
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(ctx, client.ObjectKey{Name: name}, r); err != nil {
			return nil
		}
		return r
	}
	committed := func(r *v1alpha1.AssessmentRun) bool {
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted && r.Status.Publication != nil &&
			r.Status.Publication.Phase == v1alpha1.PublicationPhase(publication.PhaseCommitted)
	}

	// 1. Each binding's first scheduled run completes before any document
	// exists: the technical baseline.
	first := map[string]*v1alpha1.AssessmentRun{}
	for _, b := range []*v1alpha1.ComplianceBinding{bA, bB} {
		l.eventually(b.Name+" first scheduled run published", func() (bool, string) {
			var runs v1alpha1.AssessmentRunList
			_ = l.c.List(ctx, &runs)
			for i := range runs.Items {
				r := &runs.Items[i]
				if r.Spec.BindingRef.Name == b.Name && r.Spec.Trigger != nil && r.Spec.Trigger.Type == v1alpha1.TriggerScheduled && committed(r) {
					first[b.Name] = r
					return true, ""
				}
			}
			return false, toJSON(l.binding(b.Name).Status.Assessment)
		})
		if s := first[b.Name].Status.Summary; s == nil || s.Evidence.Completeness != "Complete" || s.Evidence.Expected != 1 || s.Outcomes.Fail != 1 {
			t.Fatalf("baseline run of %s: %s", b.Name, toJSON(first[b.Name].Status.Summary))
		}
	}
	policySpecs := func() map[string]string {
		out := map[string]string{}
		for name, v := range l.managedPolicies() {
			out[name] = v[strings.Index(v, "/")+1:] // spec only, not the resourceVersion
		}
		return out
	}
	policiesBefore := policySpecs()
	generations := map[string]int64{bA.Name: l.binding(bA.Name).Generation, bB.Name: l.binding(bB.Name).Generation}
	uidA, uidB := string(l.binding(bA.Name).UID), string(l.binding(bB.Name).UID)

	// The transfer and download service, as its own service account.
	svcCfg := rest.AnonymousClientConfig(l.cfg)
	svcCfg.BearerToken = l.apiToken(ns, svc)
	svcC, err := client.New(svcCfg, client.Options{Scheme: l.c.Scheme()})
	if err != nil {
		t.Fatal(err)
	}
	ks := &corev1.Namespace{}
	if err := svcC.Get(ctx, client.ObjectKey{Name: "kube-system"}, ks); err != nil {
		t.Fatal(err)
	}
	dp := &DestinationPublishers{Reader: svcC, Namespace: ns}
	srv := &download.Server{Reader: svcC, Reviews: download.KubeReviewer{Client: svcC, Audience: downloadAudience}, TempDir: t.TempDir(),
		PublisherFor: func(ctx context.Context, r *v1alpha1.AssessmentRun) (publication.Publisher, error) {
			return dp.For(ctx, r.Status.Destination)
		},
		AttachmentStores: NewAttachmentStores(svcC, ns).Store, Cluster: "kube-system:" + string(ks.UID),
		AttachmentLimits: download.AttachmentLimits{MaxBytes: 64 << 10, Timeout: time.Minute, MaxConcurrent: 4, Retention: sourceRetention}}
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()
	hc := ts.Client()
	tok := map[string]string{}
	for sa, n := range sas {
		tok[sa] = l.token(n, sa, downloadAudience)
	}
	put := func(uid, token string, body []byte) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPut, ts.URL+"/v1/evidenceattachments/"+uid+"/upload", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, out
	}
	srcURL := func(d *supportingDocument) string { return ts.URL + "/v1/evidenceattachments/" + d.uid() + "/download" }
	runURL := func(r *v1alpha1.AssessmentRun) string {
		return ts.URL + "/v1/assessmentruns/" + string(r.UID) + "/download"
	}

	// 2. Register: the facility document for both bindings through the
	// documented command, as a registrar; the others through the API.
	catalog, err := attachments.ReadVendoredBaseline(os.DirFS(root))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	shared := newSupportingDocument("sa-dc-north-shared", "DC North shared facility access audit", "Facility Audit AB", "DC North halls A and B, hosting both bindings")
	expired := newSupportingDocument("sa-dc-north-2024", "DC North access audit 2024", "Facility Audit AB 2024", "DC North hall B, 2024")
	future := newSupportingDocument("sa-dc-north-next", "DC North access audit next period", "Facility Audit AB next", "DC North hall A, next period")
	pending := newSupportingDocument("sa-dc-north-pending", "DC North visitor log, not yet uploaded", "Facility Operator AB", "DC North reception")
	docs = []*supportingDocument{shared, expired, future, pending}
	work := t.TempDir()
	bin := filepath.Join(work, "bin")
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", filepath.Join(bin, "konstapel"), "../../cmd/konstapel").CombinedOutput(); err != nil {
		t.Fatalf("build konstapel: %v\n%s", err, out)
	}
	view, err := exec.CommandContext(ctx, "kubectl", "--kubeconfig", os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"), "--context", os.Getenv("KONSTAPEL_LIVE_CONTEXT"),
		"config", "view", "--minify", "--flatten").Output()
	if err != nil {
		t.Fatal(err)
	}
	kcfg, err := clientcmd.Load(view)
	if err != nil {
		t.Fatal(err)
	}
	kcfg.AuthInfos["sa-registrar"] = &clientcmdapi.AuthInfo{Token: l.apiToken(platform, "sa-registrar")}
	kcfg.Contexts["sa-registrar"] = &clientcmdapi.Context{Cluster: kcfg.Contexts[kcfg.CurrentContext].Cluster, AuthInfo: "sa-registrar"}
	kc := filepath.Join(work, "kubeconfig")
	if err := clientcmd.WriteToFile(*kcfg, kc); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`apiVersion: compliance.erenius.io/v1alpha1
kind: EvidenceAttachment
metadata:
  name: %s
spec:
  document:
    title: %s
    mediaType: application/pdf
  source:
    issuer: %s
    url: https://audit.invalid/sa-shared
  validity:
    validFrom: "%s"
    validUntil: "%s"
  scope:
    description: %s
  associations:
    - binding: {name: %s}
      catalogDigest: %s
      controls:
        - id: pe-3
          statements: [pe-3_smt.a]
    - binding: {name: %s}
      catalogDigest: %s
      controls:
        - id: pe-3
`, shared.name, shared.title, shared.issuer, now.Add(-24*time.Hour).Format(time.RFC3339), now.Add(365*24*time.Hour).Format(time.RFC3339), shared.scope,
		bA.Name, catalog.CatalogDigest, bB.Name, catalog.CatalogDigest)
	for f, data := range map[string][]byte{"attachment.yaml": []byte(manifest), "shared.pdf": shared.body} {
		if err := os.WriteFile(filepath.Join(work, f), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.CommandContext(ctx, filepath.Join(bin, "konstapel"), "evidence", "register", "--kubeconfig", kc, "--context", "sa-registrar",
		"-f", filepath.Join(work, "attachment.yaml"), "--document", filepath.Join(work, "shared.pdf"))
	cmd.Env = append(os.Environ(), "HOME="+work)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "evidenceattachment/"+shared.name+" created") {
		t.Fatalf("register the shared document: %v\n%s", err, out)
	}
	registrar := "system:serviceaccount:" + platform + ":sa-registrar"
	regCfg := rest.AnonymousClientConfig(l.cfg)
	regCfg.BearerToken = l.apiToken(platform, "sa-registrar")
	regC, err := client.New(regCfg, client.Options{Scheme: l.c.Scheme()})
	if err != nil {
		t.Fatal(err)
	}
	get := func(name string) *v1alpha1.EvidenceAttachment {
		a := &v1alpha1.EvidenceAttachment{}
		if err := l.c.Get(ctx, client.ObjectKey{Name: name}, a); err != nil {
			return nil
		}
		return a
	}
	register := func(d *supportingDocument, from, until time.Time, binding, bindingUID string) {
		t.Helper()
		sum := sha256.Sum256(d.body)
		a := &v1alpha1.EvidenceAttachment{ObjectMeta: metav1.ObjectMeta{Name: d.name}, Spec: v1alpha1.EvidenceAttachmentSpec{
			Document: v1alpha1.AttachmentDocument{Title: d.title, MediaType: "application/pdf", Size: int64(len(d.body)), SHA256: "sha256:" + hex.EncodeToString(sum[:])},
			Source:   v1alpha1.AttachmentSource{Issuer: d.issuer, URL: "https://audit.invalid/" + d.name},
			Validity: v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(from), ValidUntil: metav1.NewTime(until)},
			Associations: []v1alpha1.AttachmentAssociation{{Binding: v1alpha1.ExactBindingReference{Name: binding, UID: bindingUID}, CatalogDigest: catalog.CatalogDigest,
				Controls: []v1alpha1.AttachmentControl{{ID: "pe-3"}}}},
			Scope: v1alpha1.AttachmentScope{Description: d.scope}}}
		if err := regC.Create(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	register(expired, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), bB.Name, uidB)
	register(future, now.Add(180*24*time.Hour), now.Add(365*24*time.Hour), bA.Name, uidA)
	register(pending, now.Add(-24*time.Hour), now.Add(365*24*time.Hour), bA.Name, uidA)
	for _, d := range docs {
		l.eventually(d.name+" pinned", func() (bool, string) {
			d.record = get(d.name)
			return d.record != nil && d.record.Status.Storage != nil && d.record.Status.Storage.Destination != nil, toJSON(d.record)
		})
	}
	sa := shared.record.Spec
	if len(sa.Associations) != 2 || sa.Associations[0].Binding.UID != uidA || sa.Associations[1].Binding.UID != uidB ||
		sa.RegisteredBy == nil || sa.RegisteredBy.Username != registrar || sa.Document.Size != int64(len(shared.body)) || sa.Document.SHA256 != "sha256:"+shared.sha() {
		t.Fatalf("registered shared document: %s", toJSON(sa))
	}

	// 3. Upload as the uploader, through the transfer service; the expired
	// document last, so its short source retention outlasts the runs.
	for _, d := range []*supportingDocument{shared, future, expired} {
		if code, out := put(d.uid(), tok["sa-uploader"], d.body); code != http.StatusOK {
			t.Fatalf("upload %s: %d %s", d.name, code, out)
		}
	}
	uploader := "system:serviceaccount:" + platform + ":sa-uploader"
	for _, d := range []*supportingDocument{shared, future, expired} {
		l.eventually(d.name+" committed, available and validly associated", func() (bool, string) {
			d.record = get(d.name)
			s := d.record.Status
			ok := s.Storage.Commitment != nil && s.Storage.Commitment.Uploader.Username == uploader && s.Content != nil && s.Content.State == v1alpha1.ContentAvailable &&
				meta.IsStatusConditionTrue(s.Conditions, v1alpha1.ConditionAssociationsValid)
			return ok, toJSON(s)
		})
	}
	l.eventually("unuploaded document pending with a valid association", func() (bool, string) {
		pending.record = get(pending.name)
		s := pending.record.Status
		return s.Content != nil && s.Content.State == v1alpha1.ContentPending && meta.IsStatusConditionTrue(s.Conditions, v1alpha1.ConditionAssociationsValid), toJSON(s)
	})
	if len(shared.record.Status.Associations) != 2 {
		t.Fatalf("shared document associations: %s", toJSON(shared.record.Status.Associations))
	}
	for _, s := range shared.record.Status.Associations {
		if s.State != v1alpha1.AssociationValid {
			t.Fatalf("shared document association: %s", toJSON(shared.record.Status.Associations))
		}
	}
	states := map[string]v1alpha1.TemporalState{}
	for _, d := range docs {
		if d.record.Status.Validity != nil {
			states[d.name] = d.record.Status.Validity.State
		}
	}
	if states[shared.name] != v1alpha1.TemporalCurrent || states[expired.name] != v1alpha1.TemporalExpired || states[future.name] != v1alpha1.TemporalNotYetValid {
		t.Fatalf("validity states: %v", states)
	}
	if ec := expired.record.Status.Storage.Commitment; !ec.ExpiresAt.Time.Equal(ec.CommittedAt.Add(sourceRetention)) {
		t.Fatalf("expired document's source expiry: %s", toJSON(ec))
	}
	if sc := shared.record.Status.Storage.Commitment; !sc.ExpiresAt.Time.Equal(shared.record.Spec.Validity.ValidUntil.Add(sourceRetention)) {
		t.Fatalf("shared document's source expiry: %s", toJSON(sc))
	}
	// Registration and upload changed no binding and no engine policy.
	for name, g := range generations {
		if got := l.binding(name).Generation; got != g {
			t.Fatalf("binding %s generation %d -> %d", name, g, got)
		}
	}
	if after := policySpecs(); toJSON(after) != toJSON(policiesBefore) {
		t.Fatalf("documents changed engine policies:\nbefore %v\nafter  %v", policiesBefore, after)
	}
	l.record("registered", map[string]any{"shared": shared.uid(), "associations": []string{uidA, uidB}, "registeredBy": registrar, "uploader": uploader,
		"validity": states, "pending": pending.uid()})

	// 4. A platform run and a team request for each binding.
	rA1 := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "sa-audit-a-documents"},
		Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: bA.Name}, Scope: v1alpha1.RunScopeBinding}}
	rB1 := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "sa-audit-b-documents"},
		Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: bB.Name}, Scope: v1alpha1.RunScopeBinding}}
	for _, o := range []client.Object{rA1, rB1, reqA, reqB} {
		if err := l.c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []*v1alpha1.AssessmentRun{rA1, rB1} {
		l.eventually(r.Name+" published", func() (bool, string) {
			got := run(r.Name)
			if committed(got) {
				*r = *got
				return true, ""
			}
			return false, toJSON(got)
		})
	}
	for _, q := range []*v1alpha1.AssessmentRequest{reqA, reqB} {
		l.eventually(q.Namespace+" request published", func() (bool, string) {
			got := &v1alpha1.AssessmentRequest{}
			_ = l.c.Get(ctx, client.ObjectKeyFromObject(q), got)
			q.UID, q.Status = got.UID, got.Status
			return got.Status.Phase == v1alpha1.RequestCompleted && got.Status.ArtifactRef != "", toJSON(got.Status)
		})
	}
	// The documents change no technical result.
	for b, r := range map[string]*v1alpha1.AssessmentRun{bA.Name: rA1, bB.Name: rB1} {
		base := first[b]
		if toJSON(r.Status.Summary.Evidence) != toJSON(base.Status.Summary.Evidence) || toJSON(r.Status.Summary.Outcomes) != toJSON(base.Status.Summary.Outcomes) ||
			!slices.Equal(r.Status.EnforcementRevisions, base.Status.EnforcementRevisions) {
			t.Fatalf("run %s with documents: %s %v; before any document: %s %v", r.Name, toJSON(r.Status.Summary), r.Status.EnforcementRevisions,
				toJSON(base.Status.Summary), base.Status.EnforcementRevisions)
		}
	}

	// 5. Independent authorization. Never log a body: it may be protected.
	teamURL := func(q *v1alpha1.AssessmentRequest) string {
		return ts.URL + "/v1/namespaces/" + q.Namespace + "/assessmentrequests/" + q.Name + "/download?uid=" + string(q.UID)
	}
	matrix := map[string]int{}
	expect := func(what, url, who string, want int) []byte {
		t.Helper()
		code, body := fetch(t, hc, url, tok[who])
		if code != want {
			t.Fatalf("%s by %s: %d, want %d (%d bytes)", what, who, code, want, len(body))
		}
		matrix[what+" by "+who] = code
		return body
	}
	expect("platform package A", runURL(rA1), "sa-auditor", http.StatusForbidden)
	expect("platform package B", runURL(rB1), "sa-auditor", http.StatusForbidden)
	expect("platform package A", runURL(rA1), "sa-docreader", http.StatusForbidden)
	expect("platform package A", runURL(rA1), "sa-dev-a", http.StatusForbidden)
	expect("platform package B", runURL(rB1), "sa-dev-b", http.StatusForbidden)
	expect("source document", srcURL(shared), "sa-auditor", http.StatusForbidden)
	expect("source document", srcURL(shared), "sa-dev-a", http.StatusForbidden)
	expect("source document", srcURL(shared), "sa-uploader", http.StatusForbidden)
	expect("team B package", teamURL(reqB), "sa-dev-a", http.StatusForbidden)
	expect("team A package", teamURL(reqA), "sa-dev-b", http.StatusForbidden)
	if body := expect("source document", srcURL(shared), "sa-docreader", http.StatusOK); !bytes.Equal(body, shared.body) {
		t.Fatal("the shared source document differs from the upload")
	}
	// The baseline package of binding B names no document: run access is
	// enough.
	baseB := expect("baseline package B", runURL(first[bB.Name]), "sa-auditor", http.StatusOK)
	grant := l.bindSA("sa-auditor-documents", platform, "sa-auditor", cluster("konstapel-evidence-attachment-downloader"), "")
	var archiveA, archiveB []byte
	l.eventually("document read granted", func() (bool, string) {
		code, body := fetch(t, hc, runURL(rA1), tok["sa-auditor"])
		archiveA = body
		return code == http.StatusOK, http.StatusText(code)
	})
	archiveB = expect("platform package B", runURL(rB1), "sa-auditor", http.StatusOK)
	matrix["platform package A by sa-auditor with document read"] = http.StatusOK
	l.record("authorization", map[string]any{"matrix": matrix})

	// 6. Platform packages: the shared document under one identity in
	// both, temporal states as declared, the pending one not included.
	dirA, dA, repA := unpackPackage(t, archiveA)
	dirB, dB, repB := unpackPackage(t, archiveB)
	if !dA.Protected() || !dB.Protected() {
		t.Fatalf("platform packages not protected: %+v %+v", dA.Protection, dB.Protection)
	}
	if got, want := supportingSources(repA), sortedStrings(shared.uid(), future.uid(), pending.uid()); !slices.Equal(got, want) {
		t.Fatalf("binding A's package names %v, want %v", got, want)
	}
	if got, want := supportingSources(repB), sortedStrings(shared.uid(), expired.uid()); !slices.Equal(got, want) {
		t.Fatalf("binding B's package names %v, want %v", got, want)
	}
	included := func(rep *coverage.Report, dir string, d *supportingDocument, binding, temporal string) *coverage.SupportingRecord {
		t.Helper()
		e := supportingEntry(rep, d.uid())
		if e == nil || e.Access != coverage.AccessIncluded || e.Temporal != temporal || e.Attribution != coverage.SupportingAttributed || e.BindingUID != binding ||
			e.Association != coverage.SupportingAssociationValid || e.Content != coverage.SupportingContentAvailable || e.Withdrawn || e.Changed ||
			e.Document == nil || e.Document.Scope != d.scope || e.Document.SHA256 != d.sha() || !bytes.Equal(packageCopy(dir, d.uid()), d.body) {
			t.Fatalf("%s in the package of %s: %s", d.name, binding, toJSON(e))
		}
		return e
	}
	sharedA := included(repA, dirA, shared, uidA, coverage.SupportingCurrent)
	sharedB := included(repB, dirB, shared, uidB, coverage.SupportingCurrent)
	if sharedA.Revision == "" || sharedA.Revision != sharedB.Revision {
		t.Fatalf("the shared document's registration differs between packages: %q %q", sharedA.Revision, sharedB.Revision)
	}
	included(repA, dirA, future, uidA, coverage.SupportingNotYetValid)
	included(repB, dirB, expired, uidB, coverage.SupportingExpired)
	if e := supportingEntry(repA, pending.uid()); e == nil || e.Access != coverage.AccessNotIncluded || e.Content != coverage.SupportingContentPending ||
		(e.Document != nil && e.Document.Copy != "") || packageCopy(dirA, pending.uid()) != nil {
		t.Fatalf("the unuploaded document in binding A's package: %s", toJSON(e))
	}
	for _, archive := range [][]byte{archiveA, archiveB} {
		if bytes.Contains(archive, []byte("audit.invalid")) {
			t.Fatal("a declared source URL is in a platform package")
		}
	}
	// Binding B's control rows and technical evidence are those of its
	// baseline package; only the documentary references are added.
	_, dBase, repBase := unpackPackage(t, baseB)
	if dBase.Protected() || len(repBase.SupportingEvidence.Entries) != 0 || toJSON(dB.Evidence) != toJSON(dBase.Evidence) || toJSON(dB.Outcomes) != toJSON(dBase.Outcomes) ||
		toJSON(repB.TechnicalEvidence.Evidence) != toJSON(repBase.TechnicalEvidence.Evidence) || toJSON(repB.TechnicalEvidence.Outcomes) != toJSON(repBase.TechnicalEvidence.Outcomes) ||
		len(repB.Controls) != len(repBase.Controls) || len(repB.Controls) == 0 {
		t.Fatalf("binding B's technical evidence changed: %s %s vs %s %s", toJSON(dB.Evidence), toJSON(dB.Outcomes), toJSON(dBase.Evidence), toJSON(dBase.Outcomes))
	}
	refs := 0
	for i, row := range repB.Controls {
		base := repBase.Controls[i]
		if row.ID != base.ID || row.Automation != base.Automation || toJSON(row.Checks) != toJSON(base.Checks) || toJSON(row.Evidence) != toJSON(base.Evidence) {
			t.Fatalf("control %s changed with documents: %s vs %s", row.ID, toJSON(row), toJSON(base))
		}
		if len(base.SupportingEvidence) != 0 || (len(row.SupportingEvidence) != 0) != (row.ID == "pe-3") {
			t.Fatalf("control %s supporting references: %s (baseline %s)", row.ID, toJSON(row.SupportingEvidence), toJSON(base.SupportingEvidence))
		}
		refs += len(row.SupportingEvidence)
	}
	if refs != 2 {
		t.Fatalf("binding B's pe-3 references %d documents, want 2", refs)
	}
	l.record("platform-packages", map[string]any{"a": supportingSources(repA), "b": supportingSources(repB), "sharedRevision": sharedA.Revision,
		"protection": dA.Protection, "evidence": dB.Evidence, "outcomes": dB.Outcomes})

	// 7. Team packages: restricted entries for their own binding only.
	private := [][]byte{[]byte("%PDF"), []byte("audit.invalid"), []byte(coverage.SupportingCopyDir)}
	for _, d := range docs {
		private = append(private, []byte(d.title), []byte(d.issuer), []byte(d.scope), []byte(d.sha()))
	}
	for _, c := range []struct {
		req   *v1alpha1.AssessmentRequest
		who   string
		names []*supportingDocument
	}{{reqA, "sa-dev-a", []*supportingDocument{shared, future, pending}}, {reqB, "sa-dev-b", []*supportingDocument{shared, expired}}} {
		archive := expect("team package", teamURL(c.req), c.who, http.StatusOK)
		dir, d, rep := unpackPackage(t, archive)
		if d.Protected() || d.Scope.Kind != publication.ScopeNamespace {
			t.Fatalf("%s package: protection %+v scope %s", c.req.Namespace, d.Protection, d.Scope.Kind)
		}
		var want []string
		for _, n := range c.names {
			want = append(want, n.uid())
		}
		slices.Sort(want)
		if got := supportingSources(rep); !slices.Equal(got, want) {
			t.Fatalf("%s package names %v, want %v", c.req.Namespace, got, want)
		}
		for _, e := range rep.SupportingEvidence.Entries {
			if e.Access != coverage.AccessRestricted || e.Document != nil || e.Revision != "" {
				t.Fatalf("%s package entry not restricted: %s", c.req.Namespace, toJSON(e))
			}
		}
		all := packageText(dir)
		for _, leak := range private {
			if bytes.Contains(all, leak) {
				t.Fatalf("%s package contains %q", c.req.Namespace, leak)
			}
		}
	}
	l.record("team-packages", map[string]any{"a": "restricted: shared, future, pending", "b": "restricted: shared, expired"})

	// 8a. A source document outlives the package that copied it. Withdraw
	// the expired document now, so its source reaches its own expiry while
	// binding A's package expires.
	exp := expired.record.Status.Storage.Commitment.ExpiresAt.Time
	if err := regC.Delete(ctx, expired.record); err != nil {
		t.Fatal(err)
	}
	if time.Until(exp) > 15*time.Second {
		l.eventually("expired document withdrawn and retained", func() (bool, string) {
			a := get(expired.name)
			if a == nil {
				return false, "released before its source expiry"
			}
			c := a.Status.Storage.Cleanup
			return a.Status.Withdrawal != nil && c != nil && c.State == "NotDue", toJSON(a.Status)
		})
	}
	sharedCommitment := shared.record.Status.Storage.Commitment.DeepCopy()
	l.eventually("binding A's package deleted at its expiry", func() (bool, string) {
		r := run(rA1.Name)
		p := r.Status.Publication
		return p.Phase == "Deleted" && p.Availability == "Expired" && !controllerutil.ContainsFinalizer(r, RetentionFinalizer), toJSON(p)
	})
	if code, _ := fetch(t, hc, runURL(rA1), tok["sa-auditor"]); code != http.StatusGone {
		t.Fatalf("expired package served: %d", code)
	}
	if a := get(shared.name); a.Status.Content == nil || a.Status.Content.State != v1alpha1.ContentAvailable || *a.Status.Storage.Commitment != *sharedCommitment {
		t.Fatalf("the package's expiry changed the source document: %s", toJSON(a.Status))
	}
	if body := expect("source document after the package expired", srcURL(shared), "sa-docreader", http.StatusOK); !bytes.Equal(body, shared.body) {
		t.Fatal("the shared source changed after the package expired")
	}
	// A later run copies the source again.
	rA2 := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "sa-audit-a-later"},
		Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: bA.Name}, Scope: v1alpha1.RunScopeBinding}}
	if err := l.c.Create(ctx, rA2); err != nil {
		t.Fatal(err)
	}
	l.eventually(rA2.Name+" published", func() (bool, string) {
		got := run(rA2.Name)
		if committed(got) {
			*rA2 = *got
			return true, ""
		}
		return false, toJSON(got)
	})
	laterDir, _, laterRep := unpackPackage(t, expect("later platform package A", runURL(rA2), "sa-auditor", http.StatusOK))
	included(laterRep, laterDir, shared, uidA, coverage.SupportingCurrent)
	l.record("package-expiry", map[string]any{"expiredRun": rA1.Name, "sourceExpiresAt": sharedCommitment.ExpiresAt, "laterRun": rA2.Name})

	// 8b. A package outlives the source it copied: the withdrawn expired
	// document's source is deleted at its fixed expiry; binding B's package
	// still serves its copy.
	time.Sleep(time.Until(exp))
	l.eventually("withdrawn source deleted at its expiry and record released", func() (bool, string) {
		a := get(expired.name)
		return a == nil, toJSON(a)
	})
	cur := &v1alpha1.EvidenceDestination{}
	if err := l.c.Get(ctx, client.ObjectKeyFromObject(ed), cur); err != nil {
		t.Fatal(err)
	}
	dest, err := DestinationFromAPI(ctx, l.c, ns, cur)
	if err != nil {
		t.Fatal(err)
	}
	prefix := s3store.AttachmentPrefix(dest, attachments.Ref{ClusterID: srv.Cluster, UID: expired.uid()})
	versions, err := pub.Client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(dest.Bucket), Prefix: aws.String(prefix)})
	if err != nil {
		t.Fatal(err)
	}
	if len(versions.Versions)+len(versions.DeleteMarkers) != 0 {
		t.Fatalf("the expired source left objects under %s", prefix)
	}
	expect("deleted source document", srcURL(expired), "sa-docreader", http.StatusForbidden)
	keptDir, _, keptRep := unpackPackage(t, expect("platform package B after its source was deleted", runURL(rB1), "sa-auditor", http.StatusOK))
	included(keptRep, keptDir, expired, uidB, coverage.SupportingExpired)
	if err := l.c.Delete(ctx, grant); err != nil {
		t.Fatal(err)
	}
	l.record("source-expiry", map[string]any{"source": expired.uid(), "sourceExpiredAt": exp, "packageRun": rB1.Name, "packageServed": http.StatusOK})
}

func sortedStrings(s ...string) []string {
	slices.Sort(s)
	return s
}
