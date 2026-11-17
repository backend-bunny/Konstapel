//go:build live

package controller

// Live supporting-evidence transfer (add-supporting-evidence-attachments
// 3.1-3.4) against the real API server, the cluster's own TokenReview and
// SubjectAccessReview, and the pinned, test-owned S3 service
// (KONSTAPEL_S3_IMAGE). The download service runs in-process over TLS as its
// own service account, bound only to the shipped konstapel-evidence-download
// roles; callers are service accounts bound to the shipped attachment roles:
//   - the documented `konstapel evidence` workflow (docs/supporting-evidence.md)
//     runs unchanged apart from names, with a separate kubeconfig context per
//     role: register (dry run, then create) as a registrar, upload as an
//     uploader, status as a reader, download as a downloader. The registrant
//     and the uploader are recorded as different authenticated identities,
//     and the declared source URL is never fetched;
//   - transfers need the dedicated attribute and record read: other roles,
//     a namespace team, another audience and unknown UIDs are refused;
//   - a retry by another authorized uploader returns the first commitment,
//     and two uploaders racing on one record both get the one commitment;
//   - mismatching and interrupted uploads store nothing; an oversized
//     registration is refused;
//   - revoking a role stops the next transfer;
//   - a withdrawn record accepts no upload, while its retained source stays
//     downloadable until expiry; an expired source is no longer served.
// Run through scripts/targeting-live.sh (acceptance group "storage").

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
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
	"github.com/backend-bunny/Konstapel/internal/download"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// bindSA binds a service account to a role, test-owned. API-audience tokens
// come from apiToken (metrics_helm_live_test.go).
func (l *live) bindSA(name, ns, sa string, role rbacv1.RoleRef, namespace string) client.Object {
	subjects := []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: ns, Name: sa}}
	var o client.Object
	if namespace == "" {
		o = &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}, Subjects: subjects, RoleRef: role}
	} else {
		o = &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Subjects: subjects, RoleRef: role}
	}
	if err := l.c.Create(l.ctx, o); err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { _ = l.c.Delete(context.Background(), o) })
	return o
}

// documentedSupportingBlock returns the non-comment lines of the first ```sh
// block after marker in docs/supporting-evidence.md.
func documentedSupportingBlock(t *testing.T, marker string) []string {
	t.Helper()
	raw, err := os.ReadFile("../../docs/supporting-evidence.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(raw), marker)
	_, rest, ok2 := strings.Cut(section, "```sh\n")
	block, _, ok3 := strings.Cut(rest, "```")
	if !ok || !ok2 || !ok3 {
		t.Fatalf("%q block not found in docs/supporting-evidence.md", marker)
	}
	var out []string
	for _, line := range strings.Split(block, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

type transferResult struct {
	code   int
	header http.Header
	body   []byte
}

func TestLiveAttachmentTransfer(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	ctx := l.ctx
	const (
		ns       = "konstapel-system"
		platform = "at-platform"
		team     = "at-team"
		svc      = "at-download"
		suffix   = "-at-live"
		name     = "dc-north-physical-access-2026"
	)
	for _, n := range []string{ns, platform, team} {
		_ = l.c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
	}
	work := t.TempDir()
	bin := filepath.Join(work, "bin")
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", filepath.Join(bin, "konstapel"), "../../cmd/konstapel").CombinedOutput(); err != nil {
		t.Fatalf("build konstapel: %v\n%s", err, out)
	}

	// Storage: a pinned-to-be default destination on the test S3 service.
	s3secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "at-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	if err := l.c.Create(ctx, s3secret); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(context.Background(), s3secret) })
	ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "at-dest"}, Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{
		Endpoint: l.s3Endpoint, Bucket: pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/at-dest", DevelopmentFixture: true,
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
	for _, f := range []string{"evidence-attachments", "compliance-viewer", "assessment-requester", "evidence-download"} {
		l.applyManifests("../../config/rbac/"+f+".yaml", rename)
	}
	cluster := func(role string) rbacv1.RoleRef {
		return rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role + suffix}
	}
	sas := map[string]string{"at-registrar": platform, "at-uploader": platform, "at-uploader-2": platform, "at-reader": platform,
		"at-downloader": platform, "at-dev": team, svc: ns}
	for sa, n := range sas {
		o := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: n, Name: sa}}
		if err := l.c.Create(ctx, o); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(context.Background(), o) })
	}
	l.bindSA("at-registrar", platform, "at-registrar", cluster("konstapel-evidence-attachment-registrar"), "")
	l.bindSA("at-registrar-bindings", platform, "at-registrar", cluster("konstapel-compliance-viewer"), "")
	l.bindSA("at-uploader", platform, "at-uploader", cluster("konstapel-evidence-attachment-uploader"), "")
	revocable := l.bindSA("at-uploader-2", platform, "at-uploader-2", cluster("konstapel-evidence-attachment-uploader"), "")
	l.bindSA("at-reader", platform, "at-reader", cluster("konstapel-evidence-attachment-reader"), "")
	l.bindSA("at-downloader", platform, "at-downloader", cluster("konstapel-evidence-attachment-downloader"), "")
	l.bindSA("at-team", team, "at-dev", cluster("konstapel-assessment-requester"), team)
	l.bindSA("at-download-service", ns, svc, cluster("konstapel-evidence-download"), "")
	l.bindSA("at-download-credentials", ns, svc, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "konstapel-evidence-download-credentials" + suffix}, ns)
	l.applyManifests("../../config/admission/evidence-attachment-registrant.yaml", nil)

	// Kubernetes clients and a kubeconfig with one context per role.
	saConfig := func(n, sa string) *rest.Config {
		c := rest.AnonymousClientConfig(l.cfg)
		c.BearerToken = l.apiToken(n, sa)
		return c
	}
	saClient := func(n, sa string) client.Client {
		c, err := client.New(saConfig(n, sa), client.Options{Scheme: l.c.Scheme()})
		if err != nil {
			t.Fatal(err)
		}
		return c
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
	clusterName := kcfg.Contexts[kcfg.CurrentContext].Cluster
	for _, sa := range []string{"at-registrar", "at-uploader", "at-reader", "at-downloader"} {
		kcfg.AuthInfos[sa] = &clientcmdapi.AuthInfo{Token: l.apiToken(platform, sa)}
		kcfg.Contexts[sa] = &clientcmdapi.Context{Cluster: clusterName, AuthInfo: sa}
	}
	kc := filepath.Join(work, "kubeconfig")
	if err := clientcmd.WriteToFile(*kcfg, kc); err != nil {
		t.Fatal(err)
	}
	regC := saClient(platform, "at-registrar")
	catalog, err := attachments.ReadVendoredBaseline(os.DirFS(root))
	if err != nil {
		t.Fatal(err)
	}
	l.eventually("registrant admission effective", func() (bool, string) {
		probe := &v1alpha1.EvidenceAttachment{ObjectMeta: metav1.ObjectMeta{Name: "at-probe"}, Spec: v1alpha1.EvidenceAttachmentSpec{
			Document: v1alpha1.AttachmentDocument{Title: "probe", MediaType: "application/pdf", Size: 1, SHA256: "sha256:" + strings.Repeat("ab", 32)},
			Source:   v1alpha1.AttachmentSource{Issuer: "probe"},
			Validity: v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)), ValidUntil: metav1.NewTime(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))},
			Associations: []v1alpha1.AttachmentAssociation{{Binding: v1alpha1.ExactBindingReference{Name: "x", UID: "x"}, CatalogDigest: catalog.CatalogDigest,
				Controls: []v1alpha1.AttachmentControl{{ID: "pe-3"}}}},
			Scope: v1alpha1.AttachmentScope{Description: "probe"}}}
		if err := regC.Create(ctx, probe, client.DryRunAll); err != nil {
			return false, err.Error()
		}
		return probe.Spec.RegisteredBy != nil && probe.Spec.RegisteredBy.Username == "system:serviceaccount:"+platform+":at-registrar", toJSON(probe.Spec.RegisteredBy)
	})

	// A binding the document supports; it selects no namespace.
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "at-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("at-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "at-none"})
	var created []string
	t.Cleanup(func() {
		for _, n := range created {
			a := &v1alpha1.EvidenceAttachment{}
			if l.c.Get(context.Background(), client.ObjectKey{Name: n}, a) == nil {
				a.Finalizers = nil
				_ = l.c.Update(context.Background(), a)
				_ = l.c.Delete(context.Background(), a)
			}
		}
		for _, o := range []client.Object{&v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.Name}}, p} {
			_ = l.c.Delete(context.Background(), o)
		}
		l.eventually("transfer test policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
	})
	for _, o := range []client.Object{p, b} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	ConfigureAssessments(AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: time.Minute, Workers: 1,
		ControllerNamespace: ns, Destinations: &DestinationPublishers{Reader: l.c, Namespace: ns}})
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	stop := l.startManager()
	defer stop()
	l.eventually("destination ready", func() (bool, string) {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(ctx, client.ObjectKeyFromObject(ed), got)
		return meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionDestinationReady), toJSON(got.Status)
	})

	// The download service, as its own service account.
	svcC := saClient(ns, svc)
	ks := &corev1.Namespace{}
	if err := svcC.Get(ctx, client.ObjectKey{Name: "kube-system"}, ks); err != nil {
		t.Fatal(err)
	}
	const retention = 90 * time.Second
	srv := &download.Server{Reader: svcC, Reviews: download.KubeReviewer{Client: svcC, Audience: downloadAudience}, TempDir: t.TempDir(),
		AttachmentStores: NewAttachmentStores(svcC, ns).Store, Cluster: "kube-system:" + string(ks.UID),
		AttachmentLimits: download.AttachmentLimits{MaxBytes: 64 << 10, Timeout: 30 * time.Second, MaxConcurrent: 2, Retention: retention}}
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()
	if err := os.WriteFile(filepath.Join(work, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	// The declared source URL counts requests; nothing may fetch it.
	var urlHits atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { urlHits.Add(1) }))
	defer source.Close()
	doc := make([]byte, 6<<10)
	_, _ = rand.Read(doc)
	doc = append([]byte("%PDF-1.7 DC North physical access control audit\n"), doc...)
	validUntil := time.Now().Add(365 * 24 * time.Hour).UTC().Truncate(time.Second)
	manifest := fmt.Sprintf(`apiVersion: compliance.erenius.io/v1alpha1
kind: EvidenceAttachment
metadata:
  name: %s
spec:
  document:
    title: DC North physical access control audit
    mediaType: application/pdf
  source:
    issuer: Example Audit AB on behalf of the DC North facility operator
    url: %s/reports/dc-north
  validity:
    validFrom: "%s"
    validUntil: "%s"
  scope:
    description: DC North halls A and B
  associations:
    - binding: {name: %s}
      catalogDigest: %s
      controls:
        - id: pe-3
`, name, source.URL, validUntil.Add(-365*24*time.Hour).Format(time.RFC3339), validUntil.Format(time.RFC3339), b.Name, catalog.CatalogDigest)
	for f, data := range map[string][]byte{"attachment.yaml": []byte(manifest), "dc-north-2026.pdf": doc} {
		if err := os.WriteFile(filepath.Join(work, f), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	created = append(created, name)

	// 3.3/3.4: the documented workflow, one context per role.
	lines := documentedSupportingBlock(t, "Register, upload and download a document:")
	script := strings.NewReplacer(
		"konstapel evidence register", "konstapel evidence register --context at-registrar",
		"konstapel evidence upload", "konstapel evidence upload --context at-uploader",
		"konstapel evidence status", "konstapel evidence status --context at-reader",
		"konstapel evidence download", "konstapel evidence download --context at-downloader",
		"kubectl create token platform-uploader -n platform-ops", "kubectl create token at-uploader -n "+platform,
		"kubectl create token platform-auditor -n platform-ops", "kubectl create token at-downloader -n "+platform,
		"https://konstapel-download.konstapel-system.svc", ts.URL,
	).Replace("set -eu\n" + strings.Join(lines, "\n"))
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kc, "HOME="+work, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	const registrar, uploader = "system:serviceaccount:" + platform + ":at-registrar", "system:serviceaccount:" + platform + ":at-uploader"
	for _, want := range []string{"server-side dry run: nothing was created", "username: " + registrar, "evidenceattachment/" + name + " created",
		"evidenceattachment/" + name + " committed", "uploader: " + uploader, "Registered by: " + registrar,
		"verified against evidenceattachment/" + name} {
		if err != nil || !strings.Contains(string(out), want) {
			t.Fatalf("documented workflow (%v) lacks %q:\n%s", err, want, out)
		}
	}
	copied, _ := os.ReadFile(filepath.Join(work, "dc-north-2026-copy.pdf"))
	if !bytes.Equal(copied, doc) {
		t.Fatal("the downloaded copy differs from the uploaded document")
	}
	main := &v1alpha1.EvidenceAttachment{}
	if err := l.c.Get(ctx, client.ObjectKey{Name: name}, main); err != nil {
		t.Fatal(err)
	}
	cm0 := main.Status.Storage.Commitment
	if main.Spec.RegisteredBy == nil || main.Spec.RegisteredBy.Username != registrar || cm0 == nil || cm0.Uploader.Username != uploader ||
		main.Spec.Associations[0].Binding.UID != string(l.binding(b.Name).UID) || !cm0.ExpiresAt.Time.Equal(validUntil.Add(retention)) {
		t.Fatalf("recorded identities: registrant %+v, commitment %+v", main.Spec.RegisteredBy, cm0)
	}
	if n := urlHits.Load(); n != 0 {
		t.Fatalf("the declared source URL was fetched %d times", n)
	}
	l.record("workflow", map[string]any{"registeredBy": registrar, "uploader": cm0.Uploader.Username, "committedAt": cm0.CommittedAt, "expiresAt": cm0.ExpiresAt,
		"sourceURLFetches": 0, "commands": len(lines)})

	// 3.1: authorization of the transfer routes.
	tokens := map[string]string{}
	for sa, n := range sas {
		tokens[sa] = l.token(n, sa, downloadAudience)
	}
	hc := ts.Client()
	transfer := func(method, uid, op, token string, body []byte) transferResult {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, method, ts.URL+"/v1/evidenceattachments/"+uid+"/"+op, bytes.NewReader(body))
		if body == nil {
			req.Body = nil
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return transferResult{resp.StatusCode, resp.Header, b}
	}
	uid := string(main.UID)
	denials := map[string]int{}
	for who, code := range map[string]int{"at-registrar": 403, "at-reader": 403, "at-downloader": 403, "at-dev": 403, svc: 403} {
		if r := transfer(http.MethodPut, uid, "upload", tokens[who], doc); r.code != code {
			t.Fatalf("upload by %s: %d %s", who, r.code, r.body)
		}
		denials["upload "+who] = code
	}
	for who, code := range map[string]int{"at-registrar": 403, "at-reader": 403, "at-uploader": 403, "at-dev": 403, svc: 403} {
		if r := transfer(http.MethodGet, uid, "download", tokens[who], nil); r.code != code {
			t.Fatalf("download by %s: %d %s", who, r.code, r.body)
		}
		denials["download "+who] = code
	}
	if r := transfer(http.MethodGet, uid, "download", l.apiToken(platform, "at-downloader"), nil); r.code != http.StatusUnauthorized {
		t.Fatalf("API-audience token: %d", r.code)
	}
	if r := transfer(http.MethodGet, "00000000-0000-0000-0000-000000000000", "download", tokens["at-downloader"], nil); r.code != http.StatusForbidden {
		t.Fatalf("unknown UID: %d", r.code)
	}
	r := transfer(http.MethodGet, uid, "download", tokens["at-downloader"], nil)
	if r.code != http.StatusOK || !bytes.Equal(r.body, doc) || r.header.Get("Content-Type") != "application/octet-stream" ||
		r.header.Get("X-Content-Type-Options") != "nosniff" || r.header.Get("Content-Disposition") != `attachment; filename="`+name+`"` {
		t.Fatalf("download: %d %v", r.code, r.header)
	}
	// Another authorized uploader's retry returns the first commitment.
	r = transfer(http.MethodPut, uid, "upload", tokens["at-uploader-2"], doc)
	var retry download.UploadReceipt
	_ = json.Unmarshal(r.body, &retry)
	if r.code != http.StatusOK || retry.Uploader.Username != uploader || !retry.CommittedAt.Equal(cm0.CommittedAt.Time) {
		t.Fatalf("second uploader's retry: %d %s", r.code, r.body)
	}
	l.record("authorization", map[string]any{"denials": denials, "otherAudience": 401, "unknownUID": 403, "retryBySecondUploader": retry.Uploader.Username})

	// 3.2: bounded, verified intake against real storage.
	register := func(n string, body []byte, from, until time.Time) *v1alpha1.EvidenceAttachment {
		t.Helper()
		sum := sha256.Sum256(body)
		a := &v1alpha1.EvidenceAttachment{ObjectMeta: metav1.ObjectMeta{Name: n}, Spec: v1alpha1.EvidenceAttachmentSpec{
			Document: v1alpha1.AttachmentDocument{Title: n, MediaType: "text/html", Size: int64(len(body)), SHA256: "sha256:" + hex.EncodeToString(sum[:])},
			Source:   v1alpha1.AttachmentSource{Issuer: "Example Audit AB"},
			Validity: v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(from), ValidUntil: metav1.NewTime(until)},
			Associations: []v1alpha1.AttachmentAssociation{{Binding: v1alpha1.ExactBindingReference{Name: b.Name, UID: main.Spec.Associations[0].Binding.UID},
				CatalogDigest: catalog.CatalogDigest, Controls: []v1alpha1.AttachmentControl{{ID: "pe-3"}}}},
			Scope: v1alpha1.AttachmentScope{Description: "DC North"}}}
		if err := regC.Create(ctx, a); err != nil {
			t.Fatal(err)
		}
		created = append(created, n)
		l.eventually(n+" pinned", func() (bool, string) {
			_ = l.c.Get(ctx, client.ObjectKey{Name: n}, a)
			return a.Status.Storage != nil && a.Status.Storage.Destination != nil, toJSON(a.Status)
		})
		return a
	}
	expiredBody := []byte("<html>DC North audit 2024, expired</html>")
	expired := register("at-expired", expiredBody, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	if r := transfer(http.MethodPut, string(expired.UID), "upload", tokens["at-uploader"], expiredBody); r.code != http.StatusOK {
		t.Fatalf("expired document upload: %d %s", r.code, r.body)
	}
	pendingBody := []byte("<html>DC South audit, never stored</html>")
	pending := register("at-pending", pendingBody, validUntil.Add(-24*time.Hour), validUntil)
	d, err := DestinationFromAPI(ctx, l.c, ns, ed)
	if err != nil {
		t.Fatal(err)
	}
	stored := func(a *v1alpha1.EvidenceAttachment) []string {
		prefix := s3store.AttachmentPrefix(d, attachments.Ref{ClusterID: srv.Cluster, UID: string(a.UID)})
		out, err := pub.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(d.Bucket), Prefix: aws.String(prefix)})
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, o := range out.Contents {
			keys = append(keys, aws.ToString(o.Key))
		}
		return keys
	}
	if r := transfer(http.MethodPut, string(pending.UID), "upload", tokens["at-uploader"], bytes.Repeat([]byte("x"), len(pendingBody))); r.code != http.StatusConflict {
		t.Fatalf("mismatching bytes: %d %s", r.code, r.body)
	}
	// Interrupted mid-body.
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	conn, err := tls.Dial("tcp", ts.Listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "PUT /v1/evidenceattachments/%s/upload HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\nContent-Length: %d\r\n\r\n%s",
		pending.UID, tokens["at-uploader"], len(pendingBody), pendingBody[:10])
	time.Sleep(time.Second)
	conn.Close()
	time.Sleep(time.Second)
	if keys := stored(pending); len(keys) != 0 {
		t.Fatalf("mismatching or interrupted uploads stored objects: %v", keys)
	}
	big := register("at-oversized", bytes.Repeat([]byte("y"), 80<<10), validUntil.Add(-24*time.Hour), validUntil)
	if r := transfer(http.MethodPut, string(big.UID), "upload", tokens["at-uploader"], bytes.Repeat([]byte("y"), 80<<10)); r.code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized: %d %s", r.code, r.body)
	}
	if keys := stored(big); len(keys) != 0 {
		t.Fatalf("oversized upload stored objects: %v", keys)
	}
	l.eventually("pending record still awaits its upload", func() (bool, string) {
		_ = l.c.Get(ctx, client.ObjectKeyFromObject(pending), pending)
		c := meta.FindStatusCondition(pending.Status.Conditions, v1alpha1.ConditionDocumentCommitted)
		return c != nil && c.Reason == v1alpha1.ReasonAwaitingUpload && pending.Status.Storage.Commitment == nil, toJSON(pending.Status)
	})
	l.record("intake", map[string]any{"mismatch": 409, "interrupted": "no objects", "oversized": 413, "limit": srv.AttachmentLimits.MaxBytes})

	// Two uploaders race on one record (as on two replicas): both are
	// answered with the one commitment real storage created, which the
	// controller records.
	raceBody := []byte("<html>DC North audit, uploaded twice at once</html>")
	raced := register("at-concurrent", raceBody, validUntil.Add(-24*time.Hour), validUntil)
	type raceResult struct {
		code int
		body []byte
		err  error
	}
	results := make(chan raceResult, 2)
	for _, who := range []string{"at-uploader", "at-uploader-2"} {
		go func() {
			req, _ := http.NewRequestWithContext(ctx, http.MethodPut, ts.URL+"/v1/evidenceattachments/"+string(raced.UID)+"/upload", bytes.NewReader(raceBody))
			req.Header.Set("Authorization", "Bearer "+tokens[who])
			resp, err := hc.Do(req)
			if err != nil {
				results <- raceResult{err: err}
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			results <- raceResult{code: resp.StatusCode, body: b}
		}()
	}
	var raceReceipts []download.UploadReceipt
	for range 2 {
		r := <-results
		var rc download.UploadReceipt
		if r.err != nil || r.code != http.StatusOK || json.Unmarshal(r.body, &rc) != nil {
			t.Fatalf("concurrent upload: %d %s %v", r.code, r.body, r.err)
		}
		raceReceipts = append(raceReceipts, rc)
	}
	if a, b := raceReceipts[0], raceReceipts[1]; !a.CommittedAt.Equal(b.CommittedAt) || a.Uploader != b.Uploader || !a.ExpiresAt.Equal(b.ExpiresAt) {
		t.Fatalf("concurrent uploads answered with different commitments: %+v %+v", a, b)
	}
	l.eventually("concurrent upload's commitment recorded", func() (bool, string) {
		_ = l.c.Get(ctx, client.ObjectKeyFromObject(raced), raced)
		cm := raced.Status.Storage.Commitment
		return cm != nil && cm.Uploader.Username == raceReceipts[0].Uploader.Username && cm.CommittedAt.Time.Equal(raceReceipts[0].CommittedAt), toJSON(raced.Status)
	})
	l.record("concurrent", map[string]any{"uploads": 2, "committedBy": raceReceipts[0].Uploader.Username, "committedAt": raceReceipts[0].CommittedAt})

	// Revocation stops the next transfer.
	if r := transfer(http.MethodPut, uid, "upload", tokens["at-uploader-2"], doc); r.code != http.StatusOK {
		t.Fatalf("before revocation: %d", r.code)
	}
	if err := l.c.Delete(ctx, revocable); err != nil {
		t.Fatal(err)
	}
	l.eventually("revoked uploader refused", func() (bool, string) {
		r := transfer(http.MethodPut, uid, "upload", tokens["at-uploader-2"], doc)
		return r.code == http.StatusForbidden, fmt.Sprint(r.code)
	})

	// Withdrawal: no more uploads; the retained source stays downloadable.
	if err := regC.Delete(ctx, main); err != nil {
		t.Fatal(err)
	}
	l.eventually("withdrawn source retained", func() (bool, string) {
		_ = l.c.Get(ctx, client.ObjectKeyFromObject(main), main)
		c := meta.FindStatusCondition(main.Status.Conditions, v1alpha1.ConditionSourceRetained)
		return c != nil && c.Reason == v1alpha1.ReasonRetentionActive, toJSON(main.Status)
	})
	if r := transfer(http.MethodPut, uid, "upload", tokens["at-uploader"], doc); r.code != http.StatusConflict || !strings.Contains(string(r.body), "withdrawn") {
		t.Fatalf("upload to a withdrawn record: %d %s", r.code, r.body)
	}
	if r := transfer(http.MethodGet, uid, "download", tokens["at-downloader"], nil); r.code != http.StatusOK || r.header.Get("X-Konstapel-Withdrawn") != "true" || !bytes.Equal(r.body, doc) {
		t.Fatalf("retained download after withdrawal: %d %v", r.code, r.header)
	}
	// A withdrawn, uncommitted record is released; its UID is then unknown.
	if err := regC.Delete(ctx, pending); err != nil {
		t.Fatal(err)
	}
	l.eventually("withdrawn uncommitted record released", func() (bool, string) {
		err := l.c.Get(ctx, client.ObjectKeyFromObject(pending), &v1alpha1.EvidenceAttachment{})
		return apierrors.IsNotFound(err), fmt.Sprint(err)
	})
	if r := transfer(http.MethodPut, string(pending.UID), "upload", tokens["at-uploader"], pendingBody); r.code != http.StatusForbidden {
		t.Fatalf("upload to a deleted record: %d %s", r.code, r.body)
	}

	// Expiry: the expired document's source is served until its fixed
	// expiry (commitment + retention), then refused.
	l.eventually("expired document's commitment recorded", func() (bool, string) {
		_ = l.c.Get(ctx, client.ObjectKeyFromObject(expired), expired)
		return expired.Status.Storage.Commitment != nil, toJSON(expired.Status)
	})
	exp := expired.Status.Storage.Commitment.ExpiresAt.Time
	if !exp.Equal(expired.Status.Storage.Commitment.CommittedAt.Add(retention)) {
		t.Fatalf("expired document's source expiry %s", exp)
	}
	if time.Until(exp) > 5*time.Second {
		if r := transfer(http.MethodGet, string(expired.UID), "download", tokens["at-downloader"], nil); r.code != http.StatusOK ||
			r.header.Get("Content-Type") != "application/octet-stream" || r.header.Get("X-Konstapel-Declared-Media-Type") != "text/html" {
			t.Fatalf("before expiry: %d %v", r.code, r.header)
		}
	}
	time.Sleep(time.Until(exp) + time.Second)
	if r := transfer(http.MethodGet, string(expired.UID), "download", tokens["at-downloader"], nil); r.code != http.StatusGone {
		t.Fatalf("after expiry: %d %s", r.code, r.body)
	}
	l.record("lifecycle", map[string]any{"revoked": 403, "withdrawnUpload": 409, "withdrawnDownload": "200 X-Konstapel-Withdrawn", "deletedRecordUpload": 403,
		"expiredAt": exp, "afterExpiry": 410})
}
