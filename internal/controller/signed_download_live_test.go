//go:build live

package controller

// Live signed evidence download (add-evidence-signing 4.1-4.3): a team
// request published to an EvidenceDestination that requires signing is
// downloaded through the download service with the cluster's own
// TokenReview and SubjectAccessReview, by running the documented commands
// (kubectl, curl, and the pinned Cosign). The pair verifies offline with the
// separately distributed public key and not with another key; the signature
// route denies exactly what the archive route denies; a retired private key
// does not affect downloads; and a replaced signature object in storage
// makes both routes refuse until it is restored. Run through
// scripts/targeting-live.sh.

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/download"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

func TestLiveSignedEvidenceDownload(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	ns := "konstapel-system"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	work := t.TempDir()

	s3secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "sd-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	key, fp := signingKeySecret(t, "sd-signing", "sd-password")
	for _, s := range []*corev1.Secret{s3secret, key} {
		if err := l.c.Create(l.ctx, s.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = l.c.Delete(l.ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: s.Name}})
		})
	}
	// The auditor's separately distributed public key, and another key.
	if err := os.WriteFile(filepath.Join(work, "trusted.pub"), key.Data[evidencesign.SecretPublicKey], 0o600); err != nil {
		t.Fatal(err)
	}
	untrusted, _ := signingKeySecret(t, "unused", "x")
	if err := os.WriteFile(filepath.Join(work, "untrusted.pub"), untrusted.Data[evidencesign.SecretPublicKey], 0o600); err != nil {
		t.Fatal(err)
	}

	ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "sd-dest"}, Spec: v1alpha1.EvidenceDestinationSpec{
		S3: v1alpha1.S3Location{Endpoint: l.s3Endpoint, Bucket: pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/sd-dest", DevelopmentFixture: true,
			CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: s3secret.Name}}},
		Signing: requiredSigning(key.Name)}}
	if err := l.c.Create(l.ctx, ed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		got := &v1alpha1.EvidenceDestination{}
		if l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got) == nil {
			controllerutil.RemoveFinalizer(got, DestinationFinalizer)
			_ = l.c.Update(l.ctx, got)
			_ = l.c.Delete(l.ctx, got)
		}
	})
	dp := &DestinationPublishers{Reader: l.c, Namespace: ns}
	ConfigureAssessments(AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: 5 * time.Minute, Workers: 2,
		ControllerNamespace: ns, Destinations: dp})
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	l.applyFile("../../config/rbac/assessment-requester.yaml")
	l.applyFile("../../config/rbac/assessment-operator.yaml")

	l.setNamespace("sd-team", "sd-production")
	l.setNamespace("sd-other", "sd-production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "sd-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("sd-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "sd-production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "30s", DestinationRef: &v1alpha1.DestinationReference{Name: ed.Name, UID: string(ed.UID)}}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "sd-team"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "sd-team", Name: "evidence-reader"}}
	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "sd-team", Name: "evidence-reader"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-assessment-requester"},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "sd-team", Name: sa.Name}}}
	req := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "sd-team", Name: "nightly"},
		Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}}}
	t.Cleanup(func() {
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(l.ctx, &runs)
		for i := range runs.Items {
			if runs.Items[i].Spec.BindingRef.Name == b.Name {
				r := &runs.Items[i]
				r.Finalizers = nil
				_ = l.c.Update(l.ctx, r)
				_ = l.c.Delete(l.ctx, r)
			}
		}
		for _, o := range []client.Object{req, rb, sa, pod, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.Name}}, p} {
			_ = l.c.Delete(l.ctx, o)
		}
		l.eventually("signed download test policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
	})
	for _, o := range []client.Object{p, b, pod, sa, rb} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	stop := l.startManager()
	defer stop()
	l.eventually("signing destination ready", func() (bool, string) {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
		return meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionDestinationReady) &&
			meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionDestinationSigningReady), toJSON(got.Status)
	})
	l.waitReady(b.Name, 2)
	if err := l.c.Create(l.ctx, req); err != nil {
		t.Fatal(err)
	}
	var st v1alpha1.AssessmentRequestStatus
	l.eventually("team request published signed", func() (bool, string) {
		got := &v1alpha1.AssessmentRequest{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(req), got)
		st, req.UID = got.Status, got.UID
		return st.Phase == v1alpha1.RequestCompleted && st.ArtifactRef != "", toJSON(st)
	})
	run := &v1alpha1.AssessmentRun{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: st.Run.Name}, run); err != nil {
		t.Fatal(err)
	}
	if run.Status.Publication == nil || run.Status.Publication.Signature == nil || run.Status.Publication.Signature.KeyFingerprint != fp {
		t.Fatalf("team run not signed: %s", toJSON(run.Status.Publication))
	}
	l.record("published-signed", map[string]any{"run": run.Name, "fingerprint": fp, "signature": run.Status.Publication.Signature.SHA256})

	srv := &download.Server{Reader: l.c, Reviews: download.KubeReviewer{Client: l.c, Audience: downloadAudience}, TempDir: t.TempDir(),
		PublisherFor: func(ctx context.Context, r *v1alpha1.AssessmentRun) (publication.Publisher, error) {
			return dp.For(ctx, r.Status.Destination)
		}}
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()
	if err := os.WriteFile(filepath.Join(work, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	// The documented commands, against this cluster and this server.
	kc := filepath.Join(work, "kubeconfig")
	view, err := exec.CommandContext(l.ctx, "kubectl", "--kubeconfig", os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"), "--context", os.Getenv("KONSTAPEL_LIVE_CONTEXT"),
		"config", "view", "--minify", "--flatten").Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kc, view, 0o600); err != nil {
		t.Fatal(err)
	}
	lines := documentedBlock(t, "Download and verify a signed package:")
	script := strings.NewReplacer(" -n dev", " -n sd-team", "ci-reader", sa.Name, "namespaces/dev/", "namespaces/sd-team/",
		"https://download.example.internal", ts.URL).Replace("set -eu\n" + strings.Join(lines, "\n"))
	runScript := func(s string) (string, error) {
		cmd := exec.CommandContext(l.ctx, "sh", "-c", s)
		cmd.Dir = work
		cmd.Env = append(os.Environ(), "KUBECONFIG="+kc, "HOME="+work)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	out, err := runScript(script)
	if err != nil || !strings.Contains(out, "Verified OK") {
		t.Fatalf("documented download and verification failed: %v\n%s", err, out)
	}
	archive, _ := os.ReadFile(filepath.Join(work, "package.tar.gz"))
	if evidencesign.DigestArchive(archive).String() != run.Status.Publication.PackageSHA256 {
		t.Fatal("downloaded archive is not the committed package")
	}
	// Then the existing file and scope checks.
	dir := t.TempDir()
	untar(t, archive, dir)
	d, err := publication.LoadDescriptor(dir)
	if err != nil || d.Scope.Kind != publication.ScopeNamespace || publication.VerifyDir(dir, d) != nil {
		t.Fatalf("downloaded package scope: %+v %v", d.Scope, err)
	}
	// A key that is not the separately trusted one does not verify it.
	untrustedCheck := strings.ReplaceAll(lines[len(lines)-1], "trusted.pub", "untrusted.pub")
	if out, err := runScript(untrustedCheck); err == nil || strings.Contains(out, "Verified OK") {
		t.Fatalf("an untrusted key verified the package:\n%s", out)
	}
	l.record("documented-verification", map[string]any{"archiveBytes": len(archive), "trustedKey": "Verified OK", "untrustedKey": "rejected"})

	// The signature route denies exactly what the archive route denies.
	tok := l.token("sd-team", sa.Name, downloadAudience)
	hc := ts.Client()
	full := &v1alpha1.AssessmentRun{}
	l.eventually("a full-binding run exists", func() (bool, string) {
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(l.ctx, &runs)
		for i := range runs.Items {
			if runs.Items[i].Spec.BindingRef.Name == b.Name && runs.Items[i].Spec.Scope == v1alpha1.RunScopeBinding {
				full = &runs.Items[i]
				return true, ""
			}
		}
		return false, toJSON(runs.Items)
	})
	for what, path := range map[string]string{
		"full-binding run":  "/v1/assessmentruns/" + string(full.UID) + "/%s",
		"own run, platform": "/v1/assessmentruns/" + st.Run.UID + "/%s",
		"sibling namespace": "/v1/namespaces/sd-other/assessmentrequests/nightly/%s?uid=" + string(req.UID),
		"wrong request uid": "/v1/namespaces/sd-team/assessmentrequests/nightly/%s?uid=00000000-0000-0000-0000-000000000000",
	} {
		a, _ := fetch(t, hc, ts.URL+strings.Replace(path, "%s", "download", 1), tok)
		s, body := fetch(t, hc, ts.URL+strings.Replace(path, "%s", "signature", 1), tok)
		if a != http.StatusForbidden || s != http.StatusForbidden {
			t.Fatalf("%s: archive %d, signature %d %s", what, a, s, body)
		}
	}
	teamSig := ts.URL + "/v1/namespaces/sd-team/assessmentrequests/nightly/signature?uid=" + string(req.UID)
	teamArchive := strings.Replace(teamSig, "/signature?", "/download?", 1)
	if code, _ := fetch(t, hc, teamSig, l.token("sd-team", sa.Name, "https://kubernetes.default.svc.cluster.local")); code != http.StatusUnauthorized {
		t.Fatalf("wrong audience: %d", code)
	}
	l.record("signature-authorization", map[string]any{"broader": "Forbidden", "audience": "Unauthorized"})

	// Retiring the private key does not affect downloads.
	if err := l.c.Delete(l.ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: key.Name}}); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{teamArchive, teamSig} {
		if code, body := fetch(t, hc, u, tok); code != http.StatusOK {
			t.Fatalf("download after key retirement: %d %s", code, body)
		}
	}
	l.record("key-retired", map[string]any{"archive": 200, "signature": 200})

	// A replaced signature object makes both routes refuse; restoring it
	// restores both.
	sigKey := run.Status.Publication.Signature.Key
	original, err := os.ReadFile(filepath.Join(work, "package.sigstore.json"))
	if err != nil {
		t.Fatal(err)
	}
	other, _ := signingKeySecret(t, "other", "pw")
	otherSigner, err := evidencesign.NewSecretSigner(other.Data)
	if err != nil {
		t.Fatal(err)
	}
	dg, _ := evidencesign.ParseArchiveDigest(run.Status.Publication.PackageSHA256)
	forged, err := otherSigner.Sign(l.ctx, dg)
	if err != nil {
		t.Fatal(err)
	}
	put := func(body []byte) {
		if _, err := pub.Client.PutObject(l.ctx, &s3.PutObjectInput{Bucket: aws.String(pub.Dest.Bucket), Key: aws.String(sigKey), Body: strings.NewReader(string(body))}); err != nil {
			t.Fatal(err)
		}
	}
	put(forged.Bundle)
	for _, u := range []string{teamArchive, teamSig} {
		if code, body := fetch(t, hc, u, tok); code != http.StatusBadGateway {
			t.Fatalf("replaced signature: %d %s", code, body)
		}
	}
	put(original)
	for _, u := range []string{teamArchive, teamSig} {
		if code, body := fetch(t, hc, u, tok); code != http.StatusOK {
			t.Fatalf("restored signature: %d %s", code, body)
		}
	}
	l.record("tampered-signature", map[string]any{"replaced": 502, "restored": 200})
}
