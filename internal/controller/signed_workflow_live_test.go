//go:build live

package controller

// Live signed-publication workflow (add-evidence-signing 6.1, 6.2), on real
// Kubernetes APIs with the test-owned S3 service, disposable key Secrets and
// the pinned Cosign: full-binding and namespace-request packages, incomplete
// and diagnostic packages, key rotation with a pending dependency (the old
// run waits, then signs with its pinned key once that key is back, while a
// new run signs with the next key), retention expiry removing the signature
// with the archive, and an orphan handoff whose inventory records the
// signing intent and after which neither artifact is served. Every
// downloaded pair is verified offline with the documented Cosign command
// and the separately trusted public key, and with no other key. Sanitized
// evidence (public keys, bundles, digests, Cosign output; never private key
// material) is kept under the live output directory. Tampering, signature
// authorization and private-key retirement on download are covered by
// TestLiveSignedEvidenceDownload; leader loss mid-signing by
// TestLiveHelmDurableRecovery (availability). Run through
// scripts/targeting-live.sh.

import (
	"context"
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
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/download"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

func TestLiveSignedPublicationWorkflow(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	ns := "konstapel-system"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	evidence := filepath.Join(l.out, t.Name())
	if err := os.MkdirAll(evidence, 0o755); err != nil {
		t.Fatal(err)
	}
	// Test-owned Secrets are removed at the end; any other Secret in the
	// controller namespace is left exactly as it was.
	others := map[string]string{}
	var before corev1.SecretList
	_ = l.c.List(l.ctx, &before, client.InNamespace(ns))
	for _, s := range before.Items {
		others[s.Name] = s.ResourceVersion
	}
	owned := map[string]bool{}
	t.Cleanup(func() {
		var after corev1.SecretList
		_ = l.c.List(context.Background(), &after, client.InNamespace(ns))
		for _, s := range after.Items {
			if owned[s.Name] {
				t.Errorf("test-owned Secret %s left behind", s.Name)
			} else if rv, ok := others[s.Name]; ok && rv != s.ResourceVersion {
				t.Errorf("unrelated Secret %s was changed", s.Name)
			}
		}
	})
	putSecret := func(s *corev1.Secret) {
		t.Helper()
		owned[s.Name] = true
		cur := &corev1.Secret{}
		if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(s), cur); err == nil {
			_ = l.c.Delete(l.ctx, cur)
			l.eventually("old "+s.Name+" removed", func() (bool, string) {
				return l.c.Get(l.ctx, client.ObjectKeyFromObject(s), &corev1.Secret{}) != nil, ""
			})
		}
		if err := l.c.Create(l.ctx, s.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = l.c.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: s.Name}})
		})
	}
	s3secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "wf-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	putSecret(s3secret)
	keyA, fpA := signingKeySecret(t, "wf-signing-2026", "wf-password-1")
	keyB, fpB := signingKeySecret(t, "wf-signing-2027", "wf-password-2")
	putSecret(keyA)
	for name, k := range map[string]*corev1.Secret{"trusted-2026.pub": keyA, "trusted-2027.pub": keyB} {
		if err := os.WriteFile(filepath.Join(evidence, name), k.Data[evidencesign.SecretPublicKey], 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "wf-dest"}, Spec: v1alpha1.EvidenceDestinationSpec{
		S3: v1alpha1.S3Location{Endpoint: l.s3Endpoint, Bucket: pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/wf-dest", DevelopmentFixture: true,
			CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: s3secret.Name}}},
		Signing: requiredSigning(keyA.Name)}}
	if err := l.c.Create(l.ctx, ed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		got := &v1alpha1.EvidenceDestination{}
		if l.c.Get(context.Background(), client.ObjectKeyFromObject(ed), got) == nil {
			controllerutil.RemoveFinalizer(got, DestinationFinalizer)
			_ = l.c.Update(context.Background(), got)
			_ = l.c.Delete(context.Background(), got)
		}
		var cms corev1.ConfigMapList
		_ = l.c.List(context.Background(), &cms, client.InNamespace(ns), client.MatchingLabels{LabelOrphanHandoff: string(ed.UID)})
		for i := range cms.Items {
			_ = l.c.Delete(context.Background(), &cms.Items[i])
		}
	})
	setDest := func(f func(*v1alpha1.EvidenceDestination)) {
		t.Helper()
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			got := &v1alpha1.EvidenceDestination{}
			if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got); err != nil {
				return err
			}
			f(got)
			return l.c.Update(l.ctx, got)
		}); err != nil {
			t.Fatal(err)
		}
	}
	dp := &DestinationPublishers{Reader: l.c, Namespace: ns}
	runtime := AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: 10 * time.Minute, Workers: 2,
		ControllerNamespace: ns, Destinations: dp}
	ConfigureAssessments(runtime)
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	l.applyFile("../../config/rbac/assessment-requester.yaml")
	l.applyFile("../../config/rbac/assessment-operator.yaml")
	l.applyManifests("../../config/admission/evidence-destination-orphan.yaml", nil)

	l.setNamespace("wf-team", "wf-production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "wf-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("wf-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "wf-production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "20s", DestinationRef: &v1alpha1.DestinationReference{Name: ed.Name, UID: string(ed.UID)}}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "wf-team"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	team := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "wf-team", Name: "evidence-reader"}}
	operator := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "wf-team", Name: "platform-operator"}}
	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "wf-team", Name: "evidence-reader"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-assessment-requester"},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "wf-team", Name: team.Name}}}
	crb := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "wf-platform-operator"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-assessment-operator"},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "wf-team", Name: operator.Name}}}
	req := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "wf-team", Name: "nightly"},
		Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}}}
	var extra []client.Object
	t.Cleanup(func() {
		l.dropRuns(b.Name)
		for _, o := range append([]client.Object{req, rb, crb, team, operator, pod, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.Name}}, p}, extra...) {
			_ = l.c.Delete(context.Background(), o)
		}
	})
	for _, o := range []client.Object{p, b, pod, team, operator, rb, crb} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	stop := l.startManager()
	defer func() { stop() }()
	l.waitReady(b.Name, 1)

	srv := &download.Server{Reader: l.c, Reviews: download.KubeReviewer{Client: l.c, Audience: downloadAudience}, TempDir: t.TempDir(),
		PublisherFor: func(ctx context.Context, r *v1alpha1.AssessmentRun) (publication.Publisher, error) {
			return dp.For(ctx, r.Status.Destination)
		}}
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()
	hc := ts.Client()
	opTok := l.token("wf-team", operator.Name, downloadAudience)

	// verifyOffline downloads both artifacts from url (archive) and its
	// signature companion, keeps them as evidence, and runs the documented
	// Cosign verification with the trusted key; every other key fails.
	verifyOffline := func(label, url, tok, trusted string, untrusted ...string) publication.Descriptor {
		t.Helper()
		dir := filepath.Join(evidence, label)
		_ = os.MkdirAll(dir, 0o755)
		ac, archive := fetch(t, hc, url, tok)
		sc, bundle := fetch(t, hc, strings.Replace(url, "/download", "/signature", 1), tok)
		if ac != http.StatusOK || sc != http.StatusOK {
			t.Fatalf("%s: archive %d, signature %d %s", label, ac, sc, bundle)
		}
		_ = os.WriteFile(filepath.Join(dir, "package.tar.gz"), archive, 0o644)
		_ = os.WriteFile(filepath.Join(dir, "package.sigstore.json"), bundle, 0o644)
		cosign := func(key string) (string, error) {
			cmd := exec.CommandContext(l.ctx, "cosign", "verify-blob", "--key", filepath.Join(evidence, key), "--bundle", "package.sigstore.json", "--insecure-ignore-tlog=true", "package.tar.gz")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "HOME="+dir)
			out, err := cmd.CombinedOutput()
			return string(out), err
		}
		out, err := cosign(trusted)
		_ = os.WriteFile(filepath.Join(dir, "cosign-"+trusted+".log"), []byte(out), 0o644)
		if err != nil || !strings.Contains(out, "Verified OK") {
			t.Fatalf("%s: offline verification with %s failed: %v\n%s", label, trusted, err, out)
		}
		for _, k := range untrusted {
			if out, err := cosign(k); err == nil || strings.Contains(out, "Verified OK") {
				t.Fatalf("%s: verified with the untrusted %s", label, k)
			}
		}
		x := t.TempDir()
		untar(t, archive, x)
		d, err := publication.LoadDescriptor(x)
		if err != nil || publication.VerifyDir(x, d) != nil {
			t.Fatalf("%s: package: %v", label, err)
		}
		return d
	}
	runURL := func(r *v1alpha1.AssessmentRun) string {
		return ts.URL + "/v1/assessmentruns/" + string(r.UID) + "/download"
	}
	signedBy := func(r *v1alpha1.AssessmentRun, fp string) {
		t.Helper()
		if r.Status.Publication == nil || r.Status.Publication.Signature == nil || r.Status.Publication.Signature.KeyFingerprint != fp ||
			r.Status.SigningIntent == nil || r.Status.SigningIntent.Key == nil || r.Status.SigningIntent.Key.Fingerprint != fp {
			t.Fatalf("%s is not signed by %s: %s", r.Name, fp, toJSON(r.Status))
		}
	}

	// 1. Full-binding package, platform route.
	full := l.publishedRun(b.Name, "")
	signedBy(full, fpA)
	d := verifyOffline("full-binding", runURL(full), opTok, "trusted-2026.pub", "trusted-2027.pub")
	if d.Scope.Kind != publication.ScopeBinding {
		t.Fatalf("full-binding scope %+v", d.Scope)
	}
	l.record("full-binding", map[string]any{"run": full.Name, "keyFingerprint": fpA, "completeness": d.Evidence.Completeness, "verified": "trusted-2026.pub"})

	// 2. Namespace-request package, team route.
	if err := l.c.Create(l.ctx, req); err != nil {
		t.Fatal(err)
	}
	var st v1alpha1.AssessmentRequestStatus
	l.eventually("team request published", func() (bool, string) {
		got := &v1alpha1.AssessmentRequest{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(req), got)
		st, req.UID = got.Status, got.UID
		return st.Phase == v1alpha1.RequestCompleted && st.ArtifactRef != "", toJSON(st)
	})
	teamRun := l.run(st.Run.Name)
	signedBy(teamRun, fpA)
	d = verifyOffline("namespace-request", ts.URL+"/v1/namespaces/wf-team/assessmentrequests/nightly/download?uid="+string(req.UID),
		l.token("wf-team", team.Name, downloadAudience), "trusted-2026.pub", "trusted-2027.pub")
	if d.Scope.Kind != publication.ScopeNamespace {
		t.Fatalf("namespace scope %+v", d.Scope)
	}
	l.record("namespace-request", map[string]any{"run": teamRun.Name, "keyFingerprint": fpA, "verified": "trusted-2026.pub"})

	// 3. Incomplete: an engine reporting outage while a workload is added.
	l.scaleKyverno("kyverno-reports-controller", 0)
	l.scaleKyverno("kyverno-background-controller", 0)
	added := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged-added", Namespace: "wf-team"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	if err := l.c.Create(l.ctx, added); err != nil {
		t.Fatal(err)
	}
	extra = append(extra, added)
	l.createRun(b.Name, "wf-audit-incomplete")
	incomplete := l.publishedRun(b.Name, "wf-audit-incomplete")
	l.scaleKyverno("kyverno-reports-controller", 1)
	l.scaleKyverno("kyverno-background-controller", 1)
	signedBy(incomplete, fpA)
	if incomplete.Status.Summary.Evidence.Completeness != "Incomplete" || incomplete.Status.Summary.Export != "Assessment" {
		t.Fatalf("incomplete run: %s", toJSON(incomplete.Status.Summary))
	}
	if d := verifyOffline("incomplete", runURL(incomplete), opTok, "trusted-2026.pub", "trusted-2027.pub"); d.Evidence.Completeness != publication.Incomplete {
		t.Fatalf("incomplete package %+v", d.Evidence)
	}
	l.record("incomplete", map[string]any{"run": incomplete.Name, "summary": incomplete.Status.Summary, "verified": "trusted-2026.pub"})

	// 4. Diagnostic: an impossible OSCAL export (no content root).
	broken := runtime
	broken.ContentRoot = t.TempDir()
	stop()
	ConfigureAssessments(broken)
	stop = l.startManager()
	l.createRun(b.Name, "wf-audit-diagnostic")
	diagnostic := l.publishedRun(b.Name, "wf-audit-diagnostic")
	stop()
	ConfigureAssessments(runtime)
	stop = l.startManager()
	signedBy(diagnostic, fpA)
	if diagnostic.Status.Summary.Export != "Diagnostic" {
		t.Fatalf("diagnostic run: %s", toJSON(diagnostic.Status.Summary))
	}
	if d := verifyOffline("diagnostic", runURL(diagnostic), opTok, "trusted-2026.pub", "trusted-2027.pub"); d.PackageKind != publication.KindDiagnostic {
		t.Fatalf("diagnostic package %s", d.PackageKind)
	}
	l.record("diagnostic", map[string]any{"run": diagnostic.Name, "summary": diagnostic.Status.Summary, "verified": "trusted-2026.pub"})

	// 5. Rotation while a run depends on the old key: the 2026 Secret is
	// gone when the run is prepared, so it waits and the destination lists
	// the dependency; the destination moves to the 2027 Secret; the old
	// key comes back re-encrypted, and the waiting run signs with its
	// pinned 2026 Secret while a new run signs with 2027.
	_ = l.c.Delete(l.ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: keyA.Name}})
	l.createRun(b.Name, "wf-audit-rotation-old")
	l.eventually("the old run waits for its key", func() (bool, string) {
		r := l.run("wf-audit-rotation-old")
		c := meta.FindStatusCondition(r.Status.Conditions, v1alpha1.ConditionPublished)
		return c != nil && c.Reason == v1alpha1.ReasonSigningPending, toJSON(r.Status.Conditions)
	})
	pending := func() []v1alpha1.PendingSigningKey {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
		return got.Status.PendingSigningKeys
	}
	l.eventually("the pending key dependency is listed", func() (bool, string) {
		got := pending()
		return len(got) == 1 && got[0].SecretName == keyA.Name && got[0].Runs == 1, toJSON(got)
	})
	putSecret(keyB)
	setDest(func(e *v1alpha1.EvidenceDestination) { e.Spec.Signing = requiredSigning(keyB.Name) })
	if got := pending(); len(got) != 1 || got[0].SecretName != keyA.Name {
		t.Fatalf("rotation hid the dependency: %s", toJSON(got))
	}
	putSecret(reencrypt(t, keyA, "wf-password-1", "wf-password-1b"))
	old := l.publishedRun(b.Name, "wf-audit-rotation-old")
	signedBy(old, fpA)
	verifyOffline("rotation-old", runURL(old), opTok, "trusted-2026.pub", "trusted-2027.pub")
	l.eventually("the dependency is released", func() (bool, string) { got := pending(); return len(got) == 0, toJSON(got) })
	l.createRun(b.Name, "wf-audit-rotation-new")
	next := l.publishedRun(b.Name, "wf-audit-rotation-new")
	signedBy(next, fpB)
	verifyOffline("rotation-new", runURL(next), opTok, "trusted-2027.pub", "trusted-2026.pub")
	l.record("rotation", map[string]any{"oldRun": old.Name, "oldKey": fpA, "newRun": next.Name, "newKey": fpB, "pendingListed": keyA.Name, "reencryptedOldKey": true})

	// 6. Retention: a signed package expires and its signature is deleted
	// with it; neither artifact is served.
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		got := l.binding(b.Name)
		got.Spec.Assessment.Retention = "60s"
		return l.c.Update(l.ctx, got)
	}); err != nil {
		t.Fatal(err)
	}
	l.createRun(b.Name, "wf-audit-retention")
	short := l.publishedRun(b.Name, "wf-audit-retention")
	signedBy(short, fpB)
	prefix := s3store.RunPrefix(s3store.Destination{Prefix: ed.Spec.S3.Prefix}, publication.RunRef{ClusterID: short.Status.Scope.ClusterID, BindingUID: short.Status.Binding.UID, RunUID: string(short.UID)})
	objects := func() []string {
		out, _ := pub.Client.ListObjectsV2(l.ctx, &s3.ListObjectsV2Input{Bucket: aws.String(pub.Dest.Bucket), Prefix: aws.String(prefix)})
		var keys []string
		for _, o := range out.Contents {
			keys = append(keys, aws.ToString(o.Key))
		}
		return keys
	}
	if keys := strings.Join(objects(), " "); !strings.Contains(keys, "package.sigstore.json") {
		t.Fatalf("signed package without a stored signature: %s", keys)
	}
	l.eventually("retention deleted the signed package", func() (bool, string) {
		r := l.run(short.Name)
		return r != nil && r.Status.Publication.Cleanup.State == "Deleted" && len(objects()) == 0, toJSON(objects())
	})
	// Neither artifact is served once the package expired and was deleted;
	// both routes answer alike (the existing download contract answers 410
	// while expired objects remain and 409 once they are deleted).
	ac, _ := fetch(t, hc, runURL(short), opTok)
	sc, _ := fetch(t, hc, strings.Replace(runURL(short), "/download", "/signature", 1), opTok)
	if ac != sc || (ac != http.StatusGone && ac != http.StatusConflict) {
		t.Fatalf("deleted signed package: archive %d, signature %d", ac, sc)
	}
	l.record("retention", map[string]any{"run": short.Name, "objectsLeft": 0, "archive": ac, "signature": sc})

	// 7. Orphan handoff: the inventory records the signing intent and the
	// signature; nothing is served afterwards.
	setDest(func(e *v1alpha1.EvidenceDestination) {
		e.Spec.DeletionPolicy = v1alpha1.DeletionOrphan
		e.Spec.Orphan = &v1alpha1.OrphanRequest{Reason: "signed evidence handed to the archive team"}
	})
	if err := l.c.Delete(l.ctx, &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: ed.Name}}); err != nil {
		t.Fatal(err)
	}
	header := &corev1.ConfigMap{}
	l.eventually("orphan inventory saved", func() (bool, string) {
		err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: inventoryName(string(ed.UID), -1)}, header)
		return err == nil, ""
	})
	chunk := &corev1.ConfigMap{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: inventoryName(string(ed.UID), 0)}, chunk); err != nil {
		t.Fatal(err)
	}
	inv := chunk.Data[inventoryKey]
	if !strings.Contains(inv, `"signingIntent"`) || !strings.Contains(inv, fpA) || !strings.Contains(inv, fpB) || !strings.Contains(inv, next.Status.Publication.Signature.SHA256) {
		t.Fatalf("inventory lacks signing records: %s", inv)
	}
	for _, secret := range []string{"wf-password", "PRIVATE"} {
		if strings.Contains(inv, secret) || strings.Contains(header.Data[inventoryKey], secret) {
			t.Fatalf("inventory holds private material %q", secret)
		}
	}
	_ = os.WriteFile(filepath.Join(evidence, "orphan-inventory-chunk.json"), []byte(inv), 0o644)
	for _, u := range []string{runURL(next), strings.Replace(runURL(next), "/download", "/signature", 1)} {
		var code int
		l.eventually("orphaned package not served", func() (bool, string) { code, _ = fetch(t, hc, u, opTok); return code == http.StatusGone, "" })
	}
	l.record("orphaned", map[string]any{"inventory": header.Name, "signingRecorded": true, "archive": 410, "signature": 410})
}
