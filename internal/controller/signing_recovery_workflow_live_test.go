//go:build live

package controller

// Live signing recovery workflow (add-evidence-signing-recovery 5.1), on
// real Kubernetes APIs with the test-owned S3 service (RustFS), a disposable
// key pair generated for this run, the shipped recovery roles and requester
// admission policies, and the pinned Cosign:
//   - the destination's key signs its first package; then the key Secret is
//     deleted, and a namespace team's request ends SigningFailed with its
//     archive retained and nothing downloadable;
//   - the key is restored from backup under its recorded name (re-encrypted
//     with a new password), and a platform recoverer, holding only the
//     recoverer and assessment-operator roles, finds the run and requests
//     recovery confirming the trusted key's fingerprint (the intent never
//     pinned a key); admission records the recoverer as the requester;
//   - the registered reconciler signs the same archive with that key and
//     commits it: the request ends Recovered, the run is Completed and records
//     the recovery, storage holds one signature and one commit, the expiry is
//     the failure record's, and every evidence field is unchanged;
//   - the team (namespace route) and the platform operator (run route)
//     download the same pair; it verifies offline with the pinned Cosign and
//     the originally trusted public key and is rejected with another key; the
//     team's request status names no administrator, Secret, or reason.
// Sanitized evidence (public keys, the package and bundle, digests,
// fingerprints, Cosign output; never private key material) is kept under the
// live output directory. Faults, concurrency, and terminal outcomes are
// covered by TestLiveSigningRecoveryClaim (recovery); admission and RBAC by
// TestLiveEvidenceSigningRequestAPI (admission). Run through
// scripts/targeting-live.sh (storage group).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/download"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

func TestLiveSigningRecoveryWorkflow(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	const ns, teamNS, recoverer = "konstapel-system", "srw-team", "srw-recoverer"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	evidence := filepath.Join(l.out, t.Name())
	if err := os.MkdirAll(evidence, 0o755); err != nil {
		t.Fatal(err)
	}
	cosignVersion := pinnedCosign(t, root, evidence)

	createSecret := func(s *corev1.Secret) *corev1.Secret {
		t.Helper()
		s = s.DeepCopy()
		if err := l.c.Create(l.ctx, s); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = l.c.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: s.Name}})
		})
		return s
	}
	s3secret := createSecret(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "srw-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}})
	// The destination's key, whose public key the auditors trust, and
	// another key that must never verify. Both are generated for this run.
	keyA, fpA := signingKeySecret(t, "srw-signing-2026", "srw-password-1")
	other, fpB := signingKeySecret(t, "srw-other", "srw-password-x")
	for name, k := range map[string]*corev1.Secret{"trusted.pub": keyA, "other.pub": other} {
		if err := os.WriteFile(filepath.Join(evidence, name), k.Data[evidencesign.SecretPublicKey], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	original := createSecret(keyA)

	ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "srw-dest"}, Spec: v1alpha1.EvidenceDestinationSpec{
		S3: v1alpha1.S3Location{Endpoint: l.s3Endpoint, Bucket: pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/srw-dest", DevelopmentFixture: true,
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
	})
	dp := &DestinationPublishers{Reader: l.c, Namespace: ns}
	rt := AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: 10 * time.Minute, Workers: 2,
		ControllerNamespace: ns, Destinations: dp}
	ConfigureAssessments(rt)
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })

	// The shipped roles (recovery roles under test-owned names, rules
	// unchanged) and the shipped requester admission policies.
	l.applyFile("../../config/rbac/assessment-requester.yaml")
	l.applyFile("../../config/rbac/assessment-operator.yaml")
	l.applyManifests("../../config/rbac/evidence-signing-recovery.yaml", func(u *unstructured.Unstructured) { u.SetName(u.GetName() + "-srw-live") })
	l.bind("srw-recoverer", recoverer, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-evidence-signing-recoverer-srw-live"}, "")
	// A recoverer finds failed runs through the operator grant.
	l.bind("srw-recoverer-operator", recoverer, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-assessment-operator"}, "")
	l.applyManifests("../../config/admission/evidence-signing-requester.yaml", nil)

	l.setNamespace(teamNS, "srw-production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "srw-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("srw-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "srw-production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "20s", DestinationRef: &v1alpha1.DestinationReference{Name: ed.Name, UID: string(ed.UID)}}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: teamNS},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	team := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: teamNS, Name: "evidence-reader"}}
	operator := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: teamNS, Name: "platform-operator"}}
	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: teamNS, Name: "evidence-reader"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-assessment-requester"},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: teamNS, Name: team.Name}}}
	crb := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "srw-platform-operator"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-assessment-operator"},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: teamNS, Name: operator.Name}}}
	req := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: teamNS, Name: "nightly"},
		Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}}}
	t.Cleanup(func() {
		var list v1alpha1.EvidenceSigningRequestList
		_ = l.c.List(context.Background(), &list)
		for i := range list.Items {
			if strings.HasPrefix(list.Items[i].Name, "srw-") {
				_ = l.c.Delete(context.Background(), &list.Items[i])
			}
		}
		l.dropRuns(b.Name)
		for _, o := range []client.Object{req, rb, crb, team, operator, pod, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.Name}}, p} {
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
	// restart replaces the in-process manager with one built under the
	// publish timeout given (the runtime applies to managers built after
	// it is configured).
	stop := l.startManager()
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	restart := func(publishTimeout time.Duration) {
		stop()
		stop = nil
		rt.PublishTimeout = publishTimeout
		ConfigureAssessments(rt)
		stop = l.startManager()
	}
	l.waitReady(b.Name, 1)

	srv := &download.Server{Reader: l.c, Reviews: download.KubeReviewer{Client: l.c, Audience: downloadAudience}, TempDir: t.TempDir(),
		PublisherFor: func(ctx context.Context, r *v1alpha1.AssessmentRun) (publication.Publisher, error) {
			return dp.For(ctx, r.Status.Destination)
		}}
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()
	hc := ts.Client()
	opTok, teamTok := l.token(teamNS, operator.Name, downloadAudience), l.token(teamNS, team.Name, downloadAudience)

	// 1. The destination's key signs its first package.
	first := l.publishedRun(b.Name, "")
	if s := first.Status.Publication.Signature; s == nil || s.KeyFingerprint != fpA {
		t.Fatalf("the first package is not signed by %s: %s", fpA, toJSON(first.Status.Publication))
	}
	l.record("established-key", map[string]any{"run": first.Name, "keyFingerprint": fpA, "otherKeyFingerprint": fpB, "cosign": cosignVersion})

	// 2. The key Secret is deleted. The team's request is prepared without
	// it: its run records a Required intent without a key, waits, and ends
	// SigningFailed at the publish timeout with its archive retained.
	if err := l.c.Delete(l.ctx, original); err != nil {
		t.Fatal(err)
	}
	l.eventually("the key Secret is gone", func() (bool, string) {
		return l.c.Get(l.ctx, client.ObjectKeyFromObject(original), &corev1.Secret{}) != nil, ""
	})
	restart(30 * time.Second)
	if err := l.c.Create(l.ctx, req); err != nil {
		t.Fatal(err)
	}
	request := func() *v1alpha1.AssessmentRequest {
		got := &v1alpha1.AssessmentRequest{}
		if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(req), got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	var failedReq *v1alpha1.AssessmentRequest
	l.eventually("the team request fails signing", func() (bool, string) {
		failedReq = request()
		c := meta.FindStatusCondition(failedReq.Status.Conditions, v1alpha1.ConditionPublished)
		return failedReq.Status.Phase == v1alpha1.RequestFailed && failedReq.Status.Run != nil && c != nil && c.Reason == v1alpha1.ReasonSigningFailed, toJSON(failedReq.Status)
	})
	failed := l.run(failedReq.Status.Run.Name)
	if failed == nil {
		t.Fatalf("the request's run %s is missing", failedReq.Status.Run.Name)
	}
	in := failed.Status.SigningIntent
	if !retainedSigningFailure(failed) || in == nil || in.Mode != v1alpha1.SigningRequired || in.Key != nil || in.SecretName != keyA.Name ||
		in.ArchiveSHA256 != failed.Status.Publication.PackageSHA256 || failed.Status.SigningRecovery != nil || failed.Status.Publication.Cleanup.State != "NotDue" {
		t.Fatalf("want a retained SigningFailed run with an unpinned Required intent: %s", toJSON(failed.Status))
	}
	runURL := ts.URL + "/v1/assessmentruns/" + string(failed.UID) + "/download"
	teamURL := ts.URL + "/v1/namespaces/" + teamNS + "/assessmentrequests/" + req.Name + "/download?uid=" + string(failedReq.UID)
	refused := map[string]int{}
	for label, u := range map[string]struct{ url, tok string }{"platform": {runURL, opTok}, "team": {teamURL, teamTok}} {
		for _, artifact := range []string{"download", "signature"} {
			code, _ := fetch(t, hc, strings.Replace(u.url, "/download", "/"+artifact, 1), u.tok)
			if code == http.StatusOK {
				t.Fatalf("%s %s of a retained SigningFailed run was served", label, artifact)
			}
			refused[label+"-"+artifact] = code
		}
	}
	l.record("signing-failed", map[string]any{"run": failed.Name, "failure": failed.Status.Publication.Failure.Reason, "failedAt": failed.Status.Publication.Failure.At,
		"expiresAt": failed.Status.Publication.ExpiresAt, "archiveSha256": in.ArchiveSHA256, "intentKeyPinned": false, "request": failedReq.Status.Phase, "downloads": refused})

	// 3. The key is restored from backup under the recorded name,
	// re-encrypted with a new password; each recovery attempt is bounded
	// by the publish timeout from its claim.
	restored := createSecret(reencrypt(t, keyA, "srw-password-1", "srw-password-2"))
	restart(3 * time.Minute)

	// 4. The recoverer finds the run through the operator grant and asks for
	// recovery, confirming the trusted key's fingerprint because the intent
	// never pinned one. Admission records the recoverer as the requester.
	recC := l.as(recoverer, "system:authenticated")
	found := &v1alpha1.AssessmentRun{}
	if err := recC.Get(l.ctx, client.ObjectKeyFromObject(failed), found); err != nil || found.UID != failed.UID || !retainedSigningFailure(found) {
		t.Fatalf("the recoverer cannot find the retained run: %v", err)
	}
	newRequest := func(name string) *v1alpha1.EvidenceSigningRequest {
		return &v1alpha1.EvidenceSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.EvidenceSigningRequestSpec{
			Run:    v1alpha1.ExactRunReference{Name: found.Name, UID: string(found.UID)},
			Reason: "Signing key Secret srw-signing-2026 restored from backup after accidental deletion (live acceptance)", ExpectedKeyFingerprint: fpA}}
	}
	l.eventually("the requester admission policies are effective", func() (bool, string) {
		probe := newRequest("srw-probe")
		probe.Spec.RequestedBy = &v1alpha1.Requester{Username: "someone-else", UID: "uid-someone-else"}
		if err := recC.Create(l.ctx, probe, client.DryRunAll); err != nil {
			return false, err.Error()
		}
		return probe.Spec.RequestedBy != nil && probe.Spec.RequestedBy.Username == recoverer, toJSON(probe.Spec.RequestedBy)
	})
	esr := newRequest("srw-key-restored")
	if err := recC.Create(l.ctx, esr); err != nil {
		t.Fatal(err)
	}
	who := v1alpha1.Requester{Username: recoverer, UID: "uid-" + recoverer}
	if esr.Spec.RequestedBy == nil || *esr.Spec.RequestedBy != who {
		t.Fatalf("admission did not record the recoverer: %s", toJSON(esr.Spec.RequestedBy))
	}

	// 5. The registered reconciler signs the retained archive with the
	// restored key and commits it; the request ends Recovered.
	l.eventually("the recovery request succeeds", func() (bool, string) {
		got := &v1alpha1.EvidenceSigningRequest{}
		if err := recC.Get(l.ctx, client.ObjectKeyFromObject(esr), got); err != nil {
			return false, err.Error()
		}
		esr = got
		if got.Status.Phase == v1alpha1.SigningRequestFailed {
			t.Fatalf("the recovery request failed: %s", toJSON(got.Status))
		}
		return got.Status.Phase == v1alpha1.SigningRequestSucceeded, toJSON(got.Status)
	})
	run := l.run(failed.Name)
	rp, est := run.Status.Publication, esr.Status
	k := run.Status.SigningIntent.Key
	if est.Reason != v1alpha1.RecoveryRecovered || est.KeyFingerprint != fpA || est.RequestedBy == nil || *est.RequestedBy != who ||
		est.Run == nil || est.Run.UID != string(failed.UID) || est.Publication == nil || strings.Contains(toJSON(est), keyA.Name) {
		t.Fatalf("want Recovered under %s by %s, naming no Secret: %s", fpA, recoverer, toJSON(est))
	}
	if k == nil || k.Fingerprint != fpA || k.SecretUID != string(restored.UID) || run.Status.SigningIntent.SecretName != keyA.Name {
		t.Fatalf("want the intent pinned once to the confirmed key from the restored Secret: %s", toJSON(run.Status.SigningIntent))
	}
	sr := run.Status.SigningRecovery
	cond := meta.FindStatusCondition(run.Status.Conditions, v1alpha1.ConditionPublished)
	if run.Status.Phase != v1alpha1.RunCompleted || cond == nil || cond.Status != metav1.ConditionTrue || !strings.Contains(cond.Message, esr.Name) ||
		sr == nil || sr.Active != nil || sr.Recovered == nil || sr.Recovered.Name != esr.Name || sr.Recovered.UID != string(esr.UID) || sr.Recovered.RequestedBy != who {
		t.Fatalf("want the run Completed and recording the recovery by %s: %s", esr.Name, toJSON(run.Status))
	}
	// The same archive, signed under the confirmed key, keeps the failure
	// record's expiry; the commit time is the late publication time.
	fp := failed.Status.Publication
	if rp.Commit == nil || rp.Signature == nil || rp.Signature.KeyFingerprint != fpA || rp.PackageSHA256 != fp.PackageSHA256 || rp.PackageSHA256 != in.ArchiveSHA256 ||
		rp.DescriptorSHA256 != fp.DescriptorSHA256 || rp.PublicationID != fp.PublicationID || !rp.ExpiresAt.Equal(fp.ExpiresAt) ||
		rp.Retention == nil || rp.Retention.NotAfter == nil || !rp.Retention.NotAfter.Equal(fp.ExpiresAt) || rp.PublishedAt == nil || !rp.PublishedAt.After(fp.Failure.At.Time) {
		t.Fatalf("want the retained archive committed under %s with the recorded expiry %s:\n%s", fpA, fp.ExpiresAt, toJSON(rp))
	}
	if p := est.Publication; p.PublicationID != rp.PublicationID || p.PackageSHA256 != rp.PackageSHA256 || p.SignatureSHA256 != rp.Signature.SHA256 ||
		!p.PublishedAt.Equal(rp.PublishedAt) || !p.ExpiresAt.Equal(rp.ExpiresAt) {
		t.Fatalf("the request does not reference the run's publication:\n%s\n%s", toJSON(p), toJSON(rp))
	}
	evidenceFields := func(st *v1alpha1.AssessmentRunStatus) string {
		c := st.DeepCopy()
		meta.RemoveStatusCondition(&c.Conditions, v1alpha1.ConditionAttemptsCleaned)
		return evidenceOf(c)
	}
	if evidenceFields(&run.Status) != evidenceFields(&failed.Status) {
		t.Fatalf("recovery changed the run's evidence:\n%s\n%s", evidenceFields(&failed.Status), evidenceFields(&run.Status))
	}
	// Storage holds one signature and one commit for the run.
	versions, err := pub.Client.ListObjectVersions(l.ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(pub.Dest.Bucket), Prefix: aws.String(ed.Spec.S3.Prefix + "/")})
	if err != nil {
		t.Fatal(err)
	}
	counts, markers := map[string]int{}, 0
	for _, v := range versions.Versions {
		if key := aws.ToString(v.Key); strings.Contains(key, string(run.UID)) {
			counts[key[strings.LastIndex(key, "/")+1:]]++
		}
	}
	for _, m := range versions.DeleteMarkers {
		if strings.Contains(aws.ToString(m.Key), string(run.UID)) {
			markers++
		}
	}
	if counts[evidencesign.BundleFileName] != 1 || counts["commit.json"] != 1 || markers != 0 {
		t.Fatalf("want one signature and one commit version: %v (delete markers %d)", counts, markers)
	}
	l.record("recovered", map[string]any{"request": esr.Name, "requestedBy": who, "reason": est.Reason, "keyFingerprint": est.KeyFingerprint,
		"restoredSecretReencrypted": true, "publicationID": rp.PublicationID, "packageSha256": rp.PackageSHA256, "signatureSha256": rp.Signature.SHA256,
		"failedAt": fp.Failure.At, "publishedAt": rp.PublishedAt, "expiresAt": rp.ExpiresAt, "retention": *rp.Retention, "storageVersions": counts,
		"evidenceUnchanged": true, "summary": run.Status.Summary, "window": run.Status.Window})

	// 6. The team's request is Completed with the sanitized projection: no
	// administrator, request, Secret, or recovery reason.
	done := request()
	rs := toJSON(done.Status)
	if c := meta.FindStatusCondition(done.Status.Conditions, v1alpha1.ConditionPublished); done.Status.Phase != v1alpha1.RequestCompleted ||
		done.Status.ArtifactRef != rp.PublicationID || c == nil || c.Status != metav1.ConditionTrue || toJSON(done.Status.Summary) != toJSON(failedReq.Status.Summary) {
		t.Fatalf("want the team request Completed with the recovered package: %s", rs)
	}
	for _, leak := range []string{recoverer, esr.Name, keyA.Name, "restored from backup", "requestedBy", "recovery"} {
		if strings.Contains(rs, leak) {
			t.Fatalf("the team request status names %q: %s", leak, rs)
		}
	}
	l.record("team-request", map[string]any{"request": req.Name, "phase": done.Status.Phase, "artifactRef": done.Status.ArtifactRef, "summaryUnchanged": true, "sanitized": true})

	// 7. The team (namespace route) and the platform operator (run route)
	// download the same pair: the retained archive and the stored
	// signature, which verify offline with the pinned Cosign and the
	// trusted key and are rejected with the other key.
	teamD, teamArchive, teamBundle := verifyOfflinePair(t, l, hc, evidence, "namespace-request", teamURL, teamTok, "trusted.pub", "other.pub")
	runD, runArchive, runBundle := verifyOfflinePair(t, l, hc, evidence, "platform-run", runURL, opTok, "trusted.pub", "other.pub")
	archiveSum, bundleSum := sha256.Sum256(runArchive), sha256.Sum256(runBundle)
	if string(teamArchive) != string(runArchive) || string(teamBundle) != string(runBundle) ||
		hex.EncodeToString(archiveSum[:]) != in.ArchiveSHA256 || hex.EncodeToString(bundleSum[:]) != rp.Signature.SHA256 {
		t.Fatalf("the routes do not serve the recovered pair: archive %x (want %s), signature %x (want %s)", archiveSum, in.ArchiveSHA256, bundleSum, rp.Signature.SHA256)
	}
	if teamD.Scope.Kind != publication.ScopeNamespace || teamD.Run.RunUID != string(run.UID) || toJSON(teamD) != toJSON(runD) ||
		string(teamD.Evidence.Completeness) != string(failed.Status.Summary.Evidence.Completeness) {
		t.Fatalf("the recovered package is not the team's retained evidence: %s", toJSON(teamD))
	}
	pk, err := evidencesign.ParsePublicKey(keyA.Data[evidencesign.SecretPublicKey])
	if err != nil {
		t.Fatal(err)
	}
	d, _ := evidencesign.ParseArchiveDigest(in.ArchiveSHA256)
	if _, err := evidencesign.Verify(runBundle, d, pk); err != nil {
		t.Fatalf("the served signature does not verify under the trusted key: %v", err)
	}
	l.record("downloads", map[string]any{"namespaceRoute": http.StatusOK, "platformRoute": http.StatusOK, "identical": true, "archiveSha256": in.ArchiveSHA256,
		"signatureSha256": rp.Signature.SHA256, "verified": "trusted.pub", "rejected": "other.pub", "cosign": cosignVersion, "scope": teamD.Scope.Kind,
		"completeness": teamD.Evidence.Completeness})
}

// pinnedCosign checks that the cosign on PATH is the version devbox.json
// pins, keeps its version output as evidence, and returns the version.
func pinnedCosign(t *testing.T, root, evidence string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "devbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct{ Packages []string }
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	pinned := ""
	for _, p := range cfg.Packages {
		if v, ok := strings.CutPrefix(p, "cosign@"); ok {
			pinned = "v" + v
		}
	}
	out, err := exec.Command("cosign", "version").CombinedOutput()
	_ = os.WriteFile(filepath.Join(evidence, "cosign-version.txt"), out, 0o644)
	if pinned == "" || err != nil || !strings.Contains(string(out), pinned+"\n") {
		t.Fatalf("want the Cosign %s pinned in devbox.json (run through Devbox): %v\n%s", pinned, err, out)
	}
	return pinned
}
