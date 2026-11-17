//go:build live

package controller

// Live chart integration of supporting evidence (add-supporting-evidence-
// attachments 7.1). Both charts are installed from the packaged image with
// non-default download.attachments values; nothing runs in-process:
//   - the download replicas become ready with the rendered attachment
//     limits, and the controller is told to verify the konstapel-download
//     readers;
//   - a document is registered (registrant admission), refused above the
//     chart's upload limit, uploaded through the installed Service by the
//     shipped uploader role, and committed with the chart's retention;
//   - while the download Deployment declares another image (a reader that
//     isn't this build, with a surge replica that never starts), a platform
//     run's package carries no supporting evidence and reports it
//     unavailable (ProtectedReadersUnverified), so run access alone reads
//     nothing protected;
//   - once the readers are this build again, the next platform run's
//     package carries the verified copy, is protected, and is served only
//     with the shipped document-read role.
// Run through scripts/targeting-live.sh (charts acceptance group).

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
	"github.com/backend-bunny/Konstapel/internal/coverage"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

func TestLiveHelmSupportingEvidence(t *testing.T) {
	image, repo, imageDigest := liveImage(t)
	l := newLive(t)
	const (
		ns     = "konstapel-system"
		title  = "DC North chart-installed physical access audit"
		issuer = "Chart Audit Firm AB"
		limit  = 64 << 10
	)
	caPEM := l.installCharts(ns, repo, imageDigest, "--set", fmt.Sprintf("download.attachments.maxBytes=%d", limit),
		"--set", "download.attachments.timeout=2m", "--set", "download.attachments.maxConcurrent=3", "--set", "download.attachments.retention=26h")

	// 1. The rendered limits reach every ready download replica, and the
	// controller verifies the chart's download Deployment.
	var pods corev1.PodList
	if err := l.c.List(l.ctx, &pods, client.InNamespace(ns)); err != nil {
		t.Fatal(err)
	}
	readyDownloads := 0
	for _, p := range pods.Items {
		c := p.Spec.Containers[0]
		switch p.Labels["app.kubernetes.io/component"] {
		case "download":
			for _, want := range []string{fmt.Sprintf("--attachment-max-bytes=%d", limit), "--attachment-timeout=2m", "--attachment-max-concurrent=3", "--attachment-retention=26h"} {
				if !slices.Contains(c.Args, want) {
					t.Fatalf("download pod %s lacks %s: %v", p.Name, want, c.Args)
				}
			}
			if c.Name != DownloadContainer || c.Image != image {
				t.Fatalf("download pod %s runs %s %s", p.Name, c.Name, c.Image)
			}
			for _, cond := range p.Status.Conditions {
				if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
					readyDownloads++
				}
			}
		case "controller":
			if !slices.Contains(c.Args, "--protected-package-readers=konstapel-download") || c.Name != ControllerContainer || c.Image != image {
				t.Fatalf("controller pod %s: %s %s %v", p.Name, c.Name, c.Image, c.Args)
			}
		}
	}
	if readyDownloads != 2 {
		t.Fatalf("%d ready download replicas\n%s", readyDownloads, l.podDiagnostics(ns))
	}
	l.record("installed", map[string]any{"image": image, "downloadReplicas": readyDownloads, "maxBytes": limit, "retention": "26h"})

	// 2. Storage on the kind network as the default destination, and a
	// platform binding assessed by the installed controller.
	pub := startS3(t, l)
	if out, err := exec.Command("docker", "network", "connect", "kind", l.s3Container).CombinedOutput(); err != nil {
		t.Fatalf("attach the S3 service to the kind network: %v %s", err, out)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "hs-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "hs-dest"}, Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{
		Endpoint: "http://" + l.s3Container + ":9000", Bucket: pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/hs", DevelopmentFixture: true,
		CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: secret.Name}}}}}
	for _, o := range []client.Object{secret, ed} {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: DefaultDestinationConfigMap},
		Data: map[string]string{DefaultDestinationNameKey: ed.Name, DefaultDestinationUIDKey: string(ed.UID)}}
	if err := l.c.Create(l.ctx, cm); apierrors.IsAlreadyExists(err) {
		err = l.c.Update(l.ctx, cm)
		if err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	l.setNamespace("hs-prod", "hs-production")
	p := profileObj(t, "hs-baseline", pol)
	b := bindingObj("hs-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "hs-production"})
	const recordName, bigName = "hs-dc-north-2026", "hs-oversized"
	// Cleanup runs before the charts are uninstalled, while the controller
	// still runs.
	t.Cleanup(func() {
		for _, n := range []string{recordName, bigName} {
			a := &v1alpha1.EvidenceAttachment{}
			if l.c.Get(l.ctx, client.ObjectKey{Name: n}, a) == nil {
				a.Finalizers = nil
				_ = l.c.Update(l.ctx, a)
				_ = l.c.Delete(l.ctx, a)
			}
		}
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(l.ctx, &runs)
		for i := range runs.Items {
			if r := &runs.Items[i]; r.Spec.BindingRef.Name == b.Name {
				r.Finalizers = nil
				_ = l.c.Update(l.ctx, r)
				_ = l.c.Delete(l.ctx, r)
			}
		}
		_ = l.c.Delete(l.ctx, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.Name}})
		_ = l.c.Delete(l.ctx, p)
		got := &v1alpha1.EvidenceDestination{}
		if l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got) == nil {
			controllerutil.RemoveFinalizer(got, DestinationFinalizer)
			_ = l.c.Update(l.ctx, got)
			_ = l.c.Delete(l.ctx, got)
		}
		_ = l.c.Delete(l.ctx, cm)
		_ = l.c.Delete(l.ctx, secret)
	})
	for _, o := range []client.Object{p, b} {
		o.SetUID("")
		// Admission policies learn a new CRD kind shortly after it is
		// served and answer 503 until then.
		l.eventually("create "+o.GetName(), func() (bool, string) {
			err := l.c.Create(l.ctx, o)
			if apierrors.IsServiceUnavailable(err) {
				return false, err.Error()
			}
			if err != nil {
				t.Fatal(err)
			}
			return true, ""
		})
	}
	l.waitReady(b.Name, 1)
	l.eventually("destination ready from inside the cluster", func() (bool, string) {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
		return meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionDestinationReady), toJSON(got.Status)
	})
	got := l.binding(b.Name)
	got.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "20s",
		DestinationRef: &v1alpha1.DestinationReference{Name: ed.Name, UID: string(ed.UID)}}
	if err := l.c.Update(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	run := func(name string) *v1alpha1.AssessmentRun {
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, r); err != nil {
			return nil
		}
		return r
	}
	committed := func(r *v1alpha1.AssessmentRun) bool {
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted && r.Status.Publication != nil &&
			r.Status.Publication.Phase == v1alpha1.PublicationPhase(publication.PhaseCommitted)
	}
	// The first scheduled run completes before any document exists.
	l.eventually("first scheduled run published", func() (bool, string) {
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(l.ctx, &runs)
		for i := range runs.Items {
			if r := &runs.Items[i]; r.Spec.BindingRef.Name == b.Name && committed(r) {
				return true, ""
			}
		}
		return false, toJSON(l.binding(b.Name).Status.Assessment)
	})

	// 3. The shipped roles: an uploader, and a platform operator who reads
	// runs; the document-read grant comes later.
	for _, sa := range []string{"hs-uploader", "hs-operator"} {
		o := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: sa}}
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(l.ctx, o) })
	}
	shipped := func(role string) rbacv1.RoleRef {
		return rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role}
	}
	l.bindSA("hs-uploader", ns, "hs-uploader", shipped("konstapel-evidence-attachment-uploader"), "")
	l.bindSA("hs-operator", ns, "hs-operator", shipped("konstapel-assessment-operator"), "")

	// 4. Register the document and an oversized one, upload through the
	// installed Service: the chart's limit refuses the oversized record
	// before any byte is read, and its retention is frozen into the
	// commitment.
	root, _ := filepath.Abs("../..")
	catalog, err := attachments.ReadVendoredBaseline(os.DirFS(root))
	if err != nil {
		t.Fatal(err)
	}
	body := append([]byte("%PDF-1.7 "+title+"\n"), bytes.Repeat([]byte{0x4e}, 8<<10)...)
	sum := sha256.Sum256(body)
	bound := l.binding(b.Name)
	record := func(name string, size int64, sha string) *v1alpha1.EvidenceAttachment {
		a := &v1alpha1.EvidenceAttachment{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.EvidenceAttachmentSpec{
			Document: v1alpha1.AttachmentDocument{Title: title, MediaType: "application/pdf", Size: size, SHA256: sha},
			Source:   v1alpha1.AttachmentSource{Issuer: issuer, URL: "https://audit.invalid/chart-report"},
			Validity: v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)), ValidUntil: metav1.NewTime(time.Now().Add(365 * 24 * time.Hour).UTC().Truncate(time.Second))},
			Associations: []v1alpha1.AttachmentAssociation{{Binding: v1alpha1.ExactBindingReference{Name: b.Name, UID: string(bound.UID)}, CatalogDigest: catalog.CatalogDigest,
				Controls: []v1alpha1.AttachmentControl{{ID: "pe-3", Statements: []string{"pe-3_smt.a"}}}}},
			Scope: v1alpha1.AttachmentScope{Description: "DC North hall A"}}}
		if err := l.c.Create(l.ctx, a); err != nil {
			t.Fatal(err)
		}
		l.eventually(name+" pinned", func() (bool, string) {
			_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(a), a)
			return a.Status.Storage != nil && a.Status.Storage.Destination != nil, toJSON(a.Status)
		})
		return a
	}
	a := record(recordName, int64(len(body)), "sha256:"+hex.EncodeToString(sum[:]))
	big := record(bigName, limit+1, "sha256:"+strings.Repeat("ab", 32))
	if a.Spec.RegisteredBy == nil || a.Spec.RegisteredBy.Username == "" {
		t.Fatalf("registrant admission did not record the registrant: %+v", a.Spec.RegisteredBy)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	hc := &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "konstapel-download.konstapel-system.svc"}}}
	local := l.portForward(ns, "svc/konstapel-download", 443)
	upload := func(uid string, doc []byte) (int, []byte) {
		req, _ := http.NewRequestWithContext(l.ctx, http.MethodPut, "https://"+local+"/v1/evidenceattachments/"+uid+"/upload", bytes.NewReader(doc))
		req.Header.Set("Authorization", "Bearer "+l.token(ns, "hs-uploader", downloadAudience))
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, out
	}
	if code, out := upload(string(big.UID), bytes.Repeat([]byte{0x41}, limit+1)); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("upload above download.attachments.maxBytes: %d %s", code, out)
	}
	if code, out := upload(string(a.UID), body); code != http.StatusOK {
		t.Fatalf("upload through the installed service: %d %s", code, out)
	}
	l.eventually("document committed, available and validly associated", func() (bool, string) {
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(a), a)
		ok := a.Status.Storage.Commitment != nil && a.Status.Content != nil && a.Status.Content.State == v1alpha1.ContentAvailable &&
			len(a.Status.Associations) == 1 && a.Status.Associations[0].State == v1alpha1.AssociationValid
		return ok, toJSON(a.Status)
	})
	if got := a.Status.Storage.Commitment.Retention.Duration; got != 26*time.Hour {
		t.Fatalf("commitment retention %s, chart value 26h", got)
	}
	l.record("uploaded", map[string]any{"oversized": http.StatusRequestEntityTooLarge, "retention": a.Status.Storage.Commitment.Retention.Duration.String()})

	// platformRun creates a manual platform run and waits for its commit.
	platformRun := func(name string) *v1alpha1.AssessmentRun {
		r := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}, Scope: v1alpha1.RunScopeBinding}}
		if err := l.c.Create(l.ctx, r); err != nil {
			t.Fatal(err)
		}
		l.eventually(name+" published", func() (bool, string) {
			r = run(name)
			return committed(r), toJSON(r)
		})
		return r
	}
	download := func(r *v1alpha1.AssessmentRun) (int, []byte) {
		return fetch(t, hc, "https://"+local+"/v1/assessmentruns/"+string(r.UID)+"/download", l.token(ns, "hs-operator", downloadAudience))
	}
	unpack := func(archive []byte) (string, *publication.Descriptor, *coverage.Report) {
		dir := t.TempDir()
		if err := publication.Extract(bytes.NewReader(archive), dir); err != nil {
			t.Fatal(err)
		}
		d, err := s3store.ValidatePackage(dir)
		if err != nil {
			t.Fatalf("package does not validate: %v", err)
		}
		raw, _ := os.ReadFile(filepath.Join(dir, coverage.JSONFile))
		rep, err := coverage.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return dir, &d, rep
	}

	// 5. A reader that isn't this build: the download Deployment declares
	// another image. Its surge replica never starts (pull policy Never), so
	// the current replicas keep serving, as during a rollout.
	dep := &appsv1.Deployment{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: "konstapel-download"}, dep); err != nil {
		t.Fatal(err)
	}
	const other = "registry.invalid/konstapel-older-reader@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	setReaderImage := func(img string) {
		l.eventually("download Deployment image "+img, func() (bool, string) {
			if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(dep), dep); err != nil {
				return false, err.Error()
			}
			dep.Spec.Template.Spec.Containers[0].Image = img
			if err := l.c.Update(l.ctx, dep); err != nil {
				return false, err.Error()
			}
			return true, ""
		})
	}
	readerImages := func() []string {
		var list corev1.PodList
		_ = l.c.List(l.ctx, &list, client.InNamespace(ns), client.MatchingLabels{"app.kubernetes.io/component": "download"})
		var out []string
		for _, p := range list.Items {
			out = append(out, p.Spec.Containers[0].Image)
		}
		return out
	}
	setReaderImage(other)
	t.Cleanup(func() { setReaderImage(image) })
	l.eventually("a reader replica with another image exists", func() (bool, string) {
		imgs := readerImages()
		return slices.Contains(imgs, other) && slices.Contains(imgs, image), fmt.Sprint(imgs)
	})
	gated := platformRun("hs-audit-gated")
	code, archive := download(gated)
	if code != http.StatusOK {
		t.Fatalf("operator download of the gated run: %d (%d bytes)", code, len(archive))
	}
	_, d, rep := unpack(archive)
	se := rep.SupportingEvidence
	if d.Protected() || se.Integration != coverage.IntegrationUnavailable || se.Reason != reasonReadersUnverified || len(se.Entries) != 0 {
		t.Fatalf("gated package: protection %+v supporting %+v", d.Protection, se)
	}
	for _, leak := range [][]byte{[]byte(title), []byte(issuer), []byte("%PDF"), []byte("supporting-evidence/")} {
		if bytes.Contains(archive, leak) {
			t.Fatalf("gated package contains %q", leak)
		}
	}
	l.record("readers-unverified", map[string]any{"run": gated.Name, "protected": false, "integration": se.Integration, "reason": se.Reason, "readerImages": readerImages()})

	// 6. The readers are this build again: the next platform run carries
	// the verified copy, protected by the document-read check.
	setReaderImage(image)
	l.eventually("every reader replica runs the controller's image", func() (bool, string) {
		imgs := readerImages()
		if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(dep), dep); err != nil {
			return false, err.Error()
		}
		s := dep.Status
		done := s.ObservedGeneration >= dep.Generation && s.UpdatedReplicas == *dep.Spec.Replicas && s.Replicas == s.UpdatedReplicas && s.AvailableReplicas == s.UpdatedReplicas
		return done && !slices.Contains(imgs, other), fmt.Sprintf("%v %+v", imgs, s)
	})
	open := platformRun("hs-audit-verified")
	if code, out := download(open); code != http.StatusForbidden || bytes.Contains(out, []byte(title)) {
		// Never log the body: it may be the protected package.
		t.Fatalf("run access alone reached the protected package: %d (%d bytes)", code, len(out))
	}
	l.bindSA("hs-operator-documents", ns, "hs-operator", shipped("konstapel-evidence-attachment-downloader"), "")
	l.eventually("document read granted", func() (bool, string) {
		code, archive = download(open)
		return code == http.StatusOK, http.StatusText(code)
	})
	dir, d, rep := unpack(archive)
	copyBytes, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(coverage.SupportingCopyPath(string(a.UID)))))
	if err != nil || !bytes.Equal(copyBytes, body) || !d.Protected() {
		t.Fatalf("verified package copy (%v) or protection %+v", err, d.Protection)
	}
	var entry *coverage.SupportingRecord
	for i := range rep.SupportingEvidence.Entries {
		if rep.SupportingEvidence.Entries[i].Source == string(a.UID) {
			entry = &rep.SupportingEvidence.Entries[i]
		}
	}
	if rep.SupportingEvidence.Integration != coverage.IntegrationAvailable || entry == nil || entry.Access != coverage.AccessIncluded {
		t.Fatalf("verified package supporting %+v", rep.SupportingEvidence)
	}
	l.record("readers-verified", map[string]any{"run": open.Name, "protected": d.Protected(), "roles": d.Protection.Roles, "copyBytes": len(copyBytes), "withoutDocumentRead": http.StatusForbidden})
}
