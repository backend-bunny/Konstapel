//go:build live

package controller

// Live evidence download (add-s3-evidence-publishing task 4.5): the manager
// publishes a team request's package to a test-owned S3-compatible service
// through the real s3store publisher, and the download service serves it
// to a namespace service account authorized by the cluster's own
// TokenReview and SubjectAccessReview. The same credentials cannot fetch the
// full-binding run or another namespace, and removing the RoleBinding stops
// new downloads. Run through scripts/targeting-live.sh.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
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
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/download"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

const downloadAudience = "konstapel-download"

// startS3 runs the pinned test-owned S3 service on a loopback port and
// returns a ready publisher. The container is always removed.
func startS3(t *testing.T, l *live) *s3store.Publisher {
	image := os.Getenv("KONSTAPEL_S3_IMAGE")
	if image == "" {
		t.Fatal("KONSTAPEL_S3_IMAGE is required (scripts/runtime.env)")
	}
	secret := func() string { b := make([]byte, 12); _, _ = rand.Read(b); return hex.EncodeToString(b) }
	access, key, name := secret(), secret(), "konstapel-live-s3-"+secret()[:8]
	if out, err := exec.Command("docker", "run", "-d", "--name", name, "--label", liveContainerLabel(), "-p", "127.0.0.1::9000",
		"-e", "RUSTFS_ACCESS_KEY="+access, "-e", "RUSTFS_SECRET_KEY="+key, image, "/data").CombinedOutput(); err != nil {
		t.Fatalf("start S3 service: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	l.s3Container = name
	l.s3Access, l.s3Secret = access, key
	out, err := exec.Command("docker", "port", name, "9000/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	port := strings.TrimSpace(strings.Split(strings.Split(string(out), "\n")[0], ":")[1])
	l.s3Endpoint = "http://127.0.0.1:" + port
	d := s3store.Destination{ID: "live", Endpoint: "http://127.0.0.1:" + port, Bucket: "konstapel-live", Region: "us-east-1",
		Prefix: "konstapel-test/live", Addressing: s3store.AddressingPath, CredentialSecret: &s3store.SecretRef{Name: "live"}, DevelopmentFixture: true}
	c, err := s3store.NewClient(l.ctx, d, &s3store.StaticCredentials{AccessKeyID: access, SecretAccessKey: key})
	if err != nil {
		t.Fatal(err)
	}
	l.eventually("S3 service bucket", func() (bool, string) {
		_, err := c.CreateBucket(l.ctx, &s3.CreateBucketInput{Bucket: aws.String(d.Bucket)})
		return err == nil, ""
	})
	p := &s3store.Publisher{Client: c, Dest: d}
	if _, err := p.Ready(l.ctx); err != nil {
		t.Fatal(err)
	}
	return p
}

func (l *live) applyFile(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		l.t.Fatal(err)
	}
	for _, doc := range strings.Split(string(raw), "\n---") {
		cr := &rbacv1.ClusterRole{}
		if err := yaml.Unmarshal([]byte(doc), cr); err != nil || cr.Kind != "ClusterRole" {
			continue
		}
		if err := l.c.Create(l.ctx, cr); err != nil && !apierrors.IsAlreadyExists(err) {
			l.t.Fatal(err)
		}
	}
}

func (l *live) token(ns, sa, audience string) string {
	tr := &authnv1.TokenRequest{Spec: authnv1.TokenRequestSpec{Audiences: []string{audience}}}
	if err := l.c.SubResource("token").Create(l.ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: sa}}, tr); err != nil {
		l.t.Fatal(err)
	}
	return tr.Status.Token
}

func fetch(t *testing.T, c *http.Client, url, token string) (int, []byte) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func untar(t *testing.T, archive []byte, dir string) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		p := filepath.Join(dir, filepath.Clean("/"+h.Name))
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		b, _ := io.ReadAll(tr)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLiveEvidenceDownload(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	ConfigureAssessments(AssessmentRuntime{Publisher: pub, StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: time.Minute, Workers: 2,
		Ready: func(ctx context.Context) error { _, err := pub.Ready(ctx); return err }})
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	l.applyFile("../../config/rbac/assessment-requester.yaml")
	l.applyFile("../../config/rbac/assessment-operator.yaml")

	l.setNamespace("dl-team", "dl-production")
	l.setNamespace("dl-other", "dl-production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "dl-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("dl-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "dl-production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "30s"}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "dl-team"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "dl-team", Name: "evidence-reader"}}
	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "dl-team", Name: "evidence-reader"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-assessment-requester"},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "dl-team", Name: sa.Name}}}
	req := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "dl-team", Name: "nightly"},
		Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}}}
	t.Cleanup(func() {
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(l.ctx, &runs)
		for i := range runs.Items {
			if runs.Items[i].Spec.BindingRef.Name == b.Name {
				_ = l.c.Delete(l.ctx, &runs.Items[i])
			}
		}
		for _, o := range []client.Object{req, rb, sa, pod, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.Name}}, p} {
			_ = l.c.Delete(l.ctx, o)
		}
		l.eventually("download test policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
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
	l.waitReady(b.Name, 2)

	run := func(name string) *v1alpha1.AssessmentRun {
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, r); err != nil {
			return nil
		}
		return r
	}
	var scheduled string
	l.eventually("scheduled run published to S3", func() (bool, string) {
		got := l.binding(b.Name)
		if got.Status.Assessment == nil || got.Status.Assessment.Schedule == nil {
			return false, toJSON(got.Status.Assessment)
		}
		s := got.Status.Assessment.Schedule
		if s.ActiveRun != nil {
			scheduled = s.ActiveRun.Name
		}
		r := run(scheduled)
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted && r.Status.Publication != nil && s.ActiveRun == nil, toJSON(got.Status.Assessment)
	})
	if err := l.c.Create(l.ctx, req); err != nil {
		t.Fatal(err)
	}
	var st v1alpha1.AssessmentRequestStatus
	l.eventually("team request published to S3", func() (bool, string) {
		got := &v1alpha1.AssessmentRequest{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(req), got)
		st = got.Status
		req.UID = got.UID
		return st.Phase == v1alpha1.RequestCompleted && st.ArtifactRef != "", toJSON(st)
	})
	l.record("published", map[string]any{"scheduled": scheduled, "teamRun": st.Run.Name, "artifactRef": st.ArtifactRef})

	srv := &download.Server{Reader: l.c, Reviews: download.KubeReviewer{Client: l.c, Audience: downloadAudience}, Publisher: pub, TempDir: t.TempDir()}
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()
	hc := ts.Client()
	teamURL := ts.URL + "/v1/namespaces/dl-team/assessmentrequests/nightly/download?uid=" + string(req.UID)
	tok := l.token("dl-team", sa.Name, downloadAudience)

	// 1. The team's own credentials download the complete namespace package.
	code, body := fetch(t, hc, teamURL, tok)
	if code != http.StatusOK {
		t.Fatalf("team download: %d %s", code, body)
	}
	dir := t.TempDir()
	untar(t, body, dir)
	d, err := publication.LoadDescriptor(dir)
	ns := &corev1.Namespace{}
	_ = l.c.Get(l.ctx, client.ObjectKey{Name: "dl-team"}, ns)
	if err != nil || d.Scope.Kind != publication.ScopeNamespace || d.Scope.Request == nil || d.Scope.Request.NamespaceUID != string(ns.UID) {
		t.Fatalf("downloaded package scope: %+v %v", d.Scope, err)
	}
	if err := publication.VerifyDir(dir, d); err != nil {
		t.Fatal(err)
	}
	// The publisher's full validation: descriptor inventory, OSCAL schemas
	// and reference closure, engine-policy provenance, namespace projection.
	if _, err := s3store.ValidatePackage(dir); err != nil {
		t.Fatalf("downloaded package does not validate: %v", err)
	}
	if strings.Contains(string(body), "dl-other") {
		t.Fatal("namespace package mentions a sibling namespace")
	}
	l.record("team-download", map[string]any{"bytes": len(body), "files": len(d.Files), "completeness": d.Evidence.Completeness})

	// 2. The same credentials cannot reach anything broader.
	full := run(scheduled)
	for what, url := range map[string]string{
		"full-binding run":  ts.URL + "/v1/assessmentruns/" + string(full.UID) + "/download",
		"own run, platform": ts.URL + "/v1/assessmentruns/" + st.Run.UID + "/download",
		"sibling namespace": ts.URL + "/v1/namespaces/dl-other/assessmentrequests/nightly/download?uid=" + string(req.UID),
		"wrong request uid": ts.URL + "/v1/namespaces/dl-team/assessmentrequests/nightly/download?uid=00000000-0000-0000-0000-000000000000",
	} {
		if code, body := fetch(t, hc, url, tok); code != http.StatusForbidden {
			t.Fatalf("%s: %d %s", what, code, body)
		}
	}
	// A token for the API server's default audience is refused.
	if code, _ := fetch(t, hc, teamURL, l.token("dl-team", sa.Name, "https://kubernetes.default.svc.cluster.local")); code != http.StatusUnauthorized {
		t.Fatalf("wrong audience: %d", code)
	}
	l.record("broader-denied", map[string]any{})

	// 3. Revoking the RoleBinding stops new downloads.
	if err := l.c.Delete(l.ctx, rb); err != nil {
		t.Fatal(err)
	}
	l.eventually("revocation denies", func() (bool, string) {
		code, body := fetch(t, hc, teamURL, tok)
		return code == http.StatusForbidden, string(body)
	})
	l.record("revoked", map[string]any{})
}
