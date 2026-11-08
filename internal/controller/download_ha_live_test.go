//go:build live

package controller

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// followerDownloads exercises the installed download replicas without the
// controller that produced the evidence (add-controller-high-availability
// 3.3, 3.4). Every check runs against each download pod separately, so no
// session affinity, leader proxy or leader-local file can satisfy it.
// operatorCRB grants the platform operator SA; roots trust the current
// download certificate.
func (l *live) followerDownloads(ns string, b *v1alpha1.ComplianceBinding, run *v1alpha1.AssessmentRun, operator string, operatorCRB *rbacv1.ClusterRoleBinding, roots *x509.CertPool, dest *v1alpha1.EvidenceDestination, credentials *corev1.Secret) {
	t := l.t
	t.Helper()
	const team = "hi-team"
	// A team requests its namespace's evidence while the controller runs.
	l.setNamespace(team, "hi-production")
	reader := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: team, Name: "evidence-reader"}}
	readerRB := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: team, Name: "evidence-reader"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-assessment-requester"},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: team, Name: reader.Name}}}
	req := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: team, Name: "nightly"},
		Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}}}
	for _, o := range []client.Object{reader, readerRB, req} {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: team}}) })
	var teamRun *v1alpha1.AssessmentRun
	l.eventually("team request published", func() (bool, string) {
		got := &v1alpha1.AssessmentRequest{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(req), got)
		req.UID = got.UID
		if got.Status.Phase != v1alpha1.RequestCompleted || got.Status.Run == nil {
			return false, toJSON(got.Status)
		}
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: got.Status.Run.Name}, r); err != nil || r.Status.Publication == nil {
			return false, fmt.Sprint(err)
		}
		teamRun = r
		return true, ""
	})

	// The pods that produced and published the evidence are removed: no
	// controller runs at all while the download replicas serve.
	producer := run.Status.Publication
	l.scaleDeployment(ns, "konstapel-controller", 0)
	l.eventually("controller pods gone", func() (bool, string) {
		var pods corev1.PodList
		_ = l.c.List(l.ctx, &pods, client.InNamespace(ns), client.MatchingLabels{"app.kubernetes.io/component": "controller"})
		return len(pods.Items) == 0, fmt.Sprint(len(pods.Items))
	})
	defer l.scaleDeployment(ns, "konstapel-controller", 2)

	replicas := l.downloadPods(ns)
	clients := map[string]string{}
	for name := range replicas {
		clients[name] = l.portForward(ns, "pod/"+name, 8443)
	}
	hc := &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "konstapel-download.konstapel-system.svc"}}}
	runURL := func(addr string, r *v1alpha1.AssessmentRun) string {
		return "https://" + addr + "/v1/assessmentruns/" + string(r.UID) + "/download"
	}
	teamURL := func(addr, uid string) string {
		return "https://" + addr + "/v1/namespaces/" + team + "/assessmentrequests/nightly/download?uid=" + uid
	}
	each := func(what string, f func(pod, addr string) (bool, string)) {
		l.eventually(what+" on every download replica", func() (bool, string) {
			for pod, addr := range clients {
				if ok, detail := f(pod, addr); !ok {
					return false, pod + ": " + detail
				}
			}
			return true, ""
		})
	}
	expect := func(code int, url, tok, sha string) func(string, string) (bool, string) {
		return func(_, addr string) (bool, string) {
			got, body := fetch(t, hc, strings.Replace(url, "ADDR", addr, 1), tok)
			if got != code {
				return false, fmt.Sprintf("%d %s", got, body)
			}
			if sha != "" && fmt.Sprintf("%x", sha256.Sum256(body)) != sha {
				return false, "package digest differs from the receipt"
			}
			return true, ""
		}
	}
	opTok := func() string { return l.token(ns, operator, downloadAudience) }
	teamTok := func() string { return l.token(team, reader.Name, downloadAudience) }
	runSHA, teamSHA := producer.PackageSHA256, teamRun.Status.Publication.PackageSHA256

	// 1. Same verified packages from every replica.
	each("platform package", expect(http.StatusOK, runURL("ADDR", run), opTok(), runSHA))
	each("team package", expect(http.StatusOK, teamURL("ADDR", string(req.UID)), teamTok(), teamSHA))
	l.record("follower-download", map[string]any{"replicas": len(clients), "controllerReplicas": 0, "runSha256": runSHA, "teamSha256": teamSHA})

	// 2. Current authorization on every retry: revoking a grant denies the
	// next request on each replica, and restoring it allows it again.
	if err := l.c.Delete(l.ctx, operatorCRB); err != nil {
		t.Fatal(err)
	}
	each("operator revocation", expect(http.StatusForbidden, runURL("ADDR", run), opTok(), ""))
	if err := l.c.Delete(l.ctx, readerRB); err != nil {
		t.Fatal(err)
	}
	each("team revocation", expect(http.StatusForbidden, teamURL("ADDR", string(req.UID)), teamTok(), ""))
	for _, o := range []client.Object{operatorCRB, readerRB} {
		o.SetResourceVersion("")
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	each("restored platform grant", expect(http.StatusOK, runURL("ADDR", run), opTok(), runSHA))
	each("restored team grant", expect(http.StatusOK, teamURL("ADDR", string(req.UID)), teamTok(), teamSHA))
	each("wrong audience", expect(http.StatusUnauthorized, runURL("ADDR", run), l.token(ns, operator, "another-audience"), ""))
	l.record("follower-authorization", map[string]any{"revoked": []string{"platform", "team"}, "restored": true})

	// 3. Credential rotation: the destination points at a rotated Secret and
	// the old one is deleted; a missing Secret is a visible failure on
	// every replica, never a fallback; both serve with the rotated Secret.
	rotated := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: credentials.Name + "-rotated"}, Data: credentials.Data}
	setCredentials := func(name string) {
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			got := &v1alpha1.EvidenceDestination{}
			if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(dest), got); err != nil {
				return err
			}
			got.Spec.S3.CredentialSecret.Name = name
			return l.c.Update(l.ctx, got)
		}); err != nil {
			t.Fatal(err)
		}
	}
	setCredentials(credentials.Name + "-missing")
	each("missing credentials", expect(http.StatusServiceUnavailable, runURL("ADDR", run), opTok(), ""))
	if err := l.c.Create(l.ctx, rotated); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, rotated) })
	setCredentials(rotated.Name)
	if err := l.c.Delete(l.ctx, credentials); err != nil {
		t.Fatal(err)
	}
	each("rotated credentials", expect(http.StatusOK, runURL("ADDR", run), opTok(), runSHA))
	l.record("follower-credentials", map[string]any{"rotatedTo": rotated.Name})

	// 4. Backend failure is the defined rejection on every replica, and
	// recovery needs no controller.
	if out, err := exec.Command("docker", "pause", l.s3Container).CombinedOutput(); err != nil {
		t.Fatalf("pause S3: %v %s", err, out)
	}
	paused := true
	defer func() {
		if paused {
			_ = exec.Command("docker", "unpause", l.s3Container).Run()
		}
	}()
	// The S3 client bounds each request (s3store.RequestTimeout, three
	// attempts), so the rejection arrives within that bound rather than
	// within an ordinary client timeout: wait for it on both replicas.
	slow := &http.Client{Timeout: 4 * time.Minute, Transport: hc.Transport}
	outage := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	tok := opTok()
	for pod, addr := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			begin := time.Now()
			req, _ := http.NewRequest(http.MethodGet, runURL(addr, run), nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			result := ""
			if resp, err := slow.Do(req); err != nil {
				result = err.Error()
			} else {
				_ = resp.Body.Close()
				result = fmt.Sprintf("%d after %s", resp.StatusCode, time.Since(begin).Round(time.Second))
				if resp.StatusCode == http.StatusServiceUnavailable {
					result = "ok " + result
				}
			}
			mu.Lock()
			outage[pod] = result
			mu.Unlock()
		}()
	}
	wg.Wait()
	for pod, result := range outage {
		if !strings.HasPrefix(result, "ok ") {
			t.Fatalf("%s during the backend outage: %s", pod, result)
		}
	}
	l.record("follower-backend-outage", map[string]any{"results": outage})
	if out, err := exec.Command("docker", "unpause", l.s3Container).CombinedOutput(); err != nil {
		t.Fatalf("unpause S3: %v %s", err, out)
	}
	paused = false
	each("backend recovered", expect(http.StatusOK, runURL("ADDR", run), opTok(), runSHA))

	// 5. Namespace-UID isolation: a recreated namespace with the same name,
	// account, grant and request reaches none of the old namespace's
	// evidence, by the old or the new request UID.
	oldUID := string(req.UID)
	if err := l.c.Delete(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: team}}); err != nil {
		t.Fatal(err)
	}
	l.eventually("team namespace deleted", func() (bool, string) {
		err := l.c.Get(l.ctx, client.ObjectKey{Name: team}, &corev1.Namespace{})
		return apierrors.IsNotFound(err), fmt.Sprint(err)
	})
	l.setNamespace(team, "hi-production")
	for _, o := range []client.Object{reader, readerRB, req} {
		o.SetResourceVersion("")
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	// Both answer like a denial: the download server is no existence
	// oracle, even for a caller holding a valid grant in the namespace.
	each("old request UID in the recreated namespace", expect(http.StatusForbidden, teamURL("ADDR", oldUID), teamTok(), ""))
	each("new request UID without its own evidence", expect(http.StatusForbidden, teamURL("ADDR", string(req.UID)), teamTok(), ""))
	each("old run still served to the platform operator", expect(http.StatusOK, runURL("ADDR", teamRun), opTok(), teamSHA))
	l.record("follower-namespace-isolation", map[string]any{"oldRequestUID": oldUID, "newRequestUID": string(req.UID)})

	// No replica logged credential or key material.
	tok = opTok()
	for pod := range clients {
		out, err := exec.Command("kubectl", "--kubeconfig", os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"), "--context", os.Getenv("KONSTAPEL_LIVE_CONTEXT"),
			"-n", ns, "logs", pod).CombinedOutput()
		if err != nil {
			t.Fatalf("logs %s: %v %s", pod, err, out)
		}
		for _, secret := range []string{l.s3Secret, "PRIVATE KEY", tok[len(tok)-32:]} {
			if strings.Contains(string(out), secret) {
				t.Fatalf("download replica %s logged secret material", pod)
			}
		}
	}
	l.assertNoRestarts(ns, replicas)
}

// scaleDeployment sets a Deployment's replicas and waits for them.
func (l *live) scaleDeployment(ns, name string, replicas int32) {
	l.t.Helper()
	d := &appsv1.Deployment{}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: name}, d); err != nil {
			return err
		}
		d.Spec.Replicas = &replicas
		return l.c.Update(l.ctx, d)
	}); err != nil {
		l.t.Fatal(err)
	}
	l.eventually(name+" scaled", func() (bool, string) {
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(d), d)
		return d.Status.ReadyReplicas == replicas && d.Status.Replicas == replicas, toJSON(d.Status)
	})
}
