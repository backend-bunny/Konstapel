//go:build live

package controller

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const metricsServiceName = "konstapel-controller-metrics.konstapel-system.svc"

// apiToken requests a bound token for the API server's own audience, the
// kind of credential Prometheus presents from a projected token.
func (l *live) apiToken(ns, sa string) string {
	tr := &authnv1.TokenRequest{}
	if err := l.c.SubResource("token").Create(l.ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: sa}}, tr); err != nil {
		l.t.Fatal(err)
	}
	return tr.Status.Token
}

// TestLiveHelmMetrics installs the runtime chart with metrics enabled
// (cert-manager TLS, a reader ServiceAccount in another namespace) and
// scrapes the controller through its Service with real TokenReview and
// SubjectAccessReview: authorized, unauthorized and anonymous scrapes,
// verified server identity, revocation within the pinned cache bound, and
// a rotated certificate served without a restart.
func TestLiveHelmMetrics(t *testing.T) {
	image := os.Getenv("KONSTAPEL_LIVE_IMAGE")
	repo, digest, ok := strings.Cut(image, "@")
	if !ok {
		t.Fatalf("KONSTAPEL_LIVE_IMAGE=%q is not repository@digest", image)
	}
	if os.Getenv("KONSTAPEL_LIVE_CERT_MANAGER") != "true" {
		t.Fatal("the metrics test needs cert-manager (charts acceptance group)")
	}
	l := newLive(t)
	const ns = "konstapel-system"
	for _, n := range []string{"metrics-monitoring", "metrics-team"} {
		_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
	}
	for _, sa := range []client.ObjectKey{{Namespace: "metrics-monitoring", Name: "prometheus"}, {Namespace: "metrics-team", Name: "exceptions"}} {
		if err := l.c.Create(l.ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: sa.Namespace, Name: sa.Name}}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, n := range []string{"metrics-monitoring", "metrics-team"} {
			_ = l.c.Delete(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
		}
	})
	if out, err := l.helm("install", "konstapel-crds", chartArchive(t, "konstapel-crds"), "--namespace", ns, "--create-namespace", "--wait"); err != nil {
		t.Fatalf("install CRD chart: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = l.helm("uninstall", "konstapel-crds", "--namespace", ns) })
	if out, err := l.helm(append([]string{"install", "konstapel", chartArchive(t, "konstapel"), "--namespace", ns, "--wait", "--timeout", "5m",
		"--set", "download.enabled=false", "--set", "metrics.enabled=true",
		"--set", "metrics.readers[0].namespace=metrics-monitoring", "--set", "metrics.readers[0].name=prometheus"}, imageValues(repo, digest)...)...); err != nil {
		t.Fatalf("install runtime chart: %v\n%s\n%s", err, out, l.podDiagnostics(ns))
	}
	t.Cleanup(func() { _, _ = l.helm("uninstall", "konstapel", "--namespace", ns, "--wait") })

	tlsSecret := &corev1.Secret{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: "konstapel-controller-metrics-tls"}, tlsSecret); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(tlsSecret.Data["ca.crt"]) {
		t.Fatal("no CA in the metrics TLS Secret")
	}
	addr := l.portForward(ns, "service/konstapel-controller-metrics", 443)
	scrape := func(serverName, token string, roots *x509.CertPool) (int, string, error) {
		c := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: serverName}}}
		req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/metrics", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := c.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), nil
	}
	reader, team := l.apiToken("metrics-monitoring", "prometheus"), l.apiToken("metrics-team", "exceptions")

	// 1. The monitoring identity scrapes the contract and the retained
	// upstream collectors over verified TLS.
	var body string
	l.eventually("authorized scrape", func() (bool, string) {
		code, b, err := scrape(metricsServiceName, reader, roots)
		body = b
		return err == nil && code == http.StatusOK, toJSON(map[string]any{"code": code, "err": err})
	})
	for _, want := range []string{"konstapel_observation_enabled", "konstapel_observation_ready", "konstapel_operation_attempts_total", "controller_runtime_reconcile_total", "process_cpu_seconds_total"} {
		if !strings.Contains(body, want) {
			t.Fatalf("scrape lacks %s", want)
		}
	}
	// 2. A namespace identity and an anonymous client get nothing.
	if code, _, err := scrape(metricsServiceName, team, roots); err != nil || code != http.StatusForbidden {
		t.Fatalf("namespace identity: %d %v", code, err)
	}
	if code, _, err := scrape(metricsServiceName, "", roots); err != nil || code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d %v", code, err)
	}
	// 3. The client verifies the server: another name or CA fails.
	if _, _, err := scrape("konstapel-download.konstapel-system.svc", reader, roots); err == nil {
		t.Fatal("the metrics certificate verified for another service name")
	}
	if _, _, err := scrape(metricsServiceName, reader, x509.NewCertPool()); err == nil {
		t.Fatal("an untrusted CA was accepted")
	}
	l.record("scrapes", map[string]any{"authorized": 200, "namespace": 403, "anonymous": 401})

	// 4. A rotated certificate is served without a restart: cert-manager
	// reissues when the Secret is deleted.
	serial := func() (string, error) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, &tls.Config{RootCAs: roots, ServerName: metricsServiceName})
		if err != nil {
			return "", err
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.String(), nil
	}
	before, err := serial()
	if err != nil {
		t.Fatal(err)
	}
	var pods corev1.PodList
	_ = l.c.List(l.ctx, &pods, client.InNamespace(ns), client.MatchingLabels{"app.kubernetes.io/component": "controller"})
	restarts := map[string]int32{}
	for _, p := range pods.Items {
		restarts[p.Name] = p.Status.ContainerStatuses[0].RestartCount
	}
	if err := l.c.Delete(l.ctx, tlsSecret); err != nil {
		t.Fatal(err)
	}
	rotated := time.Now()
	l.eventually("rotated metrics certificate served", func() (bool, string) {
		// The CA is unchanged (the chart's CA issues both), so the old
		// roots verify the new leaf.
		s, err := serial()
		return err == nil && s != before, toJSON(map[string]any{"serial": s, "err": err})
	})
	l.record("rotation", map[string]any{"seconds": time.Since(rotated).Seconds()})
	_ = l.c.List(l.ctx, &pods, client.InNamespace(ns), client.MatchingLabels{"app.kubernetes.io/component": "controller"})
	for _, p := range pods.Items {
		if r, ok := restarts[p.Name]; !ok || p.Status.ContainerStatuses[0].RestartCount != r {
			t.Fatalf("controller pod %s restarted or was replaced for the rotation", p.Name)
		}
	}
	if code, _, err := scrape(metricsServiceName, reader, roots); err != nil || code != http.StatusOK {
		t.Fatalf("scrape after rotation: %d %v", code, err)
	}

	// 5. Revocation: removing the reader binding stops scraping within the
	// pinned filter's allow-cache TTL (5 minutes) plus a margin; a cached
	// answer may allow it until then, never longer.
	if err := l.c.Delete(l.ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "konstapel-metrics-reader"}}); err != nil {
		t.Fatal(err)
	}
	revoked := time.Now()
	deadline := revoked.Add(5*time.Minute + 45*time.Second)
	for {
		code, _, err := scrape(metricsServiceName, reader, roots)
		if err == nil && code == http.StatusForbidden {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("revoked identity still scrapes %s after revocation: %d %v", time.Since(revoked), code, err)
		}
		time.Sleep(5 * time.Second)
	}
	l.record("revocation", map[string]any{"seconds": time.Since(revoked).Seconds(), "boundSeconds": 300})
}
