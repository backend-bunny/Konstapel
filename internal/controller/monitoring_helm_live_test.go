//go:build live

package controller

// Live monitoring acceptance (add-prometheus-observability 3.3, 6.1): a real,
// digest-pinned Prometheus Operator (installed by scripts/acceptance.sh from
// its pinned release bundle) and a Prometheus in another namespace scrape the
// Helm-installed controller through the chart's own ServiceMonitor and load
// its PrometheusRule. Run through scripts/targeting-live.sh (charts group).

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	monitoringLabel = "monitoring-acceptance"
	// The pool Prometheus names for endpoint 0 of the chart's ServiceMonitor.
	chartPool = "serviceMonitor/konstapel-system/konstapel-controller/0"
)

type promTarget struct {
	Pool      string            `json:"scrapePool"`
	Health    string            `json:"health"`
	LastError string            `json:"lastError"`
	Labels    map[string]string `json:"labels"`
}

// promGet queries the Prometheus HTTP API behind addr.
func promGet(addr, path string, into any) error {
	c := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{}}}
	resp, err := c.Get("http://" + addr + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %d %s", path, resp.StatusCode, b)
	}
	var env struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b, &env); err != nil || env.Status != "success" {
		return fmt.Errorf("%s: %v %s", path, err, b)
	}
	return json.Unmarshal(env.Data, into)
}

func promTargets(addr string) ([]promTarget, error) {
	var d struct {
		Active []promTarget `json:"activeTargets"`
	}
	err := promGet(addr, "/api/v1/targets?state=active", &d)
	return d.Active, err
}

func poolTargets(all []promTarget, pool string) (out []promTarget) {
	for _, t := range all {
		if t.Pool == pool {
			out = append(out, t)
		}
	}
	return out
}

// waitFor polls f until it reports success; the Operator, an image pull and a
// configuration reload make these waits longer than eventually's.
func (l *live) waitFor(what string, limit time.Duration, f func() (bool, string)) time.Duration {
	l.t.Helper()
	start, last := time.Now(), ""
	for time.Since(start) < limit {
		ok, detail := f()
		if ok {
			return time.Since(start)
		}
		last = detail
		time.Sleep(3 * time.Second)
	}
	l.t.Fatalf("timed out after %s waiting for %s: %s\noperator and monitoring pods:\n%s\n%s", limit, what, last, l.podDiagnostics("default"), l.podDiagnostics("obs-monitoring"))
	return 0
}

func monitoringObject(kind, ns, name string, labels map[string]any, spec map[string]any) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "monitoring.coreos.com/v1", "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": ns}, "spec": spec}}
	if labels != nil {
		_ = unstructured.SetNestedMap(o.Object, labels, "metadata", "labels")
	}
	return o
}

// TestLiveHelmMonitoring installs the runtime chart with the ServiceMonitor
// and PrometheusRule enabled and lets a real Prometheus Operator and a
// Prometheus (in another namespace, running as the listed reader) do the
// scraping: discovery by the chart's ServiceMonitor, a successful verified-TLS
// authenticated scrape queried through the Prometheus API, the starter rules
// loaded, denial for an identity without the reader binding, a wrong server
// name and an undiscovered ServiceMonitor, the Operator's policy against file
// access from ServiceMonitors with the chart's documented Secret fallback,
// revocation seen by the scraper within the pinned cache bound, and teardown.
func TestLiveHelmMonitoring(t *testing.T) {
	image := os.Getenv("KONSTAPEL_LIVE_IMAGE")
	repo, digest, ok := strings.Cut(image, "@")
	if !ok {
		t.Fatalf("KONSTAPEL_LIVE_IMAGE=%q is not repository@digest", image)
	}
	if os.Getenv("KONSTAPEL_LIVE_CERT_MANAGER") != "true" || os.Getenv("KONSTAPEL_LIVE_PROMETHEUS_OPERATOR") != "true" {
		t.Fatal("the monitoring test needs cert-manager and the Prometheus Operator (charts acceptance group)")
	}
	promImage, operatorImage, reloaderImage := os.Getenv("KONSTAPEL_PROMETHEUS_IMAGE"), os.Getenv("KONSTAPEL_PROMETHEUS_OPERATOR_IMAGE"), os.Getenv("KONSTAPEL_PROMETHEUS_CONFIG_RELOADER_IMAGE")
	promRef, _, _ := strings.Cut(promImage, "@")
	promTag := promRef[strings.LastIndex(promRef, ":")+1:]
	if promImage == "" || operatorImage == "" || reloaderImage == "" || !strings.Contains(promImage, "@sha256:") {
		t.Fatalf("pinned images are required: %q %q %q", promImage, operatorImage, reloaderImage)
	}
	l := newLive(t)
	const ns, monNS, teamNS = "konstapel-system", "obs-monitoring", "obs-team"
	for _, n := range []string{monNS, teamNS} {
		_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
	}
	for _, sa := range []client.ObjectKey{{Namespace: monNS, Name: "prometheus"}, {Namespace: teamNS, Name: "scraper"}} {
		if err := l.c.Create(l.ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: sa.Namespace, Name: sa.Name}}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, n := range []string{monNS, teamNS} {
			_ = l.c.Delete(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
		}
	})

	// The Operator is a platform component installed by the harness.
	var running corev1.PodList
	_ = l.c.List(l.ctx, &running, client.InNamespace("default"), client.MatchingLabels{"app.kubernetes.io/name": "prometheus-operator"})
	if len(running.Items) != 1 || running.Items[0].Status.Phase != corev1.PodRunning || running.Items[0].Spec.Containers[0].Image != operatorImage {
		t.Fatalf("the pinned Prometheus Operator %s is not running: %s", operatorImage, l.podDiagnostics("default"))
	}

	if out, err := l.helm("install", "konstapel-crds", chartArchive(t, "konstapel-crds"), "--namespace", ns, "--create-namespace", "--wait"); err != nil {
		t.Fatalf("install CRD chart: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = l.helm("uninstall", "konstapel-crds", "--namespace", ns) })
	values := append([]string{"--namespace", ns, "--set", "download.enabled=false", "--set", "metrics.enabled=true",
		"--set", "metrics.readers[0].namespace=" + monNS, "--set", "metrics.readers[0].name=prometheus",
		"--set", "metrics.serviceMonitor.enabled=true", "--set", "metrics.serviceMonitor.interval=15s",
		"--set", "metrics.serviceMonitor.labels.release=" + monitoringLabel,
		"--set", "metrics.prometheusRule.enabled=true", "--set", "metrics.prometheusRule.labels.release=" + monitoringLabel}, imageValues(repo, digest)...)
	if out, err := l.helm(append([]string{"install", "konstapel", chartArchive(t, "konstapel"), "--wait", "--timeout", "5m"}, values...)...); err != nil {
		t.Fatalf("install runtime chart: %v\n%s\n%s", err, out, l.podDiagnostics(ns))
	}
	t.Cleanup(func() { _, _ = l.helm("uninstall", "konstapel", "--namespace", ns, "--wait") })
	var controllers corev1.PodList
	_ = l.c.List(l.ctx, &controllers, client.InNamespace(ns), client.MatchingLabels{"app.kubernetes.io/component": "controller"})
	replicas := len(controllers.Items)
	if replicas == 0 {
		t.Fatal("no controller pods")
	}

	// A Prometheus in another namespace, running as the ServiceAccount the
	// chart lists in metrics.readers. It discovers only ServiceMonitors and
	// PrometheusRules labelled for this acceptance, in the release namespace.
	discovery := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "obs-prometheus-discovery"}, Rules: []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"services", "endpoints", "pods"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"get", "list", "watch"}}}}
	bind := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "obs-prometheus-discovery"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: discovery.Name},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: monNS, Name: "prometheus"}}}
	for _, o := range []client.Object{discovery, bind} {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
		o := o
		t.Cleanup(func() { _ = l.c.Delete(l.ctx, o) })
	}
	onlyRelease := map[string]any{"matchLabels": map[string]any{"release": monitoringLabel}}
	onlyNS := map[string]any{"matchLabels": map[string]any{"kubernetes.io/metadata.name": ns}}
	prom := monitoringObject("Prometheus", monNS, "acceptance", nil, map[string]any{
		"image": promImage, "version": promTag, "replicas": int64(1), "serviceAccountName": "prometheus",
		"scrapeInterval": "15s", "evaluationInterval": "15s", "retention": "1h",
		"serviceMonitorSelector": onlyRelease, "serviceMonitorNamespaceSelector": onlyNS,
		"ruleSelector": onlyRelease, "ruleNamespaceSelector": onlyNS,
		"resources": map[string]any{"requests": map[string]any{"cpu": "50m", "memory": "200Mi"}},
	})
	// Teardown is owned by this test: the Prometheus (and so its StatefulSet
	// and Pod) must be gone, and a leftover fails the test.
	t.Cleanup(func() {
		_ = l.c.Delete(l.ctx, prom)
		deadline := time.Now().Add(3 * time.Minute)
		for {
			var pods corev1.PodList
			err := l.c.List(l.ctx, &pods, client.InNamespace(monNS))
			if err == nil && len(pods.Items) == 0 {
				l.record("teardown", map[string]any{"prometheusPodsLeft": 0})
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("Prometheus pods left after teardown: %v %v", err, l.podDiagnostics(monNS))
				return
			}
			time.Sleep(3 * time.Second)
		}
	})
	if err := l.c.Create(l.ctx, prom); err != nil {
		t.Fatal(err)
	}
	var opPod corev1.Pod
	_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(&running.Items[0]), &opPod)
	l.record("versions", map[string]any{"operatorImage": operatorImage, "operatorRunning": opPod.Spec.Containers[0].Image,
		"configReloaderImage": reloaderImage, "prometheusImage": promImage, "controllerImage": image, "controllerReplicas": replicas})
	l.waitFor("Prometheus pod", 8*time.Minute, func() (bool, string) {
		var pods corev1.PodList
		_ = l.c.List(l.ctx, &pods, client.InNamespace(monNS), client.MatchingLabels{"app.kubernetes.io/name": "prometheus"})
		return len(pods.Items) == 1 && pods.Items[0].Status.Phase == corev1.PodRunning && pods.Items[0].Status.ContainerStatuses != nil && allReady(pods.Items[0]), toJSON(len(pods.Items))
	})
	promAddr := l.portForward(monNS, "service/prometheus-operated", 9090)
	var build struct {
		Version string `json:"version"`
	}
	l.waitFor("Prometheus API", time.Minute, func() (bool, string) {
		err := promGet(promAddr, "/api/v1/status/buildinfo", &build)
		return err == nil, fmt.Sprint(err)
	})
	l.record("prometheus", map[string]any{"version": build.Version})

	// Hand-made negative fixtures the Operator discovers beside the chart's
	// ServiceMonitor. Each uses the Secret mode, which also works where the
	// Operator denies file access.
	scraper := l.apiToken(teamNS, "scraper")
	tokenSecret := func(name, token string) {
		if err := l.c.Create(l.ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, StringData: map[string]string{"token": token}}); err != nil {
			t.Fatal(err)
		}
	}
	tokenSecret("obs-unauthorized-token", scraper)
	tokenSecret("obs-reader-token", l.apiToken(monNS, "prometheus"))
	endpoint := func(serverName, secret string) map[string]any {
		return map[string]any{"port": "https", "scheme": "https", "path": "/metrics", "interval": "15s", "scrapeTimeout": "10s",
			"tlsConfig":     map[string]any{"serverName": serverName, "ca": map[string]any{"secret": map[string]any{"name": "konstapel-controller-metrics-tls", "key": "ca.crt"}}},
			"authorization": map[string]any{"type": "Bearer", "credentials": map[string]any{"name": secret, "key": "token"}}}
	}
	selector := map[string]any{"matchLabels": map[string]any{"app.kubernetes.io/name": "konstapel", "app.kubernetes.io/instance": "konstapel", "app.kubernetes.io/component": "controller-metrics"}}
	fixture := func(name string, labels map[string]any, ep map[string]any) {
		o := monitoringObject("ServiceMonitor", ns, name, labels, map[string]any{"selector": selector,
			"namespaceSelector": map[string]any{"matchNames": []any{ns}}, "endpoints": []any{ep}})
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(l.ctx, o) })
	}
	labelled := map[string]any{"release": monitoringLabel}
	fixture("obs-unauthorized", labelled, endpoint(metricsServiceName, "obs-unauthorized-token"))
	fixture("obs-wrong-name", labelled, endpoint("konstapel-download.konstapel-system.svc", "obs-reader-token"))
	fixture("obs-unselected", nil, endpoint(metricsServiceName, "obs-reader-token"))
	unselected := monitoringObject("PrometheusRule", ns, "obs-unselected", nil, map[string]any{"groups": []any{map[string]any{
		"name": "obs-unselected", "rules": []any{map[string]any{"alert": "ObsUnselected", "expr": "vector(1)"}}}}})
	if err := l.c.Create(l.ctx, unselected); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, unselected) })

	// 1. Discovery and a successful verified-TLS authenticated scrape of
	// every replica, using the Prometheus Pod's own ServiceAccount token.
	waited := l.waitFor("chart ServiceMonitor targets up", 8*time.Minute, func() (bool, string) {
		all, err := promTargets(promAddr)
		up := 0
		for _, tg := range poolTargets(all, chartPool) {
			if tg.Health == "up" {
				up++
			}
		}
		return err == nil && up == replicas, toJSON(map[string]any{"err": fmt.Sprint(err), "up": up, "targets": all})
	})
	all, _ := promTargets(promAddr)
	for _, tg := range poolTargets(all, chartPool) {
		if tg.Labels["app_kubernetes_io_instance"] != "konstapel" || tg.Labels["job"] != "konstapel-controller-metrics" {
			t.Fatalf("target labels %v", tg.Labels)
		}
	}
	var queried struct {
		Result []struct {
			Metric map[string]string `json:"metric"`
		} `json:"result"`
	}
	l.waitFor("a Konstapel metric through the Prometheus API", 2*time.Minute, func() (bool, string) {
		err := promGet(promAddr, "/api/v1/query?query="+`konstapel_observation_enabled{job="konstapel-controller-metrics",namespace="konstapel-system"}`, &queried)
		return err == nil && len(queried.Result) > 0, fmt.Sprint(err)
	})
	l.record("scrape", map[string]any{"secondsToUp": waited.Seconds(), "targetsUp": replicas, "series": len(queried.Result)})

	// 2. The PrometheusRule the chart rendered is loaded and evaluating; the
	// unselected rule is not.
	var rules struct {
		Groups []struct {
			Name  string `json:"name"`
			Rules []struct {
				Name   string `json:"name"`
				Health string `json:"health"`
			} `json:"rules"`
		} `json:"groups"`
	}
	l.waitFor("starter rule groups", 4*time.Minute, func() (bool, string) {
		if err := promGet(promAddr, "/api/v1/rules", &rules); err != nil {
			return false, err.Error()
		}
		healthy := 0
		for _, g := range rules.Groups {
			if g.Name == "konstapel-availability" || g.Name == "konstapel-operations" {
				for _, r := range g.Rules {
					if r.Health == "ok" {
						healthy++
					}
				}
			}
		}
		return healthy == 7, toJSON(rules)
	})
	for _, g := range rules.Groups {
		if g.Name == "obs-unselected" {
			t.Fatal("a PrometheusRule outside the rule selector was loaded")
		}
	}
	l.record("rules", map[string]any{"healthyStarterAlerts": 7})

	// 3. Denial: an identity without the reader binding is refused (403), a
	// wrong server name fails verification, and an unlabelled ServiceMonitor
	// is never discovered (the Operator had reconciled the others by now).
	l.waitFor("unauthorized and wrong-name targets down", 5*time.Minute, func() (bool, string) {
		all, _ := promTargets(promAddr)
		u, w := poolTargets(all, "serviceMonitor/konstapel-system/obs-unauthorized/0"), poolTargets(all, "serviceMonitor/konstapel-system/obs-wrong-name/0")
		return len(u) == replicas && len(w) == replicas && u[0].Health == "down" && w[0].Health == "down" &&
			strings.Contains(u[0].LastError, "403") && strings.Contains(w[0].LastError, "x509"), toJSON(all)
	})
	all, _ = promTargets(promAddr)
	if got := poolTargets(all, "serviceMonitor/konstapel-system/obs-unselected/0"); len(got) != 0 {
		t.Fatalf("a ServiceMonitor outside the selector was discovered: %v", got)
	}
	l.record("denial", map[string]any{"unauthorized": poolTargets(all, "serviceMonitor/konstapel-system/obs-unauthorized/0")[0].LastError,
		"wrongServerName": poolTargets(all, "serviceMonitor/konstapel-system/obs-wrong-name/0")[0].LastError, "unselectedTargets": 0})

	// 4. The Operator's policy on credential access: with file access from
	// ServiceMonitors denied, the chart's default (bearerTokenFile) is
	// rejected and its targets disappear; the documented Secret mode scrapes.
	if err := l.c.Patch(l.ctx, prom, client.RawPatch(types.MergePatchType, []byte(`{"spec":{"arbitraryFSAccessThroughSMs":{"deny":true}}}`))); err != nil {
		t.Fatal(err)
	}
	denied := l.waitFor("the chart ServiceMonitor rejected under the file-access policy", 5*time.Minute, func() (bool, string) {
		all, err := promTargets(promAddr)
		return err == nil && len(poolTargets(all, chartPool)) == 0 && len(poolTargets(all, "serviceMonitor/konstapel-system/obs-unauthorized/0")) == replicas, toJSON(all)
	})
	if out, err := l.helm([]string{"upgrade", "konstapel", chartArchive(t, "konstapel"), "--wait", "--timeout", "5m", "--reuse-values",
		"--set", "metrics.serviceMonitor.authorization.mode=secret", "--set", "metrics.serviceMonitor.authorization.secret.name=obs-reader-token", "--namespace", ns}...); err != nil {
		t.Fatalf("upgrade to Secret authorization: %v\n%s", err, out)
	}
	fallback := l.waitFor("Secret-authorized chart targets up under the file-access policy", 5*time.Minute, func() (bool, string) {
		all, err := promTargets(promAddr)
		up := 0
		for _, tg := range poolTargets(all, chartPool) {
			if tg.Health == "up" {
				up++
			}
		}
		return err == nil && up == replicas, toJSON(all)
	})
	l.record("credentialPolicy", map[string]any{"arbitraryFSAccessThroughSMs.deny": true, "fileModeRejectedAfterSeconds": denied.Seconds(), "secretModeUpAfterSeconds": fallback.Seconds()})

	// 5. Revocation as the scraper sees it: removing the reader binding turns
	// the chart's targets down with 403 within the pinned allow-cache bound
	// (5 minutes) plus a scrape interval and margin.
	if err := l.c.Delete(l.ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "konstapel-metrics-reader"}}); err != nil {
		t.Fatal(err)
	}
	revoked := time.Now()
	for {
		all, err := promTargets(promAddr)
		pool, down := poolTargets(all, chartPool), 0
		for _, tg := range pool {
			if tg.Health == "down" && strings.Contains(tg.LastError, "403") {
				down++
			}
		}
		if err == nil && len(pool) == replicas && down == replicas {
			break
		}
		if time.Since(revoked) > 5*time.Minute+45*time.Second {
			t.Fatalf("revoked Prometheus still scrapes %s after revocation: %v %s", time.Since(revoked), err, toJSON(pool))
		}
		time.Sleep(5 * time.Second)
	}
	l.record("revocation", map[string]any{"seconds": time.Since(revoked).Seconds(), "boundSeconds": 300})
}

func allReady(p corev1.Pod) bool {
	for _, s := range p.Status.ContainerStatuses {
		if !s.Ready {
			return false
		}
	}
	return len(p.Status.ContainerStatuses) > 0
}
