package charttest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	smAPI = "monitoring.coreos.com/v1/ServiceMonitor"
	prAPI = "monitoring.coreos.com/v1/PrometheusRule"
)

// renderWith renders the runtime chart with cluster APIs (an offline
// helm template serves none of the Operator's) and a values document.
func renderWith(t *testing.T, apis []string, values string, set ...string) ([]map[string]any, string, error) {
	t.Helper()
	args := []string{"template", "konstapel", "../../charts/konstapel", "--namespace", controllerNS, "--set", "image.digest=" + digest}
	for _, a := range apis {
		args = append(args, "--api-versions", a)
	}
	if values != "" {
		f := filepath.Join(t.TempDir(), "values.yaml")
		if err := os.WriteFile(f, []byte(values), 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "-f", f)
	}
	for _, s := range set {
		args = append(args, "--set", s)
	}
	out, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		return nil, string(out), err
	}
	return documents(t, out), string(out), nil
}

func mustRender(t *testing.T, apis []string, values string, set ...string) []map[string]any {
	t.Helper()
	docs, out, err := renderWith(t, apis, values, set...)
	if err != nil {
		t.Fatalf("render: %v\n%s", err, out)
	}
	return docs
}

func monitoringDocs(docs []map[string]any) (sm, pr map[string]any) {
	for _, d := range docs {
		if group, _, _ := strings.Cut(fmt.Sprint(d["apiVersion"]), "/"); group == "monitoring.coreos.com" {
			switch d["kind"] {
			case "ServiceMonitor":
				sm = d
			case "PrometheusRule":
				pr = d
			default:
				panic("unexpected monitoring kind " + fmt.Sprint(d["kind"]))
			}
		}
	}
	return sm, pr
}

func countMonitoring(docs []map[string]any) int {
	n := 0
	for _, d := range docs {
		if strings.HasPrefix(fmt.Sprint(d["apiVersion"]), "monitoring.coreos.com/") {
			n++
		}
	}
	return n
}

const smEnabled = "metrics:\n  enabled: true\n  serviceMonitor:\n    enabled: true\n"

// ruleValues is a test-only rule group: the chart ships no rule of its own
// yet, so the plumbing is exercised with this fixture.
const ruleValues = `metrics:
  enabled: true
  prometheusRule:
    enabled: true
    runbookBaseURL: https://example.org/runbooks/
    groups:
      example:
        interval: 1m
        rules:
          ExampleLag:
            expr: 'time() - example_timestamp_seconds{__scope__} > __threshold__'
            threshold: 600
            for: 5m
          ExampleDown:
            expr: 'up{__scope__} == 0'
            for: 10m
            severity: critical
            runbookURL: https://example.org/down
            labels: {team: platform}
            annotations: {summary: "{{ $labels.instance }} is down"}
      second:
        rules:
          Another: {expr: 'vector(1)'}
`

// Both integrations are off by default, also when the cluster serves the
// Operator APIs, and a render with both off needs no monitoring CRDs.
func TestMonitoringOffByDefaultAndWithoutCRDs(t *testing.T) {
	for _, apis := range [][]string{nil, {smAPI, prAPI}} {
		for _, set := range [][]string{nil, {"metrics.enabled=true"},
			{"metrics.enabled=true", "metrics.serviceMonitor.enabled=false", "metrics.prometheusRule.enabled=false"}} {
			docs := mustRender(t, apis, "", set...)
			if n := countMonitoring(docs); n != 0 {
				t.Errorf("apis %v set %v rendered %d monitoring objects", apis, set, n)
			}
		}
	}
	// Enabled rules with no group render nothing (no empty PrometheusRule).
	docs := mustRender(t, []string{prAPI}, "metrics:\n  enabled: true\n  prometheusRule:\n    enabled: true\n")
	if n := countMonitoring(docs); n != 0 {
		t.Errorf("rule integration without groups rendered %d objects", n)
	}
}

// Each integration needs metrics and its own enabled API; they are
// independent of each other.
func TestMonitoringIncompatibleOptionsAndMissingAPIs(t *testing.T) {
	cases := []struct {
		name   string
		apis   []string
		values string
		want   string // empty: must render
	}{
		{"service monitor without metrics", []string{smAPI}, "metrics:\n  serviceMonitor:\n    enabled: true\n", "set metrics.enabled"},
		{"rule without metrics", []string{prAPI}, "metrics:\n  prometheusRule:\n    enabled: true\n", "set metrics.enabled"},
		{"service monitor without its API", nil, smEnabled, "ServiceMonitor API"},
		{"service monitor with only the rule API", []string{prAPI}, smEnabled, "ServiceMonitor API"},
		{"rule without its API", nil, ruleValues, "PrometheusRule API"},
		{"rule with only the monitor API", []string{smAPI}, ruleValues, "PrometheusRule API"},
		{"service monitor alone", []string{smAPI}, smEnabled, ""},
		{"rule alone", []string{prAPI}, ruleValues, ""},
		{"timeout equal to interval", []string{smAPI}, smEnabled + "    scrapeTimeout: 30s\n", "must be shorter"},
		{"interval beyond the stale window", []string{smAPI}, smEnabled + "    interval: 3m\n", "at most 2m"},
		{"two CA sources", []string{smAPI}, smEnabled + "    tls: {ca: {configMap: {name: a}, file: /ca.crt}}\n", "one CA source"},
		{"secret authorization without a Secret", []string{smAPI}, smEnabled + "    authorization: {mode: secret}\n", "secret.name is required"},
		{"insecure skip verify", []string{smAPI}, smEnabled + "    insecureSkipVerify: true\n", "insecureSkipVerify"},
	}
	for _, c := range cases {
		_, out, err := renderWith(t, c.apis, c.values)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v\n%s", c.name, err, out)
		case c.want != "" && err == nil:
			t.Errorf("%s: rendered, want an error containing %q", c.name, c.want)
		case c.want != "" && !strings.Contains(out, c.want):
			t.Errorf("%s: error %q lacks %q", c.name, out, c.want)
		}
	}
}

// The ServiceMonitor selects only this release's metrics Service in the
// release namespace, through the named HTTPS port, with a verified CA and
// server name, for both certificate-management modes.
func TestServiceMonitorRendering(t *testing.T) {
	schema := serviceMonitorSchema(t)
	for _, c := range []struct {
		name, values, release, caSecret string
	}{
		{"cert-manager", smEnabled, "konstapel", "konstapel-controller-metrics-tls"},
		{"operator certificate", "tls:\n  mode: secret\n  secret: {name: konstapel-download-tls}\n" + smEnabled + "  tls: {secretName: metrics-tls}\n", "konstapel", "metrics-tls"},
		{"another release name", smEnabled, "other", "konstapel-controller-metrics-tls"},
	} {
		t.Run(c.name, func(t *testing.T) {
			values := c.values
			f := filepath.Join(t.TempDir(), "v.yaml")
			if err := os.WriteFile(f, []byte(values), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("helm", "template", c.release, "../../charts/konstapel", "--namespace", controllerNS,
				"--set", "image.digest="+digest, "--api-versions", smAPI, "-f", f).CombinedOutput()
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			docs := documents(t, out)
			sm, _ := monitoringDocs(docs)
			if sm == nil {
				t.Fatal("no ServiceMonitor")
			}
			schema.check(t, sm)

			// The selector is exact: release, component and no wildcard.
			if got := fmt.Sprint(at(sm, "spec", "selector")); got != "map[matchLabels:map[app.kubernetes.io/component:controller-metrics app.kubernetes.io/instance:"+c.release+" app.kubernetes.io/name:konstapel]]" {
				t.Errorf("selector %s", got)
			}
			if got := fmt.Sprint(at(sm, "spec", "namespaceSelector")); got != "map[matchNames:[konstapel-system]]" {
				t.Errorf("namespaceSelector %s", got)
			}
			if got := fmt.Sprint(at(sm, "spec", "targetLabels")); got != "[app.kubernetes.io/instance]" {
				t.Errorf("targetLabels %s", got)
			}
			// ... and selects the metrics Service the chart renders, by its
			// labels and its named port, and nothing else.
			svc := find(docs, "Service", "konstapel-controller-metrics")
			labels, _ := at(svc, "metadata", "labels").(map[string]any)
			for k, v := range at(sm, "spec", "selector", "matchLabels").(map[string]any) {
				if labels[k] != v {
					t.Errorf("Service label %s=%v, selector wants %v", k, labels[k], v)
				}
			}
			for _, d := range docs {
				if d["kind"] == "Service" && metadata(d)["name"] != "konstapel-controller-metrics" {
					l, _ := at(d, "metadata", "labels").(map[string]any)
					if l["app.kubernetes.io/component"] == "controller-metrics" {
						t.Errorf("Service %v also matches the selector", metadata(d)["name"])
					}
				}
			}
			ep := at(sm, "spec", "endpoints", 0).(map[string]any)
			if n := len(at(sm, "spec", "endpoints").([]any)); n != 1 {
				t.Errorf("%d endpoints", n)
			}
			wantPort := at(svc, "spec", "ports", 0, "name")
			if ep["port"] != "https" || wantPort != "https" || ep["scheme"] != "https" || ep["path"] != "/metrics" {
				t.Errorf("endpoint %v, Service port %v", ep, wantPort)
			}
			if ep["interval"] != "30s" || ep["scrapeTimeout"] != "10s" {
				t.Errorf("timing %v/%v", ep["interval"], ep["scrapeTimeout"])
			}
			tls := ep["tlsConfig"].(map[string]any)
			if tls["serverName"] != "konstapel-controller-metrics.konstapel-system.svc" || tls["insecureSkipVerify"] != nil {
				t.Errorf("tlsConfig %v", tls)
			}
			if got := fmt.Sprint(tls["ca"]); got != "map[secret:map[key:ca.crt name:"+c.caSecret+"]]" {
				t.Errorf("CA %s", got)
			}
			// The CA Secret is the one the controller serves from (same
			// namespace as the monitor, so no file access is needed).
			pod, _ := controllerContainer(t, docs)
			if !strings.Contains(fmt.Sprint(pod["volumes"]), "secretName:"+c.caSecret) {
				t.Errorf("CA Secret %s is not the served certificate Secret: %v", c.caSecret, pod["volumes"])
			}
			if ep["bearerTokenFile"] != "/var/run/secrets/kubernetes.io/serviceaccount/token" || ep["authorization"] != nil {
				t.Errorf("authorization %v", ep)
			}
		})
	}
}

// Authorization, CA, timing and discovery options reach the object and the
// result still satisfies the Operator schema.
func TestServiceMonitorOptions(t *testing.T) {
	schema := serviceMonitorSchema(t)
	docs := mustRender(t, []string{smAPI}, smEnabled+`    labels: {release: kube-prometheus-stack}
    interval: 1m
    scrapeTimeout: 15s
    serverName: metrics.example.org
    tls:
      ca:
        configMap: {name: ca-bundle, key: root.pem}
    authorization:
      mode: secret
      secret: {name: prometheus-token, key: token}
`)
	sm, _ := monitoringDocs(docs)
	schema.check(t, sm)
	ep := at(sm, "spec", "endpoints", 0).(map[string]any)
	if fmt.Sprint(ep["authorization"]) != "map[credentials:map[key:token name:prometheus-token] type:Bearer]" || ep["bearerTokenFile"] != nil {
		t.Errorf("authorization %v", ep)
	}
	if fmt.Sprint(ep["tlsConfig"]) != "map[ca:map[configMap:map[key:root.pem name:ca-bundle]] serverName:metrics.example.org]" {
		t.Errorf("tlsConfig %v", ep["tlsConfig"])
	}
	if ep["interval"] != "1m" || ep["scrapeTimeout"] != "15s" {
		t.Errorf("timing %v %v", ep["interval"], ep["scrapeTimeout"])
	}
	if labels := metadata(sm)["labels"].(map[string]any); labels["release"] != "kube-prometheus-stack" || labels["app.kubernetes.io/instance"] != "konstapel" {
		t.Errorf("labels %v", labels)
	}
	docs = mustRender(t, []string{smAPI}, smEnabled+"    tls: {ca: {file: /etc/prometheus/ca/ca.crt}}\n")
	sm, _ = monitoringDocs(docs)
	schema.check(t, sm)
	if fmt.Sprint(at(sm, "spec", "endpoints", 0, "tlsConfig")) != "map[caFile:/etc/prometheus/ca/ca.crt serverName:konstapel-controller-metrics.konstapel-system.svc]" {
		t.Errorf("tlsConfig %v", at(sm, "spec", "endpoints", 0, "tlsConfig"))
	}
}

type ruleView struct {
	group, interval, alert, expr, forDur, severity, runbook string
	labels, annotations                                     string
}

func rules(t *testing.T, pr map[string]any) []ruleView {
	t.Helper()
	var out []ruleView
	for _, g := range at(pr, "spec", "groups").([]any) {
		g := g.(map[string]any)
		for _, r := range g["rules"].([]any) {
			r := r.(map[string]any)
			l, _ := r["labels"].(map[string]any)
			a, _ := r["annotations"].(map[string]any)
			v := ruleView{group: fmt.Sprint(g["name"]), alert: fmt.Sprint(r["alert"]), expr: fmt.Sprint(r["expr"]),
				severity: fmt.Sprint(l["severity"]), labels: fmt.Sprint(l), annotations: fmt.Sprint(a)}
			if g["interval"] != nil {
				v.interval = fmt.Sprint(g["interval"])
			}
			if r["for"] != nil {
				v.forDur = fmt.Sprint(r["for"])
			}
			if a["runbook_url"] != nil {
				v.runbook = fmt.Sprint(a["runbook_url"])
			}
			out = append(out, v)
		}
	}
	return out
}

func ruleDoc(t *testing.T, values string, set ...string) map[string]any {
	t.Helper()
	_, pr := monitoringDocs(mustRender(t, []string{prAPI}, values, set...))
	return pr
}

// The rendered rule content follows thresholds, holds, severity, runbooks
// and enablement; scope matchers are exact and release-scoped.
func TestPrometheusRuleRenderedContentFollowsValues(t *testing.T) {
	schema := prometheusRuleSchema(t)
	pr := ruleDoc(t, ruleValues)
	schema.check(t, pr)
	if metadata(pr)["namespace"] != "konstapel-system" {
		t.Errorf("namespace %v", metadata(pr)["namespace"])
	}
	got := rules(t, pr)
	if len(got) != 3 {
		t.Fatalf("rules %+v", got)
	}
	// Groups and rules render in a stable order.
	if got[0].group != "example" || got[0].alert != "ExampleDown" || got[1].alert != "ExampleLag" || got[2].group != "second" {
		t.Errorf("order %+v", got)
	}
	// Without a ServiceMonitor the scope is the job and namespace.
	scope := `job="konstapel-controller-metrics",namespace="konstapel-system"`
	if got[1].expr != "time() - example_timestamp_seconds{"+scope+"} > 600" || got[1].forDur != "5m" ||
		got[1].severity != "warning" || got[1].runbook != "https://example.org/runbooks/ExampleLag" || got[1].interval != "1m" {
		t.Errorf("ExampleLag %+v", got[1])
	}
	if got[0].expr != "up{"+scope+"} == 0" || got[0].severity != "critical" || got[0].runbook != "https://example.org/down" ||
		got[0].labels != "map[severity:critical team:platform]" || !strings.Contains(got[0].annotations, "{{ $labels.instance }} is down") {
		t.Errorf("ExampleDown %+v", got[0])
	}

	changed := func(name string, set []string, check func(rs []ruleView) bool) {
		t.Helper()
		rs := rules(t, ruleDoc(t, ruleValues, set...))
		if !check(rs) {
			t.Errorf("%s: %+v", name, rs)
		}
		if reflect.DeepEqual(rs, got) {
			t.Errorf("%s did not change the rendered rules", name)
		}
	}
	p := "metrics.prometheusRule.groups.example.rules."
	changed("threshold", []string{p + "ExampleLag.threshold=1800"}, func(rs []ruleView) bool { return strings.HasSuffix(rs[1].expr, "> 1800") })
	changed("hold", []string{p + "ExampleLag.for=15m"}, func(rs []ruleView) bool { return rs[1].forDur == "15m" })
	changed("severity", []string{p + "ExampleLag.severity=info"}, func(rs []ruleView) bool { return rs[1].severity == "info" })
	changed("rule disabled", []string{p + "ExampleDown.enabled=false"}, func(rs []ruleView) bool { return len(rs) == 2 && rs[0].alert == "ExampleLag" })
	changed("group disabled", []string{"metrics.prometheusRule.groups.example.enabled=false"}, func(rs []ruleView) bool { return len(rs) == 1 && rs[0].group == "second" })
	changed("runbook base", []string{"metrics.prometheusRule.runbookBaseURL=https://docs.example.org/rb"}, func(rs []ruleView) bool { return rs[1].runbook == "https://docs.example.org/rb/ExampleLag" })
	changed("group interval", []string{"metrics.prometheusRule.groups.example.interval=2m"}, func(rs []ruleView) bool { return rs[0].interval == "2m" })

	// The alert content is the same one rendering of one rule; tuning one
	// leaves the others alone.
	rs := rules(t, ruleDoc(t, ruleValues, p+"ExampleLag.threshold=1800"))
	if !reflect.DeepEqual(rs[0], got[0]) || !reflect.DeepEqual(rs[2], got[2]) {
		t.Error("tuning one rule changed another")
	}
	// Disabling every rule renders no PrometheusRule at all.
	_, none := monitoringDocs(mustRender(t, []string{prAPI}, ruleValues, p+"ExampleDown.enabled=false", p+"ExampleLag.enabled=false",
		"metrics.prometheusRule.groups.second.enabled=false"))
	if none != nil {
		t.Error("PrometheusRule rendered with every rule disabled")
	}

	// With the ServiceMonitor the scope adds the release instance label it
	// copies onto targets; an external scrape job uses explicit matchers.
	docs := mustRender(t, []string{smAPI, prAPI}, ruleValues, "metrics.serviceMonitor.enabled=true")
	_, both := monitoringDocs(docs)
	if want := `app_kubernetes_io_instance="konstapel",job="konstapel-controller-metrics",namespace="konstapel-system"`; !strings.Contains(rules(t, both)[0].expr, "{"+want+"}") {
		t.Errorf("release-scoped expr %s", rules(t, both)[0].expr)
	}
	rs = rules(t, ruleDoc(t, ruleValues, "metrics.prometheusRule.scope.matchers.job=vm-konstapel", "metrics.prometheusRule.scope.matchers.cluster=prod"))
	if rs[0].expr != `up{cluster="prod",job="vm-konstapel"} == 0` {
		t.Errorf("external scope %s", rs[0].expr)
	}
	// Labels the user adds cannot override chart-owned ones.
	pr = ruleDoc(t, ruleValues, "metrics.prometheusRule.labels.prometheus=main")
	if l := metadata(pr)["labels"].(map[string]any); l["prometheus"] != "main" || l["app.kubernetes.io/instance"] != "konstapel" {
		t.Errorf("labels %v", l)
	}
}

// Tuning rules or monitoring never changes the workload, RBAC, assessment
// or controller settings: everything outside the monitoring objects is
// identical.
func TestMonitoringDoesNotChangeOtherResources(t *testing.T) {
	strip := func(docs []map[string]any) []map[string]any {
		var out []map[string]any
		for _, d := range docs {
			if !strings.HasPrefix(fmt.Sprint(d["apiVersion"]), "monitoring.coreos.com/") {
				out = append(out, d)
			}
		}
		return out
	}
	base := strip(mustRender(t, nil, "metrics:\n  enabled: true\n"))
	all := strip(mustRender(t, []string{smAPI, prAPI}, ruleValues+"  serviceMonitor:\n    enabled: true\n"))
	tuned := strip(mustRender(t, []string{smAPI, prAPI}, ruleValues+"  serviceMonitor:\n    enabled: true\n", "metrics.prometheusRule.groups.example.rules.ExampleLag.threshold=1"))
	if !reflect.DeepEqual(base, all) || !reflect.DeepEqual(all, tuned) {
		t.Error("monitoring values changed a non-monitoring resource")
	}
}

// Neither chart installs a monitoring stack or its CRDs, and neither lists
// a dependency; the optional objects are plain release-owned resources.
func TestChartsInstallNoMonitoringStack(t *testing.T) {
	for _, chart := range []string{"konstapel-crds", "konstapel"} {
		args := []string{"template", chart, "../../charts/" + chart, "--include-crds", "--namespace", controllerNS}
		if chart == "konstapel" {
			args = append(args, "--set", "image.digest="+digest, "--api-versions", smAPI, "--api-versions", prAPI, "-f", "-")
		}
		cmd := exec.Command("helm", args...)
		cmd.Stdin = strings.NewReader(ruleValues + "  serviceMonitor:\n    enabled: true\n")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", chart, err, out)
		}
		for _, d := range documents(t, out) {
			kind := fmt.Sprint(d["kind"])
			if kind == "CustomResourceDefinition" && strings.HasSuffix(fmt.Sprint(metadata(d)["name"]), "monitoring.coreos.com") {
				t.Errorf("%s ships the monitoring CRD %v", chart, metadata(d)["name"])
			}
			switch kind {
			case "Prometheus", "Alertmanager", "ThanosRuler", "PodMonitor", "Probe", "ScrapeConfig", "AlertmanagerConfig", "PrometheusAgent":
				t.Errorf("%s renders a %s", chart, kind)
			}
			for _, c := range deepStrings(d) {
				if strings.Contains(c, "prometheus-operator") || strings.Contains(c, "quay.io/prometheus/") {
					t.Errorf("%s renders a monitoring workload image: %s", chart, c)
				}
			}
		}
		meta, err := exec.Command("helm", "show", "chart", "../../charts/"+chart).CombinedOutput()
		if err != nil || strings.Contains(string(meta), "dependencies:") {
			t.Errorf("%s declares dependencies: %v", chart, err)
		}
	}
}

func deepStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case map[string]any:
		var out []string
		for _, e := range x {
			out = append(out, deepStrings(e)...)
		}
		return out
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, deepStrings(e)...)
		}
		return out
	}
	return nil
}
