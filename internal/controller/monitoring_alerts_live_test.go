//go:build live

package controller

// Integrated monitoring acceptance (add-prometheus-observability 6.2, 6.3).
// TestLiveHelmMonitoring (monitoring_helm_live_test.go) runs these phases on
// its Helm-installed controller and its real Prometheus: every signal below
// is produced by the controller from a real failure, scraped over verified
// TLS by Prometheus and evaluated by Prometheus's rule engine against the
// chart's rendered PrometheusRule. Alert states come from the Prometheus
// alerts API, polled throughout the test; nothing is evaluated here.
//
//	6.2 rule overrides through helm upgrade; publication failing (the test
//	    S3 fault proxy refuses one binding's requests); cleanup blocked (an S3
//	    legal hold on an object-lock bucket); an unresolved binding;
//	    per-binding evidence expiry (Kyverno's reporting stopped); reporting
//	    access lost (an unavailable capability and overdue scheduling); no
//	    replica leading (Lease access removed); no scrape succeeding (reader
//	    access revoked). A disabled domain and an unobservable one never
//	    show healthy data.
//	6.3 binding deletion and recreation; the leader pod killed; the leader
//	    restarting on leadership loss; the metrics certificate reissued; the
//	    reader token rotated and the old one revoked; reader access revoked
//	    and restored while a replica is replaced. Controller work continues
//	    throughout.

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	appsv1 "k8s.io/api/apps/v1"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// obsScope selects the release's series the way the chart's rules do: the
// ServiceMonitor's job and namespace and the release target label.
const obsScope = `job="konstapel-controller-metrics",namespace="konstapel-system",app_kubernetes_io_instance="konstapel"`

// obsDomains are the domains this install enables; bundle_resolution is
// disabled (no bundle sources) and must never look available.
var obsDomains = []string{"targeting", "assessment", "evidence_storage"}

func sel(extra string) string { return "{" + obsScope + extra + "}" }

type promSample struct {
	Metric map[string]string `json:"metric"`
	Value  float64           `json:"value"`
}

// promQuery runs an instant query through the Prometheus HTTP API.
func promQuery(addr, q string) ([]promSample, error) {
	var d struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Value  []any             `json:"value"`
		} `json:"result"`
	}
	if err := promGet(addr, "/api/v1/query?"+url.Values{"query": {q}}.Encode(), &d); err != nil {
		return nil, err
	}
	if d.ResultType != "vector" {
		return nil, fmt.Errorf("%s: result type %q", q, d.ResultType)
	}
	out := make([]promSample, 0, len(d.Result))
	for _, r := range d.Result {
		s, ok := "", len(r.Value) == 2
		if ok {
			s, ok = r.Value[1].(string)
		}
		v, err := strconv.ParseFloat(s, 64)
		if !ok || err != nil {
			return nil, fmt.Errorf("%s: value %v", q, r.Value)
		}
		out = append(out, promSample{Metric: r.Metric, Value: v})
	}
	return out, nil
}

// promAlert is one entry of the Prometheus alerts API.
type promAlert struct {
	Labels   map[string]string `json:"labels"`
	State    string            `json:"state"`
	ActiveAt time.Time         `json:"activeAt"`
}

// alertChange is one observed transition of a Konstapel alert.
type alertChange struct {
	At    time.Time `json:"at"`
	Alert string    `json:"alert"`
	State string    `json:"state"` // pending, firing or inactive
}

// alertTracker polls the Prometheus alerts API every 3 seconds for the
// whole test and keeps every transition of every Konstapel alert, so a
// phase can check what fired, when, and what never did.
type alertTracker struct {
	addr       string
	mu         sync.Mutex
	cur        map[string]promAlert
	log        []alertChange
	polls, bad int
	lastErr    string
	stop, done chan struct{}
}

// alertID is an alert's name and identifying labels (binding, capability,
// domain), without the scope labels and severity.
func alertID(labels map[string]string) string {
	var parts []string
	for k, v := range labels {
		switch k {
		case "alertname", "severity", "job", "namespace", "app_kubernetes_io_instance":
			continue
		}
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return labels["alertname"] + "{" + strings.Join(parts, ",") + "}"
}

func startAlertTracker(addr string) *alertTracker {
	a := &alertTracker{addr: addr, cur: map[string]promAlert{}, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(a.done)
		for {
			a.poll()
			select {
			case <-a.stop:
				return
			case <-time.After(3 * time.Second):
			}
		}
	}()
	return a
}

func (a *alertTracker) poll() {
	var d struct {
		Alerts []promAlert `json:"alerts"`
	}
	err := promGet(a.addr, "/api/v1/alerts", &d)
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.polls++
	if err != nil {
		a.bad++
		a.lastErr = err.Error()
		return
	}
	next := map[string]promAlert{}
	for _, al := range d.Alerts {
		if strings.HasPrefix(al.Labels["alertname"], "Konstapel") {
			next[alertID(al.Labels)] = al
		}
	}
	for id, al := range next {
		if old, ok := a.cur[id]; !ok || old.State != al.State {
			a.log = append(a.log, alertChange{At: now, Alert: id, State: al.State})
		}
	}
	for id := range a.cur {
		if _, ok := next[id]; !ok {
			a.log = append(a.log, alertChange{At: now, Alert: id, State: "inactive"})
		}
	}
	a.cur = next
}

func (a *alertTracker) close() {
	close(a.stop)
	<-a.done
}

// state is the alert's current state ("inactive" when Prometheus has none).
func (a *alertTracker) state(id string) (string, promAlert) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if al, ok := a.cur[id]; ok {
		return al.State, al
	}
	return "inactive", promAlert{}
}

// active lists every current Konstapel alert with its state.
func (a *alertTracker) active() map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string]string{}
	for id, al := range a.cur {
		out[id] = al.State
	}
	return out
}

// reached reports whether the alert was seen in state at or after since.
func (a *alertTracker) reached(id, state string, since time.Time) (time.Time, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range a.log {
		if c.Alert == id && c.State == state && !c.At.Before(since) {
			return c.At, true
		}
	}
	return time.Time{}, false
}

// last is when the alert last entered state.
func (a *alertTracker) last(id, state string) (time.Time, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.log) - 1; i >= 0; i-- {
		if c := a.log[i]; c.Alert == id {
			return c.At, c.State == state
		}
	}
	return time.Time{}, false
}

// changes are the transitions at or after since.
func (a *alertTracker) changes(since time.Time) []alertChange {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []alertChange
	for _, c := range a.log {
		if !c.At.Before(since) {
			out = append(out, c)
		}
	}
	return out
}

// obsRun is the integrated monitoring fixture: the Helm release, its
// Prometheus, the test S3 service behind the fault proxy, an object-lock
// bucket, two destinations and the bindings whose failures are observed.
type obsRun struct {
	l          *live
	ns         string
	prom       string
	alerts     *alertTracker
	direct     *s3store.Publisher
	proxy      *faultProxy
	lockBucket string
	destA      *v1alpha1.EvidenceDestination // normal bucket, through the fault proxy
	destB      *v1alpha1.EvidenceDestination // object-lock bucket, direct
	profile    string
	scheduled  *v1alpha1.BindingAssessment
	start      time.Time
	// The package whose cleanup a legal hold blocked, and when it was lifted.
	held     string
	liftedAt time.Time
}

const (
	obsProfile = "obs-baseline"
	// obs-audit: no workload (known empty scope), daily, through the proxy.
	obsAudit = "obs-audit"
	// obs-sched: a passing and a failing Pod, every 2 minutes, packages
	// retained 3 minutes on the object-lock bucket.
	obsSched = "obs-sched"
	// obs-expiry: one passing Pod, daily, current evidence valid 90s.
	obsExpiry = "obs-expiry"
	// obs-unresolved: names a profile that does not exist (yet).
	obsUnresolved      = "obs-unresolved"
	obsMissingProfile  = "obs-missing"
	obsExpiryMaxAge    = 90
	obsSchedInterval   = 120
	obsCollectTimeout  = 20
	obsOverdueGrace    = 30
	obsCleanupLateness = 120
)

func obsPod(ns, name string, privileged bool) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/obs:1",
			SecurityContext: &corev1.SecurityContext{Privileged: &privileged}}}}}
}

// prepareObservability creates, right after the chart install and while
// Prometheus starts, the S3 fixtures, destinations, workloads and bindings
// whose controller-side state the later phases observe.
func (l *live) prepareObservability(ns string) *obsRun {
	t := l.t
	t.Helper()
	l.waitChartCRDs()
	m := &obsRun{l: l, ns: ns, lockBucket: "konstapel-obs-lock", profile: obsProfile}
	m.direct = l.chartS3(t)
	m.proxy = l.startFaultProxy(t)
	if _, err := m.direct.Client.CreateBucket(l.ctx, &s3.CreateBucketInput{Bucket: aws.String(m.lockBucket), ObjectLockEnabledForBucket: aws.Bool(true)}); err != nil {
		t.Fatalf("object-lock bucket: %v", err)
	}
	m.destA, _ = l.chartDestinationAt(t, ns, "obs-a", m.direct.Dest.Bucket, m.proxy.endpoint())
	m.destB, _ = l.chartDestinationAt(t, ns, "obs-b", m.lockBucket, "http://"+l.s3Container+":9000")

	for _, n := range []struct{ name, env string }{{"obs-audit-ns", obsAudit}, {"obs-sched-ns", obsSched}, {"obs-expiry-ns", obsExpiry}} {
		l.setNamespace(n.name, n.env)
		name := n.name
		t.Cleanup(func() { _ = l.c.Delete(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}) })
	}
	for _, p := range []*corev1.Pod{obsPod("obs-sched-ns", "passing", false), obsPod("obs-sched-ns", "privileged", true), obsPod("obs-expiry-ns", "passing", false)} {
		if err := l.c.Create(l.ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	p := profileObj(t, obsProfile, pol)
	p.SetUID("")
	l.createWhenServed(p)
	ref := func(d *v1alpha1.EvidenceDestination) *v1alpha1.DestinationReference {
		return &v1alpha1.DestinationReference{Name: d.Name, UID: string(d.UID)}
	}
	m.scheduled = &v1alpha1.BindingAssessment{Interval: "120s", CollectionTimeout: "20s", Retention: "180s", DestinationRef: ref(m.destB)}
	m.createBinding(obsAudit, &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "20s", Retention: "24h", DestinationRef: ref(m.destA)})
	m.createBinding(obsSched, m.scheduled.DeepCopy())
	m.createBinding(obsExpiry, &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "20s", MaxEvidenceAge: "90s", Retention: "180s", DestinationRef: ref(m.destB)})
	t.Cleanup(func() {
		for _, b := range []string{obsAudit, obsSched, obsExpiry, obsUnresolved} {
			_ = l.c.Delete(l.ctx, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b}})
			l.dropRuns(b)
		}
		for _, p := range []string{obsProfile, obsMissingProfile} {
			_ = l.c.Delete(l.ctx, &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: p}})
		}
	})
	l.record("observability-fixtures", map[string]any{"destinations": map[string]string{"proxied": m.destA.Spec.S3.Endpoint, "objectLock": m.destB.Spec.S3.Endpoint},
		"bindings": []string{obsAudit, obsSched, obsExpiry}})
	return m
}

func (m *obsRun) createBinding(name string, a *v1alpha1.BindingAssessment) {
	b := bindingObj(name, m.profile, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: v1alpha1.LabelValue(name)})
	if name == obsUnresolved {
		b.Spec.ProfileRef.Name = obsMissingProfile
	}
	b.SetUID("")
	b.SetGeneration(0)
	b.Spec.Assessment = a
	m.l.createWhenServed(b)
}

// wait polls f every 3 seconds until it succeeds, failing with the
// controller pods and the current alerts after limit.
func (m *obsRun) wait(what string, limit time.Duration, f func() (bool, string)) time.Duration {
	m.l.t.Helper()
	start, last := time.Now(), ""
	for time.Since(start) < limit {
		ok, detail := f()
		if ok {
			return time.Since(start)
		}
		last = detail
		time.Sleep(3 * time.Second)
	}
	m.l.t.Fatalf("timed out after %s waiting for %s: %s\nalerts: %s\nkonstapel pods:\n%s", limit, what, last, toJSON(m.alerts.active()), m.l.podDiagnostics(m.ns))
	return 0
}

// waitAlert waits until the alert is in state and returns when the
// tracker first saw it enter that state (possibly before this call).
func (m *obsRun) waitAlert(id, state string, limit time.Duration) time.Time {
	m.l.t.Helper()
	m.wait(id+" "+state, limit, func() (bool, string) {
		s, _ := m.alerts.state(id)
		return s == state, s
	})
	if at, ok := m.alerts.last(id, state); ok {
		return at
	}
	return time.Now() // inactive and never active
}

func (m *obsRun) query(q string) ([]promSample, error) { return promQuery(m.prom, q) }

// one returns the value of a query that must yield exactly one sample.
func (m *obsRun) one(q string) (float64, bool, string) {
	s, err := m.query(q)
	if err != nil || len(s) != 1 {
		return 0, false, fmt.Sprintf("%s: %v %s", q, err, toJSON(s))
	}
	return s[0].Value, true, ""
}

// none reports whether a query yields no sample.
func (m *obsRun) none(q string) (bool, string) {
	s, err := m.query(q)
	return err == nil && len(s) == 0, fmt.Sprintf("%s: %v %s", q, err, toJSON(s))
}

// byLabel maps a query's samples by one label.
func (m *obsRun) byLabel(q, label string) (map[string]float64, string) {
	s, err := m.query(q)
	if err != nil {
		return nil, err.Error()
	}
	out := map[string]float64{}
	for _, x := range s {
		out[x.Metric[label]] = x.Value
	}
	return out, toJSON(s)
}

// owners maps each domain to the pods holding a ready projection younger
// than the rules' default 4-minute maximum projection age.
func (m *obsRun) owners() (map[string][]string, string) {
	s, err := m.query(`konstapel_observation_ready` + sel("") + ` == 1 and on (pod, domain) (time() - konstapel_observation_updated_timestamp_seconds` + sel("") + `) < 240`)
	if err != nil {
		return nil, err.Error()
	}
	out := map[string][]string{}
	for _, x := range s {
		out[x.Metric["domain"]] = append(out[x.Metric["domain"]], x.Metric["pod"])
	}
	return out, toJSON(out)
}

// soleOwner waits until every enabled domain has exactly one owner, the
// pod, and no disabled domain has one.
func (m *obsRun) soleOwner(pod string, limit time.Duration) time.Duration {
	m.l.t.Helper()
	return m.wait("every enabled domain owned by "+pod+" alone", limit, func() (bool, string) {
		o, detail := m.owners()
		if o == nil || len(o) != len(obsDomains) {
			return false, detail
		}
		for _, d := range obsDomains {
			if len(o[d]) != 1 || o[d][0] != pod {
				return false, detail
			}
		}
		return true, ""
	})
}

func (m *obsRun) controllerPods() map[string]corev1.Pod {
	var pods corev1.PodList
	_ = m.l.c.List(m.l.ctx, &pods, client.InNamespace(m.ns), client.MatchingLabels{"app.kubernetes.io/component": "controller"})
	out := map[string]corev1.Pod{}
	for _, p := range pods.Items {
		if p.DeletionTimestamp == nil {
			out[p.Name] = p
		}
	}
	return out
}

func restarts(p corev1.Pod) int32 {
	for _, s := range p.Status.ContainerStatuses {
		if s.Name == "controller" {
			return s.RestartCount
		}
	}
	return -1
}

// helmUpgrade upgrades the release keeping its values, with extra --set.
func (m *obsRun) helmUpgrade(sets ...string) {
	m.l.t.Helper()
	args := []string{"upgrade", "konstapel", chartArchive(m.l.t, "konstapel"), "--namespace", m.ns, "--reuse-values", "--wait", "--timeout", "5m"}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	if out, err := m.l.helm(args...); err != nil {
		m.l.t.Fatalf("helm upgrade %v: %v\n%s", sets, err, out)
	}
}

type promRule struct {
	Name     string            `json:"name"`
	Query    string            `json:"query"`
	Duration float64           `json:"duration"`
	Labels   map[string]string `json:"labels"`
	Health   string            `json:"health"`
}

// loadedRules returns the alerting rules Prometheus evaluates from the
// release's two starter groups.
func (m *obsRun) loadedRules() (map[string]promRule, error) {
	var d struct {
		Groups []struct {
			Name  string     `json:"name"`
			Rules []promRule `json:"rules"`
		} `json:"groups"`
	}
	if err := promGet(m.prom, "/api/v1/rules?type=alert", &d); err != nil {
		return nil, err
	}
	out := map[string]promRule{}
	for _, g := range d.Groups {
		if g.Name == "konstapel-availability" || g.Name == "konstapel-operations" {
			for _, r := range g.Rules {
				out[r.Name] = r
			}
		}
	}
	return out, nil
}

// Rule groups and the value prefix of one rule.
const (
	availabilityRules = "metrics.prometheusRule.groups.konstapel-availability.rules."
	operationsRules   = "metrics.prometheusRule.groups.konstapel-operations.rules."
)

// defaultsLoaded checks that Prometheus evaluates the chart's defaults:
// the documented holds, all warning, the 600s overdue grace.
func (m *obsRun) defaultsLoaded() {
	m.l.t.Helper()
	want := map[string]float64{"KonstapelMetricsUnavailable": 300, "KonstapelObservationUnavailable": 300, "KonstapelBindingUnresolved": 600,
		"KonstapelEngineUnavailable": 600, "KonstapelAssessmentOverdue": 300, "KonstapelPublicationFailing": 120, "KonstapelCleanupBlocked": 900}
	rules, err := m.loadedRules()
	if err != nil {
		m.l.t.Fatal(err)
	}
	for name, hold := range want {
		r, ok := rules[name]
		if !ok || r.Duration != hold || r.Labels["severity"] != "warning" || r.Health != "ok" {
			m.l.t.Fatalf("default %s as loaded: %s", name, toJSON(r))
		}
	}
	if !strings.Contains(rules["KonstapelAssessmentOverdue"].Query, "> 600") || !strings.Contains(rules["KonstapelCleanupBlocked"].Query, "> 3600") {
		m.l.t.Fatalf("default thresholds as loaded: %s", toJSON(rules))
	}
}

// overrides (6.2) tunes the starter rules through helm upgrade as an
// operator would: shorter holds so this run finishes in bounded time, a
// different overdue grace and cleanup lateness, a critical severity, and
// one rule disabled. PublicationFailing keeps its default 2m hold, the
// one that must fire inside the owner's 5-minute publish timeout. The
// workload is not touched.
func (m *obsRun) overrides() {
	l, t := m.l, m.l.t
	t.Helper()
	m.defaultsLoaded()
	pods := m.controllerPods()
	var dep appsv1.Deployment
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: m.ns, Name: "konstapel-controller"}, &dep); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	m.helmUpgrade(availabilityRules+"KonstapelMetricsUnavailable.for=1m", availabilityRules+"KonstapelObservationUnavailable.for=1m",
		operationsRules+"KonstapelBindingUnresolved.for=1m", operationsRules+"KonstapelBindingUnresolved.severity=critical",
		operationsRules+"KonstapelEngineUnavailable.for=1m",
		operationsRules+"KonstapelAssessmentOverdue.for=1m", operationsRules+"KonstapelAssessmentOverdue.threshold="+strconv.Itoa(obsOverdueGrace),
		operationsRules+"KonstapelCleanupBlocked.for=1m", operationsRules+"KonstapelCleanupBlocked.threshold="+strconv.Itoa(obsCleanupLateness),
		operationsRules+"KonstapelCleanupBlocked.enabled=false")
	loaded := m.wait("the tuned rules evaluated by Prometheus", 5*time.Minute, func() (bool, string) {
		rules, err := m.loadedRules()
		if err != nil {
			return false, err.Error()
		}
		hold := map[string]float64{"KonstapelMetricsUnavailable": 60, "KonstapelObservationUnavailable": 60, "KonstapelBindingUnresolved": 60,
			"KonstapelEngineUnavailable": 60, "KonstapelAssessmentOverdue": 60, "KonstapelPublicationFailing": 120}
		for name, d := range hold {
			if r, ok := rules[name]; !ok || r.Duration != d || r.Health != "ok" {
				return false, toJSON(rules)
			}
		}
		_, cleanup := rules["KonstapelCleanupBlocked"]
		return !cleanup && len(rules) == 6 && rules["KonstapelBindingUnresolved"].Labels["severity"] == "critical" &&
			rules["KonstapelEngineUnavailable"].Labels["severity"] == "warning" &&
			strings.Contains(rules["KonstapelAssessmentOverdue"].Query, fmt.Sprintf("> %d", obsOverdueGrace)), toJSON(rules)
	})
	var after appsv1.Deployment
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(&dep), &after); err != nil {
		t.Fatal(err)
	}
	now := m.controllerPods()
	if after.Generation != dep.Generation || len(now) != len(pods) {
		t.Fatalf("a rule-only upgrade changed the controller Deployment: generation %d -> %d, pods %d -> %d", dep.Generation, after.Generation, len(pods), len(now))
	}
	for name, p := range pods {
		if q, ok := now[name]; !ok || q.UID != p.UID || restarts(q) != restarts(p) {
			t.Fatalf("a rule-only upgrade replaced or restarted %s", name)
		}
	}
	l.record("rule-overrides", map[string]any{"holds": "1m (PublicationFailing default 2m)", "overdueGrace": obsOverdueGrace, "cleanupLateness": obsCleanupLateness,
		"bindingUnresolvedSeverity": "critical", "cleanupBlocked": "disabled", "loadedAfterSeconds": time.Since(start).Seconds(), "evaluatedAfterSeconds": loaded.Seconds(),
		"controllerDeploymentGeneration": after.Generation, "controllerPodsUnchanged": len(now)})
}

// latestRun returns the binding object's newest run that satisfies ok.
func (m *obsRun) latestRun(binding string, ok func(*v1alpha1.AssessmentRun) bool) *v1alpha1.AssessmentRun {
	b := &v1alpha1.ComplianceBinding{}
	if err := m.l.c.Get(m.l.ctx, client.ObjectKey{Name: binding}, b); err != nil {
		return nil
	}
	var runs v1alpha1.AssessmentRunList
	_ = m.l.c.List(m.l.ctx, &runs, client.MatchingLabels{LabelRunBinding: string(b.UID)})
	var out *v1alpha1.AssessmentRun
	for i := range runs.Items {
		r := &runs.Items[i]
		if ok(r) && (out == nil || r.CreationTimestamp.After(out.CreationTimestamp.Time)) {
			out = r
		}
	}
	return out
}

func published(r *v1alpha1.AssessmentRun) bool {
	return r.Status.Phase == v1alpha1.RunCompleted && r.Status.Publication != nil && r.Status.Publication.PublishedAt != nil
}

// baseline (6.2) checks, through the real scrape, the healthy state every
// later failure is compared with: one owner per enabled domain (the Lease
// holder), the disabled bundle domain never available, each binding's
// views and settings, and no Konstapel alert firing.
func (m *obsRun) baseline() {
	l, t := m.l, m.l.t
	t.Helper()
	for _, b := range []string{obsAudit, obsSched, obsExpiry} {
		l.waitReady(b, map[string]int32{obsAudit: 1, obsSched: 1, obsExpiry: 1}[b])
		l.publishedRun(b, "")
	}
	leader := l.leaderPod(m.ns, "")
	m.soleOwner(leader, 3*time.Minute)
	m.wait("current views of the three bindings", 4*time.Minute, func() (bool, string) {
		sched, d1 := m.byLabel(`konstapel_binding_assessment_checks`+sel(`,binding="obs-sched",view="current"`), "state")
		expiry, d2 := m.byLabel(`konstapel_binding_assessment_checks`+sel(`,binding="obs-expiry",view="current"`), "state")
		audit, d3 := m.byLabel(`konstapel_binding_assessment_status`+sel(`,binding="obs-audit",view="current"`)+` == 1`, "status")
		auditChecks, _ := m.byLabel(`konstapel_binding_assessment_checks`+sel(`,binding="obs-audit",view="current"`), "state")
		ok := len(sched) == 10 && sched["pass"] == 1 && sched["fail"] == 1 && len(expiry) == 10 && expiry["pass"] == 1 &&
			len(audit) == 1 && audit["no_targets"] == 1 && len(auditChecks) == 10
		for _, v := range auditChecks {
			ok = ok && v == 0
		}
		return ok, d1 + d2 + d3
	})
	// The current expiry is the oldest source evaluation plus the
	// binding's own evidence-age limit, and still ahead.
	for b, age := range map[string]float64{obsSched: 7200, obsExpiry: obsExpiryMaxAge} {
		q := `konstapel_binding_current_evidence_expiry_timestamp_seconds` + sel(`,binding="`+b+`"`) + ` - ignoring (view) konstapel_binding_oldest_evaluation_timestamp_seconds` + sel(`,binding="`+b+`",view="current"`)
		m.wait(b+" expiry = oldest evaluation + maxEvidenceAge", time.Minute, func() (bool, string) {
			v, ok, d := m.one(q)
			ahead, ok2, _ := m.one(`konstapel_binding_current_evidence_expiry_timestamp_seconds` + sel(`,binding="`+b+`"`) + ` - time()`)
			return ok && v == age && ok2 && ahead > 0, d
		})
	}
	settings, d := m.byLabel(`konstapel_binding_assessment_interval_seconds`+sel(""), "binding")
	timeouts, _ := m.byLabel(`konstapel_binding_collection_timeout_seconds`+sel(""), "binding")
	if settings[obsSched] != obsSchedInterval || settings[obsAudit] != 86400 || timeouts[obsSched] != obsCollectTimeout {
		t.Fatalf("binding settings through the scrape: %s", d)
	}
	if ok, d := m.none(`konstapel_binding_assessment_complete` + sel(`,binding="obs-audit"`)); !ok {
		t.Fatalf("known empty scope asserts completeness: %s", d)
	}
	caps, d := m.byLabel(`konstapel_capability_condition`+sel("")+` == 1`, "capability")
	if len(caps) != 2 {
		t.Fatalf("capabilities: %s", d)
	}
	statuses, _ := m.query(`konstapel_capability_condition` + sel(`,status="true"`) + ` == 1`)
	if len(statuses) != 2 {
		t.Fatalf("capabilities not true at baseline: %s", toJSON(statuses))
	}
	// The disabled domain is reported disabled and never ready; followers
	// expose no binding or backlog series.
	if v, ok, d := m.one(`max(konstapel_observation_enabled` + sel(`,domain="bundle_resolution"`) + `)`); !ok || v != 0 {
		t.Fatalf("bundle_resolution enabled: %s", d)
	}
	if ok, d := m.none(`konstapel_observation_ready` + sel(`,domain="bundle_resolution"`) + ` == 1`); !ok {
		t.Fatalf("a disabled domain reports ready: %s", d)
	}
	if ok, d := m.none(`{__name__=~"konstapel_binding_.+|konstapel_publication_.+|konstapel_cleanup_.+",` + obsScope + `,pod!="` + leader + `"}`); !ok {
		t.Fatalf("a follower exposes owner series: %s", d)
	}
	if v, ok, d := m.one(`konstapel_publication_failed` + sel("")); !ok || v != 0 {
		t.Fatalf("publication failures at baseline: %s", d)
	}
	for id, s := range m.alerts.active() {
		if s == "firing" {
			t.Fatalf("%s firing at baseline: %s", id, toJSON(m.alerts.active()))
		}
	}
	l.record("baseline", map[string]any{"leader": leader, "owners": "leader only, every enabled domain", "bundleResolution": "disabled, never ready",
		"obsSched": "known: pass 1, fail 1", "obsExpiry": "known: pass 1", "obsAudit": "no_targets, all counts 0, no completeness"})
}

// failures (6.2) starts four independent producer failures at once and
// follows each through the scrape and the rule evaluator:
//   - publication: the proxy refuses obs-audit's requests while a manual
//     run publishes; KonstapelPublicationFailing (default 2m hold) must
//     fire before the 5-minute publish timeout, and resolve once storage
//     returns and the run commits;
//   - cleanup: a legal hold on obs-sched's newest package blocks its expiry
//     deletion; KonstapelCleanupBlocked, re-enabled by helm upgrade, fires,
//     outlives the binding's deletion, and resolves once the hold is lifted;
//   - resolution: obs-unresolved names a missing profile;
//     KonstapelBindingUnresolved fires as critical (and stays for 6.3);
//   - evidence expiry: Kyverno's reporting stops; obs-expiry's current
//     evidence passes its expiry and is no longer counted as passing, a run
//     closed afterwards counts it as rejected, and it is current again
//     after reporting resumes.
//
// The binding deletion and recreation (6.3) happens while cleanup is
// blocked.
func (m *obsRun) failures() {
	l, t := m.l, m.l.t
	t.Helper()
	phase := time.Now()
	// Cleanup: the newest committed obs-sched package, before its expiry.
	var held *v1alpha1.AssessmentRun
	m.wait("an obs-sched package with time left before its expiry", 3*time.Minute, func() (bool, string) {
		held = m.latestRun(obsSched, func(r *v1alpha1.AssessmentRun) bool {
			return published(r) && r.Status.Publication.Commit != nil && r.Status.Publication.ExpiresAt != nil &&
				time.Until(r.Status.Publication.ExpiresAt.Time) > 20*time.Second
		})
		return held != nil, "none yet"
	})
	archive := held.Status.Publication.Commit
	legalHold := func(on s3types.ObjectLockLegalHoldStatus) {
		if _, err := m.direct.Client.PutObjectLegalHold(l.ctx, &s3.PutObjectLegalHoldInput{Bucket: aws.String(m.lockBucket), Key: aws.String(archive.ArchiveKey),
			VersionId: aws.String(archive.ArchiveVersionID), LegalHold: &s3types.ObjectLockLegalHold{Status: on}}); err != nil {
			t.Fatalf("legal hold %s: %v", on, err)
		}
	}
	legalHold(s3types.ObjectLockLegalHoldStatusOn)
	lifted := false
	t.Cleanup(func() {
		if !lifted {
			legalHold(s3types.ObjectLockLegalHoldStatusOff)
		}
	})
	m.helmUpgrade(operationsRules + "KonstapelCleanupBlocked.enabled=true")

	// Publication: refuse obs-audit's storage requests, then run.
	audit := l.binding(obsAudit)
	m.proxy.must(http.MethodPost, "/fail?uid="+string(audit.UID))
	released := false
	t.Cleanup(func() {
		if !released {
			m.proxy.release()
		}
	})
	pubRun := l.createRun(obsAudit, "obs-audit-pubfail")

	// Resolution.
	m.createBinding(obsUnresolved, nil)

	// Expiry: no more Kyverno evaluations.
	expiryBefore, _, _ := m.one(`konstapel_binding_current_evidence_expiry_timestamp_seconds` + sel(`,binding="obs-expiry"`))
	kyvernoDown := time.Now()
	scaledDown := true
	t.Cleanup(func() {
		if scaledDown {
			l.scaleKyverno("kyverno-reports-controller", 1)
			l.scaleKyverno("kyverno-background-controller", 1)
		}
	})
	l.scaleKyverno("kyverno-reports-controller", 0)
	l.scaleKyverno("kyverno-background-controller", 0)
	l.record("failures-started", map[string]any{"legalHold": held.Name, "heldExpiresAt": held.Status.Publication.ExpiresAt.UTC(), "publicationRun": pubRun.Name,
		"proxyFailing": "obs-audit binding UID", "unresolved": obsUnresolved + " -> profile " + obsMissingProfile, "kyverno": "reports and background controllers at 0",
		"expiryBefore": time.Unix(int64(expiryBefore), 0).UTC()})

	// 1. Publication failing, before the publish timeout.
	var closed time.Time
	l.eventually("obs-audit-pubfail retrying publication", func() (bool, string) {
		r := l.run(pubRun.Name)
		if r == nil || r.Status.Phase != v1alpha1.RunPublishing || r.Status.Window == nil || r.Status.Window.Closed == nil {
			return false, toJSON(r)
		}
		c := meta.FindStatusCondition(r.Status.Conditions, v1alpha1.ConditionPublished)
		closed = r.Status.Window.Closed.Time
		return c != nil && c.Status == metav1.ConditionFalse && c.Reason == v1alpha1.ReasonPublicationRetrying, toJSON(r.Status.Conditions)
	})
	failQ := `sum(increase(konstapel_operation_attempts_total` + sel(`,operation="evidence_publication",result="failure"`) + `[15m]))`
	firing := m.waitAlert("KonstapelPublicationFailing{}", "firing", time.Until(closed.Add(5*time.Minute)))
	pending, _ := m.alerts.reached("KonstapelPublicationFailing{}", "pending", phase)
	failedAttempts, _, _ := m.one(failQ)
	gauge, ok, d := m.one(`konstapel_publication_failed` + sel(""))
	if !ok || gauge != 1 || failedAttempts < 3 {
		t.Fatalf("publication failing without its inputs: gauge %v (%s), failed attempts %v", gauge, d, failedAttempts)
	}
	if firing.After(closed.Add(5 * time.Minute)) {
		t.Fatalf("PublicationFailing fired at %s, after the run's publish timeout %s", firing, closed.Add(5*time.Minute))
	}
	refused := m.proxy.state().Failed
	m.proxy.release()
	released = true
	recovered := time.Now()
	done := l.publishedRun(obsAudit, pubRun.Name)
	resolvedPub := m.waitAlert("KonstapelPublicationFailing{}", "inactive", 3*time.Minute)
	if v, ok, d := m.one(`konstapel_publication_failed` + sel("")); !ok || v != 0 {
		t.Fatalf("publication failure gauge after the commit: %s", d)
	}
	l.record("publication-failing", map[string]any{"run": pubRun.Name, "closed": closed.UTC(), "pendingAfterClosureSeconds": pending.Sub(closed).Seconds(),
		"firingAfterClosureSeconds": firing.Sub(closed).Seconds(), "publishTimeoutSeconds": 300, "failedAttempts15m": failedAttempts, "requestsRefused": refused,
		"committedAfterReleaseSeconds": done.Status.Publication.PublishedAt.Sub(recovered).Seconds(), "resolvedAfterReleaseSeconds": resolvedPub.Sub(recovered).Seconds(),
		"phase": done.Status.Phase})

	// 2. The unresolved binding, critical as configured.
	m.waitAlert("KonstapelBindingUnresolved{binding=obs-unresolved}", "firing", 4*time.Minute)
	unresolvedAt, _ := m.alerts.reached("KonstapelBindingUnresolved{binding=obs-unresolved}", "firing", phase)
	_, al := m.alerts.state("KonstapelBindingUnresolved{binding=obs-unresolved}")
	if al.Labels["severity"] != "critical" {
		t.Fatalf("BindingUnresolved severity %q, configured critical", al.Labels["severity"])
	}
	l.record("binding-unresolved", map[string]any{"firingAfterFailuresStartedSeconds": unresolvedAt.Sub(phase).Seconds(), "severity": "critical"})

	// 3. Cleanup blocked, and the binding deletion and recreation (6.3)
	// while it is.
	blockedAt := m.waitAlert("KonstapelCleanupBlocked{}", "firing", 6*time.Minute)
	blockedRun := l.run(held.Name)
	if blockedRun.Status.Publication.Cleanup.State != v1alpha1.CleanupState(publication.CleanupRetentionBlocked) {
		t.Fatalf("held package cleanup: %s", toJSON(blockedRun.Status.Publication.Cleanup))
	}
	if v, ok, d := m.one(`konstapel_cleanup_blocked` + sel("")); !ok || v < 1 {
		t.Fatalf("cleanup_blocked: %s", d)
	}
	l.record("cleanup-blocked", map[string]any{"run": held.Name, "state": blockedRun.Status.Publication.Cleanup.State, "attempts": blockedRun.Status.Publication.Cleanup.Attempts,
		"firingAfterExpirySeconds": blockedAt.Sub(held.Status.Publication.ExpiresAt.Time).Seconds()})
	m.recreate()
	legalHold(s3types.ObjectLockLegalHoldStatusOff)
	lifted = true
	m.held, m.liftedAt = held.Name, time.Now()

	// 4. Evidence expiry while reporting is stopped.
	m.expiry(kyvernoDown, expiryBefore)
	l.scaleKyverno("kyverno-reports-controller", 1)
	l.scaleKyverno("kyverno-background-controller", 1)
	scaledDown = false
	resumed := time.Now()
	m.wait("obs-expiry current again after reporting resumed", 4*time.Minute, func() (bool, string) {
		st, d := m.byLabel(`konstapel_binding_assessment_status`+sel(`,binding="obs-expiry",view="current"`)+` == 1`, "status")
		pass, ok, _ := m.one(`konstapel_binding_assessment_checks` + sel(`,binding="obs-expiry",view="current",state="pass"`))
		ahead, ok2, _ := m.one(`konstapel_binding_current_evidence_expiry_timestamp_seconds` + sel(`,binding="obs-expiry"`) + ` - time()`)
		return st["known"] == 1 && ok && pass == 1 && ok2 && ahead > 0, d
	})
	l.record("evidence-current-again", map[string]any{"afterResumeSeconds": time.Since(resumed).Seconds()})

}

// cleanupRecovered checks, after later phases ran meanwhile, that lifting
// the legal hold let the next backed-off deletion attempt remove the
// package and resolved KonstapelCleanupBlocked.
func (m *obsRun) cleanupRecovered() {
	l := m.l
	l.t.Helper()
	m.wait("held package deleted after the hold was lifted", 9*time.Minute, func() (bool, string) {
		r := l.run(m.held)
		return r != nil && r.Status.Publication.Cleanup.State == v1alpha1.CleanupState(publication.CleanupDeleted), toJSON(r.Status.Publication.Cleanup)
	})
	resolved := m.waitAlert("KonstapelCleanupBlocked{}", "inactive", 3*time.Minute)
	deletedRun := l.run(m.held)
	l.record("cleanup-recovered", map[string]any{"run": m.held, "attempts": deletedRun.Status.Publication.Cleanup.Attempts,
		"deletedAfterLiftSeconds":       deletedRun.Status.Publication.Cleanup.LastAttempt.Sub(m.liftedAt).Seconds(),
		"alertInactiveAfterLiftSeconds": resolved.Sub(m.liftedAt).Seconds()})
}

// recreate (6.3) deletes obs-sched while its retained package's cleanup is
// blocked, then creates a binding with the same name: the old object's
// series disappear, the global backlog (and its alert) outlives it, and the
// new object starts without the old one's runs or values.
func (m *obsRun) recreate() {
	l, t := m.l, m.l.t
	t.Helper()
	created, ok, d := m.one(`konstapel_binding_created_timestamp_seconds` + sel(`,binding="obs-sched"`))
	if !ok {
		t.Fatalf("obs-sched creation time: %s", d)
	}
	old := l.binding(obsSched)
	oldClosed, _, _ := m.one(`konstapel_binding_last_closed_timestamp_seconds` + sel(`,binding="obs-sched"`))
	if err := l.c.Delete(l.ctx, old); err != nil {
		t.Fatal(err)
	}
	deleted := time.Now()
	l.eventually("obs-sched deleted", func() (bool, string) {
		err := l.c.Get(l.ctx, client.ObjectKey{Name: obsSched}, &v1alpha1.ComplianceBinding{})
		return apierrors.IsNotFound(err), fmt.Sprint(err)
	})
	gone := m.wait("every obs-sched series gone", 2*time.Minute, func() (bool, string) {
		return m.none(`{__name__=~"konstapel_binding_.+",` + obsScope + `,binding="obs-sched"}`)
	})
	if v, ok, d := m.one(`konstapel_cleanup_blocked` + sel("")); !ok || v < 1 {
		t.Fatalf("blocked cleanup did not outlive its binding: %s", d)
	}
	if s, _ := m.alerts.state("KonstapelCleanupBlocked{}"); s != "firing" {
		t.Fatalf("CleanupBlocked %s after the binding was deleted", s)
	}
	m.createBinding(obsSched, m.scheduled.DeepCopy())
	cur := l.binding(obsSched)
	m.wait("recreated obs-sched exposed as the new object", 3*time.Minute, func() (bool, string) {
		s, err := m.query(`konstapel_binding_created_timestamp_seconds` + sel(`,binding="obs-sched"`))
		if err != nil || len(s) != 1 || s[0].Value <= created {
			return false, toJSON(s)
		}
		// The new object never shows the old one's latest closed run.
		latest, err := m.query(`konstapel_binding_last_closed_timestamp_seconds` + sel(`,binding="obs-sched"`))
		if err != nil || len(latest) > 1 || (len(latest) == 1 && latest[0].Value <= float64(deleted.Unix())) {
			return false, toJSON(latest)
		}
		counts, err := m.query(`count by (view) (konstapel_binding_assessment_status` + sel(`,binding="obs-sched"`) + ` == 1)`)
		if err != nil || len(counts) != 2 || counts[0].Value != 1 || counts[1].Value != 1 {
			return false, toJSON(counts)
		}
		return true, ""
	})
	if old.UID == cur.UID {
		t.Fatal("recreated binding kept the UID")
	}
	l.record("binding-recreated", map[string]any{"oldUID": old.UID, "newUID": cur.UID, "seriesGoneAfterDeleteSeconds": gone.Seconds(),
		"oldLastClosed": oldClosed, "backlogOutlivedBinding": true, "cleanupBlockedStillFiring": true})
}

// expiry checks obs-expiry's current evidence after its expiry while
// Kyverno's reporting is stopped: never a current pass, the expiry
// queryable and passed (or the owner already re-evaluated it as rejected),
// and a run closed afterwards counts the aged observation as rejected.
func (m *obsRun) expiry(down time.Time, before float64) {
	l, t := m.l, m.l.t
	t.Helper()
	var view string
	m.wait("obs-expiry current evidence past its expiry", 4*time.Minute, func() (bool, string) {
		exp, hasExp, _ := m.one(`konstapel_binding_current_evidence_expiry_timestamp_seconds` + sel(`,binding="obs-expiry"`))
		if hasExp && exp > float64(time.Now().Unix()) {
			return false, fmt.Sprintf("expiry %v ahead", exp)
		}
		st, d := m.byLabel(`konstapel_binding_assessment_status`+sel(`,binding="obs-expiry",view="current"`)+` == 1`, "status")
		counts, _ := m.byLabel(`konstapel_binding_assessment_checks`+sel(`,binding="obs-expiry",view="current"`), "state")
		switch {
		case st["unknown"] == 1 && len(counts) == 0:
			view = "unknown at its expiry"
		case st["known"] == 1 && counts["rejected"] == 1 && counts["pass"] == 0:
			view = "re-evaluated: rejected"
		default:
			return false, d + toJSON(counts)
		}
		return true, ""
	})
	expiredAt := time.Now()
	// It stays that way: never a current pass while nothing is evaluated.
	for end := time.Now().Add(20 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Second) {
		if v, ok, _ := m.one(`konstapel_binding_assessment_checks` + sel(`,binding="obs-expiry",view="current",state="pass"`)); ok && v > 0 {
			t.Fatalf("stale evidence counted as a current pass after its expiry")
		}
	}
	cur := l.binding(obsExpiry).Status.Assessment.Current
	run := l.createRun(obsExpiry, "obs-expiry-aged")
	closed := l.publishedRun(obsExpiry, run.Name)
	m.wait("latest closed run counts the aged evidence as rejected", 2*time.Minute, func() (bool, string) {
		c, d := m.byLabel(`konstapel_binding_assessment_checks`+sel(`,binding="obs-expiry",view="latest_closed"`), "state")
		complete, ok, _ := m.one(`konstapel_binding_assessment_complete` + sel(`,binding="obs-expiry",view="latest_closed"`))
		last, ok2, _ := m.one(`konstapel_binding_last_closed_timestamp_seconds` + sel(`,binding="obs-expiry"`))
		return c["rejected"] == 1 && c["pass"] == 0 && ok && complete == 0 && ok2 && int64(last) == closed.Status.Window.Closed.Unix(), d
	})
	l.record("evidence-expiry", map[string]any{"kyvernoStopped": down.UTC(), "expiryBefore": time.Unix(int64(before), 0).UTC(), "maxEvidenceAgeSeconds": obsExpiryMaxAge,
		"currentView": view, "observedAfterStopSeconds": expiredAt.Sub(down).Seconds(), "ownerCurrent": cur, "agedRun": run.Name,
		"agedRunEvidence": closed.Status.Summary.Evidence})
}

// engine (6.2) removes the controller's access to policy reports: the
// assessment capability turns false while policy delivery stays true, the
// scheduler stops starting runs, and obs-sched's due time passes. Both
// alerts fire, delivery never does, current evidence is never shown as
// passing, and both resolve once access returns.
func (m *obsRun) engine() {
	l, t := m.l, m.l.t
	t.Helper()
	role := &rbacv1.ClusterRole{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: "konstapel-controller"}, role); err != nil {
		t.Fatal(err)
	}
	full := slices.Clone(role.Rules)
	setRules := func(rules []rbacv1.PolicyRule) {
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			r := &rbacv1.ClusterRole{}
			if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(role), r); err != nil {
				return err
			}
			r.Rules = rules
			return l.c.Update(l.ctx, r)
		}); err != nil {
			t.Fatal(err)
		}
	}
	restored := false
	t.Cleanup(func() {
		if !restored {
			setRules(full)
		}
	})
	setRules(slices.DeleteFunc(slices.Clone(full), func(r rbacv1.PolicyRule) bool { return slices.Contains(r.APIGroups, "wgpolicyk8s.io") }))
	lost := time.Now()
	engineAt := m.waitAlert("KonstapelEngineUnavailable{capability=assessment}", "firing", 4*time.Minute)
	if v, ok, d := m.one(`konstapel_capability_condition` + sel(`,capability="policy_delivery",status="true"`)); !ok || v != 1 {
		t.Fatalf("policy delivery not reported available while only reporting access is lost: %s", d)
	}
	if pass, ok, _ := m.one(`konstapel_binding_assessment_checks` + sel(`,binding="obs-sched",view="current",state="pass"`)); ok && pass > 0 {
		t.Fatal("current evidence counted as passing without access to policy reports")
	}
	overdueAt := m.waitAlert("KonstapelAssessmentOverdue{binding=obs-sched}", "firing", 6*time.Minute)
	due, _, _ := m.one(`konstapel_binding_scheduled_due_timestamp_seconds` + sel(`,binding="obs-sched"`))
	setRules(full)
	restored = true
	back := time.Now()
	engineOK := m.waitAlert("KonstapelEngineUnavailable{capability=assessment}", "inactive", 4*time.Minute)
	overdueOK := m.waitAlert("KonstapelAssessmentOverdue{binding=obs-sched}", "inactive", 5*time.Minute)
	if _, ok := m.alerts.reached("KonstapelEngineUnavailable{capability=policy_delivery}", "pending", lost); ok {
		t.Fatal("policy delivery was reported unavailable while only reporting access was lost")
	}
	l.record("engine-reporting-lost", map[string]any{"engineFiringAfterSeconds": engineAt.Sub(lost).Seconds(), "overdueFiringAfterSeconds": overdueAt.Sub(lost).Seconds(),
		"dueAtFiring": time.Unix(int64(due), 0).UTC(), "overdueGraceSeconds": obsOverdueGrace, "collectionTimeoutSeconds": obsCollectTimeout,
		"engineResolvedAfterRestoreSeconds": engineOK.Sub(back).Seconds(), "overdueResolvedAfterRestoreSeconds": overdueOK.Sub(back).Seconds(),
		"policyDelivery": "true throughout, never pending"})
}

// bindingValues snapshots one owner gauge per binding.
func (m *obsRun) bindingValues(metric string) map[string]float64 {
	v, _ := m.byLabel(metric+sel(""), "binding")
	return v
}

// leaderKilled (6.3) force-deletes the leader pod while a run is in
// flight: the other replica takes the Lease, reconstructs and becomes the
// only owner; every binding is exposed once with the same values; the
// killed pod's series are gone, its replacement exposes no summaries and
// fresh counters; and the run completes.
func (m *obsRun) leaderKilled() {
	l, t := m.l, m.l.t
	t.Helper()
	before := map[string]map[string]float64{}
	for _, metric := range []string{"konstapel_binding_created_timestamp_seconds", "konstapel_binding_target_namespaces", "konstapel_binding_assessment_interval_seconds"} {
		before[metric] = m.bindingValues(metric)
	}
	run := l.createRun(obsAudit, "obs-audit-handover")
	killed, follower := l.killLeader(m.ns)
	start := time.Now()
	successor := l.leaderPod(m.ns, killed)
	if successor != follower {
		t.Fatalf("Lease taken by %s, not the remaining replica %s", successor, follower)
	}
	leased := time.Since(start)
	owned := m.soleOwner(successor, 3*time.Minute)
	m.wait("the killed leader's series gone", 2*time.Minute, func() (bool, string) {
		return m.none(`{__name__=~"konstapel_.+",` + obsScope + `,pod="` + killed + `"}`)
	})
	for metric, want := range before {
		m.wait(metric+" equal after the handover, once per binding", 2*time.Minute, func() (bool, string) {
			s, err := m.query(metric + sel(""))
			if err != nil {
				return false, err.Error()
			}
			got := map[string]float64{}
			for _, x := range s {
				if _, dup := got[x.Metric["binding"]]; dup || x.Metric["pod"] != successor {
					return false, "duplicate or non-owner series: " + toJSON(s)
				}
				got[x.Metric["binding"]] = x.Value
			}
			return toJSON(got) == toJSON(want), toJSON(got) + " want " + toJSON(want)
		})
	}
	var replacement string
	m.wait("a replacement replica scraped", 3*time.Minute, func() (bool, string) {
		for name := range m.controllerPods() {
			if name != killed && name != successor {
				replacement = name
			}
		}
		if replacement == "" {
			return false, "no replacement pod"
		}
		up, ok, d := m.one(`up` + sel(`,pod="`+replacement+`"`))
		return ok && up == 1, d
	})
	if ok, d := m.none(`{__name__=~"konstapel_binding_.+|konstapel_publication_.+|konstapel_cleanup_.+",` + obsScope + `,pod="` + replacement + `"}`); !ok {
		t.Fatalf("the replacement follower exposes owner series: %s", d)
	}
	if v, ok, d := m.one(`sum(konstapel_operation_attempts_total` + sel(`,pod="`+replacement+`"`) + `)`); !ok || v != 0 {
		t.Fatalf("the replacement's counters do not start at zero: %s", d)
	}
	if ready, _ := m.byLabel(`konstapel_observation_ready`+sel(`,pod="`+replacement+`"`), "domain"); len(ready) != 4 || slices.ContainsFunc(slices.Collect(maps.Values(ready)), func(v float64) bool { return v != 0 }) {
		t.Fatalf("the replacement follower reports readiness: %v", ready)
	}
	done := l.publishedRun(obsAudit, run.Name)
	lease := l.lease(m.ns)
	l.record("leader-killed", map[string]any{"killed": killed, "successor": successor, "replacement": replacement, "leaseTakenAfterSeconds": leased.Seconds(),
		"soleOwnerAfterSeconds": (leased + owned).Seconds(), "leaseTransitions": transitions(lease),
		"runCompleted": done.Name, "valuesUnchanged": before})
}

// noLeader (6.2 availability, 6.3 restart) removes the controller's Lease
// access: the leader cannot renew, exits on leadership loss and restarts;
// no replica can lead. Every target still scrapes, but no enabled domain
// has an owner: KonstapelObservationUnavailable fires for exactly the
// three enabled domains, no binding or backlog series is exposed (no
// healthy-looking zeros), and the firing BindingUnresolved resolves although
// nothing recovered. The restarted process's counters reset. Restoring
// access brings one owner back; BindingUnresolved fires again after its
// full hold and resolves only when its profile exists.
func (m *obsRun) noLeader() {
	l, t := m.l, m.l.t
	t.Helper()
	const unresolved = "KonstapelBindingUnresolved{binding=obs-unresolved}"
	m.waitAlert(unresolved, "firing", 3*time.Minute)
	leader := l.leaderPod(m.ns, "")
	pods := m.controllerPods()
	// The leader's process-local counters must be above zero, so that its
	// restart shows as a counter reset.
	l.publishedRun(obsAudit, l.createRun(obsAudit, "obs-audit-counted").Name)
	var counted float64
	m.wait("the leader's attempt counters scraped above zero", 2*time.Minute, func() (bool, string) {
		v, ok, d := m.one(`sum(konstapel_operation_attempts_total` + sel(`,pod="`+leader+`"`) + `)`)
		counted = v
		return ok && v > 0, d
	})
	role := &rbacv1.Role{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: m.ns, Name: "konstapel-controller"}, role); err != nil {
		t.Fatal(err)
	}
	full := slices.Clone(role.Rules)
	setRules := func(rules []rbacv1.PolicyRule) {
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			r := &rbacv1.Role{}
			if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(role), r); err != nil {
				return err
			}
			r.Rules = rules
			return l.c.Update(l.ctx, r)
		}); err != nil {
			t.Fatal(err)
		}
	}
	restored := false
	t.Cleanup(func() {
		if !restored {
			setRules(full)
		}
	})
	setRules(slices.DeleteFunc(slices.Clone(full), func(r rbacv1.PolicyRule) bool { return slices.Contains(r.APIGroups, "coordination.k8s.io") }))
	lost := time.Now()
	restartedAfter := m.wait("the leader restarted after losing the Lease", 3*time.Minute, func() (bool, string) {
		p, ok := m.controllerPods()[leader]
		return ok && restarts(p) > restarts(pods[leader]), l.podDiagnostics(m.ns)
	})
	m.wait("both replicas scraped, neither owning anything", 3*time.Minute, func() (bool, string) {
		up, _ := m.byLabel(`up`+sel(""), "pod")
		ready, d := m.query(`konstapel_observation_ready` + sel("") + ` == 1`)
		return len(up) == len(pods) && !slices.Contains(slices.Collect(maps.Values(up)), 0) && d == nil && len(ready) == 0, toJSON(up) + toJSON(ready)
	})
	for _, d := range obsDomains {
		m.waitAlert("KonstapelObservationUnavailable{domain="+d+"}", "firing", 4*time.Minute)
	}
	unobservable := time.Now()
	// No fabricated healthy data while nothing is owned.
	if ok, d := m.none(`{__name__=~"konstapel_binding_.+|konstapel_capability_.+|konstapel_publication_.+|konstapel_cleanup_.+",` + obsScope + `}`); !ok {
		t.Fatalf("owner series exposed without an owner: %s", d)
	}
	if s, _ := m.alerts.state("KonstapelObservationUnavailable{domain=bundle_resolution}"); s != "inactive" {
		t.Fatalf("the disabled bundle domain alerts: %s", s)
	}
	m.waitAlert(unresolved, "inactive", 2*time.Minute)
	if c := meta.FindStatusCondition(l.binding(obsUnresolved).Status.Conditions, v1alpha1.ConditionResolved); c == nil || c.Status == metav1.ConditionTrue {
		t.Fatalf("obs-unresolved resolved meanwhile: %s", toJSON(c))
	}
	resets, ok, _ := m.one(`sum(resets(konstapel_operation_attempts_total` + sel(`,pod="`+leader+`"`) + `[15m]))`)
	if !ok || resets < 1 {
		t.Fatalf("the restarted process's counters (%v before) show no reset", counted)
	}
	if s, _ := m.alerts.state("KonstapelPublicationFailing{}"); s != "inactive" {
		t.Fatalf("a counter reset made PublicationFailing %s", s)
	}
	setRules(full)
	restored = true
	back := time.Now()
	// The expired Lease still names the restarted pod: wait for a renewal.
	var newLeader string
	l.eventually("the Lease acquired again", func() (bool, string) {
		lease := l.lease(m.ns)
		if lease == nil || lease.Spec.HolderIdentity == nil || lease.Spec.RenewTime == nil || !lease.Spec.RenewTime.After(back) {
			return false, toJSON(lease)
		}
		newLeader, _, _ = strings.Cut(*lease.Spec.HolderIdentity, "_")
		_, running := m.controllerPods()[newLeader]
		return running, newLeader
	})
	owned := m.soleOwner(newLeader, 3*time.Minute)
	for _, d := range obsDomains {
		m.waitAlert("KonstapelObservationUnavailable{domain="+d+"}", "inactive", 3*time.Minute)
	}
	again := m.waitAlert(unresolved, "firing", 4*time.Minute)
	if again.Sub(back) < time.Minute {
		t.Fatalf("BindingUnresolved fired %s after the owner returned, inside its 1m hold", again.Sub(back))
	}
	missing := profileObj(t, obsMissingProfile, pol)
	missing.SetUID("")
	l.createWhenServed(missing)
	l.eventually("obs-unresolved resolved", func() (bool, string) {
		b := l.binding(obsUnresolved)
		c := meta.FindStatusCondition(b.Status.Conditions, v1alpha1.ConditionResolved)
		return c != nil && c.Status == metav1.ConditionTrue && c.ObservedGeneration == b.Generation, toJSON(b.Status.Conditions)
	})
	resolved := m.waitAlert(unresolved, "inactive", 3*time.Minute)
	l.record("no-leader", map[string]any{"formerLeader": leader, "restartedAfterSeconds": restartedAfter.Seconds(), "unobservableAfterSeconds": unobservable.Sub(lost).Seconds(),
		"countersBefore": counted, "resets": resets, "newLeader": newLeader, "ownerBackAfterSeconds": owned.Seconds(),
		"bindingUnresolvedRefiredAfterSeconds": again.Sub(back).Seconds(), "resolvedAfterProfileSeconds": time.Since(resolved).Seconds(),
		"ownerSeriesWhileUnobservable": 0, "bundleResolution": "never alerted"})
}

// certRotation (6.3) reissues the metrics certificate in place as
// cert-manager's manual renewal does: the controller serves the new leaf
// without a restart and Prometheus, trusting the unchanged CA, keeps every
// scrape successful.
func (m *obsRun) certRotation() {
	l, t := m.l, m.l.t
	t.Helper()
	secret := &corev1.Secret{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: m.ns, Name: "konstapel-controller-metrics-tls"}, secret); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(secret.Data["ca.crt"])
	addr := l.portForward(m.ns, "service/konstapel-controller-metrics", 443)
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
	pods := m.controllerPods()
	crt := &unstructured.Unstructured{}
	crt.SetGroupVersionKind(schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"})
	start := time.Now()
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: m.ns, Name: "konstapel-controller-metrics"}, crt); err != nil {
			return err
		}
		conds, _, _ := unstructured.NestedSlice(crt.Object, "status", "conditions")
		conds = slices.DeleteFunc(conds, func(c any) bool { cm, _ := c.(map[string]any); return cm["type"] == "Issuing" })
		conds = append(conds, map[string]any{"type": "Issuing", "status": "True", "reason": "ManuallyTriggered",
			"message": "Certificate re-issuance manually triggered", "lastTransitionTime": start.UTC().Format(time.RFC3339), "observedGeneration": crt.GetGeneration()})
		if err := unstructured.SetNestedSlice(crt.Object, conds, "status", "conditions"); err != nil {
			return err
		}
		return l.c.Status().Update(l.ctx, crt)
	}); err != nil {
		t.Fatal(err)
	}
	var after string
	served := m.wait("the reissued metrics certificate served", 3*time.Minute, func() (bool, string) {
		s, err := serial()
		after = s
		return err == nil && s != before, fmt.Sprint(s, err)
	})
	// Two more scrape intervals, then every target must have scraped
	// successfully throughout the rotation.
	time.Sleep(35 * time.Second)
	window := int(time.Since(start).Seconds()) + 1
	m.wait("every scrape successful through the rotation", time.Minute, func() (bool, string) {
		s, err := m.query(fmt.Sprintf(`min_over_time(up%s[%ds])`, sel(""), window))
		if err != nil || len(s) != len(pods) {
			return false, toJSON(s)
		}
		for _, x := range s {
			if x.Value != 1 {
				return false, toJSON(s)
			}
		}
		return true, ""
	})
	for name, p := range m.controllerPods() {
		if q, ok := pods[name]; !ok || q.UID != p.UID || restarts(q) != restarts(p) {
			t.Fatalf("controller pod %s restarted or was replaced for the rotation", name)
		}
	}
	l.record("certificate-rotation", map[string]any{"serialBefore": before, "serialAfter": after, "servedAfterSeconds": served.Seconds(),
		"scrapesFailedDuringRotation": 0, "windowSeconds": window, "restarts": 0})
}

// boundToken returns a token for the ServiceAccount bound to a new anchor
// Secret: deleting the anchor revokes the token.
func (l *live) boundToken(ns, sa, anchor string) (string, *corev1.Secret) {
	l.t.Helper()
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: anchor}}
	if err := l.c.Create(l.ctx, s); err != nil {
		l.t.Fatal(err)
	}
	tr := &authnv1.TokenRequest{Spec: authnv1.TokenRequestSpec{BoundObjectRef: &authnv1.BoundObjectReference{Kind: "Secret", APIVersion: "v1", Name: anchor, UID: s.UID}}}
	if err := l.c.SubResource("token").Create(l.ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: sa}}, tr); err != nil {
		l.t.Fatal(err)
	}
	return tr.Status.Token, s
}

// scrapeWith scrapes one replica behind the metrics Service with token.
func scrapeWith(addr, token string, roots *x509.CertPool) (int, error) {
	c := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: metricsServiceName}}}
	req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// tokenRotation (6.3) rotates the reader token the Secret-mode
// ServiceMonitor uses: a new bound token goes into the Secret, and after
// the Operator and kubelet propagated it, the old token is revoked by
// deleting its anchor. The controller refuses the old token within the
// 1-minute authentication cache; Prometheus keeps scraping with the new one.
func (m *obsRun) tokenRotation(monNS string, oldAnchor *corev1.Secret, oldToken string) {
	l, t := m.l, m.l.t
	t.Helper()
	newToken, _ := l.boundToken(monNS, "prometheus", "obs-reader-anchor-1")
	secret := &corev1.Secret{}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: m.ns, Name: "obs-reader-token"}, secret); err != nil {
			return err
		}
		secret.Data = map[string][]byte{"token": []byte(newToken)}
		return l.c.Update(l.ctx, secret)
	}); err != nil {
		t.Fatal(err)
	}
	rotated := time.Now()
	// Meanwhile, the certificate rotation (it also needs a scrape window).
	m.certRotation()
	if wait := 150*time.Second - time.Since(rotated); wait > 0 {
		time.Sleep(wait) // Operator and kubelet propagation of the Secret
	}
	tlsSecret := &corev1.Secret{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: m.ns, Name: "konstapel-controller-metrics-tls"}, tlsSecret); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(tlsSecret.Data["ca.crt"])
	addr := l.portForward(m.ns, "service/konstapel-controller-metrics", 443)
	if code, err := scrapeWith(addr, oldToken, roots); err != nil || code != http.StatusOK {
		t.Fatalf("old token before its revocation: %d %v", code, err)
	}
	if err := l.c.Delete(l.ctx, oldAnchor); err != nil {
		t.Fatal(err)
	}
	revoked := time.Now()
	var refused int
	m.wait("the revoked token refused", 2*time.Minute, func() (bool, string) {
		code, err := scrapeWith(addr, oldToken, roots)
		refused = code
		return err == nil && code != http.StatusOK, fmt.Sprint(code, err)
	})
	refusedAfter := time.Since(revoked)
	// Past the authentication cache and two scrapes, Prometheus still
	// scrapes every replica: it uses the new token.
	downSeen := 0
	m.wait("Prometheus scraping with the rotated token", 4*time.Minute, func() (bool, string) {
		all, err := promTargets(m.prom)
		pool := poolTargets(all, chartPool)
		fresh := 0
		for _, tg := range pool {
			if tg.Health != "up" {
				downSeen++
			} else if tg.LastScrape.After(revoked.Add(75 * time.Second)) {
				fresh++
			}
		}
		return err == nil && len(pool) == len(m.controllerPods()) && fresh == len(pool), toJSON(pool)
	})
	l.record("token-rotation", map[string]any{"rotatedToRevokedSeconds": revoked.Sub(rotated).Seconds(), "oldTokenRefusedAfterSeconds": refusedAfter.Seconds(),
		"oldTokenStatus": refused, "authenticationCacheSeconds": 60, "targetsDownObserved": downSeen})
}

// revocation (6.3) deletes the reader binding while a replica is replaced
// and controller work continues: every target is refused (403) within the
// pinned 5-minute allow cache, the new replica at once; with no successful
// scrape KonstapelMetricsUnavailable fires; a run still publishes; and
// restoring the binding brings every target back within the 30-second
// denial cache and resolves the alert.
func (m *obsRun) revocation() {
	l, t := m.l, m.l.t
	t.Helper()
	crb := &rbacv1.ClusterRoleBinding{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: "konstapel-metrics-reader"}, crb); err != nil {
		t.Fatal(err)
	}
	saved := crb.DeepCopy()
	if err := l.c.Delete(l.ctx, crb); err != nil {
		t.Fatal(err)
	}
	revoked := time.Now()
	restored := false
	restore := func() {
		c := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: saved.Name, Labels: saved.Labels, Annotations: saved.Annotations},
			RoleRef: saved.RoleRef, Subjects: saved.Subjects}
		if err := l.c.Create(l.ctx, c); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if !restored {
			restore()
		}
	})
	// A replica is replaced meanwhile: its successor has no cached answer.
	leader := l.leaderPod(m.ns, "")
	var follower string
	for name := range m.controllerPods() {
		if name != leader {
			follower = name
		}
	}
	l.forceDelete(m.ns, follower)
	run := l.createRun(obsAudit, "obs-audit-unmonitored")
	replicas := 2
	var denied time.Duration
	for {
		all, err := promTargets(m.prom)
		pool, down := poolTargets(all, chartPool), 0
		for _, tg := range pool {
			if tg.Health == "down" && strings.Contains(tg.LastError, "403") {
				down++
			}
		}
		if err == nil && len(pool) == replicas && down == replicas && !slices.ContainsFunc(pool, func(tg promTarget) bool { return tg.Labels["pod"] == follower }) {
			denied = time.Since(revoked)
			break
		}
		if time.Since(revoked) > 5*time.Minute+45*time.Second {
			t.Fatalf("revoked Prometheus still scrapes %s after revocation: %v %s", time.Since(revoked), err, toJSON(pool))
		}
		time.Sleep(5 * time.Second)
	}
	unavailable := m.waitAlert("KonstapelMetricsUnavailable{}", "firing", 3*time.Minute)
	// Controller work went on while nothing could be scraped.
	done := l.publishedRun(obsAudit, run.Name)
	restore()
	restored = true
	back := time.Now()
	upAgain := m.wait("every target scraped again", 3*time.Minute, func() (bool, string) {
		all, err := promTargets(m.prom)
		pool, up := poolTargets(all, chartPool), 0
		for _, tg := range pool {
			if tg.Health == "up" && tg.LastScrape.After(back) {
				up++
			}
		}
		return err == nil && len(pool) == replicas && up == replicas, toJSON(pool)
	})
	resolved := m.waitAlert("KonstapelMetricsUnavailable{}", "inactive", 3*time.Minute)
	l.record("revocation", map[string]any{"seconds": denied.Seconds(), "boundSeconds": 300, "replacedReplica": follower,
		"metricsUnavailableFiringAfterSeconds": unavailable.Sub(revoked).Seconds(), "runPublishedWhileUnmonitored": done.Name,
		"runPublishedAfterRevocationSeconds": done.Status.Publication.PublishedAt.Sub(revoked).Seconds(),
		"scrapesBackAfterRestoreSeconds":     upAgain.Seconds(), "alertResolvedAfterRestoreSeconds": resolved.Sub(back).Seconds(), "denialCacheSeconds": 30})
}
