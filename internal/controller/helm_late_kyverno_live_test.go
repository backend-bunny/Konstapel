//go:build live

package controller

// Installed charts before Kyverno (add-helm-oci-distribution 6.2), driving
// Helm, the API server and the download Service of the packaged image only:
//   - the disposable cluster's Kyverno release is uninstalled, so its
//     policy and report APIs are not served;
//   - both charts install as documented and every controller and download
//     replica becomes ready without the engine;
//   - every CRD of the installed CRD chart is exercised through the API
//     server with the runtime chart's admission policies and roles: schema
//     defaults, invalid specs rejected with the documented reasons
//     (including the documented examples), status stripped from spec writes,
//     immutable fields, status writable only by the controller's
//     ServiceAccount and readable by the documented roles;
//   - a Deny binding reports the missing engine API, its evidence names the
//     limitation and establishes nothing, and the download server still
//     authenticates;
//   - Kyverno is installed with its original chart and values: without a
//     restart, upgrade or reinstall of either chart the binding delivers and
//     enforces and the limitation clears.
// Run through scripts/targeting-live.sh (charts acceptance group).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func TestLiveHelmLateKyverno(t *testing.T) {
	image, repo, imageDigest := liveImage(t)
	l := newLive(t)
	const ns = "konstapel-system"

	// 1. No Kyverno: its release is removed and is installed again, with the
	// same chart and values, if the test ends before step 5.
	kyverno := l.removeKyverno()
	l.record("kyverno-removed", map[string]any{"chart": filepath.Base(kyverno.chart)})

	// 2. Both charts install and every replica becomes ready.
	caPEM := l.installCharts(ns, repo, imageDigest)
	for _, p := range l.readyPods(ns, "controller", 2) {
		if p.Spec.Containers[0].Image != image {
			t.Fatalf("pod %s runs %s, not the packaged image %s", p.Name, p.Spec.Containers[0].Image, image)
		}
	}
	controllers, downloads := l.componentPods(ns, "controller"), l.downloadPods(ns)
	l.record("installed-without-kyverno", map[string]any{"controllers": slices.Sorted(maps.Keys(controllers)), "downloads": slices.Sorted(maps.Keys(downloads))})

	// 3. The CRD, admission and RBAC contract of the installed release.
	l.crdContract(ns)

	// 4. Delivery without the engine: the missing API is reported, nothing
	// is established, and the replicas keep serving.
	l.setNamespace("lk-prod", "lk-production")
	p := profileObj(t, "lk-baseline", pol)
	b := bindingObj("lk-deny", p.Name, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{envLabel: "lk-production"})
	for _, o := range []client.Object{p, b} {
		o.SetUID("")
		l.createWhenServed(o)
	}
	t.Cleanup(func() {
		_ = l.c.Delete(context.Background(), b)
		_ = l.c.Delete(context.Background(), p)
		_ = l.c.Delete(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "lk-prod"}})
	})
	var reason string
	l.within("the missing engine API reported on the binding", func() (bool, string) {
		c := meta.FindStatusCondition(l.binding(b.Name).Status.Conditions, v1alpha1.ConditionEngineReady)
		if c == nil || c.Status != metav1.ConditionFalse || (c.Reason != ReasonEngineAPINotServed && c.Reason != ReasonEngineResourceMissing) {
			return false, toJSON(l.binding(b.Name).Status.Conditions)
		}
		reason = c.Reason
		return true, ""
	})
	const noEngine = "no engine policies or reports can be read"
	var absent *v1alpha1.CurrentEvidence
	l.within("evidence without the engine names the limitation and establishes nothing", func() (bool, string) {
		s := l.binding(b.Name).Status.Assessment
		if s == nil || s.Current == nil {
			return false, "no current assessment"
		}
		cur := s.Current
		absent = cur
		return slices.ContainsFunc(cur.Limitations, func(m string) bool { return strings.Contains(m, noEngine) }) &&
			cur.Evidence.Completeness != "Complete" && cur.Evidence.Attributable == 0, toJSON(cur)
	})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	hc := &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "konstapel-download." + ns + ".svc"}}}
	addr := l.portForward(ns, "svc/konstapel-download", 443)
	code, _ := fetch(t, hc, "https://"+addr+"/v1/assessmentruns/00000000-0000-0000-0000-000000000000/download", "")
	if code != http.StatusUnauthorized {
		t.Errorf("download server without Kyverno answered an unauthenticated request with %d, want 401", code)
	}
	l.samePods(ns, "controller", controllers, "without Kyverno")
	l.assertNoRestarts(ns, downloads)
	observed := map[string]any{"engineReady": reason, "unauthenticatedDownload": code}
	if absent != nil {
		observed["completeness"], observed["attributable"], observed["limitations"] = absent.Evidence.Completeness, absent.Evidence.Attributable, absent.Limitations
	}
	l.record("engine-absent", observed)

	// 5. Kyverno arrives. The installed release converges by itself.
	kyverno.install(l.ctx)
	l.waitReady(b.Name, 1)
	l.eventually("the late engine enforces the Deny binding", func() (bool, string) { return l.denied("lk-prod") })
	l.eventually("engine evidence readable", func() (bool, string) {
		s := l.binding(b.Name).Status.Assessment
		if s == nil || s.Current == nil {
			return false, "no current assessment"
		}
		return !slices.ContainsFunc(s.Current.Limitations, func(m string) bool {
			return strings.Contains(m, noEngine) || strings.Contains(m, "policy reports unavailable")
		}), toJSON(s.Current.Limitations)
	})
	l.samePods(ns, "controller", controllers, "after Kyverno arrived")
	l.assertNoRestarts(ns, downloads)
	revisions := map[string]int{}
	for _, release := range []string{"konstapel-crds", "konstapel"} {
		out, err := l.helmStdout(l.ctx, "status", release, "--namespace", ns, "--output", "json")
		var status struct {
			Version int `json:"version"`
		}
		if err != nil || json.Unmarshal([]byte(out), &status) != nil || status.Version != 1 {
			t.Fatalf("release %s changed while Kyverno arrived (want revision 1): %v %s", release, err, out)
		}
		revisions[release] = status.Version
	}
	l.record("engine-arrived", map[string]any{"policies": l.policiesFor(b.Name), "revisions": revisions, "restarts": 0})
}

// within is eventually for independent assertions: on timeout it reports an
// error and the test continues, so later steps still run.
func (l *live) within(what string, f func() (bool, string)) bool {
	l.t.Helper()
	deadline, last := time.Now().Add(3*time.Minute), ""
	for time.Now().Before(deadline) {
		ok, detail := f()
		if ok {
			return true
		}
		last = detail
		time.Sleep(2 * time.Second)
	}
	l.t.Errorf("timed out waiting for %s: %s", what, last)
	return false
}

// componentPods returns a component's pods and their restart counts.
func (l *live) componentPods(ns, component string) map[string]int32 {
	l.t.Helper()
	var pods corev1.PodList
	if err := l.c.List(l.ctx, &pods, client.InNamespace(ns), client.MatchingLabels{"app.kubernetes.io/component": component}); err != nil {
		l.t.Fatal(err)
	}
	out := map[string]int32{}
	for _, p := range pods.Items {
		if p.DeletionTimestamp != nil {
			continue
		}
		var n int32
		for _, c := range p.Status.ContainerStatuses {
			n += c.RestartCount
		}
		out[p.Name] = n
	}
	return out
}

// samePods fails unless the component runs the same, ready pods with the
// same restart counts.
func (l *live) samePods(ns, component string, before map[string]int32, when string) {
	l.t.Helper()
	ready := map[string]bool{}
	for _, p := range l.podsReady(ns, component) {
		ready[p.Name] = true
	}
	now := l.componentPods(ns, component)
	if !maps.Equal(now, before) || len(ready) != len(before) {
		l.t.Fatalf("%s pods changed, restarted or left readiness %s: before %v, now %v, ready %v", component, when, before, now, ready)
	}
}

// helmStdout runs the pinned Helm against the disposable cluster and
// returns its standard output only.
func (l *live) helmStdout(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "helm", append([]string{"--kubeconfig", os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"), "--kube-context", os.Getenv("KONSTAPEL_LIVE_CONTEXT")}, args...)...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return string(out), fmt.Errorf("%w: %s", err, stderr.String())
	}
	return string(out), nil
}

// kyvernoRelease is the disposable cluster's Kyverno release, as
// scripts/environment.sh installed it: the pinned, checksum-verified chart
// and the release's user-supplied values.
type kyvernoRelease struct {
	l             *live
	chart, values string
	installed     bool
}

// removeKyverno uninstalls the Kyverno release and waits until its APIs and
// webhooks are gone. Unless the test installs it again, a cleanup does.
func (l *live) removeKyverno() *kyvernoRelease {
	t := l.t
	t.Helper()
	path, err := exec.Command("bash", "../../scripts/fetch-chart.sh", "kyverno").Output()
	if err != nil {
		t.Fatalf("the pinned Kyverno chart: %v", err)
	}
	k := &kyvernoRelease{l: l, chart: filepath.Join("../..", strings.TrimSpace(string(path))), values: filepath.Join(t.TempDir(), "kyverno-values.yaml")}
	values, err := l.helmStdout(l.ctx, "get", "values", "kyverno", "--namespace", "kyverno", "--output", "yaml")
	if err != nil {
		t.Fatalf("Kyverno release values: %v", err)
	}
	if err := os.WriteFile(k.values, []byte(values), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if k.installed {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
		defer cancel()
		var status struct {
			Info struct {
				Status string `json:"status"`
			} `json:"info"`
		}
		if out, err := l.helmStdout(ctx, "status", "kyverno", "--namespace", "kyverno", "--output", "json"); err == nil && json.Unmarshal([]byte(out), &status) == nil && status.Info.Status == "deployed" {
			return
		}
		if out, err := l.helmStdout(ctx, "upgrade", "--install", "kyverno", k.chart, "--namespace", "kyverno", "-f", k.values, "--wait", "--timeout", "10m"); err != nil {
			t.Errorf("restoring the Kyverno release: %v\n%s", err, out)
		}
	})
	if out, err := l.helmStdout(l.ctx, "uninstall", "kyverno", "--namespace", "kyverno", "--wait", "--timeout", "5m"); err != nil {
		t.Fatalf("uninstall Kyverno: %v\n%s", err, out)
	}
	dc, err := discovery.NewDiscoveryClientForConfig(l.cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The chart's pre-delete hook removes the admission controller's
	// webhooks, so no workload request reaches a removed engine. The cleanup
	// controller's ttl and cleanup webhooks stay behind upstream; they match
	// only Kyverno's own cleanup resources and labels and are recorded.
	var lingering []string
	l.eventually("Kyverno's APIs and resource webhooks gone", func() (bool, string) {
		for _, gv := range []string{"policies.kyverno.io/v1", "wgpolicyk8s.io/v1alpha2"} {
			if _, err := dc.ServerResourcesForGroupVersion(gv); !apierrors.IsNotFound(err) {
				return false, gv + " still served: " + fmt.Sprint(err)
			}
		}
		var vwc admissionregistrationv1.ValidatingWebhookConfigurationList
		var mwc admissionregistrationv1.MutatingWebhookConfigurationList
		if err := l.c.List(l.ctx, &vwc); err != nil {
			return false, err.Error()
		}
		if err := l.c.List(l.ctx, &mwc); err != nil {
			return false, err.Error()
		}
		var left []string
		lingering = nil
		var names []string
		for _, w := range vwc.Items {
			names = append(names, w.Name)
		}
		for _, w := range mwc.Items {
			names = append(names, w.Name)
		}
		for _, name := range names {
			switch {
			case strings.HasPrefix(name, "kyverno-resource-"):
				left = append(left, name)
			case strings.HasPrefix(name, "kyverno-"):
				lingering = append(lingering, name)
			}
		}
		return len(left) == 0, fmt.Sprint(left)
	})
	l.record("kyverno-uninstalled", map[string]any{"lingeringWebhooks": lingering})
	return k
}

// install installs the release again and waits until its APIs are served.
func (k *kyvernoRelease) install(ctx context.Context) {
	l := k.l
	l.t.Helper()
	if out, err := l.helmStdout(ctx, "install", "kyverno", k.chart, "--namespace", "kyverno", "-f", k.values, "--wait", "--timeout", "10m"); err != nil {
		l.t.Fatalf("install Kyverno: %v\n%s", err, out)
	}
	k.installed = true
	dc, err := discovery.NewDiscoveryClientForConfig(l.cfg)
	if err != nil {
		l.t.Fatal(err)
	}
	l.eventually("Kyverno's APIs served", func() (bool, string) {
		want := map[string][]string{"policies.kyverno.io/v1": {"validatingpolicies"}, "wgpolicyk8s.io/v1alpha2": {"policyreports", "clusterpolicyreports"}}
		for gv, resources := range want {
			list, err := dc.ServerResourcesForGroupVersion(gv)
			if err != nil {
				return false, err.Error()
			}
			for _, r := range resources {
				if !slices.ContainsFunc(list.APIResources, func(a metav1.APIResource) bool { return a.Name == r }) {
					return false, gv + " lacks " + r
				}
			}
		}
		return true, ""
	})
}

// The contract identities: users bound to the installed chart's roles, a
// user with no Konstapel role, and the chart's ServiceAccounts.
const (
	lcTeam       = "lc-team"
	lcAdmin      = "lc-admin"
	lcViewer     = "lc-viewer"
	lcOperator   = "lc-operator"
	lcRequester  = "lc-requester"
	lcRegistrar  = "lc-registrar"
	lcReader     = "lc-reader"
	lcExceptions = "lc-exceptions"
	lcNobody     = "lc-nobody"
	lcController = "system:serviceaccount:konstapel-system:konstapel-controller"
	lcDownload   = "system:serviceaccount:konstapel-system:konstapel-download"
)

// lcCase is one shipped CRD: a minimal valid object created by an identity
// allowed to, the schema defaults and admission fields expected on it,
// invalid variants with the documented reasons, an update the API refuses,
// and the identities that may read its status.
type lcCase struct {
	resource  string
	namespace string
	creator   string
	valid     string
	expect    []lcField
	invalid   []lcInvalid
	immutable func(o map[string]any)
	refused   string
	readers   []string
}

type lcField struct {
	path []any
	want any
}

type lcInvalid struct {
	name string
	edit func(o map[string]any)
	want string
}

// set sets a field below o, creating maps on the way; an int indexes a list.
func lcSet(o map[string]any, value any, path ...any) {
	var cur any = o
	for i, p := range path {
		last := i == len(path)-1
		switch k := p.(type) {
		case string:
			m := cur.(map[string]any)
			if last {
				m[k] = value
				return
			}
			if _, ok := m[k]; !ok {
				m[k] = map[string]any{}
			}
			cur = m[k]
		case int:
			s := cur.([]any)
			if last {
				s[k] = value
				return
			}
			cur = s[k]
		}
	}
}

func lcDel(o map[string]any, path ...any) {
	var cur any = o
	for _, p := range path[:len(path)-1] {
		switch k := p.(type) {
		case string:
			cur = cur.(map[string]any)[k]
		case int:
			cur = cur.([]any)[k]
		}
	}
	delete(cur.(map[string]any), path[len(path)-1].(string))
}

func lcGet(o map[string]any, path ...any) any {
	var cur any = o
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				return nil
			}
			cur = m[k]
		case int:
			s, ok := cur.([]any)
			if !ok || k >= len(s) {
				return nil
			}
			cur = s[k]
		}
	}
	return cur
}

func lcObject(t *testing.T, doc string) map[string]any {
	t.Helper()
	o := map[string]any{}
	if err := yaml.Unmarshal([]byte(doc), &o); err != nil {
		t.Fatal(err)
	}
	return o
}

// injected is a status condition no controller writes.
var injected = map[string]any{"type": "LiveInjected", "status": "True", "reason": "Injected", "message": "written through the main resource", "lastTransitionTime": "2026-01-01T00:00:00Z"}

func hasInjected(o map[string]any) bool {
	conds, _ := lcGet(o, "status", "conditions").([]any)
	return slices.ContainsFunc(conds, func(c any) bool { m, _ := c.(map[string]any); return m["type"] == "LiveInjected" })
}

// lcCases covers every shipped CRD; crdContract fails if the chart ships
// another.
func lcCases(t *testing.T) []lcCase {
	bundle := fmt.Sprintf("{name: %s, digest: %q}", content.Name, digest(t))
	return []lcCase{{
		resource: "complianceprofiles", creator: lcAdmin, readers: []string{lcAdmin, lcViewer},
		valid: `
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceProfile
metadata: {name: lc-profile}
spec:
  bundle: ` + bundle + `
  policies: [{name: ` + pol + `}]`,
		expect: []lcField{{[]any{"spec", "policies", 0, "exceptions", "eligibility"}, "Forbidden"}},
		invalid: []lcInvalid{
			{"no policies", func(o map[string]any) { lcSet(o, []any{}, "spec", "policies") }, "should have at least 1 items"},
			{"self-service without a lifetime", func(o map[string]any) {
				lcSet(o, map[string]any{"eligibility": "SelfService"}, "spec", "policies", 0, "exceptions")
			}, "SelfService requires a positive maxLifetime"},
			{"malformed bundle digest", func(o map[string]any) { lcSet(o, "sha256:short", "spec", "bundle", "digest") }, "spec.bundle.digest"},
		},
	}, {
		resource: "compliancebindings", creator: lcAdmin, readers: []string{lcAdmin, lcViewer},
		valid: `
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata: {name: lc-binding}
spec:
  profileRef: {name: lc-profile}
  mode: Audit
  namespaceSelector: {matchLabels: {` + envLabel + `: lc-none}}`,
		expect: []lcField{
			{[]any{"spec", "assessment", "interval"}, "24h"},
			{[]any{"spec", "assessment", "collectionTimeout"}, "5m"},
			{[]any{"spec", "assessment", "maxEvidenceAge"}, "2h"},
			{[]any{"spec", "assessment", "retention"}, "2160h"},
			// konstapel-binding-enforcement-epoch (runtime chart)
			{[]any{"spec", "enforcementEpoch"}, int64(1)},
		},
		invalid: []lcInvalid{
			{"day interval", func(o map[string]any) { lcSet(o, "1d", "spec", "assessment", "interval") }, "must be a duration such as 24h, 90m or 2160h"},
			{"zero retention", func(o map[string]any) { lcSet(o, "0s", "spec", "assessment", "retention") }, "must be a positive duration"},
			{"unknown mode", func(o map[string]any) { lcSet(o, "Enforce", "spec", "mode") }, "spec.mode: Unsupported value"},
			{"no namespace selector", func(o map[string]any) { lcDel(o, "spec", "namespaceSelector") }, "spec.namespaceSelector: Required value"},
		},
	}, {
		resource: "evidencedestinations", creator: lcAdmin, readers: []string{lcAdmin, lcViewer},
		valid: `
apiVersion: compliance.erenius.io/v1alpha1
kind: EvidenceDestination
metadata: {name: lc-destination}
spec:
  s3:
    endpoint: https://s3.example.internal
    bucket: lc-evidence
    region: eu-north-1
    prefix: lc
    credentialSecret: {name: lc-s3}`,
		expect: []lcField{
			{[]any{"spec", "deletionPolicy"}, "Retire"},
			{[]any{"spec", "s3", "addressing"}, "path"},
			{[]any{"spec", "s3", "credentialSecret", "accessKeyIDKey"}, "accessKeyID"},
			{[]any{"spec", "s3", "credentialSecret", "secretAccessKeyKey"}, "secretAccessKey"},
		},
		invalid: []lcInvalid{
			{"plain http", func(o map[string]any) { lcSet(o, "http://s3.example.internal", "spec", "s3", "endpoint") }, "endpoint must be https"},
			{"two credential sources", func(o map[string]any) { lcSet(o, true, "spec", "s3", "workloadIdentity") }, "set exactly one credential source"},
			{"credentials in another namespace", func(o map[string]any) { lcSet(o, "other", "spec", "s3", "credentialSecret", "namespace") }, "references resolve in the controller namespace only"},
		},
		immutable: func(o map[string]any) { lcSet(o, "https://elsewhere.example.internal", "spec", "s3", "endpoint") },
		refused:   "endpoint, bucket, region, and prefix are immutable",
	}, {
		resource: "assessmentrequests", namespace: lcTeam, creator: lcRequester, readers: []string{lcOperator, lcRequester},
		valid: `
apiVersion: compliance.erenius.io/v1alpha1
kind: AssessmentRequest
metadata: {name: lc-request, namespace: ` + lcTeam + `}
spec:
  bindingRef: {name: lc-absent-binding}
  requester: {username: someone-else}`,
		// konstapel-assessment-requester (runtime chart) overwrites it.
		expect: []lcField{{[]any{"spec", "requester", "username"}, lcRequester}},
		invalid: []lcInvalid{
			{"no binding", func(o map[string]any) { lcDel(o, "spec", "bindingRef") }, "spec.bindingRef: Required value"},
			{"empty binding name", func(o map[string]any) { lcSet(o, "", "spec", "bindingRef", "name") }, "spec.bindingRef.name"},
		},
		immutable: func(o map[string]any) { lcSet(o, "lc-other-binding", "spec", "bindingRef", "name") },
		refused:   "spec is immutable; create a new AssessmentRequest",
	}, {
		resource: "assessmentruns", creator: lcOperator, readers: []string{lcOperator},
		valid: `
apiVersion: compliance.erenius.io/v1alpha1
kind: AssessmentRun
metadata: {name: lc-run}
spec:
  bindingRef: {name: lc-absent-binding}
  scope: Binding`,
		invalid: []lcInvalid{
			{"scheduled without a time", func(o map[string]any) { lcSet(o, map[string]any{"type": "Scheduled"}, "spec", "trigger") }, "scheduledTime is required for and only allowed on Scheduled triggers"},
			{"binding scope with a request", func(o map[string]any) {
				lcSet(o, map[string]any{"namespace": lcTeam, "name": "r", "uid": "0b7c2b5e-8f0e-4a8e-9d55-1f2a3b4c5d6e"}, "spec", "request")
			}, "request is required for and only allowed on Namespace scope"},
			{"unknown scope", func(o map[string]any) { lcSet(o, "Cluster", "spec", "scope") }, "spec.scope: Unsupported value"},
		},
		immutable: func(o map[string]any) { lcSet(o, "lc-other-binding", "spec", "bindingRef", "name") },
		refused:   "spec is immutable",
	}, {
		resource: "evidenceattachments", creator: lcRegistrar, readers: []string{lcRegistrar, lcReader},
		valid: `
apiVersion: compliance.erenius.io/v1alpha1
kind: EvidenceAttachment
metadata: {name: lc-attachment}
spec:
  document:
    title: Live contract document
    mediaType: application/pdf
    size: 1024
    sha256: sha256:9f2b5c1d0e8a7f6b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a10
  source: {issuer: Live contract issuer, url: "https://audits.example.com/lc"}
  validity: {validFrom: "2026-01-01T00:00:00Z", validUntil: "2027-01-01T00:00:00Z"}
  scope: {description: The live contract test.}
  associations:
    - binding: {name: lc-absent-binding, uid: 0b6c1f0e-2f39-4c1a-9a51-7d1d5f3c2a11}
      catalogDigest: sha256:64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb
      controls: [{id: pe-3}]`,
		// konstapel-evidence-attachment-registrant (runtime chart)
		expect: []lcField{{[]any{"spec", "registeredBy", "username"}, lcRegistrar}},
		invalid: []lcInvalid{
			{"validity reversed", func(o map[string]any) { lcSet(o, "2025-01-01T00:00:00Z", "spec", "validity", "validUntil") }, "validFrom must be before validUntil"},
			{"blank title", func(o map[string]any) { lcSet(o, "   ", "spec", "document", "title") }, "title must not be blank"},
			{"binding associated twice", func(o map[string]any) {
				a := lcGet(o, "spec", "associations").([]any)
				lcSet(o, append(a, a[0]), "spec", "associations")
			}, "each binding UID may be associated only once"},
		},
		immutable: func(o map[string]any) { lcSet(o, "Another scope.", "spec", "scope", "description") },
		refused:   "spec is immutable; register a new EvidenceAttachment",
	}, {
		resource: "complianceexceptions", namespace: lcTeam, creator: lcExceptions, readers: []string{lcExceptions},
		valid: `
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceException
metadata: {name: lc-exception, namespace: ` + lcTeam + `}
spec:
  policy: ` + pol + `
  workloadSelector: {matchLabels: {app: debug}}
  reason: live contract test
  expiresAt: "2030-01-01T00:00:00Z"
  acceptanceRevision: 1`,
		invalid: []lcInvalid{
			{"created at a later revision", func(o map[string]any) { lcSet(o, int64(2), "spec", "acceptanceRevision") }, "a new exception starts at acceptanceRevision 1"},
			{"blank reason", func(o map[string]any) { lcSet(o, " \t ", "spec", "reason") }, "reason must not be blank"},
			{"no workload selector", func(o map[string]any) { lcDel(o, "spec", "workloadSelector") }, "spec.workloadSelector: Required value"},
		},
		immutable: func(o map[string]any) { lcSet(o, "another-policy", "spec", "policy") },
		refused:   "policy is immutable; create a new ComplianceException",
	}}
}

// as returns a dynamic client authenticated as user; "" is the test's own
// cluster-admin identity.
func (l *live) dynAs(user string) dynamic.Interface {
	cfg := rest.CopyConfig(l.cfg)
	if user != "" {
		groups := []string{"system:authenticated"}
		if ns, _, ok := strings.Cut(strings.TrimPrefix(user, "system:serviceaccount:"), ":"); ok && strings.HasPrefix(user, "system:serviceaccount:") {
			groups = append(groups, "system:serviceaccounts", "system:serviceaccounts:"+ns)
		}
		cfg.Impersonate = rest.ImpersonationConfig{UserName: user, UID: "uid-" + user, Groups: groups}
	}
	return dynamic.NewForConfigOrDie(cfg)
}

func lcGVR(resource string) schema.GroupVersionResource {
	return v1alpha1.GroupVersion.WithResource(resource)
}

// retried repeats a request while the API server's admission policies or
// authorizer have not yet caught up with new kinds or bindings.
func (l *live) retried(f func() error, done func(error) bool) error {
	var err error
	for range 15 {
		err = f()
		if done(err) && !apierrors.IsServiceUnavailable(err) {
			return err
		}
		time.Sleep(2 * time.Second)
	}
	return err
}

// crdContract exercises every CRD of the installed CRD chart through the
// API server, with the installed runtime chart's admission policies and
// roles. Each finding is reported and the contract continues.
func (l *live) crdContract(ns string) {
	t := l.t
	t.Helper()
	admin := l.dynAs("")
	cases := lcCases(t)

	// Every shipped CRD is covered, and the served definitions are the
	// CRD release's.
	files, _ := filepath.Glob(filepath.Join(chartDir(t, "konstapel-crds"), "templates/*.yaml"))
	var shipped, covered []string
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.Unmarshal(raw, crd); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		shipped = append(shipped, crd.Spec.Names.Plural)
		served := &apiextensionsv1.CustomResourceDefinition{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: crd.Name}, served); err != nil {
			t.Fatalf("shipped CRD %s not served: %v", crd.Name, err)
		}
		if served.Annotations["meta.helm.sh/release-name"] != "konstapel-crds" || served.Annotations["meta.helm.sh/release-namespace"] != ns {
			t.Errorf("CRD %s is not owned by the installed konstapel-crds release: %v", crd.Name, served.Annotations)
		}
	}
	for _, c := range cases {
		covered = append(covered, c.resource)
	}
	slices.Sort(shipped)
	slices.Sort(covered)
	if !slices.Equal(shipped, covered) {
		t.Fatalf("the contract covers %v, the CRD chart ships %v", covered, shipped)
	}

	// Identities bound to the installed roles.
	for _, n := range []string{lcTeam, "team-a"} {
		if err := l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}}); err == nil {
			t.Cleanup(func() {
				_ = l.c.Delete(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
			})
		} else if !apierrors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
	}
	role := func(name string) rbacv1.RoleRef {
		return rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name}
	}
	l.bind(lcAdmin, lcAdmin, role("konstapel-compliance-admin"), "")
	l.bind(lcViewer, lcViewer, role("konstapel-compliance-viewer"), "")
	l.bind(lcOperator, lcOperator, role("konstapel-assessment-operator"), "")
	l.bind(lcRequester, lcRequester, role("konstapel-assessment-requester"), lcTeam)
	l.bind(lcRegistrar, lcRegistrar, role("konstapel-evidence-attachment-registrar"), "")
	l.bind(lcReader, lcReader, role("konstapel-evidence-attachment-reader"), "")
	l.bind(lcExceptions, lcExceptions, role("konstapel-exception-editor"), lcTeam)
	identities := []string{lcAdmin, lcViewer, lcOperator, lcRequester, lcRegistrar, lcReader, lcExceptions, lcNobody, lcController, lcDownload}
	clients := map[string]dynamic.Interface{"": admin}
	for _, id := range identities {
		clients[id] = l.dynAs(id)
	}
	resource := func(c dynamic.Interface, kc lcCase) dynamic.ResourceInterface {
		if kc.namespace == "" {
			return c.Resource(lcGVR(kc.resource))
		}
		return c.Resource(lcGVR(kc.resource)).Namespace(kc.namespace)
	}
	dryRun := []string{metav1.DryRunAll}

	var created []*unstructured.Unstructured
	defer func() {
		// The contract's objects go before the engine arrives.
		for _, u := range created {
			l.removeContractObject(u)
		}
	}()
	findings := map[string]int{}
	for _, kc := range cases {
		gvr := lcGVR(kc.resource)
		// a. Invalid specs are rejected with the documented reason.
		for _, inv := range kc.invalid {
			o := lcObject(t, kc.valid)
			inv.edit(o)
			err := l.retried(func() error {
				_, err := resource(admin, kc).Create(l.ctx, &unstructured.Unstructured{Object: o}, metav1.CreateOptions{DryRun: dryRun})
				return err
			}, func(err error) bool { return err == nil || apierrors.IsInvalid(err) })
			if !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), inv.want) {
				t.Errorf("%s %q: got %v, want Invalid mentioning %q", kc.resource, inv.name, err, inv.want)
			}
		}
		findings["invalid"] += len(kc.invalid)

		// b. The valid object, created by the identity the installed roles
		// allow, gets its defaults and admission fields; status sent with
		// the spec is dropped.
		o := lcObject(t, kc.valid)
		lcSet(o, []any{injected}, "status", "conditions")
		var u *unstructured.Unstructured
		err := l.retried(func() error {
			var err error
			u, err = resource(clients[kc.creator], kc).Create(l.ctx, &unstructured.Unstructured{Object: o}, metav1.CreateOptions{})
			return err
		}, func(err error) bool { return err == nil || !apierrors.IsForbidden(err) })
		if err != nil {
			t.Errorf("%s: %s may not create the minimal valid object: %v", kc.resource, kc.creator, err)
			continue
		}
		created = append(created, u)
		for _, f := range kc.expect {
			if got := lcGet(u.Object, f.path...); fmt.Sprint(got) != fmt.Sprint(f.want) {
				t.Errorf("%s: %v = %v, want %v", kc.resource, f.path, got, f.want)
			}
		}
		if hasInjected(u.Object) {
			t.Errorf("%s: status sent on create was stored: %s", kc.resource, toJSON(u.Object["status"]))
		}

		// c. Status written through the main resource is ignored, and the
		// protected fields refuse changes.
		if err := l.retried(func() error {
			cur, err := resource(admin, kc).Get(l.ctx, u.GetName(), metav1.GetOptions{})
			if err != nil {
				return err
			}
			lcSet(cur.Object, []any{injected}, "status", "conditions")
			got, err := resource(admin, kc).Update(l.ctx, cur, metav1.UpdateOptions{})
			if err == nil && hasInjected(got.Object) {
				t.Errorf("%s: status written through the main resource was stored", kc.resource)
			}
			return err
		}, func(err error) bool { return !apierrors.IsConflict(err) }); err != nil {
			t.Errorf("%s: update through the main resource: %v", kc.resource, err)
		}
		if kc.immutable != nil {
			err := l.retried(func() error {
				cur, err := resource(admin, kc).Get(l.ctx, u.GetName(), metav1.GetOptions{})
				if err != nil {
					return err
				}
				kc.immutable(cur.Object)
				_, err = resource(admin, kc).Update(l.ctx, cur, metav1.UpdateOptions{})
				return err
			}, func(err error) bool { return !apierrors.IsConflict(err) })
			if !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), kc.refused) {
				t.Errorf("%s: protected update got %v, want Invalid mentioning %q", kc.resource, err, kc.refused)
			}
		}

		// d. Only the controller's ServiceAccount may write status; the
		// documented roles may read it. Authorization is decided before
		// existence, so an absent object tells allowed (NotFound) from
		// denied (Forbidden) without touching any object.
		absent := &unstructured.Unstructured{}
		absent.SetAPIVersion(gvr.GroupVersion().String())
		absent.SetKind(u.GetKind())
		absent.SetName("lc-absent")
		absent.SetNamespace(kc.namespace)
		for _, id := range identities {
			want := apierrors.IsForbidden
			if id == lcController {
				want = apierrors.IsNotFound
			}
			err := l.retried(func() error {
				_, err := resource(clients[id], kc).UpdateStatus(l.ctx, absent, metav1.UpdateOptions{DryRun: dryRun})
				return err
			}, want)
			if !want(err) {
				t.Errorf("%s/status update as %s: %v", kc.resource, id, err)
			}
			want = apierrors.IsForbidden
			if id == lcController || slices.Contains(kc.readers, id) {
				want = apierrors.IsNotFound
			}
			err = l.retried(func() error {
				_, err := resource(clients[id], kc).Get(l.ctx, "lc-absent", metav1.GetOptions{}, "status")
				return err
			}, want)
			if !want(err) {
				t.Errorf("%s/status read as %s: %v", kc.resource, id, err)
			}
		}
		findings["status-checks"] += 2 * len(identities)
	}

	// e. The binding's enforcement epoch is maintained by the runtime
	// chart's admission policy: a supplied value is overwritten, and an
	// enforcement change advances it.
	bindings := admin.Resource(lcGVR("compliancebindings"))
	epoch := func(edit func(o map[string]any)) any {
		var got *unstructured.Unstructured
		if err := l.retried(func() error {
			cur, err := bindings.Get(l.ctx, "lc-binding", metav1.GetOptions{})
			if err != nil {
				return err
			}
			edit(cur.Object)
			got, err = bindings.Update(l.ctx, cur, metav1.UpdateOptions{})
			return err
		}, func(err error) bool { return !apierrors.IsConflict(err) }); err != nil {
			t.Errorf("binding update: %v", err)
			return nil
		}
		return lcGet(got.Object, "spec", "enforcementEpoch")
	}
	if got := epoch(func(o map[string]any) { lcSet(o, int64(7), "spec", "enforcementEpoch") }); fmt.Sprint(got) != "1" {
		t.Errorf("a supplied enforcementEpoch was kept: %v, want 1", got)
	}
	if got := epoch(func(o map[string]any) { lcSet(o, "Deny", "spec", "mode") }); fmt.Sprint(got) != "2" {
		t.Errorf("an enforcement change left enforcementEpoch at %v, want 2", got)
	}

	// f. Spec writes stay with their roles: the controller cannot author
	// configuration, a viewer cannot create it, and only the controller may
	// create Namespace-scope runs (the runtime chart's run-scope policy
	// names it through its ConfigMap).
	for _, w := range []struct {
		who, resource, doc string
		want               func(error) bool
		mention            string
	}{
		{lcController, "complianceprofiles", cases[0].valid, apierrors.IsForbidden, ""},
		{lcController, "compliancebindings", cases[1].valid, apierrors.IsForbidden, ""},
		{lcController, "evidencedestinations", cases[2].valid, apierrors.IsForbidden, ""},
		{lcViewer, "complianceprofiles", cases[0].valid, apierrors.IsForbidden, ""},
		{lcRegistrar, "complianceprofiles", cases[0].valid, apierrors.IsForbidden, ""},
		{lcOperator, "assessmentruns", lcNamespaceRun, apierrors.IsForbidden, "only the Konstapel controller (konstapel-system/konstapel-controller) may create"},
		{lcController, "assessmentruns", lcNamespaceRun, func(err error) bool { return err == nil }, ""},
	} {
		o := lcObject(t, w.doc)
		o["metadata"].(map[string]any)["name"] = "lc-write"
		err := l.retried(func() error {
			_, err := clients[w.who].Resource(lcGVR(w.resource)).Create(l.ctx, &unstructured.Unstructured{Object: o}, metav1.CreateOptions{DryRun: dryRun})
			return err
		}, w.want)
		if !w.want(err) || (w.mention != "" && !strings.Contains(err.Error(), w.mention)) {
			t.Errorf("%s creating %s: %v", w.who, w.resource, err)
		}
	}

	// g. The documented examples: valid ones are accepted by the installed
	// release, invalid ones rejected with their documented reason.
	examples := l.documentedExamples(admin, clients[lcController])
	findings["examples"] = examples
	l.record("crd-contract", map[string]any{"crds": shipped, "checks": findings})
}

// lcNamespaceRun is a controller-only run: Namespace scope with a Request
// trigger.
const lcNamespaceRun = `
apiVersion: compliance.erenius.io/v1alpha1
kind: AssessmentRun
metadata: {name: lc-namespace-run}
spec:
  bindingRef: {name: lc-absent-binding}
  scope: Namespace
  request: {namespace: lc-team, name: lc-request, uid: 0b7c2b5e-8f0e-4a8e-9d55-1f2a3b4c5d6e}
  trigger: {type: Request}`

// documentedExamples dry-runs the documented API examples against the
// installed release and returns how many it checked.
func (l *live) documentedExamples(admin, controller dynamic.Interface) int {
	t := l.t
	t.Helper()
	var files []string
	for _, pattern := range []string{
		"../../testdata/targeting/examples/valid/*.yaml", "../../testdata/targeting/examples/invalid/*.yaml",
		"../../testdata/assessments/examples/valid/*.yaml",
		"../../docs/examples/evidence-signing/destination.yaml", "../../docs/examples/supporting-evidence/attachment-datacenter.yaml",
	} {
		m, _ := filepath.Glob(pattern)
		files = append(files, m...)
	}
	n := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var expect string
		for _, line := range strings.Split(string(raw), "\n") {
			if rest, ok := strings.CutPrefix(line, "# expect: "); ok {
				expect = rest
			}
		}
		o := lcObject(t, string(raw))
		u := &unstructured.Unstructured{Object: o}
		gvk := u.GroupVersionKind()
		mapping, err := l.c.RESTMapper().RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		// Runs only the controller creates: Namespace scope or a
		// Scheduled/Request trigger.
		c := admin
		if trigger, _ := lcGet(o, "spec", "trigger", "type").(string); gvk.Kind == "AssessmentRun" && (trigger == "Scheduled" || trigger == "Request" || lcGet(o, "spec", "scope") == "Namespace") {
			c = controller
		}
		var ri dynamic.ResourceInterface = c.Resource(mapping.Resource)
		if ns := u.GetNamespace(); ns != "" {
			ri = c.Resource(mapping.Resource).Namespace(ns)
		}
		err = l.retried(func() error {
			_, err := ri.Create(l.ctx, u, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
			return err
		}, func(err error) bool { return err == nil || apierrors.IsInvalid(err) })
		switch {
		case expect == "" && err != nil:
			t.Errorf("documented example %s rejected by the installed release: %v", f, err)
		case expect != "" && (!apierrors.IsInvalid(err) || !strings.Contains(err.Error(), expect)):
			t.Errorf("documented invalid example %s: got %v, want Invalid mentioning %q", f, err, expect)
		}
		n++
	}
	if n == 0 {
		t.Error("no documented examples found")
	}
	return n
}

// removeContractObject deletes an object the contract created, releasing
// any finalizer the controller added, and waits until it is gone.
func (l *live) removeContractObject(u *unstructured.Unstructured) {
	gvk := u.GroupVersionKind()
	l.eventually("contract object "+u.GetName()+" removed", func() (bool, string) {
		cur := &unstructured.Unstructured{}
		cur.SetGroupVersionKind(gvk)
		err := l.c.Get(context.Background(), client.ObjectKeyFromObject(u), cur)
		if apierrors.IsNotFound(err) {
			return true, ""
		}
		if err != nil {
			return false, err.Error()
		}
		if len(cur.GetFinalizers()) > 0 {
			cur.SetFinalizers(nil)
			if err := l.c.Update(context.Background(), cur); err != nil {
				return false, err.Error()
			}
		}
		if cur.GetDeletionTimestamp() == nil {
			if err := l.c.Delete(context.Background(), cur); err != nil && !apierrors.IsNotFound(err) {
				return false, err.Error()
			}
		}
		return false, "deleting"
	})
}
