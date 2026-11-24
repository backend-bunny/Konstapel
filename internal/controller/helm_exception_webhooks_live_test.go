//go:build live

package controller

// Installed ComplianceException admission webhooks and revocation
// processing (docs/charts.md, "Exception admission webhooks"), driving Helm,
// the API server and the packaged image only, with cert-manager TLS from the
// chart's CA:
//  1. the default installation has nothing of the feature;
//  2. webhooks on (documented step 1): both configurations pass the
//     controller's own VerifyProtection, their injected CA verifies the
//     certificate the Service serves, every ready replica is an endpoint
//     and reports the webhook readiness check, acceptances record the
//     caller, and a revocation is held (RevocationProcessingDisabled);
//  3. the ServiceAccount over-granted update/patch on exceptions by hand,
//     processing off: across a new revocation, a deletion and a restart the
//     API server counts no exception write but the test's own, and no
//     record exists;
//  4. no ready replica: creates and updates are denied for everyone (fail
//     closed), and admitted again once replicas return;
//  5. revocation processing on (step 2): the gated binding is created after
//     the webhooks, every replica runs the flag and knows the controller
//     identity, the held revocations are recorded and released, a new one
//     end to end, and the controller identity cannot edit an exception;
//  6. processing off again (disable step 1): the binding goes while the
//     webhooks stay, and a new revocation is held;
//  7. webhooks off (step 2): configurations, Service and certificate go;
//  8. both on in one upgrade, then both off in one: the order Helm applies
//     them in (etcd revisions) and that nothing is recorded before the
//     webhooks are registered.
// Run through scripts/targeting-live.sh (charts acceptance group).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/exception"
)

const (
	gatedRevocationBinding = "konstapel-controller-exception-revocation"
	webhookServiceName     = "konstapel-webhook.konstapel-system.svc"
)

// orderEvent is one creation or deletion of the gated binding or a webhook
// configuration, at its etcd revision.
type orderEvent struct {
	Kind string          `json:"kind"`
	Type watch.EventType `json:"type"`
	RV   uint64          `json:"rv"`
}

// helmOrder runs op and returns the creations and deletions of the gated
// binding and both webhook configurations it caused, in commit order. The
// disposable cluster has one etcd, whose single revision counter assigns
// every resourceVersion, so revisions order changes across kinds; a
// deletion event carries the revision of the deletion.
func (l *live) helmOrder(op func()) []orderEvent {
	l.t.Helper()
	wc, err := client.NewWithWatch(l.cfg, client.Options{Scheme: l.c.Scheme()})
	if err != nil {
		l.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(l.ctx)
	var mu sync.Mutex
	var events []orderEvent
	var wg sync.WaitGroup
	for kind, list := range map[string]client.ObjectList{
		"ClusterRoleBinding":             &rbacv1.ClusterRoleBindingList{},
		"MutatingWebhookConfiguration":   &admissionregistrationv1.MutatingWebhookConfigurationList{},
		"ValidatingWebhookConfiguration": &admissionregistrationv1.ValidatingWebhookConfigurationList{},
	} {
		name := exception.WebhookConfigurationName
		if kind == "ClusterRoleBinding" {
			name = gatedRevocationBinding
		}
		if err := l.c.List(l.ctx, list); err != nil {
			l.t.Fatal(err)
		}
		from, _ := meta.NewAccessor().ResourceVersion(list)
		w, err := wc.Watch(ctx, list, client.MatchingFields{"metadata.name": name}, &client.ListOptions{Raw: &metav1.ListOptions{ResourceVersion: from}})
		if err != nil {
			l.t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer w.Stop()
			for e := range w.ResultChan() {
				if e.Type != watch.Added && e.Type != watch.Deleted {
					continue
				}
				o, ok := e.Object.(client.Object)
				if !ok {
					continue
				}
				rv, err := strconv.ParseUint(o.GetResourceVersion(), 10, 64)
				if err != nil {
					continue
				}
				mu.Lock()
				events = append(events, orderEvent{Kind: kind, Type: e.Type, RV: rv})
				mu.Unlock()
			}
		}()
	}
	op()
	// Events commit before Helm returns; allow their delivery.
	time.Sleep(5 * time.Second)
	cancel()
	wg.Wait()
	sort.Slice(events, func(i, j int) bool { return events[i].RV < events[j].RV })
	return events
}

// first returns the revision of kind's first event of type typ, or 0.
func first(events []orderEvent, kind string, typ watch.EventType) uint64 {
	for _, e := range events {
		if e.Kind == kind && e.Type == typ {
			return e.RV
		}
	}
	return 0
}

// exceptionRequests sums the API server's requests on complianceexceptions
// (not status) by verb, writes and reads alike, across every client: the
// kube-apiserver's apiserver_request_total, read from its /metrics. Dry
// runs, which store nothing, are left out: the test probes serving with
// them, and the controller sends none.
func (l *live) exceptionRequests(kc kubernetes.Interface) map[string]float64 {
	l.t.Helper()
	raw, err := kc.CoreV1().RESTClient().Get().AbsPath("/metrics").DoRaw(l.ctx)
	if err != nil {
		l.t.Fatal(err)
	}
	label := regexp.MustCompile(`(\w+)="([^"]*)"`)
	out := map[string]float64{}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "apiserver_request_total{") {
			continue
		}
		end := strings.LastIndex(line, "}")
		labels := map[string]string{}
		for _, m := range label.FindAllStringSubmatch(line[:end], -1) {
			labels[m[1]] = m[2]
		}
		if labels["group"] != v1alpha1.GroupVersion.Group || labels["resource"] != "complianceexceptions" || labels["subresource"] != "" || labels["dry_run"] != "" {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(line[end+1:]), 64)
		if err != nil {
			l.t.Fatalf("metric line %q: %v", line, err)
		}
		out[labels["verb"]] += v
	}
	return out
}

// writes keeps only the write verbs of exceptionRequests.
func writes(m map[string]float64) map[string]float64 {
	out := map[string]float64{}
	for verb, n := range m {
		switch verb {
		case "GET", "LIST", "WATCH", "HEAD", "CONNECT":
		default:
			out[verb] = n
		}
	}
	return out
}

// controllersWith waits until exactly two ready controller pods remain,
// each run with every arg in want and none in absent.
func (l *live) controllersWith(ns string, want, absent []string) []corev1.Pod {
	l.t.Helper()
	var pods []corev1.Pod
	l.eventually(fmt.Sprintf("controllers with %v without %v", want, absent), func() (bool, string) {
		var all corev1.PodList
		_ = l.c.List(l.ctx, &all, client.InNamespace(ns), client.MatchingLabels{"app.kubernetes.io/component": "controller"})
		pods = l.podsReady(ns, "controller")
		if len(all.Items) != 2 || len(pods) != 2 {
			return false, l.podDiagnostics(ns)
		}
		for _, p := range pods {
			args := p.Spec.Containers[0].Args
			for _, a := range want {
				if !slices.Contains(args, a) {
					return false, p.Name + " lacks " + a
				}
			}
			for _, a := range absent {
				if slices.ContainsFunc(args, func(s string) bool { return strings.HasPrefix(s, a) }) {
					return false, p.Name + " has " + a
				}
			}
		}
		return true, ""
	})
	return pods
}

// readyz returns a pod's verbose readiness report.
func (l *live) readyz(ns, pod string) string {
	l.t.Helper()
	addr := l.portForward(ns, "pod/"+pod, 8081)
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Get("http://" + addr + "/readyz?verbose")
	if err != nil {
		l.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestLiveHelmExceptionWebhooks(t *testing.T) {
	_, repo, imageDigest := liveImage(t)
	if os.Getenv("KONSTAPEL_LIVE_CERT_MANAGER") != "true" {
		t.Fatal("the exception webhook test needs cert-manager (charts acceptance group)")
	}
	l := newLive(t)
	// Seven Helm operations with rollouts take longer than newLive's
	// default budget; the group's go test timeout still bounds the run.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Minute)
	t.Cleanup(cancel)
	l.ctx = ctx
	kc, err := kubernetes.NewForConfig(l.cfg)
	if err != nil {
		t.Fatal(err)
	}
	const ns, team = "konstapel-system", "hw-team"
	l.awaitNoInstallation(ns)

	// The team namespace, its editors and an eligible configuration.
	l.setNamespace(team, "hw-exceptions")
	t.Cleanup(func() {
		_ = l.c.Delete(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: team}})
	})
	// Runs after the runtime chart is uninstalled (registered before it):
	// while the webhooks serve, only the controller may release.
	t.Cleanup(func() { l.releaseRevocations(team) })
	if out, err := l.helm("install", "konstapel-crds", chartArchive(t, "konstapel-crds"), "--namespace", ns, "--create-namespace", "--wait"); err != nil {
		t.Fatalf("install CRD chart: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = l.helm("uninstall", "konstapel-crds", "--namespace", ns) })
	l.waitChartCRDs()

	// cert-manager keeps a Certificate's Secret when the chart removes it;
	// this test's webhook Secret goes after the release.
	t.Cleanup(func() {
		_ = l.c.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "konstapel-webhook-tls"}})
	})
	base := append([]string{"--namespace", ns, "--wait", "--timeout", "5m", "--set", "download.enabled=false"}, imageValues(repo, imageDigest)...)
	release := func(verb string, webhooks, revocation bool) {
		t.Helper()
		args := append([]string{verb, "konstapel", chartArchive(t, "konstapel")}, base...)
		args = append(args, "--set", fmt.Sprintf("exceptions.webhooks.enabled=%t", webhooks), "--set", fmt.Sprintf("exceptions.revocationProcessing.enabled=%t", revocation))
		if out, err := l.helm(args...); err != nil {
			t.Fatalf("helm %s webhooks=%t revocation=%t: %v\n%s\n%s", verb, webhooks, revocation, err, out, l.podDiagnostics(ns))
		}
	}

	// 1. The default installation: nothing of the feature.
	release("install", false, false)
	t.Cleanup(func() {
		_, _ = l.helm("uninstall", "konstapel", "--namespace", ns, "--wait", "--cascade", "foreground")
	})
	absent := func(what string) {
		t.Helper()
		for _, o := range []client.Object{
			&admissionregistrationv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: exception.WebhookConfigurationName}},
			&admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: exception.WebhookConfigurationName}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "konstapel-webhook"}},
		} {
			if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(o), o); !apierrors.IsNotFound(err) {
				t.Fatalf("%s: %T %s exists (%v)", what, o, o.GetName(), err)
			}
		}
	}
	noGrant := func(what string) {
		t.Helper()
		for _, o := range []client.Object{&rbacv1.ClusterRoleBinding{}, &rbacv1.ClusterRole{}} {
			if err := l.c.Get(l.ctx, client.ObjectKey{Name: gatedRevocationBinding}, o); !apierrors.IsNotFound(err) {
				t.Fatalf("%s: the gated revocation %T exists (%v)", what, o, err)
			}
		}
	}
	absent("default installation")
	noGrant("default installation")
	l.controllersWith(ns, nil, []string{"--webhook-", "--exception-revocation"})
	l.record("installed-disabled", map[string]any{"webhooks": false, "revocationProcessing": false})

	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "hw-self-service"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)},
			Policies: []v1alpha1.ProfilePolicy{{Name: pol, Exceptions: v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: 720 * time.Hour}}}}}}
	b := bindingObj("hw-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "hw-exceptions"})
	editors := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "exception-editors", Namespace: team},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-exception-editor"},
		Subjects: []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: "Group", Name: "hw-editors"}}}
	for _, o := range []client.Object{p, b, editors} {
		o.SetUID("")
		l.createWhenServed(o)
	}
	t.Cleanup(func() {
		_ = l.c.Delete(context.Background(), b)
		_ = l.c.Delete(context.Background(), p)
	})
	alice := l.as("hw-alice", "hw-editors", "system:authenticated")
	dave := l.as("hw-dave", "hw-editors", "system:authenticated")
	controllerSA := l.as(controllerServiceAccount, controllerGroups...)
	newEx := func(name string) *v1alpha1.ComplianceException {
		return &v1alpha1.ComplianceException{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: team},
			Spec: v1alpha1.ComplianceExceptionSpec{Policy: pol, WorkloadSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "debug"}},
				Reason: "installed exception webhooks", ExpiresAt: metav1.NewTime(time.Now().Add(24 * time.Hour).Truncate(time.Second)), AcceptanceRevision: 1}}
	}
	serving := func(what string) {
		t.Helper()
		l.eventually(what, func() (bool, string) {
			err := alice.Create(l.ctx, newEx("probe"), client.DryRunAll)
			return err == nil, fmt.Sprint(err)
		})
	}
	accept := func(name string) *v1alpha1.ComplianceException {
		t.Helper()
		e := newEx(name)
		if err := alice.Create(l.ctx, e); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		e = l.settled(team, name)
		a, present, err := exception.ParseAcceptance(e)
		if !present || err != nil || a.Actor.Username != "hw-alice" || a.Revision != 1 {
			t.Fatalf("acceptance of %s: present=%v err=%v %+v", name, present, err, a)
		}
		return e
	}
	revoke := func(e *v1alpha1.ComplianceException) *v1alpha1.ComplianceException {
		t.Helper()
		got, err := l.jsonPatch(dave, team, e.Name, examplePatch(t, "revoke.json").withPreconditions(l.exception(team, e.Name)))
		if err != nil {
			t.Fatalf("revoke %s: %v", e.Name, err)
		}
		if !slices.Contains(got.Finalizers, exception.RevocationFinalizer) {
			t.Fatalf("revocation of %s without the finalizer", e.Name)
		}
		return got
	}
	condition := func(e *v1alpha1.ComplianceException, reason string) {
		t.Helper()
		l.eventually(e.Name+" "+reason, func() (bool, string) {
			cur := l.exception(team, e.Name)
			c := meta.FindStatusCondition(cur.Status.Conditions, v1alpha1.ConditionRevocationRecorded)
			return c != nil && c.Reason == reason && c.ObservedGeneration == cur.Generation, toJSON(cur.Status.Conditions)
		})
	}
	held := func(what string, e *v1alpha1.ComplianceException) *v1alpha1.ComplianceException {
		t.Helper()
		cur := l.exception(team, e.Name)
		if !slices.Contains(cur.Finalizers, exception.RevocationFinalizer) {
			t.Fatalf("%s: the revocation finalizer of %s is gone: %s", what, e.Name, lifecycle(cur))
		}
		if l.snapshotConfigMap(exception.RevocationRecordName(cur.UID, cur.Spec.AcceptanceRevision)) != nil {
			t.Fatalf("%s: a revocation record of %s exists", what, e.Name)
		}
		return cur
	}
	failClosed := func(what string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "failed calling webhook") {
			t.Fatalf("%s: want the unavailable webhook to fail closed, got %v", what, err)
		}
	}

	// 2. Webhooks on, revocation processing off (documented step 1).
	var registered []orderEvent
	registered = l.helmOrder(func() { release("upgrade", true, false) })
	if first(registered, "MutatingWebhookConfiguration", watch.Added) == 0 || first(registered, "ValidatingWebhookConfiguration", watch.Added) == 0 ||
		first(registered, "ClusterRoleBinding", watch.Added) != 0 {
		t.Fatalf("enabling the webhooks applied %v", registered)
	}
	noGrant("webhooks only")
	pods := l.controllersWith(ns, []string{"--webhook-cert-dir=/etc/konstapel/webhook-tls", "--webhook-port=9443"}, []string{"--exception-revocation"})
	if err := exception.VerifyProtection(l.ctx, l.c); err != nil {
		t.Fatalf("the installed webhooks do not pass the controller's check: %v", err)
	}
	// TLS: cert-manager's injected CA is the one that issued the served
	// certificate, which covers the Service name.
	tlsSecret := &corev1.Secret{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: "konstapel-webhook-tls"}, tlsSecret); err != nil {
		t.Fatal(err)
	}
	l.eventually("webhook CA injected", func() (bool, string) {
		m := &admissionregistrationv1.MutatingWebhookConfiguration{}
		v := &admissionregistrationv1.ValidatingWebhookConfiguration{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: exception.WebhookConfigurationName}, m); err != nil {
			return false, err.Error()
		}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: exception.WebhookConfigurationName}, v); err != nil {
			return false, err.Error()
		}
		want := string(tlsSecret.Data["ca.crt"])
		return want != "" && string(m.Webhooks[0].ClientConfig.CABundle) == want && string(v.Webhooks[0].ClientConfig.CABundle) == want, "caBundle not injected yet"
	})
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(tlsSecret.Data["ca.crt"]) {
		t.Fatal("no CA in konstapel-webhook-tls")
	}
	addr := l.portForward(ns, "service/konstapel-webhook", 443)
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots, ServerName: webhookServiceName})
	if err != nil {
		t.Fatalf("the webhook Service does not serve a certificate the injected CA verifies for %s: %v", webhookServiceName, err)
	}
	_ = conn.Close()
	if c, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots, ServerName: "konstapel-download.konstapel-system.svc"}); err == nil {
		_ = c.Close()
		t.Fatal("the webhook certificate verified for another service name")
	}
	// Readiness: every replica is ready with the webhook check, and the
	// Service routes to exactly the ready replicas.
	ips := map[string]bool{}
	for _, pod := range pods {
		ips[pod.Status.PodIP] = true
		if r := l.readyz(ns, pod.Name); !strings.Contains(r, "[+]webhook ok") || strings.Contains(r, "controller-identity") {
			t.Fatalf("%s readiness: %s", pod.Name, r)
		}
	}
	l.eventually("the webhook Service routes to every ready replica", func() (bool, string) {
		var eps discoveryv1.EndpointSliceList
		if err := l.c.List(l.ctx, &eps, client.InNamespace(ns), client.MatchingLabels{discoveryv1.LabelServiceName: "konstapel-webhook"}); err != nil {
			return false, err.Error()
		}
		got := map[string]bool{}
		for _, s := range eps.Items {
			for _, e := range s.Endpoints {
				if e.Conditions.Ready != nil && *e.Conditions.Ready {
					for _, a := range e.Addresses {
						got[a] = true
					}
				}
			}
		}
		return fmt.Sprint(got) == fmt.Sprint(ips), toJSON(map[string]any{"endpoints": got, "pods": ips})
	})
	serving("exception webhooks serving")
	off := revoke(accept("hw-held"))
	condition(off, v1alpha1.ReasonRevocationProcessingDisabled)
	held("webhooks only", off)
	l.record("webhooks-enabled", map[string]any{"order": registered, "caInjected": true, "readyz": "webhook ok", "endpoints": len(ips), "held": v1alpha1.ReasonRevocationProcessingDisabled})

	// 3. Over-granted by hand, processing off: the API server counts every
	// exception write (status excluded) by any client while the controller
	// reconciles a new revocation, a deletion and a restart. Only the
	// test's own writes may appear.
	overgrant := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "hw-overgrant"},
		Rules: []rbacv1.PolicyRule{{APIGroups: []string{v1alpha1.GroupVersion.Group}, Resources: []string{"complianceexceptions"}, Verbs: []string{"update", "patch"}}}}
	overgrantBinding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "hw-overgrant"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: overgrant.Name},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: ns, Name: "konstapel-controller"}}}
	for _, o := range []client.Object{overgrant, overgrantBinding} {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(context.Background(), o) })
	}
	l.eventually("the controller ServiceAccount over-granted", func() (bool, string) {
		sar := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{User: controllerServiceAccount, Groups: controllerGroups,
			ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: team, Group: v1alpha1.GroupVersion.Group, Version: "v1alpha1", Resource: "complianceexceptions", Verb: "patch", Name: off.Name}}}
		if err := l.c.Create(l.ctx, sar); err != nil {
			return false, err.Error()
		}
		return sar.Status.Allowed, sar.Status.Reason
	})
	before := writes(l.exceptionRequests(kc))
	over := revoke(accept("hw-overgranted")) // POST + PATCH
	condition(over, v1alpha1.ReasonRevocationProcessingDisabled)
	cur := l.exception(team, over.Name)
	if err := alice.Delete(l.ctx, cur, client.Preconditions{UID: &cur.UID, ResourceVersion: &cur.ResourceVersion}); err != nil { // DELETE
		t.Fatal(err)
	}
	// A restart: the new leader reconciles every exception again.
	dep := &appsv1.Deployment{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: "konstapel-controller"}, dep); err != nil {
		t.Fatal(err)
	}
	if err := l.c.Patch(l.ctx, dep, client.RawPatch(types.MergePatchType, []byte(fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"hw.konstapel.dev/restartedAt":%q}}}}}`, time.Now().UTC().Format(time.RFC3339Nano))))); err != nil {
		t.Fatal(err)
	}
	// The Deployment controller starts the rollout asynchronously: wait
	// until no pod from before the restart remains.
	l.eventually("every controller pod replaced", func() (bool, string) {
		var all corev1.PodList
		_ = l.c.List(l.ctx, &all, client.InNamespace(ns), client.MatchingLabels{"app.kubernetes.io/component": "controller"})
		for _, p := range all.Items {
			if slices.ContainsFunc(pods, func(old corev1.Pod) bool { return old.UID == p.UID }) {
				return false, p.Name + " still runs"
			}
		}
		return true, ""
	})
	restarted := l.controllersWith(ns, []string{"--webhook-cert-dir=/etc/konstapel/webhook-tls"}, []string{"--exception-revocation"})
	serving("exception webhooks serving after the restart")
	after := revoke(accept("hw-overgranted-after-restart")) // POST + PATCH
	condition(after, v1alpha1.ReasonRevocationProcessingDisabled)
	time.Sleep(2 * historyRetry)
	if cur = held("over-granted, deleted", over); cur.DeletionTimestamp == nil {
		t.Fatal("the deletion was not recorded")
	}
	held("over-granted, earlier revocation", off)
	held("over-granted, after the restart", after)
	got := writes(l.exceptionRequests(kc))
	delta := map[string]float64{}
	for verb, n := range got {
		if d := n - before[verb]; d != 0 {
			delta[verb] = d
		}
	}
	if want := map[string]float64{"POST": 2, "PATCH": 2, "DELETE": 1}; fmt.Sprint(delta) != fmt.Sprint(want) {
		t.Fatalf("with processing off and the ServiceAccount over-granted, the API server counted exception writes %v; the test sent only %v", delta, want)
	}
	for _, o := range []client.Object{overgrantBinding, overgrant} {
		if err := l.c.Delete(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	pods = restarted
	l.record("overgranted-processing-off", map[string]any{"grant": overgrant.Rules, "exceptionWrites": delta, "testWrites": map[string]int{"POST": 2, "PATCH": 2, "DELETE": 1}, "records": 0})

	// 4. No ready replica: every create and update is denied, whoever
	// sends it, and admitted again once replicas return.
	scale := func(n int) {
		t.Helper()
		if err := l.c.Patch(l.ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "konstapel-controller"}},
			client.RawPatch(types.MergePatchType, []byte(fmt.Sprintf(`{"spec":{"replicas":%d}}`, n)))); err != nil {
			t.Fatal(err)
		}
	}
	scale(0)
	l.eventually("no controller pod", func() (bool, string) {
		var all corev1.PodList
		_ = l.c.List(l.ctx, &all, client.InNamespace(ns), client.MatchingLabels{"app.kubernetes.io/component": "controller"})
		return len(all.Items) == 0, l.podDiagnostics(ns)
	})
	failClosed("create while no replica serves", alice.Create(l.ctx, newEx("hw-unserved")))
	_, err = l.jsonPatch(dave, team, after.Name, examplePatch(t, "revoke.json").withPreconditions(l.exception(team, after.Name)))
	failClosed("revoke while no replica serves", err)
	failClosed("an administrator's label edit while no replica serves", l.mergePatch(l.c, team, after.Name, `{"metadata":{"labels":{"by":"admin"}}}`))
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: team, Name: "hw-unserved"}, &v1alpha1.ComplianceException{}); !apierrors.IsNotFound(err) {
		t.Fatalf("an exception was stored while no replica served: %v", err)
	}
	scale(2)
	pods = l.controllersWith(ns, []string{"--webhook-cert-dir=/etc/konstapel/webhook-tls"}, []string{"--exception-revocation"})
	serving("exception webhooks serving again")
	l.record("webhooks-unavailable", map[string]any{"create": "denied", "update": "denied", "admin": "denied", "recovered": true})

	// 5. Revocation processing on (documented step 2): the gated binding is
	// created after the webhooks were registered; the held revocations are
	// recorded and released, the deleted one goes.
	enabled := l.helmOrder(func() { release("upgrade", true, true) })
	crb := first(enabled, "ClusterRoleBinding", watch.Added)
	if crb == 0 || crb < first(registered, "MutatingWebhookConfiguration", watch.Added) || crb < first(registered, "ValidatingWebhookConfiguration", watch.Added) ||
		first(enabled, "MutatingWebhookConfiguration", watch.Deleted) != 0 || first(enabled, "ValidatingWebhookConfiguration", watch.Deleted) != 0 {
		t.Fatalf("enabling revocation processing applied %v after the webhooks %v", enabled, registered)
	}
	pods = l.controllersWith(ns, []string{"--webhook-cert-dir=/etc/konstapel/webhook-tls", "--exception-revocation-processing"}, nil)
	for _, pod := range pods {
		if r := l.readyz(ns, pod.Name); !strings.Contains(r, "[+]webhook ok") || !strings.Contains(r, "[+]controller-identity ok") {
			t.Fatalf("%s readiness: %s", pod.Name, r)
		}
	}
	l.waitHistory(off)
	l.waitHistory(over)
	l.waitHistory(after)
	l.eventually("the deleted over-granted exception gone", func() (bool, string) {
		err := l.c.Get(l.ctx, client.ObjectKeyFromObject(over), &v1alpha1.ComplianceException{})
		return apierrors.IsNotFound(err), fmt.Sprint(err)
	})
	e2e := revoke(accept("hw-end-to-end"))
	rec := l.waitHistory(e2e)
	cur = l.exception(team, e2e.Name)
	if err := alice.Delete(l.ctx, cur, client.Preconditions{UID: &cur.UID, ResourceVersion: &cur.ResourceVersion}); err != nil {
		t.Fatal(err)
	}
	l.eventually("the revoked exception deleted", func() (bool, string) {
		err := l.c.Get(l.ctx, client.ObjectKeyFromObject(e2e), &v1alpha1.ComplianceException{})
		return apierrors.IsNotFound(err), fmt.Sprint(err)
	})
	if l.snapshotConfigMap(rec.Name) == nil {
		t.Fatal("the deletion removed the revocation record")
	}
	active := accept("hw-active")
	if err := l.mergePatch(controllerSA, team, active.Name, `{"metadata":{"labels":{"by":"controller"}}}`); err == nil || !strings.Contains(err.Error(), exception.ReasonProtectedField) {
		t.Fatalf("the controller identity edited an exception: %v", err)
	}
	// The validating webhook removed by hand: processing stops, fail
	// closed, until Helm restores it.
	val := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: exception.WebhookConfigurationName}, val); err != nil {
		t.Fatal(err)
	}
	if err := l.c.Delete(l.ctx, val); err != nil {
		t.Fatal(err)
	}
	unprotected := revoke(active)
	condition(unprotected, v1alpha1.ReasonRevocationProtectionUnverified)
	held("validating webhook removed", unprotected)
	release("upgrade", true, true)
	l.waitHistory(unprotected)
	l.record("revocation-enabled", map[string]any{"order": enabled, "records": []string{rec.Name}, "protectionRemoved": v1alpha1.ReasonRevocationProtectionUnverified, "controllerEdit": exception.ReasonProtectedField})

	// 6. Processing off first (disable step 1): the binding goes, the
	// webhooks stay; a new revocation is held.
	disabled := l.helmOrder(func() { release("upgrade", true, false) })
	if first(disabled, "ClusterRoleBinding", watch.Deleted) == 0 || first(disabled, "MutatingWebhookConfiguration", watch.Deleted) != 0 || first(disabled, "ValidatingWebhookConfiguration", watch.Deleted) != 0 {
		t.Fatalf("disabling revocation processing applied %v", disabled)
	}
	noGrant("revocation processing disabled")
	pods = l.controllersWith(ns, []string{"--webhook-cert-dir=/etc/konstapel/webhook-tls"}, []string{"--exception-revocation"})
	if err := exception.VerifyProtection(l.ctx, l.c); err != nil {
		t.Fatalf("the webhooks lost protection when processing was disabled: %v", err)
	}
	later := revoke(accept("hw-held-again"))
	condition(later, v1alpha1.ReasonRevocationProcessingDisabled)
	held("processing disabled again", later)
	l.record("revocation-disabled", map[string]any{"order": disabled, "webhooksKept": true})

	// 7. Then the webhooks (disable step 2).
	removed := l.helmOrder(func() { release("upgrade", false, false) })
	if first(removed, "MutatingWebhookConfiguration", watch.Deleted) == 0 || first(removed, "ValidatingWebhookConfiguration", watch.Deleted) == 0 {
		t.Fatalf("disabling the webhooks applied %v", removed)
	}
	absent("webhooks disabled")
	noGrant("webhooks disabled")
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: "konstapel-webhook"}, &corev1.Service{}); !apierrors.IsNotFound(err) {
		t.Fatalf("the webhook Service remains: %v", err)
	}
	l.controllersWith(ns, nil, []string{"--webhook-", "--exception-revocation"})
	held("webhooks disabled", later)
	l.record("webhooks-disabled", map[string]any{"order": removed})

	// 8. Both in one upgrade. Helm applies kinds in a fixed order, the
	// ClusterRoleBinding before the webhook configurations, so the grant
	// exists before its protection; the controller still records and
	// releases nothing until it verifies the registered webhooks.
	both := l.helmOrder(func() { release("upgrade", true, true) })
	crb, mwc, vwc := first(both, "ClusterRoleBinding", watch.Added), first(both, "MutatingWebhookConfiguration", watch.Added), first(both, "ValidatingWebhookConfiguration", watch.Added)
	if crb == 0 || mwc == 0 || vwc == 0 || crb > mwc || crb > vwc {
		t.Fatalf("one-step enable applied %v; docs/charts.md describes the binding first", both)
	}
	l.controllersWith(ns, []string{"--exception-revocation-processing"}, nil)
	rec = l.waitHistory(later)
	recRV, err := strconv.ParseUint(rec.ResourceVersion, 10, 64)
	if err != nil || recRV < mwc || recRV < vwc {
		t.Fatalf("revocation record %s (revision %s) written before the webhooks were registered (%d, %d): %v", rec.Name, rec.ResourceVersion, mwc, vwc, err)
	}
	// And both off in one upgrade: Helm deletes removed objects in the
	// same kind order, the binding before the webhooks.
	gone := l.helmOrder(func() { release("upgrade", false, false) })
	crb, mwc, vwc = first(gone, "ClusterRoleBinding", watch.Deleted), first(gone, "MutatingWebhookConfiguration", watch.Deleted), first(gone, "ValidatingWebhookConfiguration", watch.Deleted)
	if crb == 0 || mwc == 0 || vwc == 0 || crb > mwc || crb > vwc {
		t.Fatalf("one-step disable applied %v; docs/charts.md describes the binding removed first", gone)
	}
	absent("one-step disable")
	noGrant("one-step disable")
	l.controllersWith(ns, nil, []string{"--webhook-", "--exception-revocation"})
	l.record("one-step", map[string]any{"enable": both, "recordRevision": recRV, "disable": gone})
}
