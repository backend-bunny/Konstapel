//go:build live

package controller

// Failover under traffic on the Helm-installed controller
// (add-controller-high-availability 5.3, 5.6; group "availability", one control
// plane running Kyverno and two workers). Both charts run the packaged
// image with two replicas, operator TLS and authenticated metrics. Traffic
// runs for the whole test, and each event is judged by what clients,
// durable state and metrics show, not by who holds the Lease:
//   - admission: every second a privileged dry-run pod in the Deny-bound
//     namespace must be denied by a delivered engine policy (and every fifth
//     second a compliant one admitted), so enforcement never lapses;
//   - downloads: every second an authorized download through a test-owned
//     NodePort Service with the chart Service's selector, so kube-proxy
//     routes each new connection to a ready endpoint. Transport errors and
//     503/429 are retried and recorded as transient; every request must
//     return the receipt's package within 90s, and any other answer fails;
//   - reconciliation: after each event a reporting-only binding edit must be
//     reconciled by the current leader.
//
// Events, in order:
//  1. graceful follower replacement: the follower terminates within the
//     shutdown budget while the leader keeps the Lease (same holder, no
//     transition) and publishes a run started during the replacement;
//  2. graceful leader replacement while its commit is held at the test S3
//     fault proxy (staged, not committed): the leader terminates within the
//     shutdown budget although its commit is in flight, and nothing is
//     forwarded; a successor takes the Lease and commits the same run (same UID and
//     publication ID) with the exact staged archive, once;
//  3. abrupt leader failure during collection: the capture lived only in
//     the killed pod's staging volume, so the run ends as a truthful
//     CaptureLost with nothing in S3, and the next run publishes under a new
//     identity;
//  4. leader API loss while its commit is held: the leader's node drops the
//     pod's packets to the API server, while S3 stays reachable. The other
//     replica takes the Lease; the cut-off process exits on the lost
//     leadership without forwarding its commit, is not ready and serves no
//     metrics scrape (it cannot authenticate one). Meanwhile a revoked
//     operator is refused by every download replica. The successor commits
//     the same staged run once; once the API is reachable again the former
//     leader rejoins as a follower without owner metrics; no other run
//     appears and the earlier receipt keeps its identity and expiry;
//  5. loss of the leader's node while its commit is held: the replica on the
//     other worker takes the Lease and commits the same staged run once; the
//     download replica there serves the package.
//
// After every event: the binding's engine policies keep their names, UIDs
// and specs (retained, never recreated); only the Lease holder exposes
// owner metrics, equal to the current binding, and every other replica
// none; the Lease moved exactly as expected.
//
// The file sorts after helm_availability_live_test.go: it ends by stopping
// a worker, so it runs last in the group.

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3fault"
	"github.com/backend-bunny/Konstapel/internal/s3store"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Bounds for one event. They are regression guards with room for host load,
// not service levels; the measured values are recorded.
const (
	ftTakeoverBound  = 60 * time.Second                        // Lease to another running replica
	ftReconcileBound = 90 * time.Second                        // reporting-only edit reconciled
	ftTerminateBound = DefaultShutdownTimeout + 10*time.Second // graceful pod removal, below the 60s grace
	ftRequestBound   = 90 * time.Second                        // one download, retries included
	ftProbeErrBound  = 30 * time.Second                        // consecutive admission probe errors
)

func TestLiveHelmFailoverTraffic(t *testing.T) {
	image, repo, digest := liveImage(t)
	l := newLive(t)
	const ns, prefix, mon = "konstapel-system", "ft", "ft-monitoring"
	cluster := os.Getenv("KONSTAPEL_CLUSTER_NAME")
	l.eventually("two workload nodes (KONSTAPEL_CLUSTER_WORKERS=2)", func() (bool, string) {
		var nodes corev1.NodeList
		err := l.c.List(l.ctx, &nodes, client.MatchingLabels{"konstapel.dev/pool": "workload"})
		return err == nil && len(nodes.Items) >= 2, fmt.Sprintf("%d nodes, %v", len(nodes.Items), err)
	})

	// Metrics over operator TLS, scraped by a reader identity as Prometheus
	// would.
	for _, o := range []client.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: mon}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: mon, Name: "prometheus"}}} {
		if err := l.c.Create(l.ctx, o); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: mon}}) })
	mdata, metricsCA := downloadTLSData(t, ns, []string{"konstapel-controller-metrics", "konstapel-controller-metrics." + ns, metricsServiceName})
	msecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "ft-metrics-tls"}, Type: corev1.SecretTypeTLS, Data: mdata}
	if err := l.c.Create(l.ctx, msecret); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, msecret) })
	caPEM := l.installCharts(ns, repo, digest, "--set", "metrics.enabled=true", "--set", "metrics.tls.secretName="+msecret.Name,
		"--set", "metrics.readers[0].namespace="+mon, "--set", "metrics.readers[0].name=prometheus")
	var lost string // the stopped worker, once event 4 stops it
	t.Cleanup(func() {
		// Pods on a stopped node never confirm their deletion.
		if lost == "" {
			return
		}
		var pods corev1.PodList
		_ = l.c.List(l.ctx, &pods, client.InNamespace(ns))
		for _, p := range pods.Items {
			if p.Spec.NodeName == lost {
				zero := int64(0)
				_ = l.c.Delete(l.ctx, &p, &client.DeleteOptions{GracePeriodSeconds: &zero})
			}
		}
	})
	metrics := &ftMetrics{l: l, ns: ns, addrs: map[string]string{}, token: l.apiToken(mon, "prometheus")}
	metrics.roots = x509.NewCertPool()
	metrics.roots.AppendCertsFromPEM(metricsCA)

	// Publication goes through the fault proxy; tests read S3 directly.
	direct := l.chartS3(t)
	proxy := l.startFaultProxy(t)
	ed, _ := l.chartDestinationAt(t, ns, prefix, direct.Dest.Bucket, proxy.endpoint())
	store := s3Store{l: l, pub: direct, dest: s3store.Destination{Prefix: ed.Spec.S3.Prefix}}

	l.setNamespace("ft-prod", "ft-production")
	p := profileObj(t, "ft-baseline", pol)
	b := bindingObj("ft-deny", p.Name, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{envLabel: "ft-production"})
	for _, o := range []client.Object{p, b} {
		o.SetUID("")
		l.createWhenServed(o)
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, b); _ = l.c.Delete(l.ctx, p) })
	l.waitReady(b.Name, 1)
	// The first run's package is downloaded until the end, and its receipt
	// compared across the leader API loss: it must not expire meanwhile
	// (the whole test took about 6 minutes in CI, longer under load).
	l.setRetention(b.Name, "1800s", &v1alpha1.DestinationReference{Name: ed.Name, UID: string(ed.UID)})
	t.Cleanup(func() { l.dropRuns(b.Name) })
	l.waitReady(b.Name, 1)
	first := l.publishedRun(b.Name, "")
	operator, _ := l.downloadOperator(ns, "ft-operator")
	policies := l.ftPolicies(b.Name)
	if len(policies) == 0 {
		t.Fatal("no engine policy delivered for the binding")
	}
	leader := l.leaderPod(ns, "")
	metrics.owner(b.Name, leader, "")

	// Traffic starts once the engine enforces the delivered policy.
	l.eventually("a privileged pod denied by the delivered policy", func() (bool, string) {
		privileged := true
		err := l.c.Create(l.ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "ft-probe", Namespace: "ft-prod"},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &privileged}}}}},
			client.DryRunAll)
		for name := range policies {
			if err != nil && strings.Contains(err.Error(), "denied the request") && strings.Contains(err.Error(), name) {
				return true, ""
			}
		}
		return false, fmt.Sprint(err)
	})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	tr := &ftTraffic{l: l, enforced: "ft-prod", policies: policies, route: l.ftDownloadRoute(ns, cluster), roots: roots,
		token: l.token(ns, operator, downloadAudience), run: string(first.UID), want: first.Status.Publication.PackageSHA256,
		stats: map[string]*ftPhase{}, stop: make(chan struct{})}
	tr.start("baseline")
	stopped := false
	defer func() {
		if !stopped { // kept with the evidence when the test stops early
			stats, problems := tr.finish()
			l.record("traffic", map[string]any{"phases": stats, "problems": problems, "stoppedEarly": true})
			for _, p := range problems {
				t.Error(p)
			}
		}
	}()
	l.eventually("traffic flowing: a download and a denial", func() (bool, string) {
		s := tr.snapshot()["baseline"]
		return s.Downloads > 0 && s.Denied > 0, toJSON(s)
	})
	placement := map[string]string{}
	for _, c := range []string{"controller", "download"} {
		for _, p := range l.readyPods(ns, c, 2) {
			placement[p.Name] = p.Spec.NodeName
		}
	}
	l.record("baseline", map[string]any{"image": image, "placement": placement, "leader": leader, "policies": policies,
		"run": first.Name, "publicationID": first.Status.Publication.PublicationID, "downloadRoute": tr.route, "s3Endpoint": ed.Spec.S3.Endpoint})

	// after checks what every event must leave behind: retained engine
	// policies, a reconciling leader and truthful owner metrics.
	interval := 24
	after := func(event, holder, skipNode string) map[string]any {
		t.Helper()
		if got := l.ftPolicies(b.Name); toJSON(got) != toJSON(policies) {
			t.Fatalf("%s: engine policies changed (recreated or rewritten):\n before %s\n after  %s", event, toJSON(policies), toJSON(got))
		}
		interval--
		reconciled := l.ftReconcile(b.Name, fmt.Sprintf("%dh", interval))
		if got := l.ftPolicies(b.Name); toJSON(got) != toJSON(policies) {
			t.Fatalf("%s: a reporting-only edit changed the engine policies: %s", event, toJSON(got))
		}
		owned := metrics.owner(b.Name, holder, skipNode)
		return map[string]any{"policiesRetained": len(policies), "reconcileSeconds": reconciled.Seconds(), "interval": fmt.Sprintf("%dh", interval),
			"metricsOwner": holder, "metricsOwnerAfterSeconds": owned.Seconds()}
	}

	// 1. Graceful follower replacement: the leader keeps the Lease and works.
	tr.mark("graceful-follower")
	leader = l.leaderPod(ns, "")
	var follower string
	for _, p := range l.readyPods(ns, "controller", 2) {
		if p.Name != leader {
			follower = p.Name
		}
	}
	prior := l.lease(ns)
	run := l.createRun(b.Name, "ft-during-follower")
	took, exit := l.ftGracefulRemove(ns, follower)
	l.readyPods(ns, "controller", 2)
	done := l.publishedRun(b.Name, run.Name)
	if done.UID != run.UID {
		t.Fatalf("run %s published with UID %s, created %s", run.Name, done.UID, run.UID)
	}
	if cur := l.lease(ns); *cur.Spec.HolderIdentity != *prior.Spec.HolderIdentity || transitions(cur) != transitions(prior) ||
		!cur.Spec.AcquireTime.Equal(prior.Spec.AcquireTime) {
		t.Fatalf("the Lease moved when the follower was replaced:\n before %s\n after %s", toJSON(prior.Spec), toJSON(cur.Spec))
	}
	ev := after("graceful-follower", leader, "")
	ev["removed"], ev["terminatedSeconds"], ev["exit"], ev["leader"], ev["runPublished"] = follower, took.Seconds(), exit, leader, done.Status.Publication.PublicationID
	ev["leaseTransitions"] = transitions(prior)
	l.record("graceful-follower", ev)

	// 2. Graceful leader replacement while its commit is held.
	tr.mark("graceful-leader")
	held := l.ftHeld(b.Name, "ft-graceful-leader", proxy, store)
	leader = l.leaderPod(ns, "")
	prior = l.lease(ns)
	start := time.Now()
	took, exit = l.ftGracefulRemove(ns, leader)
	// The leader stopped although its commit was still in flight; nothing
	// was forwarded.
	abandoned := proxy.state()
	if abandoned.CommitsForwarded != 0 || abandoned.CommitArrivals < 1 {
		t.Fatalf("the held commit after the leader stopped: %s", toJSON(abandoned))
	}
	successor := l.leaderPod(ns, leader)
	takeover := time.Since(start)
	l.ftTransitioned(ns, prior, takeover)
	viaService := func(uid types.UID) (int, string) {
		return l.downloadPackage(l.portForward(ns, "svc/konstapel-download", 443), ns, operator, caPEM, string(uid))
	}
	rec := l.ftRecovered(b.Name, held, proxy, store, viaService, abandoned.CommitsHeld)
	ev = after("graceful-leader", successor, "")
	ev["removed"], ev["terminatedSeconds"], ev["exit"], ev["successor"], ev["leaseTakenAfterSeconds"] = leader, took.Seconds(), exit, successor, takeover.Seconds()
	ev["proxyWhenLeaderGone"], ev["recovery"] = toJSON(abandoned), rec
	l.record("graceful-leader", ev)

	// 3. Abrupt leader failure during collection.
	tr.mark("abrupt-leader")
	l.readyPods(ns, "controller", 2)
	lostRun := l.createRun(b.Name, "ft-abrupt")
	l.eventually("ft-abrupt collecting", func() (bool, string) {
		r := l.run(lostRun.Name)
		return r != nil && r.Status.Phase == v1alpha1.RunCollecting, toJSON(r)
	})
	leader = l.leaderPod(ns, "")
	prior = l.lease(ns)
	start = time.Now()
	l.forceDelete(ns, leader)
	successor = l.leaderPod(ns, leader)
	takeover = time.Since(start)
	l.ftTransitioned(ns, prior, takeover)
	var ended *v1alpha1.AssessmentRun
	l.eventually("ft-abrupt ends", func() (bool, string) {
		ended = l.run(lostRun.Name)
		return ended != nil && runDone(ended), toJSON(ended)
	})
	ref := publication.RunRef{ClusterID: first.Status.Scope.ClusterID, BindingUID: first.Status.Binding.UID, RunUID: string(lostRun.UID)}
	_, cerr := store.commit(ref)
	switch {
	case ended.UID != lostRun.UID:
		t.Fatalf("run %s has UID %s, created %s", lostRun.Name, ended.UID, lostRun.UID)
	case ended.Status.Phase != v1alpha1.RunFailed || !captureLost(ended) || (ended.Status.Publication != nil && ended.Status.Publication.PublishedAt != nil):
		t.Fatalf("a capture lost with its pod was not reported CaptureLost: %s", toJSON(ended.Status))
	case !errors.Is(cerr, publication.ErrNotFound):
		t.Fatalf("S3 holds a commit for the lost capture: %v", cerr)
	}
	next := l.publishedRun(b.Name, l.createRun(b.Name, "ft-abrupt-next").Name)
	ev = after("abrupt-leader", successor, "")
	ev["killed"], ev["successor"], ev["leaseTakenAfterSeconds"] = leader, successor, takeover.Seconds()
	ev["lostRun"], ev["outcome"], ev["nextRun"], ev["nextPublicationID"] = lostRun.Name, "CaptureLost, no commit in S3", next.Name, next.Status.Publication.PublicationID
	l.record("abrupt-leader", ev)

	// 4. Leader API loss during a handover. The leader has staged a run whose
	// commit the proxy holds; then its pod alone is cut off from the API
	// server. It still reaches S3, so only its own cancellation keeps that
	// commit from landing. While it is cut off, an operator's download grant
	// is revoked.
	tr.mark("leader-api-loss")
	retained := l.run(first.Name).Status.Publication
	runsBefore := l.ftRuns(b.Name)
	revoked, revokedCRB := l.downloadOperator(ns, "ft-revoked")
	downloadAddrs := map[string]string{}
	for _, p := range l.readyPods(ns, "download", 2) {
		downloadAddrs[p.Name] = l.portForward(ns, "pod/"+p.Name, 8443)
	}
	// eachDownload asks every download replica for the first run's package
	// as op; it reports whether every replica answered want.
	eachDownload := func(op string, want int) (bool, map[string]int) {
		got, all := map[string]int{}, true
		for name, addr := range downloadAddrs {
			code, sum := l.downloadPackage(addr, ns, op, caPEM, string(first.UID))
			if code == http.StatusOK && sum != first.Status.Publication.PackageSHA256 {
				t.Fatalf("download replica %s served %s for run %s, receipt %s", name, sum, first.Name, first.Status.Publication.PackageSHA256)
			}
			got[name] = code
			all = all && code == want
		}
		return all, got
	}
	if ok, got := eachDownload(revoked, http.StatusOK); !ok {
		t.Fatalf("the operator to be revoked cannot download before the revocation: %v", got)
	}
	held = l.ftHeld(b.Name, "ft-api-loss", proxy, store)
	leader = l.leaderPod(ns, "")
	cut := &corev1.Pod{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: leader}, cut); err != nil {
		t.Fatal(err)
	}
	restartsBefore := restarts(*cut)
	prior = l.lease(ns)
	start = time.Now()
	heal := l.ftCutOffAPI(cut)
	successor = l.leaderPod(ns, leader)
	takeover = time.Since(start)
	l.ftTransitioned(ns, prior, takeover)
	// The cut-off leader gave up on its own: its process exited on the lost
	// leadership, and its held commit, which could still reach S3, was never
	// forwarded.
	cutPod := func() *corev1.Pod {
		p := &corev1.Pod{}
		if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(cut), p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	l.eventually("the cut-off former leader's process exited", func() (bool, string) {
		return restarts(*cutPod()) > restartsBefore, l.podDiagnostics(ns)
	})
	exited := time.Since(start)
	abandoned = proxy.state()
	if abandoned.CommitsForwarded != 0 || abandoned.CommitArrivals < 1 {
		t.Fatalf("the cut-off former leader's held commit: %s", toJSON(abandoned))
	}
	// Without the API it is no ready endpoint, and its metrics fail closed:
	// it cannot authenticate a scrape, so nothing it remembers is served.
	l.eventually("the cut-off replica not ready", func() (bool, string) { return !ftReady(cutPod()), l.podDiagnostics(ns) })
	var refusals []string
	for range 5 {
		delete(metrics.addrs, cut.Name) // a port-forward may end with the restarted container
		body, err := metrics.scrape(cut.Name)
		if err == nil {
			for _, s := range ftParse(body) {
				if ftOwnerSeries(s.name) || (s.name == "konstapel_observation_ready" && s.value != 0) {
					t.Fatalf("the cut-off former leader %s exposes %s{%s} %v", cut.Name, s.name, s.labels, s.value)
				}
			}
			t.Fatalf("the cut-off former leader %s served a scrape it could not authenticate", cut.Name)
		}
		refusals = append(refusals, err.Error())
		time.Sleep(2 * time.Second)
	}
	// Revocation during the handover: the next request through every
	// download replica is refused, while the other operator keeps access.
	if err := l.c.Delete(l.ctx, revokedCRB); err != nil {
		t.Fatal(err)
	}
	revokedAt := time.Now()
	l.eventually("the revoked operator refused by every download replica", func() (bool, string) {
		ok, got := eachDownload(revoked, http.StatusForbidden)
		return ok, fmt.Sprint(got)
	})
	refusedAfter := time.Since(revokedAt)
	if ok, got := eachDownload(operator, http.StatusOK); !ok {
		t.Fatalf("the unrevoked operator after the revocation: %v", got)
	}
	// While the former leader is still cut off, the successor commits the
	// held run once, with the staged bytes, and owns the metrics.
	rec = l.ftRecovered(b.Name, held, proxy, store, viaService, abandoned.CommitsHeld)
	ev = after("leader-api-loss", successor, "")
	heal()
	healed := time.Now()
	l.eventually("the former leader ready again with the API reachable", func() (bool, string) { return ftReady(cutPod()), l.podDiagnostics(ns) })
	rejoined := time.Since(healed)
	// It rejoins as a follower: the Lease stays with the successor, and only
	// the successor exposes owner metrics.
	if cur := l.lease(ns); transitions(cur) != transitions(prior)+1 || !strings.HasPrefix(*cur.Spec.HolderIdentity, successor+"_") {
		t.Fatalf("the Lease after the former leader rejoined:\n before %s\n after %s", toJSON(prior.Spec), toJSON(cur.Spec))
	}
	delete(metrics.addrs, cut.Name)
	metrics.owner(b.Name, successor, "")
	// Nothing fabricated: the held run is the only new run, and the earlier
	// receipt keeps its identity and expiry.
	if added := ftAdded(runsBefore, l.ftRuns(b.Name)); len(added) != 1 || added[0] != held.run.Name {
		t.Fatalf("runs added during the leader API loss: %v, want only %s", added, held.run.Name)
	}
	if now := l.run(first.Name).Status.Publication; toJSON(now) != toJSON(retained) {
		t.Fatalf("the earlier receipt changed:\n before %s\n after  %s", toJSON(retained), toJSON(now))
	}
	ev["cutOff"], ev["successor"], ev["leaseTakenAfterSeconds"], ev["formerLeaderExitedAfterSeconds"] = leader, successor, takeover.Seconds(), exited.Seconds()
	ev["scrapesWhileCutOff"], ev["revokedRefusedAfterSeconds"], ev["rejoinedAfterHealSeconds"] = refusals, refusedAfter.Seconds(), rejoined.Seconds()
	ev["proxyWhenLeaderGone"], ev["recovery"], ev["retainedReceipt"] = toJSON(abandoned), rec, retained
	l.record("leader-api-loss", ev)

	// 5. Loss of the leader's node while its commit is held. The replicas
	// must sit on different workers, or the node takes both.
	tr.mark("node-loss")
	l.ftSpread(ns)
	held = l.ftHeld(b.Name, "ft-node-loss", proxy, store)
	leader = l.leaderPod(ns, "")
	leaderPod := &corev1.Pod{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: leader}, leaderPod); err != nil {
		t.Fatal(err)
	}
	lostNode := leaderPod.Spec.NodeName
	if !strings.HasPrefix(lostNode, cluster+"-worker") {
		t.Fatalf("leader on unexpected node %s", lostNode)
	}
	prior = l.lease(ns)
	start = time.Now()
	lost = lostNode
	if out, err := exec.Command("docker", "stop", lostNode).CombinedOutput(); err != nil {
		t.Fatalf("stop node %s: %v %s", lostNode, err, out)
	}
	// The stopped node's process sends nothing more.
	frozen := proxy.state()
	successor = l.leaderPod(ns, leader)
	takeover = time.Since(start)
	l.ftTransitioned(ns, prior, takeover)
	// kubectl port-forward to the Service could pick the endpoint on the
	// stopped node: read through the download replica on the other one.
	var survivor string
	for _, p := range l.podsReady(ns, "download") {
		if p.Spec.NodeName != lostNode {
			survivor = p.Name
		}
	}
	if survivor == "" {
		t.Fatal("no download replica on the surviving node")
	}
	viaSurvivor := func(uid types.UID) (int, string) {
		return l.downloadPackage(l.portForward(ns, "pod/"+survivor, 8443), ns, operator, caPEM, string(uid))
	}
	rec = l.ftRecovered(b.Name, held, proxy, store, viaSurvivor, frozen.CommitsHeld)
	ev = after("node-loss", successor, lostNode)
	if code, sum := viaSurvivor(first.UID); code != http.StatusOK || sum != first.Status.Publication.PackageSHA256 {
		t.Fatalf("download from %s after node loss: %d", survivor, code)
	}
	ev["node"], ev["from"], ev["to"], ev["leaseTakenAfterSeconds"], ev["downloadFrom"], ev["recovery"] = lostNode, leader, successor, takeover.Seconds(), survivor, rec
	l.record("node-loss", ev)

	// The traffic verdict.
	stats, problems := tr.finish()
	stopped = true
	l.record("traffic", map[string]any{"phases": stats, "problems": problems})
	for _, p := range problems {
		t.Error(p)
	}
	for _, phase := range tr.order {
		if s := stats[phase]; s.Downloads == 0 || s.Denied == 0 || s.Compliant == 0 {
			t.Errorf("phase %s had no successful traffic of every kind: %s", phase, toJSON(s))
		}
	}
	if t.Failed() {
		return
	}

	// The new leader still delivers policy changes after the node loss.
	got := l.binding(b.Name)
	got.Spec.Mode = v1alpha1.ModeAudit
	if err := l.c.Update(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	l.waitReady(b.Name, 1)
}

// ftHeldRun is a run whose package the leader staged and whose commit the
// proxy holds.
type ftHeldRun struct {
	run    *v1alpha1.AssessmentRun
	ref    publication.RunRef
	staged stagedAttempt
	watch  func() []string
}

// ftHeld creates a run, holds its commit at the proxy and returns it once
// the leader has durably staged its package and nothing is committed.
func (l *live) ftHeld(binding, name string, proxy *faultProxy, store s3Store) ftHeldRun {
	l.t.Helper()
	l.readyPods("konstapel-system", "controller", 2)
	run := l.createRun(binding, name)
	proxy.arm(s3fault.ModeHold, run.UID)
	watch := l.watchRun(run.Name, run.UID)
	proxy.waitFor("the leader's commit of "+name+" held", func(st s3fault.State) bool { return st.CommitsHeld >= 1 && st.Waiting >= 1 })
	cur := l.publishingWithoutReceipt(name)
	ref := publication.RunRef{ClusterID: cur.Status.Scope.ClusterID, BindingUID: cur.Status.Binding.UID, RunUID: string(run.UID)}
	staged := store.onlyAttempt(ref)
	if _, err := store.commit(ref); !errors.Is(err, publication.ErrNotFound) {
		l.t.Fatalf("commit exists while the commit request is held: %v", err)
	}
	return ftHeldRun{run: run, ref: ref, staged: staged, watch: watch}
}

// ftRecovered waits until the successor's commit of the held run reaches
// the proxy (more held commits than the former leader's leaderHeld), checks
// the run stays Publishing with its identity, releases the hold and
// verifies the same run committed once with the exact staged archive,
// recorded and downloadable.
func (l *live) ftRecovered(binding string, h ftHeldRun, proxy *faultProxy, store s3Store, download func(types.UID) (int, string), leaderHeld int) map[string]any {
	t := l.t
	t.Helper()
	proxy.waitFor("the successor's commit of "+h.run.Name+" held", func(st s3fault.State) bool { return st.CommitsHeld > leaderHeld })
	l.stillPublishing(binding, h.run.Name, h.run.UID, 10*time.Second)
	proxy.release()
	done := l.publishedRun(binding, h.run.Name)
	phases := h.watch()
	l.checkPhases(phases)
	m, _ := store.mustCommit(h.ref)
	st := proxy.state()
	pub := done.Status.Publication
	code, sum := download(h.run.UID)
	switch {
	case done.UID != h.run.UID:
		t.Fatalf("published run %s has UID %s, staged %s", done.Name, done.UID, h.run.UID)
	case pub.PublicationID != h.ref.PublicationID() || m.PublicationID != h.ref.PublicationID():
		t.Fatalf("publication %s (commit %s), staged run %s", pub.PublicationID, m.PublicationID, h.ref.PublicationID())
	case pub.PackageSHA256 != h.staged.PackageSHA256 || m.PackageSHA256 != h.staged.PackageSHA256 || code != http.StatusOK || sum != h.staged.PackageSHA256:
		t.Fatalf("staged %s, receipt %s, commit %s, downloaded %d %s", h.staged.PackageSHA256, pub.PackageSHA256, m.PackageSHA256, code, sum)
	case m.ArchiveKey != h.staged.ArchiveKey || m.ArchiveVersionID != h.staged.ArchiveVersionID:
		t.Fatalf("committed archive %s@%s, staged %s@%s", m.ArchiveKey, m.ArchiveVersionID, h.staged.ArchiveKey, h.staged.ArchiveVersionID)
	case st.CommitsForwarded != 1 || store.commitVersions(h.ref) != 1:
		t.Fatalf("commit forwarded %d times, %d commit versions: %s", st.CommitsForwarded, store.commitVersions(h.ref), toJSON(st))
	}
	return map[string]any{"run": done.Name, "uid": done.UID, "publicationID": pub.PublicationID, "stagedSha256": h.staged.PackageSHA256,
		"downloadedSha256": sum, "archiveKey": m.ArchiveKey, "expiresAt": pub.ExpiresAt.UTC(), "phases": phases,
		"commitArrivals": st.CommitArrivals, "commitsHeld": st.CommitsHeld, "commitsForwarded": st.CommitsForwarded}
}

// ftTransitioned checks a takeover: exactly one more Lease transition,
// within the bound.
func (l *live) ftTransitioned(ns string, prior *coordinationv1.Lease, took time.Duration) {
	l.t.Helper()
	if cur := l.lease(ns); transitions(cur) != transitions(prior)+1 {
		l.t.Fatalf("Lease takeover:\n before %s\n after %s", toJSON(prior.Spec), toJSON(cur.Spec))
	}
	if took > ftTakeoverBound {
		l.t.Fatalf("takeover took %s, bound %s", took, ftTakeoverBound)
	}
}

// ftCutOffAPI cuts pod alone off from the Kubernetes API server: its node
// drops every packet from the pod's IP to each API server endpoint of the
// kubernetes Service (inserted first in FORWARD, so open connections stall
// as in a partition rather than closing). The pod keeps its other traffic
// (S3), and port-forwards through the kubelet still reach it. The returned
// function removes the rules; the test's cleanup does if it was not called.
func (l *live) ftCutOffAPI(pod *corev1.Pod) (heal func()) {
	t := l.t
	t.Helper()
	if pod.Status.PodIP == "" || pod.Spec.NodeName == "" {
		t.Fatalf("pod %s has no IP or node", pod.Name)
	}
	var eps discoveryv1.EndpointSliceList
	if err := l.c.List(l.ctx, &eps, client.InNamespace(metav1.NamespaceDefault), client.MatchingLabels{discoveryv1.LabelServiceName: "kubernetes"}); err != nil {
		t.Fatal(err)
	}
	var rules [][]string
	for _, s := range eps.Items {
		for _, port := range s.Ports {
			for _, e := range s.Endpoints {
				for _, a := range e.Addresses {
					if port.Port != nil && !strings.Contains(a, ":") {
						rules = append(rules, []string{"FORWARD", "-s", "192.0.2.1", "-d", a, // HAND-BREAK: the rule matches no pod
							"-p", "tcp", "--dport", strconv.Itoa(int(*port.Port)), "-j", "DROP"})
					}
				}
			}
		}
	}
	if len(rules) == 0 {
		t.Fatalf("no IPv4 API server endpoint: %s", toJSON(eps.Items))
	}
	iptables := func(op string, rule []string) error {
		out, err := exec.Command("docker", append([]string{"exec", pod.Spec.NodeName, "iptables", op}, rule...)...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables %s %v on %s: %v %s", op, rule, pod.Spec.NodeName, err, out)
		}
		return nil
	}
	healed := false
	heal = func() {
		t.Helper()
		if healed {
			return
		}
		healed = true
		for _, r := range rules {
			if err := iptables("-D", r); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() {
		if !healed {
			for _, r := range rules {
				_ = iptables("-D", r)
			}
		}
	})
	for _, r := range rules {
		if err := iptables("-I", r); err != nil {
			t.Fatal(err)
		}
	}
	return heal
}

// ftReady reports the pod's Ready condition.
func ftReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// ftRuns lists the names of the binding's runs.
func (l *live) ftRuns(binding string) map[string]bool {
	l.t.Helper()
	var runs v1alpha1.AssessmentRunList
	if err := l.c.List(l.ctx, &runs); err != nil {
		l.t.Fatal(err)
	}
	out := map[string]bool{}
	for _, r := range runs.Items {
		if r.Spec.BindingRef.Name == binding {
			out[r.Name] = true
		}
	}
	return out
}

// ftAdded is the sorted names in after but not in before.
func ftAdded(before, after map[string]bool) []string {
	var out []string
	for n := range after {
		if !before[n] {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// ftPolicies maps the binding's delivered engine policies to their UID and
// spec digest: a recreated or rewritten policy changes its entry.
func (l *live) ftPolicies(binding string) map[string]string {
	l.t.Helper()
	b := l.binding(binding)
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(targeting.ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
	if err := l.c.List(l.ctx, list, client.MatchingLabels{targeting.LabelManagedBy: targeting.ManagedByValue, targeting.LabelBindingUID: string(b.UID)}); err != nil {
		l.t.Fatal(err)
	}
	out := map[string]string{}
	for _, o := range list.Items {
		out[o.GetName()] = fmt.Sprintf("%s/%x", o.GetUID(), sha256.Sum256([]byte(toJSON(o.Object["spec"]))))
	}
	return out
}

// ftReconcile makes a reporting-only edit (the assessment interval) and
// waits until the leader has reconciled that generation.
func (l *live) ftReconcile(binding, interval string) time.Duration {
	l.t.Helper()
	start := time.Now()
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		b := l.binding(binding)
		b.Spec.Assessment.Interval = v1alpha1.Duration(interval)
		return l.c.Update(l.ctx, b)
	}); err != nil {
		l.t.Fatal(err)
	}
	l.waitReady(binding, 1)
	took := time.Since(start)
	if took > ftReconcileBound {
		l.t.Fatalf("reporting-only edit reconciled after %s, bound %s", took, ftReconcileBound)
	}
	return took
}

// ftGracefulRemove deletes a controller pod with its default grace period
// and waits until it is gone. Removal within the shutdown budget (well
// below the 60s grace) means the process stopped on its own; an observed
// SIGKILL exit fails.
func (l *live) ftGracefulRemove(ns, pod string) (time.Duration, string) {
	l.t.Helper()
	start := time.Now()
	if err := l.c.Delete(l.ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: pod}}); err != nil {
		l.t.Fatal(err)
	}
	exit := "not observed"
	for {
		p := &corev1.Pod{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: pod}, p); apierrors.IsNotFound(err) {
			break
		}
		for _, s := range p.Status.ContainerStatuses {
			if s.Name == "controller" && s.State.Terminated != nil {
				exit = fmt.Sprintf("%d %s", s.State.Terminated.ExitCode, s.State.Terminated.Reason)
				if s.State.Terminated.ExitCode == 137 {
					l.t.Fatalf("%s was killed after its grace period: %s", pod, toJSON(s.State.Terminated))
				}
			}
		}
		if time.Since(start) > 90*time.Second {
			l.t.Fatalf("%s still present after %s: %s", pod, time.Since(start), l.podDiagnostics(ns))
		}
		time.Sleep(250 * time.Millisecond)
	}
	took := time.Since(start)
	if took > ftTerminateBound {
		l.t.Fatalf("%s took %s to terminate, budget %s", pod, took, ftTerminateBound)
	}
	return took, exit
}

// ftSpread makes sure the two ready replicas of each Deployment run on
// different workers, replacing a co-located one with its node cordoned.
func (l *live) ftSpread(ns string) {
	l.t.Helper()
	for _, c := range []string{"controller", "download"} {
		pods := l.readyPods(ns, c, 2)
		if pods[0].Spec.NodeName != pods[1].Spec.NodeName {
			continue
		}
		shared, victim := pods[0].Spec.NodeName, pods[1].Name
		if c == "controller" && victim == l.leaderPod(ns, "") {
			victim = pods[0].Name
		}
		l.cordon(shared, true)
		if err := l.c.Delete(l.ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: victim}}); err != nil {
			l.t.Fatal(err)
		}
		l.eventually(c+" replicas on different workers", func() (bool, string) {
			p := l.podsReady(ns, c)
			return len(p) == 2 && p[0].Spec.NodeName != p[1].Spec.NodeName, l.podDiagnostics(ns)
		})
		l.cordon(shared, false)
	}
}

// ftDownloadRoute exposes the download pods through a test-owned NodePort
// Service with the chart Service's selector and target port, and returns
// its address on the control-plane node, which stays up: kube-proxy sends
// each new connection to a ready endpoint, as the chart Service would.
func (l *live) ftDownloadRoute(ns, cluster string) string {
	l.t.Helper()
	chart := &corev1.Service{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: "konstapel-download"}, chart); err != nil {
		l.t.Fatal(err)
	}
	if chart.Spec.SessionAffinity == corev1.ServiceAffinityClientIP {
		l.t.Fatal("the chart download Service has session affinity")
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "ft-download-route"}, Spec: corev1.ServiceSpec{
		Type: corev1.ServiceTypeNodePort, Selector: chart.Spec.Selector,
		Ports: []corev1.ServicePort{{Name: "https", Port: 443, TargetPort: chart.Spec.Ports[0].TargetPort, Protocol: corev1.ProtocolTCP}}}}
	if svc.Spec.Ports[0].TargetPort == (intstr.IntOrString{}) {
		svc.Spec.Ports[0].TargetPort = intstr.FromInt32(chart.Spec.Ports[0].Port)
	}
	if err := l.c.Create(l.ctx, svc); err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { _ = l.c.Delete(l.ctx, svc) })
	node := &corev1.Node{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: cluster + "-control-plane"}, node); err != nil {
		l.t.Fatal(err)
	}
	var ip string
	for _, a := range node.Status.Addresses {
		if a.Type == corev1.NodeInternalIP && !strings.Contains(a.Address, ":") {
			ip = a.Address
		}
	}
	if ip == "" {
		l.t.Fatalf("no IPv4 address on %s", node.Name)
	}
	return net.JoinHostPort(ip, strconv.Itoa(int(svc.Spec.Ports[0].NodePort)))
}

// ftMetrics scrapes each controller pod's authenticated metrics endpoint.
type ftMetrics struct {
	l     *live
	ns    string
	roots *x509.CertPool
	token string
	addrs map[string]string
}

func (m *ftMetrics) scrape(pod string) (string, error) {
	addr, ok := m.addrs[pod]
	if !ok {
		addr = m.l.portForward(m.ns, "pod/"+pod, 8443)
		m.addrs[pod] = addr
	}
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: m.roots, ServerName: metricsServiceName}}}
	req, _ := http.NewRequestWithContext(m.l.ctx, http.MethodGet, "https://"+addr+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+m.token)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("scrape %s: %d %v", pod, resp.StatusCode, err)
	}
	return string(b), nil
}

// ftSample is one exposition line.
type ftSample struct {
	name, labels string
	value        float64
}

func ftParse(body string) []ftSample {
	var out []ftSample
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			continue
		}
		v, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			continue
		}
		series := line[:i]
		name, labels, _ := strings.Cut(series, "{")
		out = append(out, ftSample{name: name, labels: strings.TrimSuffix(labels, "}"), value: v})
	}
	return out
}

func ftOwnerSeries(name string) bool {
	for _, p := range []string{"konstapel_binding_", "konstapel_capability_", "konstapel_publication_", "konstapel_cleanup_"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// owner waits until the Lease holder exposes the binding's owner series
// equal to the binding now (creation time, target namespaces, interval)
// and is ready in every enabled domain. Every other ready replica (except
// those on skipNode) must expose no owner series and no ready domain at
// any scrape. It returns how long that took.
func (m *ftMetrics) owner(binding, holder, skipNode string) time.Duration {
	l := m.l
	l.t.Helper()
	start := time.Now()
	l.eventually("only "+holder+" exposes owner metrics, matching the binding", func() (bool, string) {
		b := l.binding(binding)
		interval, err := time.ParseDuration(string(b.Spec.Assessment.Interval))
		if err != nil {
			l.t.Fatal(err)
		}
		sel := `binding="` + binding + `"`
		seen := false
		var missing []string
		for _, p := range l.podsReady(m.ns, "controller") {
			if p.Spec.NodeName == skipNode {
				continue
			}
			body, err := m.scrape(p.Name)
			if err != nil {
				return false, err.Error()
			}
			samples := ftParse(body)
			if p.Name != holder {
				for _, s := range samples {
					if ftOwnerSeries(s.name) || (s.name == "konstapel_observation_ready" && s.value != 0) {
						l.t.Fatalf("replica %s, not the Lease holder %s, exposes %s{%s} %v", p.Name, holder, s.name, s.labels, s.value)
					}
				}
				continue
			}
			seen = true
			want := map[string]float64{"konstapel_binding_created_timestamp_seconds": float64(b.CreationTimestamp.Unix()),
				"konstapel_binding_target_namespaces": 1, "konstapel_binding_assessment_interval_seconds": interval.Seconds()}
			enabled, ready := map[string]bool{}, map[string]bool{}
			for _, s := range samples {
				if w, ok := want[s.name]; ok && strings.Contains(s.labels, sel) && s.value == w {
					delete(want, s.name)
				}
				if s.name == "konstapel_observation_enabled" && s.value == 1 {
					enabled[s.labels] = true
				}
				if s.name == "konstapel_observation_ready" && s.value == 1 {
					ready[s.labels] = true
				}
			}
			for k := range want {
				missing = append(missing, k)
			}
			for d := range enabled {
				if !ready[d] {
					missing = append(missing, "ready "+d)
				}
			}
			if len(enabled) == 0 {
				missing = append(missing, "no enabled domain")
			}
		}
		return seen && len(missing) == 0, fmt.Sprintf("holder scraped %v, missing %v", seen, missing)
	})
	return time.Since(start)
}

// ftTraffic is the client traffic kept running across every event.
type ftTraffic struct {
	l             *live
	enforced      string
	policies      map[string]string
	route, token  string
	roots         *x509.CertPool
	run, want     string
	mu            sync.Mutex
	phase         string
	order         []string
	stats         map[string]*ftPhase
	problems      []string
	stop          chan struct{}
	wg            sync.WaitGroup
	finished      bool
	finalStats    map[string]ftPhase
	finalProblems []string
}

// ftPhase is what clients saw during one event.
type ftPhase struct {
	Downloads          int      `json:"downloads"`
	DownloadAttempts   int      `json:"downloadAttempts"`
	TransientFailures  int      `json:"transientDownloadFailures"`
	FirstFailure       string   `json:"firstFailure,omitempty"`
	LastFailure        string   `json:"lastFailure,omitempty"`
	FailureSamples     []string `json:"failureSamples,omitempty"`
	MaxDownloadSeconds float64  `json:"maxDownloadSeconds"`
	Denied             int      `json:"privilegedDenied"`
	Compliant          int      `json:"compliantAdmitted"`
	ProbeErrors        int      `json:"admissionProbeErrors"`
	ProbeErrorSamples  []string `json:"admissionProbeErrorSamples,omitempty"`
}

func (tr *ftTraffic) start(phase string) {
	tr.mark(phase)
	tr.wg.Add(2)
	go tr.downloads()
	go tr.admission()
}

func (tr *ftTraffic) mark(phase string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.phase = phase
	tr.order = append(tr.order, phase)
	tr.stats[phase] = &ftPhase{}
}

// cur is the current phase's stats; call with mu held.
func (tr *ftTraffic) cur() *ftPhase { return tr.stats[tr.phase] }

func (tr *ftTraffic) problem(format string, args ...any) {
	msg := fmt.Sprintf("[%s %s] ", time.Now().UTC().Format(time.RFC3339), tr.phase) + fmt.Sprintf(format, args...)
	if len(tr.problems) < 50 {
		tr.problems = append(tr.problems, msg)
	}
}

func (tr *ftTraffic) snapshot() map[string]ftPhase {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	out := map[string]ftPhase{}
	for k, v := range tr.stats {
		out[k] = *v
	}
	return out
}

// finish stops the traffic and returns its per-phase record and every
// problem seen.
func (tr *ftTraffic) finish() (map[string]ftPhase, []string) {
	if !tr.finished {
		tr.finished = true
		close(tr.stop)
		tr.wg.Wait()
		tr.finalStats = tr.snapshot()
		tr.mu.Lock()
		tr.finalProblems = append([]string(nil), tr.problems...)
		tr.mu.Unlock()
	}
	return tr.finalStats, tr.finalProblems
}

func (tr *ftTraffic) wait() bool {
	select {
	case <-tr.stop:
		return false
	case <-time.After(time.Second):
		return true
	}
}

// downloads requests the package once a second. A request is retried on
// transport errors, 503 and 429 (each a recorded transient failure) and
// must succeed with the receipt's package within ftRequestBound; any other
// answer is a problem.
func (tr *ftTraffic) downloads() {
	defer tr.wg.Done()
	for tr.wait() {
		start := time.Now()
		for attempt := 1; ; attempt++ {
			code, sum, err := tr.get()
			now := time.Now()
			tr.mu.Lock()
			st := tr.cur()
			st.DownloadAttempts++
			ok, retry := false, false
			switch {
			case err == nil && code == http.StatusOK && sum == tr.want:
				ok = true
				st.Downloads++
				if d := now.Sub(start).Seconds(); d > st.MaxDownloadSeconds {
					st.MaxDownloadSeconds = d
				}
			case err == nil && code == http.StatusOK:
				tr.problem("download returned a package with SHA-256 %s, receipt %s", sum, tr.want)
			case err != nil || code == http.StatusServiceUnavailable || code == http.StatusTooManyRequests:
				retry = true
				st.TransientFailures++
				at := now.UTC().Format("15:04:05.000")
				if st.FirstFailure == "" {
					st.FirstFailure = at
				}
				st.LastFailure = at
				if len(st.FailureSamples) < 5 {
					st.FailureSamples = append(st.FailureSamples, fmt.Sprintf("%s attempt %d: %d %v", at, attempt, code, err))
				}
				if now.Sub(start) > ftRequestBound {
					tr.problem("no ready download replica answered within %s (%d attempts): %d %v", ftRequestBound, attempt, code, err)
					retry = false
				}
			default:
				tr.problem("download answered %d", code)
			}
			tr.mu.Unlock()
			if ok || !retry {
				break
			}
			select {
			case <-tr.stop:
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
}

// get downloads over a new connection, so every attempt is routed anew.
func (tr *ftTraffic) get() (int, string, error) {
	hc := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DisableKeepAlives: true,
		DialContext:     (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{RootCAs: tr.roots, ServerName: "konstapel-download.konstapel-system.svc"}}}
	req, _ := http.NewRequestWithContext(tr.l.ctx, http.MethodGet, "https://"+tr.route+"/v1/assessmentruns/"+tr.run+"/download", nil)
	req.Header.Set("Authorization", "Bearer "+tr.token)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", err // interrupted transfer: retried in full
	}
	return resp.StatusCode, fmt.Sprintf("%x", sha256.Sum256(b)), nil
}

// admission sends a privileged dry-run pod to the enforced namespace once a
// second, and a compliant one every fifth second. An admitted privileged
// pod, a compliant pod denied by a policy, or probe errors lasting longer
// than ftProbeErrBound are problems.
func (tr *ftTraffic) admission() {
	defer tr.wg.Done()
	var failingSince time.Time
	reported := false
	for i := 0; tr.wait(); i++ {
		compliant := i%5 == 0
		privileged := !compliant
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "ft-probe", Namespace: tr.enforced},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &privileged}}}}}
		err := tr.l.c.Create(tr.l.ctx, pod, client.DryRunAll)
		denied := false
		if err != nil && strings.Contains(err.Error(), "denied the request") {
			for name := range tr.policies {
				denied = denied || strings.Contains(err.Error(), name)
			}
		}
		now := time.Now()
		tr.mu.Lock()
		st := tr.cur()
		healthy := true
		switch {
		case compliant && err == nil:
			st.Compliant++
		case compliant && denied:
			tr.problem("a compliant pod was denied: %v", err)
		case !compliant && err == nil:
			tr.problem("a privileged pod was admitted in the enforced namespace")
		case !compliant && denied:
			st.Denied++
		default:
			healthy = false
			st.ProbeErrors++
			if len(st.ProbeErrorSamples) < 5 {
				st.ProbeErrorSamples = append(st.ProbeErrorSamples, now.UTC().Format("15:04:05.000")+" "+err.Error())
			}
		}
		if healthy {
			failingSince, reported = time.Time{}, false
		} else if failingSince.IsZero() {
			failingSince = now
		} else if now.Sub(failingSince) > ftProbeErrBound && !reported {
			reported = true
			tr.problem("admission probes failed for over %s: %v", ftProbeErrBound, err)
		}
		tr.mu.Unlock()
	}
}
