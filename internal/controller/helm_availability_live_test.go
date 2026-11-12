//go:build live

package controller

// Availability of the Helm-installed controller image on a multi-node
// cluster (add-controller-high-availability 5.2–5.6; group "availability",
// one control plane running Kyverno and two workers for Konstapel). Every
// case runs against the packaged image under the chart's ServiceAccount:
//   - placement, Lease holder and two ready replicas of each Deployment;
//   - the Lease lifecycle under the chart's minimal Lease grants (get and
//     update of the named Lease, create): creation on a fresh install,
//     renewal under contention, takeover after graceful replacement, a
//     restart from zero replicas and abrupt leader loss, election Events,
//     no refused Lease request in any controller log, and the
//     ServiceAccount's allowed/refused Lease requests;
//   - PodDisruptionBudget refusal of an availability-breaking eviction;
//   - a rolling upgrade that never drops below two ready controllers, and a
//     surge blocked by missing capacity that keeps both serving;
//   - preferred separation: replicas co-locate when one worker is cordoned;
//   - development values: one replica, no PDB, a drain proceeds;
//   - a controller outage: retained Kyverno enforcement and downloads;
//   - abrupt leader pod loss: a successor leads and reconciles;
//   - leader loss during an S3 outage after capture: the run stays
//     Publishing (uncertain, not CaptureLost) and, with the capture lost
//     with the pod, ends as a truthful CaptureLost; the next run publishes;
//   - loss of the leader's node: the other node leads and keeps serving.

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

func TestLiveHelmAvailability(t *testing.T) {
	image, repo, digest := liveImage(t)
	l := newLive(t)
	const ns = "konstapel-system"
	cluster := os.Getenv("KONSTAPEL_CLUSTER_NAME")
	var nodes corev1.NodeList
	_ = l.c.List(l.ctx, &nodes, client.MatchingLabels{"konstapel.dev/pool": "workload"})
	if len(nodes.Items) < 2 {
		t.Fatalf("need two workload nodes (KONSTAPEL_CLUSTER_WORKERS=2), have %d", len(nodes.Items))
	}

	// Install both charts with operator TLS. A Lease left by an earlier
	// installation is removed first, so the chart's controllers create it
	// under the chart Role.
	if err := l.c.Delete(l.ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: LeaderElectionID}}); err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	caPEM := l.installCharts(ns, repo, digest)

	// 1. Placement: two ready replicas of each Deployment, on both workers
	// (preferred anti-affinity), and one Lease holder.
	ctrl := l.readyPods(ns, "controller", 2)
	dl := l.readyPods(ns, "download", 2)
	leader := l.leaderPod(ns, "")

	// 1a. Lease lifecycle under the chart's reduced Lease grants (get/update
	// of the named Lease, create): a controller created the Lease, the
	// holder renews it while the other replica contends, the election's
	// Events are written, and nothing logged a refused Lease request. The
	// ServiceAccount boundary is checked against the API server.
	created := l.lease(ns)
	if created == nil || transitions(created) != 0 {
		t.Fatalf("Lease after a fresh install: %s", toJSON(created))
	}
	held := l.leaseHeld(ns)
	l.eventually("LeaderElection Event for the holder", func() (bool, string) {
		return l.electionEvent(ns, *l.lease(ns).Spec.HolderIdentity), ""
	})
	reviews := l.leaseBoundary(ns)
	l.noLeaseDenials(ns)
	l.record("lease", map[string]any{"created": toJSON(created.Spec), "held": held, "reviews": reviews})
	placement := map[string]string{}
	for _, p := range append(ctrl, dl...) {
		placement[p.Name] = p.Spec.NodeName
	}
	if ctrl[0].Spec.NodeName == ctrl[1].Spec.NodeName || dl[0].Spec.NodeName == dl[1].Spec.NodeName {
		t.Fatalf("replicas share a node although two are schedulable: %v", placement)
	}
	l.record("placement", map[string]any{"pods": placement, "leader": leader, "image": image})

	// Policy delivery, a published run and an authorized download.
	l.setNamespace("ha-prod", "ha-production")
	p := profileObj(t, "ha-baseline", pol)
	b := bindingObj("ha-deny", p.Name, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{envLabel: "ha-production"})
	for _, o := range []client.Object{p, b} {
		o.SetUID("")
		l.createWhenServed(o)
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, b); _ = l.c.Delete(l.ctx, p) })
	l.waitReady(b.Name, 1)
	l.eventually("installed controller enforces", func() (bool, string) { return l.denied("ha-prod") })
	pub, ed, credentials := l.chartDestination(t, ns, "ha")
	_ = pub
	got := l.binding(b.Name)
	got.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "20s",
		DestinationRef: &v1alpha1.DestinationReference{Name: ed.Name, UID: string(ed.UID)}}
	if err := l.c.Update(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.dropRuns(b.Name) })
	run := l.publishedRun(b.Name, "")
	operator, crb := l.downloadOperator(ns, "ha-operator")
	_ = crb
	download := func(addr string) (int, string) { return l.downloadPackage(addr, ns, operator, caPEM, string(run.UID)) }
	if code, sum := download(l.portForward(ns, "svc/konstapel-download", 443)); code != http.StatusOK || sum != run.Status.Publication.PackageSHA256 {
		t.Fatalf("download: %d %s", code, sum)
	}
	_ = credentials

	// 2. PodDisruptionBudget: one voluntary eviction proceeds; a second,
	// before the replacement is ready, is refused.
	evict := func(pod string) error {
		return l.c.SubResource("eviction").Create(l.ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: pod}},
			&policyv1.Eviction{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: pod}})
	}
	if err := evict(ctrl[0].Name); err != nil {
		t.Fatalf("first eviction: %v", err)
	}
	if err := evict(ctrl[1].Name); !apierrors.IsTooManyRequests(err) {
		t.Fatalf("second eviction while the replacement is not ready: %v", err)
	}
	ctrl = l.readyPods(ns, "controller", 2)
	l.record("pdb", map[string]any{"firstEviction": "allowed", "secondEviction": "refused (429)"})

	// 3. Rolling upgrade: a pod-template change rolls both replicas while
	// at least two stay ready (maxUnavailable 0, maxSurge 1).
	before := map[string]bool{ctrl[0].Name: true, ctrl[1].Name: true}
	done := make(chan error, 1)
	go func() {
		out, err := l.helm(append([]string{"upgrade", "konstapel", chartArchive(t, "konstapel"), "--namespace", ns, "--wait", "--timeout", "5m",
			"-f", "../../docs/examples/charts/operator-tls.yaml", "--set", "controller.resources.requests.cpu=110m"}, imageValues(repo, digest)...)...)
		if err != nil {
			err = fmt.Errorf("%v: %s", err, out)
		}
		done <- err
	}()
	minReady, rolled := 2, false
	for !rolled {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("rolling upgrade: %v", err)
			}
			rolled = true
		case <-time.After(time.Second):
		}
		if n := len(l.podsReady(ns, "controller")); n < minReady {
			minReady = n
		}
	}
	after := l.readyPods(ns, "controller", 2)
	for _, p := range after {
		if before[p.Name] {
			t.Fatalf("pod %s was not replaced by the upgrade", p.Name)
		}
	}
	if minReady < 2 {
		t.Fatalf("ready controllers dropped to %d during the rolling upgrade", minReady)
	}
	// Graceful replacement does not release the Lease: a new replica takes
	// it over (get and update) once the old holder's Lease expires.
	upgraded := l.leaderPod(ns, "")
	if before[upgraded] {
		t.Fatalf("Lease still held by replaced pod %s", upgraded)
	}
	l.noLeaseDenials(ns)
	l.record("rolling-upgrade", map[string]any{"minReadyDuringRollout": minReady, "replaced": len(after)})

	// 3b. Constrained surge: with no schedulable capacity the surge pod
	// stays Pending, both old replicas keep serving, and the rollout is
	// visibly incomplete; restoring capacity completes it.
	for _, n := range nodes.Items {
		l.cordon(n.Name, true)
	}
	if out, err := l.helm(append([]string{"upgrade", "konstapel", chartArchive(t, "konstapel"), "--namespace", ns,
		"-f", "../../docs/examples/charts/operator-tls.yaml", "--set", "controller.resources.requests.cpu=120m"}, imageValues(repo, digest)...)...); err != nil {
		t.Fatalf("constrained upgrade: %v\n%s", err, out)
	}
	l.eventually("surge pod pending", func() (bool, string) {
		var pods corev1.PodList
		_ = l.c.List(l.ctx, &pods, client.InNamespace(ns), client.MatchingLabels{"app.kubernetes.io/component": "controller"})
		for _, p := range pods.Items {
			if p.Status.Phase == corev1.PodPending && p.Spec.NodeName == "" {
				return true, ""
			}
		}
		return false, l.podDiagnostics(ns)
	})
	for end := time.Now().Add(20 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Second) {
		if n := len(l.podsReady(ns, "controller")); n < 2 {
			t.Fatalf("ready controllers dropped to %d while the rollout was blocked", n)
		}
	}
	dep := &appsv1.Deployment{}
	_ = l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: "konstapel-controller"}, dep)
	if dep.Status.UpdatedReplicas == dep.Status.Replicas && dep.Status.UnavailableReplicas == 0 {
		t.Fatalf("blocked rollout reported complete: %s", toJSON(dep.Status))
	}
	for _, n := range nodes.Items {
		l.cordon(n.Name, false)
	}
	l.eventually("rollout completes once capacity returns", func() (bool, string) {
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(dep), dep)
		return dep.Status.ObservedGeneration == dep.Generation && dep.Status.UpdatedReplicas == 2 && dep.Status.Replicas == 2 && dep.Status.AvailableReplicas == 2, toJSON(dep.Status)
	})
	l.record("constrained-rollout", map[string]any{"surge": "pending while unschedulable", "readyWhileBlocked": 2, "completed": true})

	// 3c. Preferred, not required, separation: with one worker cordoned a
	// replaced replica co-locates with the other and becomes ready.
	ctrl = l.readyPods(ns, "controller", 2)
	moved := ctrl[0]
	l.cordon(moved.Spec.NodeName, true)
	if err := evict(moved.Name); err != nil {
		t.Fatalf("evict for co-location: %v", err)
	}
	coloc := l.readyPods(ns, "controller", 2)
	if coloc[0].Spec.NodeName != coloc[1].Spec.NodeName {
		t.Fatalf("replicas did not co-locate with one worker cordoned: %s %s", coloc[0].Spec.NodeName, coloc[1].Spec.NodeName)
	}
	l.cordon(moved.Spec.NodeName, false)
	l.record("co-location", map[string]any{"node": coloc[0].Spec.NodeName, "replicasReady": 2})

	// 3d. Development: one replica renders no controller PDB, so a drain
	// (eviction) of the single replica proceeds; restore the default.
	if out, err := l.helm(append([]string{"upgrade", "konstapel", chartArchive(t, "konstapel"), "--namespace", ns, "--wait", "--timeout", "5m",
		"-f", "../../docs/examples/charts/operator-tls.yaml", "-f", "../../docs/examples/charts/development.yaml"}, imageValues(repo, digest)...)...); err != nil {
		t.Fatalf("development values: %v\n%s", err, out)
	}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: "konstapel-controller"}, &policyv1.PodDisruptionBudget{}); !apierrors.IsNotFound(err) {
		t.Fatalf("one replica kept a controller PodDisruptionBudget: %v", err)
	}
	single := l.readyPods(ns, "controller", 1)
	if err := evict(single[0].Name); err != nil {
		t.Fatalf("draining the single development replica: %v", err)
	}
	l.readyPods(ns, "controller", 1)
	if out, err := l.helm(append([]string{"upgrade", "konstapel", chartArchive(t, "konstapel"), "--namespace", ns, "--wait", "--timeout", "5m",
		"-f", "../../docs/examples/charts/operator-tls.yaml"}, imageValues(repo, digest)...)...); err != nil {
		t.Fatalf("restore defaults: %v\n%s", err, out)
	}
	l.readyPods(ns, "controller", 2)
	l.record("development", map[string]any{"replicas": 1, "pdb": "none", "drain": "allowed"})

	// 4. Controller outage: retained engine policies keep enforcing and
	// downloads keep serving while no controller runs.
	l.scaleDeployment(ns, "konstapel-controller", 0)
	l.eventually("enforcement retained without a controller", func() (bool, string) { return l.denied("ha-prod") })
	if code, sum := download(l.portForward(ns, "svc/konstapel-download", 443)); code != http.StatusOK || sum != run.Status.Publication.PackageSHA256 {
		t.Fatalf("download without a controller: %d", code)
	}
	stale := l.lease(ns)
	l.scaleDeployment(ns, "konstapel-controller", 2)
	// Restart: new processes take over the Lease the stopped ones left.
	restarted := l.leaderPod(ns, "")
	if cur := l.lease(ns); *cur.Spec.HolderIdentity == *stale.Spec.HolderIdentity || transitions(cur) <= transitions(stale) {
		t.Fatalf("Lease after a restart from zero replicas:\n before %s\n after %s", toJSON(stale.Spec), toJSON(cur.Spec))
	}
	l.leaseHeld(ns)
	l.noLeaseDenials(ns)
	l.record("controller-outage", map[string]any{"enforcement": "retained", "download": "served", "restartedLeader": restarted})

	// 5. Abrupt leader failure: the follower takes the Lease and reconciles.
	leader = l.leaderPod(ns, "")
	prior := l.lease(ns)
	start := time.Now()
	l.forceDelete(ns, leader)
	successor := l.leaderPod(ns, leader)
	took := time.Since(start)
	if cur := l.lease(ns); transitions(cur) != transitions(prior)+1 {
		t.Fatalf("Lease takeover after leader loss:\n before %s\n after %s", toJSON(prior.Spec), toJSON(cur.Spec))
	}
	l.noLeaseDenials(ns)
	got = l.binding(b.Name)
	got.Spec.Mode = v1alpha1.ModeAudit
	if err := l.c.Update(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	l.waitReady(b.Name, 1)
	l.record("leader-failure", map[string]any{"from": leader, "to": successor, "seconds": took.Seconds()})
	got = l.binding(b.Name)
	got.Spec.Mode = v1alpha1.ModeDeny
	if err := l.c.Update(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	l.waitReady(b.Name, 1)

	// 6. Leader loss while S3 is unreachable after capture: uncertain access
	// keeps the run Publishing; the capture died with the pod's staging
	// volume, so recovery ends in a truthful CaptureLost, and the next run
	// publishes under a new identity.
	if out, err := exec.Command("docker", "pause", l.s3Container).CombinedOutput(); err != nil {
		t.Fatalf("pause S3: %v %s", err, out)
	}
	paused := true
	defer func() {
		if paused {
			_ = exec.Command("docker", "unpause", l.s3Container).Run()
		}
	}()
	lost := l.manualRun(b.Name, "ha-deny-lost")
	l.eventually("captured and publishing during the outage", func() (bool, string) {
		r := l.run(lost)
		return r != nil && r.Status.Phase == v1alpha1.RunPublishing, toJSON(r)
	})
	leader = l.leaderPod(ns, "")
	l.forceDelete(ns, leader)
	l.leaderPod(ns, leader)
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(3 * time.Second) {
		r := l.run(lost)
		if r.Status.Phase != v1alpha1.RunPublishing {
			t.Fatalf("run during the outage after leader loss: %s", toJSON(r.Status))
		}
	}
	if out, err := exec.Command("docker", "unpause", l.s3Container).CombinedOutput(); err != nil {
		t.Fatalf("unpause S3: %v %s", err, out)
	}
	paused = false
	l.eventually("lost capture reported", func() (bool, string) {
		r := l.run(lost)
		return r.Status.Phase == v1alpha1.RunFailed && r.Status.Summary != nil &&
			r.Status.Summary.Export == v1alpha1.ExportState(v1alpha1.ReasonCaptureLost) &&
			(r.Status.Publication == nil || r.Status.Publication.PublishedAt == nil), toJSON(r.Status)
	})
	next := l.manualRun(b.Name, "ha-deny-next")
	nextRun := l.publishedRun(b.Name, next)
	l.record("capture-lost", map[string]any{"lost": lost, "next": nextRun.Name, "nextPublication": nextRun.Status.Publication.PublicationID})

	// 7. Node loss: the leader's node stops. The replica on the other node
	// leads and reconciles, and the download replica there keeps serving.
	leader = l.leaderPod(ns, "")
	leaderPod := &corev1.Pod{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: leader}, leaderPod); err != nil {
		t.Fatal(err)
	}
	lostNode := leaderPod.Spec.NodeName
	if !strings.HasPrefix(lostNode, cluster+"-worker") {
		t.Fatalf("leader on unexpected node %s", lostNode)
	}
	start = time.Now()
	if out, err := exec.Command("docker", "stop", lostNode).CombinedOutput(); err != nil {
		t.Fatalf("stop node %s: %v %s", lostNode, err, out)
	}
	successor = l.leaderPod(ns, leader)
	took = time.Since(start)
	got = l.binding(b.Name)
	got.Spec.Mode = v1alpha1.ModeAudit
	if err := l.c.Update(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	l.waitReady(b.Name, 1)
	var survivor string
	for _, p := range l.podsReady(ns, "download") {
		if p.Spec.NodeName != lostNode {
			survivor = p.Name
		}
	}
	if survivor == "" {
		t.Fatal("no download replica on the surviving node")
	}
	if code, sum := download(l.portForward(ns, "pod/"+survivor, 8443)); code != http.StatusOK || sum != run.Status.Publication.PackageSHA256 {
		t.Fatalf("download after node loss: %d", code)
	}
	l.record("node-loss", map[string]any{"node": lostNode, "from": leader, "to": successor, "seconds": took.Seconds(), "downloadFrom": survivor})
}

// podsReady lists ready pods of one chart component.
func (l *live) podsReady(ns, component string) []corev1.Pod {
	var pods corev1.PodList
	_ = l.c.List(l.ctx, &pods, client.InNamespace(ns), client.MatchingLabels{"app.kubernetes.io/component": component})
	var out []corev1.Pod
	for _, p := range pods.Items {
		if p.DeletionTimestamp != nil {
			continue
		}
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				out = append(out, p)
			}
		}
	}
	return out
}

// readyPods waits for exactly n ready pods of a component.
func (l *live) readyPods(ns, component string, n int) []corev1.Pod {
	l.t.Helper()
	var pods []corev1.Pod
	l.eventually(fmt.Sprintf("%d ready %s pods", n, component), func() (bool, string) {
		pods = l.podsReady(ns, component)
		return len(pods) == n, l.podDiagnostics(ns)
	})
	return pods
}

// leaderPod waits for a Lease holder other than not that is a running pod,
// and returns its name.
func (l *live) leaderPod(ns, not string) string {
	l.t.Helper()
	var holder string
	l.eventually("a Lease holder other than "+not, func() (bool, string) {
		lease := &coordinationv1.Lease{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: LeaderElectionID}, lease); err != nil || lease.Spec.HolderIdentity == nil {
			return false, fmt.Sprint(err)
		}
		pod, _, _ := strings.Cut(*lease.Spec.HolderIdentity, "_")
		holder = pod
		if pod == "" || pod == not {
			return false, pod
		}
		// A Lease can still name a replaced pod until it expires: the
		// holder must be a running replica.
		cur := &corev1.Pod{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: pod}, cur); err != nil || cur.DeletionTimestamp != nil {
			return false, "holder " + pod + " is not a running replica"
		}
		return true, pod
	})
	return holder
}

// cordon marks a node (un)schedulable.
func (l *live) cordon(node string, on bool) {
	l.t.Helper()
	n := &corev1.Node{}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: node}, n); err != nil {
			return err
		}
		n.Spec.Unschedulable = on
		return l.c.Update(l.ctx, n)
	}); err != nil {
		l.t.Fatal(err)
	}
}

func (l *live) forceDelete(ns, pod string) {
	l.t.Helper()
	zero := int64(0)
	if err := l.c.Delete(l.ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: pod}}, &client.DeleteOptions{GracePeriodSeconds: &zero}); err != nil {
		l.t.Fatal(err)
	}
}

// waitChartCRDs waits until a fresh client maps every chart kind.
func (l *live) waitChartCRDs() {
	l.t.Helper()
	l.eventually("chart CRDs discoverable", func() (bool, string) {
		fresh, err := client.New(l.cfg, client.Options{Scheme: l.c.Scheme()})
		if err != nil {
			return false, err.Error()
		}
		for _, k := range []string{"ComplianceBinding", "ComplianceProfile", "AssessmentRun", "AssessmentRequest", "EvidenceDestination", "ComplianceException"} {
			if _, err := fresh.RESTMapper().RESTMapping(v1alpha1.GroupVersion.WithKind(k).GroupKind(), v1alpha1.GroupVersion.Version); err != nil {
				return false, err.Error()
			}
		}
		l.c = fresh
		return true, ""
	})
}

// createWhenServed creates o, retrying while admission policies have not
// yet learned a new CRD kind.
func (l *live) createWhenServed(o client.Object) {
	l.t.Helper()
	l.eventually("create "+o.GetName(), func() (bool, string) {
		err := l.c.Create(l.ctx, o)
		if apierrors.IsServiceUnavailable(err) {
			return false, err.Error()
		}
		if err != nil {
			l.t.Fatal(err)
		}
		return true, ""
	})
}

// chartDestination starts the test S3 service on the kind network and an
// EvidenceDestination with its credentials in the controller namespace.
func (l *live) chartDestination(t *testing.T, ns, prefix string) (any, *v1alpha1.EvidenceDestination, *corev1.Secret) {
	t.Helper()
	pub := l.chartS3(t)
	ed, secret := l.chartDestinationAt(t, ns, prefix, pub.Dest.Bucket, "http://"+l.s3Container+":9000")
	return pub, ed, secret
}

// chartS3 starts the test S3 service, reachable from the pods on the kind
// network, and returns a publisher whose client reaches it directly.
func (l *live) chartS3(t *testing.T) *s3store.Publisher {
	t.Helper()
	pub := startS3(t, l)
	if out, err := exec.Command("docker", "network", "connect", "kind", l.s3Container).CombinedOutput(); err != nil {
		t.Fatalf("attach the S3 service to the kind network: %v %s", err, out)
	}
	// Docker can republish the loopback port when a network is attached:
	// point the direct client at the current one.
	out, err := exec.Command("docker", "port", l.s3Container, "9000/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	port := strings.TrimSpace(strings.Split(strings.Split(string(out), "\n")[0], ":")[1])
	l.s3Endpoint = "http://127.0.0.1:" + port
	pub.Dest.Endpoint = l.s3Endpoint
	c, err := s3store.NewClient(l.ctx, pub.Dest, &s3store.StaticCredentials{AccessKeyID: l.s3Access, SecretAccessKey: l.s3Secret})
	if err != nil {
		t.Fatal(err)
	}
	pub.Client = c
	if _, err := pub.Ready(l.ctx); err != nil {
		t.Fatalf("direct S3 access after attaching the kind network: %v", err)
	}
	return pub
}

// chartDestinationAt creates an EvidenceDestination for the test S3 service
// at endpoint (the service itself, or a proxy in front of it) under the key
// prefix konstapel-test/<prefix>, with its credentials in the controller
// namespace, and waits until the controller reports it ready.
func (l *live) chartDestinationAt(t *testing.T, ns, prefix, bucket, endpoint string) (*v1alpha1.EvidenceDestination, *corev1.Secret) {
	t.Helper()
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: prefix + "-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: prefix + "-dest"}, Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{
		Endpoint: endpoint, Bucket: bucket, Region: "us-east-1", Prefix: "konstapel-test/" + prefix, DevelopmentFixture: true,
		CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: secret.Name}}}}}
	for _, o := range []client.Object{secret, ed} {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		got := &v1alpha1.EvidenceDestination{}
		if l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got) == nil {
			got.Finalizers = nil
			_ = l.c.Update(l.ctx, got)
			_ = l.c.Delete(l.ctx, got)
		}
		_ = l.c.Delete(l.ctx, secret)
	})
	l.eventually("destination ready from inside the cluster", func() (bool, string) {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
		return meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionDestinationReady), toJSON(got.Status)
	})
	return ed, secret
}

func (l *live) dropRuns(binding string) {
	var runs v1alpha1.AssessmentRunList
	_ = l.c.List(l.ctx, &runs)
	for i := range runs.Items {
		if r := &runs.Items[i]; r.Spec.BindingRef.Name == binding {
			r.Finalizers = nil
			_ = l.c.Update(l.ctx, r)
			_ = l.c.Delete(l.ctx, r)
		}
	}
}

func (l *live) run(name string) *v1alpha1.AssessmentRun {
	r := &v1alpha1.AssessmentRun{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, r); err != nil {
		return nil
	}
	return r
}

func (l *live) manualRun(binding, name string) string {
	l.t.Helper()
	r := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: binding}, Scope: v1alpha1.RunScopeBinding}}
	if err := l.c.Create(l.ctx, r); err != nil {
		l.t.Fatal(err)
	}
	return name
}

// publishedRun waits for the named run (or the binding's first run) to be
// committed.
func (l *live) publishedRun(binding, name string) *v1alpha1.AssessmentRun {
	l.t.Helper()
	var out *v1alpha1.AssessmentRun
	l.eventually("run published", func() (bool, string) {
		var runs v1alpha1.AssessmentRunList
		if err := l.c.List(l.ctx, &runs); err != nil {
			return false, err.Error()
		}
		for i := range runs.Items {
			r := &runs.Items[i]
			if r.Spec.BindingRef.Name == binding && (name == "" || r.Name == name) &&
				r.Status.Phase == v1alpha1.RunCompleted && r.Status.Publication != nil && r.Status.Publication.PublishedAt != nil {
				out = r
				return true, ""
			}
		}
		return false, toJSON(runs.Items)
	})
	return out
}

// downloadOperator creates a platform operator ServiceAccount bound to the
// shipped operator role.
func (l *live) downloadOperator(ns, name string) (string, *rbacv1.ClusterRoleBinding) {
	l.t.Helper()
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	crb := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-assessment-operator"},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: ns, Name: name}}}
	for _, o := range []client.Object{sa, crb} {
		if err := l.c.Create(l.ctx, o); err != nil {
			l.t.Fatal(err)
		}
	}
	l.t.Cleanup(func() { _ = l.c.Delete(l.ctx, crb); _ = l.c.Delete(l.ctx, sa) })
	return name, crb
}

// liveImage is the packaged controller image (KONSTAPEL_LIVE_IMAGE) as
// repository and digest.
func liveImage(t *testing.T) (image, repo, digest string) {
	t.Helper()
	image = os.Getenv("KONSTAPEL_LIVE_IMAGE")
	repo, digest, ok := strings.Cut(image, "@")
	if !ok {
		t.Fatalf("KONSTAPEL_LIVE_IMAGE=%q is not repository@digest", image)
	}
	return image, repo, digest
}

// installCharts installs both charts into ns with operator TLS and the
// packaged image (plus extra Helm arguments), uninstalls them when the test
// ends, and returns the CA that issued the download server's certificate.
func (l *live) installCharts(ns, repo, digest string, extra ...string) []byte {
	t := l.t
	t.Helper()
	if out, err := l.helm("install", "konstapel-crds", chartArchive(t, "konstapel-crds"), "--namespace", ns, "--create-namespace", "--wait"); err != nil {
		t.Fatalf("install CRD chart: %v\n%s", err, out)
	}
	l.waitChartCRDs()
	tlsSecret, caPEM := downloadTLSSecret(t, ns)
	if err := l.c.Create(l.ctx, tlsSecret); err != nil {
		t.Fatal(err)
	}
	if out, err := l.helm(append([]string{"install", "konstapel", chartArchive(t, "konstapel"), "--namespace", ns, "--wait", "--timeout", "5m",
		"-f", "../../docs/examples/charts/operator-tls.yaml"}, append(extra, imageValues(repo, digest)...)...)...); err != nil {
		t.Fatalf("install runtime chart: %v\n%s\n%s", err, out, l.podDiagnostics(ns))
	}
	t.Cleanup(func() {
		if t.Failed() {
			// The pods' logs are gone once the release is uninstalled.
			kubectl := func(args ...string) []byte {
				out, _ := exec.Command("kubectl", append([]string{"--kubeconfig", os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"), "--context", os.Getenv("KONSTAPEL_LIVE_CONTEXT")}, args...)...).CombinedOutput()
				return out
			}
			var b strings.Builder
			var pods corev1.PodList
			_ = l.c.List(l.ctx, &pods, client.InNamespace(ns))
			for _, p := range pods.Items {
				for _, previous := range []string{"--previous=true", "--previous=false"} {
					fmt.Fprintf(&b, "==== %s %s\n%s\n", p.Name, previous, kubectl("-n", ns, "logs", p.Name, "--all-containers", previous))
				}
			}
			fmt.Fprintf(&b, "==== events\n%s\n", kubectl("get", "events", "-A", "--sort-by=.lastTimestamp"))
			fmt.Fprintf(&b, "==== runs and bindings\n%s\n", kubectl("get", "assessmentruns,compliancebindings", "-o", "yaml"))
			_ = os.WriteFile(filepath.Join(l.out, t.Name()+"-pods.log"), []byte(b.String()), 0o644)
		}
		_, _ = l.helm("uninstall", "konstapel", "--namespace", ns, "--wait")
		_, _ = l.helm("uninstall", "konstapel-crds", "--namespace", ns)
		_ = l.c.Delete(l.ctx, tlsSecret)
	})
	return caPEM
}

// downloadPackage downloads a run's package from the download server at addr
// as the operator ServiceAccount and returns the status and the SHA-256 of
// the body.
func (l *live) downloadPackage(addr, ns, operator string, caPEM []byte, runUID string) (int, string) {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	hc := &http.Client{Timeout: 3 * time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "konstapel-download.konstapel-system.svc"}}}
	code, body := fetch(l.t, hc, "https://"+addr+"/v1/assessmentruns/"+runUID+"/download", l.token(ns, operator, downloadAudience))
	return code, fmt.Sprintf("%x", sha256.Sum256(body))
}

// lease reads the leader-election Lease (nil when absent).
func (l *live) lease(ns string) *coordinationv1.Lease {
	l.t.Helper()
	lease := &coordinationv1.Lease{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: LeaderElectionID}, lease); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		l.t.Fatal(err)
	}
	return lease
}

// transitions is the Lease's recorded leader transition count.
func transitions(lease *coordinationv1.Lease) int32 {
	if lease == nil || lease.Spec.LeaseTransitions == nil {
		return 0
	}
	return *lease.Spec.LeaseTransitions
}

// leaseHeld checks, for longer than one lease duration, that the current
// holder keeps the Lease while two controllers contend for it: the holder,
// its acquisition time and the transition count stay fixed, and the renew
// time advances past the point where an unrenewed Lease would have expired.
func (l *live) leaseHeld(ns string) map[string]any {
	l.t.Helper()
	leader := l.leaderPod(ns, "")
	l.readyPods(ns, "controller", 2)
	first := l.lease(ns)
	end := time.Now().Add(DefaultLeaseDuration + 2*DefaultRenewDeadline)
	var cur *coordinationv1.Lease
	for time.Now().Before(end) {
		time.Sleep(DefaultRetryPeriod)
		cur = l.lease(ns)
		if cur == nil || *cur.Spec.HolderIdentity != *first.Spec.HolderIdentity || transitions(cur) != transitions(first) ||
			!cur.Spec.AcquireTime.Equal(first.Spec.AcquireTime) {
			l.t.Fatalf("Lease changed while its holder ran under contention:\n first %s\n now %s", toJSON(first.Spec), toJSON(cur))
		}
	}
	renewed := cur.Spec.RenewTime.Sub(first.Spec.RenewTime.Time)
	if renewed < DefaultLeaseDuration {
		l.t.Fatalf("holder %s renewed the Lease by only %s over %s: %s", leader, renewed, DefaultLeaseDuration+2*DefaultRenewDeadline, toJSON(cur.Spec))
	}
	return map[string]any{"holder": *cur.Spec.HolderIdentity, "renewedBy": renewed.String(), "transitions": transitions(cur)}
}

// noLeaseDenials fails when any controller container (current or previous)
// logged a refused Lease request: client-go logs every failed get, create
// or update of the Lease.
func (l *live) noLeaseDenials(ns string) {
	l.t.Helper()
	cs, err := kubernetes.NewForConfig(l.cfg)
	if err != nil {
		l.t.Fatal(err)
	}
	var pods corev1.PodList
	if err := l.c.List(l.ctx, &pods, client.InNamespace(ns), client.MatchingLabels{"app.kubernetes.io/component": "controller"}); err != nil {
		l.t.Fatal(err)
	}
	for _, p := range pods.Items {
		for _, previous := range []bool{false, true} {
			out, err := cs.CoreV1().Pods(ns).GetLogs(p.Name, &corev1.PodLogOptions{Previous: previous}).DoRaw(l.ctx)
			if err != nil {
				continue // no previous container, or the pod is gone
			}
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "leases.coordination.k8s.io") && strings.Contains(line, "forbidden") {
					l.t.Errorf("controller %s (previous=%v) was refused Lease access: %s", p.Name, previous, line)
				}
			}
		}
	}
}

// leaseBoundary checks the controller ServiceAccount's Lease access against
// the API server, by impersonation and SubjectAccessReview: get and update
// of the leader-election Lease and create are allowed; every other Lease
// verb, every other Lease, and every other namespace is refused.
func (l *live) leaseBoundary(ns string) map[string]bool {
	t := l.t
	t.Helper()
	sa := l.saClient(ns, "konstapel-controller").CoordinationV1()
	dry := []string{metav1.DryRunAll}
	forbidden := func(what string, err error) {
		t.Helper()
		if !apierrors.IsForbidden(err) {
			t.Errorf("%s as the controller: %v, want Forbidden", what, err)
		}
	}
	cur, err := sa.Leases(ns).Get(l.ctx, LeaderElectionID, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get of the leader-election Lease as the controller: %v", err)
	}
	if _, err := sa.Leases(ns).Update(l.ctx, cur, metav1.UpdateOptions{DryRun: dry}); err != nil {
		t.Errorf("update of the leader-election Lease as the controller: %v", err)
	}
	probe := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "konstapel-lease-probe"}}
	if _, err := sa.Leases(ns).Create(l.ctx, probe, metav1.CreateOptions{DryRun: dry}); err != nil {
		t.Errorf("create of a Lease as the controller: %v", err)
	}
	_, err = sa.Leases(ns).List(l.ctx, metav1.ListOptions{})
	forbidden("Lease list", err)
	_, err = sa.Leases(ns).List(l.ctx, metav1.ListOptions{FieldSelector: "metadata.name=" + LeaderElectionID})
	forbidden("field-selected Lease list", err)
	_, err = sa.Leases(ns).Watch(l.ctx, metav1.ListOptions{FieldSelector: "metadata.name=" + LeaderElectionID})
	forbidden("field-selected Lease watch", err)
	_, err = sa.Leases(ns).Patch(l.ctx, LeaderElectionID, types.MergePatchType, []byte(`{}`), metav1.PatchOptions{DryRun: dry})
	forbidden("Lease patch", err)
	forbidden("Lease delete", sa.Leases(ns).Delete(l.ctx, LeaderElectionID, metav1.DeleteOptions{DryRun: dry}))
	_, err = sa.Leases(ns).Get(l.ctx, "konstapel-other-lease", metav1.GetOptions{})
	forbidden("get of another Lease", err)
	_, err = sa.Leases("kube-system").Get(l.ctx, "kube-scheduler", metav1.GetOptions{})
	forbidden("get of a kube-system Lease", err)
	_, err = sa.Leases("default").Create(l.ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: LeaderElectionID}}, metav1.CreateOptions{DryRun: dry})
	forbidden("Lease create in another namespace", err)

	admin, err := kubernetes.NewForConfig(l.cfg)
	if err != nil {
		t.Fatal(err)
	}
	reviews := map[string]bool{}
	for _, q := range []struct {
		namespace, verb, name string
		want                  bool
	}{
		{ns, "get", LeaderElectionID, true},
		{ns, "update", LeaderElectionID, true},
		{ns, "create", "", true},
		{ns, "get", "konstapel-other-lease", false},
		{ns, "update", "konstapel-other-lease", false},
		{ns, "get", "", false},
		{ns, "list", "", false},
		{ns, "list", LeaderElectionID, false},
		{ns, "watch", "", false},
		{ns, "watch", LeaderElectionID, false},
		{ns, "patch", LeaderElectionID, false},
		{ns, "delete", LeaderElectionID, false},
		{ns, "deletecollection", "", false},
		{"default", "get", LeaderElectionID, false},
		{"default", "update", LeaderElectionID, false},
		{"default", "create", "", false},
		{"kube-system", "update", "kube-controller-manager", false},
		{"", "list", "", false},
		{"", "watch", "", false},
	} {
		r, err := admin.AuthorizationV1().SubjectAccessReviews().Create(l.ctx, &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   "system:serviceaccount:" + ns + ":konstapel-controller",
			Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + ns, "system:authenticated"},
			ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: q.namespace, Group: "coordination.k8s.io", Resource: "leases",
				Verb: q.verb, Name: q.name},
		}}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		what := fmt.Sprintf("%s leases %s %q", q.namespace, q.verb, q.name)
		reviews[what] = r.Status.Allowed
		if r.Status.Allowed != q.want {
			t.Errorf("SubjectAccessReview %s: allowed=%v, want %v", what, r.Status.Allowed, q.want)
		}
	}
	return reviews
}

// electionEvent reports whether the election recorded a LeaderElection
// Event about the Lease for holder: the recorder's Event writes work.
func (l *live) electionEvent(ns, holder string) bool {
	var events corev1.EventList
	_ = l.c.List(l.ctx, &events, client.InNamespace(ns))
	for _, e := range events.Items {
		if e.Reason == "LeaderElection" && e.InvolvedObject.Kind == "Lease" && e.InvolvedObject.Name == LeaderElectionID &&
			strings.HasPrefix(e.Message, holder+" ") {
			return true
		}
	}
	return false
}
