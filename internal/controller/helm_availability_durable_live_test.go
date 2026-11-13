//go:build live

package controller

// Durable publication recovery on the Helm-installed controller
// (add-controller-high-availability 4.1, 4.2, 5.3 same-run publication
// recovery; group "availability"). Both charts run the packaged image with
// two replicas, each with its own empty staging volume. A test-owned fault
// proxy (internal/s3fault) sits between the pods and the test S3 service
// and interrupts one run's publication at a durable boundary; the
// controller itself is unchanged:
//   - staged, not committed: the run's conditional commit is held and never
//     forwarded. The test reads the staged attempt directly from S3, removes
//     the Lease holder, and the other replica commits the same run with the
//     exact staged bytes, under the binding's retention at its commit;
//   - committed, no receipt: the commit lands, its response is withheld and
//     S3 is blackholed. The binding's retention changes, the Lease holder
//     is removed, and the other replica records the original commit
//     (publication ID, archive, digest, publishedAt, expiresAt) without
//     committing again.
// While S3 is held or unreachable, before and after the leader pod is
// removed, the run stays Publishing and is never CaptureLost.
//
// This file sorts before helm_availability_live_test.go, so it runs on the
// fresh two-worker cluster, before that test stops a worker. It does not
// rely on that order.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3fault"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

func TestLiveHelmDurableRecovery(t *testing.T) {
	image, repo, digest := liveImage(t)
	l := newLive(t)
	const ns, prefix = "konstapel-system", "dr"
	caPEM := l.installCharts(ns, repo, digest)
	direct := l.chartS3(t) // reaches S3 without the proxy
	proxy := l.startFaultProxy(t)
	ed, _ := l.chartDestinationAt(t, ns, prefix, direct.Dest.Bucket, proxy.endpoint())
	store := s3Store{l: l, pub: direct, dest: s3store.Destination{Prefix: ed.Spec.S3.Prefix}}
	ctrl := l.readyPods(ns, "controller", 2)
	placement := map[string]string{}
	for _, p := range ctrl {
		placement[p.Name] = p.Spec.NodeName
	}
	l.record("install", map[string]any{"image": image, "controllers": placement, "leader": l.leaderPod(ns, ""), "s3Endpoint": ed.Spec.S3.Endpoint})

	l.setNamespace("dr-prod", "dr-production")
	p := profileObj(t, "dr-baseline", pol)
	b := bindingObj("dr-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "dr-production"})
	for _, o := range []client.Object{p, b} {
		o.SetUID("")
		l.createWhenServed(o)
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, b); _ = l.c.Delete(l.ctx, p) })
	l.waitReady(b.Name, 1)
	l.setRetention(b.Name, "600s", &v1alpha1.DestinationReference{Name: ed.Name, UID: string(ed.UID)})
	t.Cleanup(func() { l.dropRuns(b.Name) })
	operator, _ := l.downloadOperator(ns, "dr-operator")
	download := func(uid types.UID) (int, string) {
		return l.downloadPackage(l.portForward(ns, "svc/konstapel-download", 443), ns, operator, caPEM, string(uid))
	}

	// The scheduled run publishes through the passing proxy.
	first := l.publishedRun(b.Name, "")
	if code, sum := download(first.UID); code != http.StatusOK || sum != first.Status.Publication.PackageSHA256 {
		t.Fatalf("download of the scheduled run: %d %s", code, sum)
	}
	l.record("baseline", map[string]any{"run": first.Name, "publicationID": first.Status.Publication.PublicationID, "via": proxy.endpoint()})

	// 1. Staged durably, interrupted before the commit.
	run := l.createRun(b.Name, "dr-audit-staged")
	proxy.arm(s3fault.ModeHold, run.UID)
	watch := l.watchRun(run.Name, run.UID)
	held := proxy.waitFor("the leader's commit held at the proxy", func(st s3fault.State) bool { return st.CommitsHeld >= 1 })
	cur := l.publishingWithoutReceipt(run.Name)
	ref := publication.RunRef{ClusterID: cur.Status.Scope.ClusterID, BindingUID: cur.Status.Binding.UID, RunUID: string(run.UID)}
	staged := store.onlyAttempt(ref)
	if _, err := store.commit(ref); !errors.Is(err, publication.ErrNotFound) {
		t.Fatalf("commit exists while the commit request is held: %v", err)
	}
	stagedBytes := store.get(staged.ArchiveKey, staged.ArchiveVersionID)
	stagedSum := fmt.Sprintf("%x", sha256.Sum256(stagedBytes))
	if stagedSum != staged.PackageSHA256 || int64(len(stagedBytes)) != staged.PackageSize || staged.Run != ref {
		t.Fatalf("staged attempt %s does not describe its archive (sha256 %s, %d bytes)", toJSON(staged), stagedSum, len(stagedBytes))
	}
	l.record("staged-held", map[string]any{"run": run.Name, "uid": run.UID, "publicationID": ref.PublicationID(), "archiveKey": staged.ArchiveKey,
		"stagedSha256": staged.PackageSHA256, "archiveSha256": stagedSum, "commitsHeld": held.CommitsHeld, "commitInS3": false,
		"phase": cur.Status.Phase, "closureRetention": cur.Status.Retention})
	// The retention changes before handover: the commit takes the binding's
	// retention at the commit, not the leader's held request or the closure.
	l.setRetention(b.Name, "900s", nil)
	proxy.blackhole()
	killed, follower := l.killLeader(ns)
	successor := l.successorBlocked(ns, killed, follower, proxy)
	l.stillPublishing(b.Name, run.Name, run.UID, 30*time.Second)
	l.record("staged-handover", map[string]any{"killed": killed, "successor": successor, "s3": "unreachable (blackholed)", "phase": "Publishing", "seconds": 30})
	proxy.release()
	done := l.publishedRun(b.Name, run.Name)
	phases := watch()
	m, head := store.mustCommit(ref)
	pubSt := done.Status.Publication
	code, sum := download(run.UID)
	switch {
	case done.UID != run.UID:
		t.Fatalf("published run %s has UID %s, staged %s", done.Name, done.UID, run.UID)
	case pubSt.PublicationID != ref.PublicationID() || m.PublicationID != ref.PublicationID():
		t.Fatalf("publication %s (commit %s), staged run %s", pubSt.PublicationID, m.PublicationID, ref.PublicationID())
	case pubSt.PackageSHA256 != staged.PackageSHA256 || m.PackageSHA256 != staged.PackageSHA256 || code != http.StatusOK || sum != staged.PackageSHA256:
		t.Fatalf("staged %s, receipt %s, commit %s, downloaded %d %s", staged.PackageSHA256, pubSt.PackageSHA256, m.PackageSHA256, code, sum)
	case m.ArchiveKey != staged.ArchiveKey || m.ArchiveVersionID != staged.ArchiveVersionID || pubSt.Commit == nil || pubSt.Commit.ArchiveKey != staged.ArchiveKey:
		t.Fatalf("committed archive %s (receipt %s), the leader staged %s", m.ArchiveKey, toJSON(pubSt.Commit), staged.ArchiveKey)
	case m.Retention.Duration != (900*time.Second).String() || pubSt.Retention == nil || pubSt.Retention.Duration != m.Retention.Duration:
		t.Fatalf("committed retention %s, receipt %s, binding at commit 900s", m.Retention.Duration, toJSON(pubSt.Retention))
	case !pubSt.PublishedAt.Time.Equal(*head.LastModified) || !pubSt.ExpiresAt.Time.Equal(head.LastModified.Add(900*time.Second)):
		t.Fatalf("publishedAt %s expiresAt %s, commit time %s", pubSt.PublishedAt, pubSt.ExpiresAt, head.LastModified)
	}
	st := proxy.state()
	if st.CommitsForwarded != 1 || store.commitVersions(ref) != 1 {
		t.Fatalf("commit forwarded %d times, %d commit versions: %s", st.CommitsForwarded, store.commitVersions(ref), toJSON(st))
	}
	l.checkPhases(phases)
	l.record("staged-recovered", map[string]any{"run": done.Name, "uid": done.UID, "publicationID": pubSt.PublicationID, "stagedSha256": staged.PackageSHA256,
		"committedSha256": m.PackageSHA256, "receiptSha256": pubSt.PackageSHA256, "downloadedSha256": sum, "archiveKey": m.ArchiveKey,
		"publishedAt": pubSt.PublishedAt.UTC(), "expiresAt": pubSt.ExpiresAt.UTC(), "retention": m.Retention.Duration + " (binding at commit; 10m0s at closure)",
		"commitArrivals": st.CommitArrivals, "commitsHeld": st.CommitsHeld, "commitsForwarded": st.CommitsForwarded, "phases": phases, "committedBy": successor})

	// 2. Committed in S3, interrupted before the Kubernetes receipt.
	l.setRetention(b.Name, "600s", nil)
	l.readyPods(ns, "controller", 2)
	run = l.createRun(b.Name, "dr-audit-committed")
	proxy.arm(s3fault.ModeAfter, run.UID)
	watch = l.watchRun(run.Name, run.UID)
	st = proxy.waitFor("the leader's commit forwarded and its response withheld", func(st s3fault.State) bool {
		return st.CommitsForwarded == 1 && st.Blackhole && st.Waiting >= 1
	})
	if st.LastCommitStatus != http.StatusOK {
		t.Fatalf("the backend refused the commit: %s", toJSON(st))
	}
	cur = l.publishingWithoutReceipt(run.Name)
	ref = publication.RunRef{ClusterID: cur.Status.Scope.ClusterID, BindingUID: cur.Status.Binding.UID, RunUID: string(run.UID)}
	m, head = store.mustCommit(ref)
	committedAt, committedExpiry := head.LastModified.UTC(), head.LastModified.UTC().Add(600*time.Second)
	if m.Retention.Duration != (600*time.Second).String() || m.PublicationID != ref.PublicationID() {
		t.Fatalf("commit %s", toJSON(m))
	}
	l.record("committed-withheld", map[string]any{"run": run.Name, "uid": run.UID, "publicationID": m.PublicationID, "archiveKey": m.ArchiveKey,
		"packageSha256": m.PackageSHA256, "publishedAt": committedAt, "expiresAt": committedExpiry, "retention": m.Retention.Duration,
		"manifestVersionID": aws.ToString(head.VersionId), "backendStatus": st.LastCommitStatus, "phase": cur.Status.Phase})
	l.setRetention(b.Name, "120s", nil)
	killed, follower = l.killLeader(ns)
	successor = l.successorBlocked(ns, killed, follower, proxy)
	l.stillPublishing(b.Name, run.Name, run.UID, 30*time.Second)
	l.record("committed-handover", map[string]any{"killed": killed, "successor": successor, "s3": "unreachable (blackholed)", "phase": "Publishing", "seconds": 30,
		"bindingRetention": "120s"})
	proxy.release()
	done = l.publishedRun(b.Name, run.Name)
	phases = watch()
	pubSt = done.Status.Publication
	code, sum = download(run.UID)
	switch {
	case done.UID != run.UID:
		t.Fatalf("published run %s has UID %s, committed %s", done.Name, done.UID, run.UID)
	case pubSt.PublicationID != m.PublicationID || pubSt.PackageSHA256 != m.PackageSHA256 || pubSt.Commit == nil ||
		pubSt.Commit.ArchiveKey != m.ArchiveKey || pubSt.Commit.ManifestVersionID != versionOf(head.VersionId):
		t.Fatalf("recorded %s, committed %s (manifest version %q)", toJSON(pubSt), toJSON(m), aws.ToString(head.VersionId))
	case !pubSt.PublishedAt.Time.Equal(committedAt) || !pubSt.ExpiresAt.Time.Equal(committedExpiry) || pubSt.Retention == nil || pubSt.Retention.Duration != m.Retention.Duration:
		t.Fatalf("recorded publishedAt %s expiresAt %s retention %s; committed %s, %s, %s", pubSt.PublishedAt, pubSt.ExpiresAt, toJSON(pubSt.Retention),
			committedAt, committedExpiry, m.Retention.Duration)
	case code != http.StatusOK || sum != m.PackageSHA256:
		t.Fatalf("download: %d %s, committed %s", code, sum, m.PackageSHA256)
	}
	st = proxy.state()
	if st.CommitArrivals != 1 || st.CommitsForwarded != 1 || store.commitVersions(ref) != 1 {
		t.Fatalf("committed twice: %s, %d commit versions", toJSON(st), store.commitVersions(ref))
	}
	l.checkPhases(phases)
	l.record("committed-recovered", map[string]any{"run": done.Name, "uid": done.UID, "publicationID": pubSt.PublicationID, "archiveKey": pubSt.Commit.ArchiveKey,
		"packageSha256": pubSt.PackageSHA256, "downloadedSha256": sum, "publishedAt": pubSt.PublishedAt.UTC(), "expiresAt": pubSt.ExpiresAt.UTC(),
		"retention": pubSt.Retention.Duration + " (binding now 120s)", "commitArrivals": st.CommitArrivals, "commitsForwarded": st.CommitsForwarded,
		"phases": phases, "recordedBy": successor})
}

// setRetention sets the binding's assessment retention (and destination,
// when given), retrying on conflicts.
func (l *live) setRetention(binding, retention string, dest *v1alpha1.DestinationReference) {
	l.t.Helper()
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		b := l.binding(binding)
		if b.Spec.Assessment == nil {
			b.Spec.Assessment = &v1alpha1.BindingAssessment{}
		}
		b.Spec.Assessment.Interval, b.Spec.Assessment.CollectionTimeout = "24h", "20s"
		b.Spec.Assessment.Retention = v1alpha1.Duration(retention)
		if dest != nil {
			b.Spec.Assessment.DestinationRef = dest
		}
		return l.c.Update(l.ctx, b)
	}); err != nil {
		l.t.Fatal(err)
	}
}

func (l *live) createRun(binding, name string) *v1alpha1.AssessmentRun {
	l.t.Helper()
	r := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: binding}, Scope: v1alpha1.RunScopeBinding}}
	if err := l.c.Create(l.ctx, r); err != nil {
		l.t.Fatal(err)
	}
	return r
}

func captureLost(r *v1alpha1.AssessmentRun) bool {
	if r.Status.Summary != nil && r.Status.Summary.Export == v1alpha1.ExportState(v1alpha1.ReasonCaptureLost) {
		return true
	}
	for _, c := range r.Status.Conditions {
		if c.Reason == v1alpha1.ReasonCaptureLost {
			return true
		}
	}
	return false
}

// publishingWithoutReceipt checks that the run is Publishing, not
// CaptureLost, and has recorded no publication.
func (l *live) publishingWithoutReceipt(name string) *v1alpha1.AssessmentRun {
	l.t.Helper()
	var r *v1alpha1.AssessmentRun
	l.eventually(name+" publishing with its frozen identity", func() (bool, string) {
		r = l.run(name)
		return r != nil && r.Status.Phase == v1alpha1.RunPublishing && r.Status.Scope != nil && r.Status.Binding != nil, toJSON(r)
	})
	if captureLost(r) || (r.Status.Publication != nil && r.Status.Publication.PublishedAt != nil) {
		l.t.Fatalf("run %s before handover: %s", name, toJSON(r.Status))
	}
	return r
}

// watchRun polls a run every second until the returned function is called,
// failing on any other identity, a CaptureLost or a failure, and returns
// the phases it saw in order.
func (l *live) watchRun(name string, uid types.UID) func() []string {
	stop, done := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var phases []string
	var bad string
	go func() {
		defer close(done)
		for last := false; ; {
			if r := l.run(name); r != nil {
				mu.Lock()
				ph := string(r.Status.Phase)
				if ph == "" {
					ph = "(none)"
				}
				if len(phases) == 0 || phases[len(phases)-1] != ph {
					phases = append(phases, ph)
				}
				if bad == "" && (r.UID != uid || captureLost(r) || r.Status.Phase == v1alpha1.RunFailed) {
					bad = toJSON(r)
				}
				mu.Unlock()
			}
			if last {
				return
			}
			select {
			case <-stop:
				last = true // observe once more after the caller saw the end
			case <-time.After(time.Second):
			}
		}
	}()
	return func() []string {
		close(stop)
		<-done
		mu.Lock()
		defer mu.Unlock()
		if bad != "" {
			l.t.Fatalf("run %s became %s", name, bad)
		}
		return phases
	}
}

func (l *live) checkPhases(phases []string) {
	l.t.Helper()
	for _, p := range phases {
		if p == string(v1alpha1.RunFailed) {
			l.t.Fatalf("phases %v", phases)
		}
	}
	if len(phases) == 0 || phases[len(phases)-1] != string(v1alpha1.RunCompleted) {
		l.t.Fatalf("phases %v", phases)
	}
}

// stillPublishing requires, for d, that the binding's only active run is
// the named run with its original UID, Publishing, never CaptureLost and
// without a receipt.
func (l *live) stillPublishing(binding, name string, uid types.UID, d time.Duration) {
	l.t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(3 * time.Second) {
		r := l.run(name)
		if r == nil || r.UID != uid || r.Status.Phase != v1alpha1.RunPublishing || captureLost(r) ||
			(r.Status.Publication != nil && r.Status.Publication.PublishedAt != nil) {
			l.t.Fatalf("run while S3 is unreachable after the handover: %s", toJSON(r))
		}
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(l.ctx, &runs)
		for _, o := range runs.Items {
			if o.Spec.BindingRef.Name == binding && o.Name != name && !runDone(&o) {
				l.t.Fatalf("another active run for the binding: %s\nbinding status: %s", toJSON(o), toJSON(l.binding(binding).Status))
			}
		}
	}
}

// killLeader force-deletes the controller pod holding the Lease, after
// checking that it still holds it, and waits until its container no longer
// runs on its node. It returns that pod and the other ready replica. The
// workload nodes stay cordoned until successorBlocked has seen that replica
// take over, so the Deployment's replacement pod cannot race it for the
// Lease.
func (l *live) killLeader(ns string) (killed, follower string) {
	l.t.Helper()
	pods := l.readyPods(ns, "controller", 2)
	l.cordonWorkload(true)
	leader := l.leaderPod(ns, "")
	var victim *corev1.Pod
	for i := range pods {
		if pods[i].Name == leader {
			victim = &pods[i]
		} else {
			follower = pods[i].Name
		}
	}
	if victim == nil || follower == "" {
		l.t.Fatalf("Lease holder %s is not one of the ready replicas %v", leader, len(pods))
	}
	var container string
	for _, s := range victim.Status.ContainerStatuses {
		if s.Name == "controller" {
			_, container, _ = strings.Cut(s.ContainerID, "://")
		}
	}
	lease := &coordinationv1.Lease{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: LeaderElectionID}, lease); err != nil || lease.Spec.HolderIdentity == nil ||
		!strings.HasPrefix(*lease.Spec.HolderIdentity, leader+"_") {
		l.t.Fatalf("the Lease moved before the deletion: %v %s", err, toJSON(lease.Spec))
	}
	l.forceDelete(ns, leader)
	l.eventually("the former leader's container stopped on "+victim.Spec.NodeName, func() (bool, string) {
		out, err := exec.Command("docker", "exec", victim.Spec.NodeName, "crictl", "inspect", "-o", "json", container).CombinedOutput()
		if err != nil {
			return strings.Contains(strings.ToLower(string(out)), "not found"), string(out)
		}
		var st struct {
			Status struct{ State string } `json:"status"`
		}
		_ = json.Unmarshal(out, &st)
		return st.Status.State != "" && st.Status.State != "CONTAINER_RUNNING", st.Status.State
	})
	return leader, follower
}

// successorBlocked waits until the other replica holds the Lease and its
// S3 requests reach the blackholed proxy.
func (l *live) successorBlocked(ns, killed, follower string, proxy *faultProxy) string {
	l.t.Helper()
	before := proxy.state().Blackholed
	successor := l.leaderPod(ns, killed)
	if successor != follower {
		l.t.Fatalf("Lease taken by %s, not the other installed replica %s", successor, follower)
	}
	l.cordonWorkload(false)
	proxy.waitFor("the successor's S3 requests held", func(st s3fault.State) bool { return st.Blackholed > before })
	return successor
}

// s3Store reads a destination's objects directly from the test S3 service.
type s3Store struct {
	l    *live
	pub  *s3store.Publisher
	dest s3store.Destination
}

// stagedAttempt is the attempt record the controller writes beside an
// uploaded archive.
type stagedAttempt struct {
	Run              publication.RunRef `json:"run"`
	ArchiveKey       string             `json:"archiveKey"`
	ArchiveVersionID string             `json:"archiveVersionID"`
	PackageSHA256    string             `json:"packageSha256"`
	PackageSize      int64              `json:"packageSize"`
}

// commitManifest is the run's commit object.
type commitManifest struct {
	PublicationID    string                `json:"publicationID"`
	Run              publication.RunRef    `json:"run"`
	ArchiveKey       string                `json:"archiveKey"`
	ArchiveVersionID string                `json:"archiveVersionID"`
	PackageSHA256    string                `json:"packageSha256"`
	Retention        publication.Retention `json:"retention"`
}

func (s s3Store) get(key, version string) []byte {
	s.l.t.Helper()
	in := &s3.GetObjectInput{Bucket: aws.String(s.pub.Dest.Bucket), Key: aws.String(key)}
	if version != "" {
		in.VersionId = aws.String(version)
	}
	out, err := s.pub.Client.GetObject(s.l.ctx, in)
	if err != nil {
		s.l.t.Fatalf("read %s: %v", key, err)
	}
	defer out.Body.Close()
	b, err := io.ReadAll(out.Body)
	if err != nil {
		s.l.t.Fatal(err)
	}
	return b
}

// onlyAttempt returns the run's single staged attempt.
func (s s3Store) onlyAttempt(ref publication.RunRef) stagedAttempt {
	s.l.t.Helper()
	prefix := s3store.RunPrefix(s.dest, ref) + "attempts/"
	list, err := s.pub.Client.ListObjectsV2(s.l.ctx, &s3.ListObjectsV2Input{Bucket: aws.String(s.pub.Dest.Bucket), Prefix: aws.String(prefix)})
	if err != nil {
		s.l.t.Fatal(err)
	}
	var found []stagedAttempt
	for _, o := range list.Contents {
		if strings.HasSuffix(aws.ToString(o.Key), "/attempt.json") {
			var a stagedAttempt
			if err := json.Unmarshal(s.get(aws.ToString(o.Key), ""), &a); err != nil {
				s.l.t.Fatal(err)
			}
			found = append(found, a)
		}
	}
	if len(found) != 1 {
		s.l.t.Fatalf("staged attempts under %s: %s", prefix, toJSON(found))
	}
	return found[0]
}

func (s s3Store) commit(ref publication.RunRef) (commitManifest, error) {
	key := s3store.RunPrefix(s.dest, ref) + "commit.json"
	if _, err := s.pub.Client.HeadObject(s.l.ctx, &s3.HeadObjectInput{Bucket: aws.String(s.pub.Dest.Bucket), Key: aws.String(key)}); err != nil {
		if strings.Contains(err.Error(), "NotFound") || strings.Contains(err.Error(), "StatusCode: 404") {
			return commitManifest{}, publication.ErrNotFound
		}
		return commitManifest{}, err
	}
	var m commitManifest
	return m, json.Unmarshal(s.get(key, ""), &m)
}

// mustCommit returns the run's commit and its object metadata.
func (s s3Store) mustCommit(ref publication.RunRef) (commitManifest, *s3.HeadObjectOutput) {
	s.l.t.Helper()
	m, err := s.commit(ref)
	if err != nil {
		s.l.t.Fatalf("read the commit: %v", err)
	}
	head, err := s.pub.Client.HeadObject(s.l.ctx, &s3.HeadObjectInput{Bucket: aws.String(s.pub.Dest.Bucket), Key: aws.String(s3store.RunPrefix(s.dest, ref) + "commit.json")})
	if err != nil || head.LastModified == nil {
		s.l.t.Fatalf("head the commit: %v", err)
	}
	if m.Run != ref {
		s.l.t.Fatalf("commit for %s, want %s", toJSON(m.Run), toJSON(ref))
	}
	return m, head
}

// commitVersions counts stored versions of the run's commit object.
func (s s3Store) commitVersions(ref publication.RunRef) int {
	s.l.t.Helper()
	key := s3store.RunPrefix(s.dest, ref) + "commit.json"
	out, err := s.pub.Client.ListObjectVersions(s.l.ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(s.pub.Dest.Bucket), Prefix: aws.String(key)})
	if err != nil {
		s.l.t.Fatal(err)
	}
	n := 0
	for _, v := range out.Versions {
		if aws.ToString(v.Key) == key {
			n++
		}
	}
	return n
}

// versionOf is the receipt form of an S3 version ID ("null" means none).
func versionOf(v *string) string {
	if s := aws.ToString(v); s != "null" {
		return s
	}
	return ""
}

// faultProxy is the test-owned s3fault proxy, running in a disposable
// container on the kind network in front of the test S3 service.
type faultProxy struct {
	l       *live
	name    string
	control string
}

// startFaultProxy builds the static proxy binary from this checkout and runs
// it in the pinned workload image (no further image dependency), forwarding
// to the test S3 service. Its log is kept with the test evidence.
func (l *live) startFaultProxy(t *testing.T) *faultProxy {
	t.Helper()
	image := os.Getenv("KONSTAPEL_WORKLOAD_IMAGE")
	if image == "" || l.s3Container == "" {
		t.Fatal("KONSTAPEL_WORKLOAD_IMAGE and a started S3 service are required")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "s3fault")
	build := exec.Command("go", "build", "-mod=readonly", "-trimpath", "-o", bin, "./internal/s3fault/cmd/s3fault")
	build.Dir = "../.."
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the fault proxy: %v %s", err, out)
	}
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	name := "konstapel-live-s3fault-" + hex.EncodeToString(suffix)
	if out, err := exec.Command("docker", "run", "-d", "--name", name, "--label", liveContainerLabel(), "--network", "kind", "-p", "127.0.0.1::9100",
		"-v", bin+":/s3fault:ro", "--entrypoint", "/s3fault", image, "-backend", l.s3Container+":9000").CombinedOutput(); err != nil {
		t.Fatalf("start the fault proxy: %v %s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("docker", "logs", name).CombinedOutput(); err == nil {
			_ = os.WriteFile(filepath.Join(l.out, t.Name()+"-s3fault.log"), out, 0o644)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})
	out, err := exec.Command("docker", "port", name, "9100/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	f := &faultProxy{l: l, name: name, control: "http://" + strings.TrimSpace(strings.Split(string(out), "\n")[0])}
	l.eventually("fault proxy control", func() (bool, string) {
		_, err := f.do(http.MethodGet, "/state")
		return err == nil, fmt.Sprint(err)
	})
	return f
}

// endpoint is the proxy's S3 address for pods on the kind network.
func (f *faultProxy) endpoint() string { return "http://" + f.name + ":9000" }

func (f *faultProxy) do(method, path string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(f.l.ctx, method, f.control+path, nil)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, b)
	}
	return b, nil
}

func (f *faultProxy) must(method, path string) []byte {
	f.l.t.Helper()
	b, err := f.do(method, path)
	if err != nil {
		f.l.t.Fatal(err)
	}
	return b
}

func (f *faultProxy) arm(mode string, run types.UID) {
	f.must(http.MethodPost, "/arm?mode="+mode+"&run="+string(run))
}
func (f *faultProxy) blackhole() { f.must(http.MethodPost, "/blackhole") }
func (f *faultProxy) release()   { f.must(http.MethodPost, "/release") }

func (f *faultProxy) state() s3fault.State {
	f.l.t.Helper()
	var st s3fault.State
	if err := json.Unmarshal(f.must(http.MethodGet, "/state"), &st); err != nil {
		f.l.t.Fatal(err)
	}
	return st
}

// waitFor waits for the proxy to report a fault, returning that state.
func (f *faultProxy) waitFor(what string, ok func(s3fault.State) bool) s3fault.State {
	f.l.t.Helper()
	var st s3fault.State
	f.l.eventually(what, func() (bool, string) {
		st = f.state()
		return ok(st), toJSON(st)
	})
	return st
}

// cordonWorkload (un)cordons every Konstapel workload node, and uncordons
// them when the test ends.
func (l *live) cordonWorkload(on bool) {
	l.t.Helper()
	var nodes corev1.NodeList
	if err := l.c.List(l.ctx, &nodes, client.MatchingLabels{"konstapel.dev/pool": "workload"}); err != nil {
		l.t.Fatal(err)
	}
	for _, n := range nodes.Items {
		if on {
			name := n.Name
			l.t.Cleanup(func() { l.cordon(name, false) })
		}
		l.cordon(n.Name, on)
	}
}
