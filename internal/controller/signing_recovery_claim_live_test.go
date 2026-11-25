//go:build live

package controller

// Live signing recovery (add-evidence-signing-recovery 2.3 and 2.4) on real
// Kubernetes APIs and the test-owned S3 service (RustFS). A Required
// destination whose key Secret was never installed ends a real run
// SigningFailed with its archive retained. The requests confirm a
// runtime-generated key that is not installed yet, so the claim phase writes
// no storage. With the API server's resourceVersion checks:
//   - requests reconciled at the same time by separate reconcilers (as
//     overlapping leaders would) converge on exactly one claim holder, the
//     others waiting, and the claim passes the run's CEL rules;
//   - an in-process manager (a successor with an empty cache, running the
//     registered reconciler) resumes the holder with the same claim;
//   - a holder deleted while holding the claim, and a holder that ended
//     terminally, are replaced by exactly one waiting request;
//   - nothing is written to storage while the key is absent.
// Then the attempt (2.4):
//   - the recorded Secret holding another key ends the holder KeyMismatch,
//     and a request without expectedKeyFingerprint ends
//     KeyConfirmationRequired without reading a signing Secret; neither pins;
//   - with the confirmed key installed and the destination rotated to
//     another Secret, overlapping reconcilers pin the confirmed key once,
//     sign, and store one signature while the commit is refused;
//   - with the key Secret deleted, a successor commits the stored signature
//     without reading a signing Secret, and after a lost commit response the
//     registered reconciler adopts the commit without publishing again;
//   - storage holds exactly one signature version and one commit version,
//     signed under the pinned key, with the run's recorded retention bounded
//     by its recorded expiry.
// Recording the recovered publication (2.6), the attempt deadline (2.5), and
// the live faults (5.2) build on this. Run through scripts/targeting-live.sh
// (recovery group).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

func TestLiveSigningRecoveryClaim(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	ns := "konstapel-system"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	evidence := filepath.Join(l.out, t.Name())
	if err := os.MkdirAll(evidence, 0o755); err != nil {
		t.Fatal(err)
	}
	s3secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "src-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	if err := l.c.Create(l.ctx, s3secret); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(context.Background(), s3secret) })
	// The key Secret is never installed: the run's Required intent records
	// no key and the run ends SigningFailed, its archive retained.
	ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "src-dest"}, Spec: v1alpha1.EvidenceDestinationSpec{
		S3: v1alpha1.S3Location{Endpoint: l.s3Endpoint, Bucket: pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/src-dest", DevelopmentFixture: true,
			CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: s3secret.Name}}},
		Signing: requiredSigning("src-never-installed")}}
	if err := l.c.Create(l.ctx, ed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		got := &v1alpha1.EvidenceDestination{}
		if l.c.Get(context.Background(), client.ObjectKeyFromObject(ed), got) == nil {
			controllerutil.RemoveFinalizer(got, DestinationFinalizer)
			_ = l.c.Update(context.Background(), got)
			_ = l.c.Delete(context.Background(), got)
		}
	})
	// Real publishers of the destination, with injectable commit faults.
	faults := &liveCommitFaults{}
	dp := &DestinationPublishers{Reader: l.c, Namespace: ns, New: func(ctx context.Context, d s3store.Destination, r client.Reader, ns string) (publication.Publisher, error) {
		p, err := s3store.NewPublisher(ctx, d, r, controllerNamespace(ns))
		if err != nil {
			return nil, err
		}
		return &liveFaultPublisher{Publisher: p, f: faults}, nil
	}}
	// The key the requests confirm, generated at runtime and installed only
	// in step 8.
	keyA, fpA := signingKeySecret(t, "src-never-installed", "live-pw-a")
	rt := AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: 30 * time.Second, Workers: 1,
		ControllerNamespace: ns, Destinations: dp}
	ConfigureAssessments(rt)
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })

	l.setNamespace("src-team", "src-production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "src-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("src-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "src-production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "20s", DestinationRef: &v1alpha1.DestinationReference{Name: ed.Name, UID: string(ed.UID)}}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "src-team"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	requests := func() []v1alpha1.EvidenceSigningRequest {
		var list v1alpha1.EvidenceSigningRequestList
		_ = l.c.List(context.Background(), &list)
		return list.Items
	}
	t.Cleanup(func() {
		for _, r := range requests() {
			if strings.HasPrefix(r.Name, "src-") {
				_ = l.c.Delete(context.Background(), &r)
			}
		}
		l.dropRuns(b.Name)
		for _, o := range []client.Object{pod, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.Name}}, p} {
			_ = l.c.Delete(context.Background(), o)
		}
	})
	for _, o := range []client.Object{p, b, pod} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	stop := l.startManager()
	stopped := false
	defer func() {
		if !stopped {
			stop()
		}
	}()
	l.waitReady(b.Name, 1)
	var run *v1alpha1.AssessmentRun
	l.eventually("a retained SigningFailed run", func() (bool, string) {
		var runs v1alpha1.AssessmentRunList
		if err := l.c.List(l.ctx, &runs); err != nil {
			return false, err.Error()
		}
		for i := range runs.Items {
			if r := &runs.Items[i]; r.Spec.BindingRef.Name == b.Name && retainedSigningFailure(r) {
				run = r
				return true, ""
			}
		}
		return false, toJSON(runs.Items)
	})
	// The race runs without a manager, so only the racing reconcilers act.
	stop()
	stopped = true
	if run.Status.SigningIntent == nil || run.Status.SigningIntent.Key != nil || run.Status.SigningRecovery != nil {
		t.Fatalf("fixture: want an unpinned Required intent and no recovery state: %s", toJSON(run.Status))
	}
	l.record("signing-failed", map[string]any{"run": run.Name, "failure": run.Status.Publication.Failure.Reason, "expiresAt": run.Status.Publication.ExpiresAt})

	newRequestKey := func(name, fp string) *v1alpha1.EvidenceSigningRequest {
		t.Helper()
		esr := &v1alpha1.EvidenceSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.EvidenceSigningRequestSpec{
			Run: v1alpha1.ExactRunReference{Name: run.Name, UID: string(run.UID)}, Reason: "Live claim test of signing recovery.", ExpectedKeyFingerprint: fp,
			RequestedBy: &v1alpha1.Requester{Username: "platform-admin", UID: "uid-platform-admin"}}}
		if err := l.c.Create(l.ctx, esr); err != nil {
			t.Fatal(err)
		}
		return esr
	}
	newRequest := func(name string) *v1alpha1.EvidenceSigningRequest {
		t.Helper()
		return newRequestKey(name, fpA)
	}
	get := func(name string) *v1alpha1.EvidenceSigningRequest {
		esr := &v1alpha1.EvidenceSigningRequest{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, esr); err != nil {
			return nil
		}
		return esr
	}
	claimNow := func() *v1alpha1.SigningRecoveryClaim {
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(run), r); err != nil {
			t.Fatal(err)
		}
		return claimOf(r)
	}
	// converged reports whether exactly one of names holds the claim, as
	// Pending/Accepted or, once it resumed into its attempt, Running/Signing
	// (the confirmed key is not installed), and every other waits for it.
	converged := func(names []string) (string, bool, string) {
		c := claimNow()
		if c == nil {
			return "", false, "no claim"
		}
		holder := ""
		for _, n := range names {
			esr := get(n)
			if esr == nil {
				return "", false, n + " missing"
			}
			switch {
			case holdsClaim(c, esr) && esr.Status.Phase == v1alpha1.SigningRequestPending && esr.Status.Reason == v1alpha1.RecoveryAccepted,
				holdsClaim(c, esr) && esr.Status.Phase == v1alpha1.SigningRequestRunning && esr.Status.Reason == v1alpha1.RecoverySigning:
				holder = n
			case esr.Status.Phase == v1alpha1.SigningRequestPending && esr.Status.Reason == v1alpha1.RecoveryWaiting:
			default:
				return "", false, fmt.Sprintf("%s: %s (claim %s)", n, toJSON(esr.Status), toJSON(c))
			}
		}
		return holder, holder != "", toJSON(c)
	}

	// 1. Concurrent requests through separate reconcilers.
	names := []string{"src-race-0", "src-race-1", "src-race-2", "src-race-3"}
	for _, n := range names {
		newRequest(n)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	conflicts := 0
	start := make(chan struct{})
	for _, n := range names {
		rec := &SigningRecoveryReconciler{Client: l.c, Reader: l.c, Runtime: currentRuntime()}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 30 {
				_, err := rec.Reconcile(l.ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: n}})
				if err == nil {
					return
				}
				if !apierrors.IsConflict(err) {
					t.Errorf("%s: %v", n, err)
					return
				}
				mu.Lock()
				conflicts++
				mu.Unlock()
			}
			t.Errorf("%s never settled", n)
		}()
	}
	close(start)
	wg.Wait()
	holder, ok, detail := converged(names)
	if !ok {
		t.Fatalf("racing requests did not converge on one holder: %s", detail)
	}
	claim := *claimNow()
	if !claim.ClaimedAt.Before(&claim.Deadline) || claim.Deadline.Sub(claim.ClaimedAt.Time) != rt.PublishTimeout {
		t.Fatalf("claim deadline: %s", toJSON(claim))
	}
	l.record("race", map[string]any{"requests": len(names), "conflictsRetried": conflicts, "holder": holder, "claim": claim})

	// 2. A successor (the registered reconciler in a new manager) resumes
	// the holder with the same claim; the others keep waiting.
	stop = l.startManager()
	stopped = false
	// A request created after the change shows the successor is acting.
	newRequest("src-after-leader")
	names = append(names, "src-after-leader")
	l.eventually("the successor resumes the holder and the others wait", func() (bool, string) {
		got, ok, detail := converged(names)
		return ok && got == holder, detail
	})
	if c := claimNow(); c == nil || *c != claim {
		t.Fatalf("the successor re-claimed the run: %s -> %s", toJSON(claim), toJSON(c))
	}
	l.record("successor", map[string]any{"holder": holder, "claimUnchanged": true})

	// 3. The holder is deleted while holding the claim: exactly one waiting
	// request takes it over.
	if err := l.c.Delete(l.ctx, get(holder)); err != nil {
		t.Fatal(err)
	}
	remaining := without(names, holder)
	var next string
	l.eventually("a waiting request replaces the deleted holder", func() (bool, string) {
		h, ok, d := converged(remaining)
		next = h
		return ok, d
	})
	l.record("deleted-holder", map[string]any{"deleted": holder, "holder": next, "claim": toJSON(claimNow())})

	// 4. The holder ends terminally (as a failed attempt does): it releases
	// its claim and exactly one waiting request takes it over; the terminal
	// request is never rewritten.
	ended := get(next)
	now := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	ended.Status.Phase, ended.Status.Reason, ended.Status.Message, ended.Status.CompletedAt = v1alpha1.SigningRequestFailed, v1alpha1.RecoverySigningFailed, "live: the attempt ended", &now
	meta.SetStatusCondition(&ended.Status.Conditions, metav1.Condition{Type: v1alpha1.ConditionSigningRequestComplete, Status: metav1.ConditionTrue, Reason: "SigningFailed", Message: "live", LastTransitionTime: now})
	if err := l.c.Status().Update(l.ctx, ended); err != nil {
		t.Fatal(err)
	}
	remaining = without(remaining, next)
	var last string
	l.eventually("a waiting request replaces the terminal holder", func() (bool, string) {
		h, ok, d := converged(remaining)
		last = h
		return ok, d
	})
	if got := get(next); got.Status.Reason != v1alpha1.RecoverySigningFailed || got.Status.Message != ended.Status.Message {
		t.Fatalf("the terminal request was rewritten: %s", toJSON(got.Status))
	}
	l.record("terminal-holder", map[string]any{"ended": next, "holder": last, "claim": toJSON(claimNow())})
	stop()
	stopped = true

	// 5. Without the confirmed key, nothing was written to storage: no
	// signature and no commit.
	cur := &v1alpha1.AssessmentRun{}
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(run), cur); err != nil {
		t.Fatal(err)
	}
	store, err := dp.For(l.ctx, cur.Status.Destination)
	if err != nil {
		t.Fatal(err)
	}
	ref := publication.RunRef{ClusterID: scopeCluster(cur), BindingUID: bindingUID(cur), RunUID: string(cur.UID)}
	if _, _, err := store.ReadSignature(l.ctx, ref); !errors.Is(err, publication.ErrNotFound) {
		t.Fatalf("a signature was stored: %v", err)
	}
	if st, err := store.Inspect(l.ctx, ref); err != nil || st.Commit != nil {
		t.Fatalf("storage was committed: %+v %v", st.Commit, err)
	}
	if !retainedSigningFailure(cur) || cur.Status.SigningIntent.Key != nil {
		t.Fatalf("the run is no longer the retained failure: %s", toJSON(cur.Status))
	}
	l.record("storage", map[string]any{"signature": "absent", "commit": "absent", "run": "retained SigningFailed"})

	liveSigningRecoveryAttempt(t, l, liveAttempt{run: run, ed: ed, dp: dp, faults: faults, s3: pub, s3Secret: s3secret.Name, keyA: keyA, fpA: fpA,
		holder: last, waiting: without(remaining, last), newRequestKey: newRequestKey, get: get, startManager: l.startManager})
}

func without(names []string, drop string) []string {
	var out []string
	for _, n := range names {
		if n != drop {
			out = append(out, n)
		}
	}
	return out
}
