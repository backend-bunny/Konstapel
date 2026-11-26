//go:build live

package controller

// Live signing recovery faults (add-evidence-signing-recovery 5.2) on real
// Kubernetes APIs and the test-owned S3 service (RustFS), with keys
// generated for this run. Seven bindings, each on its own Required
// destination, end real runs SigningFailed with their archives retained:
//   - pin: the intent pins key A, then the key Secret is rotated in place to
//     key B before anything is signed;
//   - commit: the first commit lands but its response is lost, and every
//     later commit is refused as a signing failure until the publish timeout;
//   - team: no key Secret; its scheduled run, and later the run of a
//     namespace AssessmentRequest;
//   - conc, exp1 and exp2 (180s retention), orphan: no key Secret.
//
// Faults are injected at fixed points rather than by timing races: hooks on
// the real S3 publisher's StoreSignature and Publish (per destination),
// clients that stop before chosen status writes, direct reconcilers standing
// in for stopped or overlapping leaders, in-process managers as successors,
// direct S3 writes, and the destination's orphan handoff. Each case asserts
// its end state:
//   - key mismatch: the pinned intent's Secret holds key B; the request ends
//     KeyMismatch, nothing is signed or committed, and the run is unchanged;
//   - leader loss after signature storage: the leader stores the signature
//     and stops; the key Secret is deleted; a successor manager resumes the
//     same request and claim, commits the stored signature without reading
//     or storing anything else, and ends Recovered;
//   - expiry during the attempt: a holder retries a refused commit until its
//     recorded expiry passes inside the attempt; with the controller clock,
//     the commit is refused (Expired, no commit); with storage ahead of the
//     controller clock, the commit lands after notAfter (Expired, never
//     served); retention then deletes both, and a later request ends Expired
//     without a storage write;
//   - lost commit response with differing expiries: recovery adopts the
//     commit that landed before SigningFailed, keeping its own publication
//     time and its later expiry, without a publish or a Secret read;
//   - replaced and lost staged archive: EvidenceLost without a storage write;
//   - concurrent requests: three requests, the manager and three overlapping
//     reconcilers, held together at the signature store and the commit;
//     one signature and one commit, one Recovered and the others
//     AlreadyRecovered, all naming the same publication;
//   - orphan handoff during the attempt: the destination is handed off while
//     the signature upload is in flight; the fence cancels it, the request
//     ends Orphaned, a later request too, and nothing is written;
//   - crashes after the run status write and after the namespace request
//     status write: a restart after the attempt deadline repairs the request
//     from the durable recovered record (Recovered, not SigningFailed), a late
//     request ends AlreadyRecovered, and nothing is signed, committed, or
//     rewritten again.
// Finally every commit under the test's destinations is a signed commit,
// each recovered package is served as the archive and signature pair that
// verifies under the intent's key, and every request's terminal outcome is
// kept as evidence. Run through scripts/targeting-live.sh (recovery group).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/download"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

func TestLiveSigningRecoveryFaults(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	s3pub := startS3(t, l)
	const ns = "konstapel-system"
	ctx := l.ctx
	_ = l.c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})

	faults := &recoveryFaults{}
	dp := &DestinationPublishers{Reader: l.c, Namespace: ns, New: func(ctx context.Context, d s3store.Destination, r client.Reader, ns string) (publication.Publisher, error) {
		p, err := s3store.NewPublisher(ctx, d, r, controllerNamespace(ns))
		if err != nil {
			return nil, err
		}
		return &recoveryFaultPublisher{Publisher: p, prefix: d.Prefix, f: faults}, nil
	}}
	x := &srfHarness{t: t, l: l, s3: s3pub, dp: dp, faults: faults}
	rt := AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: 30 * time.Second, Workers: 8,
		ControllerNamespace: ns, Destinations: dp}
	ConfigureAssessments(rt)
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })

	putSecret := func(s *corev1.Secret) *corev1.Secret {
		t.Helper()
		got := &corev1.Secret{}
		if err := l.c.Get(ctx, client.ObjectKeyFromObject(s), got); err == nil {
			got.Data = s.Data
			if err := l.c.Update(ctx, got); err != nil {
				t.Fatal(err)
			}
			return got
		}
		n := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: s.Namespace, Name: s.Name}, Data: s.Data}
		if err := l.c.Create(ctx, n); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = l.c.Delete(context.Background(), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: n.Namespace, Name: n.Name}})
		})
		return n
	}
	s3secret := putSecret(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "srf-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}})

	// Disposable keys, generated for this run. Only the pinned cases' keys
	// exist while their runs publish; the others are installed for recovery.
	keyPinA, fpPinA := signingKeySecret(t, "srf-pin-key", "srf-pin-pw-1")
	keyPinB, fpPinB := signingKeySecret(t, "srf-pin-key", "srf-pin-pw-x")
	keyCommit, fpCommit := signingKeySecret(t, "srf-commit-key", "srf-commit-pw")
	putSecret(keyPinA)
	putSecret(keyCommit)

	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "srf-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	if err := l.c.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	var cases []*srfCase
	newCase := func(id string, retention v1alpha1.Duration) *srfCase {
		t.Helper()
		c := &srfCase{id: id, key: "srf-" + id + "-key"}
		c.ed = &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "srf-" + id}, Spec: v1alpha1.EvidenceDestinationSpec{
			S3: v1alpha1.S3Location{Endpoint: l.s3Endpoint, Bucket: s3pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/srf-" + id, DevelopmentFixture: true,
				CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: s3secret.Name}}},
			Signing: requiredSigning(c.key)}}
		if err := l.c.Create(ctx, c.ed); err != nil {
			t.Fatal(err)
		}
		ed := c.ed
		t.Cleanup(func() {
			got := &v1alpha1.EvidenceDestination{}
			if l.c.Get(context.Background(), client.ObjectKeyFromObject(ed), got) == nil {
				controllerutil.RemoveFinalizer(got, DestinationFinalizer)
				_ = l.c.Update(context.Background(), got)
				_ = l.c.Delete(context.Background(), got)
			}
		})
		l.setNamespace("srf-"+id, "srf-"+id)
		c.b = bindingObj("srf-"+id, p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: v1alpha1.LabelValue("srf-" + id)})
		c.b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "20s", Retention: retention,
			DestinationRef: &v1alpha1.DestinationReference{Name: c.ed.Name, UID: string(c.ed.UID)}}
		cases = append(cases, c)
		return c
	}
	pin, commit, team := newCase("pin", ""), newCase("commit", ""), newCase("team", "")
	conc, exp1, exp2, orph := newCase("conc", ""), newCase("exp1", "180s"), newCase("exp2", "180s"), newCase("orphan", "")

	// Run-path faults. pin: the signature store is refused until the key
	// Secret is rotated, so the run signs nothing and then fails on the key
	// mismatch. commit: the first commit lands after a short delay (so its
	// expiry differs from the failure record's) and its response is lost;
	// every later commit is refused as a signing failure.
	faults.set(pin.prefix(), func(h *recoveryHooks) {
		h.store = func(context.Context, func() ([]byte, publication.Signature, error)) ([]byte, publication.Signature, error) {
			return nil, publication.Signature{}, fmt.Errorf("%w: live fault: the signature store was refused before reaching storage", publication.ErrUnavailable)
		}
	})
	var landedMu sync.Mutex
	landed := false
	faults.set(commit.prefix(), func(h *recoveryHooks) {
		h.publish = func(ctx context.Context, real func(time.Duration) (publication.Receipt, error)) (publication.Receipt, error) {
			landedMu.Lock()
			defer landedMu.Unlock()
			if landed {
				return publication.Receipt{}, fmt.Errorf("%w: live fault: the commit gate could not re-read the stored signature", publication.ErrSignatureRequired)
			}
			if err := sleepUntil(ctx, time.Now().Add(3*time.Second)); err != nil {
				return publication.Receipt{}, err
			}
			if _, err := real(0); err != nil {
				return publication.Receipt{}, err
			}
			landed = true
			return publication.Receipt{}, fmt.Errorf("%w: live fault: the commit response was lost", publication.ErrUnavailable)
		}
	})

	var request *v1alpha1.AssessmentRequest
	t.Cleanup(func() {
		var list v1alpha1.EvidenceSigningRequestList
		_ = l.c.List(context.Background(), &list)
		for i := range list.Items {
			if strings.HasPrefix(list.Items[i].Name, "srf-") {
				_ = l.c.Delete(context.Background(), &list.Items[i])
			}
		}
		if request != nil {
			_ = l.c.Delete(context.Background(), request)
		}
		var cms corev1.ConfigMapList
		_ = l.c.List(context.Background(), &cms, client.InNamespace(ns), client.HasLabels{LabelOrphanHandoff})
		for i := range cms.Items {
			if strings.HasPrefix(cms.Items[i].Name, "konstapel-orphan-"+string(orph.ed.UID)) {
				_ = l.c.Delete(context.Background(), &cms.Items[i])
			}
		}
		for _, c := range cases {
			l.dropRuns(c.b.Name)
			_ = l.c.Delete(context.Background(), &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: c.b.Name}})
			_ = l.c.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "srf-" + c.id, Name: "privileged"}})
		}
		_ = l.c.Delete(context.Background(), p)
	})
	yes := true
	for _, c := range cases {
		c.b.SetUID("")
		c.b.SetGeneration(0)
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "srf-" + c.id},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
		for _, o := range []client.Object{c.b, pod} {
			if err := l.c.Create(ctx, o); err != nil {
				t.Fatal(err)
			}
		}
	}

	// The download routes, unchanged, with authentication and authorization
	// out of the way: only their publication checks are exercised.
	srv := &download.Server{Reader: l.c, Reviews: allowAll{}, TempDir: t.TempDir(),
		PublisherFor: func(ctx context.Context, r *v1alpha1.AssessmentRun) (publication.Publisher, error) {
			return dp.For(ctx, r.Status.Destination)
		}}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	served := func(run *v1alpha1.AssessmentRun, artifact string) (int, []byte) {
		return fetch(t, ts.Client(), ts.URL+"/v1/assessmentruns/"+string(run.UID)+"/"+artifact, "opaque-live-credential")
	}

	// 0. Every run ends SigningFailed with its archive retained.
	stop := l.startManager()
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	restart := func() {
		if stop != nil {
			stop()
		}
		stop = l.startManager()
	}
	halt := func() {
		stop()
		stop = nil
	}
	// The rotation must happen within the pin run's publish timeout, so it
	// is watched for before anything else.
	l.waitReady(pin.b.Name, 1)
	l.eventually("pin: the run's intent pins key A", func() (bool, string) {
		r := x.runOf(pin, func(r *v1alpha1.AssessmentRun) bool {
			return r.Status.SigningIntent != nil && r.Status.SigningIntent.Key != nil
		})
		return r != nil, toJSON(x.runsOf(pin))
	})
	// The key Secret is rotated in place after the intent pinned key A.
	putSecret(keyPinB)
	for _, c := range cases {
		l.waitReady(c.b.Name, 1)
		l.eventually(c.id+": a retained SigningFailed run", func() (bool, string) {
			c.run = x.runOf(c, func(r *v1alpha1.AssessmentRun) bool { return r.Spec.Request == nil && retainedSigningFailure(r) })
			return c.run != nil, toJSON(x.runsOf(c))
		})
	}
	halt()
	for _, c := range []*srfCase{pin, commit} {
		faults.set(c.prefix(), func(h *recoveryHooks) { h.store, h.publish = nil, nil })
	}
	for _, c := range cases {
		in := c.run.Status.SigningIntent
		want := ""
		switch c {
		case pin:
			want = fpPinA
		case commit:
			want = fpCommit
		}
		if in == nil || in.Mode != v1alpha1.SigningRequired || in.SecretName != c.key || (want == "") != (in.Key == nil) || (in.Key != nil && in.Key.Fingerprint != want) ||
			in.ArchiveSHA256 != c.run.Status.Publication.PackageSHA256 || c.run.Status.SigningRecovery != nil || c.run.Status.Publication.Cleanup.State != "NotDue" {
			t.Fatalf("%s: want a retained SigningFailed run with a Required intent pinned to %q: %s", c.id, want, toJSON(c.run.Status))
		}
	}
	if msg := pin.run.Status.Publication.Failure.Message; !strings.Contains(msg, fpPinB) {
		t.Fatalf("pin: want the run to fail on the rotated key: %s", msg)
	}
	commitAtFailure, err := x.store(commit.run).Inspect(ctx, x.ref(commit.run))
	if err != nil || commitAtFailure.Commit == nil || commitAtFailure.Phase != publication.PhaseCommitted || commitAtFailure.Signature == nil {
		t.Fatalf("commit: want the commit whose response was lost in storage: %+v %v", commitAtFailure, err)
	}
	failureRecord := commit.run.Status.Publication
	if !commitAtFailure.PublishedAt.Before(failureRecord.Failure.At.Time) || !commitAtFailure.ExpiresAt.After(failureRecord.ExpiresAt.Time) {
		t.Fatalf("commit: want a commit before the failure with a later expiry: published %s expires %s; failed %s, failure record expires %s",
			commitAtFailure.PublishedAt, commitAtFailure.ExpiresAt, failureRecord.Failure.At, failureRecord.ExpiresAt)
	}
	fixture := map[string]any{}
	for _, c := range cases {
		x.wantVersions(c, c.run, map[string]int{evidencesign.BundleFileName: map[*srfCase]int{commit: 1}[c], "commit.json": map[*srfCase]int{commit: 1}[c]})
		fixture[c.id] = map[string]any{"run": c.run.Name, "failure": c.run.Status.Publication.Failure.Reason, "failedAt": c.run.Status.Publication.Failure.At,
			"expiresAt": c.run.Status.Publication.ExpiresAt, "keyPinned": c.run.Status.SigningIntent.Key != nil}
	}
	fixture["commitInStorage"] = map[string]any{"publishedAt": commitAtFailure.PublishedAt, "expiresAt": commitAtFailure.ExpiresAt}
	l.record("signing-failed", fixture)

	// Direct reconcilers stand in for leaders: with no manager running,
	// only they act. Their attempts are bounded long enough for the steps.
	long := currentRuntime()
	long.PublishTimeout = 3 * time.Minute
	direct := func() *SigningRecoveryReconciler {
		return &SigningRecoveryReconciler{Client: l.c, Reader: l.c, Runtime: long}
	}

	// 1. Expiry during the attempt, set up first: the holders sign, store
	// their signatures, and retry refused commits until their windows.
	keyExp1, fpExp1 := signingKeySecret(t, exp1.key, "srf-exp1-pw")
	keyExp2, fpExp2 := signingKeySecret(t, exp2.key, "srf-exp2-pw")
	expiry := map[*srfCase]time.Time{}
	for _, e := range []struct {
		c   *srfCase
		key *corev1.Secret
		fp  string
		lag time.Duration
	}{{exp1, keyExp1, fpExp1, 0}, {exp2, keyExp2, fpExp2, 30 * time.Second}} {
		putSecret(e.key)
		at := e.c.run.Status.Publication.ExpiresAt.UTC()
		expiry[e.c] = at
		// Refused before storage until shortly before the recorded expiry;
		// then the commit waits until it has passed. exp2's commit goes
		// through a publisher whose clock lags storage (the storage server
		// is ahead of the controller), so it lands after notAfter.
		faults.set(e.c.prefix(), func(h *recoveryHooks) {
			h.publish = func(ctx context.Context, real func(time.Duration) (publication.Receipt, error)) (publication.Receipt, error) {
				if time.Now().Before(at.Add(-8 * time.Second)) {
					return publication.Receipt{}, fmt.Errorf("%w: live fault: the commit was refused before reaching storage", publication.ErrUnavailable)
				}
				if err := sleepUntil(ctx, at.Add(1500*time.Millisecond)); err != nil {
					return publication.Receipt{}, err
				}
				return real(e.lag)
			}
		})
		name := "srf-" + e.c.id + "-attempt"
		x.request(name, e.c.run, e.fp)
		x.until(direct(), name, "signs and retries the refused commit", func(r *v1alpha1.EvidenceSigningRequest) bool {
			return r.Status.Phase == v1alpha1.SigningRequestRunning && r.Status.Reason == v1alpha1.RecoveryCommitting && strings.Contains(r.Status.Message, "refused")
		})
		x.wantVersions(e.c, e.c.run, map[string]int{evidencesign.BundleFileName: 1, "commit.json": 0})
	}

	// 2. Key mismatch: the pinned intent's Secret now holds key B.
	before := x.runNow(pin.run)
	x.request("srf-pin-mismatch", pin.run, "")
	x.until(direct(), "srf-pin-mismatch", "ends", terminalRequest)
	mismatch := x.wantFailed("srf-pin-mismatch", v1alpha1.RecoveryKeyMismatch)
	if m := mismatch.Status.Message; !strings.Contains(m, fpPinB) || !strings.Contains(m, fpPinA) || strings.Contains(m, pin.key) {
		t.Fatalf("pin: want KeyMismatch naming both keys and not the Secret: %s", m)
	}
	if got := x.runNow(pin.run).Status; toJSON(got) != toJSON(before.Status) {
		t.Fatalf("pin: KeyMismatch changed the run:\n%s\n%s", toJSON(before.Status), toJSON(got))
	}
	x.wantVersions(pin, pin.run, map[string]int{evidencesign.BundleFileName: 0, "commit.json": 0})
	l.record("key-mismatch", map[string]any{"request": mismatch.Name, "reason": mismatch.Status.Reason, "pinned": fpPinA, "recordedSecretHolds": fpPinB,
		"signed": false, "committed": false, "runUnchanged": true})

	// 3. Leader loss after signature storage. Key A is restored under the
	// recorded name (re-encrypted); the leader stores the signature and stops
	// before the commit.
	putSecret(reencrypt(t, keyPinA, "srf-pin-pw-1", "srf-pin-pw-2"))
	stored := make(chan []byte, 1)
	faults.set(pin.prefix(), func(h *recoveryHooks) {
		h.store = func(ctx context.Context, real func() ([]byte, publication.Signature, error)) ([]byte, publication.Signature, error) {
			b, s, err := real()
			if err != nil {
				return b, s, err
			}
			select {
			case stored <- b:
			default:
			}
			<-ctx.Done()
			return nil, publication.Signature{}, fmt.Errorf("%w: live fault: the leader stopped after storing the signature: %v", publication.ErrUnavailable, context.Cause(ctx))
		}
	})
	x.request("srf-pin-leader", pin.run, "")
	lctx, lose := context.WithCancel(ctx)
	defer lose()
	leaderDone := make(chan error, 1)
	go func() { leaderDone <- x.lead(lctx, direct(), "srf-pin-leader") }()
	var leaderSignature []byte
	select {
	case leaderSignature = <-stored:
	case err := <-leaderDone:
		t.Fatalf("pin: the leader ended before storing the signature: %v", err)
	case <-time.After(2 * time.Minute):
		t.Fatal("pin: the leader never stored the signature")
	}
	leaderClaim := claimOf(x.runNow(pin.run))
	if leaderClaim == nil || leaderClaim.Name != "srf-pin-leader" {
		t.Fatalf("pin: want the leader's request holding the claim: %s", toJSON(leaderClaim))
	}
	// The key Secret is deleted, so a successor can only commit by reusing
	// the stored signature; then the leader's process stops.
	if err := l.c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: pin.key}}); err != nil {
		t.Fatal(err)
	}
	lose()
	select {
	case err := <-leaderDone:
		if err != nil {
			t.Fatalf("pin: the leader: %v", err)
		}
	case <-time.After(time.Minute):
		t.Fatal("pin: the stopped leader did not return")
	}
	if st := x.esr("srf-pin-leader").Status; st.Phase != v1alpha1.SigningRequestRunning || st.Reason != v1alpha1.RecoverySigning {
		t.Fatalf("pin: want the leader's request left Running/Signing: %s", toJSON(st))
	}
	x.wantVersions(pin, pin.run, map[string]int{evidencesign.BundleFileName: 1, "commit.json": 0})
	pinStores, pinPublishes := faults.counts(pin.prefix())
	l.record("leader-lost", map[string]any{"request": "srf-pin-leader", "claim": leaderClaim, "signatureStored": true, "committed": false,
		"keySecretDeleted": true, "storesReachingStorage": pinStores})

	// 4. The expiry windows: each holder's next attempt starts before its
	// recorded expiry, which passes during the commit.
	for c, at := range expiry {
		if left := time.Until(at); left < 7*time.Second {
			t.Fatalf("%s: only %s left before the recorded expiry; the earlier steps overran its retention", c.id, left)
		}
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	windowErrs := map[string]error{}
	for c, at := range expiry {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := sleepUntil(ctx, at.Add(-6*time.Second))
			if err == nil {
				_, err = direct().Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: "srf-" + c.id + "-attempt"}})
			}
			mu.Lock()
			windowErrs[c.id] = err
			mu.Unlock()
		}()
	}
	wg.Wait()
	for id, err := range windowErrs {
		if err != nil {
			t.Fatalf("%s: the attempt across the expiry: %v", id, err)
		}
	}
	exp1End := x.wantFailed("srf-exp1-attempt", v1alpha1.RecoveryExpired)
	if !strings.Contains(exp1End.Status.Message, "nothing was committed") {
		t.Fatalf("exp1: want the commit refused at the recorded expiry: %s", exp1End.Status.Message)
	}
	x.wantVersions(exp1, exp1.run, map[string]int{evidencesign.BundleFileName: 1, "commit.json": 0})
	exp2End := x.wantFailed("srf-exp2-attempt", v1alpha1.RecoveryExpired)
	if !strings.Contains(exp2End.Status.Message, "never served") {
		t.Fatalf("exp2: want the late commit reported never served: %s", exp2End.Status.Message)
	}
	x.wantVersions(exp2, exp2.run, map[string]int{evidencesign.BundleFileName: 1, "commit.json": 1})
	late, err := x.store(exp2.run).Inspect(ctx, x.ref(exp2.run))
	if err != nil || late.Commit == nil || late.Phase != publication.PhaseExpired || late.Retention == nil || late.Retention.NotAfter == nil ||
		!late.Retention.NotAfter.Equal(expiry[exp2]) || !late.ExpiresAt.Equal(expiry[exp2]) || late.PublishedAt.Before(expiry[exp2]) {
		t.Fatalf("exp2: want a commit that landed at or after notAfter %s, expired at once: %+v %v", expiry[exp2], late, err)
	}
	for _, c := range []*srfCase{exp1, exp2} {
		got := x.runNow(c.run)
		if !retainedSigningFailure(got) || got.Status.SigningRecovery != nil || toJSON(got.Status.Publication) != toJSON(c.run.Status.Publication) {
			t.Fatalf("%s: Expired must leave the retained failure record and release the claim: %s", c.id, toJSON(got.Status))
		}
		for _, artifact := range []string{"download", "signature"} {
			if code, _ := served(got, artifact); code == http.StatusOK {
				t.Fatalf("%s: the expired recovery's %s was served", c.id, artifact)
			}
		}
	}
	l.record("expired-during-attempt", map[string]any{
		"exp1": map[string]any{"request": exp1End.Name, "reason": exp1End.Status.Reason, "notAfter": expiry[exp1], "committed": false, "signatureVersions": 1},
		"exp2": map[string]any{"request": exp2End.Name, "reason": exp2End.Status.Reason, "notAfter": expiry[exp2], "lateCommitPublishedAt": late.PublishedAt,
			"phase": late.Phase, "served": false},
	})

	// 5. The successor (a manager whose destinations' reader records Secret
	// reads) resumes the lost leader's request with the same claim.
	reads := &secretReads{}
	dp.Reader = liveSecretReads{Client: l.c, reads: reads}
	faults.set(pin.prefix(), func(h *recoveryHooks) { h.store = nil })
	restart()
	keyReads := func(name string) int {
		// A list of Secrets ("*") counts as a read of every Secret.
		return len(slices.DeleteFunc(reads.all(), func(n string) bool { return n != name && n != "*" }))
	}
	x.waitTerminal("srf-pin-leader")
	leader := x.wantSucceeded("srf-pin-leader", v1alpha1.RecoveryRecovered, pin)
	if sr := x.runNow(pin.run).Status.SigningRecovery; sr.Recovered.UID != leaderClaim.UID || leader.Status.KeyFingerprint != fpPinA {
		t.Fatalf("pin: the successor did not finish the leader's claimed request: %s", toJSON(sr))
	}
	if stores, publishes := faults.counts(pin.prefix()); stores != pinStores || publishes != pinPublishes+1 {
		t.Fatalf("pin: the successor stored %d signatures and made %d commits; want 0 and 1", stores-pinStores, publishes-pinPublishes)
	}
	if n := keyReads(pin.key); n != 0 {
		t.Fatalf("pin: the successor read the key Secret %d times", n)
	}
	x.wantVersions(pin, pin.run, map[string]int{evidencesign.BundleFileName: 1, "commit.json": 1})
	if b, _, err := x.store(pin.run).ReadSignature(ctx, x.ref(pin.run)); err != nil || !bytes.Equal(b, leaderSignature) {
		t.Fatalf("pin: the committed signature is not the one the lost leader stored: %v", err)
	}
	l.record("leader-successor", map[string]any{"request": leader.Name, "reason": leader.Status.Reason, "claimUID": leaderClaim.UID,
		"publicationID": leader.Status.Publication.PublicationID, "signatureSha256": leader.Status.Publication.SignatureSHA256,
		"keySecretReads": 0, "storesAfterHandover": 0, "commits": 1})

	// The namespace team's request starts now; its run fails signing while
	// the manager handles the cases below (step 9 waits for it).
	request = &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "srf-team", Name: "srf-nightly"},
		Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: team.b.Name}}}
	if err := l.c.Create(ctx, request); err != nil {
		t.Fatal(err)
	}

	// 6. Retention deletes the expired runs' storage, including the late
	// commit, which is never served; a request after the expiry ends Expired
	// without a storage write.
	for _, c := range []*srfCase{exp1, exp2} {
		l.eventually(c.id+": retention deletes the expired storage", func() (bool, string) {
			r := x.runNow(c.run)
			return r.Status.Publication.Cleanup.State == "Deleted" && len(x.objects(x.runPrefix(c, c.run))) == 0, toJSON(r.Status.Publication)
		})
		if code, _ := served(x.runNow(c.run), "download"); code == http.StatusOK {
			t.Fatalf("%s: served after retention", c.id)
		}
	}
	x.request("srf-exp1-late", exp1.run, fpExp1)
	x.waitTerminal("srf-exp1-late")
	expLate := x.wantFailed("srf-exp1-late", v1alpha1.RecoveryExpired)
	if n := len(x.objects(x.runPrefix(exp1, exp1.run))); n != 0 {
		t.Fatalf("exp1: the late request wrote %d objects", n)
	}
	l.record("expiry-retention", map[string]any{"deleted": []string{exp1.run.Name, exp2.run.Name}, "lateRequest": expLate.Name, "reason": expLate.Status.Reason})

	// 7. The staged archive is replaced, then lost: EvidenceLost without a
	// storage write, the run unchanged.
	teamPrefix := x.runPrefix(team, team.run)
	archiveKey := ""
	for _, o := range x.objects(teamPrefix) {
		if strings.HasSuffix(o.Key, "/package.tar.gz") {
			if archiveKey != "" {
				t.Fatalf("team: more than one staged archive: %s", toJSON(x.objects(teamPrefix)))
			}
			archiveKey = o.Key
		}
	}
	keyTeam, fpTeam := signingKeySecret(t, team.key, "srf-team-pw")
	for _, step := range []struct {
		name   string
		tamper func() error
	}{
		{"srf-team-archive-replaced", func() error {
			_, err := s3pub.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(s3pub.Dest.Bucket), Key: aws.String(archiveKey),
				Body: bytes.NewReader([]byte("not the retained evidence archive"))})
			return err
		}},
		{"srf-team-archive-lost", func() error {
			_, err := s3pub.Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s3pub.Dest.Bucket), Key: aws.String(archiveKey)})
			return err
		}},
	} {
		if err := step.tamper(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		snapshot, status := x.objects(teamPrefix), toJSON(x.runNow(team.run).Status)
		x.request(step.name, team.run, fpTeam)
		x.waitTerminal(step.name)
		lost := x.wantFailed(step.name, v1alpha1.RecoveryEvidenceLost)
		if got := x.objects(teamPrefix); toJSON(got) != toJSON(snapshot) {
			t.Fatalf("%s: storage changed:\n%s\n%s", step.name, toJSON(snapshot), toJSON(got))
		}
		l.eventually(step.name+": the run is unchanged and released", func() (bool, string) {
			got := toJSON(x.runNow(team.run).Status)
			return got == status, got
		})
		l.record("evidence-lost", map[string]any{"request": lost.Name, "reason": lost.Status.Reason, "storageWrites": 0, "runUnchanged": true})
	}

	// 8. Lost commit response: the commit that landed before SigningFailed
	// is adopted with its own publication time and later expiry.
	commitStores, commitPublishes := faults.counts(commit.prefix())
	commitPrefix := x.runPrefix(commit, commit.run)
	commitObject := func() []s3obj {
		return slices.DeleteFunc(x.objects(commitPrefix), func(o s3obj) bool { return path.Base(o.Key) != "commit.json" })
	}
	commitBefore := commitObject()
	x.request("srf-commit-adopt", commit.run, "")
	x.waitTerminal("srf-commit-adopt")
	adopted := x.wantSucceeded("srf-commit-adopt", v1alpha1.RecoveryRecovered, commit)
	ap := x.runNow(commit.run).Status.Publication
	if !ap.PublishedAt.Time.Equal(*commitAtFailure.PublishedAt) || !ap.ExpiresAt.Time.Equal(*commitAtFailure.ExpiresAt) || ap.ExpiresAt.Equal(failureRecord.ExpiresAt) ||
		ap.Retention == nil || ap.Retention.NotAfter != nil || toJSON(ap.Commit) != toJSON(publication.ToAPI(commitAtFailure).Commit) {
		t.Fatalf("commit: want the lost-response commit adopted unchanged (published %s, expires %s; failure record %s): %s",
			commitAtFailure.PublishedAt, commitAtFailure.ExpiresAt, failureRecord.ExpiresAt, toJSON(ap))
	}
	if stores, publishes := faults.counts(commit.prefix()); stores != commitStores || publishes != commitPublishes {
		t.Fatalf("commit: adoption stored %d signatures and made %d commits", stores-commitStores, publishes-commitPublishes)
	}
	if n := keyReads(commit.key); n != 0 {
		t.Fatalf("commit: adoption read the key Secret %d times", n)
	}
	if got := commitObject(); toJSON(got) != toJSON(commitBefore) {
		t.Fatalf("commit: the commit object was rewritten:\n%s\n%s", toJSON(commitBefore), toJSON(got))
	}
	x.wantVersions(commit, commit.run, map[string]int{evidencesign.BundleFileName: 1, "commit.json": 1})
	if o, err := (&DestinationReconciler{Reader: l.c}).obligations(ctx, commit.ed); err != nil || o.packages != 1 || o.latest == nil || !o.latest.Time.Equal(*commitAtFailure.ExpiresAt) {
		t.Fatalf("commit: want one retained package with the adopted expiry: %+v %v", o, err)
	}
	l.record("lost-commit-adopted", map[string]any{"request": adopted.Name, "reason": adopted.Status.Reason, "publishedAt": ap.PublishedAt,
		"failedAt": failureRecord.Failure.At, "expiresAt": ap.ExpiresAt, "failureRecordExpiresAt": failureRecord.ExpiresAt, "notAfter": nil,
		"publishes": 0, "keySecretReads": 0, "commitObjectUnchanged": true})

	// 9. Concurrent requests: three requests, the manager, and three more
	// overlapping reconcilers. The first attempts are held until two are
	// inside the signature store, and again inside the commit.
	keyConc, fpConc := signingKeySecret(t, conc.key, "srf-conc-pw")
	putSecret(keyConc)
	storeTogether, commitTogether := newBarrier(2), newBarrier(2)
	faults.set(conc.prefix(), func(h *recoveryHooks) {
		h.store = func(ctx context.Context, real func() ([]byte, publication.Signature, error)) ([]byte, publication.Signature, error) {
			storeTogether.wait(ctx)
			return real()
		}
		h.publish = func(ctx context.Context, real func(time.Duration) (publication.Receipt, error)) (publication.Receipt, error) {
			commitTogether.wait(ctx)
			return real(0)
		}
	})
	names := []string{"srf-conc-0", "srf-conc-1", "srf-conc-2"}
	for _, n := range names {
		x.request(n, conc.run, fpConc)
	}
	overlapErrs := make(chan error, 16)
	until := time.Now().Add(2 * time.Minute)
	for range 3 {
		rec := &SigningRecoveryReconciler{Client: l.c, Reader: l.c, Runtime: currentRuntime()}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(until) {
				open := false
				for _, n := range names {
					if r := x.esr(n); r == nil || !r.Status.Phase.Terminal() {
						open = true
						if _, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: n}}); err != nil && !apierrors.IsConflict(err) {
							overlapErrs <- fmt.Errorf("%s: %w", n, err)
							return
						}
					}
				}
				if !open {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			overlapErrs <- fmt.Errorf("the requests did not end by %s", until.Format(time.RFC3339))
		}()
	}
	wg.Wait()
	close(overlapErrs)
	for err := range overlapErrs {
		t.Errorf("conc: %v", err)
	}
	if t.Failed() {
		t.FailNow()
	}
	if !storeTogether.opened() || !commitTogether.opened() {
		t.Fatalf("conc: the attempts did not overlap (signature store %d, commit %d arrivals)", storeTogether.arrivals(), commitTogether.arrivals())
	}
	sr := x.runNow(conc.run).Status.SigningRecovery
	if sr == nil || sr.Recovered == nil {
		t.Fatalf("conc: the run records no recovery: %s", toJSON(sr))
	}
	holder := sr.Recovered.Name
	var concPub *v1alpha1.SigningRecoveryPublication
	outcomes := map[string]v1alpha1.SigningRecoveryReason{}
	for _, n := range names {
		reason := v1alpha1.RecoveryAlreadyRecovered
		if n == holder {
			reason = v1alpha1.RecoveryRecovered
		}
		r := x.wantSucceeded(n, reason, conc)
		if concPub == nil {
			concPub = r.Status.Publication
		} else if toJSON(r.Status.Publication) != toJSON(concPub) {
			t.Fatalf("conc: %s names another publication: %s, %s", n, toJSON(r.Status.Publication), toJSON(concPub))
		}
		outcomes[n] = r.Status.Reason
	}
	x.wantVersions(conc, conc.run, map[string]int{evidencesign.BundleFileName: 1, "commit.json": 1})
	concStores, concPublishes := faults.counts(conc.prefix())
	l.record("concurrent", map[string]any{"requests": outcomes, "holder": holder, "publicationID": concPub.PublicationID, "signatureSha256": concPub.SignatureSHA256,
		"storeArrivalsTogether": storeTogether.arrivals(), "commitArrivalsTogether": commitTogether.arrivals(),
		"storesReachingStorage": concStores, "commitsReachingStorage": concPublishes, "signatureVersions": 1, "commitVersions": 1})

	// 10. Orphan handoff during the attempt: the destination is handed off
	// while the signature upload is in flight.
	keyOrph, fpOrph := signingKeySecret(t, orph.key, "srf-orphan-pw")
	putSecret(keyOrph)
	inflight, cancelled := make(chan struct{}, 1), make(chan error, 1)
	faults.set(orph.prefix(), func(h *recoveryHooks) {
		h.store = func(ctx context.Context, _ func() ([]byte, publication.Signature, error)) ([]byte, publication.Signature, error) {
			select {
			case inflight <- struct{}{}:
			default:
			}
			<-ctx.Done()
			select {
			case cancelled <- context.Cause(ctx):
			default:
			}
			return nil, publication.Signature{}, fmt.Errorf("%w: live fault: the signature upload was cancelled in flight: %v", publication.ErrUnavailable, context.Cause(ctx))
		}
	})
	orphPrefix := x.runPrefix(orph, orph.run)
	orphObjects := x.objects(orphPrefix)
	x.request("srf-orphan-attempt", orph.run, fpOrph)
	select {
	case <-inflight:
	case <-time.After(2 * time.Minute):
		t.Fatal("orphan: the signature upload never started")
	}
	l.eventually("orphan: the destination is handed off", func() (bool, string) {
		ed := &v1alpha1.EvidenceDestination{}
		if err := l.c.Get(ctx, client.ObjectKeyFromObject(orph.ed), ed); err != nil {
			return false, err.Error()
		}
		ed.Spec.DeletionPolicy = v1alpha1.DeletionOrphan
		ed.Spec.Orphan = &v1alpha1.OrphanRequest{Reason: "backend decommissioned during signing recovery", Actor: "platform-admin"}
		if err := l.c.Update(ctx, ed); err != nil {
			return false, err.Error()
		}
		return l.c.Delete(ctx, ed) == nil, "delete"
	})
	var cause error
	select {
	case cause = <-cancelled:
	case <-time.After(time.Minute):
		t.Fatal("orphan: the fence did not cancel the upload in flight")
	}
	x.waitTerminal("srf-orphan-attempt")
	orphEnd := x.wantFailed("srf-orphan-attempt", v1alpha1.RecoveryOrphaned)
	x.request("srf-orphan-late", orph.run, fpOrph)
	x.waitTerminal("srf-orphan-late")
	orphLate := x.wantFailed("srf-orphan-late", v1alpha1.RecoveryOrphaned)
	if got := x.objects(orphPrefix); toJSON(got) != toJSON(orphObjects) {
		t.Fatalf("orphan: storage changed after the handoff:\n%s\n%s", toJSON(orphObjects), toJSON(got))
	}
	if stores, publishes := faults.counts(orph.prefix()); stores != 0 || publishes != 0 {
		t.Fatalf("orphan: %d signature stores and %d commits reached storage", stores, publishes)
	}
	l.eventually("orphan: the run is unpublished and released", func() (bool, string) {
		r := x.runNow(orph.run)
		return r.Status.Phase == v1alpha1.RunFailed && r.Status.Publication.Commit == nil && r.Status.SigningRecovery == nil, toJSON(r.Status)
	})
	inventory := &corev1.ConfigMap{}
	l.eventually("orphan: the handoff inventory is saved", func() (bool, string) {
		err := l.c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "konstapel-orphan-" + string(orph.ed.UID)}, inventory)
		return err == nil, fmt.Sprint(err)
	})
	l.record("orphaned", map[string]any{"requests": []string{orphEnd.Name, orphLate.Name}, "reason": orphEnd.Status.Reason,
		"cancelledInFlight": fmt.Sprint(cause), "storageWrites": 0, "inventory": inventory.Name})

	// The team request's run has failed signing too.
	var teamRun *v1alpha1.AssessmentRun
	var teamFailed *v1alpha1.AssessmentRequest
	l.eventually("team: the namespace request's run ends SigningFailed", func() (bool, string) {
		teamFailed = x.assessmentRequest(request)
		c := meta.FindStatusCondition(teamFailed.Status.Conditions, v1alpha1.ConditionPublished)
		if teamFailed.Status.Phase != v1alpha1.RequestFailed || teamFailed.Status.Run == nil || c == nil || c.Reason != v1alpha1.ReasonSigningFailed {
			return false, toJSON(teamFailed.Status)
		}
		teamRun = l.run(teamFailed.Status.Run.Name)
		return teamRun != nil && retainedSigningFailure(teamRun) && teamRun.Spec.Request != nil, toJSON(teamRun)
	})
	if in := teamRun.Status.SigningIntent; in == nil || in.Key != nil || in.SecretName != team.key {
		t.Fatalf("team: want an unpinned Required intent: %s", toJSON(teamRun.Status))
	}
	halt()
	dp.Reader = l.c

	// 11. Crashes after the run status write and after the namespace
	// request status write, then a restart after the attempt deadline.
	putSecret(keyTeam)
	short := currentRuntime()
	short.PublishTimeout = 20 * time.Second
	reqBefore := x.assessmentRequest(request)
	x.request("srf-team-crash", teamRun, fpTeam)
	first := &SigningRecoveryReconciler{Client: liveStopAfterRunWrite{l.c}, Reader: l.c, Runtime: short}
	if err := x.step(first, "srf-team-crash"); err != nil {
		t.Fatalf("team: claim: %v", err)
	}
	crashClaim := claimOf(x.runNow(teamRun))
	if crashClaim == nil || crashClaim.Name != "srf-team-crash" {
		t.Fatalf("team: want the request holding the claim: %s", toJSON(crashClaim))
	}
	if err := x.step(first, "srf-team-crash"); err == nil || !strings.Contains(err.Error(), "live fault") {
		t.Fatalf("team: want the stop after the run's status write: %v", err)
	}
	recovered := x.runNow(teamRun)
	if sr := recovered.Status.SigningRecovery; sr == nil || sr.Recovered == nil || sr.Recovered.Name != "srf-team-crash" || sr.Active != nil ||
		recovered.Status.Phase != v1alpha1.RunCompleted || recovered.Status.Publication.Commit == nil {
		t.Fatalf("team: want the run recording the recovery: %s", toJSON(recovered.Status))
	}
	if got := x.assessmentRequest(request); got.ResourceVersion != reqBefore.ResourceVersion {
		t.Fatalf("team: the namespace request was written before the injected stop: %s", toJSON(got.Status))
	}
	if st := x.esr("srf-team-crash").Status; st.Phase.Terminal() {
		t.Fatalf("team: the request ended before its status write: %s", toJSON(st))
	}
	recoveredRecord := toJSON(recovered.Status.SigningRecovery)
	teamStores, teamPublishes := faults.counts(team.prefix())
	l.record("stopped-after-run-write", map[string]any{"request": "srf-team-crash", "recovered": recovered.Status.SigningRecovery.Recovered,
		"namespaceRequest": reqBefore.Status.Phase, "deadline": crashClaim.Deadline})

	second := &SigningRecoveryReconciler{Client: liveStopBeforeSuccess{l.c}, Reader: l.c, Runtime: short}
	if err := x.step(second, "srf-team-crash"); err == nil || !strings.Contains(err.Error(), "live fault") {
		t.Fatalf("team: want the stop after the namespace request's status write: %v", err)
	}
	projected := x.assessmentRequest(request)
	ps := toJSON(projected.Status)
	if c := meta.FindStatusCondition(projected.Status.Conditions, v1alpha1.ConditionPublished); projected.Status.Phase != v1alpha1.RequestCompleted ||
		projected.Status.ArtifactRef != recovered.Status.Publication.PublicationID || c == nil || c.Status != metav1.ConditionTrue ||
		toJSON(projected.Status.Summary) != toJSON(reqBefore.Status.Summary) {
		t.Fatalf("team: want the namespace request Completed with the recovered package: %s", ps)
	}
	for _, leak := range []string{"srf-team-crash", "platform-admin", team.key, "recovery"} {
		if strings.Contains(ps, leak) {
			t.Fatalf("team: the namespace request names %q: %s", leak, ps)
		}
	}
	if st := x.esr("srf-team-crash").Status; st.Phase.Terminal() {
		t.Fatalf("team: the request ended before its status write: %s", toJSON(st))
	}
	l.record("stopped-after-request-write", map[string]any{"request": "srf-team-crash", "namespaceRequest": projected.Status.Phase,
		"artifactRef": projected.Status.ArtifactRef, "sanitized": true})

	x.request("srf-team-late", teamRun, fpTeam)
	if err := sleepUntil(ctx, crashClaim.Deadline.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	restart()
	x.waitTerminal("srf-team-crash")
	x.waitTerminal("srf-team-late")
	crash := x.wantSucceeded("srf-team-crash", v1alpha1.RecoveryRecovered, nil)
	teamLate := x.wantSucceeded("srf-team-late", v1alpha1.RecoveryAlreadyRecovered, nil)
	if toJSON(crash.Status.Publication) != toJSON(teamLate.Status.Publication) {
		t.Fatalf("team: the requests name different publications: %s %s", toJSON(crash.Status.Publication), toJSON(teamLate.Status.Publication))
	}
	final := x.runNow(teamRun)
	if got := toJSON(final.Status.SigningRecovery); got != recoveredRecord {
		t.Fatalf("team: the recovered record changed: %s -> %s", recoveredRecord, got)
	}
	if got := x.assessmentRequest(request); got.ResourceVersion != projected.ResourceVersion {
		t.Fatalf("team: the namespace request was rewritten after the restart: %s", toJSON(got.Status))
	}
	if stores, publishes := faults.counts(team.prefix()); stores != teamStores || publishes != teamPublishes {
		t.Fatalf("team: the restart stored %d signatures and made %d commits", stores-teamStores, publishes-teamPublishes)
	}
	if srfEvidence(&final.Status) != srfEvidence(&teamRun.Status) {
		t.Fatalf("team: recovery changed the run's evidence:\n%s\n%s", srfEvidence(&teamRun.Status), srfEvidence(&final.Status))
	}
	x.wantVersions(team, teamRun, map[string]int{evidencesign.BundleFileName: 1, "commit.json": 1})
	l.record("restart-after-deadline", map[string]any{"deadline": crashClaim.Deadline, "restartedAt": time.Now().UTC(), "requests": map[string]any{
		crash.Name: crash.Status.Reason, teamLate.Name: teamLate.Status.Reason}, "storesAfterRestart": 0, "commitsAfterRestart": 0, "namespaceRequestRewritten": false})
	halt()

	// No commit under the test's destinations is unsigned, each recovered
	// package is served as its verifying pair, and every request ended with
	// its defined outcome.
	commits := map[string]string{}
	listed, err := s3pub.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(s3pub.Dest.Bucket), Prefix: aws.String("konstapel-test/srf-")})
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToBool(listed.IsTruncated) {
		t.Fatal("the destinations hold more objects than one listing returns")
	}
	for _, o := range listed.Contents {
		// Only run publications; the destination probe writes its own
		// short-lived commit.json under konstapel-probe/.
		key := aws.ToString(o.Key)
		if path.Base(key) != "commit.json" || !strings.Contains(key, "/evidence/") {
			continue
		}
		got, err := s3pub.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s3pub.Dest.Bucket), Key: o.Key})
		if err != nil {
			t.Fatal(err)
		}
		var rec struct {
			Kind      string `json:"kind"`
			Signature *struct {
				KeyFingerprint string `json:"keyFingerprint"`
			} `json:"signature"`
		}
		err = json.NewDecoder(got.Body).Decode(&rec)
		_ = got.Body.Close()
		if err != nil || rec.Kind != "SignedPublicationCommit" || rec.Signature == nil || rec.Signature.KeyFingerprint == "" {
			t.Fatalf("%s is not a signed commit: %+v %v", key, rec, err)
		}
		commits[key] = rec.Signature.KeyFingerprint
	}
	want := map[*srfCase]*v1alpha1.AssessmentRun{pin: pin.run, commit: commit.run, conc: conc.run, team: teamRun}
	if len(commits) != len(want) {
		t.Fatalf("want exactly the %d recovered commits: %v", len(want), commits)
	}
	downloads := map[string]any{}
	for c, run := range want {
		r := x.runNow(run)
		in := r.Status.SigningIntent
		if fp := commits[x.runPrefix(c, run)+"commit.json"]; fp == "" || fp != in.Key.Fingerprint {
			t.Fatalf("%s: the commit is signed by %q, not the intent's %s", c.id, fp, in.Key.Fingerprint)
		}
		code, archive := served(r, "download")
		sigCode, bundle := served(r, "signature")
		sum := sha256.Sum256(archive)
		pk, err := evidencesign.ParsePublicKey([]byte(in.Key.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		d, _ := evidencesign.ParseArchiveDigest(in.ArchiveSHA256)
		if code != http.StatusOK || sigCode != http.StatusOK || hex.EncodeToString(sum[:]) != in.ArchiveSHA256 {
			t.Fatalf("%s: the recovered pair is not served: archive %d signature %d", c.id, code, sigCode)
		}
		if _, err := evidencesign.Verify(bundle, d, pk); err != nil {
			t.Fatalf("%s: the served signature does not verify under the intent key: %v", c.id, err)
		}
		downloads[c.id] = map[string]any{"archive": code, "signature": sigCode, "archiveSha256": in.ArchiveSHA256, "keyFingerprint": in.Key.Fingerprint}
	}
	var all v1alpha1.EvidenceSigningRequestList
	if err := l.c.List(ctx, &all); err != nil {
		t.Fatal(err)
	}
	ended := map[string]string{}
	for _, r := range all.Items {
		if strings.HasPrefix(r.Name, "srf-") {
			if !r.Status.Phase.Terminal() {
				t.Fatalf("%s did not end: %s", r.Name, toJSON(r.Status))
			}
			ended[r.Name] = string(r.Status.Phase) + "/" + string(r.Status.Reason)
		}
	}
	l.record("end-state", map[string]any{"signedCommits": len(commits), "unsignedCommits": 0, "downloads": downloads, "requests": ended})
}

// srfCase is one fault case: its destination, binding, key Secret name, and
// its retained SigningFailed run as it failed.
type srfCase struct {
	id  string
	ed  *v1alpha1.EvidenceDestination
	b   *v1alpha1.ComplianceBinding
	key string
	run *v1alpha1.AssessmentRun
}

func (c *srfCase) prefix() string { return c.ed.Spec.S3.Prefix }

type srfHarness struct {
	t      *testing.T
	l      *live
	s3     *s3store.Publisher
	dp     *DestinationPublishers
	faults *recoveryFaults
}

func (x *srfHarness) runsOf(c *srfCase) []v1alpha1.AssessmentRun {
	var runs v1alpha1.AssessmentRunList
	_ = x.l.c.List(x.l.ctx, &runs)
	return slices.DeleteFunc(runs.Items, func(r v1alpha1.AssessmentRun) bool { return r.Spec.BindingRef.Name != c.b.Name })
}

func (x *srfHarness) runOf(c *srfCase, ok func(*v1alpha1.AssessmentRun) bool) *v1alpha1.AssessmentRun {
	for _, r := range x.runsOf(c) {
		if ok(&r) {
			return r.DeepCopy()
		}
	}
	return nil
}

func (x *srfHarness) runNow(run *v1alpha1.AssessmentRun) *v1alpha1.AssessmentRun {
	x.t.Helper()
	r := &v1alpha1.AssessmentRun{}
	if err := x.l.c.Get(x.l.ctx, client.ObjectKeyFromObject(run), r); err != nil {
		x.t.Fatal(err)
	}
	return r
}

func (x *srfHarness) assessmentRequest(q *v1alpha1.AssessmentRequest) *v1alpha1.AssessmentRequest {
	x.t.Helper()
	got := &v1alpha1.AssessmentRequest{}
	if err := x.l.c.Get(x.l.ctx, client.ObjectKeyFromObject(q), got); err != nil {
		x.t.Fatal(err)
	}
	return got
}

func (x *srfHarness) ref(run *v1alpha1.AssessmentRun) publication.RunRef {
	return publication.RunRef{ClusterID: scopeCluster(run), BindingUID: bindingUID(run), RunUID: string(run.UID)}
}

func (x *srfHarness) runPrefix(c *srfCase, run *v1alpha1.AssessmentRun) string {
	return s3store.RunPrefix(s3store.Destination{Prefix: c.prefix()}, x.ref(run))
}

func (x *srfHarness) store(run *v1alpha1.AssessmentRun) publication.Publisher {
	x.t.Helper()
	s, err := x.dp.For(x.l.ctx, x.runNow(run).Status.Destination)
	if err != nil {
		x.t.Fatal(err)
	}
	return s
}

// esr reads a request; nil when it cannot be read (safe off the test
// goroutine).
func (x *srfHarness) esr(name string) *v1alpha1.EvidenceSigningRequest {
	r := &v1alpha1.EvidenceSigningRequest{}
	if err := x.l.c.Get(x.l.ctx, client.ObjectKey{Name: name}, r); err != nil {
		return nil
	}
	return r
}

// request creates a recovery request for run, attributed as admission would
// record it.
func (x *srfHarness) request(name string, run *v1alpha1.AssessmentRun, fp string) {
	x.t.Helper()
	esr := &v1alpha1.EvidenceSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.EvidenceSigningRequestSpec{
		Run: v1alpha1.ExactRunReference{Name: run.Name, UID: string(run.UID)}, Reason: "Live fault test of signing recovery.", ExpectedKeyFingerprint: fp,
		RequestedBy: &v1alpha1.Requester{Username: "platform-admin", UID: "uid-platform-admin"}}}
	if err := x.l.c.Create(x.l.ctx, esr); err != nil {
		x.t.Fatal(err)
	}
}

// step reconciles a request once with rec, retrying conflicts.
func (x *srfHarness) step(rec *SigningRecoveryReconciler, name string) error {
	for range 10 {
		_, err := rec.Reconcile(x.l.ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: name}})
		if !apierrors.IsConflict(err) {
			return err
		}
	}
	return fmt.Errorf("%s: conflicts persisted", name)
}

// until reconciles a request with rec until ok holds.
func (x *srfHarness) until(rec *SigningRecoveryReconciler, name, what string, ok func(*v1alpha1.EvidenceSigningRequest) bool) {
	x.t.Helper()
	for range 8 {
		if err := x.step(rec, name); err != nil {
			x.t.Fatalf("%s: %v", name, err)
		}
		if r := x.esr(name); r != nil && ok(r) {
			return
		}
	}
	x.t.Fatalf("%s %s: %s", name, what, toJSON(x.esr(name).Status))
}

// lead runs rec as a leader for one request until ctx ends (the leader
// stops) or the request ends.
func (x *srfHarness) lead(ctx context.Context, rec *SigningRecoveryReconciler, name string) error {
	for ctx.Err() == nil {
		_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: name}})
		if ctx.Err() != nil {
			return nil
		}
		if err != nil && !apierrors.IsConflict(err) {
			return err
		}
		if r := x.esr(name); r != nil && r.Status.Phase.Terminal() {
			return fmt.Errorf("%s ended: %s", name, toJSON(r.Status))
		}
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil
}

func terminalRequest(r *v1alpha1.EvidenceSigningRequest) bool { return r.Status.Phase.Terminal() }

func (x *srfHarness) waitTerminal(name string) {
	x.t.Helper()
	x.l.eventually(name+" ends", func() (bool, string) {
		r := x.esr(name)
		if r == nil {
			return false, "missing"
		}
		return r.Status.Phase.Terminal(), toJSON(r.Status)
	})
}

// wantFailed checks that a request ended Failed with reason, naming no key.
func (x *srfHarness) wantFailed(name string, reason v1alpha1.SigningRecoveryReason) *v1alpha1.EvidenceSigningRequest {
	x.t.Helper()
	r := x.esr(name)
	if r == nil || r.Status.Phase != v1alpha1.SigningRequestFailed || r.Status.Reason != reason || r.Status.KeyFingerprint != "" || r.Status.Publication != nil ||
		r.Status.CompletedAt == nil || !meta.IsStatusConditionTrue(r.Status.Conditions, v1alpha1.ConditionSigningRequestComplete) {
		x.t.Fatalf("%s: want Failed/%s: %s", name, reason, toJSON(r))
	}
	return r
}

// wantSucceeded checks that a request ended Succeeded with reason and names
// its run's recovered publication; with c, also that the run is Completed,
// records the recovery without a claim, and keeps its evidence.
func (x *srfHarness) wantSucceeded(name string, reason v1alpha1.SigningRecoveryReason, c *srfCase) *v1alpha1.EvidenceSigningRequest {
	x.t.Helper()
	r := x.esr(name)
	if r == nil || r.Status.Phase != v1alpha1.SigningRequestSucceeded || r.Status.Reason != reason || r.Status.Publication == nil {
		x.t.Fatalf("%s: want Succeeded/%s: %s", name, reason, toJSON(r))
	}
	run := x.runNow(&v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: r.Spec.Run.Name}})
	pub, sr := run.Status.Publication, run.Status.SigningRecovery
	if run.Status.Phase != v1alpha1.RunCompleted || pub == nil || pub.Commit == nil || pub.Signature == nil || sr == nil || sr.Active != nil || sr.Recovered == nil ||
		!meta.IsStatusConditionTrue(run.Status.Conditions, v1alpha1.ConditionPublished) || run.Status.SigningIntent == nil || run.Status.SigningIntent.Key == nil {
		x.t.Fatalf("%s: want the run Completed and recording its recovery: %s", name, toJSON(run.Status))
	}
	p := r.Status.Publication
	if p.PublicationID != pub.PublicationID || p.PackageSHA256 != pub.PackageSHA256 || p.SignatureSHA256 != pub.Signature.SHA256 ||
		!p.PublishedAt.Equal(pub.PublishedAt) || !p.ExpiresAt.Equal(pub.ExpiresAt) || r.Status.KeyFingerprint != pub.Signature.KeyFingerprint ||
		pub.Signature.KeyFingerprint != run.Status.SigningIntent.Key.Fingerprint || pub.PackageSHA256 != run.Status.SigningIntent.ArchiveSHA256 {
		x.t.Fatalf("%s: the request does not name the run's signed publication:\n%s\n%s", name, toJSON(r.Status), toJSON(pub))
	}
	if c != nil && srfEvidence(&run.Status) != srfEvidence(&c.run.Status) {
		x.t.Fatalf("%s: recovery changed the run's evidence:\n%s\n%s", name, srfEvidence(&c.run.Status), srfEvidence(&run.Status))
	}
	return r
}

// srfEvidence is a run status without what a successful recovery records
// (evidenceOf) and the attempt cleanup that follows a commit.
func srfEvidence(st *v1alpha1.AssessmentRunStatus) string {
	c := st.DeepCopy()
	meta.RemoveStatusCondition(&c.Conditions, v1alpha1.ConditionAttemptsCleaned)
	return evidenceOf(c)
}

// s3obj is one object version or delete marker in the test S3 service.
type s3obj struct {
	Key, Version, ETag string
	Size               int64
	Modified           time.Time
	Marker             bool
}

// objects lists every object version and delete marker under prefix.
func (x *srfHarness) objects(prefix string) []s3obj {
	x.t.Helper()
	var out []s3obj
	in := &s3.ListObjectVersionsInput{Bucket: aws.String(x.s3.Dest.Bucket), Prefix: aws.String(prefix)}
	for {
		page, err := x.s3.Client.ListObjectVersions(x.l.ctx, in)
		if err != nil {
			x.t.Fatal(err)
		}
		for _, v := range page.Versions {
			out = append(out, s3obj{Key: aws.ToString(v.Key), Version: aws.ToString(v.VersionId), ETag: aws.ToString(v.ETag), Size: aws.ToInt64(v.Size), Modified: aws.ToTime(v.LastModified)})
		}
		for _, m := range page.DeleteMarkers {
			out = append(out, s3obj{Key: aws.ToString(m.Key), Version: aws.ToString(m.VersionId), Modified: aws.ToTime(m.LastModified), Marker: true})
		}
		if !aws.ToBool(page.IsTruncated) {
			break
		}
		in.KeyMarker, in.VersionIdMarker = page.NextKeyMarker, page.NextVersionIdMarker
	}
	slices.SortFunc(out, func(a, b s3obj) int { return strings.Compare(a.Key+"\x00"+a.Version, b.Key+"\x00"+b.Version) })
	return out
}

// wantVersions checks how many versions of the signature and the commit the
// run's storage holds, with no delete markers.
func (x *srfHarness) wantVersions(c *srfCase, run *v1alpha1.AssessmentRun, want map[string]int) {
	x.t.Helper()
	got := map[string]int{}
	for _, o := range x.objects(x.runPrefix(c, run)) {
		name := path.Base(o.Key)
		if _, ok := want[name]; !ok {
			continue
		}
		if o.Marker {
			x.t.Fatalf("%s: a delete marker for %s", c.id, o.Key)
		}
		got[name]++
	}
	for name, n := range want {
		if got[name] != n {
			x.t.Fatalf("%s: want %d versions of %s, got %d", c.id, n, name, got[name])
		}
	}
}

// recoveryFaults routes each destination's signature stores and commits
// (by its S3 prefix) through the hooks a fault case sets; without a hook a
// call goes straight to the real publisher. Calls that reach storage are
// counted.
type recoveryFaults struct {
	mu    sync.Mutex
	hooks map[string]*recoveryHooks
}

// A storeHook or publishHook decides what a call does; real performs the
// real call (a commit through a publisher whose clock lags by lag).
type (
	storeHook   func(ctx context.Context, real func() ([]byte, publication.Signature, error)) ([]byte, publication.Signature, error)
	publishHook func(ctx context.Context, real func(lag time.Duration) (publication.Receipt, error)) (publication.Receipt, error)
)

type recoveryHooks struct {
	store             storeHook
	publish           publishHook
	stores, publishes int
}

func (f *recoveryFaults) set(prefix string, mutate func(*recoveryHooks)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hooks == nil {
		f.hooks = map[string]*recoveryHooks{}
	}
	if f.hooks[prefix] == nil {
		f.hooks[prefix] = &recoveryHooks{}
	}
	mutate(f.hooks[prefix])
}

func (f *recoveryFaults) get(prefix string) (storeHook, publishHook) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h := f.hooks[prefix]; h != nil {
		return h.store, h.publish
	}
	return nil, nil
}

func (f *recoveryFaults) reached(prefix string, store bool) {
	f.set(prefix, func(h *recoveryHooks) {
		if store {
			h.stores++
		} else {
			h.publishes++
		}
	})
}

// counts are the signature stores and commits that reached storage.
func (f *recoveryFaults) counts(prefix string) (stores, publishes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h := f.hooks[prefix]; h != nil {
		return h.stores, h.publishes
	}
	return 0, 0
}

// recoveryFaultPublisher is a real S3 publisher whose signature stores and
// commits recoveryFaults controls; everything else is the real publisher's.
type recoveryFaultPublisher struct {
	*s3store.Publisher
	prefix string
	f      *recoveryFaults
}

func (p *recoveryFaultPublisher) StoreSignature(ctx context.Context, run publication.RunRef, bundle []byte) ([]byte, publication.Signature, error) {
	hook, _ := p.f.get(p.prefix)
	real := func() ([]byte, publication.Signature, error) {
		p.f.reached(p.prefix, true)
		return p.Publisher.StoreSignature(ctx, run, bundle)
	}
	if hook == nil {
		return real()
	}
	return hook(ctx, real)
}

func (p *recoveryFaultPublisher) Publish(ctx context.Context, req publication.PublishRequest) (publication.Receipt, error) {
	_, hook := p.f.get(p.prefix)
	real := func(lag time.Duration) (publication.Receipt, error) {
		p.f.reached(p.prefix, false)
		s := p.Publisher
		if lag > 0 {
			lagging := *p.Publisher
			lagging.Now = func() time.Time { return time.Now().Add(-lag) }
			s = &lagging
		}
		return s.Publish(ctx, req)
	}
	if hook == nil {
		return real(0)
	}
	return hook(ctx, real)
}

// barrier holds its first arrivals until want of them are inside, so that
// overlapping attempts reach a storage write together; later arrivals pass.
// It gives up after a bound and reports whether it opened.
type barrier struct {
	mu      sync.Mutex
	want, n int
	open    chan struct{}
}

func newBarrier(want int) *barrier { return &barrier{want: want, open: make(chan struct{})} }

func (b *barrier) wait(ctx context.Context) {
	b.mu.Lock()
	b.n++
	if b.n == b.want {
		close(b.open)
	}
	b.mu.Unlock()
	select {
	case <-b.open:
	case <-ctx.Done():
	case <-time.After(30 * time.Second):
	}
}

func (b *barrier) opened() bool {
	select {
	case <-b.open:
		return true
	default:
		return false
	}
}

func (b *barrier) arrivals() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.n
}

func sleepUntil(ctx context.Context, at time.Time) error {
	timer := time.NewTimer(time.Until(at))
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

// liveStopAfterRunWrite is a live client that fails every namespace
// AssessmentRequest status write before it reaches the API server, as a
// controller stopping right after the recovered run's status write would.
type liveStopAfterRunWrite struct{ client.Client }

func (c liveStopAfterRunWrite) Status() client.SubResourceWriter {
	return liveStopRequestWriter{c.Client.Status()}
}

type liveStopRequestWriter struct{ client.SubResourceWriter }

func (w liveStopRequestWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if _, ok := obj.(*v1alpha1.AssessmentRequest); ok {
		return fmt.Errorf("%w: live fault: the controller stopped after the run's status write", publication.ErrUnavailable)
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}
