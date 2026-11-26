//go:build live

package controller

// The live recovery attempt, its deadline, and its recorded success
// (add-evidence-signing-recovery 2.4 to 2.6), continuing
// TestLiveSigningRecoveryClaim on its retained SigningFailed run. See that
// test's comment for the steps.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/download"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// liveCommitFaults refuses or loses the response of real commits.
type liveCommitFaults struct {
	mu        sync.Mutex
	refuse    bool // every commit fails before it reaches storage
	lose      int  // the next commits land, and their responses are lost
	publishes int
}

// liveFaultPublisher is a real publisher whose commits liveCommitFaults
// controls; everything else is the real publisher's.
type liveFaultPublisher struct {
	publication.Publisher
	f *liveCommitFaults
}

func (p *liveFaultPublisher) Publish(ctx context.Context, req publication.PublishRequest) (publication.Receipt, error) {
	p.f.mu.Lock()
	p.f.publishes++
	refuse, lose := p.f.refuse, p.f.lose > 0
	if lose {
		p.f.lose--
	}
	p.f.mu.Unlock()
	if refuse {
		return publication.Receipt{}, fmt.Errorf("%w: live fault: the commit was refused before reaching storage", publication.ErrUnavailable)
	}
	r, err := p.Publisher.Publish(ctx, req)
	if err == nil && lose {
		return publication.Receipt{}, fmt.Errorf("%w: live fault: the commit response was lost", publication.ErrUnavailable)
	}
	return r, err
}

func (f *liveCommitFaults) set(refuse bool, lose int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refuse, f.lose = refuse, lose
}

func (f *liveCommitFaults) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.publishes
}

// liveSecretReads records Secret reads through a live client.
type liveSecretReads struct {
	client.Client
	reads *secretReads
}

func (c liveSecretReads) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.Secret); ok {
		c.reads.add(key.Name)
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func (c liveSecretReads) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*corev1.SecretList); ok {
		c.reads.add("*")
	}
	return c.Client.List(ctx, list, opts...)
}

type liveAttempt struct {
	run           *v1alpha1.AssessmentRun
	ed            *v1alpha1.EvidenceDestination
	dp            *DestinationPublishers
	faults        *liveCommitFaults
	s3            *s3store.Publisher
	s3Secret      string
	keyA          *corev1.Secret
	fpA           string
	holder        string
	waiting       []string
	newRequestKey func(name, fp string) *v1alpha1.EvidenceSigningRequest
	get           func(name string) *v1alpha1.EvidenceSigningRequest
	startManager  func() (stop func())
}

func liveSigningRecoveryAttempt(t *testing.T, l *live, a liveAttempt) {
	ctx := l.ctx
	ns := a.keyA.Namespace
	runNow := func() *v1alpha1.AssessmentRun {
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(ctx, client.ObjectKeyFromObject(a.run), r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	ref := publication.RunRef{ClusterID: scopeCluster(a.run), BindingUID: bindingUID(a.run), RunUID: string(a.run.UID)}
	store := func() publication.Publisher {
		s, err := a.dp.For(ctx, runNow().Status.Destination)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	// drive reconciles a request n times with rec, retrying conflicts.
	drive := func(rec *SigningRecoveryReconciler, name string, n int) {
		t.Helper()
		for i, conflicts := 0, 0; i < n; {
			_, err := rec.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: name}})
			switch {
			case err == nil:
				i++
			case apierrors.IsConflict(err) && conflicts < 10:
				conflicts++
			default:
				t.Fatalf("%s: %v", name, err)
			}
		}
	}
	// keyReads are the recorded reads of anything but the S3 credentials.
	keyReads := func(r *secretReads) []string {
		return slices.DeleteFunc(r.all(), func(n string) bool { return n == a.s3Secret })
	}
	recording := func() (*SigningRecoveryReconciler, *secretReads) {
		r := &secretReads{}
		c := liveSecretReads{Client: l.c, reads: r}
		a.dp.Reader = c
		return &SigningRecoveryReconciler{Client: c, Reader: c, Runtime: currentRuntime()}, r
	}
	wantEnded := func(name string, reason v1alpha1.SigningRecoveryReason) {
		t.Helper()
		st := a.get(name).Status
		if st.Phase != v1alpha1.SigningRequestFailed || st.Reason != reason || st.KeyFingerprint != "" || strings.Contains(toJSON(st), "src-never-installed") {
			t.Fatalf("%s: want Failed/%s naming no Secret: %s", name, reason, toJSON(st))
		}
	}
	unpinned := func(what string) {
		t.Helper()
		if r := runNow(); r.Status.SigningIntent.Key != nil || !retainedSigningFailure(r) {
			t.Fatalf("%s pinned a key or changed the retained failure: %s", what, toJSON(r.Status))
		}
		if _, _, err := store().ReadSignature(ctx, ref); !errors.Is(err, publication.ErrNotFound) {
			t.Fatalf("%s stored a signature: %v", what, err)
		}
	}
	putSecret := func(name string, data map[string][]byte) *corev1.Secret {
		t.Helper()
		s := &corev1.Secret{}
		if err := l.c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, s); err == nil {
			s.Data = data
			if err := l.c.Update(ctx, s); err != nil {
				t.Fatal(err)
			}
			return s
		}
		s = &corev1.Secret{ObjectMeta: a.keyA.ObjectMeta, Data: data}
		s.Name = name
		if err := l.c.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(context.Background(), &corev1.Secret{ObjectMeta: s.ObjectMeta}) })
		return s
	}

	// 6. The recorded Secret holds another key: the holder ends KeyMismatch
	// and nothing is pinned or signed.
	keyB, fpB := signingKeySecret(t, "src-never-installed", "live-pw-b")
	putSecret("src-never-installed", keyB.Data)
	plain := &SigningRecoveryReconciler{Client: l.c, Reader: l.c, Runtime: currentRuntime()}
	drive(plain, a.holder, 1)
	wantEnded(a.holder, v1alpha1.RecoveryKeyMismatch)
	unpinned("KeyMismatch")
	l.record("key-mismatch", map[string]any{"request": a.holder, "recordedSecretFingerprint": fpB, "confirmed": a.fpA, "pinned": false})

	// 7. No confirmation: KeyConfirmationRequired before any signing Secret
	// is read.
	rec, reads := recording()
	a.newRequestKey("src-unconfirmed", "")
	drive(rec, "src-unconfirmed", 2)
	wantEnded("src-unconfirmed", v1alpha1.RecoveryKeyConfirmationRequired)
	if got := keyReads(reads); len(got) != 0 {
		t.Fatalf("KeyConfirmationRequired read signing Secrets: %v", got)
	}
	a.dp.Reader = l.c
	unpinned("KeyConfirmationRequired")
	l.record("key-confirmation-required", map[string]any{"request": "src-unconfirmed", "signingSecretReads": 0, "pinned": false})

	// 8. The confirmed key is installed under the recorded name, and the
	// destination now names another Secret holding another key. Overlapping
	// reconcilers pin the confirmed key once, sign, and store one signature;
	// every commit is refused.
	secretA := putSecret("src-never-installed", a.keyA.Data)
	putSecret("src-rotated", keyB.Data)
	l.eventually("the destination rotated to src-rotated", func() (bool, string) {
		ed := &v1alpha1.EvidenceDestination{}
		if err := l.c.Get(ctx, client.ObjectKeyFromObject(a.ed), ed); err != nil {
			return false, err.Error()
		}
		ed.Spec.Signing = requiredSigning("src-rotated")
		if err := l.c.Update(ctx, ed); err != nil {
			return false, err.Error()
		}
		return true, ""
	})
	a.faults.set(true, 0)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 3 {
		r := &SigningRecoveryReconciler{Client: l.c, Reader: l.c, Runtime: currentRuntime()}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 4 {
				for _, n := range a.waiting {
					if _, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: n}}); err != nil && !apierrors.IsConflict(err) {
						t.Errorf("%s: %v", n, err)
					}
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	for _, n := range a.waiting {
		drive(plain, n, 1)
	}
	c := claimOf(runNow())
	if c == nil {
		t.Fatal("no waiting request took the claim")
	}
	holder := c.Name
	for _, n := range a.waiting {
		st := a.get(n).Status
		if n == holder && (st.Phase != v1alpha1.SigningRequestRunning || st.Reason != v1alpha1.RecoveryCommitting || !strings.Contains(st.Message, "retrying")) ||
			n != holder && (st.Phase != v1alpha1.SigningRequestPending || st.Reason != v1alpha1.RecoveryWaiting) {
			t.Fatalf("%s (holder %s): %s", n, holder, toJSON(st))
		}
	}
	run := runNow()
	k := run.Status.SigningIntent.Key
	if k == nil || k.Fingerprint != a.fpA || k.SecretUID != string(secretA.UID) || run.Status.SigningIntent.SecretName != "src-never-installed" {
		t.Fatalf("want the intent pinned once to the confirmed %s from the recorded Secret: %s", a.fpA, toJSON(run.Status.SigningIntent))
	}
	stored, _, err := store().ReadSignature(ctx, ref)
	if err != nil {
		t.Fatalf("no signature stored: %v", err)
	}
	if st, err := store().Inspect(ctx, ref); err != nil || st.Commit != nil {
		t.Fatalf("a refused commit was made: %+v %v", st.Commit, err)
	}
	l.record("signed", map[string]any{"holder": holder, "pinned": a.fpA, "destinationSecret": "src-rotated", "commitsRefused": a.faults.count()})

	// 8b. (2.5) Every commit stays refused until the holder's deadline: the
	// holder ends SigningFailed and releases its claim; the run is its
	// retained failure with the pin, the destination still counts one
	// retained package with its expiry, and nothing is downloadable.
	failed := runNow()
	obligationsNow := func() obligations {
		t.Helper()
		o, err := (&DestinationReconciler{Reader: l.c}).obligations(ctx, a.ed)
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	before := obligationsNow()
	srv := &download.Server{Reader: l.c, Reviews: allowAll{}, TempDir: t.TempDir(),
		PublisherFor: func(ctx context.Context, r *v1alpha1.AssessmentRun) (publication.Publisher, error) {
			return a.dp.For(ctx, r.Status.Destination)
		}}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	fetchRun := func(artifact string) (int, []byte) {
		return fetch(t, ts.Client(), ts.URL+"/v1/assessmentruns/"+string(a.run.UID)+"/"+artifact, "opaque-live-credential")
	}
	if code, _ := fetchRun("download"); code == http.StatusOK {
		t.Fatal("a retained SigningFailed run was downloadable")
	}
	time.Sleep(time.Until(c.Deadline.Time) + time.Second)
	drive(plain, holder, 1)
	wantEnded(holder, v1alpha1.RecoverySigningFailed)
	if st := a.get(holder).Status; !strings.Contains(st.Message, "attempt deadline") {
		t.Fatalf("want the deadline outcome: %s", st.Message)
	}
	want := failed.Status.DeepCopy()
	want.SigningRecovery = nil
	if got := runNow().Status; toJSON(got) != toJSON(want) {
		t.Fatalf("the deadline changed the run beyond releasing the claim:\n%s\n%s", toJSON(want), toJSON(got))
	}
	after := obligationsNow()
	if after.packages != before.packages || after.packages != 1 || !after.latest.Equal(before.latest) || !after.latest.Equal(failed.Status.Publication.ExpiresAt) {
		t.Fatalf("destination accounting changed at the deadline: %d %v -> %d %v", before.packages, before.latest, after.packages, after.latest)
	}
	if st, err := store().Inspect(ctx, ref); err != nil || st.Commit != nil {
		t.Fatalf("a refused commit was made: %+v %v", st.Commit, err)
	}
	l.record("deadline", map[string]any{"request": holder, "outcome": "SigningFailed", "deadline": c.Deadline, "runUnchanged": true,
		"retainedPackages": after.packages, "latestExpiry": after.latest})

	// 9. The key Secret is deleted and the next request takes the claim. It
	// commits the stored signature without reading a signing Secret; the
	// commit response is lost.
	waiting := without(a.waiting, holder)
	next := &SigningRecoveryReconciler{Client: l.c, Reader: l.c, Runtime: currentRuntime()}
	for _, n := range waiting {
		drive(next, n, 1)
	}
	wc := claimOf(runNow())
	if wc == nil || wc.Name == holder || !slices.Contains(waiting, wc.Name) {
		t.Fatalf("no waiting request took the released claim: %s", toJSON(wc))
	}
	w := wc.Name
	if err := l.c.Delete(ctx, secretA); err != nil {
		t.Fatal(err)
	}
	a.faults.set(false, 1)
	rec, reads = recording()
	drive(rec, w, 1)
	if got := keyReads(reads); len(got) != 0 {
		t.Fatalf("the stored-signature path read signing Secrets: %v", got)
	}
	a.dp.Reader = l.c
	if st := a.get(w).Status; st.Phase != v1alpha1.SigningRequestRunning || st.Reason != v1alpha1.RecoveryCommitting || !strings.Contains(st.Message, "lost") {
		t.Fatalf("want the holder retrying after the lost commit response: %s", toJSON(st))
	}
	first, err := store().Inspect(ctx, ref)
	if err != nil || first.Commit == nil {
		t.Fatalf("the commit whose response was lost is not in storage: %+v %v", first, err)
	}

	// 9b. (2.6) The next attempt adopts the commit and records it on the run;
	// the controller stops before the request's own status write.
	publishes := a.faults.count()
	crashing := &SigningRecoveryReconciler{Client: liveStopBeforeSuccess{l.c}, Reader: l.c, Runtime: currentRuntime()}
	if _, err := crashing.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKey{Name: w}}); err == nil || !strings.Contains(err.Error(), "live fault") {
		t.Fatalf("want the stop before the request's success write: %v", err)
	}
	run = runNow()
	sr := run.Status.SigningRecovery
	if sr == nil || sr.Recovered == nil || sr.Recovered.Name != w || sr.Active != nil || run.Status.Phase != v1alpha1.RunCompleted || run.Status.Publication.Commit == nil {
		t.Fatalf("want the run recording the recovery by %s: %s", w, toJSON(run.Status))
	}
	if st := a.get(w).Status; st.Phase.Terminal() {
		t.Fatalf("the request ended before its own status write: %s", toJSON(st))
	}
	recorded := toJSON(sr)
	l.record("stopped-after-run-update", map[string]any{"request": w, "recovered": *sr.Recovered, "requestPhase": a.get(w).Status.Phase})

	// 10. Past the attempt deadline, the registered reconciler (a new
	// manager) repairs the request from the recovered run, and every other
	// request, including one created after the run update, ends
	// AlreadyRecovered; nothing is published again.
	a.newRequestKey("src-late", a.fpA)
	waiting = append(waiting, "src-late")
	time.Sleep(time.Until(wc.Deadline.Time) + time.Second)
	stop := a.startManager()
	l.eventually("the successor repairs every request from the recovered run", func() (bool, string) {
		for _, n := range waiting {
			st := a.get(n).Status
			want := v1alpha1.RecoveryAlreadyRecovered
			if n == w {
				want = v1alpha1.RecoveryRecovered
			}
			if st.Phase != v1alpha1.SigningRequestSucceeded || st.Reason != want {
				return false, n + ": " + toJSON(st)
			}
		}
		return true, ""
	})
	stop()
	if got := a.faults.count(); got != publishes {
		t.Fatalf("the recovery published again (%d -> %d)", publishes, got)
	}
	if got := toJSON(runNow().Status.SigningRecovery); got != recorded {
		t.Fatalf("the recovered record changed: %s -> %s", recorded, got)
	}
	if st := a.get(holder).Status; st.Reason != v1alpha1.RecoverySigningFailed {
		t.Fatalf("the ended holder was rewritten: %s", toJSON(st))
	}

	// One signature version and one commit version, signed under the pinned
	// key, with the recorded retention bounded by the recorded expiry.
	out, err := a.s3.Client.ListObjectVersions(context.Background(), &s3.ListObjectVersionsInput{Bucket: aws.String(a.s3.Dest.Bucket), Prefix: aws.String("konstapel-test/src-dest/")})
	if err != nil {
		t.Fatal(err)
	}
	counts, markers := map[string]int{}, map[string]int{}
	for _, v := range out.Versions {
		if key := aws.ToString(v.Key); strings.Contains(key, string(a.run.UID)) {
			counts[key[strings.LastIndex(key, "/")+1:]]++
		}
	}
	for _, m := range out.DeleteMarkers {
		if key := aws.ToString(m.Key); strings.Contains(key, string(a.run.UID)) {
			markers[key[strings.LastIndex(key, "/")+1:]]++
		}
	}
	if counts[evidencesign.BundleFileName] != 1 || counts["commit.json"] != 1 || markers[evidencesign.BundleFileName]+markers["commit.json"] != 0 {
		t.Fatalf("want one signature and one commit version: %v (delete markers %v)", counts, markers)
	}
	st, err := store().Inspect(ctx, ref)
	if err != nil || st.Commit == nil || st.Signature == nil || st.Signature.KeyFingerprint != a.fpA || !st.PublishedAt.Equal(*first.PublishedAt) {
		t.Fatalf("want the adopted commit signed under %s: %+v %v", a.fpA, st, err)
	}
	retained := failed.Status.Publication
	if r := st.Retention; r == nil || r.Duration != string(failed.Status.Retention) || r.NotAfter == nil || !r.NotAfter.Equal(retained.ExpiresAt.Time) ||
		!st.ExpiresAt.Equal(retained.ExpiresAt.Time) || !st.PublishedAt.After(retained.Failure.At.Time) {
		t.Fatalf("want the recorded retention %s bounded by %s, committed after the failure: %s expires %s published %s", failed.Status.Retention, retained.ExpiresAt, toJSON(st.Retention), st.ExpiresAt, st.PublishedAt)
	}
	bundle, sref, err := store().ReadSignature(ctx, ref)
	if err != nil || string(bundle) != string(stored) || sref.SHA256 != st.Signature.SHA256 {
		t.Fatalf("the committed signature is not the one stored in step 8: %v", err)
	}
	run = runNow()
	pk, err := evidencesign.ParsePublicKey([]byte(run.Status.SigningIntent.Key.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	d, _ := evidencesign.ParseArchiveDigest(st.PackageSHA256)
	if _, err := evidencesign.Verify(bundle, d, pk); err != nil || st.PackageSHA256 != run.Status.SigningIntent.ArchiveSHA256 {
		t.Fatalf("the committed signature does not verify for the intent's archive: %v", err)
	}

	// The run is Completed with the committed publication, Published by w,
	// and its evidence unchanged; the unchanged routes serve the pair.
	pub, committed := run.Status.Publication, publication.ToAPI(st)
	cond := meta.FindStatusCondition(run.Status.Conditions, v1alpha1.ConditionPublished)
	if run.Status.Phase != v1alpha1.RunCompleted || cond == nil || cond.Status != metav1.ConditionTrue || !strings.Contains(cond.Message, w) ||
		pub.PublicationID != committed.PublicationID || toJSON(pub.Commit) != toJSON(committed.Commit) || toJSON(pub.Signature) != toJSON(committed.Signature) ||
		!pub.PublishedAt.Equal(committed.PublishedAt) || !pub.ExpiresAt.Equal(committed.ExpiresAt) || toJSON(pub.Retention) != toJSON(committed.Retention) {
		t.Fatalf("want the run Completed with the committed publication:\n%s\n%s", toJSON(run.Status), toJSON(committed))
	}
	evidence := func(st *v1alpha1.AssessmentRunStatus) string {
		c := st.DeepCopy()
		meta.RemoveStatusCondition(&c.Conditions, v1alpha1.ConditionAttemptsCleaned)
		return evidenceOf(c)
	}
	if evidence(&run.Status) != evidence(&failed.Status) {
		t.Fatalf("recovery changed the run's evidence:\n%s\n%s", evidence(&failed.Status), evidence(&run.Status))
	}
	code, archive := fetchRun("download")
	sigCode, served := fetchRun("signature")
	sum := sha256.Sum256(archive)
	if code != http.StatusOK || sigCode != http.StatusOK || hex.EncodeToString(sum[:]) != run.Status.SigningIntent.ArchiveSHA256 || string(served) != string(stored) {
		t.Fatalf("the recovered pair is not served: archive %d signature %d", code, sigCode)
	}
	if _, err := evidencesign.Verify(served, d, pk); err != nil {
		t.Fatalf("the served signature does not verify under the pinned key: %v", err)
	}
	if o := obligationsNow(); o.packages != 1 || !o.latest.Equal(retained.ExpiresAt) {
		t.Fatalf("the recovered package is not counted once with its expiry: %d %v", o.packages, o.latest)
	}
	l.record("recovered", map[string]any{"request": w, "publicationID": st.PublicationID, "keyFingerprint": st.Signature.KeyFingerprint,
		"publishedAt": st.PublishedAt, "expiresAt": st.ExpiresAt, "retention": *st.Retention, "versions": counts, "publishes": a.faults.count(),
		"secretReadsOnStoredPath": 0, "alreadyRecovered": without(waiting, w), "downloads": []int{code, sigCode}, "at": time.Now().UTC()})
}

// liveStopBeforeSuccess is a live client that fails a request's Succeeded
// status write before it reaches the API server, as a controller stopping
// between the run's and the request's status writes would.
type liveStopBeforeSuccess struct{ client.Client }

func (c liveStopBeforeSuccess) Status() client.SubResourceWriter {
	return liveStopWriter{c.Client.Status()}
}

type liveStopWriter struct{ client.SubResourceWriter }

func (w liveStopWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if esr, ok := obj.(*v1alpha1.EvidenceSigningRequest); ok && esr.Status.Phase == v1alpha1.SigningRequestSucceeded {
		return fmt.Errorf("%w: live fault: the controller stopped before the request's success write", publication.ErrUnavailable)
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}
