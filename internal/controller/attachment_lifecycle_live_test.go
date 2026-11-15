//go:build live

package controller

// Live attachment lifecycle (add-supporting-evidence-attachments 4.1-4.3)
// against the real API server, the in-process manager and the pinned,
// test-owned S3 service (KONSTAPEL_S3_IMAGE), with the production S3 adapter
// acting as the transfer service:
//   - validity moves NotYetValid -> Current -> Expired at its declared
//     boundaries with no object, binding or storage event (the record names
//     no existing binding, so only the controller's own timer can wake it);
//   - reporting-only and exception-setting edits never change a valid
//     association, sampled continuously while the binding re-resolves;
//   - a restart (a new leader) keeps every state; a committed document
//     version removed from storage becomes Unavailable/ObjectMissing while
//     its commitment, validity and association stay as they were;
//   - a withdrawn record leaves new coverage at once, survives a restart
//     retained, is not released before its fixed expiry, and then loses
//     exactly its owned objects (an unrelated object inside its own attempt
//     directory stays);
//   - an unreachable destination (rejected credentials) makes cleanup fail
//     with a bounded backoff while ownership is kept; once access returns,
//     the next attempt removes the owned source and content recovers.
// Run through scripts/targeting-live.sh (acceptance group "storage").

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

func TestLiveAttachmentLifecycle(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	ctx := l.ctx
	const ns = "konstapel-system"
	_ = l.c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	secret := func(name, access, key string) {
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Data: map[string][]byte{"accessKeyID": []byte(access), "secretAccessKey": []byte(key)}}
		if err := l.c.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(context.Background(), s) })
	}
	secret("lc-s3", l.s3Access, l.s3Secret)
	secret("lc-s3-rejected", l.s3Access, "not-the-secret-key-of-the-test-service")
	ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "lc-dest"}, Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{
		Endpoint: l.s3Endpoint, Bucket: pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/lc-dest", DevelopmentFixture: true,
		CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: "lc-s3"}}}}}
	if err := l.c.Create(ctx, ed); err != nil {
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
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: DefaultDestinationConfigMap},
		Data: map[string]string{DefaultDestinationNameKey: ed.Name, DefaultDestinationUIDKey: string(ed.UID)}}
	err := l.c.Create(ctx, cm)
	if apierrors.IsAlreadyExists(err) {
		err = l.c.Update(ctx, cm)
	} else if err == nil {
		t.Cleanup(func() { _ = l.c.Delete(context.Background(), cm) })
	}
	if err != nil {
		t.Fatal(err)
	}
	useSecret := func(name string) {
		t.Helper()
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			cur := &v1alpha1.EvidenceDestination{}
			if err := l.c.Get(ctx, client.ObjectKeyFromObject(ed), cur); err != nil {
				return err
			}
			cur.Spec.S3.CredentialSecret.Name = name
			return l.c.Update(ctx, cur)
		}); err != nil {
			t.Fatal(err)
		}
	}

	// A binding with a valid association; it selects no namespace.
	catalog, err := attachments.ReadBaseline(os.DirFS(root))
	if err != nil {
		t.Fatal(err)
	}
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "lc-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("lc-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "lc-none"})
	var created []string
	t.Cleanup(func() {
		for _, n := range created {
			a := &v1alpha1.EvidenceAttachment{}
			if l.c.Get(context.Background(), client.ObjectKey{Name: n}, a) == nil {
				a.Finalizers = nil
				_ = l.c.Update(context.Background(), a)
				_ = l.c.Delete(context.Background(), a)
			}
		}
		for _, o := range []client.Object{&v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.Name}}, p} {
			_ = l.c.Delete(context.Background(), o)
		}
		l.eventually("lifecycle test policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
	})
	for _, o := range []client.Object{p, b} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	start := func(interval time.Duration) func() {
		ConfigureAssessments(AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: time.Minute, Workers: 1,
			ControllerNamespace: ns, Destinations: &DestinationPublishers{Reader: l.c, Namespace: ns}, IntegrityInterval: interval})
		return l.startManager()
	}
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	// First process: content is re-checked only daily, so nothing but the
	// validity timer wakes a settled record.
	stop := start(24 * time.Hour)
	defer func() { stop() }()
	l.eventually("destination ready", func() (bool, string) {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(ctx, client.ObjectKeyFromObject(ed), got)
		return meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionDestinationReady), toJSON(got.Status)
	})
	var bindingUID string
	l.eventually("binding resolved", func() (bool, string) {
		cur := l.binding(b.Name)
		bindingUID = string(cur.UID)
		return cur.Status.Profile != nil && meta.IsStatusConditionTrue(cur.Status.Conditions, v1alpha1.ConditionResolved), toJSON(cur.Status)
	})
	ks := &corev1.Namespace{}
	if err := l.c.Get(ctx, client.ObjectKey{Name: "kube-system"}, ks); err != nil {
		t.Fatal(err)
	}
	cluster := "kube-system:" + string(ks.UID)

	get := func(name string) *v1alpha1.EvidenceAttachment {
		a := &v1alpha1.EvidenceAttachment{}
		if err := l.c.Get(ctx, client.ObjectKey{Name: name}, a); err != nil {
			return nil
		}
		return a
	}
	store := func() *s3store.AttachmentStore {
		cur := &v1alpha1.EvidenceDestination{}
		if err := l.c.Get(ctx, client.ObjectKeyFromObject(ed), cur); err != nil {
			t.Fatal(err)
		}
		d, err := DestinationFromAPI(ctx, l.c, ns, cur)
		if err != nil {
			t.Fatal(err)
		}
		c, err := s3store.NewClient(ctx, d, &s3store.StaticCredentials{AccessKeyID: l.s3Access, SecretAccessKey: l.s3Secret})
		if err != nil {
			t.Fatal(err)
		}
		return &s3store.AttachmentStore{Client: c, Dest: d}
	}
	ref := func(a *v1alpha1.EvidenceAttachment) attachments.Ref {
		return attachments.Ref{ClusterID: cluster, UID: string(a.UID)}
	}
	// register creates a record and, acting as the transfer service, commits
	// its document through the production adapter once it is pinned.
	register := func(name, binding, bindingUID string, from, until time.Time, retention time.Duration) (*v1alpha1.EvidenceAttachment, attachments.Receipt) {
		t.Helper()
		body := []byte("%PDF-1.7 " + name + " DC North physical access audit")
		sum := sha256.Sum256(body)
		a := &v1alpha1.EvidenceAttachment{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.EvidenceAttachmentSpec{
			Document: v1alpha1.AttachmentDocument{Title: name, MediaType: "application/pdf", Size: int64(len(body)), SHA256: "sha256:" + hex.EncodeToString(sum[:])},
			Source:   v1alpha1.AttachmentSource{Issuer: "Example Audit AB"},
			Validity: v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(from), ValidUntil: metav1.NewTime(until)},
			Associations: []v1alpha1.AttachmentAssociation{{Binding: v1alpha1.ExactBindingReference{Name: binding, UID: bindingUID},
				CatalogDigest: catalog.CatalogDigest, Controls: []v1alpha1.AttachmentControl{{ID: "pe-3"}}}},
			Scope:        v1alpha1.AttachmentScope{Description: "DC North"},
			RegisteredBy: &v1alpha1.Requester{Username: "platform-registrar"}}}
		if err := l.c.Create(ctx, a); err != nil {
			t.Fatal(err)
		}
		created = append(created, name)
		l.eventually(name+" pinned", func() (bool, string) {
			a = get(name)
			return a != nil && a.Status.Storage != nil && a.Status.Storage.Destination != nil, toJSON(a)
		})
		st := store()
		if _, err := st.Stage(ctx, attachments.StageRequest{Ref: ref(a), Document: attachments.Expected(a.Spec),
			Uploader: attachments.Principal{Username: "platform-uploader"}, Body: bytes.NewReader(body)}); err != nil {
			t.Fatal(err)
		}
		r, err := st.Commit(ctx, attachments.CommitRequest{Ref: ref(a), SpecDigest: attachments.SpecDigest(a.Spec), Document: attachments.Expected(a.Spec),
			ValidUntil: until.UTC(), Retention: retention})
		if err != nil {
			t.Fatal(err)
		}
		// The transfer service's commit is not an API event; a label change
		// makes the controller read it now rather than at its next poll.
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			cur := get(name)
			if cur.Labels == nil {
				cur.Labels = map[string]string{}
			}
			cur.Labels["lifecycle.konstapel.dev/uploaded"] = "true"
			return l.c.Update(ctx, cur)
		}); err != nil {
			t.Fatal(err)
		}
		l.eventually(name+" committed and available", func() (bool, string) {
			a = get(name)
			return a.Status.Storage.Commitment != nil && a.Status.Content != nil && a.Status.Content.State == v1alpha1.ContentAvailable, toJSON(a.Status)
		})
		return a, r
	}
	// watch polls a record quickly until done, returning the first instant
	// done held.
	watch := func(what string, limit time.Duration, done func(*v1alpha1.EvidenceAttachment) bool) time.Time {
		t.Helper()
		deadline := time.Now().Add(limit)
		var last *v1alpha1.EvidenceAttachment
		for time.Now().Before(deadline) {
			if last = get(what); last != nil && done(last) {
				return time.Now()
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s: %s", what, toJSON(last))
		return time.Time{}
	}
	state := func(a *v1alpha1.EvidenceAttachment) v1alpha1.TemporalState {
		if a.Status.Validity == nil {
			return ""
		}
		return a.Status.Validity.State
	}

	// 4.1: no-event expiry. The record names a binding that doesn't exist
	// (Mismatched, never polled) and its content is checked daily, so only
	// the controller's validity timer can wake it.
	now := time.Now().UTC().Truncate(time.Second)
	from, until := now.Add(30*time.Second), now.Add(50*time.Second)
	timer, _ := register("lc-timer", "lc-absent", "absent-uid", from, until, attachments.DefaultRetention)
	if s := state(timer); s != v1alpha1.TemporalNotYetValid || timer.Status.Validity.NextTransition == nil || !timer.Status.Validity.NextTransition.Time.Equal(from) {
		t.Fatalf("before validFrom: %s", toJSON(timer.Status.Validity))
	}
	if c := meta.FindStatusCondition(timer.Status.Conditions, v1alpha1.ConditionAssociationsValid); c == nil || c.Status != metav1.ConditionFalse {
		t.Fatalf("the timer record's association: %s", toJSON(timer.Status))
	}
	const slack = 15 * time.Second
	current := watch("lc-timer", time.Until(from)+slack+5*time.Second, func(a *v1alpha1.EvidenceAttachment) bool { return state(a) == v1alpha1.TemporalCurrent })
	if current.Before(from) || current.After(from.Add(slack)) {
		t.Fatalf("became Current at %s, validFrom %s", current.Format(time.RFC3339Nano), from)
	}
	expired := watch("lc-timer", time.Until(until)+slack+5*time.Second, func(a *v1alpha1.EvidenceAttachment) bool { return state(a) == v1alpha1.TemporalExpired })
	if expired.Before(until) || expired.After(until.Add(slack)) {
		t.Fatalf("became Expired at %s, validUntil %s", expired.Format(time.RFC3339Nano), until)
	}
	if a := get("lc-timer"); a.Status.Validity.NextTransition != nil || a.Status.Content.State != v1alpha1.ContentAvailable ||
		!meta.IsStatusConditionTrue(a.Status.Conditions, v1alpha1.ConditionDocumentCommitted) {
		t.Fatalf("expiry changed another state: %s", toJSON(a.Status))
	}
	l.record("noEventExpiry", map[string]any{"validFrom": from, "current": current, "validUntil": until, "expired": expired})

	// 4.1: policy-preserving edits never change a valid association, even
	// while the binding re-resolves.
	dc, _ := register("lc-dc", b.Name, bindingUID, now.Add(-24*time.Hour), now.Add(365*24*time.Hour), attachments.DefaultRetention)
	l.eventually("lc-dc association valid", func() (bool, string) {
		dc = get("lc-dc")
		return meta.IsStatusConditionTrue(dc.Status.Conditions, v1alpha1.ConditionAssociationsValid), toJSON(dc.Status)
	})
	seen := map[string]int{}
	sample := func(until func() bool) {
		for deadline := time.Now().Add(3 * time.Minute); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			a := get("lc-dc")
			s := a.Status.Associations[0]
			seen[string(s.State)+"/"+s.Reason]++
			if until() {
				return
			}
		}
		t.Fatal("timed out sampling the association")
	}
	edit := func(o client.Object, change func()) {
		t.Helper()
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			if err := l.c.Get(ctx, client.ObjectKeyFromObject(o), o); err != nil {
				return err
			}
			change()
			return l.c.Update(ctx, o)
		}); err != nil {
			t.Fatal(err)
		}
	}
	bb := &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.Name}}
	edit(bb, func() { bb.Spec.Assessment = &v1alpha1.BindingAssessment{} })
	sample(func() bool { cur := l.binding(b.Name); return cur.Status.ObservedGeneration == cur.Generation })
	pp := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: p.Name}}
	edit(pp, func() {
		pp.Spec.Policies[0].Exceptions = v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: time.Hour}}
	})
	sample(func() bool {
		cur, prof := l.binding(b.Name), &v1alpha1.ComplianceProfile{}
		_ = l.c.Get(ctx, client.ObjectKey{Name: p.Name}, prof)
		return cur.Status.Profile != nil && cur.Status.Profile.Generation == prof.Generation
	})
	if len(seen) != 1 || seen["Valid/Valid"] == 0 {
		t.Fatalf("the association changed across policy-preserving edits: %v", seen)
	}
	l.record("edits", map[string]any{"samples": seen, "edits": []string{"binding spec.assessment", "profile exception settings"}})

	// 4.2: a restart (a new leader) keeps every state; then a committed
	// version removed from storage is Unavailable while its commitment,
	// validity and association stay.
	stop()
	stop = start(3 * time.Second)
	dcBefore := get("lc-dc")
	time.Sleep(5 * time.Second)
	if a := get("lc-dc"); state(a) != state(dcBefore) || a.Status.Content.State != v1alpha1.ContentAvailable || a.Status.Withdrawal != nil ||
		!meta.IsStatusConditionTrue(a.Status.Conditions, v1alpha1.ConditionAssociationsValid) {
		t.Fatalf("after a restart: %s", toJSON(a.Status))
	}
	commitment := dcBefore.Status.Storage.Commitment.DeepCopy()
	del := &s3.DeleteObjectInput{Bucket: aws.String(pub.Dest.Bucket), Key: aws.String(commitment.DocumentKey)}
	if commitment.DocumentVersionID != "" {
		del.VersionId = aws.String(commitment.DocumentVersionID)
	}
	if _, err := store().Client.DeleteObject(ctx, del); err != nil {
		t.Fatal(err)
	}
	l.eventually("removed bytes unavailable", func() (bool, string) {
		a := get("lc-dc")
		return a.Status.Content.State == v1alpha1.ContentUnavailable && a.Status.Content.Reason == v1alpha1.ReasonContentMissing, toJSON(a.Status.Content)
	})
	if a := get("lc-dc"); *a.Status.Storage.Commitment != *commitment || !meta.IsStatusConditionTrue(a.Status.Conditions, v1alpha1.ConditionDocumentCommitted) ||
		state(a) != v1alpha1.TemporalCurrent || !meta.IsStatusConditionTrue(a.Status.Conditions, v1alpha1.ConditionAssociationsValid) {
		t.Fatalf("unavailable bytes changed another state: %s", toJSON(a.Status))
	}
	l.record("unavailableBytes", map[string]any{"content": get("lc-dc").Status.Content})

	// 4.2: withdrawal leaves new coverage at once and keeps the source,
	// across a restart, until the fixed expiry; then exactly the owned
	// objects go.
	const retention = 45 * time.Second
	kept, rKept := register("lc-retained", b.Name, bindingUID, now.Add(-48*time.Hour), now.Add(-24*time.Hour), retention)
	st := store()
	prefix := s3store.AttachmentPrefix(st.Dest, ref(kept))
	unrelated := rKept.DocumentKey[:strings.LastIndex(rKept.DocumentKey, "/")+1] + "operator-notes.txt"
	if _, err := st.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(st.Dest.Bucket), Key: aws.String(unrelated), Body: strings.NewReader("keep")}); err != nil {
		t.Fatal(err)
	}
	if err := l.c.Delete(ctx, kept); err != nil {
		t.Fatal(err)
	}
	l.eventually("withdrawal recorded", func() (bool, string) {
		a := get("lc-retained")
		return a != nil && a.Status.Withdrawal != nil && a.Status.Storage.Cleanup != nil && a.Status.Storage.Cleanup.State == "NotDue" &&
			meta.FindStatusCondition(a.Status.Conditions, v1alpha1.ConditionSourceRetained) != nil, toJSON(a)
	})
	var list v1alpha1.EvidenceAttachmentList
	if err := l.c.List(ctx, &list); err != nil {
		t.Fatal(err)
	}
	var selected []string
	for _, o := range attachments.ForBinding(list.Items, bindingUID, time.Now()) {
		selected = append(selected, o.Name)
	}
	if len(selected) != 1 || selected[0] != "lc-dc" {
		t.Fatalf("new coverage selects %v, want only lc-dc", selected)
	}
	stop()
	stop = start(3 * time.Second)
	if time.Now().Before(rKept.ExpiresAt.Add(-3 * time.Second)) {
		time.Sleep(2 * time.Second)
		if a := get("lc-retained"); a == nil || a.Status.Withdrawal == nil || a.Status.Storage.Commitment == nil {
			t.Fatalf("a restart lost the retained record: %s", toJSON(a))
		}
	}
	keys := func(p string) []string {
		out, err := st.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(st.Dest.Bucket), Prefix: aws.String(p)})
		if err != nil {
			t.Fatal(err)
		}
		var k []string
		for _, o := range out.Contents {
			k = append(k, aws.ToString(o.Key))
		}
		return k
	}
	l.eventually("withdrawn source removed at its expiry", func() (bool, string) { a := get("lc-retained"); return a == nil, toJSON(a) })
	if time.Now().Before(rKept.ExpiresAt) {
		t.Fatalf("released before the fixed expiry %s", rKept.ExpiresAt)
	}
	if k := keys(prefix); len(k) != 1 || k[0] != unrelated {
		t.Fatalf("after cleanup: %v, want only %s", k, unrelated)
	}
	if _, err := st.Committed(ctx, ref(kept)); !errors.Is(err, attachments.ErrNotFound) {
		t.Fatalf("commitment remains: %v", err)
	}
	l.record("withdrawal", map[string]any{"selected": selected, "expiresAt": rKept.ExpiresAt, "kept": unrelated})

	// 4.3: storage rejects the controller's credentials while cleanup is
	// due: the attempt fails, ownership is kept, the next attempt waits for
	// its backoff, and it succeeds once access returns.
	blocked, rBlocked := register("lc-blocked", b.Name, bindingUID, now.Add(-48*time.Hour), now.Add(-24*time.Hour), 20*time.Second)
	blockedPrefix := s3store.AttachmentPrefix(st.Dest, ref(blocked))
	useSecret("lc-s3-rejected")
	if err := l.c.Delete(ctx, blocked); err != nil {
		t.Fatal(err)
	}
	var failed *v1alpha1.AttachmentCleanup
	l.eventually("cleanup refused", func() (bool, string) {
		a := get("lc-blocked")
		if a == nil {
			return false, "released while storage rejects the controller"
		}
		failed = a.Status.Storage.Cleanup
		return failed != nil && failed.Attempts >= 1 && failed.LastAttempt != nil && a.Status.Storage.Commitment != nil && a.Status.Withdrawal != nil &&
			(failed.State == string(attachments.CleanupDeletionFailed) || failed.State == string(attachments.CleanupRetentionBlocked)), toJSON(a.Status)
	})
	if time.Now().Before(rBlocked.ExpiresAt) {
		t.Fatalf("cleanup attempted before the expiry %s", rBlocked.ExpiresAt)
	}
	l.eventually("unreachable content reported", func() (bool, string) {
		a := get("lc-timer")
		return a.Status.Content.State == v1alpha1.ContentUnavailable && a.Status.Content.Reason == v1alpha1.ReasonStorageUnavailable, toJSON(a.Status.Content)
	})
	// No retry before the one-minute backoff.
	time.Sleep(20 * time.Second)
	if a := get("lc-blocked"); a == nil || a.Status.Storage.Cleanup.Attempts > failed.Attempts && a.Status.Storage.Cleanup.LastAttempt.Time.Before(failed.LastAttempt.Add(time.Minute)) {
		t.Fatalf("retried before its backoff: %s, first %s", toJSON(a), toJSON(failed))
	}
	destination := &v1alpha1.EvidenceDestination{}
	if err := l.c.Get(ctx, client.ObjectKeyFromObject(ed), destination); err != nil || !controllerutil.ContainsFinalizer(destination, DestinationFinalizer) {
		t.Fatalf("destination released while cleanup is refused: %v", err)
	}
	if k := keys(blockedPrefix); len(k) == 0 {
		t.Fatal("owned objects vanished while deletion was refused")
	}
	useSecret("lc-s3")
	l.eventually("refused cleanup recovered", func() (bool, string) { a := get("lc-blocked"); return a == nil, toJSON(a) })
	if k := keys(blockedPrefix); len(k) != 0 {
		t.Fatalf("after the recovered cleanup: %v", k)
	}
	l.eventually("content recovered", func() (bool, string) {
		a := get("lc-timer")
		return a.Status.Content.State == v1alpha1.ContentAvailable, toJSON(a.Status.Content)
	})
	l.record("cleanupFailure", map[string]any{"failed": failed, "recovered": true})
}
