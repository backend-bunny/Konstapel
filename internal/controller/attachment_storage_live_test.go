//go:build live

package controller

// Live attachment storage (add-supporting-evidence-attachments 2.1-2.4)
// against the real API server and the pinned, test-owned S3 service
// (KONSTAPEL_S3_IMAGE). The test acts as the transfer service with the
// production S3 adapter (s3store.AttachmentStore); the in-process manager
// pins destinations, records commitments and gates the retention finalizer:
//   - the controller pins the central default destination once, protects it
//     with the destination finalizer, and never relocates it when the
//     default changes;
//   - mismatching bytes are never stored; concurrent writers on separate
//     clients converge on one commitment, one of them losing its commit
//     response; a retry with another retention returns the first commitment;
//   - the controller records the commitment read from storage;
//   - credential rotation (a new Secret) keeps the pinned destination usable;
//   - abandoned attempts and multipart uploads are cleaned, unrelated objects
//     under the same prefix are not;
//   - withdrawal keeps a committed source until its fixed expiry, then
//     removes every owned version and releases the record; a withdrawn,
//     uncommitted record is released after its attempts are removed.
// Run through scripts/targeting-live.sh (acceptance group "storage").

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

// loseCommitResponse forwards the first commit-manifest PUT and then reports
// a transport error, as if the response were lost after the write landed.
type loseCommitResponse struct {
	inner s3.HTTPClient
	lost  atomic.Int32
}

func (l *loseCommitResponse) Do(r *http.Request) (*http.Response, error) {
	resp, err := l.inner.Do(r)
	if err == nil && r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/commit.json") && l.lost.Add(1) == 1 {
		resp.Body.Close()
		return nil, errors.New("connection reset by peer (test: commit response lost)")
	}
	return resp, err
}

func TestLiveAttachmentStorage(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	const ns = "konstapel-system"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	ctx := l.ctx
	secret := func(name string) *corev1.Secret {
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
		if err := l.c.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(context.Background(), s) })
		return s
	}
	secret("att-s3")
	newDest := func(name string) *v1alpha1.EvidenceDestination {
		ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{
			Endpoint: l.s3Endpoint, Bucket: pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/" + name, DevelopmentFixture: true,
			CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: "att-s3"}}}}}
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
		return ed
	}
	primary, secondary := newDest("att-primary"), newDest("att-secondary")
	setDefault := func(ed *v1alpha1.EvidenceDestination) {
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
	}
	setDefault(primary)
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
	})
	ConfigureAssessments(AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: time.Minute, Workers: 1,
		ControllerNamespace: ns, Destinations: &DestinationPublishers{Reader: l.c, Namespace: ns}})
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	stop := l.startManager()
	defer func() { stop() }()
	for _, ed := range []*v1alpha1.EvidenceDestination{primary, secondary} {
		l.eventually(ed.Name+" ready", func() (bool, string) {
			got := &v1alpha1.EvidenceDestination{}
			_ = l.c.Get(ctx, client.ObjectKeyFromObject(ed), got)
			return meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionDestinationReady), toJSON(got.Status)
		})
	}
	ks := &corev1.Namespace{}
	if err := l.c.Get(ctx, client.ObjectKey{Name: "kube-system"}, ks); err != nil {
		t.Fatal(err)
	}
	cluster := "kube-system:" + string(ks.UID)

	register := func(name string, body []byte, validUntil time.Time) *v1alpha1.EvidenceAttachment {
		sum := sha256.Sum256(body)
		a := &v1alpha1.EvidenceAttachment{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.EvidenceAttachmentSpec{
			Document: v1alpha1.AttachmentDocument{Title: name, MediaType: "application/pdf", Size: int64(len(body)), SHA256: "sha256:" + hex.EncodeToString(sum[:])},
			Source:   v1alpha1.AttachmentSource{Issuer: "Example Audit AB"},
			Validity: v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(validUntil.Add(-365 * 24 * time.Hour)), ValidUntil: metav1.NewTime(validUntil)},
			Associations: []v1alpha1.AttachmentAssociation{{Binding: v1alpha1.ExactBindingReference{Name: "att-none", UID: "none"},
				CatalogDigest: "sha256:" + strings.Repeat("0", 64), Controls: []v1alpha1.AttachmentControl{{ID: "pe-3"}}}},
			Scope:        v1alpha1.AttachmentScope{Description: "DC North"},
			RegisteredBy: &v1alpha1.Requester{Username: "platform-registrar"},
		}}
		if err := l.c.Create(ctx, a); err != nil {
			t.Fatal(err)
		}
		created = append(created, name)
		return a
	}
	get := func(name string) *v1alpha1.EvidenceAttachment {
		a := &v1alpha1.EvidenceAttachment{}
		if err := l.c.Get(ctx, client.ObjectKey{Name: name}, a); err != nil {
			return nil
		}
		return a
	}
	pinned := func(name string, ed *v1alpha1.EvidenceDestination) *v1alpha1.EvidenceAttachment {
		var a *v1alpha1.EvidenceAttachment
		l.eventually(name+" pinned to "+ed.Name, func() (bool, string) {
			a = get(name)
			return a != nil && a.Status.Storage != nil && a.Status.Storage.Destination != nil && a.Status.Storage.Destination.UID == string(ed.UID) &&
				a.Labels[v1alpha1.LabelAttachmentDestination] == string(ed.UID), toJSON(a)
		})
		return a
	}
	// The transfer service's view: the production adapter for the pinned
	// destination, built from the EvidenceDestination as the controller does.
	storeFor := func(ed *v1alpha1.EvidenceDestination, wrap func(s3.HTTPClient) s3.HTTPClient) *s3store.AttachmentStore {
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
		if wrap != nil {
			c = s3.New(c.Options(), func(o *s3.Options) { o.HTTPClient = wrap(o.HTTPClient) })
		}
		return &s3store.AttachmentStore{Client: c, Dest: d}
	}
	ref := func(a *v1alpha1.EvidenceAttachment) attachments.Ref {
		return attachments.Ref{ClusterID: cluster, UID: string(a.UID)}
	}
	request := func(a *v1alpha1.EvidenceAttachment, retention time.Duration) attachments.CommitRequest {
		return attachments.CommitRequest{Ref: ref(a), SpecDigest: attachments.SpecDigest(a.Spec), Document: attachments.Expected(a.Spec),
			ValidUntil: a.Spec.Validity.ValidUntil.UTC(), Retention: retention}
	}
	uploader := attachments.Principal{Username: "platform-uploader", UID: "uid-uploader"}

	// An already expired annual document: its source expiry is the
	// commitment time plus the retention tail.
	bodyA := []byte("%PDF-1.7 DC North physical access audit 2020")
	A := pinned(register("att-a", bodyA, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)).Name, primary)
	ed := &v1alpha1.EvidenceDestination{}
	_ = l.c.Get(ctx, client.ObjectKeyFromObject(primary), ed)
	if !controllerutil.ContainsFinalizer(ed, DestinationFinalizer) {
		t.Fatal("pinned destination is not protected by its finalizer")
	}
	store := storeFor(primary, nil)
	if _, err := store.Stage(ctx, attachments.StageRequest{Ref: ref(A), Document: attachments.Expected(A.Spec), Uploader: uploader,
		Body: bytes.NewReader([]byte("%PDF-1.7 a forged replacement document!!!!"))}); !errors.Is(err, attachments.ErrIntegrity) {
		t.Fatalf("mismatching bytes: %v", err)
	}
	// Concurrent writers on separate clients; one loses its commit response.
	const retention = 20 * time.Second
	receipts := make([]attachments.Receipt, 3)
	errs := make([]error, 3)
	var wg sync.WaitGroup
	for i := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var w func(s3.HTTPClient) s3.HTTPClient
			if i == 0 {
				w = func(c s3.HTTPClient) s3.HTTPClient { return &loseCommitResponse{inner: c} }
			}
			st := storeFor(primary, w)
			if _, err := st.Stage(ctx, attachments.StageRequest{Ref: ref(A), Document: attachments.Expected(A.Spec), Uploader: uploader, Body: bytes.NewReader(bodyA)}); err != nil {
				errs[i] = err
				return
			}
			receipts[i], errs[i] = st.Commit(ctx, request(A, retention))
		}()
	}
	wg.Wait()
	for i := range 3 {
		if errs[i] != nil || receipts[i] != receipts[0] {
			t.Fatalf("writer %d: %+v %v (writer 0: %+v)", i, receipts[i], errs[i], receipts[0])
		}
	}
	rA := receipts[0]
	if !rA.ExpiresAt.Equal(rA.CommittedAt.Add(retention)) {
		t.Fatalf("expiry %s for commitment %s", rA.ExpiresAt, rA.CommittedAt)
	}
	if again, err := storeFor(primary, nil).Commit(ctx, request(A, attachments.DefaultRetention)); err != nil || again != rA {
		t.Fatalf("retry with a changed retention: %+v %v", again, err)
	}
	l.record("commit", map[string]any{"receipt": rA, "mismatch": "ErrIntegrity", "writers": 3, "lostResponse": true})

	l.eventually("commitment recorded", func() (bool, string) {
		a := get(A.Name)
		c := a.Status.Storage.Commitment
		return c != nil && c.SHA256 == rA.Document.SHA256 && c.CommittedAt.Time.Equal(rA.CommittedAt) && c.ExpiresAt.Time.Equal(rA.ExpiresAt) &&
			c.Uploader.Username == uploader.Username && meta.IsStatusConditionTrue(a.Status.Conditions, v1alpha1.ConditionDocumentCommitted), toJSON(a.Status)
	})

	// Owned cleanup: the losers' attempts and an abandoned multipart upload
	// go; an unrelated object under the same prefix stays.
	prefix := s3store.AttachmentPrefix(store.Dest, ref(A))
	unrelated := prefix + "operator-notes.txt"
	if _, err := store.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(store.Dest.Bucket), Key: aws.String(unrelated), Body: strings.NewReader("keep")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String(store.Dest.Bucket), Key: aws.String(prefix + "attempts/abandoned/document")}); err != nil {
		t.Fatal(err)
	}
	if err := store.CleanupAttempts(ctx, ref(A), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	list := func(p string) []string {
		out, err := store.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(store.Dest.Bucket), Prefix: aws.String(p)})
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, o := range out.Contents {
			keys = append(keys, aws.ToString(o.Key))
		}
		return keys
	}
	attempts := map[string]bool{}
	for _, k := range list(prefix + "attempts/") {
		attempts[filepath.Dir(k)] = true
	}
	if len(attempts) != 1 || !attempts[filepath.Dir(rA.DocumentKey)] {
		t.Fatalf("attempts after cleanup: %v", attempts)
	}
	ups, err := store.Client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(store.Dest.Bucket), Prefix: aws.String(prefix)})
	if err != nil || len(ups.Uploads) != 0 {
		t.Fatalf("multipart uploads remain: %v %v", ups, err)
	}

	// Credential rotation: a new Secret; the old one is removed.
	secret("att-s3-rotated")
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cur := &v1alpha1.EvidenceDestination{}
		if err := l.c.Get(ctx, client.ObjectKeyFromObject(primary), cur); err != nil {
			return err
		}
		cur.Spec.S3.CredentialSecret.Name = "att-s3-rotated"
		return l.c.Update(ctx, cur)
	}); err != nil {
		t.Fatal(err)
	}
	_ = l.c.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "att-s3"}})
	bodyB := []byte("%PDF-1.7 DC North audit 2026, long retention")
	B := pinned(register("att-b", bodyB, time.Now().Add(365*24*time.Hour).UTC().Truncate(time.Second)).Name, primary)
	if _, err := store.Stage(ctx, attachments.StageRequest{Ref: ref(B), Document: attachments.Expected(B.Spec), Uploader: uploader, Body: bytes.NewReader(bodyB)}); err != nil {
		t.Fatal(err)
	}
	rB, err := store.Commit(ctx, request(B, attachments.DefaultRetention))
	if err != nil {
		t.Fatal(err)
	}
	if !rB.ExpiresAt.Equal(B.Spec.Validity.ValidUntil.UTC().Add(attachments.DefaultRetention)) {
		t.Fatalf("annual document expiry %s", rB.ExpiresAt)
	}
	l.eventually("commitment recorded after credential rotation", func() (bool, string) {
		a := get(B.Name)
		return a.Status.Storage.Commitment != nil && a.Status.Storage.Commitment.SpecDigest == rB.SpecDigest, toJSON(a.Status)
	})

	// A changed default never relocates existing documents.
	setDefault(secondary)
	C := pinned(register("att-c", []byte("staged, never committed"), time.Now().Add(time.Hour).UTC().Truncate(time.Second)).Name, secondary)
	if a := get(A.Name); a.Status.Storage.Destination.UID != string(primary.UID) {
		t.Fatal("an existing pin moved to the new default")
	}
	storeC := storeFor(secondary, nil)
	if _, err := storeC.Stage(ctx, attachments.StageRequest{Ref: ref(C), Document: attachments.Expected(C.Spec), Uploader: uploader,
		Body: bytes.NewReader([]byte("staged, never committed"))}); err != nil {
		t.Fatal(err)
	}
	l.record("pins", map[string]any{"a": primary.UID, "b": primary.UID, "c": secondary.UID, "rotatedSecret": "att-s3-rotated"})

	// Withdrawal: C (uncommitted) is released after its attempt is removed.
	if err := l.c.Delete(ctx, get(C.Name)); err != nil {
		t.Fatal(err)
	}
	l.eventually("uncommitted record released", func() (bool, string) { return get(C.Name) == nil, toJSON(get(C.Name)) })
	if keys := list(s3store.AttachmentPrefix(storeC.Dest, ref(C))); len(keys) != 0 {
		t.Fatalf("withdrawn attempt objects remain: %v", keys)
	}
	// A is retained until its fixed expiry, then every owned version goes.
	if err := l.c.Delete(ctx, get(A.Name)); err != nil {
		t.Fatal(err)
	}
	if time.Now().Before(rA.ExpiresAt.Add(-3 * time.Second)) {
		l.eventually("withdrawn source retained", func() (bool, string) {
			a := get(A.Name)
			if a == nil {
				return false, "released before expiry"
			}
			c := meta.FindStatusCondition(a.Status.Conditions, v1alpha1.ConditionSourceRetained)
			return c != nil && c.Reason == v1alpha1.ReasonRetentionActive, toJSON(a.Status)
		})
		if get(A.Name) == nil || time.Now().After(rA.ExpiresAt) {
			t.Log("expiry passed while checking retention")
		}
	}
	l.eventually("expired source deleted and record released", func() (bool, string) { return get(A.Name) == nil, toJSON(get(A.Name)) })
	if time.Now().Before(rA.ExpiresAt) {
		t.Fatal("released before the fixed expiry")
	}
	if keys := list(prefix); len(keys) != 1 || keys[0] != unrelated {
		t.Fatalf("after cleanup: %v", keys)
	}
	if _, err := store.Committed(ctx, ref(A)); !errors.Is(err, attachments.ErrNotFound) {
		t.Fatalf("commitment remains: %v", err)
	}
	// B (valid for a year) stays retained after withdrawal.
	if err := l.c.Delete(ctx, get(B.Name)); err != nil {
		t.Fatal(err)
	}
	l.eventually("annual source retained after withdrawal", func() (bool, string) {
		a := get(B.Name)
		return a != nil && a.Status.Storage.Cleanup != nil && a.Status.Storage.Cleanup.State == "NotDue", toJSON(a)
	})
	if _, err := store.Committed(ctx, ref(B)); err != nil {
		t.Fatalf("withdrawal removed a retained source: %v", err)
	}
	l.eventually("destination counts the retained document", func() (bool, string) {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(ctx, client.ObjectKeyFromObject(primary), got)
		return got.Status.OutstandingPackages >= 1 && got.Status.LatestRetainedExpiry != nil && got.Status.LatestRetainedExpiry.Time.Equal(rB.ExpiresAt), toJSON(got.Status)
	})
	l.record("withdrawal", map[string]any{"uncommitted": "released, attempts removed", "expired": "deleted after " + rA.ExpiresAt.Format(time.RFC3339),
		"annual": "retained until " + rB.ExpiresAt.Format(time.RFC3339), "unrelated": unrelated})
}
