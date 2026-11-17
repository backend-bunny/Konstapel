//go:build live

package controller

// Integrated supporting-evidence recovery (add-supporting-evidence-
// attachments 7.3) against the real API server, the cluster's own
// TokenReview and SubjectAccessReview, and the pinned RustFS fixture. The
// documents' destination is an object-lock bucket reached through the
// test-owned fault proxy (internal/s3fault); packages go to their own
// destination. Transfer-service replicas run in-process as the shipped
// download role; controllers are leader-elected candidates, each with its
// own staging directory, as separate pods would have:
//   - replica loss: a replica lost after staging, before its commit, leaves
//     an owned, uncommitted attempt and no document; a replica lost after
//     its commit landed loses the commit response. The caller's retry on
//     another replica commits once, or is answered with the original
//     commitment and uploader; a replica with another retention setting
//     changes neither. An interrupted upload stores nothing;
//   - a platform run reports truthfully what it could not include: a
//     pending upload, and a document whose storage refuses reads during the
//     whole collection window (NotRetrieved), whose source download is
//     unavailable meanwhile. A document withdrawn during the capture keeps
//     its verified copy, marked withdrawn;
//   - leader loss before durable staging fails the run as capture loss with
//     nothing stored; leader loss after durable staging is recovered by the
//     next leader, which commits the staged bytes unchanged even though a
//     document was withdrawn meanwhile;
//   - a legal hold denies a withdrawn document's source cleanup at its
//     expiry: ownership, the commitment and the destination stay, the source
//     is no longer served, and the package's copy stays readable. Once the
//     hold is lifted, the next attempt removes every owned version, and the
//     package is still valid.
// Run through scripts/targeting-live.sh (acceptance group "recovery").

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
	"github.com/backend-bunny/Konstapel/internal/coverage"
	"github.com/backend-bunny/Konstapel/internal/download"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3fault"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// replicaFate loses a transfer-service replica at its conditional commit,
// as a pod lost mid-upload: before the commit manifest is sent (landed
// false), or after the storage service stored it (landed true), so its
// response never reaches the caller. Once lost, the replica sends nothing.
type replicaFate struct {
	landed  bool
	reached chan struct{}
	dead    chan struct{}
	once    sync.Once
	kills   sync.Once
	// status is the storage service's answer to a landed commit.
	status atomic.Int32
}

func newReplicaFate(landed bool) *replicaFate {
	return &replicaFate{landed: landed, reached: make(chan struct{}), dead: make(chan struct{})}
}

func (f *replicaFate) kill() { f.kills.Do(func() { close(f.dead) }) }

// replicaTransport is the fated replica's S3 transport.
type replicaTransport struct {
	inner s3.HTTPClient
	fate  *replicaFate
}

func (r replicaTransport) Do(req *http.Request) (*http.Response, error) {
	f := r.fate
	select {
	case <-f.dead:
		return nil, errors.New("test: the replica is gone")
	default:
	}
	if req.Method == http.MethodPut && req.Header.Get("If-None-Match") == "*" && strings.HasSuffix(req.URL.Path, "/commit.json") {
		if f.landed {
			resp, err := r.inner.Do(req)
			if err == nil {
				f.status.Store(int32(resp.StatusCode))
				resp.Body.Close()
			}
		}
		f.once.Do(func() { close(f.reached) })
		select {
		case <-f.dead:
		case <-req.Context().Done():
		}
		return nil, errors.New("test: the replica was lost at its commit")
	}
	return r.inner.Do(req)
}

func TestLiveSupportingEvidenceRecovery(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	ctx := l.ctx
	const (
		ns       = "konstapel-system"
		platform = "rc-platform"
		suffix   = "-rc-live"
		svc      = "rc-download"
		team     = "rc-prod"
		docs     = "konstapel-docs-lock"
		// Source retention of the long-running replicas, and of the replica
		// with a shorter setting.
		longRetention  = 30 * time.Minute
		shortRetention = 2 * time.Minute
	)
	for _, n := range []string{ns, platform} {
		_ = l.c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
	}
	l.setNamespace(team, "rc-production")
	if _, err := pub.Client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(docs), ObjectLockEnabledForBucket: aws.Bool(true)}); err != nil {
		t.Fatalf("object-lock bucket: %v", err)
	}
	// The fault proxy in front of the documents' storage.
	proxy := &s3fault.Proxy{Backend: strings.TrimPrefix(l.s3Endpoint, "http://"), Logf: t.Logf}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	t.Cleanup(proxy.Release)

	s3secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "rc-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	if err := l.c.Create(ctx, s3secret); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(context.Background(), s3secret) })
	destination := func(name, endpoint, bucket string) *v1alpha1.EvidenceDestination {
		ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{
			Endpoint: endpoint, Bucket: bucket, Region: "us-east-1", Prefix: "konstapel-test/" + name, DevelopmentFixture: true,
			CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: s3secret.Name}}}}}
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
	docsED := destination("rc-docs", proxySrv.URL, docs)
	runsED := destination("rc-runs", l.s3Endpoint, pub.Dest.Bucket)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: DefaultDestinationConfigMap},
		Data: map[string]string{DefaultDestinationNameKey: docsED.Name, DefaultDestinationUIDKey: string(docsED.UID)}}
	err := l.c.Create(ctx, cm)
	if apierrors.IsAlreadyExists(err) {
		err = l.c.Update(ctx, cm)
	} else if err == nil {
		t.Cleanup(func() { _ = l.c.Delete(context.Background(), cm) })
	}
	if err != nil {
		t.Fatal(err)
	}

	// The shipped roles under test-owned names.
	rename := func(u *unstructured.Unstructured) { u.SetName(u.GetName() + suffix) }
	for _, f := range []string{"evidence-attachments", "assessment-operator", "evidence-download"} {
		l.applyManifests("../../config/rbac/"+f+".yaml", rename)
	}
	cluster := func(role string) rbacv1.RoleRef {
		return rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role + suffix}
	}
	sas := map[string]string{"rc-uploader-1": platform, "rc-uploader-2": platform, "rc-auditor": platform, svc: ns}
	for sa, n := range sas {
		o := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: n, Name: sa}}
		if err := l.c.Create(ctx, o); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(context.Background(), o) })
	}
	l.bindSA("rc-uploader-1", platform, "rc-uploader-1", cluster("konstapel-evidence-attachment-uploader"), "")
	l.bindSA("rc-uploader-2", platform, "rc-uploader-2", cluster("konstapel-evidence-attachment-uploader"), "")
	l.bindSA("rc-auditor-runs", platform, "rc-auditor", cluster("konstapel-assessment-operator"), "")
	l.bindSA("rc-auditor-documents", platform, "rc-auditor", cluster("konstapel-evidence-attachment-downloader"), "")
	l.bindSA("rc-download-service", ns, svc, cluster("konstapel-evidence-download"), "")
	l.bindSA("rc-download-credentials", ns, svc, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "konstapel-evidence-download-credentials" + suffix}, ns)

	// A platform binding over one failing workload, publishing to its own
	// destination.
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: team},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "rc-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("rc-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "rc-production"})
	// Evidence counts only when evaluated within the last second: while the
	// engine's reporting is stopped, a run's collection window stays open
	// for its whole 40 seconds.
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "40s", MaxEvidenceAge: "1s",
		DestinationRef: &v1alpha1.DestinationReference{Name: runsED.Name, UID: string(runsED.UID)}}
	var names []string
	var heldKey, heldVersion string
	t.Cleanup(func() {
		l.scaleKyverno("kyverno-reports-controller", 1)
		l.scaleKyverno("kyverno-background-controller", 1)
		if heldKey != "" {
			_, _ = pub.Client.PutObjectLegalHold(context.Background(), &s3.PutObjectLegalHoldInput{Bucket: aws.String(docs), Key: aws.String(heldKey),
				VersionId: aws.String(heldVersion), LegalHold: &s3types.ObjectLockLegalHold{Status: s3types.ObjectLockLegalHoldStatusOff}})
		}
		for _, n := range names {
			a := &v1alpha1.EvidenceAttachment{}
			if l.c.Get(context.Background(), client.ObjectKey{Name: n}, a) == nil {
				a.Finalizers = nil
				_ = l.c.Update(context.Background(), a)
				_ = l.c.Delete(context.Background(), a)
			}
		}
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(context.Background(), &runs)
		for i := range runs.Items {
			if r := &runs.Items[i]; r.Spec.BindingRef.Name == b.Name {
				r.Finalizers = nil
				_ = l.c.Update(context.Background(), r)
				_ = l.c.Delete(context.Background(), r)
			}
		}
		for _, o := range []client.Object{pod, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.Name}}, p} {
			_ = l.c.Delete(context.Background(), o)
		}
		l.eventually("recovery test policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
	})
	for _, o := range []client.Object{p, b, pod} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	// Controllers: leader-elected candidates, each with its own staging
	// directory. Leader B's publisher stages durably and never commits.
	runtime := func(dp *DestinationPublishers, staging string) AssessmentRuntime {
		return AssessmentRuntime{StagingDir: staging, ContentRoot: root, Poll: 2 * time.Second, PublishTimeout: 10 * time.Minute, Workers: 2,
			ControllerNamespace: ns, Destinations: dp, ProtectedReaders: NoProtectedReaders}
	}
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	stagingA := t.TempDir()
	ConfigureAssessments(runtime(&DestinationPublishers{Reader: l.c, Namespace: ns}, stagingA))
	stopA := once(l.candidateAs("", "rc-candidate-a"))
	defer stopA.stop()
	l.eventually("A elected", func() (bool, string) { return stopA.c.elected(), "" })
	for _, ed := range []*v1alpha1.EvidenceDestination{docsED, runsED} {
		l.eventually(ed.Name+" ready", func() (bool, string) {
			got := &v1alpha1.EvidenceDestination{}
			_ = l.c.Get(ctx, client.ObjectKeyFromObject(ed), got)
			return meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionDestinationReady), toJSON(got.Status)
		})
	}
	l.waitReady(b.Name, 1)
	bindingUID := string(l.binding(b.Name).UID)
	run := func(name string) *v1alpha1.AssessmentRun {
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(ctx, client.ObjectKey{Name: name}, r); err != nil {
			return nil
		}
		return r
	}
	committed := func(r *v1alpha1.AssessmentRun) bool {
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted && r.Status.Publication != nil &&
			r.Status.Publication.Phase == v1alpha1.PublicationPhase(publication.PhaseCommitted)
	}
	l.eventually("first scheduled run published before any document", func() (bool, string) {
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(ctx, &runs)
		for i := range runs.Items {
			if r := &runs.Items[i]; r.Spec.BindingRef.Name == b.Name && committed(r) {
				return true, ""
			}
		}
		return false, toJSON(l.binding(b.Name).Status.Assessment)
	})

	// Transfer-service replicas, each as the download service account.
	svcCfg := rest.AnonymousClientConfig(l.cfg)
	svcCfg.BearerToken = l.apiToken(ns, svc)
	svcC, err := client.New(svcCfg, client.Options{Scheme: l.c.Scheme()})
	if err != nil {
		t.Fatal(err)
	}
	ks := &corev1.Namespace{}
	if err := svcC.Get(ctx, client.ObjectKey{Name: "kube-system"}, ks); err != nil {
		t.Fatal(err)
	}
	clusterID := "kube-system:" + string(ks.UID)
	svcDP := &DestinationPublishers{Reader: svcC, Namespace: ns}
	replica := func(fate *replicaFate, retention time.Duration) *httptest.Server {
		base := NewAttachmentStores(svcC, ns)
		stores := base.Store
		if fate != nil {
			stores = func(ctx context.Context, ref v1alpha1.DestinationReference) (attachments.Store, error) {
				st, err := base.Store(ctx, ref)
				if err != nil {
					return nil, err
				}
				as, ok := st.(*s3store.AttachmentStore)
				if !ok {
					return nil, fmt.Errorf("unexpected attachment store %T", st)
				}
				c := s3.New(as.Client.Options(), func(o *s3.Options) { o.HTTPClient = replicaTransport{inner: o.HTTPClient, fate: fate} })
				return &s3store.AttachmentStore{Client: c, Dest: as.Dest, Now: as.Now}, nil
			}
		}
		srv := &download.Server{Reader: svcC, Reviews: download.KubeReviewer{Client: svcC, Audience: downloadAudience}, TempDir: t.TempDir(),
			PublisherFor: func(ctx context.Context, r *v1alpha1.AssessmentRun) (publication.Publisher, error) {
				return svcDP.For(ctx, r.Status.Destination)
			},
			AttachmentStores: stores, Cluster: clusterID,
			AttachmentLimits: download.AttachmentLimits{MaxBytes: 64 << 10, Timeout: time.Minute, MaxConcurrent: 2, Retention: retention}}
		ts := httptest.NewTLSServer(srv.Handler())
		t.Cleanup(ts.Close)
		if fate != nil {
			t.Cleanup(fate.kill) // runs first: a held handler returns before Close waits for it
		}
		return ts
	}
	survivor := replica(nil, longRetention)
	tok := map[string]string{}
	for sa, n := range sas {
		tok[sa] = l.token(n, sa, downloadAudience)
	}
	upload := func(ts *httptest.Server, uid, who string, body []byte) (int, []byte, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPut, ts.URL+"/v1/evidenceattachments/"+uid+"/upload", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok[who])
		resp, err := ts.Client().Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, out, nil
	}
	uploaded := func(ts *httptest.Server, uid, who string, body []byte) download.UploadReceipt {
		t.Helper()
		code, out, err := upload(ts, uid, who, body)
		var rc download.UploadReceipt
		if err != nil || code != http.StatusOK || json.Unmarshal(out, &rc) != nil {
			t.Fatalf("upload as %s: %d %s %v", who, code, out, err)
		}
		return rc
	}
	// lose uploads through a fated replica and loses the replica at its
	// commit: the caller gets no answer.
	lose := func(fate *replicaFate, uid, who string, body []byte) error {
		t.Helper()
		ts := replica(fate, longRetention)
		type result struct {
			code int
			err  error
		}
		done := make(chan result, 1)
		go func() { code, _, err := upload(ts, uid, who, body); done <- result{code, err} }()
		select {
		case <-fate.reached:
		case r := <-done:
			t.Fatalf("the upload on the lost replica ended before its commit: %d %v", r.code, r.err)
		case <-time.After(2 * time.Minute):
			t.Fatal("the lost replica never reached its commit")
		}
		ts.CloseClientConnections()
		fate.kill()
		r := <-done
		ts.Close()
		if r.err == nil {
			t.Fatalf("the caller of a lost replica got an answer: %d", r.code)
		}
		return r.err
	}
	fetchFrom := func(ts *httptest.Server, path, who string) (int, []byte, http.Header) {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok[who])
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, out, resp.Header
	}
	packageOf := func(r *v1alpha1.AssessmentRun) []byte {
		t.Helper()
		code, out, _ := fetchFrom(survivor, "/v1/assessmentruns/"+string(r.UID)+"/download", "rc-auditor")
		if code != http.StatusOK {
			// Never log the body: it may be the protected package.
			t.Fatalf("package of %s: %d (%d bytes)", r.Name, code, len(out))
		}
		return out
	}

	// Documents: registered as a platform registrar would (the registrant
	// itself is TestLiveEvidenceAttachmentAPI's subject).
	catalog, err := attachments.ReadVendoredBaseline(os.DirFS(root))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	get := func(name string) *v1alpha1.EvidenceAttachment {
		a := &v1alpha1.EvidenceAttachment{}
		if err := l.c.Get(ctx, client.ObjectKey{Name: name}, a); err != nil {
			return nil
		}
		return a
	}
	register := func(d *supportingDocument, from, until time.Time) {
		t.Helper()
		sum := sha256.Sum256(d.body)
		a := &v1alpha1.EvidenceAttachment{ObjectMeta: metav1.ObjectMeta{Name: d.name}, Spec: v1alpha1.EvidenceAttachmentSpec{
			Document: v1alpha1.AttachmentDocument{Title: d.title, MediaType: "application/pdf", Size: int64(len(d.body)), SHA256: "sha256:" + hex.EncodeToString(sum[:])},
			Source:   v1alpha1.AttachmentSource{Issuer: d.issuer},
			Validity: v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(from), ValidUntil: metav1.NewTime(until)},
			Associations: []v1alpha1.AttachmentAssociation{{Binding: v1alpha1.ExactBindingReference{Name: b.Name, UID: bindingUID}, CatalogDigest: catalog.CatalogDigest,
				Controls: []v1alpha1.AttachmentControl{{ID: "pe-3"}}}},
			Scope:        v1alpha1.AttachmentScope{Description: d.scope},
			RegisteredBy: &v1alpha1.Requester{Username: "platform-registrar"}}}
		if err := l.c.Create(ctx, a); err != nil {
			t.Fatal(err)
		}
		names = append(names, d.name)
		l.eventually(d.name+" pinned", func() (bool, string) {
			d.record = get(d.name)
			return d.record != nil && d.record.Status.Storage != nil && d.record.Status.Storage.Destination != nil, toJSON(d.record)
		})
	}
	// poke makes the controller read storage now: a commit by the transfer
	// service is not an API event.
	poke := func(d *supportingDocument) {
		t.Helper()
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			cur := get(d.name)
			if cur.Labels == nil {
				cur.Labels = map[string]string{}
			}
			cur.Labels["recovery.konstapel.dev/poke"] = fmt.Sprint(time.Now().UnixNano())
			return l.c.Update(ctx, cur)
		}); err != nil {
			t.Fatal(err)
		}
	}
	available := func(d *supportingDocument) {
		t.Helper()
		poke(d)
		l.eventually(d.name+" committed, available and validly associated", func() (bool, string) {
			d.record = get(d.name)
			s := d.record.Status
			return s.Storage.Commitment != nil && s.Content != nil && s.Content.State == v1alpha1.ContentAvailable &&
				meta.IsStatusConditionTrue(s.Conditions, v1alpha1.ConditionAssociationsValid), toJSON(s)
		})
	}
	cur := &v1alpha1.EvidenceDestination{}
	if err := l.c.Get(ctx, client.ObjectKeyFromObject(docsED), cur); err != nil {
		t.Fatal(err)
	}
	docsDest, err := DestinationFromAPI(ctx, l.c, ns, cur)
	if err != nil {
		t.Fatal(err)
	}
	// The test's own view of the documents' storage, bypassing the proxy.
	direct := &s3store.AttachmentStore{Client: pub.Client, Dest: docsDest}
	prefixOf := func(d *supportingDocument) string {
		return s3store.AttachmentPrefix(docsDest, attachments.Ref{ClusterID: clusterID, UID: d.uid()})
	}
	objects := func(d *supportingDocument) []string {
		t.Helper()
		out, err := pub.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(docs), Prefix: aws.String(prefixOf(d))})
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, o := range out.Contents {
			keys = append(keys, strings.TrimPrefix(aws.ToString(o.Key), prefixOf(d)))
		}
		return keys
	}
	attemptDirs := func(d *supportingDocument) map[string][]string {
		out := map[string][]string{}
		for _, k := range objects(d) {
			if rest, ok := strings.CutPrefix(k, "attempts/"); ok {
				dir, file, _ := strings.Cut(rest, "/")
				out[dir] = append(out[dir], file)
			}
		}
		return out
	}
	uploader1, uploader2 := "system:serviceaccount:"+platform+":rc-uploader-1", "system:serviceaccount:"+platform+":rc-uploader-2"

	current := func(d *supportingDocument) { register(d, now.Add(-24*time.Hour), now.Add(365*24*time.Hour)) }
	replicaDoc := newSupportingDocument("rc-replica-lost", "DC North audit, replica lost before commit", "Recovery Audit AB", "DC North hall A")
	lostDoc := newSupportingDocument("rc-response-lost", "DC North audit, commit response lost", "Recovery Audit AB", "DC North hall B")
	interrupted := newSupportingDocument("rc-interrupted", "DC North audit, interrupted upload", "Recovery Audit AB", "DC North hall C")
	unreachable := newSupportingDocument("rc-unreachable", "DC North audit, storage unreachable", "Recovery Audit AB", "DC North hall D")
	for _, d := range []*supportingDocument{replicaDoc, lostDoc, interrupted, unreachable} {
		current(d)
	}

	// 1a. A replica is lost after staging, before its commit: an owned,
	// uncommitted attempt and no document. The retry on another replica
	// commits once.
	lostBefore := lose(newReplicaFate(false), replicaDoc.uid(), "rc-uploader-1", replicaDoc.body)
	if dirs := attemptDirs(replicaDoc); len(dirs) != 1 || hasFile(objects(replicaDoc), "commit.json") {
		t.Fatalf("after the replica was lost before its commit: %v", objects(replicaDoc))
	}
	var abandoned string
	for dir, files := range attemptDirs(replicaDoc) {
		abandoned = dir
		if !hasFile(files, "intent.json") || !hasFile(files, "document") || !hasFile(files, "attempt.json") {
			t.Fatalf("the lost replica's attempt %s: %v", dir, files)
		}
	}
	intent, err := pub.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(docs), Key: aws.String(prefixOf(replicaDoc) + "attempts/" + abandoned + "/intent.json")})
	if err != nil {
		t.Fatal(err)
	}
	var owner struct {
		Ref      attachments.Ref       `json:"ref"`
		Uploader attachments.Principal `json:"uploader"`
	}
	if err := json.NewDecoder(intent.Body).Decode(&owner); err != nil || owner.Ref.UID != replicaDoc.uid() || owner.Uploader.Username != uploader1 {
		t.Fatalf("the abandoned attempt's owner: %+v %v", owner, err)
	}
	intent.Body.Close()
	poke(replicaDoc)
	time.Sleep(3 * time.Second)
	if a := get(replicaDoc.name); a.Status.Storage.Commitment != nil || a.Status.Content == nil || a.Status.Content.State != v1alpha1.ContentPending {
		t.Fatalf("an uncommitted attempt became available evidence: %s", toJSON(a.Status))
	}
	retried := uploaded(survivor, replicaDoc.uid(), "rc-uploader-2", replicaDoc.body)
	available(replicaDoc)
	if c := replicaDoc.record.Status.Storage.Commitment; retried.Uploader.Username != uploader2 || c.Uploader.Username != uploader2 || !c.CommittedAt.Time.Equal(retried.CommittedAt) ||
		strings.Contains(c.DocumentKey, abandoned) {
		t.Fatalf("retry after the lost replica: receipt %+v, commitment %s", retried, toJSON(c))
	}
	// The abandoned attempt is owned and removed by the owner's attempt
	// cleanup (the controller runs it once attempts are 24 hours old); the
	// committed attempt stays.
	if err := direct.CleanupAttempts(ctx, attachments.Ref{ClusterID: clusterID, UID: replicaDoc.uid()}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	dirs := attemptDirs(replicaDoc)
	if _, left := dirs[abandoned]; left || len(dirs) != 1 || !hasFile(objects(replicaDoc), "commit.json") {
		t.Fatalf("after attempt cleanup: %v", objects(replicaDoc))
	}
	l.record("replica-lost-before-commit", map[string]any{"callerError": lostBefore.Error(), "abandonedAttempt": abandoned, "abandonedBy": uploader1,
		"committedBy": uploader2, "cleanup": "abandoned attempt removed, commitment kept"})

	// 1b. A replica is lost after its commit landed: the commit response is
	// lost. The controller records the commitment from storage; a retry by
	// another uploader on another replica is answered with it.
	fate := newReplicaFate(true)
	lostAfter := lose(fate, lostDoc.uid(), "rc-uploader-1", lostDoc.body)
	if fate.status.Load() != http.StatusOK || !hasFile(objects(lostDoc), "commit.json") {
		t.Fatalf("the lost replica's commit did not land: %d %v", fate.status.Load(), objects(lostDoc))
	}
	available(lostDoc)
	first := lostDoc.record.Status.Storage.Commitment.DeepCopy()
	again := uploaded(survivor, lostDoc.uid(), "rc-uploader-2", lostDoc.body)
	if first.Uploader.Username != uploader1 || again.Uploader.Username != uploader1 || !again.CommittedAt.Equal(first.CommittedAt.Time) || !again.ExpiresAt.Equal(first.ExpiresAt.Time) {
		t.Fatalf("retry after the lost response: receipt %+v, recorded %s", again, toJSON(first))
	}
	// A replica with a shorter retention setting changes no commitment.
	short := replica(nil, shortRetention)
	if r := uploaded(short, lostDoc.uid(), "rc-uploader-2", lostDoc.body); r.Retention != longRetention.String() || !r.ExpiresAt.Equal(first.ExpiresAt.Time) {
		t.Fatalf("a replica with another retention changed the commitment: %+v", r)
	}
	manifests, err := pub.Client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(docs), Prefix: aws.String(prefixOf(lostDoc) + "commit.json")})
	if err != nil || len(manifests.Versions) != 1 || len(manifests.DeleteMarkers) != 0 {
		t.Fatalf("commit manifest versions: %v %v", manifests, err)
	}
	if a := get(lostDoc.name); *a.Status.Storage.Commitment != *first {
		t.Fatalf("the recorded commitment changed: %s", toJSON(a.Status.Storage.Commitment))
	}
	l.record("commit-response-lost", map[string]any{"callerError": lostAfter.Error(), "landed": fate.status.Load(), "committedBy": uploader1,
		"retryAnsweredWith": again.Uploader.Username, "manifestVersions": 1, "otherRetentionReplica": "unchanged " + first.Retention.Duration.String()})

	// 1c. An interrupted upload stores nothing; the record stays pending.
	pool := x509.NewCertPool()
	pool.AddCert(survivor.Certificate())
	conn, err := tls.Dial("tcp", survivor.Listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "PUT /v1/evidenceattachments/%s/upload HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\nContent-Length: %d\r\n\r\n%s",
		interrupted.uid(), tok["rc-uploader-1"], len(interrupted.body), interrupted.body[:64])
	time.Sleep(time.Second)
	conn.Close()
	time.Sleep(2 * time.Second)
	if keys := objects(interrupted); len(keys) != 0 {
		t.Fatalf("the interrupted upload stored %v", keys)
	}
	uploaded(survivor, unreachable.uid(), "rc-uploader-2", unreachable.body)
	available(unreachable)
	l.record("interrupted", map[string]any{"objects": 0, "content": get(interrupted.name).Status.Content})

	// 2. Truthful states in a platform run. Engine reporting stops, so no
	// evaluation is ever recent enough and the collection window stays open
	// for its whole 40 seconds; storage refuses every read of one document
	// for that window.
	l.scaleKyverno("kyverno-reports-controller", 0)
	l.scaleKyverno("kyverno-background-controller", 0)
	proxy.SetFailing(unreachable.uid())
	if code, out, _ := fetchFrom(survivor, "/v1/evidenceattachments/"+unreachable.uid()+"/download", "rc-auditor"); code != http.StatusServiceUnavailable {
		t.Fatalf("source download while its storage refuses reads: %d (%d bytes)", code, len(out))
	}
	staged := func(staging string, r *v1alpha1.AssessmentRun, d *supportingDocument) bool {
		_, err := os.Stat(filepath.Join(staging, string(r.UID), runSupportingDir, d.uid()))
		return err == nil
	}
	newRun := func(name string) *v1alpha1.AssessmentRun {
		t.Helper()
		r := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}, Scope: v1alpha1.RunScopeBinding}}
		if err := l.c.Create(ctx, r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	p1 := newRun("rc-audit-capture")
	l.eventually("documents copied while the window is open", func() (bool, string) {
		r := run(p1.Name)
		if r == nil || r.Status.Phase != v1alpha1.RunCollecting {
			return false, toJSON(r)
		}
		p1 = r
		return staged(stagingA, r, replicaDoc) && staged(stagingA, r, lostDoc) && proxy.Snapshot().Failed > 0, toJSON(proxy.Snapshot())
	})
	// Withdrawal during the capture.
	if err := l.c.Delete(ctx, lostDoc.record); err != nil {
		t.Fatal(err)
	}
	l.eventually("withdrawn during the capture", func() (bool, string) {
		a := get(lostDoc.name)
		return a != nil && a.Status.Withdrawal != nil, toJSON(a)
	})
	if r := run(p1.Name); r.Status.Phase != v1alpha1.RunCollecting {
		t.Fatalf("the run closed before the withdrawal: %s", toJSON(r.Status))
	}
	l.eventually(p1.Name+" published", func() (bool, string) { r := run(p1.Name); return committed(r), toJSON(r) })
	p1 = run(p1.Name)
	proxy.Release()
	dir1, d1, rep1 := unpackPackage(t, packageOf(p1))
	check := func(rep *coverage.Report, dir string, d *supportingDocument, access string, withdrawn bool, content, reason string) {
		t.Helper()
		e := supportingEntry(rep, d.uid())
		copied := packageCopy(dir, d.uid())
		if e == nil || e.Access != access || e.Withdrawn != withdrawn || e.Content != content || (reason != "" && e.ContentReason != reason) ||
			(access == coverage.AccessIncluded) != bytes.Equal(copied, d.body) || (access != coverage.AccessIncluded && copied != nil) {
			t.Fatalf("%s: %s (copy %d bytes)", d.name, toJSON(e), len(copied))
		}
	}
	check(rep1, dir1, replicaDoc, coverage.AccessIncluded, false, coverage.SupportingContentAvailable, "")
	check(rep1, dir1, lostDoc, coverage.AccessIncluded, true, coverage.SupportingContentAvailable, "")
	check(rep1, dir1, interrupted, coverage.AccessNotIncluded, false, coverage.SupportingContentPending, "")
	check(rep1, dir1, unreachable, coverage.AccessNotIncluded, false, coverage.SupportingContentUnavailable, reasonNotRetrieved)
	withdrawnRefs := 0
	for _, row := range rep1.Controls {
		for _, ref := range row.SupportingEvidence {
			if ref.Source == lostDoc.uid() && ref.Withdrawn {
				withdrawnRefs++
			}
		}
	}
	if !d1.Protected() || withdrawnRefs != 1 || p1.Status.Summary.Export != "Assessment" {
		t.Fatalf("capture package: protection %+v, withdrawn references %d, summary %s", d1.Protection, withdrawnRefs, toJSON(p1.Status.Summary))
	}
	if a := get(lostDoc.name); a == nil || a.Status.Storage.Cleanup == nil || a.Status.Storage.Cleanup.State != "NotDue" {
		t.Fatalf("the withdrawn document's source is not retained: %s", toJSON(a))
	}
	if code, out, h := fetchFrom(survivor, "/v1/evidenceattachments/"+lostDoc.uid()+"/download", "rc-auditor"); code != http.StatusOK || !bytes.Equal(out, lostDoc.body) ||
		h.Get("X-Konstapel-Withdrawn") != "true" {
		t.Fatalf("the withdrawn, retained source: %d %v", code, h)
	}
	l.record("capture", map[string]any{"run": p1.Name, "evidence": d1.Evidence, "included": []string{replicaDoc.name, lostDoc.name + " (withdrawn)"},
		"pending": interrupted.name, "notRetrieved": unreachable.name, "refusedReads": proxy.Snapshot().Failed})

	// 3. Leader loss before durable staging: the next leader has its own
	// empty staging directory, so the run is capture loss with nothing
	// stored, never reconstructed from newer state.
	p2 := newRun("rc-audit-leader-lost")
	l.eventually("a document copied by leader A", func() (bool, string) {
		r := run(p2.Name)
		if r == nil || r.Status.Phase != v1alpha1.RunCollecting {
			return false, toJSON(r)
		}
		p2 = r
		return staged(stagingA, r, replicaDoc), ""
	})
	var stalledMu sync.Mutex
	var stalled *stalledPublisher
	stagingB := t.TempDir()
	ConfigureAssessments(runtime(&DestinationPublishers{Reader: l.c, Namespace: ns,
		New: func(ctx context.Context, d s3store.Destination, r client.Reader, n string) (publication.Publisher, error) {
			pp, err := s3store.NewPublisher(ctx, d, r, controllerNamespace(n))
			if err != nil {
				return nil, err
			}
			if d.ID != string(runsED.UID) {
				return pp, nil
			}
			stalledMu.Lock()
			defer stalledMu.Unlock()
			stalled = &stalledPublisher{Publisher: pp}
			return stalled, nil
		}}, stagingB))
	stopB := once(l.candidateAs("", "rc-candidate-b"))
	leaderB := stopB.c
	defer stopB.stop()
	stopA.stop()
	l.eventually("B elected", func() (bool, string) { return leaderB.elected(), "" })
	l.eventually(p2.Name+" lost", func() (bool, string) {
		r := run(p2.Name)
		c := meta.FindStatusCondition(r.Status.Conditions, v1alpha1.ConditionPublished)
		return r.Status.Phase == v1alpha1.RunFailed && c != nil && c.Reason == v1alpha1.ReasonCaptureLost, toJSON(r.Status)
	})
	cur = &v1alpha1.EvidenceDestination{}
	if err := l.c.Get(ctx, client.ObjectKeyFromObject(runsED), cur); err != nil {
		t.Fatal(err)
	}
	runsDest, err := DestinationFromAPI(ctx, l.c, ns, cur)
	if err != nil {
		t.Fatal(err)
	}
	runsPub := &s3store.Publisher{Client: pub.Client, Dest: runsDest}
	if keys := ownedKeys(t, l, runsPub, string(p2.UID)); len(keys) != 0 {
		t.Fatalf("the lost capture stored %v", keys)
	}
	l.scaleKyverno("kyverno-reports-controller", 1)
	l.scaleKyverno("kyverno-background-controller", 1)
	l.record("leader-lost-before-staging", map[string]any{"run": p2.Name, "reason": v1alpha1.ReasonCaptureLost, "stored": 0})

	// 4. Leader loss after durable staging. The interrupted document is
	// uploaded now, and an expired one through the replica with the short
	// retention, under a legal hold.
	uploaded(survivor, interrupted.uid(), "rc-uploader-1", interrupted.body)
	available(interrupted)
	held := newSupportingDocument("rc-held", "DC North audit 2024, under legal hold", "Recovery Audit AB 2024", "DC North hall E, 2024")
	register(held, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	uploaded(short, held.uid(), "rc-uploader-1", held.body)
	available(held)
	hc := held.record.Status.Storage.Commitment.DeepCopy()
	heldKey, heldVersion = hc.DocumentKey, hc.DocumentVersionID
	if _, err := pub.Client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{Bucket: aws.String(docs), Key: aws.String(heldKey), VersionId: aws.String(heldVersion),
		LegalHold: &s3types.ObjectLockLegalHold{Status: s3types.ObjectLockLegalHoldStatusOn}}); err != nil {
		t.Fatalf("legal hold: %v", err)
	}
	l.eventually(unreachable.name+" available again", func() (bool, string) {
		a := get(unreachable.name)
		return a.Status.Content != nil && a.Status.Content.State == v1alpha1.ContentAvailable, toJSON(a.Status.Content)
	})
	p3 := newRun("rc-audit-handover")
	var stagedPkg publication.Staged
	l.eventually("leader B staged the package durably", func() (bool, string) {
		r := run(p3.Name)
		stalledMu.Lock()
		sp := stalled
		stalledMu.Unlock()
		if r == nil || sp == nil || sp.stagedPackage() == nil {
			return false, toJSON(r)
		}
		p3, stagedPkg = r, *sp.stagedPackage()
		return r.Status.Phase == v1alpha1.RunPublishing, string(r.Status.Phase)
	})
	// Withdrawals after the closure change nothing staged.
	for _, d := range []*supportingDocument{replicaDoc, held} {
		if err := l.c.Delete(ctx, get(d.name)); err != nil {
			t.Fatal(err)
		}
		l.eventually(d.name+" withdrawn", func() (bool, string) {
			a := get(d.name)
			return a != nil && a.Status.Withdrawal != nil, toJSON(a)
		})
	}
	ConfigureAssessments(runtime(&DestinationPublishers{Reader: l.c, Namespace: ns}, t.TempDir()))
	stopC := once(l.candidateAs("", "rc-candidate-c"))
	defer stopC.stop()
	stopB.stop()
	l.eventually("C elected", func() (bool, string) { return stopC.c.elected(), "" })
	l.eventually("C commits the staged package", func() (bool, string) { r := run(p3.Name); return committed(r), toJSON(r) })
	p3 = run(p3.Name)
	if pp := p3.Status.Publication; pp.PublicationID != stagedPkg.PublicationID || pp.PackageSHA256 != stagedPkg.PackageSHA256 || commits(t, l, runsPub, string(p3.UID)) != 1 {
		t.Fatalf("the successor published %s, staged %+v", toJSON(pp), stagedPkg)
	}
	archive3 := packageOf(p3)
	if sum := sha256.Sum256(archive3); hex.EncodeToString(sum[:]) != stagedPkg.PackageSHA256 {
		t.Fatal("the served package is not the staged bytes")
	}
	dir3, _, rep3 := unpackPackage(t, archive3)
	check(rep3, dir3, replicaDoc, coverage.AccessIncluded, false, coverage.SupportingContentAvailable, "")
	check(rep3, dir3, interrupted, coverage.AccessIncluded, false, coverage.SupportingContentAvailable, "")
	check(rep3, dir3, unreachable, coverage.AccessIncluded, false, coverage.SupportingContentAvailable, "")
	check(rep3, dir3, held, coverage.AccessIncluded, false, coverage.SupportingContentAvailable, "")
	if e := supportingEntry(rep3, held.uid()); e.Temporal != coverage.SupportingExpired {
		t.Fatalf("the expired document's temporal state: %s", toJSON(e))
	}
	if e := supportingEntry(rep3, lostDoc.uid()); e != nil {
		t.Fatalf("a document withdrawn before the run started entered it: %s", toJSON(e))
	}
	l.record("leader-lost-after-staging", map[string]any{"run": p3.Name, "publicationID": stagedPkg.PublicationID, "packageSha256": stagedPkg.PackageSHA256,
		"withdrawnAfterClosure": []string{replicaDoc.name, held.name}, "commits": 1})

	// 5. Denied cleanup: the legal hold refuses the held document's source
	// deletion at its expiry.
	var blocked *v1alpha1.AttachmentCleanup
	time.Sleep(time.Until(hc.ExpiresAt.Time))
	l.eventually("source cleanup denied by the legal hold", func() (bool, string) {
		a := get(held.name)
		if a == nil {
			return false, "released while storage refuses the deletion"
		}
		blocked = a.Status.Storage.Cleanup
		ok := blocked != nil && blocked.Attempts >= 1 && blocked.LastAttempt != nil && a.Status.Withdrawal != nil && a.Status.Storage.Commitment != nil &&
			*a.Status.Storage.Commitment == *hc && (blocked.State == string(attachments.CleanupRetentionBlocked) || blocked.State == string(attachments.CleanupDeletionFailed))
		return ok, toJSON(a.Status)
	})
	if _, err := pub.Client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(docs), Key: aws.String(heldKey), VersionId: aws.String(heldVersion)}); err != nil {
		t.Fatalf("the held document version is gone: %v", err)
	}
	ed := &v1alpha1.EvidenceDestination{}
	if err := l.c.Get(ctx, client.ObjectKeyFromObject(docsED), ed); err != nil || !controllerutil.ContainsFinalizer(ed, DestinationFinalizer) {
		t.Fatalf("the documents' destination released while a cleanup is denied: %v", err)
	}
	if code, out, _ := fetchFrom(survivor, "/v1/evidenceattachments/"+held.uid()+"/download", "rc-auditor"); code != http.StatusGone {
		t.Fatalf("an expired source served while its deletion is denied: %d (%d bytes)", code, len(out))
	}
	dir3, _, rep3 = unpackPackage(t, packageOf(p3))
	check(rep3, dir3, held, coverage.AccessIncluded, false, coverage.SupportingContentAvailable, "")
	if _, err := pub.Client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{Bucket: aws.String(docs), Key: aws.String(heldKey), VersionId: aws.String(heldVersion),
		LegalHold: &s3types.ObjectLockLegalHold{Status: s3types.ObjectLockLegalHoldStatusOff}}); err != nil {
		t.Fatalf("lift the legal hold: %v", err)
	}
	heldKey = ""
	// The next attempt follows the backoff (at most 2m after a second
	// failure, 4m after a third).
	deadline := time.Now().Add(6 * time.Minute)
	for get(held.name) != nil {
		if time.Now().After(deadline) {
			t.Fatalf("the denied cleanup never recovered: %s", toJSON(get(held.name)))
		}
		time.Sleep(3 * time.Second)
	}
	versions, err := pub.Client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(docs), Prefix: aws.String(prefixOf(held))})
	if err != nil || len(versions.Versions)+len(versions.DeleteMarkers) != 0 {
		t.Fatalf("after the recovered cleanup: %v %v", versions, err)
	}
	dir3, _, rep3 = unpackPackage(t, packageOf(p3))
	check(rep3, dir3, held, coverage.AccessIncluded, false, coverage.SupportingContentAvailable, "")
	l.record("cleanup-denied", map[string]any{"document": held.name, "blocked": blocked, "expiresAt": hc.ExpiresAt, "recovered": true,
		"packageAfterSourceDeletion": http.StatusOK})
}

// stoppable stops its candidate at most once (a candidate's stop waits for
// its manager's single exit).
type stoppable struct {
	c *candidate
	o sync.Once
}

func once(c *candidate) *stoppable { return &stoppable{c: c} }

func (s *stoppable) stop() { s.o.Do(s.c.stop) }

// hasFile reports whether keys holds name, as a key or a key's base name.
func hasFile(keys []string, name string) bool {
	for _, v := range keys {
		if v == name || path.Base(v) == name {
			return true
		}
	}
	return false
}
