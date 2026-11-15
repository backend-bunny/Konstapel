package download

// add-supporting-evidence-attachments 3.1-3.2: attachment upload/download
// routes on the download service, against the in-memory attachment store.
// Authentication and authorization are the archive routes' (TokenReview for
// the service audience, SubjectAccessReview on a dedicated attribute plus
// read of the resolved record); bytes are bounded and verified before
// anything is stored; only the pinned destination's store is used; and a
// download serves only the recorded, confirmed, unexpired commitment as a
// passive attachment.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
	attfake "github.com/backend-bunny/Konstapel/internal/attachments/fake"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

const cluster = "kube-system:cluster-1"

type attEnv struct {
	t      *testing.T
	c      client.Client
	rev    *reviews
	store  *attfake.Store
	srv    *Server
	ts     *httptest.Server
	now    time.Time
	tmp    string
	stores func(context.Context, v1alpha1.DestinationReference) (attachments.Store, error)
	bodies map[string][]byte // attachment name -> registered bytes
}

func registered(name, uid string, body []byte, validUntil time.Time) *v1alpha1.EvidenceAttachment {
	sum := sha256.Sum256(body)
	return &v1alpha1.EvidenceAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uid), Finalizers: []string{v1alpha1.EvidenceAttachmentFinalizer}},
		Spec: v1alpha1.EvidenceAttachmentSpec{
			Document: v1alpha1.AttachmentDocument{Title: name, MediaType: "text/html", Size: int64(len(body)), SHA256: "sha256:" + hex.EncodeToString(sum[:])},
			Source:   v1alpha1.AttachmentSource{Issuer: "Example Audit AB", URL: "https://audits.example.com/" + name},
			Validity: v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(validUntil.Add(-365 * 24 * time.Hour)), ValidUntil: metav1.NewTime(validUntil)},
			Associations: []v1alpha1.AttachmentAssociation{{Binding: v1alpha1.ExactBindingReference{Name: "audit", UID: "uid-audit"},
				CatalogDigest: "sha256:" + strings.Repeat("0", 64), Controls: []v1alpha1.AttachmentControl{{ID: "pe-3"}}}},
			Scope:        v1alpha1.AttachmentScope{Description: "DC North"},
			RegisteredBy: &v1alpha1.Requester{Username: "registrar", UID: "uid-registrar"},
		},
		Status: v1alpha1.EvidenceAttachmentStatus{Storage: &v1alpha1.AttachmentStorage{
			Destination: &v1alpha1.DestinationReference{Name: "primary", UID: "dest-uid"}, DestinationID: "dest-uid"}},
	}
}

func newAttEnv(t *testing.T) *attEnv {
	e := &attEnv{t: t, now: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC), tmp: t.TempDir(), bodies: map[string][]byte{}}
	clock := func() time.Time { return e.now }
	e.store = e.newStore()
	north := []byte("<html><script>alert('DC North physical access audit')</script></html>")
	south := []byte("%PDF-1.7 DC South physical access audit")
	big := bytes.Repeat([]byte("x"), 2<<10)
	unpinned := []byte("not pinned yet")
	e.bodies = map[string][]byte{"dc-north": north, "dc-south": south, "big": big, "unpinned": unpinned}
	year := e.now.Add(365 * 24 * time.Hour).Truncate(time.Second)
	objs := []client.Object{registered("dc-north", "att-north", north, year), registered("dc-south", "att-south", south, year),
		registered("big", "att-big", big, year)}
	u := registered("unpinned", "att-unpinned", unpinned, year)
	u.Status.Storage = nil
	objs = append(objs, u)
	e.c = fake.NewClientBuilder().WithScheme(scheme()).WithObjects(objs...).WithStatusSubresource(&v1alpha1.EvidenceAttachment{}).Build()
	e.rev = &reviews{tokens: map[string]string{"up": "uploader", "down": "downloader", "reg": "registrar", "team": "team-dev", "south": "south-uploader"},
		grants: map[string]bool{}}
	for _, n := range []string{"dc-north", "dc-south", "big", "unpinned"} {
		e.grant("uploader", "create", "upload", n)
		e.grant("uploader", "get", "", n)
		e.grant("downloader", "get", "download", n)
		e.grant("downloader", "get", "", n)
		e.grant("registrar", "get", "", n)
	}
	// south-uploader may upload only dc-south (a resourceName-scoped grant).
	e.grant("south-uploader", "create", "upload", "dc-south")
	e.grant("south-uploader", "get", "", "dc-south")
	e.stores = func(_ context.Context, ref v1alpha1.DestinationReference) (attachments.Store, error) {
		if ref.UID != "dest-uid" {
			return nil, attachments.ErrUnavailable
		}
		return e.store, nil
	}
	e.srv = &Server{Reader: e.c, Reviews: e.rev, TempDir: e.tmp, Cluster: cluster, Now: clock,
		AttachmentStores: func(ctx context.Context, ref v1alpha1.DestinationReference) (attachments.Store, error) {
			return e.stores(ctx, ref)
		},
		AttachmentLimits: AttachmentLimits{MaxBytes: 1 << 10, Timeout: 2 * time.Second, MaxConcurrent: 2, Retention: attachments.DefaultRetention}}
	e.ts = httptest.NewServer(e.srv.Handler())
	t.Cleanup(e.ts.Close)
	return e
}

// newStore is the pinned destination's (EvidenceDestination UID dest-uid)
// empty store.
func (e *attEnv) newStore() *attfake.Store {
	s := attfake.New(func() time.Time { return e.now })
	s.Dest.ID = "dest-uid"
	return s
}

// asked returns the reviews made so far.
func (e *attEnv) asked() []string {
	e.rev.mu.Lock()
	defer e.rev.mu.Unlock()
	return append([]string(nil), e.rev.asked...)
}

func (e *attEnv) grant(user, verb, sub, name string) {
	r := "evidenceattachments"
	if sub != "" {
		r += "/" + sub
	}
	e.rev.grants[user+" "+verb+" /"+r+"/"+name] = true
}

func (e *attEnv) revoke(user, verb, sub, name string) {
	r := "evidenceattachments"
	if sub != "" {
		r += "/" + sub
	}
	delete(e.rev.grants, user+" "+verb+" /"+r+"/"+name)
}

func (e *attEnv) get(name string) *v1alpha1.EvidenceAttachment {
	e.t.Helper()
	a := &v1alpha1.EvidenceAttachment{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, a); err != nil {
		e.t.Fatal(err)
	}
	return a
}

func (e *attEnv) ref(uid string) attachments.Ref {
	return attachments.Ref{ClusterID: cluster, UID: uid}
}

type response struct {
	code   int
	header http.Header
	body   []byte
}

func (e *attEnv) do(method, uid, sub, token string, body io.Reader, length int64) response {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.ts.URL+"/v1/evidenceattachments/"+uid+"/"+sub, body)
	if body != nil {
		req.ContentLength = length
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return response{resp.StatusCode, resp.Header, b}
}

func (e *attEnv) upload(uid, token string, body []byte) response {
	e.t.Helper()
	return e.do(http.MethodPut, uid, "upload", token, bytes.NewReader(body), int64(len(body)))
}

func (e *attEnv) download(uid, token string) response {
	e.t.Helper()
	return e.do(http.MethodGet, uid, "download", token, nil, 0)
}

// record writes the stored commitment into status, as the controller does.
func (e *attEnv) record(name string) attachments.Receipt {
	e.t.Helper()
	a := e.get(name)
	r, err := e.store.Committed(context.Background(), e.ref(string(a.UID)))
	if err != nil {
		e.t.Fatal(err)
	}
	a.Status.Storage.Commitment = &v1alpha1.AttachmentCommitment{ManifestKey: r.ManifestKey, ManifestVersionID: r.ManifestVersionID,
		DocumentKey: r.DocumentKey, DocumentVersionID: r.DocumentVersionID, SHA256: r.Document.SHA256, Size: r.Document.Size,
		SpecDigest: r.SpecDigest, Uploader: v1alpha1.Requester{Username: r.Uploader.Username, UID: r.Uploader.UID},
		CommittedAt: metav1.NewTime(r.CommittedAt), Retention: metav1.Duration{Duration: r.Retention}, ExpiresAt: metav1.NewTime(r.ExpiresAt)}
	if err := e.c.Status().Update(context.Background(), a); err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *attEnv) staged() int {
	n := 0
	for _, c := range e.store.Calls() {
		if strings.HasPrefix(c, "Stage ") {
			n++
		}
	}
	return n
}

func (e *attEnv) tempEmpty() {
	e.t.Helper()
	left, _ := os.ReadDir(e.tmp)
	if len(left) != 0 {
		e.t.Fatalf("temporary files remain: %v", left)
	}
	e.srv.mu.Lock()
	defer e.srv.mu.Unlock()
	if e.srv.used != 0 {
		e.t.Fatalf("staging reservation leaked: %d", e.srv.used)
	}
}

func TestAttachmentUploadCommitsAsTheAuthenticatedCaller(t *testing.T) {
	e := newAttEnv(t)
	body := e.bodies["dc-north"]
	r := e.upload("att-north", "up", body)
	if r.code != http.StatusOK {
		t.Fatalf("upload: %d %s", r.code, r.body)
	}
	var got UploadReceipt
	if err := json.Unmarshal(r.body, &got); err != nil {
		t.Fatal(err)
	}
	a := e.get("dc-north")
	if got.Name != "dc-north" || got.UID != "att-north" || got.Uploader.Username != "uploader" || got.SHA256 != a.Spec.Document.SHA256 ||
		got.Size != int64(len(body)) || got.Retention != attachments.DefaultRetention.String() {
		t.Fatalf("receipt %+v", got)
	}
	if !got.ExpiresAt.Equal(a.Spec.Validity.ValidUntil.Add(attachments.DefaultRetention)) {
		t.Fatalf("expiry %s", got.ExpiresAt)
	}
	// The authenticated caller is the uploader; the registrant and the
	// declared source stay separate.
	stored, err := e.store.Committed(context.Background(), e.ref("att-north"))
	if err != nil || stored.Uploader.Username != "uploader" || stored.SpecDigest != attachments.SpecDigest(a.Spec) || stored.Ref.ClusterID != cluster {
		t.Fatalf("stored commitment %+v %v", stored, err)
	}
	// Exactly the archive routes' authorization shape, on the attachment's
	// own attributes.
	want := []string{"uploader create /evidenceattachments/upload/dc-north", "uploader get /evidenceattachments/dc-north"}
	if !slices.Equal(e.asked(), append(want, want...)) {
		t.Fatalf("reviews: %v", e.asked())
	}
	// A retry (for example after a lost response) returns the original
	// commitment and stages nothing new.
	e.now = e.now.Add(time.Hour)
	again := e.upload("att-north", "up", body)
	var second UploadReceipt
	_ = json.Unmarshal(again.body, &second)
	if again.code != http.StatusOK || !second.CommittedAt.Equal(got.CommittedAt) || !second.ExpiresAt.Equal(got.ExpiresAt) {
		t.Fatalf("retry: %d %s", again.code, again.body)
	}
	if e.store.Attempts(e.ref("att-north")) != 1 {
		t.Fatalf("retry staged another attempt: %v", e.store.Calls())
	}
	// Another authorized uploader's retry is answered with the first
	// uploader's commitment, never re-attributed.
	e.grant("downloader", "create", "upload", "dc-north")
	third := e.upload("att-north", "down", body)
	var other UploadReceipt
	_ = json.Unmarshal(third.body, &other)
	if third.code != http.StatusOK || other.Uploader.Username != "uploader" {
		t.Fatalf("second uploader: %d %s", third.code, third.body)
	}
	e.tempEmpty()
}

func TestAttachmentUploadAuthorization(t *testing.T) {
	e := newAttEnv(t)
	body := e.bodies["dc-north"]
	for _, c := range []struct {
		name, uid, token string
		code             int
	}{
		{"no token", "att-north", "", http.StatusUnauthorized},
		{"token not accepted for the audience", "att-north", "unknown", http.StatusUnauthorized},
		{"registrar without upload", "att-north", "reg", http.StatusForbidden},
		{"downloader", "att-north", "down", http.StatusForbidden},
		{"namespace team", "att-north", "team", http.StatusForbidden},
		{"grant for another record only", "att-north", "south", http.StatusForbidden},
		{"unknown UID", "att-missing", "up", http.StatusForbidden},
		{"a name is not an address", "dc-north", "up", http.StatusForbidden},
	} {
		t.Run(c.name, func(t *testing.T) {
			if r := e.upload(c.uid, c.token, body); r.code != c.code {
				t.Fatalf("got %d %s, want %d", r.code, r.body, c.code)
			}
		})
	}
	// The record grant alone is not enough, nor the upload grant alone.
	e.revoke("uploader", "get", "", "dc-north")
	if r := e.upload("att-north", "up", body); r.code != http.StatusForbidden {
		t.Fatalf("upload without record read: %d", r.code)
	}
	e.grant("uploader", "get", "", "dc-north")
	e.revoke("uploader", "create", "upload", "dc-north")
	if r := e.upload("att-north", "up", body); r.code != http.StatusForbidden {
		t.Fatalf("record read without upload: %d", r.code)
	}
	e.grant("uploader", "create", "upload", "dc-north")
	// Review outages fail closed.
	e.rev.down = true
	if r := e.upload("att-north", "up", body); r.code != http.StatusServiceUnavailable {
		t.Fatalf("review outage: %d", r.code)
	}
	e.rev.down = false
	if e.staged() != 0 {
		t.Fatalf("a denied upload was staged: %v", e.store.Calls())
	}
	// The south-only uploader can upload its own record.
	if r := e.upload("att-south", "south", e.bodies["dc-south"]); r.code != http.StatusOK {
		t.Fatalf("scoped uploader: %d %s", r.code, r.body)
	}
	e.tempEmpty()
}

// revokingReader revokes a grant before the server receives the bytes,
// after the request was first authorized.
type revokingReader struct {
	r    io.Reader
	once sync.Once
	f    func()
}

func (r *revokingReader) Read(p []byte) (int, error) {
	r.once.Do(r.f)
	return r.r.Read(p)
}

func TestAttachmentUploadRechecksAuthorizationAndRecord(t *testing.T) {
	e := newAttEnv(t)
	body := e.bodies["dc-north"]
	// Revoked while the bytes are in flight: nothing is staged.
	rd := &revokingReader{r: bytes.NewReader(body), f: func() {
		for deadline := time.Now().Add(5 * time.Second); len(e.asked()) < 2 && time.Now().Before(deadline); {
			time.Sleep(time.Millisecond)
		}
		e.rev.mu.Lock()
		delete(e.rev.grants, "uploader create /evidenceattachments/upload/dc-north")
		e.rev.mu.Unlock()
	}}
	if r := e.do(http.MethodPut, "att-north", "upload", "up", rd, int64(len(body))); r.code != http.StatusForbidden {
		t.Fatalf("revoked mid-transfer: %d %s", r.code, r.body)
	}
	if e.staged() != 0 || len(e.asked()) != 3 {
		t.Fatalf("a revoked upload was staged or not re-authorized: %v %v", e.store.Calls(), e.asked())
	}
	e.grant("uploader", "create", "upload", "dc-north")
	// Withdrawn after staging, before the commit: nothing is committed (the
	// controller's withdrawal removes the attempt).
	e.store.AfterStage = func(attachments.Ref) {
		e.store.AfterStage = nil
		if err := e.c.Delete(context.Background(), e.get("dc-north")); err != nil {
			t.Fatal(err)
		}
	}
	if r := e.upload("att-north", "up", body); r.code != http.StatusConflict || !strings.Contains(string(r.body), "withdrawn") {
		t.Fatalf("withdrawn after staging: %d %s", r.code, r.body)
	}
	if _, err := e.store.Committed(context.Background(), e.ref("att-north")); !errors.Is(err, attachments.ErrNotFound) {
		t.Fatalf("a withdrawn record was committed: %v", err)
	}
	// A withdrawn record accepts no upload at all: refused before any byte
	// is received (no second review).
	before := len(e.asked())
	if r := e.upload("att-north", "up", body); r.code != http.StatusConflict || !strings.Contains(string(r.body), "withdrawn") {
		t.Fatalf("withdrawn: %d %s", r.code, r.body)
	}
	if n := len(e.asked()) - before; n != 2 {
		t.Fatalf("a withdrawn record's upload was received (%d reviews)", n)
	}
	// Withdrawn while the commit lands: the caller is told; the commitment
	// is left for the controller to retain until its expiry.
	e.store.BeforeCommit = func(attachments.Ref) {
		e.store.BeforeCommit = nil
		if err := e.c.Delete(context.Background(), e.get("dc-south")); err != nil {
			t.Fatal(err)
		}
	}
	if r := e.upload("att-south", "up", e.bodies["dc-south"]); r.code != http.StatusConflict || !strings.Contains(string(r.body), "withdrawn") {
		t.Fatalf("withdrawn during commit: %d %s", r.code, r.body)
	}
	// Recreated under the same name during the upload: another identity.
	e.store.AfterStage = func(attachments.Ref) {
		e.store.AfterStage = nil
		old := e.get("big")
		old.Finalizers = nil
		_ = e.c.Update(context.Background(), old)
		_ = e.c.Delete(context.Background(), old)
		re := registered("big", "att-big-2", e.bodies["big"], old.Spec.Validity.ValidUntil.Time)
		if err := e.c.Create(context.Background(), re); err != nil {
			t.Fatal(err)
		}
	}
	e.srv.AttachmentLimits.MaxBytes = 4 << 10
	if r := e.upload("att-big", "up", e.bodies["big"]); r.code != http.StatusForbidden {
		t.Fatalf("recreated during upload: %d %s", r.code, r.body)
	}
	if _, err := e.store.Committed(context.Background(), e.ref("att-big")); !errors.Is(err, attachments.ErrNotFound) {
		t.Fatal("the replaced record's upload was committed")
	}
	// Not pinned yet: nothing can be stored, so nothing is accepted.
	if r := e.upload("att-unpinned", "up", e.bodies["unpinned"]); r.code != http.StatusConflict || !strings.Contains(string(r.body), "pinned") {
		t.Fatalf("unpinned: %d %s", r.code, r.body)
	}
	e.tempEmpty()
}

func TestAttachmentUploadVerifiesBytesBeforeStoring(t *testing.T) {
	e := newAttEnv(t)
	body := e.bodies["dc-north"]
	forged := bytes.Repeat([]byte("z"), len(body))
	chunked := func(b []byte) io.Reader { return io.MultiReader(bytes.NewReader(b)) }
	for _, c := range []struct {
		name   string
		body   io.Reader
		length int64
		code   int
	}{
		{"same size, other bytes", bytes.NewReader(forged), int64(len(forged)), http.StatusConflict},
		{"declared length differs", bytes.NewReader(append(body, 'x')), int64(len(body) + 1), http.StatusConflict},
		{"short, chunked", chunked(body[:10]), -1, http.StatusConflict},
		{"long, chunked", chunked(append(append([]byte{}, body...), "trailing"...)), -1, http.StatusConflict},
		{"empty", bytes.NewReader(nil), 0, http.StatusConflict},
	} {
		t.Run(c.name, func(t *testing.T) {
			if r := e.do(http.MethodPut, "att-north", "upload", "up", c.body, c.length); r.code != c.code {
				t.Fatalf("got %d %s, want %d", r.code, r.body, c.code)
			}
		})
	}
	// A registered size above the service limit is refused before reading.
	if r := e.upload("att-big", "up", e.bodies["big"]); r.code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over the limit: %d %s", r.code, r.body)
	}
	if e.staged() != 0 {
		t.Fatalf("unverified bytes reached storage: %v", e.store.Calls())
	}
	if _, err := e.store.Committed(context.Background(), e.ref("att-north")); !errors.Is(err, attachments.ErrNotFound) {
		t.Fatal("a falsely available document was committed")
	}
	// The correct bytes, chunked, are accepted.
	if r := e.do(http.MethodPut, "att-north", "upload", "up", chunked(body), -1); r.code != http.StatusOK {
		t.Fatalf("chunked upload: %d %s", r.code, r.body)
	}
	// Storage that refuses the bytes or the commit leaves nothing available.
	e.store.Fail(attfake.OpCommit, fmt.Errorf("%w: test outage", attachments.ErrUnavailable))
	if r := e.upload("att-south", "up", e.bodies["dc-south"]); r.code != http.StatusServiceUnavailable {
		t.Fatalf("commit outage: %d %s", r.code, r.body)
	}
	e.store.Fail(attfake.OpCommit, nil)
	if _, err := e.store.Committed(context.Background(), e.ref("att-south")); !errors.Is(err, attachments.ErrNotFound) {
		t.Fatal("committed during an outage")
	}
	e.store.Fail(attfake.OpStage, fmt.Errorf("%w: stored version differs", attachments.ErrIntegrity))
	if r := e.upload("att-south", "up", e.bodies["dc-south"]); r.code != http.StatusBadGateway {
		t.Fatalf("storage verification failure: %d %s", r.code, r.body)
	}
	e.store.Fail(attfake.OpStage, nil)
	// A different stored commitment under this UID is never replaced.
	e.store.Fail(attfake.OpCommit, fmt.Errorf("%w: another document", attachments.ErrConflict))
	if r := e.upload("att-south", "up", e.bodies["dc-south"]); r.code != http.StatusConflict {
		t.Fatalf("storage conflict: %d %s", r.code, r.body)
	}
	e.store.Fail(attfake.OpCommit, nil)
	e.tempEmpty()
}

// stallingBody sends part of a document and then blocks until released.
type stallingBody struct {
	first   []byte
	release chan struct{}
	started chan struct{}
	once    sync.Once
	stop    sync.Once
}

// unblock releases the body (idempotent).
func (s *stallingBody) unblock() { s.stop.Do(func() { close(s.release) }) }

func (s *stallingBody) Read(p []byte) (int, error) {
	if len(s.first) > 0 {
		n := copy(p, s.first)
		s.first = s.first[n:]
		return n, nil
	}
	s.once.Do(func() { close(s.started) })
	<-s.release
	return 0, io.ErrUnexpectedEOF
}

func TestAttachmentTransfersAreBounded(t *testing.T) {
	e := newAttEnv(t)
	body := e.bodies["dc-north"]
	if r := e.upload("att-south", "up", e.bodies["dc-south"]); r.code != http.StatusOK {
		t.Fatal(r.code)
	}
	e.record("dc-south")
	// Two stalled uploads hold this replica's two slots; a third transfer,
	// upload or download, is refused with Retry-After.
	var stalls []*stallingBody
	var wg sync.WaitGroup
	codes := make([]int, 2)
	e.srv.AttachmentLimits.Timeout = time.Hour
	for i := range 2 {
		s := &stallingBody{first: body[:8], release: make(chan struct{}), started: make(chan struct{})}
		stalls = append(stalls, s)
		t.Cleanup(s.unblock) // a failing check never leaves the server blocked
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/v1/evidenceattachments/att-north/upload", s)
			req.ContentLength = int64(len(body))
			req.Header.Set("Authorization", "Bearer up")
			if resp, err := e.ts.Client().Do(req); err == nil {
				codes[i] = resp.StatusCode
				resp.Body.Close()
			}
		}()
		<-s.started
	}
	waitSlots := func(n int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for len(e.srv.attSem) != n {
			if time.Now().After(deadline) {
				t.Fatalf("%d transfer slots in use, want %d", len(e.srv.attSem), n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitSlots(2)
	if r := e.upload("att-north", "up", body); r.code != http.StatusTooManyRequests || r.header.Get("Retry-After") == "" {
		t.Fatalf("saturated upload: %d %v", r.code, r.header)
	}
	if r := e.download("att-south", "down"); r.code != http.StatusTooManyRequests {
		t.Fatalf("saturated download: %d", r.code)
	}
	// Requests refused on their declaration are refused before taking a
	// slot or reading a byte.
	if r := e.do(http.MethodPut, "att-north", "upload", "up", bytes.NewReader(append(body, 'x')), int64(len(body)+1)); r.code != http.StatusConflict {
		t.Fatalf("declared length mismatch while saturated: %d", r.code)
	}
	if r := e.upload("att-big", "up", e.bodies["big"]); r.code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized while saturated: %d", r.code)
	}
	for _, s := range stalls {
		s.unblock()
	}
	wg.Wait()
	waitSlots(0)
	if e.staged() != 1 {
		t.Fatalf("an interrupted upload was staged: %v", e.store.Calls())
	}
	if r := e.download("att-south", "down"); r.code != http.StatusOK {
		t.Fatalf("download after release: %d", r.code)
	}
	// A transfer that outlives the deadline is cut off with nothing stored.
	e.srv.AttachmentLimits.Timeout = 300 * time.Millisecond
	s := &stallingBody{first: body[:8], release: make(chan struct{}), started: make(chan struct{})}
	t.Cleanup(s.unblock)
	go func() { <-s.started; time.Sleep(2 * time.Second); s.unblock() }()
	if r := e.do(http.MethodPut, "att-north", "upload", "up", s, int64(len(body))); r.code != http.StatusRequestTimeout {
		t.Fatalf("deadline: %d %s", r.code, r.body)
	}
	waitSlots(0)
	e.srv.AttachmentLimits.Timeout = 2 * time.Second
	// A client that disconnects mid-body leaves nothing staged and frees
	// its slot.
	conn, err := net.Dial("tcp", strings.TrimPrefix(e.ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "PUT /v1/evidenceattachments/att-north/upload HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer up\r\nContent-Length: %d\r\n\r\n%s", len(body), body[:10])
	waitSlots(1)
	conn.Close()
	waitSlots(0)
	if e.staged() != 1 {
		t.Fatalf("staged: %v", e.store.Calls())
	}
	if _, err := e.store.Committed(context.Background(), e.ref("att-north")); !errors.Is(err, attachments.ErrNotFound) {
		t.Fatal("an interrupted or timed-out upload was committed")
	}
	if r := e.upload("att-north", "up", body); r.code != http.StatusOK {
		t.Fatalf("after interrupted transfers: %d %s", r.code, r.body)
	}
	e.tempEmpty()
	for i, c := range codes {
		if c == http.StatusOK {
			t.Fatalf("stalled upload %d succeeded", i)
		}
	}
}

func TestAttachmentDownloadServesTheRecordedCommitmentPassively(t *testing.T) {
	e := newAttEnv(t)
	body := e.bodies["dc-north"]
	if r := e.download("att-north", "down"); r.code != http.StatusConflict {
		t.Fatalf("before any commitment: %d %s", r.code, r.body)
	}
	if r := e.upload("att-north", "up", body); r.code != http.StatusOK {
		t.Fatal(r.code)
	}
	// Committed in storage but not recorded yet: not served.
	if r := e.download("att-north", "down"); r.code != http.StatusConflict {
		t.Fatalf("unrecorded commitment: %d %s", r.code, r.body)
	}
	rec := e.record("dc-north")
	e.rev.asked = nil
	r := e.download("att-north", "down")
	if r.code != http.StatusOK || !bytes.Equal(r.body, body) {
		t.Fatalf("download: %d %q", r.code, r.body)
	}
	if want := []string{"downloader get /evidenceattachments/download/dc-north", "downloader get /evidenceattachments/dc-north"}; !slices.Equal(e.asked(), want) {
		t.Fatalf("reviews: %v", e.asked())
	}
	// An HTML document is never served as HTML.
	for k, v := range map[string]string{
		"Content-Type": "application/octet-stream", "X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store",
		"Content-Disposition": `attachment; filename="dc-north"`, "Content-Security-Policy": "default-src 'none'; sandbox",
		"X-Konstapel-Declared-Media-Type": "text/html", "X-Konstapel-Document-SHA256": rec.Document.SHA256,
		"X-Konstapel-Expires-At": rec.ExpiresAt.Format(time.RFC3339), "X-Konstapel-Attachment-UID": "att-north",
	} {
		if got := r.header.Get(k); got != v {
			t.Errorf("%s: %q, want %q", k, got, v)
		}
	}
	if r.header.Get("X-Konstapel-Withdrawn") != "" || r.header.Get("Repr-Digest") == "" {
		t.Errorf("headers %v", r.header)
	}
	for _, h := range r.header {
		for _, v := range h {
			if strings.Contains(v, e.store.Dest.Endpoint) || strings.Contains(v, rec.DocumentKey) {
				t.Fatalf("storage location disclosed: %v", r.header)
			}
		}
	}
	// Authorization: download and record read are both required.
	for token, code := range map[string]int{"up": http.StatusForbidden, "reg": http.StatusForbidden, "team": http.StatusForbidden, "": http.StatusUnauthorized} {
		if got := e.download("att-north", token); got.code != code {
			t.Fatalf("%q: %d", token, got.code)
		}
	}
	if got := e.download("att-missing", "down"); got.code != http.StatusForbidden {
		t.Fatalf("unknown UID: %d", got.code)
	}
	// Damaged storage is never served.
	e.store.Tamper(e.ref("att-north"), bytes.Repeat([]byte("z"), len(body)))
	if got := e.download("att-north", "down"); got.code != http.StatusBadGateway || bytes.Contains(got.body, []byte("z")) {
		t.Fatalf("tampered: %d %s", got.code, got.body)
	}
	e.store.Tamper(e.ref("att-north"), body[:5])
	if got := e.download("att-north", "down"); got.code != http.StatusBadGateway {
		t.Fatalf("truncated: %d", got.code)
	}
	e.store = e.newStore() // the manifest is gone
	if got := e.download("att-north", "down"); got.code != http.StatusServiceUnavailable {
		t.Fatalf("missing commitment: %d %s", got.code, got.body)
	}
	e.tempEmpty()
}

func TestAttachmentDownloadRefusesUnconfirmedOrExpiredDocuments(t *testing.T) {
	e := newAttEnv(t)
	for _, n := range []string{"dc-north", "dc-south"} {
		if r := e.upload(map[string]string{"dc-north": "att-north", "dc-south": "att-south"}[n], "up", e.bodies[n]); r.code != http.StatusOK {
			t.Fatal(r.code)
		}
		e.record(n)
	}
	// A recorded commitment that disagrees with storage (here: another
	// record's document version, a cross-attachment confusion) is refused.
	south := e.get("dc-south")
	north := e.get("dc-north")
	south.Status.Storage.Commitment.DocumentKey = north.Status.Storage.Commitment.DocumentKey
	south.Status.Storage.Commitment.DocumentVersionID = north.Status.Storage.Commitment.DocumentVersionID
	if err := e.c.Status().Update(context.Background(), south); err != nil {
		t.Fatal(err)
	}
	if r := e.download("att-south", "down"); r.code != http.StatusBadGateway {
		t.Fatalf("cross-attachment commitment: %d %s", r.code, r.body)
	}
	// A recorded commitment for other bytes than the immutable spec.
	north.Status.Storage.Commitment.SHA256 = "sha256:" + strings.Repeat("1", 64)
	if err := e.c.Status().Update(context.Background(), north); err != nil {
		t.Fatal(err)
	}
	calls := len(e.store.Calls())
	if r := e.download("att-north", "down"); r.code != http.StatusBadGateway || len(e.store.Calls()) != calls {
		t.Fatalf("inconsistent commitment: %d, storage calls %v", r.code, e.store.Calls()[calls:])
	}
	e.record("dc-north")
	// Withdrawn but retained: still served to authorized readers until the
	// fixed expiry, and marked withdrawn.
	if err := e.c.Delete(context.Background(), e.get("dc-north")); err != nil {
		t.Fatal(err)
	}
	r := e.download("att-north", "down")
	if r.code != http.StatusOK || r.header.Get("X-Konstapel-Withdrawn") != "true" {
		t.Fatalf("withdrawn, retained: %d %v", r.code, r.header)
	}
	// Storage unavailable.
	e.store.Fail(attfake.OpOpen, attachments.ErrUnavailable)
	if r := e.download("att-north", "down"); r.code != http.StatusServiceUnavailable {
		t.Fatalf("storage outage: %d", r.code)
	}
	e.store.Fail(attfake.OpOpen, nil)
	// Handed off to an operator: never contacted, never served.
	e.stores = func(context.Context, v1alpha1.DestinationReference) (attachments.Store, error) {
		return nil, fmt.Errorf("%w: %w", attachments.ErrUnavailable, publication.ErrOrphaned)
	}
	if r := e.download("att-north", "down"); r.code != http.StatusGone {
		t.Fatalf("orphaned: %d", r.code)
	}
	// A store for another destination than the pin is never used.
	other := attfake.New(func() time.Time { return e.now })
	other.Dest.ID = "other-destination"
	e.stores = func(context.Context, v1alpha1.DestinationReference) (attachments.Store, error) { return other, nil }
	if r := e.download("att-north", "down"); r.code != http.StatusServiceUnavailable || len(other.Calls()) != 0 {
		t.Fatalf("another destination: %d %v", r.code, other.Calls())
	}
	e.stores = func(context.Context, v1alpha1.DestinationReference) (attachments.Store, error) { return e.store, nil }
	// At and after the fixed expiry the source is no longer served.
	e.now = e.get("dc-north").Status.Storage.Commitment.ExpiresAt.Time
	calls = len(e.store.Calls())
	if r := e.download("att-north", "down"); r.code != http.StatusGone {
		t.Fatalf("expired: %d %s", r.code, r.body)
	}
	if len(e.store.Calls()) != calls {
		t.Fatalf("storage was read for an expired document: %v", e.store.Calls()[calls:])
	}
	e.tempEmpty()
}

// rawUpload uploads from any goroutine; it reports transport errors in the
// response instead of failing the test.
func (e *attEnv) rawUpload(uid, token string, body []byte) response {
	req, _ := http.NewRequest(http.MethodPut, e.ts.URL+"/v1/evidenceattachments/"+uid+"/upload", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := e.ts.Client().Do(req)
	if err != nil {
		return response{body: []byte(err.Error())}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return response{resp.StatusCode, resp.Header, b}
}

// Two authorized uploads of one record race, as on two replicas: both
// verify and stage their bytes, exactly one commitment is created, and both
// callers are answered with it (one of them as a retry would be).
func TestAttachmentConcurrentUploadsConvergeOnOneCommitment(t *testing.T) {
	e := newAttEnv(t)
	body := e.bodies["dc-north"]
	e.grant("downloader", "create", "upload", "dc-north")
	// Neither commits before both have staged.
	var mu sync.Mutex
	arrived, both := 0, make(chan struct{})
	e.store.AfterStage = func(attachments.Ref) {
		mu.Lock()
		if arrived++; arrived == 2 {
			close(both)
		}
		mu.Unlock()
		select {
		case <-both:
		case <-time.After(5 * time.Second):
		}
	}
	results := make([]response, 2)
	var wg sync.WaitGroup
	for i, token := range []string{"up", "down"} {
		wg.Add(1)
		go func() { defer wg.Done(); results[i] = e.rawUpload("att-north", token, body) }()
	}
	wg.Wait()
	var receipts [2]UploadReceipt
	for i, r := range results {
		if r.code != http.StatusOK {
			t.Fatalf("upload %d: %d %s", i, r.code, r.body)
		}
		if err := json.Unmarshal(r.body, &receipts[i]); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := e.store.Committed(context.Background(), e.ref("att-north"))
	if err != nil {
		t.Fatal(err)
	}
	if e.store.Attempts(e.ref("att-north")) != 2 {
		t.Fatalf("both uploads should have staged: %v", e.store.Calls())
	}
	for i, got := range receipts {
		if !got.CommittedAt.Equal(stored.CommittedAt) || got.Uploader != stored.Uploader || got.SHA256 != stored.Document.SHA256 {
			t.Fatalf("upload %d answered with %+v, the commitment is %+v", i, got, stored)
		}
	}
	if u := stored.Uploader.Username; u != "uploader" && u != "downloader" {
		t.Fatalf("committed uploader %q", u)
	}
	// The controller records that one commitment, and it is what is served.
	e.store.AfterStage = nil
	e.record("dc-north")
	if r := e.download("att-north", "down"); r.code != http.StatusOK || !bytes.Equal(r.body, body) {
		t.Fatalf("download: %d", r.code)
	}
	e.tempEmpty()
}

// The commit was created but its response was lost: the caller gets a
// retryable failure, and the retry returns that commitment without staging
// or committing anything new.
func TestAttachmentUploadAfterALostCommitResponse(t *testing.T) {
	e := newAttEnv(t)
	body := e.bodies["dc-north"]
	e.store.LoseCommitResponse = fmt.Errorf("%w: connection reset after the commit", attachments.ErrUnavailable)
	if r := e.upload("att-north", "up", body); r.code != http.StatusServiceUnavailable || r.header.Get("Retry-After") == "" {
		t.Fatalf("lost commit response: %d %s", r.code, r.body)
	}
	stored, err := e.store.Committed(context.Background(), e.ref("att-north"))
	if err != nil {
		t.Fatalf("the commitment itself was not kept: %v", err)
	}
	calls := len(e.store.Calls())
	e.now = e.now.Add(10 * time.Minute)
	r := e.upload("att-north", "up", body)
	var got UploadReceipt
	_ = json.Unmarshal(r.body, &got)
	if r.code != http.StatusOK || !got.CommittedAt.Equal(stored.CommittedAt) || !got.ExpiresAt.Equal(stored.ExpiresAt) {
		t.Fatalf("retry: %d %s, stored %+v", r.code, r.body, stored)
	}
	for _, c := range e.store.Calls()[calls:] {
		if !strings.HasPrefix(c, "Committed ") {
			t.Fatalf("the retry wrote to storage: %v", e.store.Calls()[calls:])
		}
	}
	e.tempEmpty()
}

// A destination handed off to an operator (deletionPolicy: Orphan) is never
// written to again, also when the handoff happens during an upload.
func TestAttachmentUploadNeverWritesAHandedOffDestination(t *testing.T) {
	e := newAttEnv(t)
	body := e.bodies["dc-north"]
	pinned := e.stores
	orphaned := func(context.Context, v1alpha1.DestinationReference) (attachments.Store, error) {
		return nil, fmt.Errorf("%w: %w: handed off", attachments.ErrUnavailable, publication.ErrOrphaned)
	}
	e.stores = orphaned
	if r := e.upload("att-north", "up", body); r.code != http.StatusGone {
		t.Fatalf("handed off before the upload: %d %s", r.code, r.body)
	}
	if e.staged() != 0 {
		t.Fatalf("staged into a handed-off destination: %v", e.store.Calls())
	}
	// Handed off after staging, before the commit.
	e.stores = pinned
	e.store.AfterStage = func(attachments.Ref) {
		e.store.AfterStage = nil
		e.stores = orphaned
	}
	if r := e.upload("att-north", "up", body); r.code != http.StatusGone {
		t.Fatalf("handed off during the upload: %d %s", r.code, r.body)
	}
	for _, c := range e.store.Calls() {
		if strings.HasPrefix(c, "Commit ") {
			t.Fatalf("committed into a handed-off destination: %v", e.store.Calls())
		}
	}
	e.tempEmpty()
}

// endless is a request body that never ends.
type endless struct{}

func (endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

// countingBody counts the bytes the handler reads from a request body.
type countingBody struct {
	io.ReadCloser
	n *atomic.Int64
}

func (c countingBody) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// An undeclared (chunked) body is read only up to the registered size plus
// one byte, however much the client sends.
func TestAttachmentUploadReadsAtMostTheRegisteredSize(t *testing.T) {
	e := newAttEnv(t)
	var read atomic.Int64
	h := e.srv.Handler()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = countingBody{r.Body, &read}
		h.ServeHTTP(w, r)
	}))
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/v1/evidenceattachments/att-north/upload", endless{})
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer up")
	// The server may close the connection before the client stops sending;
	// either way the upload must fail.
	if resp, err := ts.Client().Do(req); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("endless body: %d", resp.StatusCode)
		}
	}
	if n, size := read.Load(), int64(len(e.bodies["dc-north"])); n > size+1 {
		t.Fatalf("read %d bytes of a %d-byte registration", n, size)
	}
	if e.staged() != 0 {
		t.Fatalf("staged: %v", e.store.Calls())
	}
	e.tempEmpty()
}

// The record's pin is immutable at the API; should status nevertheless
// name another destination mid-upload, nothing is committed. Storage that
// already holds a commitment for another registration under this UID is
// never answered as this upload's commitment.
func TestAttachmentUploadRefusesAChangedPinOrAForeignCommitment(t *testing.T) {
	e := newAttEnv(t)
	body := e.bodies["dc-north"]
	e.store.AfterStage = func(attachments.Ref) {
		e.store.AfterStage = nil
		a := e.get("dc-north")
		a.Status.Storage.Destination = &v1alpha1.DestinationReference{Name: "secondary", UID: "dest-uid-2"}
		if err := e.c.Status().Update(context.Background(), a); err != nil {
			t.Error(err)
		}
	}
	if r := e.upload("att-north", "up", body); r.code != http.StatusConflict || !strings.Contains(string(r.body), "pin changed") {
		t.Fatalf("pin changed: %d %s", r.code, r.body)
	}
	if _, err := e.store.Committed(context.Background(), e.ref("att-north")); !errors.Is(err, attachments.ErrNotFound) {
		t.Fatal("committed after the pin changed")
	}
	// dc-south's UID already holds a commitment of another registration
	// (same bytes, another spec): refused, preserved, nothing staged.
	south := e.get("dc-south")
	other := south.Spec.DeepCopy()
	other.Scope.Description = "DC South, another registration"
	sbody := e.bodies["dc-south"]
	if _, err := e.store.Stage(context.Background(), attachments.StageRequest{Ref: e.ref("att-south"), Document: attachments.Expected(south.Spec),
		Uploader: attachments.Principal{Username: "someone"}, Body: bytes.NewReader(sbody)}); err != nil {
		t.Fatal(err)
	}
	foreign, err := e.store.Commit(context.Background(), attachments.CommitRequest{Ref: e.ref("att-south"), SpecDigest: attachments.SpecDigest(*other),
		Document: attachments.Expected(south.Spec), ValidUntil: south.Spec.Validity.ValidUntil.Time, Retention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	staged := e.staged()
	if r := e.upload("att-south", "up", sbody); r.code != http.StatusConflict || !strings.Contains(string(r.body), "different commitment") {
		t.Fatalf("foreign commitment: %d %s", r.code, r.body)
	}
	if got, _ := e.store.Committed(context.Background(), e.ref("att-south")); got != foreign || e.staged() != staged {
		t.Fatalf("the foreign commitment was replaced or another attempt staged: %+v %v", got, e.store.Calls())
	}
	e.tempEmpty()
}

func TestAttachmentRoutesNeedAStore(t *testing.T) {
	srv := &Server{Reader: fake.NewClientBuilder().WithScheme(scheme()).Build(), Reviews: &reviews{}, TempDir: t.TempDir()}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/v1/evidenceattachments/x/download")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("attachment routes served without a store: %d", resp.StatusCode)
	}
}

func TestAttachmentLimitsValidate(t *testing.T) {
	if err := DefaultAttachmentLimits().Validate(2 << 30); err != nil {
		t.Fatal(err)
	}
	d := DefaultAttachmentLimits()
	if d.MaxBytes != 32<<20 || d.Timeout != 5*time.Minute || d.MaxConcurrent != 2 || d.Retention != 2160*time.Hour {
		t.Fatalf("defaults %+v", d)
	}
	for name, edit := range map[string]func(*AttachmentLimits){
		"zero size":            func(l *AttachmentLimits) { l.MaxBytes = 0 },
		"above the API":        func(l *AttachmentLimits) { l.MaxBytes = MaxAttachmentBytes + 1 },
		"above temp storage":   func(l *AttachmentLimits) { l.MaxBytes = 64 << 20 },
		"sub-second timeout":   func(l *AttachmentLimits) { l.Timeout = time.Millisecond },
		"unbounded timeout":    func(l *AttachmentLimits) { l.Timeout = 2 * time.Hour },
		"no concurrency":       func(l *AttachmentLimits) { l.MaxConcurrent = 0 },
		"too much concurrency": func(l *AttachmentLimits) { l.MaxConcurrent = 65 },
		"zero retention":       func(l *AttachmentLimits) { l.Retention = 0 },
		"fractional retention": func(l *AttachmentLimits) { l.Retention = 1500 * time.Millisecond },
	} {
		l := DefaultAttachmentLimits()
		edit(&l)
		if err := l.Validate(48 << 20); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	l := DefaultAttachmentLimits()
	l.MaxBytes, l.Timeout, l.MaxConcurrent, l.Retention = 1<<30, time.Hour, 64, 24*time.Hour
	if err := l.Validate(2 << 30); err != nil {
		t.Fatalf("raised limits: %v", err)
	}
}
