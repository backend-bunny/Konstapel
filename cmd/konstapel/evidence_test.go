package main

// add-supporting-evidence-attachments 3.3/3.4: the `konstapel evidence`
// commands against a fake Kubernetes API and the real download.Server
// attachment routes (in-memory store) over TLS.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
	attfake "github.com/backend-bunny/Konstapel/internal/attachments/fake"
	"github.com/backend-bunny/Konstapel/internal/download"
)

// grants is a fake reviewer: token -> user, and allowed
// "user verb resource/subresource name" tuples.
type grants struct {
	users   map[string]string
	allowed map[string]bool
}

func (g grants) Authenticate(_ context.Context, token string) (authnv1.UserInfo, error) {
	u, ok := g.users[token]
	if !ok {
		return authnv1.UserInfo{}, download.ErrUnauthenticated
	}
	return authnv1.UserInfo{Username: u, UID: "uid-" + u}, nil
}

func (g grants) Authorize(_ context.Context, u authnv1.UserInfo, a authzv1.ResourceAttributes) (bool, error) {
	r := a.Resource
	if a.Subresource != "" {
		r += "/" + a.Subresource
	}
	return g.allowed[u.Username+" "+a.Verb+" "+r+" "+a.Name], nil
}

type cliEnv struct {
	t       *testing.T
	dir     string
	c       client.Client
	store   *attfake.Store
	ts      *httptest.Server
	urlHits atomic.Int32
	// requests counts requests that reached the download service.
	requests atomic.Int32
	// serve, when set, answers instead of the download service.
	serve  http.HandlerFunc
	source *httptest.Server
	doc    []byte
}

func newCLIEnv(t *testing.T) *cliEnv {
	e := &cliEnv{t: t, dir: t.TempDir(), doc: []byte("%PDF-1.7 DC North physical access control audit 2026")}
	// The declared source URL: never to be fetched by any command.
	e.source = httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { e.urlHits.Add(1) }))
	t.Cleanup(e.source.Close)
	s := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(s)
	var seq atomic.Int32
	binding := &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "baseline-audit", UID: "uid-binding-1"}}
	e.c = fake.NewClientBuilder().WithScheme(s).WithObjects(binding).WithStatusSubresource(&v1alpha1.EvidenceAttachment{}).
		WithInterceptorFuncs(interceptor.Funcs{Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			// The API server assigns UIDs and, through admission, the
			// registrant.
			if a, ok := obj.(*v1alpha1.EvidenceAttachment); ok {
				a.Spec.RegisteredBy = &v1alpha1.Requester{Username: "platform-registrar", UID: "uid-registrar"}
				for _, o := range opts {
					if o == client.DryRunAll {
						return nil
					}
				}
				a.SetUID(types.UID("uid-att-" + string(rune('0'+seq.Add(1)))))
			}
			return c.Create(ctx, obj, opts...)
		}}).Build()
	clock := func() time.Time { return time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC) }
	e.store = attfake.New(clock)
	e.store.Dest.ID = "dest-uid"
	g := grants{users: map[string]string{"up": "platform-uploader", "down": "platform-auditor"}, allowed: map[string]bool{}}
	for _, u := range []string{"platform-uploader", "platform-auditor"} {
		for _, name := range []string{"dc-north-2026", "dc-north-2026-b"} {
			g.allowed[u+" get evidenceattachments "+name] = true
		}
	}
	g.allowed["platform-uploader create evidenceattachments/upload dc-north-2026"] = true
	g.allowed["platform-auditor get evidenceattachments/download dc-north-2026"] = true
	srv := &download.Server{Reader: e.c, Reviews: g, TempDir: t.TempDir(), Cluster: "kube-system:cluster-1", Now: clock,
		AttachmentStores: func(context.Context, v1alpha1.DestinationReference) (attachments.Store, error) { return e.store, nil }}
	h := srv.Handler()
	e.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.requests.Add(1)
		if e.serve != nil {
			e.serve(w, r)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(e.ts.Close)
	e.write("dc-north-2026.pdf", e.doc)
	e.write("up.token", []byte("up\n"))
	e.write("down.token", []byte("down"))
	e.write("attachment.yaml", []byte(`apiVersion: compliance.erenius.io/v1alpha1
kind: EvidenceAttachment
metadata:
  name: dc-north-2026
spec:
  document:
    title: DC North physical access control audit 2026
    mediaType: application/pdf
  source:
    issuer: Example Audit AB
    url: `+e.source.URL+`/reports/dc-north-2026
  validity:
    validFrom: "2026-01-01T00:00:00Z"
    validUntil: "2027-01-01T00:00:00Z"
  scope:
    description: DC North halls A and B
  associations:
    - binding: {name: baseline-audit}
      catalogDigest: sha256:64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb
      controls:
        - id: pe-3
`))
	return e
}

func (e *cliEnv) write(name string, b []byte) string {
	p := filepath.Join(e.dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *cliEnv) path(name string) string { return filepath.Join(e.dir, name) }

// run runs one command; transfer commands get the test server's client.
func (e *cliEnv) run(args ...string) (string, error) {
	var out, errOut bytes.Buffer
	cmd := &evidenceCmd{stdout: &out, stderr: &errOut, newClient: func() (client.Client, error) { return e.c, nil }, http: e.ts.Client()}
	err := cmd.run(args)
	return out.String() + errOut.String(), err
}

func (e *cliEnv) transfer(op, name, uid, token string, extra ...string) (string, error) {
	return e.run(append([]string{op, name, "--uid", uid, "--server", e.ts.URL, "--token-file", e.path(token + ".token")}, extra...)...)
}

func (e *cliEnv) record(name string) *v1alpha1.EvidenceAttachment {
	a := &v1alpha1.EvidenceAttachment{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, a); err != nil {
		e.t.Fatal(err)
	}
	return a
}

// pinAndRecord stands in for the controller: the pin before upload, the
// commitment read from storage after it.
func (e *cliEnv) pin(name string) {
	a := e.record(name)
	a.Status.Storage = &v1alpha1.AttachmentStorage{Destination: &v1alpha1.DestinationReference{Name: "primary", UID: "dest-uid"}, DestinationID: "dest-uid"}
	if err := e.c.Status().Update(context.Background(), a); err != nil {
		e.t.Fatal(err)
	}
}

func (e *cliEnv) recordCommitment(name string) {
	a := e.record(name)
	r, err := e.store.Committed(context.Background(), attachments.Ref{ClusterID: "kube-system:cluster-1", UID: string(a.UID)})
	if err != nil {
		e.t.Fatal(err)
	}
	a.Status.Storage.Commitment = &v1alpha1.AttachmentCommitment{ManifestKey: r.ManifestKey, DocumentKey: r.DocumentKey, DocumentVersionID: r.DocumentVersionID,
		SHA256: r.Document.SHA256, Size: r.Document.Size, SpecDigest: r.SpecDigest, Uploader: v1alpha1.Requester{Username: r.Uploader.Username, UID: r.Uploader.UID},
		CommittedAt: metav1.NewTime(r.CommittedAt), Retention: metav1.Duration{Duration: r.Retention}, ExpiresAt: metav1.NewTime(r.ExpiresAt)}
	if err := e.c.Status().Update(context.Background(), a); err != nil {
		e.t.Fatal(err)
	}
}

func TestEvidenceWorkflow(t *testing.T) {
	e := newCLIEnv(t)
	sum := sha256.Sum256(e.doc)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	// Register: a reviewable dry run first, then the record. The document
	// identity comes from the file and the binding UID from the cluster.
	out, err := e.run("register", "-f", e.path("attachment.yaml"), "--document", e.path("dc-north-2026.pdf"), "--dry-run")
	if err != nil || !strings.Contains(out, "nothing was created") || !strings.Contains(out, digest) || !strings.Contains(out, "uid: uid-binding-1") {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	var list v1alpha1.EvidenceAttachmentList
	_ = e.c.List(context.Background(), &list)
	if len(list.Items) != 0 {
		t.Fatal("a dry run created the record")
	}
	out, err = e.run("register", "-f", e.path("attachment.yaml"), "--document", e.path("dc-north-2026.pdf"))
	if err != nil || !strings.Contains(out, "evidenceattachment/dc-north-2026 created") {
		t.Fatalf("register: %v\n%s", err, out)
	}
	a := e.record("dc-north-2026")
	uid := string(a.UID)
	if a.Spec.Document.SHA256 != digest || a.Spec.Document.Size != int64(len(e.doc)) || a.Spec.Associations[0].Binding.UID != "uid-binding-1" ||
		!strings.Contains(out, "uid: "+uid) || !strings.Contains(out, "registeredBy: platform-registrar") {
		t.Fatalf("registered %+v\n%s", a.Spec, out)
	}

	// Upload waits for the controller to pin a destination, and gives up
	// with the reason, sending nothing.
	before := e.requests.Load()
	if out, err := e.transfer("upload", "dc-north-2026", uid, "up", "--file", e.path("dc-north-2026.pdf"), "--pin-wait", "0s"); err == nil ||
		!strings.Contains(err.Error(), "no pinned storage destination") || e.requests.Load() != before {
		t.Fatalf("unpinned upload: %v %s", err, out)
	}
	// Exact record UID: a stale or foreign UID is refused before sending.
	if _, err := e.transfer("upload", "dc-north-2026", "uid-other", "up", "--file", e.path("dc-north-2026.pdf")); err == nil || !strings.Contains(err.Error(), "recreated") {
		t.Fatalf("wrong UID: %v", err)
	}
	// Another file than the registered one is refused before sending.
	other := e.write("other.pdf", []byte("%PDF-1.7 another document"))
	if _, err := e.transfer("upload", "dc-north-2026", uid, "up", "--file", other); err == nil || !strings.Contains(err.Error(), "nothing was sent") {
		t.Fatalf("wrong file: %v", err)
	}
	if e.requests.Load() != before {
		t.Fatal("a refused upload reached the service")
	}
	pinned := make(chan struct{})
	go func() { time.Sleep(1500 * time.Millisecond); e.pin("dc-north-2026"); close(pinned) }()
	// Downloaders cannot upload; the hint names the role.
	if _, err := e.transfer("upload", "dc-north-2026", uid, "down", "--file", e.path("dc-north-2026.pdf")); err == nil || !strings.Contains(err.Error(), "403") ||
		!strings.Contains(err.Error(), "konstapel-evidence-attachment-uploader") {
		t.Fatalf("downloader uploading: %v", err)
	}
	<-pinned
	if n := e.store.Attempts(attachments.Ref{ClusterID: "kube-system:cluster-1", UID: uid}); n != 0 {
		t.Fatalf("refused uploads reached storage: %d", n)
	}
	first, err := e.transfer("upload", "dc-north-2026", uid, "up", "--file", e.path("dc-north-2026.pdf"))
	if err != nil || !strings.Contains(first, "uploader: platform-uploader") || !strings.Contains(first, "expiresAt: 2027-04-01T00:00:00Z") {
		t.Fatalf("upload: %v\n%s", err, first)
	}
	// A rerun after a lost response converges on the same commitment.
	again, err := e.transfer("upload", "dc-north-2026", uid, "up", "--file", e.path("dc-north-2026.pdf"))
	if err != nil || again != first {
		t.Fatalf("retry: %v\n%s\nwant\n%s", err, again, first)
	}

	// Download: only after the controller recorded the commitment.
	if _, err := e.transfer("download", "dc-north-2026", uid, "down", "--output", e.path("early.pdf")); err == nil || !strings.Contains(err.Error(), "not committed") {
		t.Fatalf("download before recording: %v", err)
	}
	if _, err := os.Stat(e.path("early.pdf")); !os.IsNotExist(err) {
		t.Fatal("a failed download wrote its output")
	}
	e.recordCommitment("dc-north-2026")
	if _, err := e.transfer("download", "dc-north-2026", uid, "up", "--output", e.path("copy.pdf")); err == nil || !strings.Contains(err.Error(), "konstapel-evidence-attachment-downloader") {
		t.Fatalf("uploader downloading: %v", err)
	}
	out, err = e.transfer("download", "dc-north-2026", uid, "down", "--output", e.path("copy.pdf"))
	if err != nil || !strings.Contains(out, "verified against evidenceattachment/dc-north-2026") {
		t.Fatalf("download: %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(e.path("copy.pdf")); !bytes.Equal(got, e.doc) {
		t.Fatal("downloaded bytes differ")
	}
	// An existing output is never replaced, and nothing is fetched for it.
	before = e.requests.Load()
	if _, err := e.transfer("download", "dc-north-2026", uid, "down", "--output", e.path("copy.pdf")); err == nil || !strings.Contains(err.Error(), "choose a new --output") ||
		e.requests.Load() != before {
		t.Fatalf("overwrite: %v", err)
	}
	// Bytes that are not the registered document are never written, even
	// from a service that claims success.
	for name, body := range map[string][]byte{"other bytes": []byte("%PDF-1.7 a substituted document!!!!!!!!!!!!!!!!!!!!!"), "truncated": e.doc[:9]} {
		e.serve = func(w http.ResponseWriter, _ *http.Request) {
			d := sha256.Sum256(body)
			w.Header().Set("Repr-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(d[:])+":")
			_, _ = w.Write(body)
		}
		if _, err := e.transfer("download", "dc-north-2026", uid, "down", "--output", e.path("bad.pdf")); err == nil || !strings.Contains(err.Error(), "nothing was written") {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := os.Stat(e.path("bad.pdf")); !os.IsNotExist(err) {
			t.Fatalf("%s: unverified bytes were written", name)
		}
	}
	e.serve = nil
	// Status shows the three identities distinctly.
	out, err = e.run("status", "dc-north-2026", "--uid", uid)
	for _, want := range []string{"Registered by: platform-registrar", "by platform-uploader", "Example Audit AB (declared, not authenticated)", "(informational; never fetched)", "binding baseline-audit (uid uid-binding-1)"} {
		if err != nil || !strings.Contains(out, want) {
			t.Fatalf("status lacks %q: %v\n%s", want, err, out)
		}
	}
	out, err = e.run("status", "dc-north-2026", "-o", "json")
	var st struct {
		UID    string                            `json:"uid"`
		Status v1alpha1.EvidenceAttachmentStatus `json:"status"`
	}
	if err != nil || json.Unmarshal([]byte(out), &st) != nil || st.UID != uid || st.Status.Storage.Commitment.Uploader.Username != "platform-uploader" {
		t.Fatalf("status json: %v\n%s", err, out)
	}
	if _, err := e.run("status", "dc-north-2026", "--uid", "uid-other"); err == nil {
		t.Fatal("status accepted another UID")
	}
	// A withdrawn record (kept by the controller's retention finalizer) is
	// refused before anything is sent.
	held := e.record("dc-north-2026")
	held.Finalizers = []string{v1alpha1.EvidenceAttachmentFinalizer}
	if err := e.c.Update(context.Background(), held); err != nil {
		t.Fatal(err)
	}
	if err := e.c.Delete(context.Background(), held); err != nil {
		t.Fatal(err)
	}
	before = e.requests.Load()
	if _, err := e.transfer("upload", "dc-north-2026", uid, "up", "--file", e.path("dc-north-2026.pdf")); err == nil || !strings.Contains(err.Error(), "withdrawn") ||
		e.requests.Load() != before {
		t.Fatalf("withdrawn upload: %v", err)
	}
	if n := e.urlHits.Load(); n != 0 {
		t.Fatalf("the declared source URL was fetched %d times", n)
	}
}

func TestEvidenceRegisterRefusesUnsafeInput(t *testing.T) {
	e := newCLIEnv(t)
	manifest, _ := os.ReadFile(e.path("attachment.yaml"))
	for name, c := range map[string]struct {
		manifest string
		want     string
	}{
		"replaced binding": {strings.Replace(string(manifest), "{name: baseline-audit}", "{name: baseline-audit, uid: uid-binding-0}", 1), "was recreated"},
		"missing binding":  {strings.Replace(string(manifest), "{name: baseline-audit}", "{name: no-such-binding}", 1), "not found"},
		"forged registrant": {strings.Replace(string(manifest), "  scope:", "  registeredBy: {username: someone-else}\n  scope:", 1),
			"admission records the authenticated registrant"},
		"other document":  {strings.Replace(string(manifest), "    mediaType: application/pdf", "    mediaType: application/pdf\n    size: 7", 1), "register the file you will upload"},
		"unknown field":   {strings.Replace(string(manifest), "  scope:", "  content: JVBERi0=\n  scope:", 1), "unknown field"},
		"status supplied": {string(manifest) + "status:\n  observedGeneration: 3\n", "only the controller writes it"},
		"another kind":    {strings.Replace(string(manifest), "kind: EvidenceAttachment", "kind: ComplianceException", 1), "kind EvidenceAttachment"},
	} {
		t.Run(name, func(t *testing.T) {
			p := e.write(strings.ReplaceAll(name, " ", "-")+".yaml", []byte(c.manifest))
			if out, err := e.run("register", "-f", p, "--document", e.path("dc-north-2026.pdf")); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v %s, want %q", err, out, c.want)
			}
		})
	}
	var list v1alpha1.EvidenceAttachmentList
	_ = e.c.List(context.Background(), &list)
	if len(list.Items) != 0 {
		t.Fatalf("refused registrations created records: %d", len(list.Items))
	}
}

func TestEvidenceTransferInputs(t *testing.T) {
	e := newCLIEnv(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"upload", "x", "--uid", "u", "--file", "f", "--server", "http://download.example.internal", "--token-file", e.path("up.token")}, "must be an https:// URL"},
		{[]string{"upload", "x", "--uid", "u", "--file", "f", "--token-file", e.path("up.token")}, "--server and --token-file are required"},
		{[]string{"upload", "x", "--file", "f"}, "--uid"},
		{[]string{"download", "x", "y", "--uid", "u"}, "expected one EvidenceAttachment name"},
		{[]string{"download", "--uid", "u", "--output", "o"}, "expected one EvidenceAttachment name"},
		{[]string{"status"}, "expected one EvidenceAttachment name"},
		{[]string{"frobnicate"}, "unknown evidence command"},
		{nil, "a command is required"},
	} {
		if _, err := e.run(c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v, want %q", c.args, err, c.want)
		}
	}
	empty := e.write("empty.token", nil)
	if _, err := e.run("upload", "x", "--uid", "u", "--file", "f", "--server", e.ts.URL, "--token-file", empty); err == nil || !strings.Contains(err.Error(), "--audience konstapel-download") {
		t.Errorf("empty token: %v", err)
	}
}

// Kubeconfig handling follows kubectl: --kubeconfig, else KUBECONFIG; the
// current context unless --context names another; an unknown context is an
// actionable error, never a fallback.
func TestEvidenceKubeconfigAndContext(t *testing.T) {
	dir := t.TempDir()
	kc := func(name, current string) string {
		p := filepath.Join(dir, name)
		cfg := `apiVersion: v1
kind: Config
current-context: ` + current + `
clusters:
- name: a
  cluster: {server: "https://a.example.internal:6443"}
- name: b
  cluster: {server: "https://b.example.internal:6443"}
users:
- name: u
  user: {token: t}
contexts:
- name: platform-a
  context: {cluster: a, user: u}
- name: platform-b
  context: {cluster: b, user: u}
`
		if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	explicit, fromEnv := kc("explicit", "platform-a"), kc("env", "platform-b")
	t.Setenv("KUBECONFIG", fromEnv)
	for _, c := range []struct {
		kubeconfig, context, host string
	}{
		{"", "", "https://b.example.internal:6443"},
		{"", "platform-a", "https://a.example.internal:6443"},
		{explicit, "", "https://a.example.internal:6443"},
		{explicit, "platform-b", "https://b.example.internal:6443"},
	} {
		cfg, err := (&evidenceCmd{kubeconfig: c.kubeconfig, context: c.context}).restConfig()
		if err != nil || cfg.Host != c.host || cfg.UserAgent != "konstapel-evidence" {
			t.Errorf("%+v: %v %v", c, cfg, err)
		}
	}
	if _, err := (&evidenceCmd{kubeconfig: explicit, context: "missing"}).restConfig(); err == nil || !strings.Contains(err.Error(), "--context") {
		t.Errorf("unknown context: %v", err)
	}
	if _, err := (&evidenceCmd{kubeconfig: filepath.Join(dir, "absent")}).restConfig(); err == nil || !strings.Contains(err.Error(), "--kubeconfig") {
		t.Errorf("absent kubeconfig: %v", err)
	}
}

// `konstapel evidence` is dispatched before the C2P provider is started:
// with no provider manifest present, the command still reaches its own
// kubeconfig handling.
func TestEvidenceStartsNoProviderOrDelivery(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // bin/c2p-konstapel-kyverno-manifest.json does not exist here
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = []string{"konstapel", "evidence", "status", "dc-north", "--kubeconfig", filepath.Join(dir, "absent")}
	err := run()
	if err == nil || !strings.Contains(err.Error(), "kubeconfig") || strings.Contains(err.Error(), "manifest") || strings.Contains(err.Error(), "provider") {
		t.Fatalf("evidence dispatch: %v", err)
	}
}
