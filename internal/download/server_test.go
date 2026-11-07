package download

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	pubfake "github.com/backend-bunny/Konstapel/internal/publication/fake"
)

// reviews is a fake Reviewer: tokens map to users, and grants lists the
// "user verb ns/resource/subresource/name" tuples that are allowed.
type reviews struct {
	tokens map[string]string
	grants map[string]bool
	down   bool
	asked  []string
}

func key(user string, a authzv1.ResourceAttributes) string {
	r := a.Resource
	if a.Subresource != "" {
		r += "/" + a.Subresource
	}
	return user + " " + a.Verb + " " + a.Namespace + "/" + r + "/" + a.Name
}

func (f *reviews) Authenticate(_ context.Context, token string) (authnv1.UserInfo, error) {
	if f.down {
		return authnv1.UserInfo{}, errors.New("apiserver unreachable")
	}
	u, ok := f.tokens[token]
	if !ok {
		return authnv1.UserInfo{}, ErrUnauthenticated
	}
	return authnv1.UserInfo{Username: u}, nil
}

func (f *reviews) Authorize(_ context.Context, u authnv1.UserInfo, a authzv1.ResourceAttributes) (bool, error) {
	if a.Group != v1alpha1.GroupVersion.Group {
		return false, errors.New("wrong group")
	}
	f.asked = append(f.asked, key(u.Username, a))
	return f.grants[key(u.Username, a)], nil
}

type env struct {
	t       *testing.T
	c       client.Client
	pub     *pubfake.Publisher
	rev     *reviews
	srv     *Server
	h       http.Handler
	now     time.Time
	nsRun   publication.RunRef
	archive []byte
}

const fixtures = "../../testdata/publication"

func scheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = v1alpha1.AddToScheme(s)
	return s
}

// newEnv publishes the namespace-complete fixture as team "dev"'s request
// "nightly" and the binding-no-targets fixture as a platform run.
func newEnv(t *testing.T) *env {
	e := &env{t: t, now: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)}
	e.pub = pubfake.New(func() time.Time { return e.now })
	commit := func(dir string) (publication.RunRef, v1alpha1.PublicationStatus, string) {
		d, err := publication.LoadDescriptor(filepath.Join(fixtures, dir))
		if err != nil {
			t.Fatal(err)
		}
		s, err := e.pub.Stage(context.Background(), publication.StageRequest{Run: d.Run, Dir: filepath.Join(fixtures, dir)})
		if err != nil {
			t.Fatal(err)
		}
		r, err := e.pub.Publish(context.Background(), publication.PublishRequest{Staged: s,
			Retention: publication.Retention{Duration: "24h", BindingConfiguration: "g1", SelectedAt: e.now}})
		if err != nil {
			t.Fatal(err)
		}
		return d.Run, publication.ToAPI(publication.Committed(r)), d.Digest()
	}
	nsRef, nsPub, nsDigest := commit("namespace-complete")
	platRef, platPub, platDigest := commit("binding-no-targets")
	e.nsRun = nsRef
	run := func(name string, ref publication.RunRef, pub v1alpha1.PublicationStatus, digest string, scope v1alpha1.RunScope, req *v1alpha1.RequestReference, nsUID string) *v1alpha1.AssessmentRun {
		return &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(ref.RunUID)},
			Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: "audit-all"}, Scope: scope, Request: req},
			Status: v1alpha1.AssessmentRunStatus{Phase: v1alpha1.RunCompleted, Binding: &v1alpha1.ResolvedBinding{Name: "audit-all", UID: ref.BindingUID},
				Scope: &v1alpha1.FrozenScope{ClusterID: ref.ClusterID, NamespaceUID: nsUID}, DescriptorSHA256: digest, Publication: &pub}}
	}
	nsRunObj := run("nightly-run", nsRef, nsPub, nsDigest, v1alpha1.RunScopeNamespace, &v1alpha1.RequestReference{Namespace: "dev", Name: "nightly", UID: "req-uid"}, "uid-dev")
	platRunObj := run("scheduled-run", platRef, platPub, platDigest, v1alpha1.RunScopeBinding, nil, "")
	req := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "dev", Name: "nightly", UID: "req-uid"},
		Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: "audit-all"}},
		Status: v1alpha1.AssessmentRequestStatus{Phase: v1alpha1.RequestCompleted, NamespaceUID: "uid-dev",
			Run: &v1alpha1.RunReference{Name: nsRunObj.Name, UID: string(nsRunObj.UID)}, ArtifactRef: nsPub.PublicationID}}
	sibling := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "nightly", UID: "req-prod"},
		Spec:   v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: "audit-all"}},
		Status: v1alpha1.AssessmentRequestStatus{Phase: v1alpha1.RequestCompleted, NamespaceUID: "uid-prod", Run: &v1alpha1.RunReference{Name: nsRunObj.Name}, ArtifactRef: nsPub.PublicationID}}
	e.c = fake.NewClientBuilder().WithScheme(scheme()).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "dev", UID: "uid-dev"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod", UID: "uid-prod"}},
		req, sibling, nsRunObj, platRunObj).WithStatusSubresource(req, sibling, nsRunObj, platRunObj).Build()
	e.rev = &reviews{tokens: map[string]string{"team-token": "alice", "admin-token": "root"}, grants: map[string]bool{
		"alice get dev/assessmentrequests/download/nightly": true, "alice get dev/assessmentrequests/nightly": true,
		"alice get prod/assessmentrequests/download/nightly": false,
		"root get /assessmentruns/download/scheduled-run":    true, "root get /assessmentruns/scheduled-run": true,
	}}
	e.srv = &Server{Reader: e.c, Reviews: e.rev, Publisher: e.pub, TempDir: t.TempDir(), MaxConcurrent: 2, MaxDiskBytes: 1 << 20}
	e.h = e.srv.Handler()
	return e
}

func (e *env) get(path, token string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

const teamPath = "/v1/namespaces/dev/assessmentrequests/nightly/download?uid=req-uid"

func noLeak(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	body := w.Body.String()
	for _, s := range []string{"memory://", "evidence/", "team-token", "admin-token", "uid-prod", "bucket", "konstapel/"} {
		if w.Code != http.StatusOK && strings.Contains(body, s) {
			t.Fatalf("error response leaks %q: %s", s, body)
		}
	}
}

func TestTeamDownloadsItsVerifiedPackage(t *testing.T) {
	e := newEnv(t)
	w := e.get(teamPath, "team-token")
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	run := &v1alpha1.AssessmentRun{}
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: "nightly-run"}, run)
	sum := sha256.Sum256(w.Body.Bytes())
	if hex.EncodeToString(sum[:]) != run.Status.Publication.PackageSHA256 {
		t.Fatal("served bytes are not the committed package")
	}
	h := w.Header()
	if h.Get("Cache-Control") != "private, no-store" || !strings.HasPrefix(h.Get("Repr-Digest"), "sha-256=:") ||
		h.Get("X-Konstapel-Expires-At") == "" || h.Get("X-Konstapel-Published-At") == "" || h.Get("X-Konstapel-Publication") != run.Status.Publication.PublicationID {
		t.Fatalf("headers %v", h)
	}
	if entries, _ := os.ReadDir(e.srv.TempDir); len(entries) != 0 {
		t.Fatal("temporary download data left behind")
	}
}

func TestPlatformRunDownload(t *testing.T) {
	e := newEnv(t)
	run := &v1alpha1.AssessmentRun{}
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: "scheduled-run"}, run)
	if w := e.get("/v1/assessmentruns/"+string(run.UID)+"/download", "admin-token"); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// The team's namespace permission does not reach the full-binding run,
	// nor its own run through the platform route.
	for _, uid := range []string{string(run.UID), e.nsRun.RunUID, "guessed-uid"} {
		if w := e.get("/v1/assessmentruns/"+uid+"/download", "team-token"); w.Code != http.StatusForbidden {
			t.Fatalf("team reached run %s: %d", uid, w.Code)
		}
	}
}

func TestAuthenticationAndAuthorizationFailClosed(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name, path, token string
		hdr               []string
		code              int
	}{
		{"no token", teamPath, "", nil, http.StatusUnauthorized},
		{"forwarded identity only", teamPath, "", []string{"X-Remote-User", "alice", "X-Forwarded-User", "alice", "Impersonate-User", "alice"}, http.StatusUnauthorized},
		{"wrong audience or unknown token", teamPath, "other-service-token", nil, http.StatusUnauthorized},
		{"sibling namespace", "/v1/namespaces/prod/assessmentrequests/nightly/download?uid=req-prod", "team-token", nil, http.StatusForbidden},
		{"wrong request UID", "/v1/namespaces/dev/assessmentrequests/nightly/download?uid=req-old", "team-token", nil, http.StatusForbidden},
		{"missing UID", "/v1/namespaces/dev/assessmentrequests/nightly/download", "team-token", nil, http.StatusBadRequest},
		{"guessed storage key", "/v1/download?key=konstapel/evidence/x/commit.json", "team-token", nil, http.StatusNotFound},
	}
	for _, c := range cases {
		if w := e.get(c.path, c.token, c.hdr...); w.Code != c.code {
			t.Errorf("%s: %d %s", c.name, w.Code, w.Body)
		} else {
			noLeak(t, w)
		}
	}
	// Review API failures deny with a retryable error, never allow.
	e.rev.down = true
	if w := e.get(teamPath, "team-token"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("review outage: %d", w.Code)
	}
}

func TestRevocationAndRecreatedNamespaceDenyNewDownloads(t *testing.T) {
	e := newEnv(t)
	if w := e.get(teamPath, "team-token"); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	e.rev.grants["alice get dev/assessmentrequests/download/nightly"] = false
	if w := e.get(teamPath, "team-token"); w.Code != http.StatusForbidden {
		t.Fatalf("revoked RBAC still downloads: %d", w.Code)
	}
	e.rev.grants["alice get dev/assessmentrequests/download/nightly"] = true
	// Recreate the namespace: same name, new UID.
	ns := &corev1.Namespace{}
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: "dev"}, ns)
	_ = e.c.Delete(context.Background(), ns)
	_ = e.c.Create(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "dev", UID: "uid-dev-2"}})
	if w := e.get(teamPath, "team-token"); w.Code != http.StatusForbidden {
		t.Fatalf("recreated namespace still downloads: %d", w.Code)
	}
	// A deleted request is not resolvable either, even with the artifact ref.
	e = newEnv(t)
	_ = e.c.Delete(context.Background(), &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "dev", Name: "nightly"}})
	if w := e.get(teamPath, "team-token"); w.Code != http.StatusForbidden {
		t.Fatalf("deleted request downloads: %d", w.Code)
	}
}

func TestStorageFailuresAreExplicit(t *testing.T) {
	cases := []struct {
		name  string
		setup func(e *env)
		code  int
	}{
		{"corrupt", func(e *env) { e.pub.Corrupt(e.nsRun, []byte("tampered")) }, http.StatusBadGateway},
		{"missing before expiry", func(e *env) { e.pub.Corrupt(e.nsRun, nil) }, http.StatusServiceUnavailable},
		{"expired", func(e *env) { e.now = e.now.Add(25 * time.Hour) }, http.StatusGone},
		{"backend down", func(e *env) { e.pub.Fail(pubfake.OpOpen, publication.ErrUnavailable) }, http.StatusServiceUnavailable},
		{"uncommitted run", func(e *env) {
			r := &v1alpha1.AssessmentRun{}
			_ = e.c.Get(context.Background(), client.ObjectKey{Name: "nightly-run"}, r)
			r.Status.Phase = v1alpha1.RunPublishing
			_ = e.c.Status().Update(context.Background(), r)
		}, http.StatusConflict},
		{"disk limit", func(e *env) { e.srv.MaxDiskBytes = 1 }, http.StatusServiceUnavailable},
	}
	for _, c := range cases {
		e := newEnv(t)
		c.setup(e)
		w := e.get(teamPath, "team-token")
		if w.Code != c.code {
			t.Errorf("%s: %d %s", c.name, w.Code, w.Body)
		}
		noLeak(t, w)
		if entries, _ := os.ReadDir(e.srv.TempDir); len(entries) != 0 {
			t.Errorf("%s: temporary data left behind", c.name)
		}
	}
}

func TestConcurrencyIsBounded(t *testing.T) {
	e := newEnv(t)
	e.srv.sem <- struct{}{}
	e.srv.sem <- struct{}{}
	if w := e.get(teamPath, "team-token"); w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("over the concurrency limit: %d", w.Code)
	}
	<-e.srv.sem
	if w := e.get(teamPath, "team-token"); w.Code != http.StatusOK {
		t.Fatalf("slot not reusable: %d", w.Code)
	}
}

// A run pinned to an EvidenceDestination is served from that destination,
// never from the legacy publisher; an unreachable pin is unavailable.
func TestPinnedRunIsServedFromItsDestination(t *testing.T) {
	e := newEnv(t)
	run := &v1alpha1.AssessmentRun{}
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: "nightly-run"}, run)
	run.Status.Destination = &v1alpha1.DestinationPin{DestinationReference: v1alpha1.DestinationReference{Name: "primary", UID: "uid-primary"}}
	if err := e.c.Status().Update(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	pinned := e.srv.Publisher
	e.srv.Publisher = nil // no legacy destination
	var asked string
	e.srv.PublisherFor = func(_ context.Context, r *v1alpha1.AssessmentRun) (publication.Publisher, error) {
		asked = r.Status.Destination.UID
		return pinned, nil
	}
	if w := e.get(teamPath, "team-token"); w.Code != http.StatusOK || asked != "uid-primary" {
		t.Fatalf("pinned download: %d asked %q", w.Code, asked)
	}
	e.srv.PublisherFor = func(context.Context, *v1alpha1.AssessmentRun) (publication.Publisher, error) {
		return nil, errors.New("destination gone")
	}
	e.srv.Publisher = pinned // a legacy publisher must not be used for a pinned run
	if w := e.get(teamPath, "team-token"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unreachable pin: %d", w.Code)
	}
}

func TestOrphanedDestinationIsGone(t *testing.T) {
	e := newEnv(t)
	run := &v1alpha1.AssessmentRun{}
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: "nightly-run"}, run)
	run.Status.Destination = &v1alpha1.DestinationPin{DestinationReference: v1alpha1.DestinationReference{Name: "primary", UID: "uid-primary"}}
	_ = e.c.Status().Update(context.Background(), run)
	e.srv.PublisherFor = func(context.Context, *v1alpha1.AssessmentRun) (publication.Publisher, error) {
		return nil, publication.ErrOrphaned
	}
	if w := e.get(teamPath, "team-token"); w.Code != http.StatusGone {
		t.Fatalf("orphaned destination download: %d", w.Code)
	}
}
