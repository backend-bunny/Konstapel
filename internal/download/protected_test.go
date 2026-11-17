package download

// Protected platform packages (add-supporting-evidence-attachments 5.4,
// 5.5): a package that carries supporting documents requires the
// cluster-wide document-read grant in addition to run access, decided from
// the package's own recorded protection and checked on every request.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

const protectedRunUID = "run-uid-binding-protected"

// protectedPackage is the binding-no-targets fixture as another run, with
// a supporting context and one document copy.
func protectedPackage(t *testing.T, version string) string {
	t.Helper()
	src := filepath.Join(fixtures, "binding-no-targets")
	d, err := publication.LoadDescriptor(src)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, f := range d.Files {
		b, _ := os.ReadFile(filepath.Join(src, filepath.FromSlash(f.Path)))
		_ = os.MkdirAll(filepath.Dir(filepath.Join(dir, f.Path)), 0o755)
		if err := os.WriteFile(filepath.Join(dir, f.Path), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.MkdirAll(filepath.Join(dir, "supporting-evidence", "documents"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, filepath.FromSlash(publication.SupportingContextFile)), []byte(`{"private":"DC North audit"}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, filepath.FromSlash(publication.SupportingDocumentDir+"att-1")), []byte("%PDF private bytes"), 0o644)
	d.Run.RunUID = protectedRunUID
	d.Files, err = publication.Inventory(dir, func(p string) publication.FileRole {
		for _, f := range d.Files {
			if f.Path == p {
				return f.Role
			}
		}
		if p == publication.SupportingContextFile {
			return publication.RoleSupportingContext
		}
		return publication.RoleSupportingDocument
	})
	if err != nil {
		t.Fatal(err)
	}
	d.Protection = publication.ProtectionFor(d.Files)
	if version != "" {
		d.Protection.Version = version
	} else if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := assessment.Write(filepath.Join(dir, publication.DescriptorFile), d); err != nil {
		t.Fatal(err)
	}
	return dir
}

// addProtectedRun publishes the protected package as platform run
// "protected-run" and returns its download path.
func (e *env) addProtectedRun(t *testing.T) string {
	t.Helper()
	dir := protectedPackage(t, "")
	d, _ := publication.LoadDescriptor(dir)
	s, err := e.pub.Stage(context.Background(), publication.StageRequest{Run: d.Run, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.pub.Publish(context.Background(), publication.PublishRequest{Staged: s, Retention: publication.Retention{Duration: "24h", BindingConfiguration: "g1", SelectedAt: e.now}})
	if err != nil {
		t.Fatal(err)
	}
	pub := publication.ToAPI(publication.Committed(r))
	run := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "protected-run", UID: types.UID(protectedRunUID)},
		Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: "audit-all"}, Scope: v1alpha1.RunScopeBinding},
		Status: v1alpha1.AssessmentRunStatus{Phase: v1alpha1.RunCompleted, Binding: &v1alpha1.ResolvedBinding{Name: "audit-all", UID: d.Run.BindingUID},
			Scope: &v1alpha1.FrozenScope{ClusterID: d.Run.ClusterID}, DescriptorSHA256: d.Digest(), Publication: &pub}}
	if err := e.c.Create(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	e.grant("root get /assessmentruns/download/protected-run", "root get /assessmentruns/protected-run")
	return "/v1/assessmentruns/" + protectedRunUID + "/download"
}

func (e *env) grant(keys ...string) {
	e.rev.mu.Lock()
	defer e.rev.mu.Unlock()
	for _, k := range keys {
		e.rev.grants[k] = true
	}
}

func (e *env) revoke(keys ...string) {
	e.rev.mu.Lock()
	defer e.rev.mu.Unlock()
	for _, k := range keys {
		delete(e.rev.grants, k)
	}
}

var documentRead = []string{"root get /evidenceattachments/download/", "root get /evidenceattachments/"}

func TestProtectedPackageRequiresDocumentRead(t *testing.T) {
	e := newEnv(t)
	path := e.addProtectedRun(t)
	sigPath := strings.TrimSuffix(path, "/download") + "/signature"

	// A run reader cannot fetch the protected package through the run route.
	for _, p := range []string{path, sigPath} {
		w := e.get(p, "admin-token")
		if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "PDF") || strings.Contains(w.Body.String(), "DC North") {
			t.Fatalf("%s without document read: %d %s", p, w.Code, w.Body)
		}
		noLeak(t, w)
	}
	// The same reader still reads an unprotected platform package.
	run := &v1alpha1.AssessmentRun{}
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: "scheduled-run"}, run)
	if w := e.get("/v1/assessmentruns/"+string(run.UID)+"/download", "admin-token"); w.Code != http.StatusOK {
		t.Fatalf("unprotected package: %d", w.Code)
	}
	// A grant restricted to one record's name is not the cluster-wide grant.
	e.grant("root get /evidenceattachments/download/att-1", "root get /evidenceattachments/att-1")
	if w := e.get(path, "admin-token"); w.Code != http.StatusForbidden {
		t.Fatalf("named grant: %d", w.Code)
	}
	// Only one half of the grant is not enough either.
	e.grant(documentRead[0])
	if w := e.get(path, "admin-token"); w.Code != http.StatusForbidden {
		t.Fatalf("half grant: %d", w.Code)
	}
	e.grant(documentRead...)
	w := e.get(path, "admin-token")
	if w.Code != http.StatusOK {
		t.Fatalf("with document read: %d %s", w.Code, w.Body)
	}
	dir := t.TempDir()
	if err := publication.Extract(bytes.NewReader(w.Body.Bytes()), dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "supporting-evidence", "documents", "att-1")); string(b) != "%PDF private bytes" {
		t.Fatal("the protected copy was not served intact")
	}
	// Revocation applies to the next request.
	e.revoke(documentRead[1])
	if w := e.get(path, "admin-token"); w.Code != http.StatusForbidden {
		t.Fatalf("after revocation: %d", w.Code)
	}
	// Historical access never depends on an attachment record: none exists
	// in this cluster at all.
	e.grant(documentRead...)
	if w := e.get(path, "admin-token"); w.Code != http.StatusOK {
		t.Fatalf("regranted: %d", w.Code)
	}
	if entries, _ := os.ReadDir(e.srv.TempDir); len(entries) != 0 {
		t.Fatal("temporary download data left behind")
	}
	// Review failures deny.
	e.rev.down = true
	if w := e.get(path, "admin-token"); w.Code == http.StatusOK {
		t.Fatal("served while reviews were down")
	}
}

// The namespace route never serves a protected package, even if a request's
// run named one.
func TestNamespaceRouteNeverServesProtectedPackage(t *testing.T) {
	e := newEnv(t)
	e.addProtectedRun(t)
	run := &v1alpha1.AssessmentRun{}
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: "protected-run"}, run)
	protectedSHA := run.Status.Publication.PackageSHA256
	run.Spec.Scope, run.Spec.Request = v1alpha1.RunScopeNamespace, &v1alpha1.RequestReference{Namespace: "dev", Name: "leaky", UID: "req-leaky"}
	if err := e.c.Update(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	run.Status.Scope.NamespaceUID = "uid-dev"
	if err := e.c.Status().Update(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	req := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: "dev", Name: "leaky", UID: "req-leaky"},
		Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: "audit-all"}}}
	if err := e.c.Create(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	req.Status = v1alpha1.AssessmentRequestStatus{Phase: v1alpha1.RequestCompleted, NamespaceUID: "uid-dev",
		Run: &v1alpha1.RunReference{Name: run.Name, UID: string(run.UID)}, ArtifactRef: run.Status.Publication.PublicationID}
	if err := e.c.Status().Update(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	// The route resolves this request: an unprotected package would be
	// served (positive control), so the denial below is the protection's.
	e.srv.Publisher = swapped{Publisher: e.pub, run: protectedRunUID, archive: unprotectedArchive(t)}
	h := sha256.Sum256(unprotectedArchive(t))
	run.Status.Publication.PackageSHA256 = hex.EncodeToString(h[:])
	if err := e.c.Status().Update(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	e.grant("alice get dev/assessmentrequests/download/leaky", "alice get dev/assessmentrequests/leaky",
		"alice get /evidenceattachments/download/", "alice get /evidenceattachments/")
	path := "/v1/namespaces/dev/assessmentrequests/leaky/download?uid=req-leaky"
	if w := e.get(path, "team-token"); w.Code != http.StatusOK {
		t.Fatalf("positive control: an unprotected package via this route: %d %s", w.Code, w.Body)
	}
	e.srv.Publisher = e.pub
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: "protected-run"}, run)
	run.Status.Publication.PackageSHA256 = protectedSHA
	if err := e.c.Status().Update(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if w := e.get(path, "team-token"); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "PDF") {
		t.Fatalf("namespace route served a protected package: %d", w.Code)
	}
}

// unprotectedArchive is the protected package's run without its
// supporting files.
func unprotectedArchive(t *testing.T) []byte {
	t.Helper()
	dir := protectedPackage(t, "")
	d, _ := publication.LoadDescriptor(dir)
	_ = os.RemoveAll(filepath.Join(dir, "supporting-evidence"))
	var files []publication.File
	for _, f := range d.Files {
		if !strings.HasPrefix(f.Path, publication.SupportingDir) {
			files = append(files, f)
		}
	}
	d.Files, d.Protection = files, nil
	if err := assessment.Write(filepath.Join(dir, publication.DescriptorFile), d); err != nil {
		t.Fatal(err)
	}
	b, err := publication.Archive(dir)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// swapped serves other archive bytes for one run, with a matching status,
// as if a newer producer had written a protection this reader does not
// know.
type swapped struct {
	publication.Publisher
	run     string
	archive []byte
}

func (s swapped) Open(ctx context.Context, ref publication.RunRef) (io.ReadCloser, publication.Status, error) {
	rc, st, err := s.Publisher.Open(ctx, ref)
	if err != nil || ref.RunUID != s.run {
		return rc, st, err
	}
	rc.Close()
	h := sha256.Sum256(s.archive)
	st.PackageSHA256, st.PackageSize = hex.EncodeToString(h[:]), int64(len(s.archive))
	return io.NopCloser(bytes.NewReader(s.archive)), st, nil
}

func TestUnknownProtectionFailsClosed(t *testing.T) {
	e := newEnv(t)
	path := e.addProtectedRun(t)
	e.grant(documentRead...)
	future, err := publication.Archive(protectedPackage(t, "konstapel.io/package-protection/v2"))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.Publisher = swapped{Publisher: e.pub, run: protectedRunUID, archive: future}
	run := &v1alpha1.AssessmentRun{}
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: "protected-run"}, run)
	h := sha256.Sum256(future)
	run.Status.Publication.PackageSHA256 = hex.EncodeToString(h[:])
	if err := e.c.Status().Update(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	w := e.get(path, "admin-token")
	if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "PDF") {
		t.Fatalf("unknown protection: %d %s", w.Code, w.Body)
	}
}
