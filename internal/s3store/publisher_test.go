package s3store

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/publicationtest"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var testRun = publication.RunRef{ClusterID: "kube-system:synthetic-cluster", BindingUID: "binding-uid-1", RunUID: "run-uid-1"}

func fullPackage(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pkg")
	if _, err := publicationtest.FullAssessmentPackage(repoRoot(t), dir, testRun); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newPublisher(t *testing.T, f *fakeS3, now func() time.Time) *Publisher {
	t.Helper()
	_, d := f.serve(t)
	c, err := NewClient(context.Background(), d, &StaticCredentials{AccessKeyID: "AKIAFAKE", SecretAccessKey: "fake-secret"})
	if err != nil {
		t.Fatal(err)
	}
	return &Publisher{Client: c, Dest: d, Now: now}
}

func retention(d string) publication.Retention {
	return publication.Retention{Duration: d, BindingConfiguration: "generation-1/epoch-1", SelectedAt: time.Now().UTC().Truncate(time.Second)}
}

func TestArchiveIsDeterministic(t *testing.T) {
	dir := fullPackage(t)
	a, err := Archive(dir)
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Hour)
	_ = os.Chtimes(filepath.Join(dir, "summary.json"), later, later)
	b, err := Archive(dir)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("repeat packaging produced different bytes")
	}
	_ = os.Symlink("/etc/hostname", filepath.Join(dir, "link"))
	if _, err := Archive(dir); err == nil {
		t.Fatal("symlink archived")
	}
}

func TestValidatePackageRejectsUnsafePackages(t *testing.T) {
	if _, err := ValidatePackage(fullPackage(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePackage(filepath.Join(repoRoot(t), "testdata/publication/binding-diagnostic")); err != nil {
		t.Fatal("diagnostic package rejected:", err)
	}
	// An assessment package without its plan, SSP, and schemas is not valid OSCAL.
	if _, err := ValidatePackage(filepath.Join(repoRoot(t), "testdata/publication/namespace-complete")); err == nil {
		t.Fatal("assessment package without required OSCAL accepted")
	}
	dir := fullPackage(t)
	_ = os.WriteFile(filepath.Join(dir, "assessment-plan.json"), []byte(`{"assessment-plan": {}}`), 0o644)
	if _, err := ValidatePackage(dir); err == nil {
		t.Fatal("tampered package accepted")
	}
}

func TestStagePublishAndRecover(t *testing.T) {
	for _, mode := range []string{"", "Enabled"} {
		f := newFake()
		f.versioning = mode
		p := newPublisher(t, f, time.Now)
		ctx := context.Background()
		dir := fullPackage(t)
		s, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: dir})
		if err != nil {
			t.Fatal(mode, err)
		}
		if st, err := p.Inspect(ctx, testRun); err != nil || st.Phase != publication.PhaseUploading || st.Availability == publication.AvailabilityAvailable {
			t.Fatalf("%s staged-only status: %+v %v", mode, st, err)
		}
		r, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("2160h")})
		if err != nil {
			t.Fatal(mode, err)
		}
		if r.Validate() != nil || !r.ExpiresAt.Equal(r.PublishedAt.Add(2160*time.Hour)) || !strings.HasPrefix(r.Commit.ManifestKey, "konstapel/evidence/synthetic-cluster/binding-uid-1/run-uid-1/") {
			t.Fatalf("%s receipt %+v", mode, r)
		}
		if (mode == "Enabled") != (r.Commit.ArchiveVersionID != "") {
			t.Fatalf("%s archive version %q", mode, r.Commit.ArchiveVersionID)
		}
		// A retry, a different retention, and a restarted publisher all
		// converge on the original commit.
		again, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("24h")})
		if err != nil || !reflect.DeepEqual(again, r) {
			t.Fatalf("%s retry changed the receipt: %v", mode, err)
		}
		restarted := &Publisher{Client: p.Client, Dest: p.Dest, Now: time.Now}
		recovered, err := restarted.Recover(ctx, testRun)
		if err != nil || recovered != s {
			t.Fatalf("%s recover %+v %v", mode, recovered, err)
		}
		if got, err := restarted.Publish(ctx, publication.PublishRequest{Staged: recovered, Retention: retention("1h")}); err != nil || !reflect.DeepEqual(got, r) {
			t.Fatalf("%s restarted publish changed the receipt: %v", mode, err)
		}
		if st, err := p.Inspect(ctx, testRun); err != nil || st.Phase != publication.PhaseCommitted || st.Validate() != nil {
			t.Fatalf("%s committed status %+v %v", mode, st, err)
		}
	}
}

func TestConcurrentAttemptsCommitOnce(t *testing.T) {
	f := newFake()
	f.versioning = "Enabled"
	p := newPublisher(t, f, time.Now)
	ctx := context.Background()
	dir := fullPackage(t)
	s1, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	s2, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: dir}) // a second attempt, new attempt key
	if err != nil || s1 != s2 {
		t.Fatalf("second attempt of the same package: %v", err)
	}
	r1, err1 := p.Publish(ctx, publication.PublishRequest{Staged: s1, Retention: retention("2160h")})
	r2, err2 := p.Publish(ctx, publication.PublishRequest{Staged: s2, Retention: retention("2160h")})
	if err1 != nil || err2 != nil || !reflect.DeepEqual(r1, r2) {
		t.Fatalf("attempts did not reconcile: %v %v", err1, err2)
	}
	if n := len(f.objects[r1.Commit.ManifestKey]); n != 1 {
		t.Fatalf("commit written %d times", n)
	}
}

func TestConflictingContentNeverOverwrites(t *testing.T) {
	f := newFake()
	p := newPublisher(t, f, time.Now)
	ctx := context.Background()
	first, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: fullPackage(t)})
	if err != nil {
		t.Fatal(err)
	}
	other := fullPackage(t) // same run identity, different bytes
	second, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: other})
	if err != nil || second.PackageSHA256 == first.PackageSHA256 {
		t.Fatalf("setup: %v", err)
	}
	r, err := p.Publish(ctx, publication.PublishRequest{Staged: second, Retention: retention("2160h")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Publish(ctx, publication.PublishRequest{Staged: first, Retention: retention("2160h")}); !errors.Is(err, publication.ErrConflict) {
		t.Fatalf("different content for a committed run: %v", err)
	}
	if _, err := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: fullPackage(t)}); !errors.Is(err, publication.ErrConflict) {
		t.Fatalf("staging different content after commit: %v", err)
	}
	if st, _ := p.Inspect(ctx, testRun); st.PackageSHA256 != r.PackageSHA256 {
		t.Fatal("the winning commit was overwritten")
	}
}

func TestCorruptUploadNeverPublishes(t *testing.T) {
	f := newFake()
	f.corrupt = true
	p := newPublisher(t, f, time.Now)
	if _, err := p.Stage(context.Background(), publication.StageRequest{Run: testRun, Dir: fullPackage(t)}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("truncated upload accepted: %v", err)
	}
	if _, err := p.Recover(context.Background(), testRun); !errors.Is(err, publication.ErrCaptureLost) {
		t.Fatalf("nothing verified should be recoverable: %v", err)
	}
}

func TestExpiryAndDeletion(t *testing.T) {
	f := newFake()
	f.versioning = "Enabled"
	clock := time.Now()
	p := newPublisher(t, f, func() time.Time { return clock })
	ctx := context.Background()
	f.objects["konstapel/unrelated"] = []fakeVersion{{id: "v0", body: []byte("keep"), at: clock}}
	s, _ := p.Stage(ctx, publication.StageRequest{Run: testRun, Dir: fullPackage(t)})
	r, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("1h")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Delete(ctx, testRun); !errors.Is(err, publication.ErrRetentionActive) {
		t.Fatalf("deleted before expiry: %v", err)
	}
	clock = r.ExpiresAt.Add(time.Second)
	if st, _ := p.Inspect(ctx, testRun); st.Phase != publication.PhaseExpired || st.Availability != publication.AvailabilityExpired {
		t.Fatalf("expiry not reported: %+v", st)
	}
	c, err := p.Delete(ctx, testRun)
	if err != nil || c.State != publication.CleanupDeleted {
		t.Fatalf("%+v %v", c, err)
	}
	for k := range f.objects {
		if k != "konstapel/unrelated" {
			t.Errorf("owned object %s survived deletion", k)
		}
	}
	if _, kept := f.objects["konstapel/unrelated"]; !kept {
		t.Fatal("deletion touched an unrelated object")
	}
}

func TestReadyRequiresCompatibleBackend(t *testing.T) {
	if _, err := newPublisher(t, newFake(), time.Now).Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := newFake()
	f.conditional = false
	if _, err := newPublisher(t, f, time.Now).Ready(context.Background()); !errors.Is(err, publication.ErrUnavailable) || !strings.Contains(err.Error(), "If-None-Match") {
		t.Fatalf("incompatible backend reported ready: %v", err)
	}
}

func TestLoadCredentialsFromControllerSecret(t *testing.T) {
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "konstapel-system", Name: "s3"},
		Data: map[string][]byte{"accessKeyID": []byte("AKIAONE"), "secretAccessKey": []byte("secret-one")}}
	c := fake.NewClientBuilder().WithScheme(clientgoscheme.Scheme).WithObjects(sec).Build()
	ref := &SecretRef{Name: "s3"}
	got, err := LoadCredentials(context.Background(), c, "konstapel-system", ref)
	if err != nil || got.AccessKeyID != "AKIAONE" {
		t.Fatal(got, err)
	}
	// Rotation: the next load sees the new value.
	sec.Data["secretAccessKey"] = []byte("secret-two")
	_ = c.Update(context.Background(), sec)
	if got, _ = LoadCredentials(context.Background(), c, "konstapel-system", ref); got.SecretAccessKey != "secret-two" {
		t.Fatal("rotated secret not read")
	}
	// Another namespace is never consulted; missing keys are named, not valued.
	if _, err := LoadCredentials(context.Background(), c, "team-a", ref); !errors.Is(err, ErrCredentials) {
		t.Fatalf("secret read outside the controller namespace: %v", err)
	}
	delete(sec.Data, "accessKeyID")
	_ = c.Update(context.Background(), sec)
	_, err = LoadCredentials(context.Background(), c, "konstapel-system", ref)
	if !errors.Is(err, ErrCredentials) || !strings.Contains(err.Error(), "accessKeyID") || strings.Contains(err.Error(), "secret-two") {
		t.Fatalf("missing key not reported safely: %v", err)
	}
}

// TLS verification is always on: an endpoint with an untrusted certificate
// fails visibly, and trusting it requires its CA in caBundle.
func TestTLSTrustIsExplicit(t *testing.T) {
	f := newFake()
	srv := httptest.NewTLSServer(http.HandlerFunc(f.handle))
	defer srv.Close()
	d := Destination{ID: "tls", Endpoint: srv.URL, Bucket: "evidence", Region: "us-east-1", Addressing: AddressingPath, CredentialSecret: &SecretRef{Name: "s3"}}
	creds := &StaticCredentials{AccessKeyID: "AKIAFAKE", SecretAccessKey: "fake-secret"}
	c, err := NewClient(context.Background(), d, creds)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Probe(context.Background(), c, d); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted certificate accepted: %v", err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	d.CABundle = ca
	if c, err = NewClient(context.Background(), d, creds); err != nil {
		t.Fatal(err)
	}
	if r, err := Probe(context.Background(), c, d); err != nil || !r.Ready {
		t.Fatalf("trusted CA bundle not used: %+v %v", r, err)
	}
}
