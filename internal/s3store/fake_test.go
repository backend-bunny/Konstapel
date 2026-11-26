package s3store

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/s3store/s3fake"
)

// fakeS3 is the shared in-memory S3 server (s3fake) with this package's
// helpers.
type fakeS3 struct{ *s3fake.Server }

type fakeVersion = s3fake.Version

func newFake() *fakeS3 { return &fakeS3{s3fake.New()} }

func (f *fakeS3) serve(t *testing.T) (*httptest.Server, Destination) {
	srv := httptest.NewServer(f.Server)
	t.Cleanup(srv.Close)
	return srv, Destination{ID: "fake", Endpoint: srv.URL, Bucket: "evidence", Region: "us-east-1", Prefix: "konstapel",
		Addressing: AddressingPath, CredentialSecret: &SecretRef{Name: "s3"}, DevelopmentFixture: true}
}

func probeFake(t *testing.T, f *fakeS3) (Compatibility, error) {
	t.Helper()
	_, d := f.serve(t)
	c, err := NewClient(context.Background(), d, &StaticCredentials{AccessKeyID: "AKIAFAKE", SecretAccessKey: "fake-secret"})
	if err != nil {
		t.Fatal(err)
	}
	return Probe(context.Background(), c, d)
}
