package s3store

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

func TestNewPublisherReadsControllerSecretAndRotates(t *testing.T) {
	f := newFake()
	_, d := f.serve(t)
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "konstapel-system", Name: "s3"},
		Data: map[string][]byte{"accessKeyID": []byte("AKIAONE"), "secretAccessKey": []byte("one")}}
	c := fake.NewClientBuilder().WithScheme(clientgoscheme.Scheme).WithObjects(sec).Build()

	p, err := NewPublisher(context.Background(), d, c, "konstapel-system")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.accessKeys[len(f.accessKeys)-1]; got != "AKIAONE" {
		t.Fatalf("signed with %q", got)
	}

	// A rotated Secret is used once cached credentials expire.
	sec.Data["accessKeyID"] = []byte("AKIATWO")
	_ = c.Update(context.Background(), sec)
	rot := SecretCredentials(c, "konstapel-system", d.CredentialSecret, time.Millisecond)
	if _, err := rot.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if got, err := rot.Retrieve(context.Background()); err != nil || got.AccessKeyID != "AKIATWO" {
		t.Fatalf("rotation not picked up: %q %v", got.AccessKeyID, err)
	}
}

func TestNewPublisherMissingSecretIsNotReady(t *testing.T) {
	f := newFake()
	_, d := f.serve(t)
	c := fake.NewClientBuilder().WithScheme(clientgoscheme.Scheme).Build()
	p, err := NewPublisher(context.Background(), d, c, "konstapel-system")
	if err != nil {
		t.Fatalf("building the publisher must not need the Secret: %v", err)
	}
	if _, err := p.Ready(context.Background()); !errors.Is(err, publication.ErrUnavailable) {
		t.Fatalf("missing Secret reported ready: %v", err)
	}
	if len(f.accessKeys) != 0 {
		t.Fatal("requests were sent without credentials")
	}
}
