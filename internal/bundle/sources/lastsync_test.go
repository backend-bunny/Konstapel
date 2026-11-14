package sources

import (
	"context"
	"errors"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
	"github.com/backend-bunny/Konstapel/internal/bundle/resolve"
)

// LastSync records each completed Sync's start and whether it read the
// configuration; an absent ConfigMap is a successful read, a failed read
// is not, and recovery is recorded.
func TestLastSync(t *testing.T) {
	var fail bool
	cfg := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if fail {
				return errors.New("apiserver unavailable")
			}
			return c.Get(ctx, key, obj, opts...)
		}}).Build()
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	w, err := New(Options{Namespace: ns, Config: cfg, Objects: kubeaccess.NewMemoryReader(), Acceptances: resolve.NewAcceptances(),
		Compatibility: func() (string, error) { return "compat-1", nil }, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if at, ok := w.LastSync(); !at.IsZero() || ok {
		t.Fatalf("before any Sync: %s %v", at, ok)
	}
	if _, err := w.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if at, ok := w.LastSync(); !at.Equal(now) || !ok || w.State().Available {
		t.Fatalf("absent ConfigMap: %s %v (it is read, and unavailable)", at, ok)
	}
	now = now.Add(time.Minute)
	fail = true
	if _, err := w.Sync(context.Background()); err == nil {
		t.Fatal("failed read succeeded")
	}
	if at, ok := w.LastSync(); !at.Equal(now) || ok {
		t.Fatalf("failed read: %s %v", at, ok)
	}
	now = now.Add(time.Minute)
	fail = false
	if _, err := w.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if at, ok := w.LastSync(); !at.Equal(now) || !ok {
		t.Fatalf("recovered: %s %v", at, ok)
	}
}
