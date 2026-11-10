package kubeaccess

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// ErrObjectNotFound reports that a referenced Secret or ConfigMap does not
// exist in the controller namespace.
var ErrObjectNotFound = errors.New("referenced object not found")

// ObjectReader reads one named Secret or ConfigMap in the controller's own
// namespace, which is fixed when the reader is built. It is the only
// Kubernetes access the provider needs: get by name, no list, no watch, no
// other namespace. A missing object returns an error wrapping
// ErrObjectNotFound. Errors must not contain object data.
type ObjectReader interface {
	Get(ctx context.Context, kind, name string) (Object, error)
}

// Object is the data of a Secret or ConfigMap. Its values never appear in
// formatted output, logs or JSON.
type Object struct {
	typ  string
	data map[string][]byte
}

// NewObject returns an Object with the given Secret type ("" for a
// ConfigMap) and a copy of data.
func NewObject(typ string, data map[string][]byte) Object {
	return Object{typ: typ, data: cloneData(data)}
}

// Type is the Secret type, or "" for a ConfigMap.
func (o Object) Type() string { return o.typ }

// Value returns a copy of the value under key.
func (o Object) Value(key string) ([]byte, bool) {
	v, ok := o.data[key]
	return append([]byte(nil), v...), ok
}

func (o Object) String() string   { return "Object{redacted}" }
func (o Object) GoString() string { return "kubeaccess.Object{redacted}" }

// Format redacts the object for every fmt verb.
func (o Object) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, o.GoString())
		return
	}
	_, _ = io.WriteString(f, o.String())
}

// MarshalJSON redacts the object.
func (Object) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }

// LogValue redacts the object in structured logs.
func (o Object) LogValue() slog.Value { return slog.StringValue(o.String()) }

func cloneData(data map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(data))
	for k, v := range data {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

func checkKind(kind string) error {
	if kind != bundle.KindSecret && kind != bundle.KindConfigMap {
		return fmt.Errorf("unsupported object kind %q", kind)
	}
	return nil
}

// ClientReader reads objects through a controller-runtime client.Reader,
// pinned to one namespace. Use an uncached reader (the manager's APIReader):
// a cached client would need list and watch permission on every Secret in the
// namespace. The RBAC it needs is "get" on the referenced secrets and
// configmaps in that namespace, ideally restricted with resourceNames.
type ClientReader struct {
	reader    client.Reader
	namespace string
}

// NewClientReader returns a reader for objects in namespace.
func NewClientReader(r client.Reader, namespace string) (*ClientReader, error) {
	if r == nil || namespace == "" {
		return nil, errors.New("kubeaccess: a reader and the controller namespace are required")
	}
	return &ClientReader{reader: r, namespace: namespace}, nil
}

// Get reads one object by name.
func (c *ClientReader) Get(ctx context.Context, kind, name string) (Object, error) {
	if err := checkKind(kind); err != nil {
		return Object{}, err
	}
	key := client.ObjectKey{Namespace: c.namespace, Name: name}
	var obj client.Object
	if kind == bundle.KindSecret {
		obj = &corev1.Secret{}
	} else {
		obj = &corev1.ConfigMap{}
	}
	if err := c.reader.Get(ctx, key, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return Object{}, fmt.Errorf("%w: %s %s/%s", ErrObjectNotFound, kind, c.namespace, name)
		}
		// API errors carry the status message only, never object data.
		return Object{}, fmt.Errorf("reading %s %s/%s: %w", kind, c.namespace, name, err)
	}
	switch o := obj.(type) {
	case *corev1.Secret:
		return Object{typ: string(o.Type), data: cloneData(o.Data)}, nil
	case *corev1.ConfigMap:
		data := cloneData(o.BinaryData)
		for k, v := range o.Data {
			data[k] = []byte(v)
		}
		return Object{data: data}, nil
	}
	return Object{}, fmt.Errorf("unsupported object kind %q", kind)
}

// MemoryReader is an in-memory ObjectReader for tests and fixtures. It is
// safe for concurrent use and counts reads.
type MemoryReader struct {
	mu      sync.Mutex
	objects map[string]Object
	reads   map[string]int
	err     error
}

// NewMemoryReader returns an empty MemoryReader.
func NewMemoryReader() *MemoryReader {
	return &MemoryReader{objects: map[string]Object{}, reads: map[string]int{}}
}

// Put creates or replaces an object.
func (m *MemoryReader) Put(kind, name string, obj Object) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[kind+"/"+name] = Object{typ: obj.typ, data: cloneData(obj.data)}
}

// Delete removes an object.
func (m *MemoryReader) Delete(kind, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, kind+"/"+name)
}

// FailWith makes every Get fail with err (nil restores normal reads).
func (m *MemoryReader) FailWith(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

// Reads returns how often kind/name was read.
func (m *MemoryReader) Reads(kind, name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reads[kind+"/"+name]
}

// Get implements ObjectReader.
func (m *MemoryReader) Get(_ context.Context, kind, name string) (Object, error) {
	if err := checkKind(kind); err != nil {
		return Object{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads[kind+"/"+name]++
	if m.err != nil {
		return Object{}, m.err
	}
	o, ok := m.objects[kind+"/"+name]
	if !ok {
		return Object{}, fmt.Errorf("%w: %s %s", ErrObjectNotFound, kind, name)
	}
	return Object{typ: o.typ, data: cloneData(o.data)}, nil
}
