package conformance

import (
	"context"
	"slices"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

// Call is one API request a RecordingClient saw.
type Call struct {
	// Verb is get, list, create, update, patch, apply, delete,
	// deletecollection, or one of those prefixed with "<subresource> ".
	Verb string `json:"verb"`
	// Kind is the object's kind ("PolicyReportList" for a list), or "" for
	// an apply configuration.
	Kind      string `json:"kind,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// Write reports whether the call changes cluster state.
func (c Call) Write() bool {
	verb := c.Verb[strings.LastIndex(c.Verb, " ")+1:]
	return verb != "get" && verb != "list"
}

// RecordingClient is the recording API fixture: a client over a (fake)
// cluster that records every request, reads and writes alike, and can fail
// chosen ones. Hand it to collection code as the most capable client
// available and assert on what it saw: a collection adapter must issue only
// its declared reads in its scope, and no write of any kind.
type RecordingClient struct {
	client.Client
	// Fail, when set, is asked before each request; an error fails it.
	Fail func(Call) error

	mu    sync.Mutex
	calls []Call
}

// NewRecordingClient records the requests made through c.
func NewRecordingClient(c client.Client) *RecordingClient { return &RecordingClient{Client: c} }

// Calls are the requests seen so far, in order.
func (c *RecordingClient) Calls() []Call {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

// Writes are the recorded requests that change cluster state.
func (c *RecordingClient) Writes() []Call {
	return slices.DeleteFunc(c.Calls(), func(x Call) bool { return !x.Write() })
}

// Reset forgets the recorded requests.
func (c *RecordingClient) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = nil
}

func (c *RecordingClient) record(verb string, obj runtime.Object, namespace string) error {
	kind := ""
	if obj != nil {
		if gvk, err := apiutil.GVKForObject(obj, c.Scheme()); err == nil {
			kind = gvk.Kind
		}
	}
	call := Call{Verb: verb, Kind: kind, Namespace: namespace}
	c.mu.Lock()
	c.calls = append(c.calls, call)
	fail := c.Fail
	c.mu.Unlock()
	if fail != nil {
		return fail(call)
	}
	return nil
}

func (c *RecordingClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := c.record("get", obj, key.Namespace); err != nil {
		return err
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func (c *RecordingClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	o := &client.ListOptions{}
	o.ApplyOptions(opts)
	if err := c.record("list", list, o.Namespace); err != nil {
		return err
	}
	return c.Client.List(ctx, list, opts...)
}

func (c *RecordingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if err := c.record("create", obj, obj.GetNamespace()); err != nil {
		return err
	}
	return c.Client.Create(ctx, obj, opts...)
}

func (c *RecordingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if err := c.record("update", obj, obj.GetNamespace()); err != nil {
		return err
	}
	return c.Client.Update(ctx, obj, opts...)
}

func (c *RecordingClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if err := c.record("patch", obj, obj.GetNamespace()); err != nil {
		return err
	}
	return c.Client.Patch(ctx, obj, patch, opts...)
}

func (c *RecordingClient) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
	if err := c.record("apply", nil, ""); err != nil {
		return err
	}
	return c.Client.Apply(ctx, obj, opts...)
}

func (c *RecordingClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if err := c.record("delete", obj, obj.GetNamespace()); err != nil {
		return err
	}
	return c.Client.Delete(ctx, obj, opts...)
}

func (c *RecordingClient) DeleteAllOf(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error {
	o := &client.DeleteAllOfOptions{}
	o.ApplyOptions(opts)
	if err := c.record("deletecollection", obj, o.Namespace); err != nil {
		return err
	}
	return c.Client.DeleteAllOf(ctx, obj, opts...)
}

func (c *RecordingClient) Status() client.SubResourceWriter {
	return c.SubResource("status")
}

func (c *RecordingClient) SubResource(sub string) client.SubResourceClient {
	return recordingSubResource{c: c, sub: sub, next: c.Client.SubResource(sub)}
}

type recordingSubResource struct {
	c    *RecordingClient
	sub  string
	next client.SubResourceClient
}

func (s recordingSubResource) Get(ctx context.Context, obj client.Object, sub client.Object, opts ...client.SubResourceGetOption) error {
	if err := s.c.record(s.sub+" get", obj, obj.GetNamespace()); err != nil {
		return err
	}
	return s.next.Get(ctx, obj, sub, opts...)
}

func (s recordingSubResource) Create(ctx context.Context, obj client.Object, sub client.Object, opts ...client.SubResourceCreateOption) error {
	if err := s.c.record(s.sub+" create", obj, obj.GetNamespace()); err != nil {
		return err
	}
	return s.next.Create(ctx, obj, sub, opts...)
}

func (s recordingSubResource) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if err := s.c.record(s.sub+" update", obj, obj.GetNamespace()); err != nil {
		return err
	}
	return s.next.Update(ctx, obj, opts...)
}

func (s recordingSubResource) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	if err := s.c.record(s.sub+" patch", obj, obj.GetNamespace()); err != nil {
		return err
	}
	return s.next.Patch(ctx, obj, patch, opts...)
}

func (s recordingSubResource) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
	if err := s.c.record(s.sub+" apply", nil, ""); err != nil {
		return err
	}
	return s.next.Apply(ctx, obj, opts...)
}
