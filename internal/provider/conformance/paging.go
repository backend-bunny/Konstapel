package conformance

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PageFault is a pagination fault a PagingClient injects into one page.
type PageFault int

// Pagination faults.
const (
	// PageOK serves the page.
	PageOK PageFault = iota
	// PageExpired fails the request as an expired continuation (410).
	PageExpired
	// PageRepeated serves the previous page again, with a continuation.
	PageRepeated
	// PageEmpty serves no objects but a continuation, forever.
	PageEmpty
)

// Page identifies one list request of a PagingClient.
type Page struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	// Number is the page's position in its list, from 0. A restarted list
	// starts again from 0.
	Number int `json:"page"`
}

// PagingClient serves lists in pages, as the API server does and the fake
// client does not: it honors client.Limit and client.Continue over the
// wrapped client's complete list, and can inject pagination faults. Wrap it
// in a RecordingClient to see every page request.
type PagingClient struct {
	client.Client
	// Fault, when set, chooses a fault for each page request.
	Fault func(Page) PageFault

	mu    sync.Mutex
	pages []Page
}

// NewPagingClient pages the lists of c.
func NewPagingClient(c client.Client) *PagingClient { return &PagingClient{Client: c} }

// Pages are the page requests served or failed so far, in order.
func (p *PagingClient) Pages() []Page {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Page(nil), p.pages...)
}

func (p *PagingClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	o := &client.ListOptions{}
	o.ApplyOptions(opts)
	if err := p.Client.List(ctx, list, opts...); err != nil {
		return err
	}
	items, err := meta.ExtractList(list)
	if err != nil {
		return err
	}
	// A stable order, so that pages neither overlap nor skip.
	slices.SortFunc(items, func(a, b runtime.Object) int { return strings.Compare(key(a), key(b)) })
	number, offset := 0, 0
	if o.Continue != "" {
		if _, err := fmt.Sscanf(o.Continue, "page-%d-offset-%d", &number, &offset); err != nil || offset > len(items) {
			return apierrors.NewBadRequest("invalid continue token " + strconv.Quote(o.Continue))
		}
	}
	kind := ""
	if gvk, err := apiGVK(list, p.Scheme()); err == nil {
		kind = gvk.Kind
	}
	page := Page{Kind: strings.TrimSuffix(kind, "List"), Namespace: o.Namespace, Number: number}
	p.mu.Lock()
	p.pages = append(p.pages, page)
	fault := p.Fault
	p.mu.Unlock()
	f := PageOK
	if fault != nil {
		f = fault(page)
	}
	limit := len(items)
	if o.Limit > 0 && int(o.Limit) < limit {
		limit = int(o.Limit)
	}
	start, end, next := offset, min(offset+limit, len(items)), ""
	switch f {
	case PageExpired:
		return apierrors.NewResourceExpired("the provided continue parameter is too old to display a consistent list result")
	case PageRepeated:
		start, end = max(offset-limit, 0), offset
		next = fmt.Sprintf("page-%d-offset-%d", number+1, offset)
	case PageEmpty:
		start, end = offset, offset
		next = fmt.Sprintf("page-%d-offset-%d", number+1, offset)
	default:
		if end < len(items) {
			next = fmt.Sprintf("page-%d-offset-%d", number+1, end)
		}
	}
	if err := meta.SetList(list, items[start:end]); err != nil {
		return err
	}
	if l, ok := list.(metav1.ListInterface); ok {
		l.SetContinue(next)
	}
	return nil
}

func key(o runtime.Object) string {
	m, err := meta.Accessor(o)
	if err != nil {
		return ""
	}
	return m.GetNamespace() + "/" + m.GetName()
}

func apiGVK(obj runtime.Object, s *runtime.Scheme) (schema.GroupVersionKind, error) {
	if gvk := obj.GetObjectKind().GroupVersionKind(); !gvk.Empty() {
		return gvk, nil
	}
	gvks, _, err := s.ObjectKinds(obj)
	if err != nil || len(gvks) == 0 {
		return schema.GroupVersionKind{}, fmt.Errorf("no kind for %T: %v", obj, err)
	}
	return gvks[0], nil
}
