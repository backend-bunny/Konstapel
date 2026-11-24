package provider

import (
	"context"
	"errors"
	"fmt"
	"slices"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Collection boundary (add-assessment-provider-contract 2.1).
//
// The host owns scope. It resolves targeting, freezes the namespace
// instances and the expected inventory, and lists the workloads that
// inventory is derived from. A provider's collection adapter only reads its
// own declared evidence source inside that scope, through the readers
// Sources grants, and returns the source objects unevaluated together with
// the limitations it met. Attribution, freshness and outcomes are the
// evaluator's; collection never derives expected subjects from what it
// reads, so missing evidence stays missing.
//
// Readers are narrow by construction: they list one declared resource,
// never write, and refuse any namespace outside the scope. They bound what
// an adapter can reach through this interface; they are not a sandbox.
// Adapters are trusted in-tree code, and the controller service account's
// RBAC is shared by every feature and broader than any provider's reads.

// Namespace is one namespace instance of a host-frozen scope.
type Namespace struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

// Scope is the host-frozen collection scope: the cluster and the namespace
// instances the expected inventory covers, in the order the host reads
// them. An empty scope (no targets) permits no read at all.
type Scope struct {
	Cluster    string      `json:"cluster"`
	Namespaces []Namespace `json:"namespaces"`
}

// HasNamespaceUID reports whether the scope contains the namespace instance.
func (s Scope) HasNamespaceUID(uid string) bool {
	return uid != "" && slices.ContainsFunc(s.Namespaces, func(n Namespace) bool { return n.UID == uid })
}

// ErrOutOfScope is a read outside the host-frozen scope. No API request is
// made for it.
var ErrOutOfScope = errors.New("outside the host-frozen collection scope")

// SourceReader is a collection adapter's read-only access to one declared
// evidence source.
type SourceReader interface {
	// List returns the source's objects in one namespace of the scope. A
	// cluster-scoped source is listed with namespace "" and only when the
	// scope is not empty; the adapter must then keep only what its
	// inventory can attribute.
	List(ctx context.Context, namespace string) ([]map[string]any, error)
}

// Sources grants a collection adapter its readers.
type Sources interface {
	// Source returns the reader of a read the provider's descriptor
	// declares, with its exact resource shape and the list verb. Any other
	// read is refused.
	Source(Read) (SourceReader, error)
}

// ClientSources is the host's Sources: readers over c for the declared
// reads of d, limited to scope and sharing one budget of DefaultLimits
// (without its timeout: the caller's context is the deadline). Only c.List
// is called, so a reader cannot write even when c can. Collect is the
// host's bounded entry point; it also decides what a stopped collection
// means.
func ClientSources(c client.Reader, d Descriptor, scope Scope) Sources {
	l := DefaultLimits()
	l.Timeout = 0
	return clientSources{c: c, d: d, scope: scope, b: &budget{l: l}}
}

type clientSources struct {
	c     client.Reader
	d     Descriptor
	scope Scope
	b     *budget
}

func (s clientSources) Source(r Read) (SourceReader, error) {
	if err := s.d.Validate(); err != nil {
		return nil, err
	}
	i := slices.IndexFunc(s.d.Reads, func(x Read) bool { return x.ID() == r.ID() })
	if i < 0 {
		return nil, fmt.Errorf("%s does not declare a read of %s", s.d.Contract(), r.ID())
	}
	declared := s.d.Reads[i]
	switch {
	case declared.Kind != r.Kind || declared.Namespaced != r.Namespaced:
		return nil, fmt.Errorf("%s declares %s as kind %s (namespaced %t), not %s (namespaced %t)",
			s.d.Contract(), r.ID(), declared.Kind, declared.Namespaced, r.Kind, r.Namespaced)
	case !slices.Contains(declared.Verbs, "list"):
		return nil, fmt.Errorf("%s does not declare list for %s", s.d.Contract(), r.ID())
	}
	names := map[string]bool{}
	for _, n := range s.scope.Namespaces {
		if n.Name != "" {
			names[n.Name] = true
		}
	}
	return clientReader{c: s.c, read: declared, names: names, empty: len(s.scope.Namespaces) == 0, b: s.b}, nil
}

type clientReader struct {
	c     client.Reader
	read  Read
	names map[string]bool
	empty bool
	b     *budget
}

// List reads every page of the source in namespace, within the
// collection's budget. It returns the complete list or no objects: a source
// failure is returned unchanged, and a bound returns the collection's
// LimitError. A continuation that expired restarts the list once from its
// first page; a second expiry stops the collection.
func (r clientReader) List(ctx context.Context, namespace string) ([]map[string]any, error) {
	var opts []client.ListOption
	switch {
	case r.read.Namespaced && (namespace == "" || !r.names[namespace]):
		return nil, fmt.Errorf("list %s in namespace %q: %w", r.read.ID(), namespace, ErrOutOfScope)
	case r.read.Namespaced:
		opts = append(opts, client.InNamespace(namespace))
	case namespace != "" || r.empty:
		return nil, fmt.Errorf("list cluster-scoped %s (namespace %q, empty scope %t): %w", r.read.ID(), namespace, r.empty, ErrOutOfScope)
	}
	what := r.read.ID()
	if namespace != "" {
		what += " in namespace " + namespace
	}
	var (
		out     []map[string]any
		seen    = map[string]bool{}
		cont    string
		objects int
		bytes   int64
		expired bool
	)
	for {
		if err := r.b.request(ctx, what); err != nil {
			r.b.giveBack(objects, bytes)
			return nil, err
		}
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(schema.GroupVersionKind{Group: r.read.Group, Version: r.read.Version, Kind: r.read.Kind + "List"})
		page := append(slices.Clone(opts), client.Limit(r.b.l.PageSize))
		if cont != "" {
			page = append(page, client.Continue(cont))
		}
		if err := r.c.List(ctx, list, page...); err != nil {
			r.b.giveBack(objects, bytes)
			if cont != "" && (apierrors.IsResourceExpired(err) || apierrors.IsGone(err)) {
				if !expired {
					// Restart from the first page: a list is one
					// consistent snapshot, never pages of two.
					expired, out, seen, cont, objects, bytes = true, nil, map[string]bool{}, "", 0, 0
					continue
				}
				return nil, r.b.halt(&LimitError{Code: StopPaginationExpired, Message: fmt.Sprintf("the list of %s expired twice during pagination", what)})
			}
			r.b.failed(ctx, err, what)
			return nil, err
		}
		var size int64
		for _, it := range list.Items {
			key := it.GetNamespace() + "/" + it.GetName()
			n, err := jsonSize(it.Object)
			if err == nil && seen[key] {
				err = errors.New("returned twice")
			}
			if err != nil {
				r.b.giveBack(objects, bytes)
				return nil, r.b.halt(&LimitError{Code: StopInvalidList, Message: fmt.Sprintf("the list of %s is not usable: object %s %v", what, key, err)})
			}
			seen[key] = true
			size += n
		}
		if err := r.b.take(len(list.Items), size, what); err != nil {
			return nil, err
		}
		objects, bytes = objects+len(list.Items), bytes+size
		for _, it := range list.Items {
			out = append(out, it.Object)
		}
		if cont = list.GetContinue(); cont == "" {
			if out == nil {
				out = []map[string]any{}
			}
			return out, nil
		}
	}
}
