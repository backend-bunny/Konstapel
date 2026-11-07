// Package capability discovers whether the external policy engine's APIs are
// served in the shape Konstapel needs and whether its service account may use
// them, per capability (add-helm-oci-distribution group 4). A missing API, an
// unsupported resource shape, denied access and an unreachable dependency are
// distinct results, so Conditions can say which one applies.
package capability

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/discovery"
)

// Name identifies a capability.
type Name string

const (
	// Delivery renders and applies engine policies.
	Delivery Name = "PolicyDelivery"
	// Assessment reads engine policy reports.
	Assessment Name = "Assessment"
	// Exceptions uses native engine policy exceptions.
	Exceptions Name = "Exceptions"
)

// Reason is a stable capability result.
type Reason string

const (
	Available Reason = "Available"
	// APINotServed: the group/version is not served at all.
	APINotServed Reason = "APINotServed"
	// ResourceMissing: the group/version is served without the resource.
	ResourceMissing Reason = "ResourceMissing"
	// UnsupportedResource: the resource is served with another kind, scope,
	// or without a required verb.
	UnsupportedResource Reason = "UnsupportedResource"
	// AccessDenied: discovery or a required operation is forbidden to the
	// service account.
	AccessDenied Reason = "AccessDenied"
	// Unavailable: discovery or authorization could not be completed
	// (transport failure, timeout, server error).
	Unavailable Reason = "DependencyUnavailable"
)

// Resource is one external API resource a capability needs.
type Resource struct {
	Group, Version, Resource, Kind string
	Namespaced                     bool
	// Verbs must be advertised by discovery.
	Verbs []string
	// Access are the operations the service account must be allowed, across
	// all namespaces for a namespaced resource. Only operations the owning
	// implementation actually performs are required.
	Access []string
}

func (r Resource) groupVersion() string { return r.Group + "/" + r.Version }

// Requirements are the tested external API shapes per capability. Version
// compatibility comes from this matrix, not from the engine's version string.
var Requirements = map[Name][]Resource{
	Delivery: {{Group: "policies.kyverno.io", Version: "v1", Resource: "validatingpolicies", Kind: "ValidatingPolicy",
		Verbs:  []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		Access: []string{"get", "list", "watch", "create", "update", "patch", "delete"}}},
	Assessment: {
		{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "policyreports", Kind: "PolicyReport", Namespaced: true,
			Verbs: []string{"get", "list", "watch"}, Access: []string{"get", "list", "watch"}},
		// Served alongside; the collector reads namespaced reports only.
		{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "clusterpolicyreports", Kind: "ClusterPolicyReport",
			Verbs: []string{"get", "list", "watch"}},
	},
	// The native exception path is owned by add-self-service-policy-exceptions;
	// until it uses PolicyExceptions, only their presence is required.
	Exceptions: {{Group: "policies.kyverno.io", Version: "v1", Resource: "policyexceptions", Kind: "PolicyException", Namespaced: true,
		Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"}}},
}

// Result is a capability check outcome.
type Result struct {
	Name    Name
	Reason  Reason
	Message string
}

// Available reports whether the capability can be used.
func (r Result) Available() bool { return r.Reason == Available }

// Error is a Result for an unavailable capability, usable as an error.
type Error struct{ Result Result }

func (e *Error) Error() string { return e.Result.Message }

// ReasonOf returns the capability reason carried by err, or "".
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Result.Reason
	}
	return ""
}

// Reviewer asks whether the service account may perform verb on a resource
// (in every namespace when namespace is "").
type Reviewer func(ctx context.Context, attrs authorizationv1.ResourceAttributes) (allowed bool, reason string, err error)

// Monitor checks capabilities with bounded discovery and authorization calls
// and caches each result for TTL, so callers can poll it cheaply and recover
// as soon as a dependency returns.
type Monitor struct {
	Discovery discovery.ServerResourcesInterfaceWithContext
	// Review checks access; nil requires no access review.
	Review Reviewer
	// Timeout bounds each check (default 10s).
	Timeout time.Duration
	// TTL is how long a result is reused (default 15s).
	TTL time.Duration
	Now func() time.Time

	mu    sync.Mutex
	cache map[Name]cached
}

type cached struct {
	at  time.Time
	res Result
}

func (m *Monitor) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Check returns the capability's current result.
func (m *Monitor) Check(ctx context.Context, n Name) Result {
	ttl := m.TTL
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	m.mu.Lock()
	if c, ok := m.cache[n]; ok && m.now().Sub(c.at) < ttl {
		m.mu.Unlock()
		return c.res
	}
	m.mu.Unlock()
	timeout := m.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res := m.check(cctx, n)
	m.mu.Lock()
	if m.cache == nil {
		m.cache = map[Name]cached{}
	}
	m.cache[n] = cached{at: m.now(), res: res}
	m.mu.Unlock()
	return res
}

// Refresh drops cached results, for example after a NoMatch error.
func (m *Monitor) Refresh() {
	m.mu.Lock()
	m.cache = nil
	m.mu.Unlock()
}

// Engine adapts a capability to an (available, error) check: an unavailable
// capability returns false and an *Error carrying its result.
func (m *Monitor) Engine(n Name) func(context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		r := m.Check(ctx, n)
		if r.Available() {
			return true, nil
		}
		return false, &Error{Result: r}
	}
}

func (m *Monitor) check(ctx context.Context, n Name) Result {
	reqs, ok := Requirements[n]
	if !ok {
		return Result{Name: n, Reason: Unavailable, Message: fmt.Sprintf("unknown capability %s", n)}
	}
	fail := func(reason Reason, format string, a ...any) Result {
		return Result{Name: n, Reason: reason, Message: string(n) + ": " + fmt.Sprintf(format, a...)}
	}
	for _, req := range reqs {
		gv := req.groupVersion()
		list, err := discoverWithContext(ctx, m.Discovery, gv)
		switch {
		case err == nil:
		case apierrors.IsNotFound(err) || discovery.IsGroupDiscoveryFailedError(err):
			return fail(APINotServed, "%s is not served", gv)
		case apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err):
			return fail(AccessDenied, "discovery of %s is forbidden: %v", gv, err)
		default:
			return fail(Unavailable, "discovery of %s failed: %v", gv, err)
		}
		i := slices.IndexFunc(list.APIResources, func(r metaResource) bool { return r.Name == req.Resource })
		if i < 0 {
			return fail(ResourceMissing, "%s is served without %s", gv, req.Resource)
		}
		got := list.APIResources[i]
		switch {
		case got.Kind != req.Kind:
			return fail(UnsupportedResource, "%s/%s has kind %s, want %s", gv, req.Resource, got.Kind, req.Kind)
		case got.Namespaced != req.Namespaced:
			return fail(UnsupportedResource, "%s/%s is %s, want %s", gv, req.Resource, scope(got.Namespaced), scope(req.Namespaced))
		}
		var missing []string
		for _, v := range req.Verbs {
			if !slices.Contains(got.Verbs, v) {
				missing = append(missing, v)
			}
		}
		if len(missing) > 0 {
			return fail(UnsupportedResource, "%s/%s does not support %s", gv, req.Resource, strings.Join(missing, ", "))
		}
		if m.Review == nil {
			continue
		}
		var denied []string
		for _, verb := range req.Access {
			allowed, why, err := m.Review(ctx, authorizationv1.ResourceAttributes{Group: req.Group, Version: req.Version, Resource: req.Resource, Verb: verb})
			if err != nil {
				return fail(Unavailable, "authorization check for %s %s failed: %v", verb, req.Resource, err)
			}
			if !allowed {
				d := verb
				if why != "" {
					d += " (" + why + ")"
				}
				denied = append(denied, d)
			}
		}
		if len(denied) > 0 {
			return fail(AccessDenied, "the service account may not %s %s.%s", strings.Join(denied, ", "), req.Resource, req.Group)
		}
	}
	return Result{Name: n, Reason: Available, Message: string(n) + ": available"}
}

func scope(namespaced bool) string {
	if namespaced {
		return "namespaced"
	}
	return "cluster-scoped"
}
