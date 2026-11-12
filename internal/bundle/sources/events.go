package sources

import (
	"context"
	"maps"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// ConfigMapCacheOptions returns options for a cache (cache.New) that holds
// only the sources ConfigMap: ConfigMaps of one namespace selected by the
// field selector metadata.name=<name>. The informer's list and watch carry
// that selector, which is what lets RBAC restrict them with resourceNames.
// The cache must hold no other type.
func ConfigMapCacheOptions(namespace, name string) cache.Options {
	return cache.Options{
		DefaultNamespaces: map[string]cache.Config{namespace: {}},
		ByObject: map[client.Object]cache.ByObject{
			&corev1.ConfigMap{}: {
				Namespaces: map[string]cache.Config{namespace: {}},
				Field:      fields.OneTermEqualSelector("metadata.name", name),
			},
		},
	}
}

// isSources reports whether o is the sources ConfigMap.
func (w *Watcher) isSources(o client.Object) bool {
	_, isCM := o.(*corev1.ConfigMap)
	return isCM && o.GetNamespace() == w.opts.Namespace && o.GetName() == w.opts.Name
}

// Kick asks the running Watcher for a Sync. It never blocks; requests
// coalesce.
func (w *Watcher) Kick() {
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

// ConfigMapHandler is the informer handler for the sources ConfigMap: every
// add, update or delete of exactly that object asks for a Sync (Kick).
// Anything else is ignored. The handler does not read or change state
// itself, so the informer is never blocked.
func (w *Watcher) ConfigMapHandler() toolscache.ResourceEventHandler {
	on := func(obj any) {
		if t, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
			obj = t.Obj
		}
		if o, ok := obj.(client.Object); ok && w.isSources(o) {
			w.Kick()
		}
	}
	return toolscache.ResourceEventHandlerFuncs{
		AddFunc:    on,
		UpdateFunc: func(_, n any) { on(n) },
		DeleteFunc: on,
	}
}

// Predicate admits only the sources ConfigMap and the Secrets and
// ConfigMaps in the controller namespace that the current configuration
// references. It consults the configuration on every event, so the set
// follows configuration changes. Watches are not needed for referenced
// objects (Sync reads them by name), but whoever does watch them must filter
// with this predicate.
func (w *Watcher) Predicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(o client.Object) bool {
		if w.isSources(o) {
			return true
		}
		if o.GetNamespace() != w.opts.Namespace {
			return false
		}
		kind := ""
		switch o.(type) {
		case *corev1.Secret:
			kind = bundle.KindSecret
		case *corev1.ConfigMap:
			kind = bundle.KindConfigMap
		default:
			return false
		}
		return len(w.ReferencedBy(kind, o.GetName())) > 0
	})
}

// addPending records affected bundle names for the Trigger.
func (w *Watcher) addPending(names []string) {
	if len(names) == 0 {
		return
	}
	w.pendingMu.Lock()
	for _, n := range names {
		w.pending[n] = true
	}
	w.pendingMu.Unlock()
	select {
	case w.notify <- struct{}{}:
	default:
	}
}

// takePending returns and clears the pending names.
func (w *Watcher) takePending() []string {
	w.pendingMu.Lock()
	defer w.pendingMu.Unlock()
	out := slices.Sorted(maps.Keys(w.pending))
	clear(w.pending)
	return out
}

// NeedLeaderElection is false: every replica resolves content (admission
// webhooks run on every replica), so every replica keeps its revisions
// current.
func (w *Watcher) NeedLeaderElection() bool { return false }

// Start syncs at once, then on every ConfigMap event and every Interval,
// until ctx ends. A failed Sync is logged and retried at the next trigger.
func (w *Watcher) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("bundle-sources")
	ticker := time.NewTicker(w.opts.Interval)
	defer ticker.Stop()
	for {
		ch, err := w.Sync(ctx)
		switch {
		case err != nil:
			logger.Info("bundle source sync failed; retrying", "error", bounded(err.Error()))
		case !ch.Empty():
			st := w.State()
			logger.Info("bundle sources changed", "revision", st.Revision, "available", st.Available, "reason", st.Reason,
				"affected", ch.Affected, "invalidated", ch.Invalidated, "invalidatedAll", ch.InvalidatedAll, "objects", ch.Objects)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-w.kick:
		case <-ticker.C:
		}
	}
}

// ProfilesFor lists the profiles whose spec.bundle.name is one of names, as
// reconcile requests (profiles are cluster-scoped). r is the manager's
// cached client.
func ProfilesFor(ctx context.Context, r client.Reader, names []string) ([]reconcile.Request, error) {
	if len(names) == 0 {
		return nil, nil
	}
	var list v1alpha1.ComplianceProfileList
	if err := r.List(ctx, &list); err != nil {
		return nil, err
	}
	var out []reconcile.Request
	for _, p := range list.Items {
		if slices.Contains(names, p.Spec.Bundle.Name) {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&p)})
		}
	}
	slices.SortFunc(out, func(a, b reconcile.Request) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Trigger turns the affected bundle names of every Sync into one
// GenericEvent per affected ComplianceProfile on each output channel: one
// channel per controller (source.Channel), the profile controller with
// handler.EnqueueRequestForObject and the binding controller with the
// profile-to-bindings map function. It runs on the leader only; names
// affected while no Trigger runs are kept (at most one entry per bundle
// name) and sent when it starts.
type Trigger struct {
	w        *Watcher
	profiles client.Reader
	out      []chan<- event.GenericEvent
	retry    time.Duration
}

// DefaultTriggerRetry is how soon a failed profile list is retried.
const DefaultTriggerRetry = 5 * time.Second

// NewTrigger returns the Trigger for w. profiles is the manager's cached
// client.
func (w *Watcher) NewTrigger(profiles client.Reader, out ...chan<- event.GenericEvent) *Trigger {
	return &Trigger{w: w, profiles: profiles, out: out, retry: DefaultTriggerRetry}
}

// NeedLeaderElection is true: the controllers it feeds run on the leader.
func (t *Trigger) NeedLeaderElection() bool { return true }

// Start sends events until ctx ends.
func (t *Trigger) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("bundle-sources-trigger")
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.w.notify:
		}
		names := t.w.takePending()
		reqs, err := ProfilesFor(ctx, t.profiles, names)
		if err != nil {
			logger.Info("listing profiles failed; retrying", "error", err.Error())
			t.w.addPending(names)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(t.retry):
			}
			continue
		}
		for _, r := range reqs {
			for _, ch := range t.out {
				select {
				case ch <- event.GenericEvent{Object: &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: r.Name}}}:
				case <-ctx.Done():
					return nil
				}
			}
		}
	}
}
