package controller

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	toolscache "k8s.io/client-go/tools/cache"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle/sources"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/observability"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// ContentConfirmer is implemented by content sources whose verdicts can be
// withdrawn after content was read (stack.Router): Confirm fails unless the
// content for ref may still be used now. The binding reconciler calls it
// immediately before it applies rendered policies.
type ContentConfirmer interface {
	Confirm(ctx context.Context, ref v1alpha1.BundleReference) error
}

var _ ContentConfirmer = (*stack.Router)(nil)

// bundleHost is the part of the manager the bundle wiring uses.
type bundleHost interface {
	Add(manager.Runnable) error
	GetAPIReader() client.Reader
	GetClient() client.Client
	GetCache() crcache.Cache
}

// bundleWiring is the bundle machinery added to a manager when OCI bundle
// sources are enabled.
type bundleWiring struct {
	stack  *stack.Stack
	router *stack.Router
	// profileEvents and bindingEvents carry the Trigger's events into the
	// profile and binding controllers (source.Channel).
	profileEvents, bindingEvents chan event.GenericEvent
	trigger                      *sources.Trigger
	watcher                      *syncedWatcher
	pinner                       *stack.Pinner
	configCache                  crcache.Cache
}

// setupBundles returns the content source every consumer uses and, when
// bundle sources are enabled, the wiring it added to h.
//
//   - LocalBundle unset (tests that pass any ContentSource): Content as is.
//   - Bundles disabled: a Router that serves LocalBundle from Content and
//     reports every other name as a Config ContentError. Nothing else is
//     constructed: no cache directory, informer, watcher or pinner.
//   - Bundles enabled: the full stack, a dedicated single-object ConfigMap
//     cache, the Watcher (every replica, after that cache synced), its
//     Trigger (leader), and the Pinner (every replica).
func setupBundles(h bundleHost, opts Options, newConfigCache func(crcache.Options) (crcache.Cache, error)) (targeting.ContentSource, *bundleWiring, error) {
	b := opts.Bundles
	if err := b.Validate(); err != nil {
		return nil, nil, err
	}
	if opts.LocalBundle == "" {
		if b.Enabled() {
			return nil, nil, errors.New("bundle sources need the vendored bundle name (Options.LocalBundle)")
		}
		return opts.Content, nil, nil
	}
	if opts.Content == nil {
		return nil, nil, errors.New("the vendored content source (Options.Content) is required")
	}
	if !b.Enabled() {
		return stack.NewRouter(opts.Content, opts.LocalBundle), nil, nil
	}
	cc, err := newConfigCache(sources.ConfigMapCacheOptions(b.Namespace, b.SourcesConfigMap))
	if err != nil {
		return nil, nil, fmt.Errorf("bundle sources ConfigMap cache: %w", err)
	}
	// Every replica resolves content, so the cache must start on every
	// replica. A cache built with ByObject options does not say so itself
	// (it would be started only on the leader).
	cc = everyReplica{cc}
	deps := stack.Deps{APIReader: h.GetAPIReader(), Config: cc}
	if opts.Observability != nil {
		deps.ObserveResolution = observeOperation(opts.Observability, observability.OperationBundleResolution)
	}
	s, err := stack.New(b, deps)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (targeting.ContentSource, *bundleWiring, error) {
		_ = s.Close()
		return nil, nil, err
	}
	inf, err := cc.GetInformer(context.Background(), &corev1.ConfigMap{})
	if err != nil {
		return fail(fmt.Errorf("bundle sources ConfigMap informer: %w", err))
	}
	if _, err := inf.AddEventHandler(s.Watcher.ConfigMapHandler()); err != nil {
		return fail(fmt.Errorf("bundle sources ConfigMap handler: %w", err))
	}
	w := &bundleWiring{
		stack: s, router: s.Router(opts.Content, opts.LocalBundle), configCache: cc,
		profileEvents: make(chan event.GenericEvent), bindingEvents: make(chan event.GenericEvent),
		watcher: &syncedWatcher{w: s.Watcher, synced: cc.WaitForCacheSync},
	}
	w.trigger = s.Watcher.NewTrigger(h.GetClient(), w.profileEvents, w.bindingEvents)
	w.pinner = &stack.Pinner{
		Pin:     s.Pin,
		Desired: stack.ClusterState{Client: h.GetClient(), Engine: h.GetAPIReader(), Local: opts.LocalBundle}.Desired,
		Events:  pinEvents(h.GetCache()),
	}
	for _, r := range []manager.Runnable{cc, w.watcher, w.trigger, w.pinner} {
		if err := h.Add(r); err != nil {
			return fail(err)
		}
	}
	return w.router, w, nil
}

// everyReplica runs a cache on every replica, not only on the leader.
type everyReplica struct{ crcache.Cache }

func (everyReplica) NeedLeaderElection() bool { return false }

// syncedWatcher starts the Watcher once the sources ConfigMap cache has
// synced, so its first Sync never mistakes an empty, unsynced cache for a
// deleted ConfigMap. Until then the configuration is "not loaded yet" and
// OCI content is a Config error; nothing else waits for it (a missing grant
// leaves only OCI content unavailable, never the controller).
type syncedWatcher struct {
	w      *sources.Watcher
	synced func(context.Context) bool
}

// NeedLeaderElection is the Watcher's: false, every replica resolves.
func (s *syncedWatcher) NeedLeaderElection() bool { return s.w.NeedLeaderElection() }

func (s *syncedWatcher) Start(ctx context.Context) error {
	if !s.synced(ctx) {
		if ctx.Err() == nil {
			log.FromContext(ctx).Info("bundle sources ConfigMap cache did not sync; OCI bundle content stays unavailable")
		}
		<-ctx.Done()
		return nil
	}
	return s.w.Start(ctx)
}

// pinEvents subscribes the Pinner to changes of profiles, bindings and
// assessment runs in the manager cache. Each event only kicks it.
func pinEvents(c crcache.Cache) func(context.Context, func()) error {
	return func(ctx context.Context, kick func()) error {
		on := func(any) { kick() }
		h := toolscache.ResourceEventHandlerFuncs{AddFunc: on, UpdateFunc: func(_, n any) { on(n) }, DeleteFunc: on}
		for _, obj := range []client.Object{&v1alpha1.ComplianceProfile{}, &v1alpha1.ComplianceBinding{}, &v1alpha1.AssessmentRun{}} {
			inf, err := c.GetInformer(ctx, obj)
			if err != nil {
				return err
			}
			if _, err := inf.AddEventHandler(h); err != nil {
				return err
			}
		}
		return nil
	}
}
