package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle/sources"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/capability"
	"github.com/backend-bunny/Konstapel/internal/observability"
)

// capabilityChecker is the capability owner's cached check.
type capabilityChecker interface {
	Check(ctx context.Context, n capability.Name) capability.Result
}

// observedCapabilities are the capabilities the manager always uses.
var observedCapabilities = map[capability.Name]observability.Capability{
	capability.Delivery:   observability.CapabilityPolicyDelivery,
	capability.Assessment: observability.CapabilityAssessment,
}

// capabilityStatus maps a capability result: a dependency that could not
// be asked is unknown; every definite refusal or missing API is false.
func capabilityStatus(r capability.Result) observability.Status {
	switch r.Reason {
	case capability.Available:
		return observability.StatusTrue
	case capability.Unavailable, "":
		return observability.StatusUnknown
	}
	return observability.StatusFalse
}

// publishTargeting publishes bindings from the manager's synchronized
// cache with the capability owner's current (cached) results.
func publishTargeting(c client.Reader, hub *observability.Hub, caps capabilityChecker) func(context.Context, observability.Term, time.Time) error {
	return func(ctx context.Context, t observability.Term, now time.Time) error {
		var list v1alpha1.ComplianceBindingList
		if err := c.List(ctx, &list); err != nil {
			return fmt.Errorf("list bindings: %w", err)
		}
		states := map[observability.Capability]observability.Status{}
		for name, label := range observedCapabilities {
			states[label] = capabilityStatus(caps.Check(ctx, name))
		}
		return hub.PublishTargeting(t, now, observability.TargetingFrom(list.Items, states))
	}
}

// publishStorage publishes the durable backlog from retained run records.
func publishStorage(c client.Reader, hub *observability.Hub) func(context.Context, observability.Term, time.Time) error {
	return func(ctx context.Context, t observability.Term, now time.Time) error {
		var list v1alpha1.AssessmentRunList
		if err := c.List(ctx, &list); err != nil {
			return fmt.Errorf("list assessment runs: %w", err)
		}
		return hub.PublishStorage(t, now, observability.StorageFrom(list.Items, now))
	}
}

// publishBundles marks bundle resolution synchronized while the sources
// Watcher's latest Sync read its configuration within bound.
func publishBundles(lastSync func() (time.Time, bool), bound time.Duration, hub *observability.Hub) func(context.Context, observability.Term, time.Time) error {
	return func(_ context.Context, t observability.Term, now time.Time) error {
		at, ok := lastSync()
		switch {
		case at.IsZero():
			return errors.New("bundle sources not synchronized yet")
		case !ok:
			return errors.New("the latest bundle source sync failed")
		case now.Sub(at) > bound:
			return fmt.Errorf("bundle sources last synchronized %s ago", now.Sub(at).Truncate(time.Second))
		}
		return hub.PublishBundleResolution(t, now)
	}
}

// bundleSyncBound is how old the Watcher's latest successful Sync may be:
// two refresh intervals plus one read timeout.
func bundleSyncBound(o stack.Options) time.Duration {
	interval := o.RefreshInterval
	if interval == 0 {
		interval = stack.DefaultRefreshInterval
	}
	return 2*interval + sources.DefaultReadTimeout
}

// setupObservability adds one leader-elected Refresher per implemented
// owner domain. Bundle resolution is observed only when bundle sources
// are enabled.
func setupObservability(mgr manager.Manager, hub *observability.Hub, caps capabilityChecker, bundles *bundleWiring, bundleOpts stack.Options) error {
	synced := func(ctx context.Context) bool { return mgr.GetCache().WaitForCacheSync(ctx) }
	refreshers := []*observability.Refresher{}
	for _, d := range []struct {
		name    string
		domain  observability.Domain
		obj     client.Object
		publish func(context.Context, observability.Term, time.Time) error
	}{
		{"targeting-projection", observability.DomainTargeting, &v1alpha1.ComplianceBinding{}, publishTargeting(mgr.GetClient(), hub, caps)},
		{"storage-projection", observability.DomainEvidenceStorage, &v1alpha1.AssessmentRun{}, publishStorage(mgr.GetClient(), hub)},
	} {
		inf, err := mgr.GetCache().GetInformer(context.Background(), d.obj)
		if err != nil {
			return err
		}
		trigger, notify := observability.Notifier()
		if _, err := inf.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
			AddFunc:    func(any) { notify() },
			UpdateFunc: func(any, any) { notify() },
			DeleteFunc: func(any) { notify() },
		}); err != nil {
			return err
		}
		refreshers = append(refreshers, &observability.Refresher{Name: d.name, Hub: hub, Domain: d.domain, Synced: synced, Publish: d.publish, Trigger: trigger})
	}
	if bundles != nil {
		w := bundles.stack.Watcher
		refreshers = append(refreshers, &observability.Refresher{Name: "bundle-projection", Hub: hub, Domain: observability.DomainBundleResolution,
			Publish: publishBundles(w.LastSync, bundleSyncBound(bundleOpts), hub)})
	}
	for _, r := range refreshers {
		if err := mgr.Add(r); err != nil {
			return err
		}
	}
	return nil
}

// observeOperation adapts an error outcome to the Hub's attempt metrics.
func observeOperation(hub *observability.Hub, op observability.Operation) func(error, time.Duration) {
	return func(err error, d time.Duration) {
		r := observability.ResultSuccess
		if err != nil {
			r = observability.ResultFailure
		}
		hub.ObserveOperation(op, r, d)
	}
}
