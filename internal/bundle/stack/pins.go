package stack

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/discovery"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Pin defaults.
const (
	// DefaultPinResync re-reads cluster state and retries failed pins even
	// without an event.
	DefaultPinResync = time.Minute
	// DefaultPinTimeout bounds one pin (a resolution that may retrieve).
	DefaultPinTimeout = 2 * time.Minute
	// DefaultPinStateTimeout bounds the cluster reads of one pass.
	DefaultPinStateTimeout = 30 * time.Second
)

// PinKey identifies one pin: a lease holder (bundle.HolderProfile,
// HolderApplied or HolderAssessment), its owner and the pinned bundle.
type PinKey struct {
	Holder, Owner, Name, Digest string
}

func (k PinKey) String() string {
	return k.Holder + ":" + k.Owner + ":" + k.Name + "@" + k.Digest
}

// PinFunc pins ref for holder/owner and returns its idempotent release.
// (*Stack).Pin implements it.
type PinFunc func(ctx context.Context, ref v1alpha1.BundleReference, holder, owner string) (func() error, error)

// Desired is the pin set cluster state calls for.
type Desired struct {
	Keys map[PinKey]bool
	// Unknown holders could not be read this pass: their current pins are
	// kept as they are (never released because of a read failure).
	Unknown map[string]bool
}

// DesiredFunc computes the pin set from cluster state.
type DesiredFunc func(ctx context.Context) (Desired, error)

// Pinner keeps the cache leases cluster state calls for: set semantics per
// holder and owner, acquiring missing pins and releasing stale ones. Leases
// live in memory, so after a restart the first pass re-pins everything.
//
// It runs on every replica (NeedLeaderElection is false): each replica has
// its own cache and serves admission webhooks, so it pins what it may serve.
// Reconcilers never wait for it: it runs in its own goroutine, woken by Kick
// (coalescing, non-blocking) and every Resync, and a pin that fails (the
// registry is down, the source is not configured) is retried on the next
// pass. A pin keeps bytes only; it never authorizes later use.
type Pinner struct {
	Pin     PinFunc
	Desired DesiredFunc
	// Events, when set, is called once at Start to subscribe to the
	// cluster events that change the desired set; it calls kick on each.
	Events func(ctx context.Context, kick func()) error
	// Resync, Timeout and StateTimeout default to DefaultPinResync,
	// DefaultPinTimeout and DefaultPinStateTimeout.
	Resync, Timeout, StateTimeout time.Duration

	once sync.Once
	kick chan struct{}

	mu   sync.Mutex
	held map[PinKey]func() error
	// passes counts completed passes (tests wait on it, never sleep).
	passes chan struct{}
}

func (p *Pinner) init() {
	p.once.Do(func() {
		p.kick = make(chan struct{}, 1)
		p.held = map[PinKey]func() error{}
	})
}

// Kick asks for a pass. It never blocks; requests coalesce.
func (p *Pinner) Kick() {
	p.init()
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// NeedLeaderElection is false: every replica pins what it serves.
func (p *Pinner) NeedLeaderElection() bool { return false }

// Held returns the current pins, sorted.
func (p *Pinner) Held() []PinKey {
	p.init()
	p.mu.Lock()
	defer p.mu.Unlock()
	keys := slices.Collect(maps.Keys(p.held))
	slices.SortFunc(keys, func(a, b PinKey) int { return strings.Compare(a.String(), b.String()) })
	return keys
}

// Start runs passes until ctx ends, then releases every pin.
func (p *Pinner) Start(ctx context.Context) error {
	p.init()
	logger := log.FromContext(ctx).WithName("bundle-pins")
	if p.Events != nil {
		if err := p.Events(ctx, p.Kick); err != nil {
			return fmt.Errorf("bundle pins: subscribing to events: %w", err)
		}
	}
	resync := p.Resync
	if resync <= 0 {
		resync = DefaultPinResync
	}
	ticker := time.NewTicker(resync)
	defer ticker.Stop()
	defer p.releaseAll()
	for {
		if err := p.Reconcile(ctx); err != nil && ctx.Err() == nil {
			logger.Info("some bundle pins are not held; retrying", "error", err.Error())
		}
		if p.passes != nil {
			select {
			case p.passes <- struct{}{}:
			case <-ctx.Done():
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-p.kick:
		case <-ticker.C:
		}
	}
}

// Reconcile runs one pass: release pins no longer desired (except for
// holders whose state is unknown), then acquire missing ones. It returns
// the pin and release failures, joined; they are retried next pass.
func (p *Pinner) Reconcile(ctx context.Context) error {
	p.init()
	st := p.StateTimeout
	if st <= 0 {
		st = DefaultPinStateTimeout
	}
	sctx, cancel := context.WithTimeout(ctx, st)
	want, err := p.Desired(sctx)
	cancel()
	if err != nil {
		return fmt.Errorf("reading the desired pins: %w", err)
	}
	var errs []error
	p.mu.Lock()
	var stale []PinKey
	for k := range p.held {
		if !want.Keys[k] && !want.Unknown[k.Holder] {
			stale = append(stale, k)
		}
	}
	var missing []PinKey
	for k := range want.Keys {
		if _, ok := p.held[k]; !ok {
			missing = append(missing, k)
		}
	}
	p.mu.Unlock()
	for _, k := range stale {
		p.mu.Lock()
		release := p.held[k]
		delete(p.held, k)
		p.mu.Unlock()
		if err := release(); err != nil {
			errs = append(errs, fmt.Errorf("releasing %s: %w", k, err))
		}
	}
	slices.SortFunc(missing, func(a, b PinKey) int { return strings.Compare(a.String(), b.String()) })
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = DefaultPinTimeout
	}
	for _, k := range missing {
		if ctx.Err() != nil {
			break
		}
		pctx, cancel := context.WithTimeout(ctx, timeout)
		release, err := p.Pin(pctx, v1alpha1.BundleReference{Name: k.Name, Digest: k.Digest}, k.Holder, k.Owner)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("pinning %s: %w", k, err))
			continue
		}
		p.mu.Lock()
		p.held[k] = release
		p.mu.Unlock()
	}
	return errors.Join(errs...)
}

func (p *Pinner) releaseAll() {
	p.mu.Lock()
	held := p.held
	p.held = map[PinKey]func() error{}
	p.mu.Unlock()
	for _, release := range held {
		_ = release()
	}
}

// ClusterState computes the desired pins from cluster objects.
//
//   - profile: every ComplianceProfile's spec.bundle (owner profile/<name>);
//   - applied: the bundle and bundle-digest annotations of every engine
//     policy Konstapel manages (owner binding/<binding>): what is enforcing
//     now, which a failed update or revocation leaves in place. Binding
//     status records only the last resolved profile digest, not what is
//     applied, so the engine policies are the authority. An engine API
//     that is not served means nothing is applied;
//   - assessment: for every AssessmentRun that may still snapshot (phase
//     empty, Pending, Collecting or Exporting), its binding's profile's
//     spec.bundle (owner run/<name>).
//
// The vendored bundle (Local) is never pinned: it is not in the cache.
type ClusterState struct {
	// Client is the manager's cached client (profiles, bindings, runs).
	Client client.Reader
	// Engine reads engine policies uncached (the manager's API reader),
	// selected by the managed-by label.
	Engine client.Reader
	// Local is the vendored bundle name.
	Local string
}

// Desired implements DesiredFunc.
func (s ClusterState) Desired(ctx context.Context) (Desired, error) {
	d := Desired{Keys: map[PinKey]bool{}, Unknown: map[string]bool{}}
	add := func(holder, owner string, ref v1alpha1.BundleReference) {
		if ref.Name == "" || ref.Digest == "" || ref.Name == s.Local {
			return
		}
		d.Keys[PinKey{Holder: holder, Owner: owner, Name: ref.Name, Digest: ref.Digest}] = true
	}

	var profiles v1alpha1.ComplianceProfileList
	profilesOK := s.Client.List(ctx, &profiles) == nil
	if !profilesOK {
		d.Unknown[bundle.HolderProfile] = true
	}
	byName := map[string]v1alpha1.BundleReference{}
	for _, p := range profiles.Items {
		byName[p.Name] = p.Spec.Bundle
		add(bundle.HolderProfile, "profile/"+p.Name, p.Spec.Bundle)
	}

	policies := &unstructured.UnstructuredList{}
	policies.SetGroupVersionKind(targeting.ValidatingPolicyGVK.GroupVersion().WithKind(targeting.ValidatingPolicyGVK.Kind + "List"))
	err := s.Engine.List(ctx, policies, client.MatchingLabels{targeting.LabelManagedBy: targeting.ManagedByValue})
	switch {
	case err == nil:
		for _, o := range policies.Items {
			a := o.GetAnnotations()
			owner := a[targeting.AnnotationBinding]
			if owner == "" {
				owner = o.GetLabels()[targeting.LabelBindingUID]
			}
			add(bundle.HolderApplied, "binding/"+owner, v1alpha1.BundleReference{Name: a[targeting.AnnotationBundle], Digest: a[targeting.AnnotationBundleDigest]})
		}
	case meta.IsNoMatchError(err) || discovery.IsGroupDiscoveryFailedError(err):
		// The engine API is not served: nothing is applied.
	default:
		d.Unknown[bundle.HolderApplied] = true
	}

	var runs v1alpha1.AssessmentRunList
	var bindings v1alpha1.ComplianceBindingList
	if !profilesOK || s.Client.List(ctx, &runs) != nil || s.Client.List(ctx, &bindings) != nil {
		d.Unknown[bundle.HolderAssessment] = true
		return d, nil
	}
	profileOf := map[string]string{}
	for _, b := range bindings.Items {
		profileOf[b.Name] = b.Spec.ProfileRef.Name
	}
	for _, r := range runs.Items {
		switch r.Status.Phase {
		case "", v1alpha1.RunPending, v1alpha1.RunCollecting, v1alpha1.RunExporting:
		default:
			continue
		}
		if p, ok := profileOf[r.Spec.BindingRef.Name]; ok {
			add(bundle.HolderAssessment, "run/"+r.Name, byName[p])
		}
	}
	return d, nil
}
