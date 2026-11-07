package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// The controller protects destinations with a finalizer before accepting pins.
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=evidencedestinations,verbs=update;patch
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=evidencedestinations/finalizers,verbs=update

const (
	// DestinationFinalizer holds an EvidenceDestination while runs, uploads,
	// retained packages, or cleanup may still need it.
	DestinationFinalizer = "compliance.erenius.io/destination"
	// LabelRunDestination records a run's accepted destination UID. It is
	// written before the destination is confirmed, so an obligation is never
	// unrecorded, and it is never changed afterwards.
	LabelRunDestination = "compliance.erenius.io/destination-uid"
)

// errDestinationLost means a run's destination selection lost to deletion,
// replacement, or readiness: the run must fail without storage writes.
var errDestinationLost = errors.New("evidence destination cannot accept this run")

// pinDestination durably pins a starting run to its binding's selected
// destination. The protocol:
//  1. Record intent: label the run with the destination UID (or reuse an
//     existing label after an interrupted start; it is never changed).
//  2. Confirm: re-read the destination uncached, require the same UID and
//     no deletion, and add the finalizer with an update conditioned on the
//     destination's resourceVersion, so a deletion racing the confirmation
//     makes it conflict.
//  3. Return the pin; the caller records it with the run's transition to
//     Collecting, before any storage write.
//
// A run whose selection is None uses the legacy file destination and gets no
// pin. Any other failure returns errDestinationLost (or a retryable error).
func (r *AssessmentRunReconciler) pinDestination(ctx context.Context, run *v1alpha1.AssessmentRun, b *v1alpha1.ComplianceBinding, now metav1.Time) (*v1alpha1.DestinationPin, error) {
	ns := r.Runtime.ControllerNamespace
	reader := r.reader()
	var ref v1alpha1.DestinationReference
	source := v1alpha1.DestinationFromBinding
	if uid := run.Labels[LabelRunDestination]; uid != "" {
		// An earlier start recorded intent: keep that destination.
		ed, err := destinationByUID(ctx, reader, uid)
		if err != nil {
			return nil, err
		}
		ref = v1alpha1.DestinationReference{Name: ed.Name, UID: uid}
		if b.Spec.Assessment == nil || b.Spec.Assessment.DestinationRef == nil {
			source = v1alpha1.DestinationFromDefault
		}
	} else {
		sel := selectDestination(ctx, reader, ns, b)
		switch {
		case sel.Source == v1alpha1.DestinationNone:
			return nil, nil
		case !sel.Ready:
			return nil, fmt.Errorf("%w: %s: %s", errDestinationLost, sel.Reason, sel.Message)
		}
		ref, source = *sel.Ref, sel.Source
		if run.Labels == nil {
			run.Labels = map[string]string{}
		}
		run.Labels[LabelRunDestination] = ref.UID
		if err := r.Client.Update(ctx, run); err != nil {
			return nil, err
		}
	}
	ed := &v1alpha1.EvidenceDestination{}
	if err := reader.Get(ctx, client.ObjectKey{Name: ref.Name}, ed); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("%w: EvidenceDestination %s no longer exists", errDestinationLost, ref.Name)
		}
		return nil, err
	}
	switch {
	case string(ed.UID) != ref.UID:
		return nil, fmt.Errorf("%w: EvidenceDestination %s was replaced", errDestinationLost, ref.Name)
	case !ed.DeletionTimestamp.IsZero():
		return nil, fmt.Errorf("%w: EvidenceDestination %s is retiring", errDestinationLost, ref.Name)
	}
	controllerutil.AddFinalizer(ed, DestinationFinalizer)
	// Always update: the resourceVersion precondition is the confirmation.
	if err := r.Client.Update(ctx, ed); err != nil {
		if apierrors.IsConflict(err) {
			return nil, fmt.Errorf("destination changed while pinning; retrying: %w", err)
		}
		return nil, err
	}
	if !ed.DeletionTimestamp.IsZero() {
		return nil, fmt.Errorf("%w: EvidenceDestination %s is retiring", errDestinationLost, ref.Name)
	}
	s := ed.Spec.S3
	return &v1alpha1.DestinationPin{DestinationReference: ref, Endpoint: s.Endpoint, Bucket: s.Bucket, Region: s.Region, Prefix: s.Prefix, Source: source, PinnedAt: now}, nil
}

func destinationByUID(ctx context.Context, r client.Reader, uid string) (*v1alpha1.EvidenceDestination, error) {
	var list v1alpha1.EvidenceDestinationList
	if err := r.List(ctx, &list); err != nil {
		return nil, err
	}
	for i := range list.Items {
		if string(list.Items[i].UID) == uid {
			return &list.Items[i], nil
		}
	}
	return nil, fmt.Errorf("%w: the run's recorded destination %s no longer exists", errDestinationLost, uid)
}

// DestinationPublishers builds publishers for pinned destinations by UID.
// The pinned location must still match the destination (it is immutable,
// so a mismatch means a different resource), and credentials and trust are
// resolved through it on every build, so rotation applies to history.
type DestinationPublishers struct {
	Reader    client.Reader
	Namespace string
	// New builds a publisher; tests replace it.
	New func(ctx context.Context, d s3store.Destination, r client.Reader, namespace string) (publication.Publisher, error)

	mu    sync.Mutex
	cache map[string]cached

	// In-process operations per destination UID, cancelled by Fence.
	inflightMu sync.Mutex
	inflight   map[string]map[*inflightOp]struct{}
	fenced     map[string]bool
}

type inflightOp struct {
	desc   string
	cancel context.CancelFunc
}

// Begin registers a unit of storage work against a destination. The
// returned context is cancelled when the destination is fenced; done must
// be called when the work ends. Work cannot begin on a fenced destination.
func (p *DestinationPublishers) Begin(ctx context.Context, uid, desc string) (context.Context, func(), error) {
	p.inflightMu.Lock()
	defer p.inflightMu.Unlock()
	if p.fenced[uid] {
		return ctx, func() {}, publication.ErrOrphaned
	}
	ctx, cancel := context.WithCancel(ctx)
	op := &inflightOp{desc: desc, cancel: cancel}
	if p.inflight == nil {
		p.inflight = map[string]map[*inflightOp]struct{}{}
	}
	if p.inflight[uid] == nil {
		p.inflight[uid] = map[*inflightOp]struct{}{}
	}
	p.inflight[uid][op] = struct{}{}
	return ctx, func() {
		cancel()
		p.inflightMu.Lock()
		delete(p.inflight[uid], op)
		p.inflightMu.Unlock()
	}, nil
}

// Fence stops all new work for a destination in this process, cancels work
// in flight, and waits up to wait for it to end. It returns the work that
// was still in flight: its remote outcome is unknown. Cancellation never
// reverses a request the storage service already received.
func (p *DestinationPublishers) Fence(uid string, wait time.Duration) []string {
	p.inflightMu.Lock()
	if p.fenced == nil {
		p.fenced = map[string]bool{}
	}
	p.fenced[uid] = true
	for op := range p.inflight[uid] {
		op.cancel()
	}
	p.inflightMu.Unlock()
	deadline := time.Now().Add(wait)
	for {
		p.inflightMu.Lock()
		var left []string
		for op := range p.inflight[uid] {
			left = append(left, op.desc)
		}
		p.inflightMu.Unlock()
		if len(left) == 0 || !time.Now().Before(deadline) {
			slices.Sort(left)
			return left
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type cached struct {
	generation int64
	pub        publication.Publisher
}

// For returns the publisher of a run's pinned destination.
func (p *DestinationPublishers) For(ctx context.Context, pin *v1alpha1.DestinationPin) (publication.Publisher, error) {
	if pin.OrphanedAt != nil {
		// Handed off: never served, even after the destination is gone or
		// another destination exists at the same location.
		return nil, publication.ErrOrphaned
	}
	ed, err := destinationByUID(ctx, p.Reader, pin.UID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", publication.ErrUnavailable, err)
	}
	if ed.Status.OrphanIntent != nil {
		return nil, publication.ErrOrphaned
	}
	s := ed.Spec.S3
	if s.Endpoint != pin.Endpoint || s.Bucket != pin.Bucket || s.Region != pin.Region || s.Prefix != pin.Prefix {
		return nil, fmt.Errorf("pinned location of %s does not match the destination", pin.Name)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.cache[pin.UID]; ok && c.generation == ed.Generation {
		return c.pub, nil
	}
	d, err := DestinationFromAPI(ctx, p.Reader, p.Namespace, ed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", publication.ErrUnavailable, err)
	}
	build := p.New
	if build == nil {
		build = func(ctx context.Context, d s3store.Destination, r client.Reader, ns string) (publication.Publisher, error) {
			return s3store.NewPublisher(ctx, d, r, controllerNamespace(ns))
		}
	}
	pub, err := build(ctx, d, p.Reader, p.Namespace)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", publication.ErrUnavailable, err)
	}
	if p.cache == nil {
		p.cache = map[string]cached{}
	}
	p.cache[pin.UID] = cached{generation: ed.Generation, pub: pub}
	return pub, nil
}

// publisherFor routes a run's storage work: its pinned destination, or the
// legacy file destination for unpinned runs.
func (r *AssessmentRunReconciler) publisherFor(ctx context.Context, run *v1alpha1.AssessmentRun) (publication.Publisher, error) {
	if run.Status.Destination == nil {
		if r.Runtime.Publisher == nil {
			return nil, errors.New("no evidence publisher is configured")
		}
		return r.Runtime.Publisher, nil
	}
	if r.Runtime.Destinations == nil {
		return nil, fmt.Errorf("%w: pinned destinations are not configured", publication.ErrUnavailable)
	}
	return r.Runtime.Destinations.For(ctx, run.Status.Destination)
}

func (r *AssessmentRunReconciler) reader() client.Reader {
	if r.Assess != nil && r.Assess.Reader != nil {
		return r.Assess.Reader
	}
	return r.Client
}

// orphanFenced returns, from an uncached read, a pinned run's destination
// when its orphan handoff was accepted, and nil otherwise. A destination
// that no longer exists is not fenced here (its absence is handled by the
// caller).
func orphanFenced(ctx context.Context, r client.Reader, pin *v1alpha1.DestinationPin) (*v1alpha1.EvidenceDestination, error) {
	ed, err := destinationByUID(ctx, r, pin.UID)
	if errors.Is(err, errDestinationLost) {
		return nil, nil
	}
	if err != nil || ed.Status.OrphanIntent == nil {
		return nil, err
	}
	return ed, nil
}
