package observability

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/utils/clock"
)

// DefaultMaxAge is the maximum projection age: a domain whose owner has not
// republished within it is no longer ready, even if scrapes still succeed.
const DefaultMaxAge = 2 * time.Minute

// Errors returned by Publish and Withdraw.
var (
	// ErrNotLeading: the term is not this replica's current leadership term.
	ErrNotLeading = errors.New("observability: not the current leadership term")
	// ErrDisabled: the domain is not enabled in this process.
	ErrDisabled = errors.New("observability: domain is disabled")
	// ErrOutOfOrder: the snapshot is older than the one already held.
	ErrOutOfOrder = errors.New("observability: snapshot older than the current projection")
)

// Term identifies one leadership acquisition. Zero is never a valid term.
type Term uint64

// Options configure a Hub.
type Options struct {
	// Enabled lists the owner domains this process is expected to report.
	// Every other domain is exposed as disabled, never as working.
	Enabled []Domain
	// MaxAge bounds projection age; zero means DefaultMaxAge.
	MaxAge time.Duration
	// Clock is the scrape-time clock; nil uses the real clock.
	Clock clock.PassiveClock
}

type held[T any] struct {
	produced time.Time
	value    T
}

// Hub holds immutable owner snapshots and serves them as Prometheus
// metrics. A scrape only reads what owners published; it never calls back
// into an owner, a report, a registry or storage.
//
// Owner projections are leader-scoped: they are accepted only for the
// current leadership term, cleared when it ends, and absent until an owner
// republishes from reconstructed state in the next term. Operation metrics
// are process-local and exposed by every replica.
type Hub struct {
	clock   clock.PassiveClock
	maxAge  time.Duration
	enabled map[Domain]bool
	descs   map[string]*prometheus.Desc

	attempts  *prometheus.CounterVec
	durations *prometheus.HistogramVec

	mu         sync.Mutex
	term       Term // current term while leading
	lastTerm   Term
	targeting  *held[TargetingSnapshot]
	assessment *held[AssessmentSnapshot]
	bundles    *held[struct{}]
	storage    *held[StorageSnapshot]
}

// NewHub returns a Hub that is not leading and holds no projection.
func NewHub(o Options) (*Hub, error) {
	h := &Hub{clock: o.Clock, maxAge: o.MaxAge, enabled: map[Domain]bool{}, descs: map[string]*prometheus.Desc{}}
	if h.clock == nil {
		h.clock = clock.RealClock{}
	}
	if h.maxAge == 0 {
		h.maxAge = DefaultMaxAge
	}
	if h.maxAge < 0 {
		return nil, fmt.Errorf("observability: max age %s must be positive", h.maxAge)
	}
	for _, d := range o.Enabled {
		if !isOwnerDomain(d) {
			return nil, fmt.Errorf("observability: %q is not an owner domain", d)
		}
		h.enabled[d] = true
	}
	for _, m := range Catalog {
		names := make([]string, len(m.Labels))
		for i, l := range m.Labels {
			names[i] = l.Name
		}
		switch m.Name {
		case "konstapel_operation_attempts_total":
			h.attempts = prometheus.NewCounterVec(prometheus.CounterOpts{Name: m.Name, Help: m.Help}, names)
		case "konstapel_operation_duration_seconds":
			h.durations = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: m.Name, Help: m.Help, Buckets: DurationBuckets}, names)
		default:
			h.descs[m.Name] = prometheus.NewDesc(m.Name, m.Help, names, nil)
		}
	}
	// Every enum combination exists from the start: "zero attempts" is a
	// known value, not a missing series.
	for _, op := range operationValues {
		for _, r := range resultValues {
			h.attempts.WithLabelValues(op, r)
			h.durations.WithLabelValues(op, r)
		}
	}
	return h, nil
}

func isOwnerDomain(d Domain) bool {
	for _, o := range Domains {
		if d == o {
			return true
		}
	}
	return false
}

// Acquire starts a new leadership term. Projections from any earlier term
// are discarded; owners must republish from synchronized state.
func (h *Hub) Acquire() Term {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastTerm++
	h.term = h.lastTerm
	h.clear()
	return h.term
}

// Release ends term t and clears every owner projection. Releasing a term
// that is not current does nothing.
func (h *Hub) Release(t Term) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if t == 0 || t != h.term {
		return
	}
	h.term = 0
	h.clear()
}

// Term returns the current leadership term, or false when not leading.
// Owners capture it before reading the state they publish.
func (h *Hub) Term() (Term, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.term, h.term != 0
}

func (h *Hub) clear() {
	h.targeting, h.assessment, h.bundles, h.storage = nil, nil, nil, nil
}

func (h *Hub) admit(t Term, d Domain, produced time.Time, current time.Time, have bool) error {
	switch {
	case !h.enabled[d]:
		return fmt.Errorf("%w: %s", ErrDisabled, d)
	case t == 0 || t != h.term:
		return ErrNotLeading
	case produced.IsZero():
		return errors.New("observability: snapshot production time is required")
	case have && produced.Before(current):
		return ErrOutOfOrder
	}
	return nil
}

func publish[T interface{ validate() error }](h *Hub, t Term, d Domain, produced time.Time, v T, slot **held[T], clone func(T) T) error {
	if err := v.validate(); err != nil {
		return fmt.Errorf("observability: invalid %s snapshot: %w", d, err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var cur time.Time
	if *slot != nil {
		cur = (*slot).produced
	}
	if err := h.admit(t, d, produced, cur, *slot != nil); err != nil {
		return err
	}
	*slot = &held[T]{produced: produced, value: clone(v)}
	return nil
}

// PublishTargeting replaces the targeting projection. produced is when
// the owner read the synchronized state it summarizes.
func (h *Hub) PublishTargeting(t Term, produced time.Time, s TargetingSnapshot) error {
	return publish(h, t, DomainTargeting, produced, s, &h.targeting, TargetingSnapshot.clone)
}

// PublishAssessment replaces the assessment projection.
func (h *Hub) PublishAssessment(t Term, produced time.Time, s AssessmentSnapshot) error {
	return publish(h, t, DomainAssessment, produced, s, &h.assessment, AssessmentSnapshot.clone)
}

// PublishStorage replaces the evidence-storage projection.
func (h *Hub) PublishStorage(t Term, produced time.Time, s StorageSnapshot) error {
	return publish(h, t, DomainEvidenceStorage, produced, s, &h.storage, StorageSnapshot.clone)
}

// PublishBundleResolution records that bundle resolution is synchronized
// and usable at produced. The domain has readiness only.
func (h *Hub) PublishBundleResolution(t Term, produced time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	var cur time.Time
	if h.bundles != nil {
		cur = h.bundles.produced
	}
	if err := h.admit(t, DomainBundleResolution, produced, cur, h.bundles != nil); err != nil {
		return err
	}
	h.bundles = &held[struct{}]{produced: produced}
	return nil
}

// Withdraw clears domain d's projection when its owner loses synchronized
// or usable state (a watch gap, an unsynchronized cache).
func (h *Hub) Withdraw(t Term, d Domain) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if t == 0 || t != h.term {
		return ErrNotLeading
	}
	switch d {
	case DomainTargeting:
		h.targeting = nil
	case DomainAssessment:
		h.assessment = nil
	case DomainBundleResolution:
		h.bundles = nil
	case DomainEvidenceStorage:
		h.storage = nil
	default:
		return fmt.Errorf("observability: %q is not an owner domain", d)
	}
	return nil
}

// ObserveOperation records one completed attempt of a bounded operation.
func (h *Hub) ObserveOperation(op Operation, r Result, d time.Duration) {
	h.attempts.WithLabelValues(string(op), string(r)).Inc()
	h.durations.WithLabelValues(string(op), string(r)).Observe(d.Seconds())
}

// Describe implements prometheus.Collector.
func (h *Hub) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range h.descs {
		ch <- d
	}
	h.attempts.Describe(ch)
	h.durations.Describe(ch)
}

// Collect implements prometheus.Collector.
func (h *Hub) Collect(ch chan<- prometheus.Metric) {
	h.attempts.Collect(ch)
	h.durations.Collect(ch)
	for _, m := range h.gather(h.clock.Now()) {
		ch <- m
	}
}

// fresh reports whether a projection produced at p is usable at now.
func (h *Hub) fresh(p, now time.Time) bool { return now.Sub(p) <= h.maxAge }

func (h *Hub) gather(now time.Time) []prometheus.Metric {
	h.mu.Lock()
	tg, as, bu, st := h.targeting, h.assessment, h.bundles, h.storage
	h.mu.Unlock()
	// Held values are immutable after publication; no lock is needed.

	var out []prometheus.Metric
	gauge := func(name string, v float64, labels ...string) {
		out = append(out, prometheus.MustNewConstMetric(h.descs[name], prometheus.GaugeValue, v, labels...))
	}
	ts := func(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }
	b2f := func(b bool) float64 {
		if b {
			return 1
		}
		return 0
	}

	produced := map[Domain]*time.Time{}
	if tg != nil {
		produced[DomainTargeting] = &tg.produced
	}
	if as != nil {
		produced[DomainAssessment] = &as.produced
	}
	if bu != nil {
		produced[DomainBundleResolution] = &bu.produced
	}
	if st != nil {
		produced[DomainEvidenceStorage] = &st.produced
	}
	ready := map[Domain]bool{}
	for _, d := range Domains {
		p := produced[d]
		ready[d] = h.enabled[d] && p != nil && h.fresh(*p, now)
		gauge("konstapel_observation_enabled", b2f(h.enabled[d]), string(d))
		gauge("konstapel_observation_ready", b2f(ready[d]), string(d))
		if p != nil {
			gauge("konstapel_observation_updated_timestamp_seconds", ts(*p), string(d))
		}
	}

	// A binding name whose ready domains disagree on its UID is in
	// transition (deleted and recreated); none of its series is exposed
	// until the owners agree.
	uids := map[string]string{}
	ambiguous := map[string]bool{}
	note := func(r BindingRef) {
		if u, ok := uids[r.Name]; ok && u != r.UID {
			ambiguous[r.Name] = true
		}
		uids[r.Name] = r.UID
	}
	if ready[DomainTargeting] {
		for _, b := range tg.value.Bindings {
			note(b.Binding)
		}
	}
	if ready[DomainAssessment] {
		for _, b := range as.value.Bindings {
			note(b.Binding)
		}
	}

	if ready[DomainTargeting] {
		for _, b := range tg.value.Bindings {
			n := b.Binding.Name
			if ambiguous[n] {
				continue
			}
			gauge("konstapel_binding_created_timestamp_seconds", ts(b.Created), n)
			for cond, s := range map[string]Status{"Resolved": b.Resolved, "EngineReady": b.EngineReady} {
				for _, v := range statusValues {
					gauge("konstapel_binding_condition", b2f(string(s) == v), n, cond, v)
				}
			}
			if b.TargetNamespaces != nil {
				gauge("konstapel_binding_target_namespaces", float64(*b.TargetNamespaces), n)
			}
		}
		for c, s := range tg.value.Capabilities {
			for _, v := range statusValues {
				gauge("konstapel_capability_condition", b2f(string(s) == v), string(c), v)
			}
		}
	}

	if ready[DomainAssessment] {
		for _, b := range as.value.Bindings {
			n := b.Binding.Name
			if ambiguous[n] {
				continue
			}
			views := []struct {
				view View
				p    viewProjection
			}{{ViewCurrent, projectCurrent(b.Current, now)}, {ViewLatestClosed, projectClosed(b.LatestClosed)}}
			for _, v := range views {
				view := string(v.view)
				for _, s := range AssessmentStatuses {
					gauge("konstapel_binding_assessment_status", b2f(string(v.p.status) == s), n, view, s)
				}
				if v.p.counts != nil {
					for _, s := range CheckStates {
						gauge("konstapel_binding_assessment_checks", float64(v.p.counts[s]), n, view, s)
					}
				}
				if v.p.complete != nil {
					gauge("konstapel_binding_assessment_complete", b2f(*v.p.complete), n, view)
				}
				if v.p.oldest != nil {
					gauge("konstapel_binding_oldest_evaluation_timestamp_seconds", ts(*v.p.oldest), n, view)
				}
			}
			if b.Current != nil && b.Current.ValidUntil != nil {
				gauge("konstapel_binding_current_evidence_expiry_timestamp_seconds", ts(*b.Current.ValidUntil), n)
			}
			if r := b.LatestClosed; r != nil {
				gauge("konstapel_binding_snapshot_collection_started_timestamp_seconds", ts(r.CollectionStarted), n)
				gauge("konstapel_binding_last_closed_timestamp_seconds", ts(r.Closed), n)
			}
			gauge("konstapel_binding_assessment_interval_seconds", b.Interval.Seconds(), n)
			gauge("konstapel_binding_max_evidence_age_seconds", b.MaxEvidenceAge.Seconds(), n)
			gauge("konstapel_binding_collection_timeout_seconds", b.CollectionTimeout.Seconds(), n)
			if b.Due != nil {
				gauge("konstapel_binding_scheduled_due_timestamp_seconds", ts(*b.Due), n)
			}
		}
	}

	if ready[DomainEvidenceStorage] {
		s := st.value
		gauge("konstapel_publication_pending", float64(s.PublicationPending))
		gauge("konstapel_publication_failed", float64(s.PublicationFailed))
		gauge("konstapel_cleanup_pending", float64(s.CleanupPending))
		gauge("konstapel_cleanup_blocked", float64(s.CleanupBlocked))
		if s.OldestCleanupExpiry != nil {
			gauge("konstapel_cleanup_oldest_expiry_timestamp_seconds", ts(*s.OldestCleanupExpiry))
		}
	}
	return out
}
