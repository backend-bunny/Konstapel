package observability

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

var t0 = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

func newHub(t *testing.T, enabled ...Domain) (*Hub, *clocktesting.FakePassiveClock) {
	t.Helper()
	clk := clocktesting.NewFakePassiveClock(t0)
	h, err := NewHub(Options{Enabled: enabled, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	return h, clk
}

// scrape gathers h through a pedantic registry and returns every series as
// "name{label="value",...}" mapped to its value (histograms by _count).
func scrape(t *testing.T, h *Hub) map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(h)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	return series(families)
}

func series(families []*dto.MetricFamily) map[string]float64 {
	out := map[string]float64{}
	for _, f := range families {
		for _, m := range f.Metric {
			var ls []string
			for _, l := range m.Label {
				ls = append(ls, fmt.Sprintf("%s=%q", l.GetName(), l.GetValue()))
			}
			key := f.GetName() + "{" + strings.Join(ls, ",") + "}"
			switch {
			case m.Gauge != nil:
				out[key] = m.Gauge.GetValue()
			case m.Counter != nil:
				out[key] = m.Counter.GetValue()
			case m.Histogram != nil:
				out[key] = float64(m.Histogram.GetSampleCount())
			}
		}
	}
	return out
}

func exposition(t *testing.T, h *Hub) string {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(h)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, f := range families {
		if err := enc.Encode(f); err != nil {
			t.Fatal(err)
		}
	}
	return buf.String()
}

// families returns the metric names that have at least one series.
func families(s map[string]float64) []string {
	set := map[string]bool{}
	for k := range s {
		set[k[:strings.IndexByte(k, '{')]] = true
	}
	return slices.Sorted(maps.Keys(set))
}

func withPrefix(s map[string]float64, prefix string) map[string]float64 {
	out := map[string]float64{}
	for k, v := range s {
		if strings.HasPrefix(k, prefix) {
			out[k] = v
		}
	}
	return out
}

func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func completeSummary(pass, fail int) Summary {
	return Summary{
		Evidence: publication.EvidenceSummary{Completeness: publication.Complete, Expected: pass + fail, Attributable: pass + fail},
		Outcomes: publication.OutcomeCounts{Pass: pass, Fail: fail},
	}
}

func targetingOf(bs ...BindingRef) TargetingSnapshot {
	s := TargetingSnapshot{Capabilities: map[Capability]Status{CapabilityPolicyDelivery: StatusTrue, CapabilityAssessment: StatusFalse}}
	for _, b := range bs {
		s.Bindings = append(s.Bindings, BindingTargeting{Binding: b, Created: t0.Add(-time.Hour), Resolved: StatusTrue, EngineReady: StatusUnknown, TargetNamespaces: ptr(2)})
	}
	return s
}

func assessmentOf(bs ...BindingRef) AssessmentSnapshot {
	var s AssessmentSnapshot
	for _, b := range bs {
		s.Bindings = append(s.Bindings, BindingAssessment{Binding: b,
			Current:      &CurrentView{Summary: completeSummary(3, 1), ValidUntil: ptr(t0.Add(time.Hour))},
			LatestClosed: &ClosedRun{Summary: completeSummary(2, 2), CollectionStarted: t0.Add(-25 * time.Minute), Closed: t0.Add(-20 * time.Minute)},
			Interval:     time.Hour, MaxEvidenceAge: 2 * time.Hour, CollectionTimeout: 5 * time.Minute, Due: ptr(t0.Add(40 * time.Minute))})
	}
	return s
}

var (
	alpha  = BindingRef{Name: "alpha", UID: "uid-alpha-1"}
	alpha2 = BindingRef{Name: "alpha", UID: "uid-alpha-2"}
	beta   = BindingRef{Name: "beta", UID: "uid-beta-1"}
)

// Before an owner publishes from synchronized state, enabled domains are
// present but not ready and nothing else of theirs is exposed.
func TestUnsynchronizedStartupIsNotReady(t *testing.T) {
	h, _ := newHub(t, Domains...)
	got := scrape(t, h)
	for _, d := range Domains {
		if got[fmt.Sprintf("konstapel_observation_enabled{domain=%q}", d)] != 1 {
			t.Errorf("%s not enabled", d)
		}
		k := fmt.Sprintf("konstapel_observation_ready{domain=%q}", d)
		if v, ok := got[k]; !ok || v != 0 {
			t.Errorf("%s = %v, %v; want present 0", k, v, ok)
		}
	}
	want := []string{"konstapel_observation_enabled", "konstapel_observation_ready", "konstapel_operation_attempts_total", "konstapel_operation_duration_seconds"}
	if f := families(got); !slices.Equal(f, want) {
		t.Errorf("families before synchronization = %v, want %v", f, want)
	}
	if err := h.PublishTargeting(0, t0, targetingOf(alpha)); !errors.Is(err, ErrNotLeading) {
		t.Errorf("publish while not leading: %v", err)
	}
	// Leading alone is not synchronization.
	h.Acquire()
	if f := families(scrape(t, h)); !slices.Equal(f, want) {
		t.Errorf("families after acquisition = %v, want %v", f, want)
	}
}

// A disabled domain says so and is never reported as working.
func TestDisabledDomains(t *testing.T) {
	h, _ := newHub(t, DomainTargeting)
	term := h.Acquire()
	if err := h.PublishStorage(term, t0, StorageSnapshot{}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("publishing a disabled domain: %v", err)
	}
	if err := h.PublishBundleResolution(term, t0); !errors.Is(err, ErrDisabled) {
		t.Fatalf("publishing a disabled domain: %v", err)
	}
	got := scrape(t, h)
	for _, d := range []Domain{DomainAssessment, DomainBundleResolution, DomainEvidenceStorage} {
		if got[fmt.Sprintf("konstapel_observation_enabled{domain=%q}", d)] != 0 || got[fmt.Sprintf("konstapel_observation_ready{domain=%q}", d)] != 0 {
			t.Errorf("%s: disabled domain is reported enabled or ready", d)
		}
	}
	if _, err := NewHub(Options{Enabled: []Domain{DomainProcess}}); err == nil {
		t.Error("the process pseudo-domain was accepted as an owner domain")
	}
}

// The exporter checks projection age with the clock: a stalled owner loses
// readiness and its values even though scrapes keep succeeding.
func TestStalledProducerLosesReadiness(t *testing.T) {
	h, clk := newHub(t, DomainTargeting, DomainEvidenceStorage)
	term := h.Acquire()
	mustOK(t, h.PublishTargeting(term, t0, targetingOf(alpha)))
	mustOK(t, h.PublishStorage(term, t0, StorageSnapshot{PublicationFailed: 1}))

	clk.SetTime(t0.Add(DefaultMaxAge))
	got := scrape(t, h)
	if got[`konstapel_observation_ready{domain="targeting"}`] != 1 || got[`konstapel_publication_failed{}`] != 1 {
		t.Fatalf("fresh projection at the maximum age is not served: %v", got)
	}

	clk.SetTime(t0.Add(DefaultMaxAge + time.Second))
	got = scrape(t, h)
	for _, d := range []string{"targeting", "evidence_storage"} {
		if got[fmt.Sprintf("konstapel_observation_ready{domain=%q}", d)] != 0 {
			t.Errorf("%s is still ready after its maximum age", d)
		}
		if got[fmt.Sprintf("konstapel_observation_updated_timestamp_seconds{domain=%q}", d)] != float64(t0.Unix()) {
			t.Errorf("%s: the stale projection's production time must stay visible", d)
		}
	}
	for _, f := range families(got) {
		if strings.HasPrefix(f, "konstapel_binding_") || strings.HasPrefix(f, "konstapel_capability_") || strings.HasPrefix(f, "konstapel_publication_") || strings.HasPrefix(f, "konstapel_cleanup_") {
			t.Errorf("stale projection still exposes %s", f)
		}
	}

	// Only a newer owner snapshot restores readiness; scraping never does.
	mustOK(t, h.PublishTargeting(term, clk.Now(), targetingOf(alpha)))
	if scrape(t, h)[`konstapel_observation_ready{domain="targeting"}`] != 1 {
		t.Error("republished projection is not ready")
	}
	if err := h.PublishTargeting(term, t0, targetingOf(alpha)); !errors.Is(err, ErrOutOfOrder) {
		t.Errorf("an older snapshot replaced a newer one: %v", err)
	}
}

// Known empty state is a zero; unknown state is absent.
func TestKnownZeroVersusMissingData(t *testing.T) {
	h, _ := newHub(t, Domains...)
	term := h.Acquire()
	empty := StorageSnapshot{}
	mustOK(t, h.PublishStorage(term, t0, empty))
	unknownTargets := targetingOf(alpha, beta)
	unknownTargets.Bindings[1].TargetNamespaces = nil
	unknownTargets.Bindings[0].TargetNamespaces = ptr(0)
	mustOK(t, h.PublishTargeting(term, t0, unknownTargets))
	got := scrape(t, h)

	for _, k := range []string{"konstapel_publication_pending{}", "konstapel_publication_failed{}", "konstapel_cleanup_pending{}", "konstapel_cleanup_blocked{}"} {
		if v, ok := got[k]; !ok || v != 0 {
			t.Errorf("%s = %v, %v; known empty backlog must be zero", k, v, ok)
		}
	}
	if _, ok := got["konstapel_cleanup_oldest_expiry_timestamp_seconds{}"]; ok {
		t.Error("oldest cleanup expiry without any pending cleanup")
	}
	if v, ok := got[`konstapel_binding_target_namespaces{binding="alpha"}`]; !ok || v != 0 {
		t.Error("known zero targets must be exposed as 0")
	}
	if _, ok := got[`konstapel_binding_target_namespaces{binding="beta"}`]; ok {
		t.Error("unknown target inventory must be absent")
	}
	// Domains that never published expose nothing but availability.
	if len(withPrefix(got, "konstapel_binding_assessment")) != 0 {
		t.Error("unpublished assessment domain exposes summaries")
	}
	if err := h.PublishStorage(term, t0, StorageSnapshot{OldestCleanupExpiry: &t0}); err == nil {
		t.Error("an expiry without backlog was accepted")
	}
}

// Every owner value is exposed as recorded; conditions and capabilities
// are one-hot.
func TestOwnerValuesAreExposed(t *testing.T) {
	h, _ := newHub(t, Domains...)
	term := h.Acquire()
	mustOK(t, h.PublishTargeting(term, t0, targetingOf(alpha)))
	mustOK(t, h.PublishAssessment(term, t0, assessmentOf(alpha)))
	mustOK(t, h.PublishBundleResolution(term, t0))
	mustOK(t, h.PublishStorage(term, t0, StorageSnapshot{PublicationPending: 2, PublicationFailed: 1, CleanupPending: 3, CleanupBlocked: 1, OldestCleanupExpiry: ptr(t0.Add(-time.Hour))}))
	got := scrape(t, h)
	want := map[string]float64{
		`konstapel_binding_condition{binding="alpha",condition="Resolved",status="true"}`:        1,
		`konstapel_binding_condition{binding="alpha",condition="Resolved",status="false"}`:       0,
		`konstapel_binding_condition{binding="alpha",condition="EngineReady",status="unknown"}`:  1,
		`konstapel_binding_condition{binding="alpha",condition="EngineReady",status="true"}`:     0,
		`konstapel_capability_condition{capability="policy_delivery",status="true"}`:             1,
		`konstapel_capability_condition{capability="assessment",status="false"}`:                 1,
		`konstapel_binding_created_timestamp_seconds{binding="alpha"}`:                           float64(t0.Add(-time.Hour).Unix()),
		`konstapel_binding_assessment_status{binding="alpha",status="known",view="current"}`:     1,
		`konstapel_binding_assessment_checks{binding="alpha",state="fail",view="current"}`:       1,
		`konstapel_binding_assessment_checks{binding="alpha",state="fail",view="latest_closed"}`: 2,
		`konstapel_binding_assessment_complete{binding="alpha",view="latest_closed"}`:            1,
		`konstapel_binding_last_closed_timestamp_seconds{binding="alpha"}`:                       float64(t0.Add(-20 * time.Minute).Unix()),
		`konstapel_binding_snapshot_collection_started_timestamp_seconds{binding="alpha"}`:       float64(t0.Add(-25 * time.Minute).Unix()),
		`konstapel_binding_assessment_interval_seconds{binding="alpha"}`:                         3600,
		`konstapel_binding_max_evidence_age_seconds{binding="alpha"}`:                            7200,
		`konstapel_binding_collection_timeout_seconds{binding="alpha"}`:                          300,
		`konstapel_binding_scheduled_due_timestamp_seconds{binding="alpha"}`:                     float64(t0.Add(40 * time.Minute).Unix()),
		`konstapel_observation_ready{domain="bundle_resolution"}`:                                1,
		`konstapel_publication_pending{}`:                                                        2,
		`konstapel_cleanup_blocked{}`:                                                            1,
		`konstapel_cleanup_oldest_expiry_timestamp_seconds{}`:                                    float64(t0.Add(-time.Hour).Unix()),
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("%s = %v (present %v), want %v", k, g, ok, v)
		}
	}
	if _, ok := got[`konstapel_capability_condition{capability="exceptions",status="unknown"}`]; ok {
		t.Error("a capability the owner did not report is exposed")
	}
	// Exposition carries only binding names, never UIDs.
	if strings.Contains(exposition(t, h), "uid-alpha") {
		t.Error("binding UID leaked into labels")
	}
}

// Current evidence expires at the owner's validity deadline; republishing
// the same summary cannot extend it, and the historical view stays.
func TestCurrentEvidenceExpiresAtOwnerDeadline(t *testing.T) {
	h, clk := newHub(t, DomainAssessment)
	term := h.Acquire()
	s := assessmentOf(alpha)
	s.Bindings[0].Current.ValidUntil = ptr(t0.Add(time.Minute))
	mustOK(t, h.PublishAssessment(term, t0, s))

	clk.SetTime(t0.Add(time.Minute - time.Nanosecond))
	if scrape(t, h)[`konstapel_binding_assessment_status{binding="alpha",status="known",view="current"}`] != 1 {
		t.Fatal("current view is not known before its deadline")
	}
	clk.SetTime(t0.Add(time.Minute))
	mustOK(t, h.PublishAssessment(term, clk.Now(), s)) // a refresh of the same summary
	got := scrape(t, h)
	if got[`konstapel_binding_assessment_status{binding="alpha",status="unknown",view="current"}`] != 1 {
		t.Error("expired current evidence is not unknown")
	}
	for k := range withPrefix(got, "konstapel_binding_assessment_") {
		if strings.Contains(k, `view="current"`) && !strings.HasPrefix(k, "konstapel_binding_assessment_status") {
			t.Errorf("expired current evidence still exposes %s", k)
		}
	}
	if got[`konstapel_binding_assessment_status{binding="alpha",status="known",view="latest_closed"}`] != 1 ||
		got[`konstapel_binding_last_closed_timestamp_seconds{binding="alpha"}`] != float64(t0.Add(-20*time.Minute).Unix()) {
		t.Error("the historical view changed when current evidence expired")
	}
}

// Leadership loss clears every owner projection; a successor exposes
// nothing until owners republish reconstructed state, and stale writes of
// the old term are rejected.
func TestLeadershipLossAndAcquisition(t *testing.T) {
	h, _ := newHub(t, Domains...)
	old := h.Acquire()
	mustOK(t, h.PublishTargeting(old, t0, targetingOf(alpha)))
	mustOK(t, h.PublishAssessment(old, t0, assessmentOf(alpha)))
	mustOK(t, h.PublishStorage(old, t0, StorageSnapshot{CleanupBlocked: 1, OldestCleanupExpiry: &t0}))
	h.ObserveOperation(OperationEvidencePublication, ResultFailure, time.Second)

	h.Release(old)
	got := scrape(t, h)
	for _, d := range Domains {
		if got[fmt.Sprintf("konstapel_observation_ready{domain=%q}", d)] != 0 {
			t.Errorf("%s ready after leadership loss", d)
		}
		if _, ok := got[fmt.Sprintf("konstapel_observation_updated_timestamp_seconds{domain=%q}", d)]; ok {
			t.Errorf("%s keeps the former leader's projection time", d)
		}
	}
	if n := len(withPrefix(got, "konstapel_binding_")) + len(withPrefix(got, "konstapel_cleanup_")); n != 0 {
		t.Errorf("former leader still exposes %d summary series", n)
	}
	if got[`konstapel_operation_attempts_total{operation="evidence_publication",result="failure"}`] != 1 {
		t.Error("process-local attempts must survive leadership changes")
	}
	if err := h.PublishAssessment(old, t0.Add(time.Second), assessmentOf(alpha)); !errors.Is(err, ErrNotLeading) {
		t.Errorf("a write from the lost term was accepted: %v", err)
	}

	next := h.Acquire()
	h.Release(old) // a late release of the old term is a no-op
	if err := h.PublishAssessment(old, t0.Add(time.Second), assessmentOf(alpha)); !errors.Is(err, ErrNotLeading) {
		t.Errorf("a write from an earlier term was accepted after reacquisition: %v", err)
	}
	if n := len(withPrefix(scrape(t, h), "konstapel_binding_")); n != 0 {
		t.Errorf("successor exposes %d binding series before reconstruction", n)
	}
	mustOK(t, h.PublishTargeting(next, t0.Add(time.Second), targetingOf(alpha)))
	if scrape(t, h)[`konstapel_observation_ready{domain="targeting"}`] != 1 {
		t.Error("reconstructed projection is not ready")
	}
	if cur, ok := h.Term(); !ok || cur != next {
		t.Errorf("Term() = %d, %v", cur, ok)
	}
}

// An owner that loses synchronized state withdraws its projection.
func TestWithdraw(t *testing.T) {
	h, _ := newHub(t, Domains...)
	term := h.Acquire()
	mustOK(t, h.PublishTargeting(term, t0, targetingOf(alpha)))
	mustOK(t, h.Withdraw(term, DomainTargeting))
	got := scrape(t, h)
	if got[`konstapel_observation_ready{domain="targeting"}`] != 0 || len(withPrefix(got, "konstapel_binding_")) != 0 {
		t.Error("withdrawn projection is still served")
	}
	if err := h.Withdraw(term+1, DomainTargeting); !errors.Is(err, ErrNotLeading) {
		t.Errorf("withdraw from another term: %v", err)
	}
	// After a withdrawal any synchronized snapshot is accepted again.
	mustOK(t, h.PublishTargeting(term, t0.Add(-time.Second), targetingOf(alpha)))
}

// Deleting a binding removes its series; reusing the name with a new UID
// starts without the old binding's runs; while owners disagree on which
// object a name denotes, none of its series is exposed.
func TestBindingDeletionAndNameReuse(t *testing.T) {
	h, clk := newHub(t, DomainTargeting, DomainAssessment)
	term := h.Acquire()
	mustOK(t, h.PublishTargeting(term, t0, targetingOf(alpha, beta)))
	mustOK(t, h.PublishAssessment(term, t0, assessmentOf(alpha, beta)))

	// Deleted: alpha is gone from both owners.
	clk.SetTime(t0.Add(time.Second))
	mustOK(t, h.PublishTargeting(term, clk.Now(), targetingOf(beta)))
	mustOK(t, h.PublishAssessment(term, clk.Now(), assessmentOf(beta)))
	got := scrape(t, h)
	for k := range got {
		if strings.Contains(k, `binding="alpha"`) {
			t.Errorf("deleted binding still exposes %s", k)
		}
	}
	if len(withPrefix(got, `konstapel_binding_condition{binding="beta"`)) == 0 {
		t.Error("other bindings disappeared")
	}

	// Recreated: targeting already sees the new UID, assessment still
	// holds the old object.
	clk.SetTime(t0.Add(2 * time.Second))
	mustOK(t, h.PublishTargeting(term, clk.Now(), targetingOf(alpha2, beta)))
	mustOK(t, h.PublishAssessment(term, clk.Now(), assessmentOf(alpha, beta)))
	for k := range scrape(t, h) {
		if strings.Contains(k, `binding="alpha"`) {
			t.Errorf("ambiguous binding exposes %s", k)
		}
	}

	// The assessment owner reconstructs the new object: no old run.
	clk.SetTime(t0.Add(3 * time.Second))
	fresh := BindingAssessment{Binding: alpha2, Interval: 24 * time.Hour, MaxEvidenceAge: 2 * time.Hour, CollectionTimeout: 5 * time.Minute, Due: ptr(clk.Now())}
	mustOK(t, h.PublishAssessment(term, clk.Now(), AssessmentSnapshot{Bindings: []BindingAssessment{fresh, assessmentOf(beta).Bindings[0]}}))
	got = scrape(t, h)
	if got[`konstapel_binding_assessment_status{binding="alpha",status="no_assessment",view="latest_closed"}`] != 1 ||
		got[`konstapel_binding_assessment_status{binding="alpha",status="unknown",view="current"}`] != 1 {
		t.Error("recreated binding does not start without assessments")
	}
	for _, k := range []string{`konstapel_binding_last_closed_timestamp_seconds{binding="alpha"}`, `konstapel_binding_assessment_checks{binding="alpha",state="pass",view="latest_closed"}`} {
		if _, ok := got[k]; ok {
			t.Errorf("recreated binding inherited %s", k)
		}
	}
	if got[`konstapel_binding_condition{binding="alpha",condition="Resolved",status="true"}`] != 1 {
		t.Error("recreated binding's targeting state is missing")
	}

	// A snapshot naming one binding twice is rejected, not guessed.
	dup := targetingOf(alpha, alpha2)
	if err := h.PublishTargeting(term, clk.Now(), dup); err == nil {
		t.Error("a snapshot with a duplicate name was accepted")
	}
}

// Source, closure and due times are the owner's: repeated scrapes at later
// times return the same values, and scraping never changes a projection.
func TestSourceTimesSurviveRepeatedScrapes(t *testing.T) {
	h, clk := newHub(t, DomainTargeting, DomainAssessment)
	term := h.Acquire()
	s := assessmentOf(alpha)
	s.Bindings[0].Current.OldestEvaluated = ptr(t0.Add(-30 * time.Minute))
	mustOK(t, h.PublishTargeting(term, t0, targetingOf(alpha)))
	mustOK(t, h.PublishAssessment(term, t0, s))
	first := scrape(t, h)
	clk.SetTime(t0.Add(90 * time.Second))
	second := scrape(t, h)
	if !maps.Equal(first, second) {
		t.Errorf("scrape time changed exposed values:\n%v\n%v", first, second)
	}
	if first[`konstapel_binding_oldest_evaluation_timestamp_seconds{binding="alpha",view="current"}`] != float64(t0.Add(-30*time.Minute).Unix()) {
		t.Error("oldest source evaluation is not the owner's")
	}
	// Mutating the published value does not reach the projection.
	s.Bindings[0].Current.Outcomes.Fail = 99
	*s.Bindings[0].Due = t0
	if !maps.Equal(first, scrape(t, h)) {
		t.Error("published snapshot is not immutable")
	}
}

func TestLeadershipRunnable(t *testing.T) {
	h, _ := newHub(t, DomainTargeting)
	l := Leadership{Hub: h}
	if !l.NeedLeaderElection() {
		t.Fatal("leadership must be leader-elected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- l.Start(ctx) }()
	var term Term
	for deadline := time.Now().Add(5 * time.Second); ; {
		var ok bool
		if term, ok = h.Term(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("leadership was not acquired")
		}
		time.Sleep(time.Millisecond)
	}
	mustOK(t, h.PublishTargeting(term, t0, targetingOf(alpha)))
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, ok := h.Term(); ok {
		t.Error("still leading after the leader context ended")
	}
	if len(withPrefix(scrape(t, h), "konstapel_binding_")) != 0 {
		t.Error("projection survived leadership loss")
	}
}

// Owners publish while Prometheus scrapes; run with -race.
func TestConcurrentPublishAndScrape(t *testing.T) {
	h, _ := newHub(t, Domains...)
	h.Acquire()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(h)
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 20 {
			term, _ := h.Term()
			h.Release(term)
			h.Acquire()
		}
	})
	for range 4 {
		wg.Go(func() {
			for j := range 50 {
				term, _ := h.Term()
				at := t0.Add(time.Duration(j) * time.Millisecond)
				_ = h.PublishAssessment(term, at, assessmentOf(alpha, beta))
				_ = h.PublishTargeting(term, at, targetingOf(alpha, beta))
				h.ObserveOperation(OperationBundleResolution, ResultSuccess, time.Millisecond)
			}
		})
		wg.Go(func() {
			for range 50 {
				if _, err := reg.Gather(); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
}

func TestSnapshotValidation(t *testing.T) {
	bad := []struct {
		name string
		pub  func(h *Hub, term Term) error
	}{
		{"missing UID", func(h *Hub, term Term) error {
			return h.PublishTargeting(term, t0, targetingOf(BindingRef{Name: "x"}))
		}},
		{"duplicate UID", func(h *Hub, term Term) error {
			return h.PublishTargeting(term, t0, targetingOf(alpha, BindingRef{Name: "other", UID: alpha.UID}))
		}},
		{"invalid status", func(h *Hub, term Term) error {
			s := targetingOf(alpha)
			s.Bindings[0].Resolved = "True"
			return h.PublishTargeting(term, t0, s)
		}},
		{"unknown capability", func(h *Hub, term Term) error {
			s := targetingOf(alpha)
			s.Capabilities["registry"] = StatusTrue
			return h.PublishTargeting(term, t0, s)
		}},
		{"negative backlog", func(h *Hub, term Term) error {
			return h.PublishStorage(term, t0, StorageSnapshot{CleanupPending: -1})
		}},
		{"run closed before start", func(h *Hub, term Term) error {
			s := assessmentOf(alpha)
			s.Bindings[0].LatestClosed.Closed = t0.Add(-time.Hour)
			return h.PublishAssessment(term, t0, s)
		}},
		{"zero production time", func(h *Hub, term Term) error {
			return h.PublishTargeting(term, time.Time{}, targetingOf(alpha))
		}},
	}
	for _, c := range bad {
		h, _ := newHub(t, Domains...)
		if err := c.pub(h, h.Acquire()); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

// The typed enums and the documented vocabularies are the same.
func TestTypedEnumsMatchCatalog(t *testing.T) {
	check := func(name string, got []string, want []string) {
		t.Helper()
		sort.Strings(got)
		want = slices.Sorted(slices.Values(want))
		if !slices.Equal(got, want) {
			t.Errorf("%s: typed %v, catalog %v", name, got, want)
		}
	}
	check("status", []string{string(StatusTrue), string(StatusFalse), string(StatusUnknown)}, statusValues)
	check("capability", []string{string(CapabilityPolicyDelivery), string(CapabilityAssessment), string(CapabilityExceptions)}, capabilityValues)
	check("operation", []string{string(OperationBundleResolution), string(OperationEvidencePublication), string(OperationEvidenceCleanup)}, operationValues)
	check("result", []string{string(ResultSuccess), string(ResultFailure)}, resultValues)
	check("view", []string{string(ViewCurrent), string(ViewLatestClosed)}, viewValues)
	check("assessment status", []string{string(AssessmentKnown), string(AssessmentNoTargets), string(AssessmentNone), string(AssessmentUnknown)}, AssessmentStatuses)
	var domains []string
	for _, d := range Domains {
		domains = append(domains, string(d))
	}
	check("domain", domains, domainValues)
	// Every catalog family is served by the Hub with the documented labels.
	h, _ := newHub(t)
	ch := make(chan *prometheus.Desc, 64)
	h.Describe(ch)
	close(ch)
	n := 0
	for d := range ch {
		n++
		s := d.String()
		if !strings.Contains(s, `fqName: "konstapel_`) {
			t.Errorf("unexpected descriptor %s", s)
		}
	}
	if n != len(Catalog) {
		t.Errorf("Hub describes %d families, catalog has %d", n, len(Catalog))
	}
}
