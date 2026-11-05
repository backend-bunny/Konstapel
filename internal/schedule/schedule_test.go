package schedule

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)

type sim struct {
	t     *testing.T
	name  string
	uid   string
	every time.Duration
	st    State
	runs  []Trigger
}

func newSim(t *testing.T, every time.Duration) *sim {
	return &sim{t: t, name: "Baseline_Audit", uid: "uid-b", every: every}
}

// step plans at now; if done, the active run finished first.
func (s *sim) step(now time.Time, done bool, pending ...Pending) Decision {
	d := Plan(Input{Now: now, BindingName: s.name, BindingUID: s.uid, Interval: s.every, State: s.st, ActiveDone: done, Pending: pending})
	s.st = d.State
	if d.Start != nil {
		s.runs = append(s.runs, *d.Start)
	}
	return d
}

func TestInitialRunAnchorsSchedule(t *testing.T) {
	s := newSim(t, 24*time.Hour)
	d := s.step(t0.Add(1500*time.Millisecond), false)
	if d.Start == nil || d.Start.Kind != Scheduled || !d.Start.ScheduledTime.Equal(t0.Add(time.Second)) {
		t.Fatalf("no initial run: %+v", d)
	}
	if !d.NextDue.Equal(t0.Add(24*time.Hour + time.Second)) {
		t.Fatalf("next due %v", d.NextDue)
	}
	// Planning again before the slot frees or the next tick starts nothing.
	if d = s.step(t0.Add(time.Hour), true); d.Start != nil {
		t.Fatalf("unexpected run %+v", d.Start)
	}
}

func TestIndependentIntervals(t *testing.T) {
	hourly, daily := newSim(t, time.Hour), newSim(t, 24*time.Hour)
	daily.uid = "uid-other"
	for h := 0; h <= 24; h++ {
		now := t0.Add(time.Duration(h) * time.Hour)
		hourly.step(now, true)
		daily.step(now, true)
	}
	if len(hourly.runs) != 25 || len(daily.runs) != 2 {
		t.Fatalf("hourly %d daily %d", len(hourly.runs), len(daily.runs))
	}
}

func TestManualAndRequestsDoNotResetCadence(t *testing.T) {
	s := newSim(t, 24*time.Hour)
	s.step(t0, false)
	req := Pending{Kind: Request, Namespace: "team-a", Name: "r", UID: "req-1", Created: t0.Add(time.Hour)}
	man := Pending{Kind: Manual, Name: "m", UID: "run-1", Created: t0.Add(2 * time.Hour)}
	d := s.step(t0.Add(3*time.Hour), true, req, man)
	if d.Start == nil || d.Start.Kind != Request {
		t.Fatalf("oldest pending not started first: %+v", d.Start)
	}
	d = s.step(t0.Add(4*time.Hour), true, man)
	if d.Start == nil || d.Start.Kind != Manual {
		t.Fatalf("manual not started: %+v", d.Start)
	}
	if !s.st.Anchor.Equal(t0) || !s.st.LastScheduled.Equal(t0) {
		t.Fatal("manual or request work moved the schedule")
	}
	d = s.step(t0.Add(24*time.Hour), true)
	if d.Start == nil || d.Start.Kind != Scheduled || !d.Start.ScheduledTime.Equal(t0.Add(24*time.Hour)) {
		t.Fatalf("cadence changed: %+v", d.Start)
	}
}

func TestOverdueScheduledIsNotStarved(t *testing.T) {
	s := newSim(t, time.Hour)
	s.step(t0, false)
	// A manual run occupies the slot past the next tick.
	man := Pending{Kind: Manual, Name: "m", UID: "run-1", Created: t0.Add(time.Minute)}
	s.step(t0.Add(2*time.Minute), true, man)
	later := Pending{Kind: Request, Namespace: "ns", Name: "r", UID: "req", Created: t0.Add(3 * time.Minute)}
	if d := s.step(t0.Add(70*time.Minute), false, later); d.Start != nil {
		t.Fatal("started while the slot was busy")
	}
	d := s.step(t0.Add(75*time.Minute), true, later)
	if d.Start == nil || d.Start.Kind != Scheduled {
		t.Fatalf("overdue scheduled run starved by queued work: %+v", d.Start)
	}
	if d = s.step(t0.Add(80*time.Minute), true, later); d.Start == nil || d.Start.Kind != Request {
		t.Fatalf("queued request not started next: %+v", d.Start)
	}
}

func TestMissedIntervalsCoalesceWithGap(t *testing.T) {
	s := newSim(t, time.Hour)
	s.step(t0, false)
	// Controller down from 00:30 until 04:10: 01:00, 02:00, 03:00, 04:00 due.
	d := s.step(t0.Add(4*time.Hour+10*time.Minute), true)
	if d.Start == nil || !d.Start.ScheduledTime.Equal(t0.Add(4*time.Hour)) {
		t.Fatalf("catch-up run should cover the latest due time: %+v", d.Start)
	}
	if len(s.runs) != 2 {
		t.Fatalf("unbounded backlog: %d runs", len(s.runs))
	}
	g := s.st.Gaps
	if len(g) != 1 || g[0].Missed != 3 || !g[0].From.Equal(t0.Add(time.Hour)) || !g[0].To.Equal(t0.Add(3*time.Hour)) || s.st.MissedTotal != 3 {
		t.Fatalf("gap %+v total %d", g, s.st.MissedTotal)
	}
}

func TestGapsAreBounded(t *testing.T) {
	s := newSim(t, time.Hour)
	s.step(t0, false)
	now := t0
	for i := 0; i < MaxGaps+5; i++ {
		now = now.Add(3 * time.Hour)
		s.step(now, true)
	}
	if len(s.st.Gaps) != MaxGaps || s.st.MissedTotal != 2*(MaxGaps+5) {
		t.Fatalf("gaps %d total %d", len(s.st.Gaps), s.st.MissedTotal)
	}
}

func TestIntervalEditReanchors(t *testing.T) {
	s := newSim(t, 24*time.Hour)
	s.step(t0, false)
	s.step(t0.Add(time.Hour), true) // slot free
	s.every = time.Hour
	d := s.step(t0.Add(150*time.Minute), true)
	// Re-anchored at the last scheduled time (00:00): 01:00 and 02:00 are due;
	// one run covers 02:00 and 01:00 is a recorded gap.
	if d.Start == nil || !d.Start.ScheduledTime.Equal(t0.Add(2*time.Hour)) || s.st.MissedTotal != 1 {
		t.Fatalf("%+v missed %d", d.Start, s.st.MissedTotal)
	}
	// An interval edit while a run is active leaves it in place.
	s.every = 30 * time.Minute
	d = s.step(t0.Add(160*time.Minute), false)
	if d.Start != nil || s.st.Active != s.runs[len(s.runs)-1].RunName {
		t.Fatal("interval edit disturbed the active run")
	}
}

func TestQueueBound(t *testing.T) {
	var pending []Pending
	for i := 0; i < 5; i++ {
		pending = append(pending, Pending{Kind: Request, Namespace: "ns", Name: fmt.Sprint(i), UID: fmt.Sprint("u", i), Created: t0.Add(time.Duration(i) * time.Minute)})
	}
	d := Plan(Input{Now: t0.Add(time.Hour), BindingName: "b", BindingUID: "u", Interval: 24 * time.Hour,
		State: State{Anchor: t0, Interval: 24 * time.Hour, LastScheduled: t0, Active: "busy"}, Pending: pending, MaxQueue: 3})
	if len(d.Rejected) != 2 || d.Rejected[0].Name != "3" || d.Rejected[1].Name != "4" {
		t.Fatalf("newest requests beyond the bound must be rejected: %+v", d.Rejected)
	}
}

func TestDeterministicIdentitiesUnderConcurrency(t *testing.T) {
	in := Input{Now: t0.Add(5 * time.Hour), BindingName: "b", BindingUID: "u", Interval: time.Hour,
		State: State{Anchor: t0, Interval: time.Hour, LastScheduled: t0}}
	names := make([]string, 16)
	var wg sync.WaitGroup
	for i := range names {
		wg.Add(1)
		go func() { defer wg.Done(); names[i] = Plan(in).Start.RunName }()
	}
	wg.Wait()
	for _, n := range names {
		if n != names[0] {
			t.Fatal("concurrent planners chose different run identities")
		}
	}
	// Identities distinguish binding instances, times, kinds, and requests.
	base := Trigger{Kind: Scheduled, ScheduledTime: t0}
	seen := map[string]string{}
	for label, n := range map[string]string{
		"base":        RunName("b", "u", base),
		"other uid":   RunName("b", "u2", base),
		"other time":  RunName("b", "u", Trigger{Kind: Scheduled, ScheduledTime: t0.Add(time.Hour)}),
		"request":     RunName("b", "u", Trigger{Kind: Request, Pending: &Pending{UID: "r1"}}),
		"request 2":   RunName("b", "u", Trigger{Kind: Request, Pending: &Pending{UID: "r2"}}),
		"manual same": RunName("b", "u", Trigger{Kind: Manual, Pending: &Pending{UID: "r1"}}),
	} {
		if other, dup := seen[n]; dup {
			t.Fatalf("%s and %s share run name %s", label, other, n)
		}
		seen[n] = label
	}
	if n := RunName("A Very_Long Binding Name That Exceeds The Readable Limit Of Forty", "u", base); len(n) > 63 {
		t.Fatalf("run name %q too long", n)
	}
}
