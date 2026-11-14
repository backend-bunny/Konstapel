package schedule

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// stepMet plans at now after the active run finished; met reports that it
// was a scheduled run that closed with an assessment export.
func (s *sim) stepMet(now time.Time, met bool, pending ...Pending) Decision {
	in := Input{Now: now, BindingName: s.name, BindingUID: s.uid, Interval: s.every, State: s.st, ActiveDone: true, Pending: pending}
	if met && s.st.Active != "" {
		in.ActiveMet = s.st.LastScheduled
	}
	d := Plan(in)
	s.st = d.State
	if d.Start != nil {
		s.runs = append(s.runs, *d.Start)
	}
	return d
}

// The initial run is due when it is planned and stays due, however late,
// until a scheduled run closes with an assessment export.
func TestInitialRunIsDueUntilMet(t *testing.T) {
	s := newSim(t, time.Hour)
	if !s.st.Due().IsZero() {
		t.Fatal("a never-planned schedule has a due time")
	}
	s.step(t0, false)
	if !s.st.Outstanding.Equal(t0) || !s.st.Due().Equal(t0) {
		t.Fatalf("initial run: outstanding %v due %v", s.st.Outstanding, s.st.Due())
	}
	// Still collecting long after: the initial obligation stays due.
	s.step(t0.Add(3*time.Hour), false)
	if !s.st.Due().Equal(t0) {
		t.Fatalf("initial run overdue but due moved to %v", s.st.Due())
	}
	// It closes with an assessment, meeting 00:00. The 01:00 and 02:00 ticks
	// passed meanwhile: they coalesce into a catch-up run at 03:00 and the
	// first of them is now the outstanding obligation.
	d := s.stepMet(t0.Add(3*time.Hour+time.Minute), true)
	if d.Start == nil || !d.Start.ScheduledTime.Equal(t0.Add(3*time.Hour)) || !s.st.Due().Equal(t0.Add(time.Hour)) {
		t.Fatalf("catch-up: start %+v due %v", d.Start, s.st.Due())
	}
	// The catch-up closes with an assessment: nothing outstanding.
	s.stepMet(t0.Add(3*time.Hour+10*time.Minute), true)
	if !s.st.Outstanding.IsZero() || !s.st.Due().Equal(t0.Add(4*time.Hour)) {
		t.Fatalf("after catch-up: outstanding %v due %v", s.st.Outstanding, s.st.Due())
	}
}

// A diagnostic, a lost capture or a deleted run does not meet the
// obligation: the earliest unmet time stays due through later runs.
func TestUnmetRunKeepsEarliestObligation(t *testing.T) {
	s := newSim(t, time.Hour)
	s.step(t0, false)
	s.stepMet(t0.Add(10*time.Minute), true) // met
	s.step(t0.Add(time.Hour), false)        // starts the 01:00 run
	if !s.st.Due().Equal(t0.Add(time.Hour)) {
		t.Fatalf("due %v", s.st.Due())
	}
	s.stepMet(t0.Add(time.Hour+10*time.Minute), false) // diagnostic: not met
	s.step(t0.Add(2*time.Hour), false)                 // starts the 02:00 run
	if !s.st.Outstanding.Equal(t0.Add(time.Hour)) || !s.st.Due().Equal(t0.Add(time.Hour)) {
		t.Fatalf("an unmet 01:00 obligation was dropped: outstanding %v", s.st.Outstanding)
	}
	// The 02:00 run closes with an assessment: it meets everything up to it.
	s.stepMet(t0.Add(2*time.Hour+10*time.Minute), true)
	if !s.st.Outstanding.IsZero() || !s.st.Due().Equal(t0.Add(3*time.Hour)) {
		t.Fatalf("after catch-up: outstanding %v due %v", s.st.Outstanding, s.st.Due())
	}
}

// Missed ticks coalesce into one run, but the earliest missed time is the
// outstanding obligation; the gap stays recorded after catch-up.
func TestMissedTicksAreOutstandingFromTheFirstMiss(t *testing.T) {
	s := newSim(t, time.Hour)
	s.step(t0, false)
	s.stepMet(t0.Add(10*time.Minute), true)
	// The controller was down from 00:10 until 03:30.
	d := s.step(t0.Add(3*time.Hour+30*time.Minute), true)
	if d.Start == nil || !d.Start.ScheduledTime.Equal(t0.Add(3*time.Hour)) || len(s.st.Gaps) != 1 {
		t.Fatalf("coalesced run %+v gaps %+v", d.Start, s.st.Gaps)
	}
	if !s.st.Outstanding.Equal(t0.Add(time.Hour)) {
		t.Fatalf("outstanding %v, want the first missed time 01:00", s.st.Outstanding)
	}
	s.stepMet(t0.Add(3*time.Hour+40*time.Minute), true)
	if !s.st.Outstanding.IsZero() || len(s.st.Gaps) != 1 || s.st.MissedTotal != 2 {
		t.Fatalf("catch-up: outstanding %v gaps %+v missed %d", s.st.Outstanding, s.st.Gaps, s.st.MissedTotal)
	}
}

// While a manual or request run holds the slot past a tick, that tick is
// due although no scheduled run has started; manual and request runs
// never meet scheduled obligations.
func TestHeldSlotAndManualRunsDoNotHideDueWork(t *testing.T) {
	s := newSim(t, time.Hour)
	s.step(t0, false)
	s.stepMet(t0.Add(5*time.Minute), true)
	manual := Pending{Kind: Manual, Name: "m", UID: "uid-m", Created: t0.Add(10 * time.Minute)}
	if d := s.step(t0.Add(10*time.Minute), true, manual); d.Start == nil || d.Start.Kind != Manual {
		t.Fatalf("manual run not started: %+v", d.Start)
	}
	// 01:30: the manual run still holds the slot; 01:00 is due.
	s.step(t0.Add(90*time.Minute), false)
	if !s.st.Outstanding.IsZero() || !s.st.Due().Equal(t0.Add(time.Hour)) {
		t.Fatalf("held slot: outstanding %v due %v", s.st.Outstanding, s.st.Due())
	}
	// The manual run finishes (the caller never reports a manual run as
	// met); the overdue scheduled run starts and is outstanding.
	s.stepMet(t0.Add(100*time.Minute), false)
	if !s.st.Outstanding.Equal(t0.Add(time.Hour)) {
		t.Fatalf("outstanding %v", s.st.Outstanding)
	}
}

// An interval edit re-anchors the schedule but keeps outstanding work.
func TestIntervalEditKeepsOutstandingWork(t *testing.T) {
	s := newSim(t, time.Hour)
	s.step(t0, false)
	s.stepMet(t0.Add(5*time.Minute), true)
	s.step(t0.Add(time.Hour), false) // 01:00 run starts
	s.stepMet(t0.Add(70*time.Minute), false)
	s.every = 24 * time.Hour
	s.step(t0.Add(2*time.Hour), true)
	if !s.st.Outstanding.Equal(t0.Add(time.Hour)) {
		t.Fatalf("interval edit discarded outstanding work: %v", s.st.Outstanding)
	}
	if s.st.Interval != 24*time.Hour || !s.st.Anchor.Equal(t0.Add(time.Hour)) {
		t.Fatalf("not re-anchored: %+v", s.st)
	}
}

// Outstanding only observes the schedule: no decision reads it.
func TestOutstandingDoesNotChangeDecisions(t *testing.T) {
	base := newSim(t, time.Hour)
	base.step(t0, false)
	base.stepMet(t0.Add(5*time.Minute), true)
	steps := []struct {
		at   time.Duration
		done bool
	}{{time.Hour, true}, {150 * time.Minute, true}, {5 * time.Hour, false}, {6 * time.Hour, true}}
	for _, step := range steps {
		for _, preset := range []time.Time{{}, t0.Add(-48 * time.Hour)} {
			in := Input{Now: t0.Add(step.at), BindingName: base.name, BindingUID: base.uid, Interval: base.every, State: base.st, ActiveDone: step.done}
			in.State.Outstanding = preset
			got := Plan(in)
			in.State.Outstanding = time.Time{}
			want := Plan(in)
			got.State.Outstanding, want.State.Outstanding = time.Time{}, time.Time{}
			a, _ := json.Marshal(got)
			b, _ := json.Marshal(want)
			if string(a) != string(b) {
				t.Fatalf("Outstanding %v changed the decision:\n%s\n%s", preset, a, b)
			}
		}
		base.step(t0.Add(step.at), step.done)
	}
}

// A schedule with nothing outstanding persists exactly as before.
func TestNoOutstandingIsByteIdentical(t *testing.T) {
	st := State{Anchor: t0, Interval: time.Hour, LastScheduled: t0}
	raw, _ := json.Marshal(ToStatus(st, t0.Add(time.Hour), ""))
	if strings.Contains(string(raw), "outstanding") {
		t.Fatalf("absent outstanding persisted: %s", raw)
	}
	st.Outstanding = t0
	s := ToStatus(st, t0.Add(time.Hour), "")
	back, err := FromStatus(s)
	if err != nil || !back.Outstanding.Equal(t0) {
		t.Fatalf("round trip %v %v", back.Outstanding, err)
	}
}
