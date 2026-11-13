// Package schedule decides when continuous-assessment runs start. It is pure:
// every decision is a function of persisted state, binding settings, pending
// work, and the current time, so retries, concurrent reconciles, and leader
// changes converge on the same run identities.
package schedule

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"slices"
	"strings"
	"time"
)

// MaxGaps bounds the recorded missed-interval summaries per binding.
const MaxGaps = 10

// TriggerKind records what caused a run.
type TriggerKind string

const (
	Scheduled TriggerKind = "Scheduled"
	Manual    TriggerKind = "Manual"
	Request   TriggerKind = "Request"
)

// Gap records scheduled times that were missed and coalesced into one later
// run. Konstapel never claims to have assessed the missed states.
type Gap struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Missed int       `json:"missed"`
}

// State is the per-binding schedule state the controller persists.
type State struct {
	// Anchor and Interval define the scheduled times Anchor + k*Interval.
	Anchor   time.Time     `json:"anchor"`
	Interval time.Duration `json:"interval"`
	// LastScheduled is the scheduled time of the newest scheduled run.
	LastScheduled time.Time `json:"lastScheduled"`
	// Active is the run currently holding the binding's single slot.
	Active string `json:"active,omitempty"`
	// Gaps are the most recent missed-interval summaries, oldest first.
	Gaps []Gap `json:"gaps,omitempty"`
	// MissedTotal counts every missed scheduled time, including those whose
	// gap summaries were dropped by MaxGaps.
	MissedTotal int `json:"missedTotal,omitempty"`
	// Outstanding is the earliest scheduled time, including missed times
	// coalesced into a later run, not yet met by a scheduled run that
	// closed with an assessment export; zero when nothing is outstanding.
	// It only observes the schedule: no decision reads it.
	Outstanding time.Time `json:"outstanding,omitzero"`
}

// Due is the earliest scheduled obligation not yet met: Outstanding when
// set, otherwise the first scheduled time after the newest scheduled run,
// which may already have passed while the slot was held. It is zero for a
// schedule that has never been planned.
func (st State) Due() time.Time {
	switch {
	case !st.Outstanding.IsZero():
		return st.Outstanding
	case st.Anchor.IsZero():
		return time.Time{}
	case st.LastScheduled.IsZero() || st.Interval <= 0:
		return st.Anchor
	}
	return latestDue(st.Anchor, st.Interval, st.LastScheduled).Add(st.Interval)
}

// Met records that the scheduled run for scheduled time at closed with an
// assessment export: every obligation up to at is met, including missed
// times it caught up on.
func (st State) Met(at time.Time) State {
	if !st.Outstanding.IsZero() && !st.Outstanding.After(at) {
		st.Outstanding = time.Time{}
	}
	return st
}

// Pending is one queued manual run or namespace request.
type Pending struct {
	Kind TriggerKind
	// Name is the AssessmentRun (Manual) or AssessmentRequest (Request) name.
	Namespace, Name, UID string
	Created              time.Time
}

// Trigger is a run to start.
type Trigger struct {
	Kind          TriggerKind
	ScheduledTime time.Time // Scheduled only
	Pending       *Pending  // Manual and Request only
	// RunName is the deterministic AssessmentRun name for this trigger.
	RunName string
}

// Decision is the outcome of one planning step.
type Decision struct {
	State State
	// Start is the trigger to start now, if the binding's slot is free.
	Start *Trigger
	// Rejected are namespace requests beyond the queue bound.
	Rejected []Pending
	// NextDue is the next scheduled time after the plan, for requeueing.
	NextDue time.Time
}

// Input is everything a planning step reads.
type Input struct {
	Now         time.Time
	BindingName string
	BindingUID  string
	Interval    time.Duration
	State       State
	// ActiveDone reports that State.Active finished or failed, releasing the slot.
	ActiveDone bool
	// ActiveMet is the scheduled time of State.Active when it is a
	// scheduled run that closed with an assessment export; zero otherwise.
	ActiveMet time.Time
	Pending   []Pending
	// MaxQueue bounds pending namespace requests per binding; 0 means 100.
	MaxQueue int
}

// Plan computes the next state and the run to start, if any.
//
//   - The first plan for a binding starts an initial scheduled run now and
//     anchors the schedule there.
//   - Scheduled times are Anchor + k*Interval. Changing the interval
//     re-anchors at the last scheduled time without touching an active run.
//   - Missed scheduled times coalesce into one run at the latest due time;
//     the earlier ones are recorded as a gap, never as evaluations.
//   - At most one run is active per binding. When the slot frees, an overdue
//     scheduled run starts before any manual or requested run, so manual work
//     cannot starve the schedule; manual and request triggers never move the
//     schedule.
//   - Pending work is ordered by creation time, then kind, namespace, name,
//     and UID; requests beyond MaxQueue are rejected, newest first.
func Plan(in Input) Decision {
	now := in.Now.UTC().Truncate(time.Second)
	st := in.State
	st.Gaps = slices.Clone(st.Gaps)
	if in.ActiveDone {
		st.Active = ""
		if !in.ActiveMet.IsZero() {
			st = st.Met(in.ActiveMet)
		}
	}
	d := Decision{}

	pending := slices.Clone(in.Pending)
	slices.SortFunc(pending, func(a, b Pending) int {
		return cmp.Or(a.Created.Compare(b.Created), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name), cmp.Compare(a.UID, b.UID))
	})
	limit := in.MaxQueue
	if limit <= 0 {
		limit = 100
	}
	requests := 0
	kept := pending[:0]
	for _, p := range pending {
		if p.Kind == Request {
			requests++
			if requests > limit {
				d.Rejected = append(d.Rejected, p)
				continue
			}
		}
		kept = append(kept, p)
	}
	pending = kept

	var due *time.Time
	switch {
	case st.Anchor.IsZero():
		// Initial run: anchor the schedule now.
		st.Anchor, st.Interval = now, in.Interval
		t := now
		due = &t
	default:
		if st.Interval != in.Interval {
			// Re-anchor at the last scheduled time; an active run is untouched.
			if !st.LastScheduled.IsZero() {
				st.Anchor = st.LastScheduled
			}
			st.Interval = in.Interval
		}
		latest := latestDue(st.Anchor, st.Interval, now)
		if latest.After(st.LastScheduled) {
			due = &latest
		}
	}

	if due != nil && st.Active == "" {
		earliest := *due
		if !st.LastScheduled.IsZero() {
			first := st.LastScheduled.Add(st.Interval)
			if missed := int(due.Sub(first) / st.Interval); missed > 0 {
				earliest = first
				st.Gaps = append(st.Gaps, Gap{From: first, To: due.Add(-st.Interval), Missed: missed})
				st.MissedTotal += missed
				if len(st.Gaps) > MaxGaps {
					st.Gaps = st.Gaps[len(st.Gaps)-MaxGaps:]
				}
			}
		}
		if st.Outstanding.IsZero() {
			st.Outstanding = earliest
		}
		st.LastScheduled = *due
		t := Trigger{Kind: Scheduled, ScheduledTime: *due}
		t.RunName = RunName(in.BindingName, in.BindingUID, t)
		st.Active, d.Start = t.RunName, &t
	} else if st.Active == "" && len(pending) > 0 {
		p := pending[0]
		t := Trigger{Kind: p.Kind, Pending: &p}
		t.RunName = RunName(in.BindingName, in.BindingUID, t)
		st.Active, d.Start = t.RunName, &t
	}
	d.State = st
	d.NextDue = latestDue(st.Anchor, st.Interval, now).Add(st.Interval)
	return d
}

// latestDue is the latest scheduled time Anchor + k*Interval not after now.
func latestDue(anchor time.Time, interval time.Duration, now time.Time) time.Time {
	if interval <= 0 || now.Before(anchor) {
		return anchor
	}
	return anchor.Add(now.Sub(anchor) / interval * interval)
}

var unsafe = regexp.MustCompile(`[^a-z0-9-]+`)

// RunName is the deterministic AssessmentRun name for a trigger. Scheduled
// runs are identified by binding UID and scheduled time; manual runs by the
// platform-created run's UID; requests by the request UID. Equal triggers
// always produce the same name, so a create that loses a race or is retried
// finds the existing run instead of duplicating it.
func RunName(bindingName, bindingUID string, t Trigger) string {
	key := bindingUID + "\x00" + string(t.Kind) + "\x00"
	switch t.Kind {
	case Scheduled:
		key += t.ScheduledTime.UTC().Format(time.RFC3339)
	default:
		key += t.Pending.UID
	}
	h := sha256.Sum256([]byte(key))
	readable := strings.Trim(unsafe.ReplaceAllString(strings.ToLower(bindingName), "-"), "-")
	if len(readable) > 40 {
		readable = strings.TrimRight(readable[:40], "-")
	}
	return readable + "-" + strings.ToLower(string(t.Kind[0])) + "-" + hex.EncodeToString(h[:])[:16]
}
