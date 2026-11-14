package schedule

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// FromStatus restores schedule state persisted in a binding's
// status.assessment.schedule. A nil schedule is a binding never scheduled.
func FromStatus(s *v1alpha1.AssessmentSchedule) (State, error) {
	if s == nil {
		return State{}, nil
	}
	interval, err := time.ParseDuration(string(s.Interval))
	if err != nil || interval <= 0 {
		return State{}, fmt.Errorf("persisted schedule interval %q: invalid", s.Interval)
	}
	st := State{Anchor: s.Anchor.UTC(), Interval: interval, MissedTotal: int(s.MissedTotal)}
	if s.LastScheduled != nil {
		st.LastScheduled = s.LastScheduled.UTC()
	}
	if s.ActiveRun != nil {
		st.Active = s.ActiveRun.Name
	}
	if s.OutstandingSince != nil {
		st.Outstanding = s.OutstandingSince.UTC()
	}
	for _, g := range s.Gaps {
		st.Gaps = append(st.Gaps, Gap{From: g.From.UTC(), To: g.To.UTC(), Missed: int(g.Missed)})
	}
	return st, nil
}

// ToStatus persists schedule state. activeUID is the active run's UID, known
// once the run exists.
func ToStatus(st State, nextDue time.Time, activeUID string) *v1alpha1.AssessmentSchedule {
	s := &v1alpha1.AssessmentSchedule{Anchor: metav1.NewTime(st.Anchor), Interval: v1alpha1.Duration(st.Interval.String()), MissedTotal: int32(st.MissedTotal)}
	if !st.LastScheduled.IsZero() {
		t := metav1.NewTime(st.LastScheduled)
		s.LastScheduled = &t
	}
	if !nextDue.IsZero() {
		t := metav1.NewTime(nextDue)
		s.NextDue = &t
	}
	if st.Active != "" {
		s.ActiveRun = &v1alpha1.RunReference{Name: st.Active, UID: activeUID}
	}
	if !st.Outstanding.IsZero() {
		t := metav1.NewTime(st.Outstanding)
		s.OutstandingSince = &t
	}
	for _, g := range st.Gaps {
		s.Gaps = append(s.Gaps, v1alpha1.MissedInterval{From: metav1.NewTime(g.From), To: metav1.NewTime(g.To), Missed: int32(g.Missed)})
	}
	return s
}
