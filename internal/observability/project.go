package observability

import (
	"cmp"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// viewProjection is one view's exposed state.
type viewProjection struct {
	status AssessmentStatus
	// counts holds every CheckStates entry for known and no_targets views
	// and is nil otherwise.
	counts map[string]int
	// complete is set only for known views.
	complete *bool
	oldest   *time.Time
}

// projectSummary renames the owner's normalized counts. Inconsistent,
// partially scoped or lost inventories are unknown: their counts would not
// sum to the inventory, so none is emitted.
func projectSummary(s Summary) viewProjection {
	e, o := s.Evidence, s.Outcomes
	if s.InventoryUnknown || e.StaleScopes > 0 || e.Validate() != nil || !consistent(o, e.Attributable) {
		return viewProjection{status: AssessmentUnknown}
	}
	counts := map[string]int{
		"pass": o.Pass, "fail": o.Fail, "error": o.Error, "skip": o.Skip,
		"accepted_risk": o.AcceptedRisk, "out_of_scope": o.NotApplicable, "unknown": o.Unknown,
		"missing": e.Missing, "rejected": e.Rejected, "unresolved": e.Unresolved,
	}
	if e.Completeness == publication.NoTargets {
		return viewProjection{status: AssessmentNoTargets, counts: counts}
	}
	complete := e.Completeness == publication.Complete
	return viewProjection{status: AssessmentKnown, counts: counts, complete: &complete, oldest: s.OldestEvaluated}
}

func consistent(o publication.OutcomeCounts, attributable int) bool {
	for _, n := range []int{o.Pass, o.Fail, o.Error, o.Skip, o.AcceptedRisk, o.NotApplicable, o.Unknown} {
		if n < 0 {
			return false
		}
	}
	return o.Pass+o.Fail+o.Error+o.Skip+o.AcceptedRisk+o.NotApplicable+o.Unknown == attributable
}

// projectCurrent projects current evidence at now. Expired evidence is
// unknown until the owner re-evaluates it.
func projectCurrent(c *CurrentView, now time.Time) viewProjection {
	if c == nil || (c.ValidUntil != nil && !now.Before(*c.ValidUntil)) {
		return viewProjection{status: AssessmentUnknown}
	}
	return projectSummary(c.Summary)
}

// projectClosed projects the latest closed run. Historical views never
// expire: their times stay those of the run.
func projectClosed(r *ClosedRun) viewProjection {
	if r == nil {
		return viewProjection{status: AssessmentNone}
	}
	return projectSummary(r.Summary)
}

func evidenceFromStatus(e v1alpha1.EvidenceSummary) publication.EvidenceSummary {
	return publication.EvidenceSummary{Completeness: publication.Completeness(e.Completeness), Expected: int(e.Expected),
		Attributable: int(e.Attributable), Missing: int(e.Missing), Rejected: int(e.Rejected),
		Unresolved: int(e.Unresolved), StaleScopes: int(e.StaleScopes)}
}

func outcomesFromStatus(o v1alpha1.OutcomeCounts) publication.OutcomeCounts {
	return publication.OutcomeCounts{Pass: int(o.Pass), Fail: int(o.Fail), Error: int(o.Error), Skip: int(o.Skip),
		AcceptedRisk: int(o.AcceptedRisk), NotApplicable: int(o.NotApplicable), Unknown: int(o.Unknown)}
}

func timeOf(t *metav1.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.Time
	return &v
}

// CurrentFromStatus adapts a binding's status.assessment.current. Free-text
// limitations are not carried. The oldest source evaluation is the owner's
// recorded one; it is absent for summaries recorded before the owner
// recorded it, and never derived from the expiry.
func CurrentFromStatus(c *v1alpha1.CurrentEvidence) *CurrentView {
	if c == nil {
		return nil
	}
	v := &CurrentView{Summary: Summary{Evidence: evidenceFromStatus(c.Evidence), Outcomes: outcomesFromStatus(c.Outcomes), OldestEvaluated: timeOf(c.OldestEvaluation)}}
	if c.NextExpiry != nil {
		t := c.NextExpiry.Time
		v.ValidUntil = &t
	}
	return v
}

// ClosedFromRun adapts a closed full-binding run. Namespace-scope and
// unclosed runs report false. A closed run without a summary, or whose
// capture was lost, has no trustworthy inventory.
func ClosedFromRun(r *v1alpha1.AssessmentRun) (*ClosedRun, bool) {
	if r == nil || r.Spec.Scope != v1alpha1.RunScopeBinding || r.Status.Window == nil || r.Status.Window.Closed == nil {
		return nil, false
	}
	c := &ClosedRun{CollectionStarted: r.Status.Window.Started.Time, Closed: r.Status.Window.Closed.Time}
	if s := r.Status.Summary; s == nil || string(s.Export) == string(publication.ExportCaptureLost) {
		c.InventoryUnknown = true
	} else {
		c.Evidence, c.Outcomes = evidenceFromStatus(s.Evidence), outcomesFromStatus(s.Outcomes)
		c.OldestEvaluated = timeOf(s.OldestEvaluation)
	}
	return c, true
}

// ClosedFromDescriptor adapts a frozen full-binding package descriptor.
func ClosedFromDescriptor(d publication.Descriptor) (*ClosedRun, bool) {
	if d.Scope.Kind != publication.ScopeBinding || d.Window.Closed.IsZero() {
		return nil, false
	}
	return &ClosedRun{Summary: Summary{Evidence: d.Evidence, Outcomes: d.Outcomes},
		CollectionStarted: d.Window.Started, Closed: d.Window.Closed}, true
}

// LatestClosed selects the latest closed full-binding run of one binding
// UID: the latest closure wins whether it is complete, incomplete or
// diagnostic, and namespace-scope runs never replace it. Publication state
// plays no part. Nil means no such run has closed.
func LatestClosed(bindingUID string, runs []v1alpha1.AssessmentRun) *ClosedRun {
	var best *ClosedRun
	var bestName string
	for i := range runs {
		r := &runs[i]
		if r.Status.Binding == nil || r.Status.Binding.UID != bindingUID {
			continue
		}
		c, ok := ClosedFromRun(r)
		if !ok {
			continue
		}
		if best == nil || cmp.Or(c.Closed.Compare(best.Closed), c.CollectionStarted.Compare(best.CollectionStarted), cmp.Compare(r.Name, bestName)) > 0 {
			best, bestName = c, r.Name
		}
	}
	return best
}
