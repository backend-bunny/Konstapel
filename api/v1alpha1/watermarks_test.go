package v1alpha1

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The observability watermarks are additive: absent, they leave status
// encoded exactly as before.
func TestWatermarksAreAbsentUnlessSet(t *testing.T) {
	now := metav1.NewTime(time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))
	cur := CurrentEvidence{Evidence: EvidenceSummary{Completeness: "Complete", Expected: 1, Attributable: 1}, Outcomes: OutcomeCounts{Pass: 1}, EvaluatedAt: now}
	sched := AssessmentSchedule{Anchor: now, Interval: "24h", NextDue: &now}
	for name, v := range map[string]any{"current": cur, "summary": AssessmentSummary{Evidence: cur.Evidence, Export: "Assessment"}, "schedule": sched} {
		raw, _ := json.Marshal(v)
		if strings.Contains(string(raw), "oldestEvaluation") || strings.Contains(string(raw), "outstandingSince") {
			t.Errorf("%s encodes an absent watermark: %s", name, raw)
		}
	}
	want := `{"evidence":{"completeness":"Complete","expected":1,"attributable":1,"missing":0,"rejected":0,"unresolved":0},"outcomes":{"pass":1,"fail":0,"error":0,"skip":0,"acceptedRisk":0,"notApplicable":0,"unknown":0},"evaluatedAt":"2026-11-05T00:00:00Z"}`
	if raw, _ := json.Marshal(cur); string(raw) != want {
		t.Errorf("current evidence encoding changed:\n%s\n%s", raw, want)
	}
	cur.OldestEvaluation, sched.OutstandingSince = &now, &now
	for name, v := range map[string]any{"current": cur, "schedule": sched} {
		raw, _ := json.Marshal(v)
		if !strings.Contains(string(raw), `"2026-11-05T00:00:00Z"`) || !(strings.Contains(string(raw), "oldestEvaluation") || strings.Contains(string(raw), "outstandingSince")) {
			t.Errorf("%s drops a set watermark: %s", name, raw)
		}
	}
}
