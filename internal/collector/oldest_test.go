package collector

import (
	"testing"
	"time"
)

// OldestEvaluated is the earliest source evaluation among attributable
// observations only; rejected and missing evidence do not count, and the
// owner's next expiry is that time plus the evidence-age limit.
func TestOldestEvaluated(t *testing.T) {
	c := freshCapture(t)
	start := c.Window.Started
	if got := evaluate(t, c, nil, maxAge).OldestEvaluated(); got != nil {
		t.Fatalf("no evidence, oldest %v", got)
	}
	times := []time.Time{start.Add(3 * time.Minute), start.Add(time.Minute), start.Add(-time.Minute)}
	c.Window.Closed = start.Add(5 * time.Minute)
	for i, e := range c.Expected {
		c.Reports = append(c.Reports, report("r"+e.Key(), "ns", e.Workload.UID, result(e.Check.EnginePolicy, e.Check.Index, e.Workload.UID, "pass", times[i])))
	}
	ev := evaluate(t, c, nil, maxAge)
	got := ev.OldestEvaluated()
	// The third result predates the observed-state boundary: rejected, so
	// the oldest attributable evaluation is the second.
	if s := states(ev); s[Attributable] != 2 || s[Rejected] != 1 {
		t.Fatalf("states %v", s)
	}
	if got == nil || !got.Equal(times[1]) {
		t.Fatalf("oldest %v, want %v", got, times[1])
	}
	if ev.NextExpiry == nil || !ev.NextExpiry.Equal(got.Add(maxAge)) {
		t.Fatalf("next expiry %v is not oldest + maxEvidenceAge", ev.NextExpiry)
	}
}
