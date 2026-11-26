package conformance

import (
	"slices"
	"testing"
)

// The deliberate regressions cover every rule the suite enforces. The
// remaining kinds are a malformed case (TestHarnessRejectsMalformedCases),
// an adapter error, and an invalid summary, which Summarize cannot produce
// from valid observations.
func TestMutationsCoverEveryRule(t *testing.T) {
	notMutated := []Kind{KindCase, KindEvaluate, KindSummary}
	names := map[string]bool{}
	for _, m := range mutations() {
		if names[m.name] {
			t.Errorf("mutation %q is listed twice", m.name)
		}
		names[m.name] = true
		if !slices.Contains(AllKinds, m.want) {
			t.Errorf("mutation %q wants undeclared kind %q", m.name, m.want)
		}
	}
	for _, k := range AllKinds {
		covered := slices.ContainsFunc(mutations(), func(m mutation) bool { return m.want == k })
		if covered == slices.Contains(notMutated, k) {
			t.Errorf("kind %s: mutated %t, listed as not mutated %t", k, covered, !covered)
		}
	}
}
