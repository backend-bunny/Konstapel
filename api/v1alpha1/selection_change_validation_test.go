package v1alpha1_test

import (
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/crdtest"
)

// add-assessment-provider-contract 3.5: status.observedSelectionChange is
// additive, bounded and written once: it cannot be removed or rewritten,
// and a run without it validates unchanged.
func TestObservedSelectionChangeIsWrittenOnce(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["AssessmentRun"]
	frozen := map[string]any{"name": "org-baseline", "digest": "sha256:" + strings.Repeat("a", 64)}
	observed := map[string]any{"name": "org-next", "digest": "sha256:" + strings.Repeat("b", 64)}
	run := func(change map[string]any) map[string]any {
		o := runWithIntent(t, nil)
		if change != nil {
			o["status"] = map[string]any{"observedSelectionChange": change}
		}
		return o
	}
	change := func(at string, obs map[string]any) map[string]any {
		c := map[string]any{"observedTime": at, "frozen": frozen}
		if obs != nil {
			c["observed"] = obs
		}
		return c
	}
	for name, o := range map[string]map[string]any{
		"absent":          run(nil),
		"observed bundle": run(change("2026-11-27T10:00:30Z", observed)),
		"no selection":    run(change("2026-11-27T10:00:30Z", nil)),
	} {
		if errs := v.Validate(o); len(errs) > 0 {
			t.Errorf("%s rejected: %v", name, errs.ToAggregate())
		}
	}
	for name, o := range map[string]map[string]any{
		"no time":        run(map[string]any{"frozen": frozen, "observed": observed}),
		"bad digest":     run(change("2026-11-27T10:00:30Z", map[string]any{"name": "org-next", "digest": "sha256:xyz"})),
		"oversized name": run(change("2026-11-27T10:00:30Z", map[string]any{"name": strings.Repeat("a", 254), "digest": observed["digest"]})),
	} {
		if errs := v.Validate(o); len(errs) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	prev := run(change("2026-11-27T10:00:30Z", observed))
	for name, c := range map[string]struct {
		next map[string]any
		want string
	}{
		"removed":   {run(nil), "never removed"},
		"retimed":   {run(change("2026-11-27T10:01:00Z", observed)), "written once"},
		"rewritten": {run(change("2026-11-27T10:00:30Z", nil)), "written once"},
	} {
		errs := v.ValidateUpdate(c.next, prev)
		if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), c.want) {
			t.Errorf("%s: want %q, got %v", name, c.want, errs.ToAggregate())
		}
	}
	if errs := v.ValidateUpdate(prev, run(nil)); len(errs) > 0 {
		t.Errorf("first write rejected: %v", errs.ToAggregate())
	}
	if errs := v.ValidateUpdate(prev, prev); len(errs) > 0 {
		t.Errorf("unchanged rewrite rejected: %v", errs.ToAggregate())
	}
}
