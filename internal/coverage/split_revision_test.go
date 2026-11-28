package coverage

import (
	"slices"
	"testing"
)

// The split revision (konstapel-linux-hardening 0.2.0, the next version of
// bundles/konstapel-linux-hardening/definition.json) resolves its inventory
// and mappings like the released 0.1.0: every single-validation check maps
// to its original check's controls, the superseded combined checks map
// nothing, and the control inventory is the same Moderate selection.
func TestSplitRevisionCoverage(t *testing.T) {
	next := fromDefinition(t, "bundles/konstapel-linux-hardening/definition.json")
	released := official(t, hardening)
	var all []string
	for _, p := range next.Policies {
		all = append(all, p.Name)
	}
	r := Build(Input{Content: next, Selection: selecting(next, all...), Options: opts(t)})
	if !r.Inventory.Resolved || !r.Mappings.Resolved || len(r.Controls) != moderateCount || len(r.Limitations) != 0 {
		t.Fatalf("inventory %+v mappings %+v limitations %v", r.Inventory, r.Mappings, r.Limitations)
	}
	old := Build(Input{Content: released, Selection: selecting(released), Options: opts(t)})
	for i := range r.Controls {
		if r.Controls[i].ID != old.Controls[i].ID {
			t.Fatalf("row %d: %s, released %s", i, r.Controls[i].ID, old.Controls[i].ID)
		}
	}
	want := map[string][]string{
		"ac-6": {"disallow-privilege-escalation", "disallow-privileged-containers", "require-drop-all-capabilities", "require-run-as-nonroot", "restrict-added-capabilities"},
		"cm-6": {"disallow-privilege-escalation", "require-container-seccomp-profile", "require-drop-all-capabilities", "require-run-as-nonroot", "restrict-added-capabilities", "restrict-pod-seccomp-profile"},
		"cm-7": {"require-container-seccomp-profile", "require-drop-all-capabilities", "restrict-added-capabilities", "restrict-pod-seccomp-profile"},
	}
	for id, rules := range want {
		ctl := row(t, r, id)
		if ctl.Automation != AutomationPartial {
			t.Errorf("%s automation %s", id, ctl.Automation)
		}
		var got []string
		for _, ch := range ctl.Checks {
			got = append(got, ch.RuleID)
			if ch.Selection != CheckSelected {
				t.Errorf("%s/%s selection %s", id, ch.RuleID, ch.Selection)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, rules) {
			t.Errorf("%s maps %v, want %v", id, got, rules)
		}
	}
	for _, c := range r.Controls {
		for _, ch := range c.Checks {
			if ch.RuleID == "disallow-capabilities-strict" || ch.RuleID == "restrict-seccomp-strict" {
				t.Errorf("%s still maps the superseded %s", c.ID, ch.RuleID)
			}
		}
	}
}
