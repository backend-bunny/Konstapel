package coverage

import (
	"encoding/json"
	"strings"
	"testing"
)

func row(t *testing.T, r *Report, id string) ControlCoverage {
	t.Helper()
	for _, c := range r.Controls {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("control %s is not in the report", id)
	return ControlCoverage{}
}

func checkOf(t *testing.T, c ControlCoverage, rule string) CheckCoverage {
	t.Helper()
	for _, ch := range c.Checks {
		if ch.RuleID == rule {
			return ch
		}
	}
	t.Fatalf("%s maps no rule %s (%+v)", c.ID, rule, c.Checks)
	return CheckCoverage{}
}

// The shipped privileged-container bundle: AC-6 is partial and keeps its
// authored limits; physical controls stay visible with no automation.
func TestPrivilegedBundleCoverage(t *testing.T) {
	c := official(t, privileged)
	r := Build(Input{Content: c, Selection: selecting(c, privPolicy), Options: opts(t)})
	if !r.Inventory.Resolved || !r.Mappings.Resolved || len(r.Limitations) != 0 {
		t.Fatalf("inventory %+v mappings %+v limitations %v", r.Inventory, r.Mappings, r.Limitations)
	}
	ac6 := row(t, r, "ac-6")
	if ac6.Automation != AutomationPartial {
		t.Fatalf("ac-6 automation %s", ac6.Automation)
	}
	ch := checkOf(t, ac6, privPolicy)
	if ch.Selection != CheckSelected || ch.CheckID != privPolicy || ch.Policy != privPolicy || !strings.HasPrefix(ch.PolicyDigest, "sha256:") {
		t.Errorf("check %+v", ch)
	}
	if !strings.Contains(ch.Description, "does not assess authorization") || len(ch.Statements) != 1 || ch.Statements[0].ID != "ac-6_smt" ||
		!strings.Contains(ch.Statements[0].Description, "partial least-privilege coverage only") {
		t.Errorf("authored limits are not retained: %+v", ch)
	}
	for _, x := range r.Controls {
		if x.Automation == "full" {
			t.Fatalf("%s claims full coverage", x.ID)
		}
		if x.ID != "ac-6" && (x.Automation != AutomationNone || len(x.Checks) != 0) {
			t.Errorf("%s: %s with %d checks; only ac-6 is mapped", x.ID, x.Automation, len(x.Checks))
		}
	}
	pe3 := row(t, r, "pe-3")
	if pe3.Automation != AutomationNone || pe3.Title != "Physical Access Control" || pe3.Label != "PE-3" {
		t.Errorf("pe-3 %+v", pe3)
	}
}

// A mapped policy the profile does not select stays visible as unselected;
// it never counts as automated.
func TestUnselectedPolicyIsNotAutomated(t *testing.T) {
	c := official(t, hardening)
	r := Build(Input{Content: c, Selection: selecting(c, privPolicy, "disallow-privilege-escalation"), Options: opts(t)})
	if len(r.Limitations) != 0 {
		t.Fatalf("limitations %v", r.Limitations)
	}
	// cm-7 maps only capabilities and seccomp, neither selected.
	cm7 := row(t, r, "cm-7")
	if cm7.Automation != AutomationUnselected || len(cm7.Checks) != 2 {
		t.Fatalf("cm-7 %s %+v", cm7.Automation, cm7.Checks)
	}
	for _, ch := range cm7.Checks {
		if ch.Selection != CheckUnselected || ch.PolicyParameters != nil {
			t.Errorf("cm-7 check %+v", ch)
		}
	}
	// cm-6 maps one selected and three unselected checks: partial, with
	// each check's own state.
	cm6 := row(t, r, "cm-6")
	if cm6.Automation != AutomationPartial || len(cm6.Checks) != 4 {
		t.Fatalf("cm-6 %s %+v", cm6.Automation, cm6.Checks)
	}
	if checkOf(t, cm6, "disallow-privilege-escalation").Selection != CheckSelected ||
		checkOf(t, cm6, "restrict-seccomp-strict").Selection != CheckUnselected {
		t.Errorf("cm-6 checks %+v", cm6.Checks)
	}
	ac6 := row(t, r, "ac-6")
	if ac6.Automation != AutomationPartial || len(ac6.Checks) != 4 {
		t.Errorf("ac-6 %s %+v", ac6.Automation, ac6.Checks)
	}
	// Selecting nothing leaves every mapped control unselected.
	none := Build(Input{Content: c, Selection: selecting(c), Options: opts(t)})
	for _, id := range []string{"ac-6", "cm-6", "cm-7"} {
		if a := row(t, none, id).Automation; a != AutomationUnselected {
			t.Errorf("%s with nothing selected: %s", id, a)
		}
	}
}

// Profile parameters are engine settings of the selected policy, kept on
// the check and never matched to OSCAL parameters.
func TestPolicyParametersStayPolicyParameters(t *testing.T) {
	c := official(t, hardening)
	sel := selecting(c, "require-run-as-nonroot")
	sel.Policies[0].Parameters = json.RawMessage(`{ "mode" : "strict" }`)
	r := Build(Input{Content: c, Selection: sel, Options: opts(t)})
	ch := checkOf(t, row(t, r, "cm-6"), "require-run-as-nonroot")
	if string(ch.PolicyParameters) != `{"mode":"strict"}` || ch.OSCALParameters != nil {
		t.Fatalf("check %+v", ch)
	}
	cm6 := row(t, r, "cm-6")
	if len(cm6.Parameters) == 0 {
		t.Fatal("cm-6 lost its OSCAL parameters")
	}
	for _, p := range cm6.Parameters {
		if strings.Contains(p.ID, "mode") || len(p.Values) > 0 {
			t.Errorf("OSCAL parameter %+v carries a policy setting", p)
		}
	}
}

// A selection pinning other content joins nothing: mapped controls are
// unknown, never partial.
func TestSelectionOfOtherContent(t *testing.T) {
	c := official(t, privileged)
	sel := selecting(c, privPolicy)
	sel.Bundle.Digest = "sha256:" + strings.Repeat("0", 64)
	r := Build(Input{Content: c, Selection: sel, Options: opts(t)})
	if !hasCode(r.Limitations, CodeSelectionContentMismatch) {
		t.Fatalf("limitations %v", r.Limitations)
	}
	ac6 := row(t, r, "ac-6")
	if ac6.Automation != AutomationUnknown || ac6.Checks[0].Selection != CheckUnresolved {
		t.Errorf("ac-6 %s %+v", ac6.Automation, ac6.Checks)
	}
	if row(t, r, "pe-3").Automation != AutomationNone {
		t.Error("an unmapped control changed state")
	}
	sel = selecting(c, "no-such-policy")
	if r := Build(Input{Content: c, Selection: sel, Options: opts(t)}); !hasCode(r.Limitations, CodePolicyNotInContent) {
		t.Errorf("limitations %v", r.Limitations)
	}
}
