package coverage

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

const coverageDoc = repo + "/docs/control-coverage.md"

// docInventory regenerates the inventory block of docs/control-coverage.md
// from the shipped bundles.
func docInventory(t *testing.T) string {
	t.Helper()
	var sb strings.Builder
	priv := official(t, privileged)
	r := Build(Input{Content: priv, Selection: selecting(priv, privPolicy), Options: opts(t)})
	groups := map[string]bool{}
	for _, c := range r.Controls {
		groups[c.Groups[0].ID] = true
	}
	inv := r.Inventory
	fmt.Fprintf(&sb, "profile  %s\n         %s\n         OSCAL %s, %s\n", inv.Profile.Path, inv.Profile.Title, inv.Profile.OSCALVersion, inv.Profile.Digest)
	fmt.Fprintf(&sb, "catalog  %s\n         OSCAL %s, %s\n", inv.Catalog.Path, inv.Catalog.OSCALVersion, inv.Catalog.Digest)
	fmt.Fprintf(&sb, "selected %d controls (%d base controls, %d enhancements) in %d groups, %d statement parts\n",
		inv.Controls, inv.Controls-inv.Enhancements, inv.Enhancements, len(groups), inv.Statements)
	var pe []string
	for _, c := range r.Controls {
		if c.Groups[0].ID == "pe" {
			pe = append(pe, c.ID+"="+c.Automation)
		}
	}
	fmt.Fprintf(&sb, "physical (pe) %d: %s\n", len(pe), strings.Join(pe, " "))
	summary := func(title string, r *Report) {
		fmt.Fprintf(&sb, "\n%s\n", title)
		by := map[string][]string{}
		for _, c := range r.Controls {
			by[c.Automation] = append(by[c.Automation], c.ID)
		}
		for _, s := range []string{AutomationPartial, AutomationUnselected, AutomationUnknown} {
			if len(by[s]) > 0 {
				fmt.Fprintf(&sb, "  %-10s %s\n", s, strings.Join(by[s], ", "))
			}
		}
		fmt.Fprintf(&sb, "  %-10s %d controls\n", AutomationNone, len(by[AutomationNone]))
	}
	summary("konstapel-privileged-containers, profile selects disallow-privileged-containers", r)
	hard := official(t, hardening)
	summary("konstapel-linux-hardening, profile selects disallow-privilege-escalation",
		Build(Input{Content: hard, Selection: selecting(hard, "disallow-privilege-escalation"), Options: opts(t)}))
	return sb.String()
}

// docRow is the ac-6 row of the hardening example, as JSON.
func docRow(t *testing.T) string {
	t.Helper()
	hard := official(t, hardening)
	sel := selecting(hard, "disallow-privilege-escalation")
	r := Build(Input{Content: hard, Selection: sel, Options: opts(t)})
	ac6 := row(t, r, "ac-6")
	// Keep the example short: one selected and one unselected check.
	var checks []CheckCoverage
	for _, ch := range ac6.Checks {
		if ch.RuleID == "disallow-privilege-escalation" || ch.RuleID == "require-run-as-nonroot" {
			ch.PolicyDigest = ch.PolicyDigest[:15] + "..."
			checks = append(checks, ch)
		}
	}
	ac6.Checks = checks
	b, err := json.MarshalIndent(ac6, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

// block returns the text between <!-- name:begin --> and <!-- name:end -->,
// without the fence lines.
func block(t *testing.T, doc, name string) string {
	t.Helper()
	_, rest, ok := strings.Cut(doc, "<!-- "+name+":begin -->\n")
	body, _, ok2 := strings.Cut(rest, "<!-- "+name+":end -->")
	if !ok || !ok2 {
		t.Fatalf("%s has no %s block", coverageDoc, name)
	}
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "```") || lines[len(lines)-1] != "```" {
		t.Fatalf("%s block is not one fenced code block", name)
	}
	return strings.Join(lines[1:len(lines)-1], "\n") + "\n"
}

// The examples in docs/control-coverage.md are regenerated from the pinned
// Moderate inventory and the shipped bundles. Run with
// KONSTAPEL_UPDATE_DOCS=1 to print the current blocks.
func TestControlCoverageDocExamples(t *testing.T) {
	raw, err := os.ReadFile(coverageDoc)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for name, want := range map[string]string{"coverage-inventory": docInventory(t), "coverage-row": docRow(t)} {
		if os.Getenv("KONSTAPEL_UPDATE_DOCS") != "" {
			fmt.Printf("<!-- %s:begin -->\n```\n%s```\n<!-- %s:end -->\n", name, want, name)
			continue
		}
		if got := block(t, doc, name); got != want {
			t.Errorf("%s block is stale; want:\n%s", name, want)
		}
	}
	// The documentation keeps policy parameters apart from OSCAL parameters,
	// and the example row shows no policy parameter as an OSCAL value.
	if !strings.Contains(doc, "`policyParameters` hold engine configuration, never values of the control's\nOSCAL parameters") {
		t.Error("the documentation does not separate policy parameters from OSCAL parameters")
	}
	if strings.Contains(block(t, doc, "coverage-row"), "oscalParameters") {
		t.Error("the example row presents an OSCAL parameter setting the content does not author")
	}
}
