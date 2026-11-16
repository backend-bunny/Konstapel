package coverage

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// The Moderate summary counts every selected control once by automation
// state and names no control.
func TestSummarizeModerate(t *testing.T) {
	priv := official(t, privileged)
	r := Build(Input{Content: priv, Selection: selecting(priv, privPolicy), Options: opts(t)})
	s := Summarize(r, strings.Repeat("a", 64))
	a := s.Automation
	if !s.InventoryResolved || !s.MappingsResolved || s.Controls != moderateCount || s.Enhancements != r.Inventory.Enhancements ||
		a.None+a.Unselected+a.Partial+a.Unknown != moderateCount || a.Partial == 0 || a.None == 0 ||
		s.TechnicalEvidence != EvidenceNotProvided || s.Bundle == nil || s.Bundle.Digest != priv.Bundle.Digest {
		t.Fatalf("summary %+v", s)
	}
	raw, _ := json.Marshal(s)
	for _, c := range r.Controls {
		if strings.Contains(string(raw), `"`+c.ID+`"`) {
			t.Fatalf("summary names control %s: %s", c.ID, raw)
		}
	}
}

// Large-baseline bound: the summary of a report with 100,000 controls and
// thousands of limitations stays the same small, fixed shape, with at most
// eight sorted blocking codes and no row data.
func TestSummarizeIsBoundedForLargeBaselines(t *testing.T) {
	r := &Report{Inventory: Inventory{Resolved: true}, TechnicalEvidence: TechnicalEvidence{State: EvidenceResolved}}
	states := []string{AutomationNone, AutomationUnselected, AutomationPartial, AutomationUnknown}
	for i := range 100000 {
		row := ControlCoverage{Automation: states[i%4]}
		row.ID = fmt.Sprintf("x-%d", i)
		row.Title = strings.Repeat("t", 200)
		if i%50 == 0 {
			row.Limitations = []Limitation{{Code: fmt.Sprintf("Code%03d", i%997), Blocking: true, Subject: row.ID, Message: strings.Repeat("m", 500)}}
		}
		r.Controls = append(r.Controls, row)
	}
	r.Inventory.Controls = len(r.Controls)
	r.Limitations = []Limitation{{Code: "Zz", Blocking: false, Message: "notice"}}
	s := Summarize(r, strings.Repeat("b", 64))
	if s.Controls != 100000 || s.Automation != (publication.AutomationCounts{None: 25000, Unselected: 25000, Partial: 25000, Unknown: 25000}) ||
		s.Limitations != 2001 || len(s.BlockingCodes) != publication.MaxBlockingCodes || !slices.IsSorted(s.BlockingCodes) || slices.Contains(s.BlockingCodes, "Zz") {
		t.Fatalf("summary %+v", s)
	}
	raw, _ := json.Marshal(s)
	if len(raw) > 1024 || strings.Contains(string(raw), "x-1") || strings.Contains(string(raw), "mmm") || strings.Contains(string(raw), "ttt") {
		t.Fatalf("summary of %d bytes carries row data: %s", len(raw), raw)
	}
}

// The inputs digest ignores order and JSON formatting, and changes with
// the binding, the namespaces, the bundle, the selected policies and their
// parameters, and between no profile and an empty one.
func TestInputsDigest(t *testing.T) {
	sel := func(params string, names ...string) *Selection {
		s := &Selection{}
		s.Bundle.Name, s.Bundle.Digest = "b", "sha256:"+strings.Repeat("1", 64)
		for _, n := range names {
			p := SelectedPolicy{Name: n}
			if params != "" {
				p.Parameters = json.RawMessage(params)
			}
			s.Policies = append(s.Policies, p)
		}
		return s
	}
	base := InputsDigest("uid", []string{"n1", "n2"}, sel(`{"a": 1}`, "p", "q"))
	if len(base) != 64 || base != InputsDigest("uid", []string{"n2", "n1", "n1"}, sel(`{"a":1}`, "q", "p")) {
		t.Fatal("order or formatting changed the digest")
	}
	other := sel(`{"a":1}`, "p", "q")
	other.Bundle.Digest = "sha256:" + strings.Repeat("2", 64)
	for name, d := range map[string]string{
		"binding":    InputsDigest("uid2", []string{"n1", "n2"}, sel(`{"a":1}`, "p", "q")),
		"namespaces": InputsDigest("uid", []string{"n1"}, sel(`{"a":1}`, "p", "q")),
		"bundle":     InputsDigest("uid", []string{"n1", "n2"}, other),
		"policies":   InputsDigest("uid", []string{"n1", "n2"}, sel(`{"a":1}`, "p")),
		"parameters": InputsDigest("uid", []string{"n1", "n2"}, sel(`{"a":2}`, "p", "q")),
		"no profile": InputsDigest("uid", []string{"n1", "n2"}, nil),
	} {
		if d == base {
			t.Errorf("%s does not change the digest", name)
		}
	}
	if InputsDigest("uid", nil, nil) == InputsDigest("uid", nil, sel("")) {
		t.Error("no profile and an empty selection compare equal")
	}
	if InputsDigest("uid", nil, sel(`{`, "p")) != "" {
		t.Error("invalid parameters produced a comparable digest")
	}
}
