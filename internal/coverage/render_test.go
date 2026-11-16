package coverage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

var update = flag.Bool("update", false, "rewrite the coverage golden files")

const goldenDir = "testdata/golden"

// goldenContentPath is where the fixtures' content is packaged.
var goldenContentPath = "bundles/" + strings.Repeat("f", 64)

// goldenEvidence are fixed package references to the capture and evaluation.
var goldenEvidence = []Source{
	{Path: "capture.json", Kind: SourceCapture, SHA256: strings.Repeat("c", 64)},
	{Path: "evaluation.json", Kind: SourceEvaluation, SHA256: strings.Repeat("e", 64)},
}

// goldenAlt is the alternate-catalog content with deterministic UUIDs, so
// its document digests (and the golden files) are stable.
func goldenAlt(t *testing.T, edit func(*altDocs)) Content {
	t.Helper()
	uuidSeq = 0
	a := newAlt()
	if edit != nil {
		edit(a)
	}
	return a.content(t)
}

func goldenScope() Scope {
	return Scope{Kind: "Binding", Cluster: evCluster, Binding: &ObjectRef{Name: "bind-a", UID: "bind-a"},
		Namespaces: []NamespaceRef{{Name: evNS, UID: evNSUID}}}
}

func altContribs(c Content) []contrib {
	return []contrib{
		{binding: "bind-a", revision: "r1", policy: "rotate-keys-policy", bundle: c.Bundle},
		{binding: "bind-a", revision: "r1", policy: "no-root-policy", bundle: c.Bundle},
	}
}

// goldenInputs are the three golden fixtures' inputs.
func goldenInputs(t *testing.T) map[string]Input {
	t.Helper()
	in := map[string]Input{}

	// complete: both checks selected, every expected observation current.
	c := goldenAlt(t, nil)
	sel := selecting(c, "rotate-keys-policy", "no-root-policy")
	sel.Policies[0].Parameters = json.RawMessage(`{"maxAgeDays": 90}`)
	capC := capture(t, altContribs(c), pod("p1"), pod("p2"))
	reportAll(&capC, evStarted.Add(time.Minute), "pass")
	in["complete"] = Input{Scope: goldenScope(), Content: c, Selection: sel, Options: opts(t), Evidence: evaluated(t, capC, evMaxAge),
		Packaging: &Packaging{ContentPath: goldenContentPath, Evidence: goldenEvidence}}

	// incomplete: a failure, a missing observation, and one unselected check.
	c = goldenAlt(t, nil)
	capI := capture(t, altContribs(c)[:1], pod("p1"), pod("p2"))
	e := altContribs(c)[0]
	capI.Reports = append(capI.Reports, result(e.enginePolicy(), 0, pod("p1"), "fail", evStarted.Add(time.Minute)))
	in["incomplete"] = Input{Scope: goldenScope(), Content: c, Selection: selecting(c, "rotate-keys-policy"), Options: opts(t),
		Evidence: evaluated(t, capI, evMaxAge), Packaging: &Packaging{ContentPath: goldenContentPath, Evidence: goldenEvidence}}

	// no-automation: no authored mapping at all and zero targets: every
	// control is listed with no automated assessment.
	c = goldenAlt(t, func(a *altDocs) { a.oscal = a.oscal[1:] }) // drop the component definition
	capN := capture(t, nil)
	in["no-automation"] = Input{Scope: goldenScope(), Content: c, Selection: selecting(c), Options: opts(t),
		Evidence: evaluated(t, capN, evMaxAge), Packaging: &Packaging{ContentPath: goldenContentPath, Evidence: goldenEvidence}}
	return in
}

// The golden fixtures render byte-identically, both files are one report's
// rendering, and the states they exist to show hold.
func TestRenderGolden(t *testing.T) {
	for name, in := range goldenInputs(t) {
		t.Run(name, func(t *testing.T) {
			r := Build(in)
			f, err := Render(r)
			if err != nil {
				t.Fatal(err)
			}
			jp, tp := filepath.Join(goldenDir, name+".json"), filepath.Join(goldenDir, name+".txt")
			if *update {
				if err := os.MkdirAll(goldenDir, 0o755); err != nil {
					t.Fatal(err)
				}
				for p, b := range map[string][]byte{jp: f.JSON, tp: f.Text} {
					if err := os.WriteFile(p, b, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			for p, b := range map[string][]byte{jp: f.JSON, tp: f.Text} {
				want, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(want, b) {
					t.Errorf("%s differs from the rendering (run with -update after an intended change)", p)
				}
			}
			if err := VerifyFiles(f); err != nil {
				t.Fatal(err)
			}
			if len(r.Controls) != r.Inventory.Controls || !r.Inventory.Resolved || len(r.Controls) == 0 {
				t.Fatalf("inventory %+v with %d rows", r.Inventory, len(r.Controls))
			}
			te := r.TechnicalEvidence.Evidence
			switch name {
			case "complete":
				if te.Completeness != "Complete" || row(t, r, "op1").Automation != AutomationPartial || row(t, r, "fa1").Automation != AutomationNone {
					t.Errorf("complete: %+v", te)
				}
			case "incomplete":
				if te.Completeness != "Incomplete" || r.TechnicalEvidence.Outcomes.Fail != 1 || te.Missing != 1 ||
					row(t, r, "op2").Automation != AutomationUnselected {
					t.Errorf("incomplete: %+v %+v", te, r.TechnicalEvidence.Outcomes)
				}
			case "no-automation":
				if te.Completeness != "NoTargets" || !r.Mappings.Resolved {
					t.Errorf("no-automation: %+v mappings %+v", te, r.Mappings)
				}
				for _, c := range r.Controls {
					if c.Automation != AutomationNone || c.Evidence != nil {
						t.Errorf("no-automation row %s: %s", c.ID, c.Automation)
					}
				}
			}
			// No rendering claims satisfaction.
			for _, b := range [][]byte{f.JSON, f.Text} {
				if bytes.Contains(bytes.ToLower(b), []byte("satisfied\"")) || bytes.Contains(b, []byte(`"full"`)) {
					t.Errorf("%s claims satisfaction", name)
				}
			}
		})
	}
}

// shuffled is in with every order-insensitive input permuted.
func shuffled(in Input, seed uint64) Input {
	rng := rand.New(rand.NewPCG(seed, seed))
	in.Selection.Policies = slices.Clone(in.Selection.Policies)
	rng.Shuffle(len(in.Selection.Policies), func(i, j int) {
		in.Selection.Policies[i], in.Selection.Policies[j] = in.Selection.Policies[j], in.Selection.Policies[i]
	})
	if in.Evidence != nil {
		ev := clone(*in.Evidence)
		obs := ev.Evaluation.Observations
		rng.Shuffle(len(obs), func(i, j int) { obs[i], obs[j] = obs[j], obs[i] })
		// The capture's own order is the owner's validated, frozen order
		// (CaptureV2.Validate requires it); only the evaluation's
		// observation order is free.
		in.Evidence = &ev
	}
	if in.Packaging != nil {
		p := *in.Packaging
		p.Evidence = slices.Clone(p.Evidence)
		slices.Reverse(p.Evidence)
		in.Packaging = &p
	}
	return in
}

// Hand-break guard (nondeterministic ordering): the same frozen inputs in
// any order render the same bytes.
func TestRenderDeterministicOrdering(t *testing.T) {
	inputs := goldenInputs(t)
	// The Moderate baseline with the hardening states fixture exercises
	// natural ID ordering, shared checks and every evidence state.
	c, ev := statesFixture(t)
	inputs["moderate"] = Input{Content: c, Selection: allHardening(c), Options: opts(t), Evidence: ev,
		Packaging: &Packaging{ContentPath: "bundles/x", Evidence: goldenEvidence}}
	for name, in := range inputs {
		want, err := Render(Build(in))
		if err != nil {
			t.Fatal(err)
		}
		for seed := range uint64(3) {
			got, err := Render(Build(shuffled(in, seed+1)))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.JSON, want.JSON) || !bytes.Equal(got.Text, want.Text) {
				t.Fatalf("%s: rendering depends on input order (seed %d)", name, seed+1)
			}
		}
	}
}

// Hand-break guard (JSON/text divergence): every identity, state, count,
// limitation and source of the JSON is stated in the text, and the text
// names the JSON's digest.
func TestRenderTextEquivalentToJSON(t *testing.T) {
	inputs := goldenInputs(t)
	c, ev := statesFixture(t)
	inputs["moderate"] = Input{Content: c, Selection: allHardening(c), Options: opts(t), Evidence: ev,
		Packaging: &Packaging{ContentPath: "bundles/x", Evidence: goldenEvidence}}
	for name, in := range inputs {
		f, err := Render(Build(in))
		if err != nil {
			t.Fatal(err)
		}
		r, err := Parse(f.JSON)
		if err != nil {
			t.Fatal(err)
		}
		text := string(f.Text)
		lines := strings.Split(text, "\n")
		has := func(prefix string) bool {
			return slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(strings.TrimLeft(l, " "), prefix) })
		}
		sum := sha256.Sum256(f.JSON)
		want := []string{TextReportLine + hex.EncodeToString(sum[:]), "As of: " + ts(r.AsOf), "Inventory: " + resolved(r.Inventory.Resolved),
			"Technical evidence: " + r.TechnicalEvidence.State, fmt.Sprintf("Controls: %d", len(r.Controls)),
			fmt.Sprintf("Limitations: %d", len(r.Limitations)), fmt.Sprintf("Sources: %d", len(r.Sources))}
		if r.TechnicalEvidence.Evidence != nil {
			want = append(want, "Evidence: "+summary(*r.TechnicalEvidence.Evidence), "Outcomes: "+outcomes(*r.TechnicalEvidence.Outcomes))
		}
		for _, c := range r.Controls {
			want = append(want, fmt.Sprintf("Control %s [%s] %s", c.ID, c.Automation, c.Title), "Qualified ID: "+c.QualifiedID)
			for _, ch := range c.Checks {
				want = append(want, fmt.Sprintf("Check %s [%s] policy %s", ch.RuleID, ch.Selection, orNone(ch.Policy)))
			}
		}
		for _, l := range r.Limitations {
			want = append(want, "Limitation "+l.Code)
		}
		for _, s := range r.Sources {
			want = append(want, fmt.Sprintf("Source: %s (%s) sha256 %s", s.Path, s.Kind, s.SHA256))
		}
		for _, o := range r.TechnicalEvidence.Observations {
			want = append(want, "Observation "+printableKey(o.Observation.Key))
		}
		for _, w := range want {
			if !has(w) {
				t.Errorf("%s: the text does not state %q", name, w)
			}
		}
		count := 0
		for _, l := range lines {
			if strings.HasPrefix(l, "  Control ") {
				count++
			}
		}
		if count != len(r.Controls) {
			t.Errorf("%s: text lists %d controls, JSON %d", name, count, len(r.Controls))
		}
	}
}

// Hand-break guards for the pair: an edited text, a non-canonical or
// extended JSON, and another schema version all fail verification.
func TestVerifyFilesFailsClosed(t *testing.T) {
	f, err := Render(Build(goldenInputs(t)["incomplete"]))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyFiles(f); err != nil {
		t.Fatal(err)
	}
	edit := func(b []byte, old, new string) []byte {
		if !bytes.Contains(b, []byte(old)) {
			t.Fatalf("no %q to edit", old)
		}
		return bytes.Replace(b, []byte(old), []byte(new), 1)
	}
	cases := map[string]Files{
		"text says partial for unselected": {JSON: f.JSON, Text: edit(f.Text, "[unselected]", "[partial]")},
		"text dropped a line":              {JSON: f.JSON, Text: edit(f.Text, "Limitations:", "Limitation count:")},
		"json changed under the text":      {JSON: edit(f.JSON, `"automation": "unselected"`, `"automation": "partial"`), Text: f.Text},
		"json not canonical":               {JSON: append(bytes.TrimSuffix(f.JSON, []byte("\n")), ' ', '\n'), Text: f.Text},
		"json unknown field":               {JSON: edit(f.JSON, `"asOf"`, `"verdict": "pass", "asOf"`), Text: f.Text},
		"json other version":               {JSON: edit(f.JSON, SchemaVersion, "konstapel.io/coverage/v2"), Text: f.Text},
	}
	for name, c := range cases {
		if err := VerifyFiles(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Content strings cannot inject terminal control sequences into the text.
func TestRenderTextNeutralizesControlCharacters(t *testing.T) {
	r := Unavailable(Input{Scope: Scope{Cluster: "c\x1b[31mred"}, Content: Content{Bundle: v1alpha1.BundleReference{Name: "b", Digest: "d"}}},
		CodeContentUnavailable, "", "message with \x07 bell")
	f, err := Render(r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsAny(f.Text, "\x1b\x07") {
		t.Fatalf("control characters reached the text:\n%s", f.Text)
	}
}

// The coverage diagnostic: no readable content lists no controls, keeps the
// owner's evidence verbatim, attributes none of it, and renders validly.
func TestUnavailableReport(t *testing.T) {
	in := goldenInputs(t)["incomplete"]
	in.Content = Content{Bundle: in.Content.Bundle}
	r := Unavailable(in, CodeContentUnavailable, in.Content.Bundle.Name, "the package carries no content for %s", in.Content.Bundle.Name)
	if r.Inventory.Resolved || len(r.Controls) != 0 || !hasCode(r.Limitations, CodeContentUnavailable) || !anyBlocking(r.Limitations) {
		t.Fatalf("diagnostic %+v %v", r.Inventory, r.Limitations)
	}
	te := r.TechnicalEvidence
	if te.State != EvidenceResolved || *te.Evidence != in.Evidence.Evaluation.Evidence || *te.Outcomes != in.Evidence.Evaluation.Outcomes {
		t.Fatalf("evidence not retained: %+v", te)
	}
	for _, c := range te.Contributions {
		if c.Attribution != AttributionUnresolved {
			t.Errorf("contribution %s attributed %s without an inventory", c.LogicalPolicy, c.Attribution)
		}
	}
	for _, o := range te.Observations {
		if len(o.Controls) > 0 {
			t.Errorf("observation attributed to %v", o.Controls)
		}
	}
	if !slices.Equal(r.Sources, goldenEvidence) {
		t.Errorf("sources %+v", r.Sources)
	}
	f, err := Render(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyFiles(f); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(f.Text, []byte("None listed: the inventory is unresolved")) {
		t.Errorf("text does not explain the empty list:\n%s", f.Text)
	}
}

// A selection that was not recorded is never read as "nothing selected".
func TestSelectionUnavailable(t *testing.T) {
	c := goldenAlt(t, nil)
	r := Build(Input{Content: c, Selection: Selection{}, Options: opts(t)})
	if !hasCode(r.Limitations, CodeSelectionUnavailable) {
		t.Fatalf("limitations %v", r.Limitations)
	}
	for _, ctl := range r.Controls {
		for _, ch := range ctl.Checks {
			if ch.Selection != CheckUnresolved {
				t.Errorf("%s/%s is %s without a recorded selection", ctl.ID, ch.RuleID, ch.Selection)
			}
		}
		if len(ctl.Checks) > 0 && ctl.Automation != AutomationUnknown {
			t.Errorf("%s is %s without a recorded selection", ctl.ID, ctl.Automation)
		}
	}
}

// Sources reference the packaged documents by package path and digest.
func TestSourcesArePackageRelative(t *testing.T) {
	r := Build(goldenInputs(t)["complete"])
	var paths []string
	for _, s := range r.Sources {
		paths = append(paths, s.Path)
		if len(s.SHA256) != 64 {
			t.Errorf("source %s digest %q", s.Path, s.SHA256)
		}
	}
	want := []string{goldenContentPath + "/" + altBase, goldenContentPath + "/" + altCatalog, goldenContentPath + "/" + altCD,
		goldenContentPath + "/" + altProfile, "capture.json", "evaluation.json"}
	slices.Sort(want)
	if !slices.Equal(paths, want) {
		t.Fatalf("sources %v, want %v", paths, want)
	}
}
