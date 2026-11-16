package coverage

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// moderateWithIDs decodes the pinned Moderate profile's selection directly,
// independently of the reader, as the expectation.
func moderateWithIDs(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(repo + "/" + moderatePath)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Profile struct {
			Imports []struct {
				IncludeControls []struct {
					WithIDs []string `json:"with-ids"`
				} `json:"include-controls"`
			} `json:"imports"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, i := range p.Profile.Imports {
		for _, inc := range i.IncludeControls {
			ids = append(ids, inc.WithIDs...)
		}
	}
	return ids
}

// Every control and enhancement the pinned Moderate profile selects is in
// the inventory, and nothing else, whatever the policy selection.
func TestModerateInventoryIsTheProfileSelection(t *testing.T) {
	want := moderateWithIDs(t)
	slices.Sort(want)
	if len(want) != moderateCount {
		t.Fatalf("the pinned Moderate profile selects %d IDs, the fixture expects %d", len(want), moderateCount)
	}
	for _, name := range []string{privileged, hardening} {
		c := official(t, name)
		b, err := ReadBaseline(c, opts(t))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got []string
		for _, ctl := range b.Controls {
			got = append(got, ctl.ID)
		}
		if !slices.IsSortedFunc(got, compareIDs) {
			t.Errorf("%s: controls are not in identifier order", name)
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Fatalf("%s: inventory differs from the profile's with-ids (got %d, want %d)", name, len(got), len(want))
		}
		if b.Profile.Path != moderatePath || b.Catalog.Path != catalogPath || b.Profile.OSCALVersion != "1.2.3" {
			t.Errorf("%s: documents %+v %+v", name, b.Profile, b.Catalog)
		}
		if len(b.Limitations) != 0 {
			t.Errorf("%s: limitations %v", name, b.Limitations)
		}
		// Enhancements keep distinct IDs and their parent; statements are
		// per control.
		e, ok := b.Control("ac-2.1")
		if !ok || e.Parent != "ac-2" || len(e.Groups) != 1 || e.Groups[0].ID != "ac" {
			t.Errorf("%s: ac-2.1 = %+v", name, e)
		}
		if !b.HasStatement("ac-6", "ac-6_smt") || b.HasStatement("ac-6", "cm-6_smt.b") || !b.HasStatement("cm-6", "cm-6_smt.b") {
			t.Errorf("%s: statement membership is not per control", name)
		}
		if _, ok := b.Control("ac-6.4"); ok || !b.InCatalog("ac-6.4") {
			t.Errorf("%s: ac-6.4 is in the catalog but not selected by Moderate", name)
		}
		if b.Qualified("ac-6") != b.Catalog.Digest+"#ac-6" {
			t.Errorf("%s: qualified identity %s", name, b.Qualified("ac-6"))
		}
	}
}

// Policy selection never changes which controls exist: a report selecting
// nothing and one selecting everything list the same 287 controls.
func TestInventoryIndependentOfSelection(t *testing.T) {
	c := official(t, hardening)
	var all []string
	for _, p := range c.Policies {
		all = append(all, p.Name)
	}
	none := Build(Input{Content: c, Selection: selecting(c), Options: opts(t)})
	every := Build(Input{Content: c, Selection: selecting(c, all...), Options: opts(t)})
	for _, r := range []*Report{none, every} {
		if !r.Inventory.Resolved || len(r.Controls) != moderateCount || r.Inventory.Controls != moderateCount {
			t.Fatalf("inventory %+v with %d rows", r.Inventory, len(r.Controls))
		}
	}
	for i := range none.Controls {
		if none.Controls[i].ID != every.Controls[i].ID {
			t.Fatalf("row %d differs: %s vs %s", i, none.Controls[i].ID, every.Controls[i].ID)
		}
	}
}
