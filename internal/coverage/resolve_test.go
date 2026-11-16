package coverage

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

func ids(r *Report) []string {
	var out []string
	for _, c := range r.Controls {
		out = append(out, c.ID)
	}
	return out
}

// The same model resolves and joins a non-NIST catalog through a profile
// chain: no identifier, label, family or statement convention is assumed.
func TestAlternateCatalog(t *testing.T) {
	a := newAlt()
	c := a.content(t)
	r := Build(Input{Content: c, Selection: selecting(c, "rotate-keys-policy"), Options: opts(t)})
	if !r.Inventory.Resolved || !r.Mappings.Resolved || len(r.Limitations) != 0 {
		t.Fatalf("inventory %+v mappings %+v limitations %v", r.Inventory, r.Mappings, r.Limitations)
	}
	noNIST(t, r)
	if got, want := ids(r), []string{"fa1", "op1", "op1.e1", "op2"}; !slices.Equal(got, want) {
		t.Fatalf("controls %v, want %v", got, want)
	}
	if r.Inventory.Controls != 4 || r.Inventory.Enhancements != 1 || r.Inventory.Statements != 6 {
		t.Errorf("inventory counts %+v", r.Inventory)
	}
	if r.Inventory.Profile.Path != altProfile || r.Inventory.Catalog.Path != altCatalog || len(r.Inventory.Imports) != 1 || r.Inventory.Imports[0].Path != altBase {
		t.Errorf("documents %+v %+v %+v", r.Inventory.Profile, r.Inventory.Catalog, r.Inventory.Imports)
	}
	op1 := row(t, r, "op1")
	if op1.Automation != AutomationPartial || op1.Label != "OP 1" || op1.Groups[0].ID != "ops" ||
		!slices.Equal(op1.Statements, []string{"op1-req", "op1-req-a", "op1-req-b"}) {
		t.Errorf("op1 %+v", op1)
	}
	ch := checkOf(t, op1, "rotate-keys")
	if ch.Selection != CheckSelected || ch.CheckID != "rotate-keys" || ch.Policy != "rotate-keys-policy" ||
		len(ch.RuleParameters) != 1 || ch.RuleParameters[0].ID != "rotation_days" || !slices.Equal(ch.RuleParameters[0].Values, []string{"90"}) ||
		ch.OSCALParameters != nil || ch.Statements[0].ID != "op1-req-a" || ch.CheckDescription != "rotation check" {
		t.Errorf("op1 check %+v", ch)
	}
	if e := row(t, r, "op1.e1"); e.Parent != "op1" || e.Automation != AutomationNone {
		t.Errorf("op1.e1 %+v", e)
	}
	op2 := row(t, r, "op2")
	if op2.Automation != AutomationUnselected {
		t.Errorf("op2 %s", op2.Automation)
	}
	ch = checkOf(t, op2, "no-root")
	if ch.Selection != CheckUnselected || len(ch.Statements) != 0 || ch.RequirementDescription != "Non-root only." ||
		len(ch.OSCALParameters) != 1 || ch.OSCALParameters[0].ParamID != "op2-freq" {
		t.Errorf("op2 check %+v", ch)
	}
	if fa1 := row(t, r, "fa1"); fa1.Automation != AutomationNone || fa1.Groups[0].Title != "Facilities" {
		t.Errorf("fa1 %+v", fa1)
	}
}

// Inventory failures: each makes the whole inventory unresolved with a
// coded, blocking limitation, and the report lists no controls.
func TestUnresolvedInventory(t *testing.T) {
	cases := []struct {
		name string
		edit func(a *altDocs)
		code string
	}{
		{"missing import", func(a *altDocs) { a.altImport(0)["href"] = "missing.json" }, CodeImportUnresolved},
		{"external import", func(a *altDocs) { a.altImport(0)["href"] = "https://example.org/base.json" }, CodeImportExternal},
		{"import leaves the content", func(a *altDocs) { a.altImport(0)["href"] = "../../../base.json" }, CodeImportOutsideContent},
		{"no resource link resolves", func(a *altDocs) { a.raw[altCatalog] = nil; a.oscal = slices.Delete(a.oscal, 1, 2) }, CodeImportUnresolved},
		{"missing back-matter resource", func(a *altDocs) { a.baseImport(0)["href"] = "#" + strings.Repeat("2", 8) + altResource[8:] }, CodeImportUnresolved},
		{"ambiguous resource", func(a *altDocs) {
			a.extra[altDir+"other.json"] = a.catalog
			rl := at(a.base, "profile", "back-matter", "resources", 0).(obj)
			rl["rlinks"] = append(rl["rlinks"].([]any), obj{"href": "other.json", "media-type": "application/oscal.catalog+json"})
		}, CodeImportAmbiguous},
		{"import cycle", func(a *altDocs) { a.baseImport(0)["href"] = "profile.json" }, CodeImportCycle},
		{"self import", func(a *altDocs) { a.altImport(0)["href"] = "profile.json" }, CodeImportCycle},
		{"matching selection", func(a *altDocs) {
			a.baseImport(0)["include-controls"] = []any{obj{"matching": []any{obj{"pattern": "op*"}}}}
		}, CodeSemanticsUnsupported},
		{"modify", func(a *altDocs) {
			at(a.profile, "profile").(obj)["modify"] = obj{"set-parameters": []any{obj{"param-id": "op2-freq", "values": []any{"daily"}}}}
		}, CodeSemanticsUnsupported},
		{"custom merge", func(a *altDocs) {
			at(a.profile, "profile").(obj)["merge"] = obj{"custom": obj{"insert-controls": []any{obj{"include-all": obj{}}}}}
		}, CodeSemanticsUnsupported},
		{"combine merge (OSCAL 1.1.3)", func(a *altDocs) {
			at(a.profile, "profile", "metadata").(obj)["oscal-version"] = "1.1.3"
			a.oscal[2].Version = "1.1.3"
			at(a.profile, "profile").(obj)["merge"] = obj{"combine": obj{"method": "merge"}, "as-is": true}
		}, CodeSemanticsUnsupported},
		{"selection from another revision", func(a *altDocs) {
			a.baseImport(0)["include-controls"] = []any{obj{"with-ids": []any{"op1", "op9"}}}
		}, CodeSelectionNotInSource},
		{"exclusion from another revision", func(a *altDocs) {
			a.altImport(0)["exclude-controls"] = []any{obj{"with-ids": []any{"op9"}}}
		}, CodeSelectionNotInSource},
		{"selection the imported profile does not make", func(a *altDocs) {
			imp := a.altImport(0)
			delete(imp, "include-all")
			imp["include-controls"] = []any{obj{"with-ids": []any{"op1", "op1.e1"}}}
			a.baseImport(0)["include-controls"] = []any{obj{"with-ids": []any{"op1"}}}
		}, CodeSelectionNotInSource},
		{"multiple catalogs", func(a *altDocs) {
			other := newAlt().catalog
			at(other, "catalog", "metadata").(obj)["title"] = "Another revision"
			a.extra[altDir+"catalog-r2.json"] = other
			imps := at(a.profile, "profile").(obj)
			imps["imports"] = append(imps["imports"].([]any), obj{"href": "catalog-r2.json", "include-controls": []any{obj{"with-ids": []any{"fa1"}}}})
		}, CodeMultipleCatalogs},
		{"empty selection", func(a *altDocs) {
			a.altImport(0)["exclude-controls"] = []any{obj{"with-ids": []any{"op1", "op2", "op3", "fa1"}, "with-child-controls": "yes"}}
		}, CodeEmptySelection},
		{"duplicate catalog id", func(a *altDocs) {
			g := at(a.catalog, "catalog", "groups", 2).(obj)
			g["controls"] = append(g["controls"].([]any), obj{"id": "op2", "title": "Again"})
		}, CodeDuplicateCatalogID},
		{"unsupported OSCAL version", func(a *altDocs) {
			at(a.catalog, "catalog", "metadata").(obj)["oscal-version"] = "1.0.4"
			a.oscal[1].Version = "1.0.4"
		}, CodeSchemaVersionUnsupported},
		{"declared version differs", func(a *altDocs) { a.oscal[2].Version = "1.1.3" }, CodeSchemaVersionMismatch},
		{"schema-invalid catalog", func(a *altDocs) { delete(at(a.catalog, "catalog", "groups", 2, "controls", 0).(obj), "title") }, CodeDocumentInvalid},
		{"import of another model", func(a *altDocs) { a.altImport(0)["href"] = "component-definition.json" }, CodeDocumentInvalid},
		{"no declared profile", func(a *altDocs) { a.oscal = a.oscal[:2] }, CodeProfileNotDeclared},
		{"ambiguous profile", func(a *altDocs) { a.oscal = append(a.oscal, bundle.OSCALDocument{Path: altBase, Version: "1.2.3"}) }, CodeProfileAmbiguous},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAlt()
			tc.edit(a)
			c := a.content(t)
			_, err := ReadBaseline(c, opts(t))
			if !errors.Is(err, ErrUnresolved) {
				t.Fatalf("resolved despite %s: %v", tc.name, err)
			}
			ue := unresolved(t, err)
			if !hasCode(ue.Limitations, tc.code) || !anyBlocking(ue.Limitations) {
				t.Fatalf("limitations %v, want %s", limitationCodes(ue.Limitations), tc.code)
			}
			r := Build(Input{Content: c, Selection: selecting(c, "rotate-keys-policy"), Options: opts(t)})
			if r.Inventory.Resolved || len(r.Controls) != 0 || r.Inventory.Controls != 0 || !hasCode(r.Limitations, tc.code) {
				t.Fatalf("report presents an inventory: %+v %v", r.Inventory, ids(r))
			}
		})
	}
}

// A version without a trusted schema from the controller is unsupported,
// even when the content carries a schema of its own.
func TestNoTrustedSchema(t *testing.T) {
	o := Options{Schemas: map[string][]byte{"1.1.3": trustedSchemas(t)["1.1.3"]}}
	_, err := ReadBaseline(newAlt().content(t), o)
	if ue := unresolved(t, err); !hasCode(ue.Limitations, CodeSchemaVersionUnsupported) {
		t.Fatalf("limitations %v", ue.Limitations)
	}
}

// Content that no longer matches its verified inventory is never read, and
// a document with a repeated JSON key is rejected rather than decoded.
func TestTamperedAndAmbiguousBytes(t *testing.T) {
	a := newAlt()
	c := a.content(t)
	payload := c.payload.(fstest.MapFS)
	payload[altBase] = &fstest.MapFile{Data: bytes.Replace(payload[altBase].Data, []byte(`"op2"`), []byte(`"op3"`), 1)}
	ue := unresolved(t, func() error { _, err := ReadBaseline(c, opts(t)); return err }())
	if !hasCode(ue.Limitations, CodeDocumentUnavailable) {
		t.Fatalf("limitations %v", ue.Limitations)
	}

	a = newAlt()
	c = a.content(t)
	raw := c.payload.(fstest.MapFS)[altProfile].Data
	a.raw[altProfile] = bytes.Replace(raw, []byte(`"merge": {`), []byte(`"merge": {"as-is": false, `), 1)
	if bytes.Equal(a.raw[altProfile], raw) {
		t.Fatal("fixture edit did not apply")
	}
	_, err := ReadBaseline(a.content(t), opts(t))
	if ue := unresolved(t, err); !hasCode(ue.Limitations, CodeDocumentInvalid) {
		t.Fatalf("limitations %v", ue.Limitations)
	}
}

// Duplicate selection edges are deduplicated with a notice; the control is
// counted once and the inventory stays resolved.
func TestDuplicateSelectionEdges(t *testing.T) {
	a := newAlt()
	a.baseImport(0)["include-controls"] = []any{
		obj{"with-ids": []any{"op1", "op2"}, "with-child-controls": "yes"},
		obj{"with-ids": []any{"op2", "fa1", "op3"}},
	}
	imps := at(a.profile, "profile").(obj)
	imps["imports"] = append(imps["imports"].([]any), obj{"href": "catalog.json", "include-controls": []any{obj{"with-ids": []any{"fa1"}}}})
	b, err := ReadBaseline(a.content(t), opts(t))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range b.Controls {
		got = append(got, c.ID)
	}
	if !slices.Equal(got, []string{"fa1", "op1", "op1.e1", "op2"}) {
		t.Fatalf("controls %v", got)
	}
	var subjects []string
	for _, l := range b.Limitations {
		if l.Code != CodeDuplicateSelection || l.Blocking {
			t.Errorf("limitation %+v", l)
		}
		subjects = append(subjects, l.Subject)
	}
	slices.Sort(subjects)
	if !slices.Equal(subjects, []string{"fa1", "op2"}) {
		t.Errorf("duplicate notices for %v", subjects)
	}
}
