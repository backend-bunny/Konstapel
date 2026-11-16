package coverage

import (
	"bytes"
	"os"
	"slices"
	"testing"
	"testing/fstest"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// Mapping problems leave the inventory resolved. A problem attributable to
// a selected control makes that control unknown; a mapping to a control
// outside the baseline, or to another catalog, is never attributed.
func TestMappingStates(t *testing.T) {
	cases := []struct {
		name     string
		edit     func(a *altDocs)
		code     string
		blocking bool
		want     map[string]string // control -> automation
	}{
		{"wrong-control statement", func(a *altDocs) {
			at(a.requirement(0), "statements", 0).(obj)["statement-id"] = "op2-req"
		}, CodeStatementNotInControl, true, map[string]string{"op1": AutomationUnknown, "op2": AutomationUnselected}},
		{"statement absent from the catalog", func(a *altDocs) {
			at(a.requirement(0), "statements", 0).(obj)["statement-id"] = "op1-req-z"
		}, CodeStatementNotInControl, true, map[string]string{"op1": AutomationUnknown}},
		{"undeclared rule", func(a *altDocs) {
			at(a.requirement(0), "statements", 0, "props", 0).(obj)["value"] = "rotate-everything"
		}, CodeRuleUndeclared, true, map[string]string{"op1": AutomationUnknown}},
		{"rule without a check in the content", func(a *altDocs) { a.policies = a.policies[1:] }, CodeRuleNotInContent, true,
			map[string]string{"op1": AutomationUnknown, "op2": AutomationUnselected}},
		{"rule without a declared check", func(a *altDocs) {
			c := at(a.cd, "component-definition", "components", 1).(obj)
			c["props"] = c["props"].([]any)[3:]
		}, CodeCheckUndeclared, true, map[string]string{"op1": AutomationUnknown}},
		{"unknown set-parameter", func(a *altDocs) {
			at(a.requirement(1), "set-parameters", 0).(obj)["param-id"] = "op9-freq"
		}, CodeParameterUnresolved, true, map[string]string{"op2": AutomationUnknown, "op1": AutomationPartial}},
		{"control not selected by the baseline", func(a *altDocs) {
			at(a.requirement(1)).(obj)["control-id"] = "op3"
		}, CodeMappingControlNotSelected, false, map[string]string{"op2": AutomationNone}},
		{"control not in the catalog", func(a *altDocs) {
			at(a.requirement(1)).(obj)["control-id"] = "zz9"
		}, CodeMappingControlUnknown, false, map[string]string{"op2": AutomationNone}},
		{"same identifiers, other catalog revision", func(a *altDocs) {
			other := newAlt().catalog
			at(other, "catalog", "metadata").(obj)["version"] = "2.0.0"
			a.extra[altDir+"catalog-r2.json"] = other
			at(a.cd, "component-definition", "components", 0, "control-implementations", 0).(obj)["source"] = "catalog-r2.json"
		}, CodeMappingCatalogMismatch, false, map[string]string{"op1": AutomationNone, "op2": AutomationNone}},
		{"source resolves to the baseline profile", func(a *altDocs) {
			at(a.cd, "component-definition", "components", 0, "control-implementations", 0).(obj)["source"] = "profile.json"
		}, "", false, map[string]string{"op1": AutomationPartial, "op2": AutomationUnselected}},
		{"unresolvable source", func(a *altDocs) {
			at(a.cd, "component-definition", "components", 0, "control-implementations", 0).(obj)["source"] = "missing.json"
		}, CodeMappingSourceUnresolved, true, map[string]string{"op1": AutomationUnknown, "fa1": AutomationUnknown}},
		{"unreadable component definition", func(a *altDocs) {
			delete(at(a.cd, "component-definition", "components", 0).(obj), "description")
		}, CodeDocumentInvalid, true, map[string]string{"op1": AutomationUnknown, "fa1": AutomationUnknown, "op1.e1": AutomationUnknown}},
		{"duplicate mapping edge", func(a *altDocs) {
			ci := at(a.cd, "component-definition", "components", 0, "control-implementations").([]any)
			dup := newAlt().cd
			at(a.cd, "component-definition", "components", 0).(obj)["control-implementations"] = append(ci,
				at(dup, "component-definition", "components", 0, "control-implementations", 0))
		}, CodeDuplicateMapping, false, map[string]string{"op1": AutomationPartial, "op2": AutomationUnselected}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAlt()
			tc.edit(a)
			c := a.content(t)
			r := Build(Input{Content: c, Selection: selecting(c, "rotate-keys-policy"), Options: opts(t)})
			if !r.Inventory.Resolved || len(r.Controls) != 4 {
				t.Fatalf("inventory %+v %v", r.Inventory, r.Limitations)
			}
			var all []Limitation
			all = append(all, r.Limitations...)
			for _, x := range r.Controls {
				all = append(all, x.Limitations...)
			}
			if tc.code == "" {
				if len(all) != 0 {
					t.Fatalf("limitations %v", all)
				}
			} else if i := slices.IndexFunc(all, func(l Limitation) bool { return l.Code == tc.code }); i < 0 || all[i].Blocking != tc.blocking {
				t.Fatalf("limitations %+v, want %s (blocking %v)", all, tc.code, tc.blocking)
			}
			for id, want := range tc.want {
				if got := row(t, r, id).Automation; got != want {
					t.Errorf("%s: %s, want %s", id, got, want)
				}
			}
			if tc.code == CodeDuplicateMapping {
				if ch := row(t, r, "op1").Checks; len(ch) != 1 || len(ch[0].Statements) != 1 {
					t.Errorf("duplicate edge inflated op1: %+v", ch)
				}
			}
		})
	}
}

// editContent is c with one file's bytes replaced (and re-inventoried).
func editContent(t *testing.T, c Content, p string, edit func([]byte) []byte) Content {
	t.Helper()
	payload := fstest.MapFS{}
	files := map[string]file{}
	for q, f := range c.files {
		files[q] = f
		raw, err := fsReadFile(c, q)
		if err != nil {
			t.Fatal(err)
		}
		payload[q] = &fstest.MapFile{Data: raw}
	}
	b := edit(payload[p].Data)
	if bytes.Equal(b, payload[p].Data) {
		t.Fatalf("edit of %s changed nothing", p)
	}
	payload[p] = &fstest.MapFile{Data: b}
	d := digest(b)
	files[p] = file{sha256: d[len("sha256:"):], size: int64(len(b))}
	c.files, c.payload = files, payload
	return c
}

func fsReadFile(c Content, p string) ([]byte, error) { raw, _, err := c.read(p); return raw, err }

// The shipped AC-6 mapping pointed at a CM-6 statement is refused: the
// statement exists in the catalog, but not in AC-6.
func TestModerateWrongControlStatement(t *testing.T) {
	c := editContent(t, official(t, privileged), "content/component-definition.json", func(b []byte) []byte {
		return bytes.Replace(b, []byte(`"statement-id": "ac-6_smt"`), []byte(`"statement-id": "cm-6_smt.b"`), 1)
	})
	r := Build(Input{Content: c, Selection: selecting(c, privPolicy), Options: opts(t)})
	ac6, cm6 := row(t, r, "ac-6"), row(t, r, "cm-6")
	if ac6.Automation != AutomationUnknown || !hasCode(ac6.Limitations, CodeStatementNotInControl) || ac6.Checks[0].Selection != CheckUnresolved {
		t.Fatalf("ac-6 %s %+v %v", ac6.Automation, ac6.Checks, ac6.Limitations)
	}
	if cm6.Automation != AutomationNone {
		t.Fatalf("the statement was attributed to cm-6: %s", cm6.Automation)
	}
}

// The handle of a frozen bundle and of the vendored tree read the same
// baseline as the built archive.
func TestHandles(t *testing.T) {
	want, err := ReadBaseline(official(t, privileged), opts(t))
	if err != nil {
		t.Fatal(err)
	}
	// Frozen copy of the official bundle.
	raw, _ := os.ReadFile(repo + "/bundles/" + privileged + "/definition.json")
	def, err := bundle.LoadDefinition(raw)
	if err != nil {
		t.Fatal(err)
	}
	def.Source.Revision = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	a, err := bundle.Build(def, os.DirFS(repo), time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	id := bundle.FrozenIdentity{FrozenVersion: bundle.FrozenVersion, Name: a.Descriptor.Name, Version: a.Descriptor.Version, Source: a.Descriptor.Source,
		Digests: bundle.Digests{Revision: a.Descriptor.Source.Revision, Content: a.Descriptor.ContentDigest(), Archive: a.LayerDigest, OCI: a.ManifestDigest}}
	f, err := bundle.WriteFrozen(t.TempDir()+"/frozen", a.Manifest, a.Layer, id)
	if err != nil {
		t.Fatal(err)
	}
	fc, err := FromFrozen(f)
	if err != nil {
		t.Fatal(err)
	}
	// The vendored tree, checked against its SHA256SUMS.
	sums, _ := os.ReadFile(repo + "/content/SHA256SUMS")
	ref := v1alpha1.BundleReference{Name: "vendored", Digest: digest(sums)}
	vc, err := FromVendored(os.DirFS(repo), ref, def.OSCAL, def.Policies)
	if err != nil {
		t.Fatal(err)
	}
	// A vendored caller names the profile: the tree's SHA256SUMS does not
	// cover every declared entry point, so discovery would fail closed.
	vo := opts(t)
	vo.Profile = moderatePath
	if _, err := ReadBaseline(vc, opts(t)); !hasCode(unresolved(t, err).Limitations, CodeDocumentUnavailable) {
		t.Errorf("discovery over an incomplete closure: %v", err)
	}
	for name, c := range map[string]Content{"frozen": fc, "vendored": vc} {
		o := opts(t)
		if name == "vendored" {
			o = vo
		}
		b, err := ReadBaseline(c, o)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if b.Catalog.Digest != want.Catalog.Digest || b.Profile.Digest != want.Profile.Digest || len(b.Controls) != len(want.Controls) {
			t.Errorf("%s: %+v %+v %d", name, b.Catalog, b.Profile, len(b.Controls))
		}
	}
	// The vendored SHA256SUMS does not list the authored component
	// definition, so its mappings are outside the closure: unresolved,
	// never assumed absent.
	r := Build(Input{Content: vc, Selection: Selection{Bundle: ref}, Options: vo})
	if r.Mappings.Resolved || row(t, r, "pe-3").Automation != AutomationUnknown {
		t.Errorf("vendored mappings %+v", r.Mappings)
	}
	if _, err := FromVendored(os.DirFS(repo), v1alpha1.BundleReference{Name: "vendored", Digest: want.Catalog.Digest}, def.OSCAL, def.Policies); err == nil {
		t.Error("vendored content served under another digest")
	}
}
