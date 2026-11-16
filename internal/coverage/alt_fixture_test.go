package coverage

import (
	"fmt"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// The alternate-catalog fixture: a small, non-NIST framework with its own
// identifier style (no "_smt" statements, no families), a two-level profile
// chain, and a C2P-style component definition. It shows the model is
// framework-neutral; it is not a production framework adapter.
const (
	altDir      = "content/alt/"
	altCatalog  = altDir + "catalog.json"
	altBase     = altDir + "base-profile.json"
	altProfile  = altDir + "profile.json"
	altCD       = altDir + "component-definition.json"
	altResource = "11111111-1111-4111-8111-111111111111"
)

var uuidSeq int

func uuid() string {
	uuidSeq++
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", uuidSeq, uuidSeq)
}

type obj = map[string]any

func meta(title, version string) obj {
	return obj{"title": title, "last-modified": "2026-11-16T00:00:00Z", "version": "1.0.0", "oscal-version": version}
}

func stmt(id string, items ...string) obj {
	s := obj{"id": id, "name": "statement", "prose": "Do the thing."}
	var parts []any
	for _, it := range items {
		parts = append(parts, obj{"id": it, "name": "item", "prose": "Part."})
	}
	if parts != nil {
		s["parts"] = parts
	}
	return s
}

// altDocs are the fixture's documents as mutable JSON values.
type altDocs struct {
	catalog, base, profile, cd obj
	extra                      map[string]any // more files, by path
	raw                        map[string][]byte
	oscal                      []bundle.OSCALDocument
	policies                   []bundle.Policy
}

func newAlt() *altDocs {
	catalog := obj{"catalog": obj{
		"uuid":     uuid(),
		"metadata": meta("Example Secure Operations Framework", "1.2.3"),
		"groups": []any{
			obj{"id": "ops", "title": "Operations",
				"controls": []any{
					obj{"id": "op1", "title": "Key Rotation", "props": []any{obj{"name": "label", "value": "OP 1"}},
						"parts": []any{stmt("op1-req", "op1-req-a", "op1-req-b"), obj{"id": "op1-guide", "name": "guidance", "prose": "Guide."}},
						"controls": []any{
							obj{"id": "op1.e1", "title": "Automated Rotation", "parts": []any{stmt("op1.e1-req")}},
						}},
					obj{"id": "op2", "title": "Privilege Limits",
						"params": []any{obj{"id": "op2-freq", "label": "review frequency"}},
						"parts":  []any{stmt("op2-req")}},
				},
			},
			obj{"id": "aux", "title": "Auxiliary",
				"groups": []any{obj{"id": "aux-log", "title": "Logging",
					"controls": []any{obj{"id": "op3", "title": "Logging", "parts": []any{stmt("op3-req")}}}}}},
			obj{"id": "fac", "title": "Facilities",
				"controls": []any{obj{"id": "fa1", "title": "Site Access", "parts": []any{stmt("fa1-req")}}}},
		},
	}}
	base := obj{"profile": obj{
		"uuid":     uuid(),
		"metadata": meta("Example base selection", "1.2.3"),
		"imports": []any{obj{"href": "#" + altResource,
			"include-controls": []any{
				obj{"with-ids": []any{"op1"}, "with-child-controls": "yes"},
				obj{"with-ids": []any{"op2", "op3", "fa1"}},
			}}},
		"back-matter": obj{"resources": []any{obj{"uuid": altResource, "rlinks": []any{
			obj{"href": "https://example.org/catalog.json", "media-type": "application/oscal.catalog+json"},
			obj{"href": "catalog.xml", "media-type": "application/oscal.catalog+xml"},
			obj{"href": "catalog.json", "media-type": "application/oscal.catalog+json"},
		}}}},
	}}
	profile := obj{"profile": obj{
		"uuid":     uuid(),
		"metadata": meta("Example tailored baseline", "1.2.3"),
		"imports": []any{obj{"href": "base-profile.json", "include-all": obj{},
			"exclude-controls": []any{obj{"with-ids": []any{"op3"}}}}},
		"merge": obj{"as-is": true},
	}}
	rules := []any{
		obj{"name": "Rule_Id", "ns": "https://example.org/ns", "value": "rotate-keys", "remarks": "rs0"},
		obj{"name": "Rule_Description", "value": "Partial: checks the declared rotation interval only.", "remarks": "rs0"},
		obj{"name": "Parameter_Id", "value": "rotation_days", "remarks": "rs0"},
		obj{"name": "Parameter_Description", "value": "Maximum key age in days.", "remarks": "rs0"},
		obj{"name": "Rule_Id", "value": "no-root", "remarks": "rs1"},
		obj{"name": "Rule_Description", "value": "Partial: declared non-root execution only.", "remarks": "rs1"},
	}
	checks := []any{
		obj{"name": "Rule_Id", "value": "rotate-keys", "remarks": "c0"},
		obj{"name": "Check_Id", "value": "rotate-keys", "remarks": "c0"},
		obj{"name": "Check_Description", "value": "rotation check", "remarks": "c0"},
		obj{"name": "Rule_Id", "value": "no-root", "remarks": "c1"},
		obj{"name": "Check_Id", "value": "no-root", "remarks": "c1"},
	}
	cd := obj{"component-definition": obj{
		"uuid":     uuid(),
		"metadata": meta("Example mappings", "1.1.3"),
		"components": []any{
			obj{"uuid": uuid(), "type": "software", "title": "Workloads", "description": "Workloads.", "props": rules,
				"control-implementations": []any{obj{"uuid": uuid(), "source": "catalog.json", "description": "Example",
					"implemented-requirements": []any{
						obj{"uuid": uuid(), "control-id": "op1", "description": "Rotation evidence only.",
							"set-parameters": []any{obj{"param-id": "rotation_days", "values": []any{"90"}}},
							"statements": []any{obj{"statement-id": "op1-req-a", "uuid": uuid(), "description": "Declared interval.",
								"props": []any{obj{"name": "Rule_Id", "value": "rotate-keys"}}}}},
						obj{"uuid": uuid(), "control-id": "op2", "description": "Non-root only.",
							"props":          []any{obj{"name": "Rule_Id", "value": "no-root"}},
							"set-parameters": []any{obj{"param-id": "op2-freq", "values": []any{"monthly"}}}},
					}}}},
			obj{"uuid": uuid(), "type": "validation", "title": "example-engine", "description": "Engine.", "props": checks},
		},
	}}
	return &altDocs{catalog: catalog, base: base, profile: profile, cd: cd, extra: map[string]any{}, raw: map[string][]byte{},
		oscal: []bundle.OSCALDocument{
			{Path: altCD, Version: "1.1.3"},
			{Path: altCatalog, Version: "1.2.3"},
			{Path: altProfile, Version: "1.2.3"},
		},
		policies: []bundle.Policy{
			{Name: "rotate-keys-policy", Path: altDir + "policies/rotate.yaml", Checks: []bundle.Check{{RuleID: "rotate-keys", CheckID: "rotate-keys"}}},
			{Name: "no-root-policy", Path: altDir + "policies/no-root.yaml", Checks: []bundle.Check{{RuleID: "no-root", CheckID: "no-root"}}},
		}}
}

func (a *altDocs) content(t testing.TB) Content {
	t.Helper()
	f := &fixture{files: map[string][]byte{}, oscal: a.oscal, policies: a.policies}
	f.put(altCatalog, a.catalog)
	f.put(altBase, a.base)
	f.put(altProfile, a.profile)
	f.put(altCD, a.cd)
	for p, v := range a.extra {
		f.put(p, v)
	}
	for _, p := range a.policies {
		f.files[p.Path] = []byte("kind: ValidatingPolicy\n")
	}
	for p, b := range a.raw {
		if b == nil {
			delete(f.files, p)
		} else {
			f.files[p] = b
		}
	}
	return f.content(t)
}

// at walks a JSON value by object keys and array indexes.
func at(v any, path ...any) any {
	for _, k := range path {
		switch k := k.(type) {
		case string:
			v = v.(obj)[k]
		case int:
			v = v.([]any)[k]
		}
	}
	return v
}

func (a *altDocs) altImport(i int) obj { return at(a.profile, "profile", "imports", i).(obj) }
func (a *altDocs) baseImport(i int) obj {
	return at(a.base, "profile", "imports", i).(obj)
}
func (a *altDocs) requirement(i int) obj {
	return at(a.cd, "component-definition", "components", 0, "control-implementations", 0, "implemented-requirements", i).(obj)
}

// noNIST fails if the report of a non-NIST fixture mentions NIST
// conventions, which would mean something is hard-coded.
func noNIST(t *testing.T, r *Report) {
	t.Helper()
	for _, c := range r.Controls {
		for _, s := range c.Statements {
			if strings.Contains(s, "_smt") {
				t.Errorf("statement %s uses a NIST convention", s)
			}
		}
	}
	if strings.Contains(strings.ToLower(r.Inventory.Catalog.Path), "nist") {
		t.Errorf("catalog %s", r.Inventory.Catalog.Path)
	}
}
