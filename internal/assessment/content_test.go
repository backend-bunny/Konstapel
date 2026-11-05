package assessment

import (
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the vendored OSCAL schema, including its nested references and
// draft-07 format assertions, when upgrading the JSON Schema implementation.
func TestSchemaValidation(t *testing.T) {
	root := repo(t)
	var document Object
	if err := Read(filepath.Join(root, "content/component-definition.json"), &document); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(Object)
		field  string
	}{
		{name: "valid"},
		{name: "required field", mutate: func(d Object) { delete(d, "uuid") }, field: "uuid"},
		{name: "uuid pattern", mutate: func(d Object) { d["uuid"] = "invalid" }, field: "uuid"},
		{name: "date-time format", mutate: func(d Object) {
			Map(d["metadata"])["last-modified"] = "2026-99-99T00:00:00Z"
		}, field: "last-modified"},
		{name: "nested reference", mutate: func(d Object) {
			Map(d["components"].([]any)[0])["title"] = 42
		}, field: "title"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := clone(document)
			if tc.mutate != nil {
				tc.mutate(Map(doc["component-definition"]))
			}
			path := filepath.Join(t.TempDir(), "component.json")
			if err := Write(path, doc); err != nil {
				t.Fatal(err)
			}
			err := Schema(path, filepath.Join(root, "content/schemas/oscal-1.1.3.json"))
			if tc.field == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("expected diagnostic identifying %q, got %v", tc.field, err)
			}
		})
	}
}
