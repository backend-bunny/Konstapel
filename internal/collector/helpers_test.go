package collector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"
)

func repo(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func clone[T any](v T) T { b, _ := json.Marshal(v); var x T; _ = json.Unmarshal(b, &x); return x }

// renderedName is the engine policy name in a rendered golden file under
// testdata/targeting/rendered. Names derive from the vendored bundle digest,
// so tests read them instead of hard-coding them.
func renderedName(t *testing.T, file string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repo(t), "testdata/targeting/rendered", file))
	if err != nil {
		t.Fatal(err)
	}
	var o struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	if err := yaml.Unmarshal(raw, &o); err != nil || o.Metadata.Name == "" {
		t.Fatalf("%s: no engine policy name (%v)", file, err)
	}
	return o.Metadata.Name
}
