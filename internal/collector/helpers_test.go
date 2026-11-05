package collector

import (
	"encoding/json"
	"path/filepath"
	"testing"
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
