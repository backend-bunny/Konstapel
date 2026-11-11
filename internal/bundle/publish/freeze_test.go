package publish

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type failRunner struct{ passRunner }

func (*failRunner) Run(context.Context, string, []string) error { return errors.New("2 tests failed") }

func TestFreezeRecordsTheFixturesThatRan(t *testing.T) {
	dir := frozenLayout(t, revA, testTime)
	r := &passRunner{}
	in := freezeInput()
	in.Runner = r
	f, err := Freeze(context.Background(), dir, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.ran) != 1 || len(r.ran[0]) != 3 {
		t.Fatalf("ran %v, want the three fixture directories", r.ran)
	}
	var paths []string
	for _, x := range f.Record.Tests.Files {
		paths = append(paths, x.Path)
	}
	if len(paths) != 3 || !strings.HasSuffix(paths[0], "/.kyverno-test-controllers/kyverno-test.yaml") {
		t.Fatalf("test files %v", paths)
	}
	if f.Record.ContentDigest != f.Descriptor.ContentDigest() || f.Record.Source.Commit != revA ||
		f.Record.Definition.Path != "bundles/konstapel-privileged-containers/definition.json" {
		t.Fatalf("record %+v", f.Record)
	}
	if got := f.Record.Tools; len(got) != 2 || got[0].Name != "go" || got[1].Name != "kyverno" {
		t.Fatalf("tools %+v", got)
	}
	// Deterministic: the same inputs give the same record bytes.
	dir2 := frozenLayout(t, revA, testTime)
	g, err := Freeze(context.Background(), dir2, freezeInput())
	if err != nil {
		t.Fatal(err)
	}
	if string(g.RecordJSON) != string(f.RecordJSON) {
		t.Fatal("record is not deterministic")
	}
	// Never replaced.
	if _, err := Freeze(context.Background(), dir, freezeInput()); !errors.Is(err, ErrFrozenInputs) {
		t.Fatalf("second freeze: %v", err)
	}
}

func TestFreezeRefuses(t *testing.T) {
	t.Run("failing fixtures", func(t *testing.T) {
		dir := frozenLayout(t, revA, testTime)
		in := freezeInput()
		in.Runner = &failRunner{}
		if _, err := Freeze(context.Background(), dir, in); err == nil || !strings.Contains(err.Error(), "not freezing") {
			t.Fatalf("got %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, RecordFile)); !os.IsNotExist(err) {
			t.Fatal("a record was written for failing fixtures")
		}
	})
	t.Run("tampered layout", func(t *testing.T) {
		dir := frozenLayout(t, revA, testTime)
		if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(`{"manifests":[]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Freeze(context.Background(), dir, freezeInput()); !errors.Is(err, ErrFrozenInputs) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad definition digest", func(t *testing.T) {
		in := freezeInput()
		in.DefinitionSHA256 = "nope"
		if _, err := Freeze(context.Background(), frozenLayout(t, revA, testTime), in); !errors.Is(err, ErrFrozenInputs) {
			t.Fatalf("got %v", err)
		}
	})
}

// Load accepts only a record bound to exactly the layout's bytes.
func TestLoadRejectsUnboundRecords(t *testing.T) {
	good := frozenAt(t, revA, testTime)
	other := frozenAt(t, revB, testTime)
	for _, tc := range []struct {
		name   string
		record func() []byte
	}{
		{"missing", nil},
		{"another bundle's record", func() []byte { return other.RecordJSON }},
		{"not canonical", func() []byte { return append(append([]byte(nil), good.RecordJSON...), '\n') }},
		{"unknown field", func() []byte {
			return []byte(strings.Replace(string(good.RecordJSON), `{"format"`, `{"extra":1,"format"`, 1))
		}},
		{"tests not passed", func() []byte {
			r := good.Record
			r.Tests.Result = "failed"
			return r.Canonical()
		}},
		{"test file not in the payload", func() []byte {
			r := good.Record
			r.Tests.Files = append([]FileDigest(nil), r.Tests.Files...)
			r.Tests.Files[0].Path = "tests/zzz/kyverno-test.yaml"
			return r.Canonical()
		}},
		{"test file digest differs", func() []byte {
			r := good.Record
			r.Tests.Files = append([]FileDigest(nil), r.Tests.Files...)
			r.Tests.Files[0].SHA256 = strings.Repeat("0", 64)
			return r.Canonical()
		}},
		{"content digest differs", func() []byte {
			r := good.Record
			r.ContentDigest = "sha256:" + strings.Repeat("0", 64)
			return r.Canonical()
		}},
		{"other commit", func() []byte {
			r := good.Record
			r.Source.Commit = revB
			return r.Canonical()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := frozenLayout(t, revA, testTime)
			if tc.record != nil {
				if err := os.WriteFile(filepath.Join(dir, RecordFile), tc.record(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Load(dir); !errors.Is(err, ErrFrozenInputs) {
				t.Fatalf("got %v", err)
			}
		})
	}
	t.Run("valid", func(t *testing.T) {
		dir := frozenLayout(t, revA, testTime)
		if err := os.WriteFile(filepath.Join(dir, RecordFile), good.RecordJSON, 0o644); err != nil {
			t.Fatal(err)
		}
		f, err := Load(dir)
		if err != nil || f.ManifestDigest != good.ManifestDigest {
			t.Fatalf("got %v", err)
		}
	})
}

// The real pinned kyverno CLI passes the official bundle's fixtures against
// the unpacked frozen layer (run through Devbox; skipped without kyverno).
func TestFreezeWithKyverno(t *testing.T) {
	if _, err := exec.LookPath("kyverno"); err != nil {
		t.Skip("kyverno CLI not on PATH; run through devbox")
	}
	dir := frozenLayout(t, revA, testTime)
	in := freezeInput()
	in.Runner = Kyverno{}
	f, err := Freeze(context.Background(), dir, in)
	if err != nil {
		t.Fatal(err)
	}
	if f.Record.Tools[1].Name != "kyverno" || !strings.HasPrefix(f.Record.Tools[1].Version, "v1.") {
		t.Fatalf("tools %+v", f.Record.Tools)
	}
}
