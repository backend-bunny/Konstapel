package conformance

import (
	"path/filepath"
	"slices"
	"testing"
)

// Dirs lists the case directories under root (each holds a case.json).
func Dirs(root string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(root, "*", CaseFile))
	if err != nil {
		return nil, err
	}
	dirs := make([]string, len(files))
	for i, f := range files {
		dirs[i] = filepath.Dir(f)
	}
	slices.Sort(dirs)
	return dirs, nil
}

// Run verifies every case under root against the adapter, each as a
// subtest. With update, a case whose invariants hold has its expected.json
// rewritten instead of compared; review the diff before committing it.
func Run(t *testing.T, a Adapter, root string, update bool) {
	t.Helper()
	dirs, err := Dirs(root)
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no conformance cases under %s: %v", root, err)
	}
	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			c, want, err := Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			if update {
				got, errs := Check(a, c)
				for _, e := range errs {
					t.Error(e)
				}
				if len(errs) == 0 {
					if err := Write(dir, got); err != nil {
						t.Fatal(err)
					}
				}
				return
			}
			if want == nil {
				t.Fatalf("%s has no %s; run with -update after reviewing the case", dir, ExpectedFile)
			}
			for _, e := range Verify(a, c, *want) {
				t.Error(e)
			}
		})
	}
}
