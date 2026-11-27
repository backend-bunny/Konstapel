package c2p_test

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider/c2p"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
)

// A continuous package retains the evaluation made at closure, not every
// input of that evaluation (add-assessment-provider-contract 4.5). Replay
// therefore retrieves and validates the closure evaluation; it is not a
// semantic re-evaluation of frozen inputs. These tests pin the two
// missing inputs of kyverno.Evaluate, so the gap cannot close or widen
// silently:
//
//   - EvaluationInput.Boundaries, the host's continuity boundaries: a
//     result evaluated before the run's window but after the workload's
//     boundary is attributable at closure, and rejected by any
//     re-evaluation of the package, which can only fall back to the
//     window start.
//   - EvaluationInput.MaxEvidenceAge, the binding's evidence-age limit:
//     the package does not say which limit the closure used, and a
//     different one gives a different evaluation.
//
// The evaluation time is not missing: it is the capture's Window.Closed.
func TestPackageLacksReevaluationInputs(t *testing.T) {
	c := savedV2(t)
	// A run that began after its workloads' reports were evaluated, on a
	// host that had observed every workload continuously since before
	// those evaluations: the usual scheduled run against background
	// reports.
	since := c.Window.Started
	c.Window.Started = c.Window.Closed.Add(-time.Second)
	var boundaries []collector.Boundary
	for _, w := range c.Workloads {
		boundaries = append(boundaries, collector.Boundary{WorkloadUID: w.UID, StateSHA256: w.StateSHA256, Since: since})
	}
	closure, err := kyverno.Evaluate(kyverno.EvaluationInput{Capture: c, Boundaries: boundaries, MaxEvidenceAge: maxEvidenceAge}, c.Window.Closed)
	if err != nil {
		t.Fatal(err)
	}
	if closure.Evidence.Attributable == 0 {
		t.Fatalf("the closure evaluation attributes nothing: %+v", closure.Evidence)
	}
	e := exportSnapshot(t, c, closure)

	t.Run("no package file records boundaries or the evidence-age limit", func(t *testing.T) {
		keys := packageKeys(t, e.dir)
		if len(keys) == 0 {
			t.Fatal("no JSON keys read from the package")
		}
		// collector.Boundary serializes as workloadUID, stateSha256 and
		// since; "since" is the only key it adds to a capture's.
		for _, k := range []string{"since", "boundaries", "maxEvidenceAge", "maxevidenceage"} {
			if keys[k] {
				t.Errorf("the package now records %q: revisit the re-evaluation gap", k)
			}
		}
	})

	t.Run("re-evaluating the package without boundaries differs", func(t *testing.T) {
		retained := readRetained(t, e.dir)
		again, err := kyverno.Evaluate(kyverno.EvaluationInput{Capture: retained.Capture, MaxEvidenceAge: maxEvidenceAge}, retained.Capture.Window.Closed)
		if err != nil {
			t.Fatal(err)
		}
		if again.Evidence.Attributable >= closure.Evidence.Attributable || again.Evidence.Rejected == 0 {
			t.Fatalf("re-evaluation without boundaries matched the closure: %+v, closure %+v", again.Evidence, closure.Evidence)
		}
		// The closure boundary itself is retained and used: with the
		// host's boundaries, re-evaluation reproduces the closure.
		with, err := kyverno.Evaluate(kyverno.EvaluationInput{Capture: retained.Capture, Boundaries: boundaries, MaxEvidenceAge: maxEvidenceAge}, retained.Capture.Window.Closed)
		if err != nil {
			t.Fatal(err)
		}
		sameJSON(t, with, retained.Evaluation)
	})

	t.Run("re-evaluating the package with another evidence-age limit differs", func(t *testing.T) {
		retained := readRetained(t, e.dir)
		shorter, err := kyverno.Evaluate(kyverno.EvaluationInput{Capture: retained.Capture, Boundaries: boundaries, MaxEvidenceAge: time.Second}, retained.Capture.Window.Closed)
		if err != nil {
			t.Fatal(err)
		}
		if shorter.Evidence.Attributable >= closure.Evidence.Attributable {
			t.Fatalf("a shorter limit did not change the evaluation: %+v, closure %+v", shorter.Evidence, closure.Evidence)
		}
	})

	t.Run("replay converts the retained closure evaluation", func(t *testing.T) {
		p := &c2p.Provider{}
		if err := p.Configure(context.Background(), config(t, filepath.Join(e.dir, collector.CaptureFile))); err != nil {
			t.Fatal(err)
		}
		direct := &collector.SnapshotProvider{Snapshot: collector.Snapshot{Capture: c, Evaluation: closure}}
		if err := direct.Configure(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		sameJSON(t, aggregate(t, e.input, p), aggregate(t, e.input, direct))
	})
}

func readRetained(t *testing.T, dir string) collector.Snapshot {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, collector.CaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := collector.ReadCapture(raw, installed.Registry())
	if err != nil {
		t.Fatal(err)
	}
	ev, err := os.ReadFile(filepath.Join(dir, collector.EvaluationFile))
	if err != nil {
		t.Fatal(err)
	}
	s, err := collector.ReadSnapshot(doc, installed.Registry(), ev)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// packageKeys is every object key of every JSON file in the package.
func packageKeys(t *testing.T, dir string) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, x := range v {
				keys[k] = true
				walk(x)
			}
		case []any:
			for _, x := range v {
				walk(x)
			}
		}
	}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var v any
		if json.Unmarshal(raw, &v) == nil {
			walk(v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return keys
}
