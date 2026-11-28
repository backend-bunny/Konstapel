package c2p_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/c2p"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
)

// Package inputs for semantic re-evaluation (add-assessment-provider-contract
// 4.5). kyverno.Evaluate needs two inputs a capture does not hold: the
// host's continuity boundaries (EvaluationInput.Boundaries) and the
// binding's evidence-age limit (EvaluationInput.MaxEvidenceAge); the time
// is the capture's Window.Closed. A package written with its frozen inputs
// (Kyverno payload 3) re-evaluates from its files alone to its closure
// evaluation. A package without them (every earlier package) still has its
// stored evaluation retrieved and converted, and reports re-evaluation as
// unavailable.

// backgroundRun is a run that began after its workloads' reports were
// evaluated, on a host that had observed every workload continuously since
// before those evaluations: the usual scheduled run against background
// reports. Its closure evaluation attributes them only through the
// boundaries.
func backgroundRun(t *testing.T) (collector.CaptureV2, []collector.Boundary) {
	t.Helper()
	c := savedV2(t)
	since := c.Window.Started
	c.Window.Started = c.Window.Closed.Add(-time.Second)
	var boundaries []collector.Boundary
	for _, w := range c.Workloads {
		boundaries = append(boundaries, collector.Boundary{WorkloadUID: w.UID, StateSHA256: w.StateSHA256, Since: since})
	}
	return c, boundaries
}

// closeRun evaluates a capture at its closure as a closing run does.
func closeRun(t *testing.T, c collector.CaptureV2, boundaries []collector.Boundary, age time.Duration) collector.Evaluation {
	t.Helper()
	ev, err := kyverno.Evaluate(kyverno.EvaluationInput{Capture: c, Boundaries: boundaries, MaxEvidenceAge: age}, c.Window.Closed)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// exportFrozen exports the closure with its frozen inputs.
func exportFrozen(t *testing.T, c collector.CaptureV2, boundaries []collector.Boundary, age time.Duration) (exported, collector.Evaluation) {
	t.Helper()
	closure := closeRun(t, c, boundaries, age)
	in := collector.FreezeEvaluationInputs(age, boundaries)
	return exportWith(t, c, closure, &in), closure
}

// replayed replays a package that records its inputs and checks that the
// re-evaluation and the stored evaluation are both the closure
// evaluation, observation by observation.
func replayed(t *testing.T, dir string, closure collector.Evaluation) c2p.Replay {
	t.Helper()
	r, err := c2p.ReplayPackage(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != c2p.Recomputed || r.Recomputed == nil || r.Inputs == nil || r.Reason != nil {
		t.Fatalf("not re-evaluated: %+v", r)
	}
	sameNormalized(t, *r.Recomputed, closure)
	sameNormalized(t, r.Stored, closure)
	if r.EvaluatedAt.IsZero() {
		t.Fatal("no recorded closure")
	}
	return r
}

// sameNormalized requires equal normalized results: per observation its
// state, outcome, attribution (report and result), evaluation time and
// applicability, and equal evidence and outcome summaries. The whole
// evaluation must also be equal.
func sameNormalized(t *testing.T, got, want collector.Evaluation) {
	t.Helper()
	if got.Evidence != want.Evidence || got.Outcomes != want.Outcomes || len(got.Observations) != len(want.Observations) {
		t.Fatalf("summaries differ: %+v %+v, want %+v %+v", got.Evidence, got.Outcomes, want.Evidence, want.Outcomes)
	}
	for i, o := range got.Observations {
		w := want.Observations[i]
		if o.Key != w.Key || o.State != w.State || o.Outcome != w.Outcome || o.Report != w.Report || o.Index != w.Index ||
			o.Applicability != w.Applicability || (o.Evaluated == nil) != (w.Evaluated == nil) || (o.Evaluated != nil && !o.Evaluated.Equal(*w.Evaluated)) {
			t.Fatalf("observation %d differs: %+v, want %+v", i, o, w)
		}
	}
	if !collector.SameEvaluation(got, want) {
		t.Fatal("the evaluations differ beyond their normalized results")
	}
}

// The positive check of the former re-evaluation gap: a package records
// both inputs, re-evaluates from its files alone to its closure evaluation
// and converts that stored evaluation exactly as before.
func TestPackageRecordsReevaluationInputs(t *testing.T) {
	c, boundaries := backgroundRun(t)
	e, closure := exportFrozen(t, c, boundaries, maxEvidenceAge)
	if closure.Evidence.Attributable == 0 {
		t.Fatalf("the closure evaluation attributes nothing: %+v", closure.Evidence)
	}
	keys := packageKeys(t, e.dir)
	for _, k := range []string{"evaluationInputs", "since", "boundaries", "maxEvidenceAge"} {
		if !keys[k] {
			t.Errorf("the package does not record %q", k)
		}
	}
	r := replayed(t, e.dir, closure)
	if r.Capture.PayloadVersion != collector.CaptureV3Version || r.Inputs.MaxEvidenceAge != maxEvidenceAge.String() || len(r.Inputs.Boundaries) != len(boundaries) {
		t.Fatalf("replay %s with %+v", r.Capture, r.Inputs)
	}
	report := r.Report()
	if report.Reevaluation.Status != c2p.Recomputed || report.Reevaluation.Equivalent == nil || !*report.Reevaluation.Equivalent ||
		*report.Reevaluation.Evidence != report.Stored.Evidence || report.Stored.Source != collector.EvaluationFile {
		t.Fatalf("report %+v", report)
	}
	// The boundaries matter: without them the reports are rejected.
	if without := closeRun(t, c, nil, maxEvidenceAge); without.Evidence.Attributable >= closure.Evidence.Attributable || without.Evidence.Rejected == 0 {
		t.Fatalf("the boundaries do not matter to this run: %+v", without.Evidence)
	}
	// Conversion is unchanged: the plugin converts the stored evaluation,
	// which is also the recomputed one.
	p := &c2p.Provider{}
	if err := p.Configure(context.Background(), config(t, filepath.Join(e.dir, collector.CaptureFile))); err != nil {
		t.Fatal(err)
	}
	recomputed := &collector.SnapshotProvider{Snapshot: collector.Snapshot{Capture: c, Evaluation: *r.Recomputed}}
	if err := recomputed.Configure(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	sameJSON(t, aggregate(t, e.input, p), aggregate(t, e.input, recomputed))
}

// A package written without the inputs (every package before payload 3)
// keeps its bytes' meaning: no file records them, replay retrieves and
// converts its stored evaluation, and re-evaluation is reported as
// unavailable rather than recomputed with inputs from elsewhere.
func TestEarlierPackagesReevaluationUnavailable(t *testing.T) {
	c, boundaries := backgroundRun(t)
	closure := closeRun(t, c, boundaries, maxEvidenceAge)
	e := exportSnapshot(t, c, closure)
	keys := packageKeys(t, e.dir)
	if len(keys) == 0 {
		t.Fatal("no JSON keys read from the package")
	}
	for _, k := range []string{"evaluationInputs", "since", "boundaries", "maxEvidenceAge"} {
		if keys[k] {
			t.Errorf("an earlier package records %q", k)
		}
	}
	raw, err := os.ReadFile(filepath.Join(e.dir, collector.CaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := collector.CaptureVersion(raw); err != nil || v != collector.CaptureV2Version {
		t.Fatalf("the capture is no longer the version 2 document: %d %v", v, err)
	}
	r, err := c2p.ReplayPackage(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != c2p.Unavailable || r.Recomputed != nil || r.Inputs != nil || !errors.Is(r.Reason, collector.ErrReevaluationUnavailable) {
		t.Fatalf("replay %+v", r)
	}
	sameNormalized(t, r.Stored, closure)
	b, err := json.Marshal(r.Report())
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Stored       map[string]any `json:"stored"`
		Reevaluation map[string]any `json:"reevaluation"`
	}
	if err := json.Unmarshal(b, &report); err != nil {
		t.Fatal(err)
	}
	reason, _ := report.Reevaluation["reason"].(string)
	if report.Reevaluation["status"] != "Unavailable" || report.Reevaluation["evidence"] != nil || report.Reevaluation["outcomes"] != nil ||
		!strings.Contains(reason, "retrieved, not recomputed") || report.Stored["evidence"] == nil {
		t.Fatalf("the report does not keep the stored evaluation apart from a recomputation: %s", b)
	}
	p := &c2p.Provider{}
	if err := p.Configure(context.Background(), config(t, filepath.Join(e.dir, collector.CaptureFile))); err != nil {
		t.Fatal(err)
	}
	direct := &collector.SnapshotProvider{Snapshot: collector.Snapshot{Capture: c, Evaluation: closure}}
	if err := direct.Configure(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	sameJSON(t, aggregate(t, e.input, p), aggregate(t, e.input, direct))
}

// Freshness: evidence older than the frozen limit at closure is rejected
// at closure and on replay. The binding's limit changing after the run
// changes nothing: replay takes no limit and uses the frozen one, while
// evaluating with the new setting would give another result.
func TestReplayUsesTheFrozenEvidenceAge(t *testing.T) {
	c := savedV2(t)
	full := closeRun(t, c, nil, maxEvidenceAge)
	var newest, oldest time.Time
	for _, o := range full.Observations {
		if o.Evaluated == nil {
			continue
		}
		if newest.IsZero() || o.Evaluated.After(newest) {
			newest = *o.Evaluated
		}
		if oldest.IsZero() || o.Evaluated.Before(oldest) {
			oldest = *o.Evaluated
		}
	}
	if oldest.IsZero() {
		t.Fatal("nothing attributable in the saved capture")
	}
	// A limit that the newest evidence meets and the oldest exceeds when
	// the reports differ in age; otherwise one that every report exceeds.
	frozen := c.Window.Closed.Sub(newest) - time.Second
	if newest.After(oldest) {
		frozen = c.Window.Closed.Sub(newest) + newest.Sub(oldest)/2
	}
	if frozen <= 0 {
		t.Fatalf("the saved capture closed at its newest evidence: %s", newest)
	}
	frozen = frozen.Truncate(time.Second)
	e, closure := exportFrozen(t, c, nil, frozen)
	if closure.Evidence.Rejected == 0 {
		t.Fatalf("no evidence is older than the frozen limit %s: %+v", frozen, closure.Evidence)
	}
	for _, o := range closure.Observations {
		if o.State == collector.Rejected && !strings.Contains(strings.Join(o.Reasons, ";"), "exceeds maxEvidenceAge "+frozen.String()) {
			t.Fatalf("rejected for another reason than its age: %+v", o)
		}
	}
	r := replayed(t, e.dir, closure)
	if r.Inputs.MaxEvidenceAge != frozen.String() {
		t.Fatalf("replay used %s, frozen %s", r.Inputs.MaxEvidenceAge, frozen)
	}
	// The binding now says 2h (the chart default): an evaluation with the
	// current setting differs, the replay does not follow it.
	current := closeRun(t, c, nil, maxEvidenceAge)
	if collector.SameEvaluation(current, closure) {
		t.Fatal("the binding's new limit does not change this run's evaluation")
	}
	if collector.SameEvaluation(*r.Recomputed, current) {
		t.Fatal("replay used the binding's current limit")
	}
	// Nor does replay read the clock: a replay long after closure is the
	// same, while evaluating at the replay time would expire everything.
	if later := closeRunAt(t, c, nil, frozen, c.Window.Closed.Add(24*time.Hour)); later.Evidence.Attributable != 0 {
		t.Fatalf("a later evaluation time did not expire the evidence: %+v", later.Evidence)
	}
}

func closeRunAt(t *testing.T, c collector.CaptureV2, boundaries []collector.Boundary, age time.Duration, at time.Time) collector.Evaluation {
	t.Helper()
	ev, err := kyverno.Evaluate(kyverno.EvaluationInput{Capture: c, Boundaries: boundaries, MaxEvidenceAge: age}, at)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// Continuity: one workload changed during the window (its observations are
// unresolved and the host holds no boundary for the frozen state), one was
// first observed in its frozen state only at the window start (its earlier
// reports are rejected), and the others were observed continuously from
// before their reports (attributable). Replay reproduces each from the
// recorded boundaries; it never reconstructs continuity.
func TestReplayUsesTheFrozenContinuity(t *testing.T) {
	c, boundaries := backgroundRun(t)
	if len(c.Workloads) < 3 {
		t.Fatalf("the saved capture has %d workloads", len(c.Workloads))
	}
	changed, fresh := c.Workloads[0], c.Workloads[1]
	next := changed
	next.StateSHA256 = strings.Repeat("e", 64)
	collector.NewTracker(&c).Workload(c.Window.Started, next, false)
	var recorded []collector.Boundary
	for _, b := range boundaries {
		switch b.WorkloadUID {
		case changed.UID:
			// The host's tracker follows the new state; the frozen one has
			// no boundary any more.
		case fresh.UID:
			b.Since = c.Window.Started
			recorded = append(recorded, b)
		default:
			recorded = append(recorded, b)
		}
	}
	e, closure := exportFrozen(t, c, recorded, maxEvidenceAge)
	states := map[string]map[collector.ObservationState]int{}
	byKey := map[string]string{}
	for _, x := range c.Expected {
		byKey[x.Key()] = x.Workload.UID
	}
	for _, o := range closure.Observations {
		uid := byKey[o.Key]
		if states[uid] == nil {
			states[uid] = map[collector.ObservationState]int{}
		}
		states[uid][o.State]++
	}
	if len(states[changed.UID]) != 1 || states[changed.UID][collector.Unresolved] == 0 {
		t.Errorf("the changed workload: %v, want only unresolved", states[changed.UID])
	}
	// Evidence of the freshly observed state predates its boundary.
	if states[fresh.UID][collector.Attributable] != 0 || states[fresh.UID][collector.Rejected] == 0 {
		t.Errorf("the freshly observed workload: %v, want rejected and nothing attributable", states[fresh.UID])
	}
	if closure.Evidence.Attributable == 0 {
		t.Fatalf("no continuously observed workload is attributable: %+v", closure.Evidence)
	}
	replayed(t, e.dir, closure)
	// Reconstructed continuity (every workload observed since before the
	// window) would give another evaluation.
	reconstructed := closeRun(t, c, boundaries, maxEvidenceAge)
	if collector.SameEvaluation(reconstructed, closure) {
		t.Fatal("the recorded boundaries do not matter to this run")
	}
}

// Source removal: the package alone is replayed. It is copied away from
// the content root it was exported from, any cluster or proxy request
// would reach a trap, and the replay still re-evaluates it.
func TestReplayNeedsOnlyThePackage(t *testing.T) {
	c, boundaries := backgroundRun(t)
	e, closure := exportFrozen(t, c, boundaries, maxEvidenceAge)
	moved := filepath.Join(t.TempDir(), "retained")
	copyTree(t, e.dir, moved)
	if err := os.RemoveAll(e.dir); err != nil {
		t.Fatal(err)
	}
	tr := newTrap(t)
	t.Chdir(t.TempDir())
	replayed(t, moved, closure)
	if n := tr.hits.Load(); n != 0 {
		t.Fatalf("replay made %d network requests", n)
	}
	// An altered package is refused, not re-evaluated.
	path := filepath.Join(moved, collector.EvaluationFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, append(raw, ' '))
	if _, err := c2p.ReplayPackage(moved); err == nil {
		t.Fatal("an altered package was replayed")
	}
}

// The production registry reads the payload 3 a package records; a
// registry of the builds before it refuses the same bytes.
func TestPayload3IsReadOnlyByItsReaders(t *testing.T) {
	c, boundaries := backgroundRun(t)
	e, _ := exportFrozen(t, c, boundaries, maxEvidenceAge)
	raw, err := os.ReadFile(filepath.Join(e.dir, collector.CaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.ReadCapture(raw, installed.Registry()); err != nil {
		t.Fatal(err)
	}
	if _, err := collector.ReadCapture(raw, earlierRegistry(t)); !errors.Is(err, collector.ErrUnsupportedCapture) {
		t.Fatalf("the earlier registry read a payload 3: %v", err)
	}
}

// earlierRegistry is the production registry of the builds before payload
// 3: the same Kyverno descriptor reading payloads 1 and 2 only.
func earlierRegistry(t *testing.T) *provider.Registry {
	t.Helper()
	d := kyverno.Descriptor()
	d.Capture = provider.CaptureCompatibility{Write: collector.CaptureV2Version, Read: []int{1, collector.CaptureV2Version}}
	r, err := provider.New(kyverno.Contract, d)
	if err != nil {
		t.Fatal(err)
	}
	return r
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

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(to, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}
