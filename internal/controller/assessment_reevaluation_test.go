package controller

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider/c2p"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Package inputs for semantic re-evaluation (add-assessment-provider-contract
// 4.5): a closing run freezes the evaluation inputs it was given with its
// closure, and its package records them once the writer is enabled.

// crashAtPublishing fails the run status update that would record an
// exported closure, as a controller crash between export and that update
// would: closed.json and the staged package exist, the run is still
// Collecting.
type crashAtPublishing struct{ client.Client }

func (c crashAtPublishing) Status() client.SubResourceWriter {
	return crashWriter{c.Client.Status()}
}

type crashWriter struct{ client.SubResourceWriter }

func (w crashWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if r, ok := obj.(*v1alpha1.AssessmentRun); ok && r.Status.Phase == v1alpha1.RunPublishing {
		return errors.New("crashed before recording the closure")
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

// backgroundRunEnv starts a run two minutes after the controller first
// observed the workload, with a report evaluated in between: the report
// is attributable at closure only through the host's continuity boundary.
// The binding's evidence-age limit is 30m.
func backgroundRunEnv(t *testing.T, write int) (*runEnv, string) {
	t.Helper()
	b := shortTimeout(epochBinding("audit-prod", production))
	b.Spec.Assessment.MaxEvidenceAge = "30m"
	e := newRunEnv(t, b)
	e.rr.Instance = "process-1"
	e.rr.CaptureWrite = write
	e.deliver("audit-prod")
	e.assess("audit-prod") // observes pod-1 at a0
	e.report("prod", "pod-1", e.enginePolicy(), "fail", a0.Add(time.Minute))
	e.now = a0.Add(2 * time.Minute)
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	if r := e.run(name); r.Status.Window == nil || !r.Status.Window.Started.Time.Equal(e.now) {
		t.Fatalf("run window %+v", r.Status.Window)
	}
	return e, name
}

// published extracts the run's published package and replays it.
func (e *runEnv) published(name string) (string, c2p.Replay) {
	e.t.Helper()
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted {
		e.t.Fatalf("run %s: %+v", r.Status.Phase, r.Status.Conditions)
	}
	rc, _, err := e.pub.Open(context.Background(), e.ref(r))
	if err != nil {
		e.t.Fatal(err)
	}
	defer rc.Close()
	dir := filepath.Join(e.t.TempDir(), "package")
	if err := publication.Extract(rc, dir); err != nil {
		e.t.Fatal(err)
	}
	replay, err := c2p.ReplayPackage(dir)
	if err != nil {
		e.t.Fatal(err)
	}
	return dir, replay
}

// The closure freezes the binding's limit and the continuity boundaries it
// evaluated with. A crash after export, a binding edited afterwards and a
// restarted controller with an empty tracker change nothing: the package
// is exported again from closed.json, records the frozen inputs, and
// re-evaluates from them alone to the closure evaluation.
func TestRunFreezesEvaluationInputsAtClosure(t *testing.T) {
	e, name := backgroundRunEnv(t, collector.CaptureV3Version)
	e.now = a0.Add(2*time.Minute + 5*time.Minute + time.Second)
	e.rr.Client = crashAtPublishing{e.c}
	if _, err := e.rr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err == nil {
		t.Fatal("the crash was not reached")
	}
	run := e.run(name)
	var frozen closedRun
	raw, err := os.ReadFile(filepath.Join(e.rr.staging(run), "closed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &frozen); err != nil {
		t.Fatal(err)
	}
	if frozen.Inputs == nil || frozen.Inputs.MaxEvidenceAge != "30m0s" || len(frozen.Inputs.Boundaries) != 1 ||
		frozen.Inputs.Boundaries[0].WorkloadUID != "pod-1" || !frozen.Inputs.Boundaries[0].Since.Equal(a0) {
		t.Fatalf("closed.json inputs %+v", frozen.Inputs)
	}
	if frozen.Evaluation.Evidence.Attributable != 1 || frozen.Evaluation.Outcomes.Fail != 1 {
		t.Fatalf("the closure did not attribute through the boundary: %+v", frozen.Evaluation.Evidence)
	}

	// After the run: the binding's limit changes and the controller
	// restarts without its continuity tracker.
	b := e.binding("audit-prod")
	b.Spec.Assessment.MaxEvidenceAge = "2h"
	if err := e.c.Update(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	e.restart()
	e.rr.CaptureWrite = collector.CaptureV3Version
	e.now = e.now.Add(time.Hour)
	e.step(name)
	e.step(name)
	dir, replay := e.published(name)
	if replay.Status != c2p.Recomputed || replay.Capture.PayloadVersion != collector.CaptureV3Version {
		t.Fatalf("replay %s %s", replay.Status, replay.Capture)
	}
	if replay.Inputs.MaxEvidenceAge != "30m0s" || len(replay.Inputs.Boundaries) != 1 || !replay.Inputs.Boundaries[0].Since.Equal(a0) {
		t.Fatalf("the package records %+v, not the inputs frozen at closure", replay.Inputs)
	}
	if !collector.SameEvaluation(*replay.Recomputed, frozen.Evaluation) || !collector.SameEvaluation(replay.Stored, frozen.Evaluation) {
		t.Fatal("the package does not re-evaluate to the closure evaluation")
	}
	if s := e.run(name).Status.Summary; s == nil || s.Evidence.Attributable != 1 || s.Outcomes.Fail != 1 {
		t.Fatalf("summary %+v", s)
	}
	if !replay.EvaluatedAt.Equal(frozen.Capture.Window.Closed) {
		t.Fatalf("evaluated at %s, closed %s", replay.EvaluatedAt, frozen.Capture.Window.Closed)
	}
	// What the current settings would give instead: the restarted host
	// has no boundary for the pod, so the report would be rejected.
	current, err := frozen.Capture.Evaluate(nil, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if current.Evidence.Attributable != 0 || current.Evidence.Rejected != 1 {
		t.Fatalf("the current settings give the same evaluation: %+v", current.Evidence)
	}
	if _, err := os.Stat(filepath.Join(dir, collector.CaptureFile)); err != nil {
		t.Fatal(err)
	}
}

// Until the writer is enabled (the installed descriptor writes payload 2),
// packages are the version 2 document exactly as before: re-evaluation is
// unavailable and their stored evaluation is the closure's. The closure
// still freezes its inputs in staging.
func TestRunWritesPayload2UntilTheWriterIsEnabled(t *testing.T) {
	e, name := backgroundRunEnv(t, 0)
	e.now = a0.Add(2*time.Minute + 5*time.Minute + time.Second)
	e.step(name)
	e.step(name)
	dir, replay := e.published(name)
	if replay.Status != c2p.Unavailable || !errors.Is(replay.Reason, collector.ErrReevaluationUnavailable) {
		t.Fatalf("replay %+v", replay)
	}
	raw, err := os.ReadFile(filepath.Join(dir, collector.CaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := collector.CaptureVersion(raw); err != nil || v != collector.CaptureV2Version {
		t.Fatalf("capture version %d %v", v, err)
	}
	if replay.Stored.Evidence.Attributable != 1 {
		t.Fatalf("stored %+v", replay.Stored.Evidence)
	}
}

// A closure staged without inputs (before they were recorded) is exported
// without them even when the writer is enabled: the limit and boundaries
// are never read again from the binding or the tracker.
func TestClosureWithoutInputsIsNotCompletedFromCurrentState(t *testing.T) {
	e, name := backgroundRunEnv(t, collector.CaptureV3Version)
	e.now = a0.Add(2*time.Minute + 5*time.Minute + time.Second)
	e.rr.Client = crashAtPublishing{e.c}
	if _, err := e.rr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err == nil {
		t.Fatal("the crash was not reached")
	}
	path := filepath.Join(e.rr.staging(e.run(name)), "closed.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var staged map[string]json.RawMessage
	if err := json.Unmarshal(raw, &staged); err != nil {
		t.Fatal(err)
	}
	delete(staged, "inputs")
	b, _ := json.Marshal(staged)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	e.rr.Client = e.c
	e.step(name)
	e.step(name)
	_, replay := e.published(name)
	if replay.Status != c2p.Unavailable || replay.Capture.PayloadVersion != collector.CaptureV2Version {
		t.Fatalf("a closure without inputs was completed: %s %s", replay.Status, replay.Capture)
	}
}
