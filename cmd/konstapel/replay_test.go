package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// replayPackage exports the saved capture's closure, with its frozen
// evaluation inputs when frozen is set.
func replayPackage(t *testing.T, frozen bool) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "testdata/assessments/kyverno-1.19.2-background/capture.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := collector.ReadCapture(raw, installed.Registry())
	if err != nil {
		t.Fatal(err)
	}
	c, err := doc.V2()
	if err != nil {
		t.Fatal(err)
	}
	const age = 2 * time.Hour
	ev, err := kyverno.Evaluate(kyverno.EvaluationInput{Capture: c, MaxEvidenceAge: age}, c.Window.Closed)
	if err != nil {
		t.Fatal(err)
	}
	var inputs *collector.EvaluationInputs
	if frozen {
		in := collector.FreezeEvaluationInputs(age, []collector.Boundary{})
		inputs = &in
	}
	ns := []string{}
	for _, s := range c.Subjects {
		if !slices.Contains(ns, string(s.NamespaceUID)) {
			ns = append(ns, string(s.NamespaceUID))
		}
	}
	run := publication.RunRef{ClusterID: c.Cluster, BindingUID: "binding-uid", RunUID: "run-uid"}
	out := filepath.Join(t.TempDir(), "package")
	if _, err := collector.Export(context.Background(), collector.ExportRequest{Root: root, Out: out, Run: run,
		Scope:                publication.Scope{Kind: publication.ScopeBinding, ClusterID: c.Cluster, BindingUID: run.BindingUID, NamespaceUIDs: ns, Revision: "scope-1"},
		BindingConfiguration: "binding-config-1", Capture: c, Evaluation: ev, Inputs: inputs}); err != nil {
		t.Fatal(err)
	}
	return out
}

// konstapel replay reports the stored evaluation and the re-evaluation
// apart, and its exit status says which one it has: 0 re-evaluated, 2
// unavailable (stored only), 1 failed.
func TestReplayCommandExitStatuses(t *testing.T) {
	for name, tc := range map[string]struct {
		frozen bool
		code   int
		status string
	}{
		"frozen inputs":   {true, exitReplayRecomputed, "Recomputed"},
		"earlier package": {false, exitReplayUnavailable, "Unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := dispatch(context.Background(), []string{"replay", "--package", replayPackage(t, tc.frozen)}, nil, &stdout, &stderr)
			if code != tc.code {
				t.Fatalf("exit %d, want %d: %s", code, tc.code, stderr.String())
			}
			var report struct {
				Stored struct {
					Source   string          `json:"source"`
					Evidence json.RawMessage `json:"evidence"`
				} `json:"stored"`
				Reevaluation struct {
					Status     string          `json:"status"`
					Reason     string          `json:"reason"`
					Equivalent *bool           `json:"equivalent"`
					Evidence   json.RawMessage `json:"evidence"`
				} `json:"reevaluation"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.Stored.Source != collector.EvaluationFile || report.Stored.Evidence == nil || report.Reevaluation.Status != tc.status {
				t.Fatalf("report %s", stdout.String())
			}
			if tc.frozen && (report.Reevaluation.Equivalent == nil || !*report.Reevaluation.Equivalent || !bytes.Equal(report.Reevaluation.Evidence, report.Stored.Evidence)) {
				t.Fatalf("not equivalent: %s", stdout.String())
			}
			if !tc.frozen && (report.Reevaluation.Evidence != nil || !strings.Contains(report.Reevaluation.Reason, "re-evaluation unavailable")) {
				t.Fatalf("an unavailable re-evaluation reports results: %s", stdout.String())
			}
		})
	}
	var stdout, stderr bytes.Buffer
	if code := dispatch(context.Background(), []string{"replay"}, nil, &stdout, &stderr); code != exitReplayFailed || !strings.Contains(stderr.String(), "Usage: konstapel replay") {
		t.Fatalf("no package: exit %d %s", code, stderr.String())
	}
	if code := dispatch(context.Background(), []string{"replay", "--package", t.TempDir()}, nil, &stdout, &stderr); code != exitReplayFailed {
		t.Fatalf("an empty directory: exit %d", code)
	}
}
