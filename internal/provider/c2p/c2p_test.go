package c2p_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oscal-compass/compliance-to-policy-go/v2/framework/actions"
	"github.com/oscal-compass/compliance-to-policy-go/v2/plugin"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
	"github.com/oscal-compass/oscal-sdk-go/extensions"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/c2p"
	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

const (
	// savedCapture is a capture the controller froze against Kyverno
	// 1.19.2 background reports: passes, failures and missing evidence.
	savedCapture = "testdata/assessments/kyverno-1.19.2-background/capture.json"
	// prototypeCapture is the prototype's version 1 capture.
	prototypeCapture = "testdata/capture.json"
	maxEvidenceAge   = 2 * time.Hour
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatal(err)
	}
	return dir
}

// exported is a continuous package and the frozen snapshot it was
// exported from.
type exported struct {
	dir   string
	snap  collector.Snapshot
	input *actions.InputContext
}

// exportSaved exports the saved capture, evaluated at its closure as a
// closing run evaluates it, as the controller's continuous export does.
func exportSaved(t *testing.T) exported {
	t.Helper()
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, savedCapture))
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
	ev, err := kyverno.Evaluate(kyverno.EvaluationInput{Capture: c, MaxEvidenceAge: maxEvidenceAge}, c.Window.Closed)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Outcomes.Fail == 0 || ev.Outcomes.Pass == 0 || ev.Evidence.Missing == 0 {
		t.Fatalf("the saved capture no longer covers passes, failures and missing evidence: %+v %+v", ev.Evidence, ev.Outcomes)
	}
	nsUIDs := []string{}
	var rules []string
	for _, s := range c.Subjects {
		if !slices.Contains(nsUIDs, string(s.NamespaceUID)) {
			nsUIDs = append(nsUIDs, string(s.NamespaceUID))
		}
	}
	for _, e := range c.Expected {
		if !slices.Contains(rules, e.Contribution.LogicalPolicy) {
			rules = append(rules, e.Contribution.LogicalPolicy)
		}
	}
	run := publication.RunRef{ClusterID: c.Cluster, BindingUID: "binding-uid", RunUID: "run-uid"}
	out := filepath.Join(t.TempDir(), "package")
	d, err := collector.Export(context.Background(), collector.ExportRequest{Root: root, Out: out, Run: run,
		Scope:                publication.Scope{Kind: publication.ScopeBinding, ClusterID: run.ClusterID, BindingUID: run.BindingUID, NamespaceUIDs: nsUIDs, Revision: "scope-1"},
		BindingConfiguration: "binding-config-1", Capture: c, Evaluation: ev})
	if err != nil {
		t.Fatal(err)
	}
	if d.PackageKind != publication.KindAssessment {
		t.Fatalf("package %s: %+v", d.PackageKind, d.Diagnostic)
	}
	slices.Sort(rules)
	input, _, err := assessment.InputFrom(root, assessment.ComponentDefinitions, rules)
	if err != nil {
		t.Fatal(err)
	}
	return exported{dir: out, snap: collector.Snapshot{Capture: c, Evaluation: ev}, input: input}
}

// config is the C2P configuration konstapel passes the plugin.
func config(t *testing.T, capture string) map[string]string {
	return map[string]string{"root": repoRoot(t), "output": t.TempDir(), "namespace": "konstapel-acceptance", "owner": "konstapel-assessment", "action": "Deny", "capture": capture}
}

// aggregate dispatches GetResults through the C2P framework.
func aggregate(t *testing.T, input *actions.InputContext, p policy.Provider) []policy.PVPResult {
	t.Helper()
	results, err := actions.AggregateResults(context.Background(), input, map[plugin.ID]policy.Provider{plugin.ID(assessment.ProviderID): p})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("%d results", len(results))
	}
	return results
}

// subject is the normalized result of one subject: what an assessment
// claims, without generated identifiers or render times.
type subject struct {
	Result, State, Outcome, Reason string
	Evaluated                      string
}

func normalized(results []policy.PVPResult) map[string]subject {
	out := map[string]subject{}
	for _, r := range results {
		for _, o := range r.ObservationsByCheck {
			for _, s := range o.Subjects {
				n := subject{Result: s.Result.String(), Reason: strings.TrimSpace(s.Reason)}
				for _, p := range s.Props {
					switch p.Name {
					case "evidence-state":
						n.State = p.Value
					case "source-outcome":
						n.Outcome = p.Value
					}
				}
				if !s.EvaluatedOn.IsZero() {
					n.Evaluated = s.EvaluatedOn.UTC().Format(time.RFC3339Nano)
				}
				out[o.CheckID+" "+s.ResourceID] = n
			}
		}
	}
	return out
}

// packaged is the normalized results a package's assessment results record.
func packaged(t *testing.T, dir string) map[string]subject {
	t.Helper()
	var doc assessment.Object
	if err := assessment.Read(filepath.Join(dir, "assessment-results.json"), &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]subject{}
	results, _ := assessment.At(doc, "assessment-results", "results").([]any)
	for _, r := range results {
		obs, _ := assessment.Map(r)["observations"].([]any)
		for _, o := range obs {
			var check string
			props, _ := assessment.Map(o)["props"].([]any)
			for _, p := range props {
				if m := assessment.Map(p); m["name"] == "assessment-check-id" {
					check = assessment.Str(m["value"])
				}
			}
			subjects, _ := assessment.Map(o)["subjects"].([]any)
			for _, s := range subjects {
				var n subject
				var id string
				props, _ := assessment.Map(s)["props"].([]any)
				for _, p := range props {
					m := assessment.Map(p)
					v := assessment.Str(m["value"])
					switch m["name"] {
					case "resource-id":
						id = v
					case "result":
						n.Result = v
					case "evidence-state":
						n.State = v
					case "source-outcome":
						n.Outcome = v
					case "reason":
						n.Reason = v
					case "evaluated-on":
						at, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", v)
						if err != nil {
							t.Fatal(err)
						}
						n.Evaluated = at.UTC().Format(time.RFC3339Nano)
					}
				}
				out[check+" "+id] = n
			}
		}
	}
	return out
}

func sameJSON(t *testing.T, got, want any) {
	t.Helper()
	g, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	w, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(g) != string(w) {
		t.Fatalf("got\n%s\nwant\n%s", g, w)
	}
}

func sameSubjects(t *testing.T, got, want map[string]subject) {
	t.Helper()
	if len(got) == 0 || len(got) != len(want) {
		t.Fatalf("%d subjects, want %d", len(got), len(want))
	}
	for k, w := range want {
		if g, ok := got[k]; !ok || g != w {
			t.Errorf("%s: %+v, want %+v", k, g, w)
		}
	}
}

// The plugin's dispatch converts a retained package exactly as continuous
// export converted the controller's frozen snapshot: the same results,
// which are the results the package's OSCAL records.
func TestDispatchConvertsTheExportedSnapshot(t *testing.T) {
	e := exportSaved(t)
	direct := &collector.SnapshotProvider{Snapshot: e.snap}
	if err := direct.Configure(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	want := aggregate(t, e.input, direct)
	p := &c2p.Provider{}
	if err := p.Configure(context.Background(), config(t, filepath.Join(e.dir, collector.CaptureFile))); err != nil {
		t.Fatal(err)
	}
	got := aggregate(t, e.input, p)
	sameJSON(t, got, want)
	sameSubjects(t, packaged(t, e.dir), normalized(got))

	// An envelope of the same payload converts to the same results.
	payload, err := os.ReadFile(filepath.Join(e.dir, collector.CaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(collector.CaptureEnvelope{Version: collector.CaptureEnvelopeVersion, Provider: kyverno.Contract,
		PayloadVersion: collector.CaptureV2Version, EvaluatorVersion: kyverno.EvaluatorVersion, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, collector.CaptureFile), env)
	copyFile(t, filepath.Join(e.dir, collector.EvaluationFile), filepath.Join(dir, collector.EvaluationFile))
	if err := p.Configure(context.Background(), config(t, filepath.Join(dir, collector.CaptureFile))); err != nil {
		t.Fatal(err)
	}
	sameJSON(t, aggregate(t, e.input, p), want)
}

// Replay keeps the retained interpretation. Re-evaluating the retained
// capture at its recorded closure gives the retained evaluation; a later
// evaluation time changes freshness, and conversion still reads only the
// frozen evaluation, so the replay's wall clock rewrites nothing.
func TestReplayKeepsTheRetainedInterpretation(t *testing.T) {
	e := exportSaved(t)
	raw, err := os.ReadFile(filepath.Join(e.dir, collector.CaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := collector.ReadCapture(raw, installed.Registry())
	if err != nil {
		t.Fatal(err)
	}
	evRaw, err := os.ReadFile(filepath.Join(e.dir, collector.EvaluationFile))
	if err != nil {
		t.Fatal(err)
	}
	retained, err := collector.ReadSnapshot(doc, installed.Registry(), evRaw)
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, retained, e.snap)
	in := kyverno.EvaluationInput{Capture: retained.Capture, MaxEvidenceAge: maxEvidenceAge}
	again, err := kyverno.Evaluate(in, retained.Capture.Window.Closed)
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, again, retained.Evaluation)
	later, err := kyverno.Evaluate(in, retained.Capture.Window.Closed.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if later.Evidence.Attributable != 0 || retained.Evaluation.Evidence.Attributable == 0 {
		t.Fatalf("a later evaluation time did not change freshness: %+v %+v", later.Evidence, retained.Evaluation.Evidence)
	}
	p := &c2p.Provider{}
	if err := p.Configure(context.Background(), config(t, filepath.Join(e.dir, collector.CaptureFile))); err != nil {
		t.Fatal(err)
	}
	direct := &collector.SnapshotProvider{Snapshot: retained}
	if err := direct.Configure(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	sameJSON(t, aggregate(t, e.input, p), aggregate(t, e.input, direct))
}

// The prototype's version 1 capture is converted by the prototype
// provider, unchanged.
func TestDispatchKeepsThePrototype(t *testing.T) {
	root := repoRoot(t)
	cfg := config(t, filepath.Join(root, prototypeCapture))
	input, _, err := assessment.Input(root)
	if err != nil {
		t.Fatal(err)
	}
	proto := &assessment.Provider{}
	if err := proto.Configure(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	p := &c2p.Provider{}
	if err := p.Configure(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	sameJSON(t, aggregate(t, input, p), aggregate(t, input, proto))
}

// What the dispatch cannot convert is an explicit error: another
// provider's capture, installed or not, an evaluator this build does not
// install, and a payload 2 capture without a consistent evaluation of it.
// A failed Configure leaves nothing configured.
func TestDispatchRefusesWhatItCannotConvert(t *testing.T) {
	e := exportSaved(t)
	ctx := context.Background()
	payload, err := os.ReadFile(filepath.Join(e.dir, collector.CaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := os.ReadFile(filepath.Join(e.dir, collector.EvaluationFile))
	if err != nil {
		t.Fatal(err)
	}
	envelope := func(contract string, payloadVersion, evaluator int, payload []byte) []byte {
		b, err := json.Marshal(collector.CaptureEnvelope{Version: collector.CaptureEnvelopeVersion, Provider: contract,
			PayloadVersion: payloadVersion, EvaluatorVersion: evaluator, Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	reporting, _, err := conformance.Load(filepath.Join(repoRoot(t), "testdata/providers/conformance/v1/konstapel-reporttest/shared-image-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	withReporting, err := provider.New(kyverno.Contract, kyverno.Descriptor(), reporttest.Descriptor())
	if err != nil {
		t.Fatal(err)
	}
	var ev collector.Evaluation
	if err := json.Unmarshal(evaluation, &ev); err != nil {
		t.Fatal(err)
	}
	tampered := func(mutate func(*collector.Evaluation)) []byte {
		var c collector.Evaluation
		if err := json.Unmarshal(evaluation, &c); err != nil {
			t.Fatal(err)
		}
		mutate(&c)
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := []struct {
		name       string
		readers    collector.CaptureReaders
		capture    []byte
		evaluation []byte // nil: no evaluation file
		want       string
	}{
		{"uninstalled provider", nil, envelope(reporttest.Contract, reporttest.PayloadVersion, 1, reporting.Input), nil, "not installed"},
		{"installed provider without conversion", withReporting, envelope(reporttest.Contract, reporttest.PayloadVersion, 1, reporting.Input), nil, "has no C2P conversion"},
		{"uninstalled evaluator", nil, envelope(kyverno.Contract, collector.CaptureV2Version, kyverno.EvaluatorVersion+1, payload), evaluation, "evaluator"},
		{"no evaluation", nil, payload, nil, collector.EvaluationFile},
		{"unknown evaluation field", nil, payload, []byte(`{"observations":[],"evidence":{},"outcomes":{},"verdict":"pass"}`), "unknown field"},
		{"dropped observation", nil, payload, tampered(func(c *collector.Evaluation) { c.Observations = c.Observations[1:] }), "no observation"},
		{"miscounted summary", nil, payload, tampered(func(c *collector.Evaluation) { c.Outcomes.Pass++ }), "summary"},
		{"invented report", nil, payload, tampered(func(c *collector.Evaluation) {
			for i := range c.Observations {
				if c.Observations[i].Report != "" {
					c.Observations[i].Report = "uid-not-captured"
					return
				}
			}
		}), "report"},
		{"unknown capture version", nil, []byte(`{"version":4}`), nil, "capture version 4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, collector.CaptureFile), tc.capture)
			if tc.evaluation != nil {
				writeFile(t, filepath.Join(dir, collector.EvaluationFile), tc.evaluation)
			}
			p := &c2p.Provider{Readers: tc.readers}
			// A previous good configuration is never reused after a
			// failed one.
			if err := p.Configure(ctx, config(t, filepath.Join(e.dir, collector.CaptureFile))); err != nil {
				t.Fatal(err)
			}
			err := p.Configure(ctx, config(t, filepath.Join(dir, collector.CaptureFile)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Configure: %v, want an error naming %q", err, tc.want)
			}
			if strings.Contains(tc.name, "provider") && !errors.Is(err, collector.ErrUnsupportedCapture) {
				t.Fatalf("not an unsupported capture: %v", err)
			}
			if _, err := p.GetResults(ctx, policy.Policy{{Rule: extensions.Rule{ID: assessment.PolicyName}}}); err == nil || !strings.Contains(err.Error(), "not configured") {
				t.Fatalf("converted after a failed Configure: %v", err)
			}
			if err := p.Generate(ctx, nil); err == nil || !strings.Contains(err.Error(), "not configured") {
				t.Fatalf("generated after a failed Configure: %v", err)
			}
		})
	}
	if ev.Evidence.Expected == 0 {
		t.Fatal("empty fixture evaluation")
	}
}

// trap records any HTTP request: the kubeconfig and the proxies of the
// environment, which the plugin inherits, point at it.
type trap struct{ hits atomic.Int64 }

func newTrap(t *testing.T) *trap {
	t.Helper()
	tr := &trap{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tr.hits.Add(1)
		http.Error(w, "no network access is expected", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	writeFile(t, kubeconfig, []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: trap
  cluster:
    server: %s
contexts:
- name: trap
  context:
    cluster: trap
    user: trap
current-context: trap
users:
- name: trap
  user: {}
`, srv.URL)))
	t.Setenv("KUBECONFIG", kubeconfig)
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(k, srv.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	return tr
}

// startPlugin builds the konstapel-provider plugin with its C2P manifest
// (as scripts/build.sh does) and starts it with cfg.
func startPlugin(t *testing.T, cfg map[string]string) policy.Provider {
	t.Helper()
	root := repoRoot(t)
	dir := t.TempDir()
	bin := filepath.Join(dir, "konstapel-provider")
	build := exec.Command("go", "build", "-o", bin, "./cmd/konstapel-provider")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	options := []map[string]any{}
	for _, name := range []string{"root", "output", "namespace", "owner"} {
		options = append(options, map[string]any{"name": name, "required": true})
	}
	for _, name := range []string{"action", "capture"} {
		options = append(options, map[string]any{"name": name, "required": false})
	}
	manifest := filepath.Join(dir, "c2p-konstapel-kyverno-manifest.json")
	if err := assessment.Write(manifest, assessment.Object{
		"metadata":       assessment.Object{"id": assessment.ProviderID, "description": "Bounded modern Kyverno evidence provider", "version": "test", "types": []string{"pvp"}},
		"executablePath": "konstapel-provider", "sha256": assessment.Hash(raw), "configuration": options,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(plugin.Cleanup)
	p, err := assessment.StartProvider(manifest, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The shipped plugin binary dispatches like the in-process provider and,
// for Generate, Configure and GetResults alike, reads only local files: a
// cluster or registry request would reach the trap. The prototype's
// Generate renders its local policy artifacts; a frozen snapshot is never
// regenerated.
func TestPluginBinaryIsLocalAndConvertsLikeTheDispatch(t *testing.T) {
	e := exportSaved(t)
	tr := newTrap(t)
	ctx := context.Background()

	snapshot := startPlugin(t, config(t, filepath.Join(e.dir, collector.CaptureFile)))
	p := &c2p.Provider{}
	if err := p.Configure(ctx, config(t, filepath.Join(e.dir, collector.CaptureFile))); err != nil {
		t.Fatal(err)
	}
	got, want := aggregate(t, e.input, snapshot), aggregate(t, e.input, p)
	sameSubjects(t, normalized(got), normalized(want))
	for i, o := range got[0].ObservationsByCheck {
		w := want[0].ObservationsByCheck[i]
		if o.CheckID != w.CheckID || o.Title != w.Title || o.Description != w.Description || !o.Collected.Equal(w.Collected) || len(o.Subjects) != len(w.Subjects) {
			t.Fatalf("observation %d: %+v, want %+v", i, o, w)
		}
	}
	sameSubjects(t, packaged(t, e.dir), normalized(got))
	if err := actions.GeneratePolicy(ctx, e.input, map[plugin.ID]policy.Provider{plugin.ID(assessment.ProviderID): snapshot}); err == nil || !strings.Contains(err.Error(), "never regenerated") {
		t.Fatalf("a frozen snapshot was regenerated: %v", err)
	}

	root := repoRoot(t)
	cfg := config(t, "")
	proto := startPlugin(t, cfg)
	input, _, err := assessment.Input(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := actions.GeneratePolicy(ctx, input, map[plugin.ID]policy.Provider{plugin.ID(assessment.ProviderID): proto}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"generated/policy.json", "generated/manifest.json", "generated/upstream/" + assessment.PolicyName + ".yaml"} {
		if _, err := os.Stat(filepath.Join(cfg["output"], f)); err != nil {
			t.Fatalf("Generate did not render %s locally: %v", f, err)
		}
	}
	if n := tr.hits.Load(); n != 0 {
		t.Fatalf("the C2P provider made %d network requests", n)
	}
}

// The conversion path cannot reach a cluster, a registry or another
// process directly: none of its files imports a network, Kubernetes client
// or registry package, or calls the assessment cluster client, and the
// conversion itself reads no clock.
func TestConversionPathImportsNoClusterOrRegistryClient(t *testing.T) {
	root := repoRoot(t)
	forbidden := []string{"net", "os/exec", "k8s.io/client-go", "sigs.k8s.io/controller-runtime", "oras.land", "github.com/google/go-containerregistry",
		"github.com/backend-bunny/Konstapel/internal/bundle/"}
	for _, f := range []string{"cmd/konstapel-provider/main.go", "internal/provider/c2p/c2p.go", "internal/collector/c2p.go", "internal/collector/export.go", "internal/assessment/provider.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, f), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			for _, bad := range forbidden {
				if path == bad || strings.HasPrefix(path, strings.TrimSuffix(bad, "/")+"/") {
					t.Errorf("%s imports %s", f, path)
				}
			}
		}
		src, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		calls := []string{"NewTarget(", ".Deliver(", ".Apply(", ".Prerequisites(", "http."}
		if f != "internal/collector/export.go" {
			// Export stamps its validation time; conversion reads no clock.
			calls = append(calls, "time.Now(", "time.Since(", "time.Until(")
		}
		for _, call := range calls {
			if strings.Contains(string(src), call) {
				t.Errorf("%s calls %s", f, call)
			}
		}
	}
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, to, b)
}
