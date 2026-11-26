package stack_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oscal-compass/compliance-to-policy-go/v2/framework/actions"
	"github.com/oscal-compass/compliance-to-policy-go/v2/plugin"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider/c2p"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// A published OCI run replays from its package alone (task 3.2): after
// the cache and the registry are lost, the retained capture, read through
// the boundary with the production registry, resolves to exactly the
// packaged frozen copy of its applied bundle, never the live, desired or
// vendored content.
func TestOCIRunReplaysFromPackageAfterEviction(t *testing.T) {
	t.Parallel()
	w := stack.NewWorld(t)
	rc := newRunCluster(t, w.Stack.Router(stack.LocalContent(), stack.VendoredName), w.Ref())
	rc.deliver()
	run := rc.start()
	rc.report(runT0.Add(time.Minute))
	run = rc.finish(run.Name)
	dir, d := rc.pkg(run)
	f := requireBundleExport(t, dir, d, w.Ref())

	w.Fetch.Down.Store(true)
	if err := w.Stack.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(w.Opts.CacheDir); err != nil {
		t.Fatal(err)
	}
	w.Open()
	if _, err := w.Stack.Router(stack.LocalContent(), stack.VendoredName).Content(context.Background(), w.Ref()); err == nil {
		t.Fatal("the live content is still usable; the eviction did not take effect")
	}

	content, err := collector.PackageContent(dir, d)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "capture.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := collector.ReadCapture(raw, installed.Registry())
	if err != nil {
		t.Fatal(err)
	}
	use, err := doc.ContentUse(installed.Registry())
	if err != nil || use.Role != collector.ContentApplied {
		t.Fatalf("%+v %v", use, err)
	}
	members, err := content.Resolve(use)
	if err != nil || len(members) != 1 {
		t.Fatalf("%+v %v", members, err)
	}
	m := members[0]
	if m.Ref != w.Ref() || !m.Applied || m.Vendored || m.Root != filepath.Join(dir, filepath.FromSlash(publication.ContentPath(w.Ref().Digest))) ||
		!reflect.DeepEqual(m.Frozen.Identity, f.Identity) {
		t.Fatalf("replay member %+v", m)
	}
	want, err := collector.FrozenContentSet(f)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := collector.FrozenContentSet(m.Frozen); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v %v", got, err)
	}
}

// A published OCI run converts and re-exports from its package alone
// (task 4.2): with the registry down and the cache evicted, the plugin's
// C2P dispatch converts the retained capture and evaluation, and a fresh
// export from the packaged content records the same normalized results as
// the published package. Neither fetches anything.
func TestOCIRunConvertsAndReExportsFromPackageAfterEviction(t *testing.T) {
	t.Parallel()
	w := stack.NewWorld(t)
	rc := newRunCluster(t, w.Stack.Router(stack.LocalContent(), stack.VendoredName), w.Ref())
	rc.deliver()
	run := rc.start()
	rc.report(runT0.Add(time.Minute))
	run = rc.finish(run.Name)
	dir, d := rc.pkg(run)
	requireBundleExport(t, dir, d, w.Ref())

	w.Fetch.Down.Store(true)
	if err := w.Stack.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(w.Opts.CacheDir); err != nil {
		t.Fatal(err)
	}
	w.Open()
	fetches := w.Fetch.Calls.Load()

	ctx := context.Background()
	registry := installed.Registry()
	raw, err := os.ReadFile(filepath.Join(dir, collector.CaptureFile))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := collector.ReadCapture(raw, registry)
	if err != nil {
		t.Fatal(err)
	}
	evRaw, err := os.ReadFile(filepath.Join(dir, collector.EvaluationFile))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := collector.ReadSnapshot(doc, registry, evRaw)
	if err != nil {
		t.Fatal(err)
	}
	content, err := collector.PackageContent(dir, d)
	if err != nil {
		t.Fatal(err)
	}
	use, err := doc.ContentUse(registry)
	if err != nil {
		t.Fatal(err)
	}
	members, err := content.Resolve(use)
	if err != nil || len(members) != 1 {
		t.Fatalf("%+v %v", members, err)
	}
	set, err := collector.FrozenContentSet(members[0].Frozen)
	if err != nil {
		t.Fatal(err)
	}
	var rules []string
	for _, e := range snap.Capture.Expected {
		if !slices.Contains(rules, e.Contribution.LogicalPolicy) {
			rules = append(rules, e.Contribution.LogicalPolicy)
		}
	}
	slices.Sort(rules)
	input, _, err := assessment.InputFromSet(members[0].Root, set, rules)
	if err != nil {
		t.Fatal(err)
	}
	p := &c2p.Provider{}
	if err := p.Configure(ctx, map[string]string{"root": stack.RepoRoot, "output": t.TempDir(), "namespace": "unused", "owner": "unused",
		"capture": filepath.Join(dir, collector.CaptureFile)}); err != nil {
		t.Fatal(err)
	}
	results, err := actions.AggregateResults(ctx, input, map[plugin.ID]policy.Provider{plugin.ID(assessment.ProviderID): p})
	if err != nil || len(results) != 1 || len(results[0].ObservationsByCheck) == 0 {
		t.Fatalf("%+v %v", results, err)
	}

	root, err := filepath.Abs(stack.RepoRoot)
	if err != nil {
		t.Fatal(err)
	}
	again := filepath.Join(t.TempDir(), "replayed")
	d2, err := collector.Export(ctx, collector.ExportRequest{Root: root, TrustedRoot: root, Content: content, Out: again,
		Run: d.Run, Scope: d.Scope, BindingConfiguration: d.Revisions.BindingConfiguration, Capture: snap.Capture, Evaluation: snap.Evaluation})
	if err != nil {
		t.Fatal(err)
	}
	if d2.PackageKind != publication.KindAssessment || d2.Evidence != d.Evidence || d2.Outcomes != d.Outcomes {
		t.Fatalf("replayed %s %+v %+v, published %+v %+v", d2.PackageKind, d2.Evidence, d2.Outcomes, d.Evidence, d.Outcomes)
	}
	for _, f := range []string{"assessment-results.json", "assessment-plan.json"} {
		if got, want := normalizedOSCAL(t, filepath.Join(again, f)), normalizedOSCAL(t, filepath.Join(dir, f)); got != want {
			t.Fatalf("%s differs after replay:\n%s\n%s", f, got, want)
		}
	}
	if n := w.Fetch.Calls.Load(); n != fetches {
		t.Fatalf("replay fetched %d times", n-fetches)
	}
}

// generatedID is an identifier a rendering generates, also inside a
// reference such as "#<uuid>".
var generatedID = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// normalizedOSCAL is an OSCAL document without what a new rendering may
// change: generated identifiers and render times. Arrays compare as sets.
func normalizedOSCAL(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var norm func(v any) any
	norm = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			out := map[string]any{}
			for k, e := range x {
				if k == "uuid" || strings.HasSuffix(k, "-uuid") || k == "last-modified" || k == "start" || k == "end" {
					continue
				}
				out[k] = norm(e)
			}
			return out
		case []any:
			items := make([]string, len(x))
			for i, e := range x {
				b, err := json.Marshal(norm(e))
				if err != nil {
					t.Fatal(err)
				}
				items[i] = string(b)
			}
			slices.Sort(items)
			return items
		case string:
			return generatedID.ReplaceAllString(x, "<generated>")
		}
		return v
	}
	b, err := json.Marshal(norm(doc))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
