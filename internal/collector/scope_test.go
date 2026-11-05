package collector

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

func kinds(c CaptureV2) []ChangeKind {
	var out []ChangeKind
	for _, ch := range c.ScopeChanges {
		out = append(out, ch.Kind)
	}
	return out
}

func TestWorkloadChangesStayVisible(t *testing.T) {
	c := captureV2(t)
	frozenExpected := slices.Clone(c.Expected)
	tr := NewTracker(&c)
	at := c.Window.Started.Add(time.Minute)
	dev, prod := c.Workloads[0], c.Workloads[1]

	updated := dev
	updated.StateSHA256 = "new-state"
	tr.Workload(at, updated, false)
	tr.Workload(at, updated, false) // repeated event is recorded once
	tr.Workload(at, prod, true)     // removed
	replacement := prod
	replacement.UID = "pod-prod-2"
	tr.Workload(at, replacement, false)
	added := Workload{Resource: "/v1/pods", Namespace: "shop-dev", NamespaceUID: "uid-shop-dev", Name: "new", UID: "pod-new", StateSHA256: "s"}
	tr.Workload(at, added, false)
	// Ignored: unmatched resource, and a workload in an unfrozen namespace.
	tr.Workload(at, Workload{Resource: "/v1/configmaps", NamespaceUID: "uid-shop-dev", Name: "cm", UID: "cm"}, false)
	tr.Workload(at, Workload{Resource: "/v1/pods", NamespaceUID: "uid-elsewhere", Name: "x", UID: "x"}, false)

	want := []ChangeKind{WorkloadUpdated, WorkloadRemoved, WorkloadReplaced, WorkloadAdded}
	if !slices.Equal(kinds(c), want) {
		t.Fatalf("got %v, want %v", kinds(c), want)
	}
	if err := c.Validate(); err != nil {
		t.Fatal("recorded changes must keep the capture valid:", err)
	}
	// The frozen denominator is untouched: nothing is dropped or added.
	if !slices.EqualFunc(frozenExpected, c.Expected, func(a, b Expected) bool { return a.Key() == b.Key() }) {
		t.Fatal("tracking changed the expected inventory")
	}
	// Every expected observation of a changed workload carries its change.
	for _, e := range c.Expected {
		ch, changed := c.ChangeFor(e)
		if !changed {
			t.Fatalf("change not attached to %s", e.Workload.UID)
		}
		if ch.Previous == nil || ch.Previous.UID != e.Workload.UID || ch.Previous.StateSHA256 != e.Workload.StateSHA256 {
			t.Fatal("change must keep the frozen identity and state")
		}
	}
}

func TestNamespaceJoinDoesNotBroadenSnapshot(t *testing.T) {
	c := captureV2(t)
	tr := NewTracker(&c)
	at := c.Window.Started.Add(time.Minute)
	subjects := slices.Clone(c.Subjects)
	joined := subjects[0]
	joined.Namespace, joined.NamespaceUID = "shop-new", "uid-shop-new"
	tr.Configuration(at, append(subjects, joined), nil)
	if !slices.Equal(kinds(c), []ChangeKind{NamespaceJoined}) {
		t.Fatalf("got %v", kinds(c))
	}
	// A workload in the joined namespace is still not part of the snapshot.
	tr.Workload(at, Workload{Resource: "/v1/pods", Namespace: "shop-new", NamespaceUID: "uid-shop-new", Name: "web", UID: "pod-new-ns"}, false)
	if len(c.ScopeChanges) != 1 || len(c.Expected) != 3 {
		t.Fatal("joined namespace broadened the frozen snapshot")
	}
	for _, e := range c.Expected {
		if _, changed := c.ChangeFor(e); changed {
			t.Fatal("a joining namespace must not invalidate frozen evidence")
		}
	}
}

func TestNamespaceRecreateAndLeave(t *testing.T) {
	c := captureV2(t)
	tr := NewTracker(&c)
	at := c.Window.Started.Add(time.Minute)
	var current []targeting.EvidenceSubject
	for _, s := range c.Subjects {
		if s.Namespace == "shop-dev" {
			s.NamespaceUID = "uid-shop-dev-2" // deleted and recreated under the same name
		}
		current = append(current, s)
	}
	tr.Configuration(at, current, nil)
	if !slices.Equal(kinds(c), []ChangeKind{NamespaceRecreated, NamespaceLeft}) {
		t.Fatalf("got %v", kinds(c))
	}
	for _, e := range c.Expected {
		_, changed := c.ChangeFor(e)
		if changed != (e.NamespaceUID == "uid-shop-dev") {
			t.Fatalf("namespace change attached to wrong subject %s", e.NamespaceUID)
		}
	}
}

func TestConfigurationChangesDuringCollection(t *testing.T) {
	c := captureV2(t)
	tr := NewTracker(&c)
	at := c.Window.Started.Add(time.Minute)
	current := slices.Clone(c.Subjects)
	var changedBinding string
	for i := range current {
		if current[i].BindingName == "deny-production" {
			current[i].Revision = "sha256:new"
			changedBinding = string(current[i].BindingUID)
		}
	}
	tr.Configuration(at, current, []targeting.StaleScope{{Binding: targeting.ObjectRevision{Name: "audit-all", UID: "uid-audit-all"}, Policy: "disallow-privileged-containers", Reason: targeting.ReasonContentUnavailable, Message: "bundle unavailable"}})
	if !slices.Equal(kinds(c), []ChangeKind{ConfigurationChanged, ConfigurationChanged}) {
		t.Fatalf("got %v", kinds(c))
	}
	for _, e := range c.Expected {
		ch, changed := c.ChangeFor(e)
		if !changed {
			t.Fatalf("configuration change not attached to %s/%s", e.NamespaceUID, e.Contribution.BindingUID)
		}
		if e.Contribution.BindingUID == changedBinding && ch.Revision != "sha256:new" {
			t.Fatal("revision change not recorded")
		}
	}
}

func TestChangesOutsideWindowAreIgnoredOrRejected(t *testing.T) {
	c := captureV2(t)
	tr := NewTracker(&c)
	moved := c.Workloads[0]
	moved.StateSHA256 = "late"
	tr.Workload(c.Window.Closed.Add(time.Second), moved, false)
	if len(c.ScopeChanges) != 0 {
		t.Fatal("change after closure recorded")
	}
	c.ScopeChanges = []ScopeChange{{Kind: WorkloadUpdated, Observed: c.Window.Started.Add(-time.Second)}}
	if c.Validate() == nil {
		t.Fatal("change before the window accepted")
	}
}

func TestFreezeScopeFromListedObjects(t *testing.T) {
	subjects, stale := contractSubjects(t)
	var rendered []assessment.Object
	for _, ch := range renderedChecks(t) {
		raw, _ := os.ReadFile(filepath.Join(repo(t), "testdata/targeting/rendered", map[bool]string{true: "audit-all.yaml", false: "deny-production.yaml"}[strings.HasSuffix(ch.EnginePolicy, "c07ae34193f1d3c1")]))
		var o assessment.Object
		_ = yaml.Unmarshal(raw, &o)
		rendered = append(rendered, o)
	}
	pod := func(ns, name, uid string) assessment.Object {
		return assessment.Object{"apiVersion": "v1", "kind": "Pod", "metadata": assessment.Object{"namespace": ns, "name": name, "uid": uid}, "spec": assessment.Object{"containers": []any{}}, "status": assessment.Object{"phase": "Running"}}
	}
	started := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	listed := []ListedObject{{"/v1/pods", "uid-shop-prod", pod("shop-prod", "web", "p2")}, {"/v1/pods", "uid-shop-dev", pod("shop-dev", "web", "p1")}}
	c, err := FreezeScope(subjects[0].Cluster, started, "mapping-1", subjects, stale, rendered, listed)
	if err != nil {
		t.Fatal(err)
	}
	c.Window.Closed = started.Add(time.Minute)
	if err = c.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(c.Expected) != 3 || len(c.Checks) != 2 || c.Workloads[0].NamespaceUID != "uid-shop-dev" {
		t.Fatalf("unexpected frozen scope: %d expected, %d checks", len(c.Expected), len(c.Checks))
	}
	// No targets is an explicit empty scope, never an error or a pass.
	empty, err := FreezeScope(subjects[0].Cluster, started, "mapping-1", subjects, stale, rendered, nil)
	if err != nil || len(empty.Expected) != 0 {
		t.Fatal(err, empty.Expected)
	}
	if _, err = FreezeScope(subjects[0].Cluster, started, "mapping-1", subjects, stale, rendered, []ListedObject{{"/v1/pods", "uid-shop-dev", pod("shop-dev", "web", "")}}); err == nil {
		t.Fatal("listed object without UID accepted")
	}
	if _, err = FreezeScope(subjects[0].Cluster, started, "mapping-1", subjects, stale, rendered[:1], listed); err == nil {
		t.Fatal("subject whose engine policy was not rendered accepted")
	}
}
