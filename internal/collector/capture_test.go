package collector

import (
	"encoding/json"
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

// contractSubjects reads targeting's pinned ExpectedEvidence golden file, so
// these tests break if the targeting contract changes underneath them.
func contractSubjects(t *testing.T) ([]targeting.EvidenceSubject, []targeting.StaleScope) {
	t.Helper()
	var golden struct {
		ContractVersion int                         `json:"contractVersion"`
		Subjects        []targeting.EvidenceSubject `json:"subjects"`
		Stale           []targeting.StaleScope      `json:"stale"`
	}
	if err := assessment.Read(filepath.Join(repo(t), "testdata/targeting/contract/evidence.json"), &golden); err != nil {
		t.Fatal(err)
	}
	if golden.ContractVersion != targeting.ContractVersion {
		t.Fatalf("golden contract %d, code %d", golden.ContractVersion, targeting.ContractVersion)
	}
	return golden.Subjects, golden.Stale
}

func renderedChecks(t *testing.T) []Check {
	t.Helper()
	var out []Check
	for _, f := range []string{"audit-all.yaml", "deny-production.yaml"} {
		raw, err := os.ReadFile(filepath.Join(repo(t), "testdata/targeting/rendered", f))
		if err != nil {
			t.Fatal(err)
		}
		for _, doc := range strings.Split(string(raw), "\n---") {
			var o assessment.Object
			if err = yaml.Unmarshal([]byte(doc), &o); err != nil {
				t.Fatal(err)
			}
			if o["kind"] != "ValidatingPolicy" {
				continue
			}
			c, err := PolicyChecks(o, nil)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, c...)
		}
	}
	return out
}

func workload(ns, nsUID, name, uid string, privileged bool) Workload {
	pod := assessment.Object{"apiVersion": "v1", "kind": "Pod", "metadata": assessment.Object{"name": name, "labels": assessment.Object{"app": name}}, "spec": assessment.Object{"containers": []any{assessment.Object{"name": "c", "securityContext": assessment.Object{"privileged": privileged}}}}}
	return Workload{Resource: "/v1/pods", Namespace: ns, NamespaceUID: nsUID, Name: name, UID: uid, StateSHA256: WorkloadState(pod)}
}

func TestPolicyChecksEnumerateSubValidations(t *testing.T) {
	checks := renderedChecks(t)
	if len(checks) != 2 {
		t.Fatalf("want one check per rendered policy, got %d", len(checks))
	}
	// Both policies render the same validation; the check content digest is
	// equal, but the engine policy keeps them distinct.
	if checks[0].SHA256 != checks[1].SHA256 || checks[0].EnginePolicy == checks[1].EnginePolicy {
		t.Fatalf("%+v", checks)
	}
	p := assessment.Object{"metadata": assessment.Object{"name": "p"}, "spec": assessment.Object{"validations": []any{assessment.Object{"expression": "a"}, assessment.Object{"expression": "b"}}}}
	two, err := PolicyChecks(p, []string{"first", "second"})
	if err != nil || len(two) != 2 || two[1].Index != 1 || two[1].Name != "second" || two[0].SHA256 == two[1].SHA256 {
		t.Fatalf("%+v %v", two, err)
	}
	if _, err = PolicyChecks(p, []string{"only-one"}); err == nil {
		t.Fatal("mismatched names accepted")
	}
	if _, err = PolicyChecks(assessment.Object{"metadata": assessment.Object{"name": "empty"}, "spec": assessment.Object{}}, nil); err == nil {
		t.Fatal("policy without validations accepted")
	}
	changed := assessment.Object{"metadata": assessment.Object{"name": "p"}, "spec": assessment.Object{"validations": []any{assessment.Object{"expression": "a"}, assessment.Object{"expression": "b"}}, "variables": []any{assessment.Object{"name": "x", "expression": "1"}}}}
	if c, _ := PolicyChecks(changed, nil); c[0].SHA256 == two[0].SHA256 {
		t.Fatal("a variable change must change the check identity")
	}
}

func TestWorkloadStateIgnoresStatusOnly(t *testing.T) {
	base := assessment.Object{"metadata": assessment.Object{"labels": assessment.Object{"a": "b"}, "resourceVersion": "1"}, "spec": assessment.Object{"x": 1}}
	statusOnly := clone(base)
	statusOnly["status"] = assessment.Object{"phase": "Running"}
	assessment.Map(statusOnly["metadata"])["resourceVersion"] = "2"
	assessment.Map(statusOnly["metadata"])["managedFields"] = []any{assessment.Object{"manager": "kubelet"}}
	if WorkloadState(base) != WorkloadState(statusOnly) {
		t.Fatal("status-only update changed workload state")
	}
	for name, mutate := range map[string]func(assessment.Object){
		"spec":       func(o assessment.Object) { assessment.Map(o["spec"])["x"] = 2 },
		"label":      func(o assessment.Object) { assessment.Map(assessment.Map(o["metadata"])["labels"])["a"] = "c" },
		"annotation": func(o assessment.Object) { assessment.Map(o["metadata"])["annotations"] = assessment.Object{"k": "v"} },
	} {
		o := clone(base)
		mutate(o)
		if WorkloadState(o) == WorkloadState(base) {
			t.Errorf("%s change kept workload state", name)
		}
	}
}

func TestInventoryFromTargetingContract(t *testing.T) {
	subjects, _ := contractSubjects(t)
	checks := renderedChecks(t)
	workloads := []Workload{
		workload("shop-dev", "uid-shop-dev", "web", "pod-dev", false),
		workload("shop-prod", "uid-shop-prod", "web", "pod-prod", true),
		// Same name in a namespace no binding selects: never expected.
		workload("other", "uid-other", "web", "pod-other", true),
		// A resource the policies do not match.
		{Resource: "/v1/configmaps", Namespace: "shop-prod", NamespaceUID: "uid-shop-prod", Name: "cm", UID: "cm-1", StateSHA256: "x"},
	}
	inv, err := BuildInventory(subjects, checks, workloads, "mapping-1")
	if err != nil {
		t.Fatal(err)
	}
	// shop-dev: audit-all; shop-prod: audit-all and deny-production overlap.
	if len(inv) != 3 {
		t.Fatalf("want 3 expected observations, got %d: %+v", len(inv), inv)
	}
	prod := map[string]bool{}
	for _, e := range inv {
		if e.Workload.UID == "pod-other" || e.Workload.Resource == "/v1/configmaps" {
			t.Fatalf("unexpected subject in inventory: %+v", e)
		}
		if e.NamespaceUID == "uid-shop-prod" {
			prod[e.Contribution.Revision] = true
		}
		if e.Cluster == "" || e.SourceSHA256 == "" || e.Contribution.EnginePolicy != e.Check.EnginePolicy {
			t.Fatalf("incomplete identity: %+v", e)
		}
	}
	if len(prod) != 2 {
		t.Fatal("overlapping bindings must remain distinct contributions")
	}
	if !slices.IsSortedFunc(inv, func(a, b Expected) int { return strings.Compare(a.Key(), b.Key()) }) {
		t.Fatal("inventory not deterministic")
	}
	if _, err = BuildInventory(subjects, checks[:1], workloads, "mapping-1"); err == nil {
		t.Fatal("subject without rendered checks accepted")
	}
	dup := append(slices.Clone(workloads), workloads[0])
	if _, err = BuildInventory(subjects, checks, dup, "mapping-1"); err == nil {
		t.Fatal("duplicate workload identity accepted")
	}
}

func TestExpectedIdentityDistinguishesEveryDimension(t *testing.T) {
	subjects, _ := contractSubjects(t)
	inv, err := BuildInventory(subjects, renderedChecks(t), []Workload{workload("shop-dev", "uid-shop-dev", "web", "pod-dev", false)}, "mapping-1")
	if err != nil || len(inv) != 1 {
		t.Fatal(err, inv)
	}
	base := inv[0]
	for name, mutate := range map[string]func(*Expected){
		"cluster":          func(e *Expected) { e.Cluster = "other" },
		"namespace uid":    func(e *Expected) { e.NamespaceUID = "uid-shop-dev-recreated" },
		"workload uid":     func(e *Expected) { e.Workload.UID = "pod-replaced" },
		"workload state":   func(e *Expected) { e.Workload.StateSHA256 = "updated" },
		"resource":         func(e *Expected) { e.Workload.Resource = "apps/v1/deployments" },
		"sub-validation":   func(e *Expected) { e.Check.Index = 1 },
		"check content":    func(e *Expected) { e.Check.SHA256 = "changed" },
		"engine policy":    func(e *Expected) { e.Check.EnginePolicy = "konstapel-other" },
		"binding":          func(e *Expected) { e.Contribution.BindingUID = "uid-deny-production" },
		"revision":         func(e *Expected) { e.Contribution.Revision = "sha256:other" },
		"source revision":  func(e *Expected) { e.SourceSHA256 = "sha256:other" },
		"mapping revision": func(e *Expected) { e.MappingSHA256 = "mapping-2" },
	} {
		e := base
		mutate(&e)
		if e.Key() == base.Key() {
			t.Errorf("%s change kept the same observation identity", name)
		}
	}
}

func captureV2(t *testing.T) CaptureV2 {
	t.Helper()
	subjects, stale := contractSubjects(t)
	checks := renderedChecks(t)
	workloads := []Workload{workload("shop-dev", "uid-shop-dev", "web", "pod-dev", false), workload("shop-prod", "uid-shop-prod", "web", "pod-prod", true)}
	inv, err := BuildInventory(subjects, checks, workloads, "mapping-1")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	return CaptureV2{Version: CaptureV2Version, Cluster: subjects[0].Cluster, Window: CaptureWindow{Started: now, Closed: now.Add(5 * time.Minute)},
		MappingSHA256: "mapping-1", Subjects: subjects, Stale: stale, Checks: checks, Workloads: workloads, Expected: inv, Reports: []assessment.Object{}}
}

func TestCaptureV2RoundTripAndInventoryBinding(t *testing.T) {
	c := captureV2(t)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := CaptureVersion(b); err != nil || v != CaptureV2Version {
		t.Fatal(v, err)
	}
	var back CaptureV2
	if err = json.Unmarshal(b, &back); err != nil || back.Validate() != nil {
		t.Fatal("capture does not round-trip", err)
	}
	b2, _ := json.Marshal(back)
	if string(b) != string(b2) {
		t.Fatal("capture bytes changed on round-trip")
	}
	for name, mutate := range map[string]func(*CaptureV2){
		"dropped expectation": func(c *CaptureV2) { c.Expected = c.Expected[1:] },
		"extra workload": func(c *CaptureV2) {
			c.Workloads = append(c.Workloads, workload("shop-dev", "uid-shop-dev", "new", "pod-new", true))
		},
		"forged state":         func(c *CaptureV2) { c.Expected[0].Workload.StateSHA256 = "forged" },
		"other cluster":        func(c *CaptureV2) { c.Subjects[0].Cluster = "kube-system:elsewhere" },
		"v1 version":           func(c *CaptureV2) { c.Version = 1 },
		"unordered window":     func(c *CaptureV2) { c.Window.Closed = c.Window.Started.Add(-time.Second) },
		"missing mapping":      func(c *CaptureV2) { c.MappingSHA256 = "" },
		"policy without check": func(c *CaptureV2) { c.Checks = c.Checks[:1] },
	} {
		x := captureV2(t)
		mutate(&x)
		if x.Validate() == nil {
			t.Errorf("%s: invalid capture accepted", name)
		}
	}
}

func TestCaptureVersionsStaySeparate(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repo(t), "testdata/capture.json"))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := CaptureVersion(raw); err != nil || v != 1 {
		t.Fatal("prototype capture must stay version 1", v, err)
	}
	var v1 assessment.Capture
	if err = json.Unmarshal(raw, &v1); err != nil {
		t.Fatal(err)
	}
	if _, _, err = assessment.Reconcile(v1); err != nil {
		t.Fatal("prototype v1 path broken:", err)
	}
	b, _ := json.Marshal(captureV2(t))
	var asV1 assessment.Capture
	_ = json.Unmarshal(b, &asV1)
	if _, _, err = assessment.Reconcile(asV1); err == nil {
		t.Fatal("v1 reconciliation accepted a v2 capture")
	}
	if _, err = CaptureVersion([]byte(`{"version": 3}`)); err == nil {
		t.Fatal("unknown capture version accepted")
	}
}
