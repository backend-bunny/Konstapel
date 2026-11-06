package hardening

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Tasks 3.3-3.4: a bundle capture exported end to end through the
// collector's public API. Two bindings (Audit everywhere, Deny in
// production) evaluate the four checks and the privileged check against a
// compliant development Pod and a production Pod that violates two checks,
// so production observations repeat across binding instances.

var exportT0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

type exportFixture struct {
	capture collector.CaptureV2
	ev      collector.Evaluation
}

// violations of the production Pod, by logical policy and validation index.
var prodViolations = map[string]map[int]bool{
	"disallow-privilege-escalation": {0: true},
	"disallow-capabilities-strict":  {1: true},
}

func bundleCapture(t *testing.T) exportFixture {
	t.Helper()
	c, ref := served(t)
	var policies []v1alpha1.ProfilePolicy
	for _, p := range c.Bundle.Policies {
		policies = append(policies, v1alpha1.ProfilePolicy{Name: p.Name})
	}
	profile := v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "linux-hardening", UID: "p-hardening", Generation: 1},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: ref, Policies: policies}}
	var bindings []v1alpha1.ComplianceBinding
	for _, b := range bundleBindings {
		sel := b.sel
		bindings = append(bindings, v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.name, UID: k8stypes.UID("uid-" + b.name), Generation: 1},
			Spec: v1alpha1.ComplianceBindingSpec{ProfileRef: v1alpha1.ProfileReference{Name: profile.Name}, Mode: b.mode, NamespaceSelector: &sel, EnforcementEpoch: 1}})
	}
	const cluster = "kube-system:fixture"
	nsUID := map[string]k8stypes.UID{"shop-prod": "uid-shop-prod", "shop-dev": "uid-shop-dev"}
	var namespaces []targeting.Namespace
	for name, l := range bundleNamespaces {
		namespaces = append(namespaces, targeting.Namespace{Name: name, UID: nsUID[name], Labels: l})
	}
	res := targeting.Resolve(targeting.Input{Cluster: cluster, Bundles: []targeting.Bundle{c.Bundle}, Profiles: []v1alpha1.ComplianceProfile{profile},
		Bindings: bindings, Namespaces: namespaces})
	subjects, stale, err := targeting.ExpectedEvidence(res, map[string]*targeting.Content{ref.Digest: c})
	if err != nil {
		t.Fatal(err)
	}
	var rendered []assessment.Object
	var contributions []targeting.Contribution
	for _, br := range res.Bindings {
		for _, contrib := range br.Contributions {
			obj, err := targeting.Render(contrib, c.Policies[contrib.Policy])
			if err != nil {
				t.Fatal(err)
			}
			obj.SetUID(k8stypes.UID("uid-" + obj.GetName()))
			rendered = append(rendered, obj.Object)
			contributions = append(contributions, contrib)
		}
	}
	pod := func(ns, name, uid string) collector.ListedObject {
		return collector.ListedObject{Resource: "/v1/pods", NamespaceUID: string(nsUID[ns]), Object: assessment.Object{"apiVersion": "v1", "kind": "Pod",
			"metadata": assessment.Object{"namespace": ns, "name": name, "uid": uid}, "spec": assessment.Object{"containers": []any{}}, "status": assessment.Object{"phase": "Running"}}}
	}
	capture, err := collector.FreezeScope(cluster, exportT0, "sha256:mapping-fixture", subjects, stale, rendered,
		[]collector.ListedObject{pod("shop-dev", "web", "pod-dev"), pod("shop-prod", "web", "pod-prod")})
	if err != nil {
		t.Fatal(err)
	}
	capture.Contributions = contributions
	capture.Window.Closed = exportT0.Add(5 * time.Minute)
	// One PolicyReport per workload, with a result for every expected check.
	at := exportT0.Add(time.Minute)
	byWorkload := map[string][]any{}
	for _, e := range capture.Expected {
		outcome := "pass"
		if e.Workload.UID == "pod-prod" && prodViolations[e.Contribution.LogicalPolicy][e.Check.Index] {
			outcome = "fail"
		}
		byWorkload[e.Workload.UID] = append(byWorkload[e.Workload.UID], assessment.Object{"policy": e.Check.EnginePolicy, "result": outcome,
			"source": "KyvernoValidatingPolicy", "properties": assessment.Object{"cel.validationIndex": fmt.Sprint(e.Check.Index)},
			"timestamp": assessment.Object{"seconds": float64(at.Unix()), "nanos": float64(0)}})
	}
	for _, w := range capture.Workloads {
		capture.Reports = append(capture.Reports, assessment.Object{"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport",
			"metadata": assessment.Object{"uid": "report-" + w.UID, "namespace": w.Namespace},
			"scope":    assessment.Object{"apiVersion": "v1", "kind": "Pod", "namespace": w.Namespace, "uid": w.UID}, "results": byWorkload[w.UID]})
	}
	ev, err := capture.Evaluate(nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return exportFixture{capture, ev}
}

func exportBundle(t *testing.T, f exportFixture) (string, publication.Descriptor) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "pkg")
	run := publication.RunRef{ClusterID: f.capture.Cluster, BindingUID: "uid-audit-all", RunUID: "run-hardening"}
	req := collector.ExportRequest{Root: root, Out: out, Run: run,
		Scope:                publication.Scope{Kind: publication.ScopeBinding, ClusterID: run.ClusterID, BindingUID: run.BindingUID, NamespaceUIDs: []string{"uid-shop-dev", "uid-shop-prod"}, Revision: "scope-1"},
		BindingConfiguration: "binding-config-1", Capture: f.capture, Evaluation: f.ev}
	d, err := collector.Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return out, d
}

func readOSCAL(t *testing.T, path, root string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := assessment.Read(path, &doc); err != nil {
		t.Fatal(err)
	}
	return assessment.Map(doc[root])
}

// Task 3.3: the generated documents are valid at their declared OSCAL 1.1.3
// schema, the package re-verifies, and the official NIST 1.2.3 inputs and the
// authored mappings travel unchanged.
func TestBundleExportProducesValidOSCAL(t *testing.T) {
	out, d := exportBundle(t, bundleCapture(t))
	if d.PackageKind != publication.KindAssessment || d.Diagnostic != nil {
		t.Fatalf("package %s, diagnostic %+v", d.PackageKind, d.Diagnostic)
	}
	if d.Evidence.Completeness != publication.Complete || d.Evidence.Expected != 21 || d.Outcomes.Fail != 4 || d.Outcomes.Pass != 17 {
		t.Fatalf("evidence %+v outcomes %+v", d.Evidence, d.Outcomes)
	}
	if err := collector.VerifyPackage(out); err != nil {
		t.Fatal(err)
	}
	schema := filepath.Join(root, "content/schemas/oscal-1.1.3.json")
	for doc, key := range map[string]string{"assessment-plan": "assessment-plan", "assessment-results": "assessment-results", "system-security-plan": "system-security-plan"} {
		path := filepath.Join(out, doc+".json")
		if err := assessment.Schema(path, schema); err != nil {
			t.Errorf("%s: %v", doc, err)
		}
		if v := assessment.Str(assessment.At(readOSCAL(t, path, key), "metadata", "oscal-version")); v != "1.1.3" {
			t.Errorf("%s declares OSCAL %s", doc, v)
		}
	}
	nist := assessment.NIST
	for _, f := range []string{nist + "NIST_SP-800-53_rev5_catalog.json", nist + "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json",
		"content/component-definition.json", "content/linux-hardening/component-definition.json"} {
		rel := strings.TrimPrefix(f, "content/")
		if assessment.FileHash(filepath.Join(out, "content", rel)) != fileSum(t, f) {
			t.Errorf("%s changed in the package", f)
		}
	}
	for _, f := range []string{"NIST_SP-800-53_rev5_catalog.json", "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"} {
		var doc map[string]any
		if err := assessment.Read(filepath.Join(out, "content", strings.TrimPrefix(nist, "content/")+f), &doc); err != nil {
			t.Fatal(err)
		}
		for _, v := range doc {
			if assessment.Str(assessment.At(assessment.Map(v), "metadata", "oscal-version")) != "1.2.3" {
				t.Errorf("%s is not the official 1.2.3 document", f)
			}
		}
	}
}

// Task 3.4: distinct checks stay identifiable, repeated binding instances
// stay distinct subjects of one check, and controls are neither multiplied
// nor claimed satisfied.
func TestBundleExportKeepsChecksDistinctWithoutMultiplyingControls(t *testing.T) {
	out, _ := exportBundle(t, bundleCapture(t))
	results := readOSCAL(t, filepath.Join(out, "assessment-results.json"), "assessment-results")
	r := assessment.Map(results["results"].([]any)[0])

	perPolicy := map[string]int{}
	bindingsPerPolicy := map[string]map[string]bool{}
	for _, e := range bundleCapture(t).capture.Expected {
		perPolicy[e.Contribution.LogicalPolicy]++
	}
	obs, _ := r["observations"].([]any)
	if len(obs) != len(perPolicy) {
		t.Fatalf("%d observations for %d logical checks", len(obs), len(perPolicy))
	}
	byUUID := map[string]string{}
	for _, o := range obs {
		om := assessment.Map(o)
		title := assessment.Str(om["title"])
		byUUID[assessment.Str(om["uuid"])] = title
		subjects, _ := om["subjects"].([]any)
		if len(subjects) != perPolicy[title] {
			t.Errorf("%s: %d subjects, want %d", title, len(subjects), perPolicy[title])
		}
		bindingsPerPolicy[title] = map[string]bool{}
		for _, s := range subjects {
			for _, p := range assessment.Map(s)["props"].([]any) {
				if pm := assessment.Map(p); pm["name"] == "binding-uid" {
					bindingsPerPolicy[title][assessment.Str(pm["value"])] = true
				}
			}
		}
		if len(bindingsPerPolicy[title]) != 2 {
			t.Errorf("%s: subjects from bindings %v, want both instances distinct", title, bindingsPerPolicy[title])
		}
	}
	// One finding per statement, however many checks or bindings feed it,
	// related only to the checks that actually failed.
	findings, _ := r["findings"].([]any)
	targets := map[string]bool{}
	for _, f := range findings {
		fm := assessment.Map(f)
		target := assessment.Str(assessment.At(fm, "target", "target-id"))
		if targets[target] {
			t.Errorf("control statement %s has more than one finding", target)
		}
		targets[target] = true
		if state := assessment.Str(assessment.At(fm, "target", "status", "state")); state != "not-satisfied" {
			t.Errorf("%s: finding state %s; passing evidence must never claim satisfaction", target, state)
		}
		related, _ := fm["related-observations"].([]any)
		for _, ro := range related {
			check := byUUID[assessment.Str(assessment.Map(ro)["observation-uuid"])]
			if _, failing := prodViolations[check]; !failing {
				t.Errorf("%s finding relates the passing check %s", target, check)
			}
		}
	}
	for _, want := range []string{"ac-6_smt", "cm-6_smt", "cm-7_smt"} {
		if !targets[want] {
			t.Errorf("no finding for %s (targets %v)", want, targets)
		}
	}
	ssp := readOSCAL(t, filepath.Join(out, "system-security-plan.json"), "system-security-plan")
	seen := map[string]int{}
	for _, req := range assessment.At(ssp, "control-implementation", "implemented-requirements").([]any) {
		seen[assessment.Str(assessment.Map(req)["control-id"])]++
	}
	if seen["ac-6"] != 1 || seen["cm-6"] != 1 || seen["cm-7"] != 1 || len(seen) != 3 {
		t.Errorf("SSP implemented requirements %v; each mapped control exactly once", seen)
	}
	raw, _ := os.ReadFile(filepath.Join(out, "assessment-results.json"))
	text := string(raw)
	if !strings.Contains(text, "partial") || strings.Contains(text, `"state": "satisfied"`) {
		t.Error("results must state partial coverage and claim no satisfied control")
	}
}

// Passing evidence for every check makes no control claim at all.
func TestAllPassingBundleExportMakesNoControlClaim(t *testing.T) {
	f := bundleCapture(t)
	for _, rep := range f.capture.Reports {
		for _, res := range rep["results"].([]any) {
			assessment.Map(res)["result"] = "pass"
		}
	}
	ev, err := f.capture.Evaluate(nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.ev = ev
	out, d := exportBundle(t, f)
	if d.PackageKind != publication.KindAssessment || d.Outcomes.Fail != 0 || d.Outcomes.Pass != 21 {
		t.Fatalf("%s %+v", d.PackageKind, d.Outcomes)
	}
	r := assessment.Map(readOSCAL(t, filepath.Join(out, "assessment-results.json"), "assessment-results")["results"].([]any)[0])
	if findings, ok := r["findings"]; ok {
		t.Fatalf("all-passing bundle evidence produced control findings: %v", findings)
	}
}
