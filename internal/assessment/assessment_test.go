package assessment

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oscal-compass/compliance-to-policy-go/v2/framework/actions"
	"github.com/oscal-compass/compliance-to-policy-go/v2/plugin"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
)

func repo(t *testing.T) string {
	t.Helper()
	p, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func clone[T any](v T) T { b, _ := json.Marshal(v); var x T; _ = json.Unmarshal(b, &x); return x }
func fixture(t *testing.T) Capture {
	t.Helper()
	root := repo(t)
	p, e := Render(root, "Deny", "test", "test")
	if e != nil {
		t.Fatal(e)
	}
	Map(p["metadata"])["uid"] = "policy-uid"
	now := time.Now().UTC().Truncate(time.Second)
	r := Resource{"v1", "Pod", "team-a", "same-name", "uid-a"}
	result := Object{"policy": PolicyName, "source": "KyvernoValidatingPolicy", "rule": "validation-0", "result": "fail", "message": "Privileged mode is disallowed.", "timestamp": Object{"seconds": float64(now.Unix()), "nanos": float64(0)}}
	return Capture{Version: 1, Cluster: "kube-system:cluster-a", Context: "fixture", Boundary: now.Add(-time.Minute), Collected: now.Add(time.Minute), Policy: p, PolicyDigest: Digest(p["spec"]), MappingDigest: FileHash(filepath.Join(root, "content/component-definition.json")), Expected: []Resource{r}, Reports: []Object{{"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport", "metadata": Object{"uid": "report-a", "namespace": "team-a"}, "scope": r, "results": []any{result}}}}
}
func TestContentAndRendering(t *testing.T) {
	root := repo(t)
	if _, e := ValidateMapping(root); e != nil {
		t.Fatal(e)
	}
	before := FileHash(filepath.Join(root, SourcePolicy))
	for _, action := range []string{"", "Deny", "Audit"} {
		p, e := Render(root, action, "test", "owner")
		if e != nil {
			t.Fatal(e)
		}
		actions := At(p, "spec", "validationActions").([]any)
		want := action
		if want == "" {
			want = "Deny"
		}
		if actions[0] != want || At(p, "spec", "evaluation", "background", "enabled") != true || p["apiVersion"] != "policies.kyverno.io/v1" {
			t.Fatal(p)
		}
	}
	if _, e := Render(root, "Ignore", "test", "owner"); e == nil {
		t.Fatal("unsupported action accepted")
	}
	if FileHash(filepath.Join(root, SourcePolicy)) != before {
		t.Fatal("upstream modified")
	}
	temp := t.TempDir()
	if e := os.MkdirAll(filepath.Join(temp, "content"), 0755); e != nil {
		t.Fatal(e)
	}
	for _, dir := range []string{"upstream", "schemas"} {
		if e := os.Symlink(filepath.Join(root, "content", dir), filepath.Join(temp, "content", dir)); e != nil {
			t.Fatal(e)
		}
	}
	b, e := os.ReadFile(filepath.Join(root, "content/component-definition.json"))
	if e != nil {
		t.Fatal(e)
	}
	b = []byte(strings.ReplaceAll(string(b), `"control-id": "ac-6"`, `"control-id": "ac-999"`))
	if e = os.WriteFile(filepath.Join(temp, "content/component-definition.json"), b, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = ValidateMapping(temp); e == nil {
		t.Fatal("invalid control accepted")
	}
}
func TestReportNormalization(t *testing.T) {
	for _, state := range []string{"pass", "fail", "warn", "warning", "error", "skip", "future"} {
		t.Run(state, func(t *testing.T) {
			c := clone(fixture(t))
			Map(c.Reports[0]["results"].([]any)[0])["result"] = state
			ev, p, e := Reconcile(c)
			if e != nil {
				t.Fatal(e)
			}
			s := p.ObservationsByCheck[0].Subjects[0]
			if !ev.Complete || ev.Evaluations[0].Outcome != state || s.Result != Normalize(state) || (state != "pass" && s.Result == policy.ResultPass) {
				t.Fatal(ev, s)
			}
		})
	}
}
func TestCompletenessAndLayouts(t *testing.T) {
	cases := map[string]func(*Capture){"missing": func(c *Capture) { c.Reports = nil }, "stale": func(c *Capture) { c.Boundary = c.Collected.Add(-time.Second) }, "replaced UID": func(c *Capture) { c.Expected[0].UID = "replacement" }, "collection failure": func(c *Capture) { c.CollectionErrors = []string{"forbidden"} }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := clone(fixture(t))
			change(&c)
			ev, p, e := Reconcile(c)
			if e != nil {
				t.Fatal(e)
			}
			if ev.Complete {
				t.Fatal("incomplete evidence accepted")
			}
			for _, s := range p.ObservationsByCheck[0].Subjects {
				if s.Result == policy.ResultPass {
					t.Fatal("incomplete passed")
				}
			}
		})
	}
	invalid := map[string]func(*Capture){"unknown API": func(c *Capture) { c.Reports[0]["apiVersion"] = "future/v1" }, "missing scope": func(c *Capture) { delete(c.Reports[0], "scope") }, "missing timestamp": func(c *Capture) { delete(Map(c.Reports[0]["results"].([]any)[0]), "timestamp") }, "bad policy digest": func(c *Capture) { c.PolicyDigest = "bad" }, "empty inventory": func(c *Capture) { c.Expected = nil }, "invalid results": func(c *Capture) { c.Reports[0]["results"] = "bad" }}
	invalid["legacy source with same policy name"] = func(c *Capture) { Map(c.Reports[0]["results"].([]any)[0])["source"] = "Kyverno" }
	invalid["invalid timestamp nanos"] = func(c *Capture) {
		Map(At(Map(c.Reports[0]["results"].([]any)[0]), "timestamp"))["nanos"] = float64(1e9)
	}
	for name, change := range invalid {
		t.Run(name, func(t *testing.T) {
			c := clone(fixture(t))
			change(&c)
			if _, _, e := Reconcile(c); e == nil {
				t.Fatal("malformed capture accepted")
			}
		})
	}
	c := clone(fixture(t))
	result := Map(c.Reports[0]["results"].([]any)[0])
	result["resources"] = []any{c.Reports[0]["scope"]}
	delete(c.Reports[0], "scope")
	c.Reports[0]["kind"] = "ClusterPolicyReport"
	if ev, _, e := Reconcile(c); e != nil || !ev.Complete {
		t.Fatal(ev, e)
	}
}
func TestSubjectIdentity(t *testing.T) {
	c := clone(fixture(t))
	other := c.Expected[0]
	other.Namespace = "team-b"
	other.UID = "uid-b"
	c.Expected = append(c.Expected, other)
	report := clone(c.Reports[0])
	report["scope"] = clone(Object{"apiVersion": "v1", "kind": "Pod", "namespace": other.Namespace, "name": other.Name, "uid": other.UID})
	Map(report["metadata"])["uid"] = "report-b"
	c.Reports = append(c.Reports, report)
	_, p, e := Reconcile(c)
	if e != nil {
		t.Fatal(e)
	}
	a, b := p.ObservationsByCheck[0].Subjects[0], p.ObservationsByCheck[0].Subjects[1]
	if a.ResourceID == b.ResourceID || a.EvaluatedOn.IsZero() || a.Reason == "" {
		t.Fatal(a, b)
	}
	c.Cluster = "other-cluster"
	_, p2, e := Reconcile(c)
	if e != nil {
		t.Fatal(e)
	}
	if a.ResourceID == p2.ObservationsByCheck[0].Subjects[0].ResourceID {
		t.Fatal("cluster identity lost")
	}
}
func TestPluginAndExport(t *testing.T) {
	root := repo(t)
	cmd := exec.Command("bash", "scripts/build.sh")
	cmd.Dir = root
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, b)
	}
	defer plugin.Cleanup()
	manifest := filepath.Join(root, "bin/c2p-konstapel-kyverno-manifest.json")
	out := t.TempDir()
	capturePath := filepath.Join(out, "input.json")
	c := clone(fixture(t))
	if e := Write(capturePath, c); e != nil {
		t.Fatal(e)
	}
	cfg := map[string]string{"root": root, "output": out, "namespace": "test", "owner": "test", "action": "Deny", "capture": capturePath}
	p, e := StartProvider(manifest, cfg)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = StartProvider(filepath.Join(out, "missing.json"), cfg); e == nil {
		t.Fatal("missing plugin accepted")
	}
	badcfg := clone(cfg)
	delete(badcfg, "namespace")
	if _, e = StartProvider(manifest, badcfg); e == nil {
		t.Fatal("missing config accepted")
	}
	var m Object
	if e = Read(manifest, &m); e != nil {
		t.Fatal(e)
	}
	m["sha256"] = strings.Repeat("0", 64)
	m["executablePath"] = filepath.Join(root, "bin/konstapel-provider")
	badmanifest := filepath.Join(root, "bin/c2p-test-bad-manifest.json")
	defer os.Remove(badmanifest)
	if e = Write(badmanifest, m); e != nil {
		t.Fatal(e)
	}
	if _, e = StartProvider(badmanifest, cfg); e == nil {
		t.Fatal("checksum mismatch accepted")
	}
	input, plan, e := Input(root)
	if e != nil {
		t.Fatal(e)
	}
	providers := map[plugin.ID]policy.Provider{plugin.ID(ProviderID): p}
	if e = actions.GeneratePolicy(context.Background(), input, providers); e != nil {
		t.Fatal(e)
	}
	var generatedManifest Object
	if e = Read(filepath.Join(out, "generated/manifest.json"), &generatedManifest); e != nil {
		t.Fatal(e)
	}
	if generatedManifest["renderedSha256"] != FileHash(filepath.Join(out, "generated/policy.json")) {
		t.Fatal("rendered file checksum mismatch")
	}
	for _, mode := range []string{"fail", "pass", "missing"} {
		t.Run(mode, func(t *testing.T) {
			sample := clone(c)
			if mode == "missing" {
				sample.Reports = nil
			} else {
				Map(sample.Reports[0]["results"].([]any)[0])["result"] = mode
			}
			if e := Write(capturePath, sample); e != nil {
				t.Fatal(e)
			}
			res, e := actions.AggregateResults(context.Background(), input, providers)
			if e != nil {
				t.Fatal(e)
			}
			dest := filepath.Join(out, mode)
			if e = Export(context.Background(), root, dest, input, clone(plan), res, sample); e != nil {
				t.Fatal(e)
			}
			var doc Object
			if e = Read(filepath.Join(dest, "assessment-results.json"), &doc); e != nil {
				t.Fatal(e)
			}
			b, _ := json.Marshal(doc)
			if strings.Contains(string(b), `"state":"satisfied"`) {
				t.Fatal("full satisfaction asserted")
			}
			if mode == "missing" {
				if !strings.Contains(string(b), `"value":"false"`) {
					t.Fatal("missing completeness")
				}
				for _, result := range At(doc, "assessment-results", "results").([]any) {
					if findings, _ := Map(result)["findings"].([]any); len(findings) > 0 {
						t.Fatal("missing evidence became an observed violation")
					}
				}
			}
		})
	}
}

func TestDeliveryPrerequisitesAndOwnership(t *testing.T) {
	if _, err := NewTarget("", "", time.Second); err == nil {
		t.Fatal("ambient target accepted")
	}
	for _, mode := range []string{"missing-api", "conflict"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			script := `#!/usr/bin/env bash
set -eu
args="$*"
case "$args" in
*"/apis/policies.kyverno.io/v1"*)
 if [[ $TEST_TARGET_MODE == missing-api ]]; then echo 'required API unavailable' >&2; exit 1; fi
 echo '{"resources":[{"name":"validatingpolicies"}]}' ;;
*"/apis/wgpolicyk8s.io/v1alpha2"*) echo '{"resources":[{"name":"policyreports"},{"name":"clusterpolicyreports"}]}' ;;
*"get validatingpolicies"*) echo '{"metadata":{"uid":"other","labels":{"konstapel.io/owner":"other-owner"}}}' ;;
*) echo 'unexpected mutation' >&2; exit 99;;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
			t.Setenv("TEST_TARGET_MODE", mode)
			target := &Target{Kubeconfig: "explicit-config", Context: "explicit-context", Cluster: "fixture", Timeout: time.Second}
			rendered, err := Render(repo(t), "Deny", "test", "test")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = target.Deliver(context.Background(), rendered, "test"); err == nil {
				t.Fatal("invalid prerequisite/ownership accepted")
			}
		})
	}
}

func TestSavedCapture(t *testing.T) {
	var c Capture
	if err := Read(filepath.Join(repo(t), "testdata/capture.json"), &c); err != nil {
		t.Fatal(err)
	}
	ev, p, err := Reconcile(c)
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Complete || len(ev.Evaluations) != 2 || len(p.ObservationsByCheck[0].Subjects) != 2 {
		t.Fatal(ev)
	}
	c.Reports = append(c.Reports, clone(c.Reports[0]))
	Map(c.Reports[2]["results"].([]any)[0])["result"] = "pass"
	ev, _, err = Reconcile(c)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Complete {
		t.Fatal("ambiguous conflicting evidence accepted")
	}
}

func TestAdmissionAttribution(t *testing.T) {
	denied := []byte("Policy " + PolicyName + " failed: Privileged mode is disallowed")
	err := os.ErrPermission
	if CheckAdmission(denied, err, true) != nil {
		t.Fatal("valid policy rejection not recognized")
	}
	for _, b := range [][]byte{[]byte("RBAC forbidden"), []byte("Pod Security Admission rejected"), []byte("another policy failed")} {
		if CheckAdmission(b, err, true) == nil {
			t.Fatal("unrelated rejection counted")
		}
	}
	if CheckAdmission(denied, nil, true) == nil {
		t.Fatal("accepted request counted as denied")
	}
	if CheckAdmission(nil, err, false) == nil {
		t.Fatal("rejected compliant request accepted")
	}
}
func TestIncompleteCLIAndCleanupGuard(t *testing.T) {
	root := repo(t)
	var c Capture
	if err := Read(filepath.Join(root, "testdata/capture.json"), &c); err != nil {
		t.Fatal(err)
	}
	c.Reports = nil
	dir := t.TempDir()
	capture := filepath.Join(dir, "input.json")
	if err := Write(capture, c); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(root, "bin/konstapel"), "convert", "--root", root, "--provider", filepath.Join(root, "bin/c2p-konstapel-kyverno-manifest.json"), "--capture", capture, "--output", filepath.Join(dir, "package"))
	if b, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(b), "incomplete evidence") {
		t.Fatalf("missing evidence did not fail CLI: %v %s", err, b)
	}
	if err := ValidatePackage(root, filepath.Join(dir, "package")); err != nil {
		t.Fatal("diagnostic package not retained/valid", err)
	}
	// The acceptance refusal path must not delete pre-existing resources, even
	// when their owner label equals the configured value.
	fake := `#!/usr/bin/env bash
set -eu
case "$*" in
*"get --raw /apis/policies"*) echo '{"resources":[{"name":"validatingpolicies"}]}' ;;
*"get --raw /apis/wgpolicy"*) echo '{"resources":[{"name":"policyreports"},{"name":"clusterpolicyreports"}]}' ;;
*"get namespace konstapel-acceptance"*) echo 'namespace/konstapel-acceptance' ;;
*"get events"*) echo '{"items":[]}' ;;
*"delete "*) echo 'unrelated deletion' >> "$FAKE_DELETIONS"; exit 99;;
*) echo 'unexpected command' >&2;exit 1;;
esac
`
	bindir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bindir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bindir, "kubectl"), []byte(fake), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bindir+":"+os.Getenv("PATH"))
	marker := filepath.Join(dir, "deletions")
	t.Setenv("FAKE_DELETIONS", marker)
	target := &Target{Kubeconfig: "explicit", Context: "kind-konstapel-assessment", Cluster: "fixture", Timeout: time.Second}
	err := Acceptance(context.Background(), target, root, filepath.Join(dir, "refused"), "konstapel-acceptance", "konstapel-assessment", time.Second, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "namespace already exists") {
		t.Fatal("existing namespace not refused", err)
	}
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("cleanup deleted unrelated resource")
	}
}
