package assessment

import (
	"context"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
	"github.com/oscal-compass/oscal-sdk-go/extensions"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPolicyProvenance(t *testing.T) {
	changes := map[string]func(Object){
		"expression": func(s Object) { Map(s["validations"].([]any)[0])["expression"] = "true" },
		"matching": func(s Object) {
			Map(At(s, "matchConstraints", "resourceRules").([]any)[0])["resources"] = []any{"services"}
		},
		"background":    func(s Object) { Map(At(s, "evaluation", "background"))["enabled"] = false },
		"variables":     func(s Object) { Map(s["variables"].([]any)[1])["expression"] = "[]" },
		"extra field":   func(s Object) { s["failurePolicy"] = "Ignore" },
		"missing field": func(s Object) { delete(s, "validations") },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c := clone(fixture(t))
			change(Map(c.Policy["spec"]))
			if _, err := VerifyPolicy(repo(t), c); err == nil || !strings.Contains(err.Error(), "provenance") {
				t.Fatal("drift accepted", err)
			}
			// Recomputing a self-consistent digest must not make changed source trusted.
			c.PolicyDigest = Digest(c.Policy["spec"])
			out := filepath.Join(t.TempDir(), "package")
			if err := Export(context.Background(), repo(t), out, nil, nil, nil, c); err == nil || !strings.Contains(err.Error(), "provenance") {
				t.Fatal("export accepted drift", err)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("unverified package written", err)
			}
			path := filepath.Join(t.TempDir(), "capture.json")
			if err := Write(path, c); err != nil {
				t.Fatal(err)
			}
			p := Provider{Config: map[string]string{"root": repo(t), "capture": path}}
			if _, err := p.GetResults(context.Background(), policy.Policy{{Rule: extensions.Rule{ID: PolicyName}}}); err == nil || !strings.Contains(err.Error(), "provenance") {
				t.Fatal("provider accepted drift", err)
			}
		})
	}
	for _, action := range []string{"Deny", "Audit"} {
		c := clone(fixture(t))
		rendered, err := Render(repo(t), action, "test", "test")
		if err != nil {
			t.Fatal(err)
		}
		c.Policy = clone(rendered)
		Map(c.Policy["metadata"])["uid"] = "server-uid"
		Map(c.Policy["metadata"])["resourceVersion"] = "42"
		c.Policy["status"] = Object{"conditionStatus": Object{"ready": true}}
		if _, err = VerifyPolicy(repo(t), c); err != nil {
			t.Fatal("server metadata rejected", err)
		}
	}
	var saved Capture
	if err := Read(filepath.Join(repo(t), "testdata/capture.json"), &saved); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPolicy(repo(t), saved); err != nil {
		t.Fatal("saved live policy rejected", err)
	}
}

func TestDuplicateInventoryFails(t *testing.T) {
	c := clone(fixture(t))
	c.Expected = append(c.Expected, c.Expected[0])
	if _, _, err := Reconcile(c); err == nil {
		t.Fatal("duplicate inventory accepted")
	}
}

func TestCollectionRechecksAdmittedResource(t *testing.T) {
	c := clone(fixture(t))
	dir := t.TempDir()
	if err := Write(filepath.Join(dir, "policy.json"), c.Policy); err != nil {
		t.Fatal(err)
	}
	if err := Write(filepath.Join(dir, "reports.json"), Object{"items": c.Reports}); err != nil {
		t.Fatal(err)
	}
	script := `#!/usr/bin/env bash
set -eu
case "$*" in
*"get clusterpolicyreports"*) echo '{"items":[]}' ;;
*"get policyreports"*) cat "$TEST_CAPTURE_DIR/reports.json" ;;
*"get validatingpolicies"*) cat "$TEST_CAPTURE_DIR/policy.json" ;;
*"get Pod"*) echo '{"metadata":{"uid":"replacement-uid"}}' ;;
*) exit 99;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("TEST_CAPTURE_DIR", dir)
	target := Target{Kubeconfig: "explicit", Context: "explicit", Cluster: c.Cluster, Timeout: time.Second}
	saved := target.Capture(context.Background(), repo(t), c.Policy, c.Expected, c.Boundary)
	ev, _, err := Reconcile(saved)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Complete || len(saved.CollectionErrors) == 0 || !strings.Contains(saved.CollectionErrors[0], "missing/replaced") {
		t.Fatal("old report hid resource replacement", ev, saved.CollectionErrors)
	}
}

func TestPackagePolicyDigests(t *testing.T) {
	c := clone(fixture(t))
	root := repo(t)
	input, plan, err := Input(root)
	if err != nil {
		t.Fatal(err)
	}
	_, result, err := Reconcile(c)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "package")
	if err = Export(context.Background(), root, out, input, plan, []policy.PVPResult{result}, c); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(out, "rendered-policy.json")
	var rendered Object
	if err = Read(path, &rendered); err != nil {
		t.Fatal(err)
	}
	Map(At(rendered, "spec", "validations").([]any)[0])["expression"] = "true"
	if err = Write(path, rendered); err != nil {
		t.Fatal(err)
	}
	if err = ValidatePackage(root, out); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatal("corrupt rendered policy accepted", err)
	}
}

func TestTeardownChecksClusterIdentity(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "deletions")
	if err := os.WriteFile(filepath.Join(dir, "kubectl"), []byte("#!/usr/bin/env bash\nprintf '%s' \"$TEST_CLUSTER_UID\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kind"), []byte("#!/usr/bin/env bash\nprintf '%s' \"$*\" >> \"$TEST_DELETIONS\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cluster-uid"), []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("TEST_DELETIONS", marker)
	t.Setenv("KONSTAPEL_CLUSTER_NAME", "konstapel-assessment-teardown-test")
	for _, uid := range []string{"replaced", "original"} {
		t.Setenv("TEST_CLUSTER_UID", uid)
		cmd := exec.Command("bash", "scripts/environment.sh", "delete", filepath.Join(dir, "kubeconfig"), dir)
		cmd.Dir = repo(t)
		b, err := cmd.CombinedOutput()
		if uid == "replaced" {
			if err == nil || !strings.Contains(string(b), "identity changed") {
				t.Fatal("replaced cluster accepted", err, string(b))
			}
			if _, err = os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("replaced cluster deleted", err)
			}
		} else {
			if err != nil {
				t.Fatal(err, string(b))
			}
			data, err := os.ReadFile(marker)
			if err != nil || !strings.Contains(string(data), "delete cluster --name konstapel-assessment-teardown-test") {
				t.Fatal("owned cluster not deleted", err, string(data))
			}
		}
	}
}
