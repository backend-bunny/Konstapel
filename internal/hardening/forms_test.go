package hardening

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

var update = flag.Bool("update", false, "rewrite generated CLI fixtures")

// The workload-forms matrix (task 2.1): every matched workload kind, a
// compliant spec and one violation per check, each with an omitted, Linux and
// Windows OS declaration. The generated kyverno test runs all four variants
// against it, so each check's OS convention and template extraction is
// exercised on every form independently of the upstream suites.

var forms = []struct {
	kind, apiVersion string
	wrap             func(spec map[string]any) map[string]any
}{
	{"Pod", "v1", func(s map[string]any) map[string]any { return s }},
	{"Deployment", "apps/v1", template},
	{"DaemonSet", "apps/v1", template},
	{"StatefulSet", "apps/v1", func(s map[string]any) map[string]any {
		t := template(s)
		t["serviceName"] = "svc"
		return t
	}},
	{"ReplicaSet", "apps/v1", template},
	{"ReplicationController", "v1", func(s map[string]any) map[string]any {
		return map[string]any{"selector": map[string]any{"app": "w"}, "template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "w"}}, "spec": s}}
	}},
	{"Job", "batch/v1", func(s map[string]any) map[string]any {
		return map[string]any{"template": map[string]any{"spec": withRestart(s)}}
	}},
	{"CronJob", "batch/v1", func(s map[string]any) map[string]any {
		return map[string]any{"schedule": "0 * * * *", "jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": withRestart(s)}}}}
	}},
}

func template(s map[string]any) map[string]any {
	return map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"app": "w"}},
		"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "w"}}, "spec": s}}
}

func withRestart(s map[string]any) map[string]any {
	s["restartPolicy"] = "Never"
	return s
}

// compliantContainer satisfies all four checks on its own.
func compliantContainer() map[string]any {
	return map[string]any{"name": "app", "image": "busybox:1.38.0", "securityContext": map[string]any{
		"allowPrivilegeEscalation": false,
		"capabilities":             map[string]any{"drop": []any{"ALL"}},
		"runAsNonRoot":             true,
		"seccompProfile":           map[string]any{"type": "RuntimeDefault"},
	}}
}

// violations break exactly one check each.
var violations = []struct {
	name, check string
	apply       func(sc map[string]any)
}{
	{"escalation", "disallow-privilege-escalation", func(sc map[string]any) { sc["allowPrivilegeEscalation"] = true }},
	{"capabilities", "disallow-capabilities-strict", func(sc map[string]any) { delete(sc, "capabilities") }},
	{"root", "require-run-as-nonroot", func(sc map[string]any) { sc["runAsNonRoot"] = false }},
	{"seccomp", "restrict-seccomp-strict", func(sc map[string]any) { delete(sc, "seccompProfile") }},
}

var checkNames = []string{"disallow-privilege-escalation", "disallow-capabilities-strict", "require-run-as-nonroot", "restrict-seccomp-strict"}

type expectation struct{ kind, policy, result, resource string }

func generateForms() (resources []byte, test []byte) {
	var docs [][]byte
	var exp []expectation
	for _, f := range forms {
		for _, os := range []string{"", "linux", "windows"} {
			osName := os
			if osName == "" {
				osName = "unset"
			}
			cases := append([]string{"compliant"}, func() []string {
				var n []string
				for _, v := range violations {
					n = append(n, v.name)
				}
				return n
			}()...)
			for _, c := range cases {
				if c == "compliant" && os == "linux" {
					continue // unset already covers the Linux rules for compliant specs
				}
				ctr := compliantContainer()
				broken := ""
				for _, v := range violations {
					if v.name == c {
						v.apply(ctr["securityContext"].(map[string]any))
						broken = v.check
					}
				}
				spec := map[string]any{"containers": []any{ctr}}
				if os != "" {
					spec["os"] = map[string]any{"name": os}
				}
				name := strings.ToLower(f.kind) + "-" + c + "-os-" + osName
				obj := map[string]any{"apiVersion": f.apiVersion, "kind": f.kind,
					"metadata": map[string]any{"name": name, "namespace": "default"}, "spec": f.wrap(spec)}
				b, _ := yaml.Marshal(obj)
				docs = append(docs, b)
				for _, check := range checkNames {
					result := "pass"
					if check == broken && os != "windows" {
						result = "fail"
					}
					exp = append(exp, expectation{f.kind, check, result, name})
				}
			}
		}
	}
	resources = bytes.Join(docs, []byte("---\n"))

	// Group expectations into the CLI test's results list.
	type key struct{ kind, policy, result string }
	grouped := map[key][]string{}
	var keys []key
	for _, e := range exp {
		k := key{e.kind, e.policy, e.result}
		if _, ok := grouped[k]; !ok {
			keys = append(keys, k)
		}
		grouped[k] = append(grouped[k], e.resource)
	}
	var results []any
	for _, k := range keys {
		results = append(results, map[string]any{"isValidatingPolicy": true, "kind": k.kind, "policy": k.policy, "result": k.result, "resources": grouped[k]})
	}
	var policies []any
	for _, c := range checkNames {
		policies = append(policies, "../../../content/linux-hardening/variants/"+c+".yaml")
	}
	t := map[string]any{"apiVersion": "cli.kyverno.io/v1alpha1", "kind": "Test", "metadata": map[string]any{"name": "linux-hardening-workload-forms"},
		"policies": policies, "resources": []any{"resources.yaml"}, "results": results}
	test, _ = yaml.Marshal(t)
	header := []byte("# Generated by internal/hardening (go test ./internal/hardening -run TestWorkloadFormsFixtures -update). Do not edit.\n")
	return append(header, resources...), append(header, test...)
}

func TestWorkloadFormsFixtures(t *testing.T) {
	dir := filepath.Join(root, "testdata/linux-hardening/forms")
	resources, test := generateForms()
	files := map[string][]byte{"resources.yaml": resources, "kyverno-test.yaml": test}
	for name, want := range files {
		path := filepath.Join(dir, name)
		if *update {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s is stale; run go test ./internal/hardening -run TestWorkloadFormsFixtures -update", path)
		}
	}
	// Every kind has a failing case for every check, and Windows never fails.
	var kinds []string
	for _, f := range forms {
		kinds = append(kinds, f.kind)
	}
	if !slices.Contains(kinds, "CronJob") || !slices.Contains(kinds, "Pod") || !slices.Contains(kinds, "Deployment") || len(kinds) != 8 {
		t.Errorf("forms = %v", kinds)
	}
	// Explicit Windows workloads are outside scope: no check may expect a
	// failure for them, and every check must fail its own violation elsewhere.
	var parsed struct {
		Results []struct {
			Policy    string   `json:"policy"`
			Result    string   `json:"result"`
			Resources []string `json:"resources"`
		} `json:"results"`
	}
	if err := yaml.Unmarshal(test, &parsed); err != nil {
		t.Fatal(err)
	}
	fails := map[string]int{}
	for _, r := range parsed.Results {
		for _, res := range r.Resources {
			if r.Result == "fail" {
				fails[r.Policy]++
				if strings.Contains(res, "-os-windows") {
					t.Errorf("%s expects %s to fail", r.Policy, res)
				}
			}
		}
	}
	for _, c := range checkNames {
		if fails[c] != 2*len(forms) { // unset and linux OS for each kind
			t.Errorf("%s fails %d forms, want %d", c, fails[c], 2*len(forms))
		}
	}
}
