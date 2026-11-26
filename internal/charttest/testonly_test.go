package charttest

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

// The test-only reporting provider is absent from both charts as rendered,
// with the defaults and with every documented values example
// (add-assessment-provider-contract 4.3): no RBAC on its source, no
// argument, configuration or label names it. The binaries, image payload
// and bundles are checked by internal/provider/installed.
func TestChartsShipNoTestOnlyProvider(t *testing.T) {
	markers := []string{reporttest.Name, reporttest.Postures().Group, reporttest.Postures().Resource + "." + reporttest.Postures().Group,
		reporttest.CheckKind, "internal/provider/reporttest", "internal/provider/conformance"}
	scan := func(name, out string) {
		t.Helper()
		if !strings.Contains(out, "kind: ") {
			t.Fatalf("%s rendered nothing:\n%s", name, out)
		}
		for _, m := range markers {
			if strings.Contains(out, m) {
				t.Errorf("%s renders test-only marker %q", name, m)
			}
		}
	}
	crds, err := exec.Command("helm", "template", "konstapel-crds", "../../charts/konstapel-crds").CombinedOutput()
	if err != nil {
		t.Fatalf("render konstapel-crds: %v\n%s", err, crds)
	}
	scan("konstapel-crds", string(crds))
	_, out, err := render(t, "konstapel-system", "image.digest="+digest)
	if err != nil {
		t.Fatal(out)
	}
	scan("konstapel defaults", out)
	examples, _ := filepath.Glob("../../docs/examples/charts/*.yaml")
	if len(examples) == 0 {
		t.Fatal("no values examples")
	}
	for _, f := range examples {
		args := []string{"template", "konstapel", "../../charts/konstapel", "--namespace", "konstapel-system", "--set", "image.digest=" + digest, "-f", f}
		raw, err := exec.Command("helm", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("render %s: %v\n%s", f, err, raw)
		}
		scan("konstapel with "+filepath.Base(f), string(raw))
	}
}
