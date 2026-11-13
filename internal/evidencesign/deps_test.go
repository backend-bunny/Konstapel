package evidencesign

import (
	"os/exec"
	"strings"
	"testing"
)

// Task 1.4: the signer adds no Go module and no package outside the
// controller's existing dependency closure, so linking it into the controller
// changes neither go.mod/go.sum nor the image's SBOM and license inventory
// (scripts/image), and it never executes a program or opens an HTTP client
// itself: runtime signing stays in Go, without Cosign or a shell in the image.
func TestDependenciesStayWithinTheController(t *testing.T) {
	list := func(args ...string) []string {
		t.Helper()
		cmd := exec.Command("go", append([]string{"list", "-mod=readonly"}, args...)...)
		cmd.Dir = repoRoot(t)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list %v: %v", args, err)
		}
		return strings.Fields(string(out))
	}
	const self = "github.com/backend-bunny/Konstapel/internal/evidencesign"
	controller := map[string]bool{}
	for _, p := range list("-deps", "./cmd/konstapel") {
		controller[p] = true
	}
	thirdParty := 0
	for _, p := range list("-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", self) {
		if p == self {
			continue
		}
		thirdParty++
		if !controller[p] {
			t.Errorf("%s depends on %s, which the controller (cmd/konstapel) does not link yet; check go.mod, the image SBOM and license notices", self, p)
		}
	}
	if thirdParty == 0 {
		t.Fatal("no third-party dependencies listed; the check is not working")
	}
	for _, p := range list("-f", `{{join .Imports "\n"}}`, self) {
		switch p {
		case "os/exec", "net/http", "net", "os":
			t.Errorf("%s imports %s directly; signing must not run programs, read files, or open network clients", self, p)
		}
	}
}
