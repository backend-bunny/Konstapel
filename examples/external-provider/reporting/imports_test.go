// Package quickstart holds module-level checks of the independent example.
package quickstart

import (
	"os/exec"
	"strings"
	"testing"
)

// konstapel is the module path of the repository the example builds on.
const konstapel = "github.com/backend-bunny/Konstapel"

// public are the only Konstapel packages an external provider may import.
var public = map[string]bool{
	konstapel + "/pkg/providerapi/v1": true,
	konstapel + "/pkg/providerkit":    true,
}

// TestOnlyPublicKitImports fails when any package or test of this module
// depends, directly or transitively, on a Konstapel package other than the
// public protocol types and kit, in particular anything under internal/ or
// api/.
func TestOnlyPublicKitImports(t *testing.T) {
	out, err := exec.Command("go", "list", "-mod=readonly", "-deps", "-test", "-f", "{{.ImportPath}}", "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	seen := map[string]bool{}
	for _, path := range strings.Fields(string(out)) {
		if path != konstapel && !strings.HasPrefix(path, konstapel+"/") {
			continue
		}
		seen[path] = true
		rest := strings.TrimPrefix(path, konstapel+"/")
		switch {
		case strings.HasPrefix(rest, "internal/") || rest == "internal":
			t.Errorf("imports internal package %s", path)
		case strings.HasPrefix(rest, "api/") || rest == "api":
			t.Errorf("imports API package %s", path)
		case !public[path]:
			t.Errorf("imports %s, which is not the public protocol or kit", path)
		}
	}
	for path := range public {
		if !seen[path] {
			t.Errorf("does not import %s: the check would pass vacuously", path)
		}
	}
}
