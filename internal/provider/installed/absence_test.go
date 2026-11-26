package installed_test

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

// The test-only reporting provider is absent from what Konstapel ships
// (add-assessment-provider-contract 4.3), checked in the artifacts
// themselves rather than in the import graph alone. The rendered charts
// are checked by internal/charttest (TestChartsShipNoTestOnlyProvider) and
// the built image by scripts/image/test.sh.

// testOnlyMarkers identify the test-only provider and the conformance
// harness in an artifact: their package paths, which a linked package
// leaves in a Go binary's symbols, and the provider's identities.
var testOnlyMarkers = []string{
	module + "/internal/provider/reporttest",
	module + "/internal/provider/conformance",
	reporttest.Name,
	reporttest.Postures().Group,
	reporttest.CheckKind,
}

// referenceMarkers identify the example reporting provider of
// examples/external-provider/reporting (add-external-assessment-providers
// 5.1): its provider name, which its check group, image and chart names
// contain, its check group and its module path. It is a test/demo artifact
// like the test-only provider: nothing Konstapel ships names it, so no
// default installation registers or selects it.
var referenceMarkers = []string{"example-reporting", "reporting.example.test", "example.com/konstapel-reporting"}

func markersIn(b []byte) []string {
	var found []string
	for _, m := range append(slices.Clone(testOnlyMarkers), referenceMarkers...) {
		if bytes.Contains(b, []byte(m)) {
			found = append(found, m)
		}
	}
	return found
}

// buildShipped builds a main package as scripts/build.sh does for task
// build and the image. The image recipe adds CGO_ENABLED=0 and -trimpath,
// which change file paths but neither the linked packages nor their
// import paths in the symbols; the built image itself is scanned by
// scripts/image/test.sh.
func buildShipped(t *testing.T, pkg string) []byte {
	t.Helper()
	bin := filepath.Join(t.TempDir(), filepath.Base(pkg))
	cmd := exec.Command("go", "build", "-mod=readonly", "-o", bin, pkg)
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, out)
	}
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Neither shipped binary, built as it ships, carries the
// test-only provider or the harness. The scan is real: a binary that links
// the test-only provider shows its markers.
func TestShippedBinariesCarryNoTestOnlyProvider(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the shipped binaries")
	}
	linked := markersIn(buildShipped(t, "./internal/provider/reporttest/testdata/linked"))
	for _, want := range []string{module + "/internal/provider/reporttest", reporttest.Name} {
		if !strings.Contains(strings.Join(linked, "\n"), want) {
			t.Fatalf("a binary linking the test-only provider shows %v, not %s; the scan is not working", linked, want)
		}
	}
	for _, pkg := range []string{"./cmd/konstapel", "./cmd/konstapel-provider"} {
		if found := markersIn(buildShipped(t, pkg)); len(found) > 0 {
			t.Errorf("%s carries test-only markers %v", pkg, found)
		}
	}
}

// The rest of the image payload carries none either: the content tree, the
// notices and the script that writes the C2P plugin manifest (whose
// provider is the installed Kyverno one).
func TestImagePayloadCarriesNoTestOnlyProvider(t *testing.T) {
	root := repoRoot(t)
	scanned := 0
	err := filepath.WalkDir(filepath.Join(root, "content"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		scanned++
		if found := markersIn(raw); len(found) > 0 {
			t.Errorf("%s carries test-only markers %v", p, found)
		}
		return nil
	})
	if err != nil || scanned == 0 {
		t.Fatalf("content tree: %d files, %v", scanned, err)
	}
	for _, f := range []string{"LICENSE", "NOTICE", "scripts/build.sh", "melange.yaml", "apko.yaml"} {
		raw, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		if found := markersIn(raw); len(found) > 0 {
			t.Errorf("%s carries test-only markers %v", f, found)
		}
	}
	build, err := os.ReadFile(filepath.Join(root, "scripts/build.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(build), `id:"`+assessment.ProviderID+`"`) {
		t.Errorf("scripts/build.sh does not write the %s C2P plugin manifest", assessment.ProviderID)
	}
}

// Every distributable bundle, built as it is published, names an installed
// production provider and carries nothing of the test-only one.
func TestShippedBundlesNameNoTestOnlyProvider(t *testing.T) {
	root := repoRoot(t)
	defs, err := filepath.Glob(filepath.Join(root, "bundles/*/definition.json"))
	if err != nil || len(defs) == 0 {
		t.Fatalf("no bundle definitions: %v", err)
	}
	r := installed.Registry()
	for _, f := range defs {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if found := markersIn(raw); len(found) > 0 {
			t.Errorf("%s carries test-only markers %v", f, found)
		}
		def, err := bundle.LoadDefinition(raw)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		def.Source.Revision = strings.Repeat("c", 40)
		a, err := bundle.Build(def, os.DirFS(root), time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		d, serr := r.Lookup(a.Descriptor.Compatibility.Provider)
		if serr != nil || d.TestOnly {
			t.Errorf("%s names provider %s, which is not an installed production provider: %v", f, a.Descriptor.Compatibility.Provider, serr)
		}
		_, files, err := bundle.Unpack(a.Layer)
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: unpack: %d files, %v", f, len(files), err)
		}
		for name, file := range files {
			if found := markersIn(file.Data); len(found) > 0 {
				t.Errorf("%s: bundle file %s carries test-only markers %v", f, name, found)
			}
		}
	}
	sources, err := os.ReadFile(filepath.Join(root, "bundles/official-sources.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if found := markersIn(sources); len(found) > 0 {
		t.Errorf("bundles/official-sources.yaml carries test-only markers %v", found)
	}
}

// The example reporting provider is not compiled in: its contract resolves
// to no installed provider, so only an administrator's AssessmentProvider
// registration could ever select it, and no shipped artifact carries one
// (the scans above and internal/charttest TestChartsRegisterNoReferenceProvider).
func TestReferenceProviderIsNotInstalled(t *testing.T) {
	r := installed.Registry()
	if d, err := r.Lookup("example-reporting/v1"); err == nil {
		t.Fatalf("example-reporting/v1 resolves to installed provider %+v", d)
	}
	for _, d := range r.Descriptors() {
		if found := markersIn([]byte(d.Name + " " + d.Contract())); len(found) > 0 {
			t.Errorf("installed provider %s carries markers %v", d.Name, found)
		}
	}
}
