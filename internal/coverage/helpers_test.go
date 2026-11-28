package coverage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
)

const repo = "../.."

// Paths of the official NIST fixtures inside the shipped bundles.
const (
	nistDir       = "content/upstream/nist/nist.gov/SP800-53/rev5/json/"
	moderatePath  = nistDir + "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"
	catalogPath   = nistDir + "NIST_SP-800-53_rev5_catalog.json"
	privileged    = "konstapel-privileged-containers"
	hardening     = "konstapel-linux-hardening"
	privPolicy    = "disallow-privileged-containers"
	moderateCount = 287
)

var (
	schemasOnce sync.Once
	schemas     map[string][]byte
)

// trustedSchemas are the controller's own OSCAL schemas.
func trustedSchemas(t testing.TB) map[string][]byte {
	t.Helper()
	schemasOnce.Do(func() {
		schemas = map[string][]byte{}
		for _, v := range SupportedOSCAL {
			b, err := os.ReadFile(filepath.Join(repo, "content/schemas/oscal-"+v+".json"))
			if err != nil {
				panic(err)
			}
			schemas[v] = b
		}
	})
	return schemas
}

func opts(t testing.TB) Options { return Options{Schemas: trustedSchemas(t)} }

var (
	builtMu sync.Mutex
	built   = map[string]Content{}
)

// officialDefinition is the definition of the latest released version of
// name. The hardening bundle's next version (0.2.0, the split revision) is
// not released; its released 0.1.0 definition is kept beside it.
func officialDefinition(name string) string {
	if name == hardening {
		return filepath.Join("bundles", name, "released", "0.1.0.json")
	}
	return filepath.Join("bundles", name, "definition.json")
}

// official builds the released definition of name from this repository, as
// the release workflow did, and returns its verified content handle.
func official(t testing.TB, name string) Content {
	t.Helper()
	return fromDefinition(t, officialDefinition(name))
}

// fromDefinition builds the definition at the repository-relative path def
// and returns its verified content handle.
func fromDefinition(t testing.TB, def string) Content {
	t.Helper()
	builtMu.Lock()
	defer builtMu.Unlock()
	if c, ok := built[def]; ok {
		return c
	}
	raw, err := os.ReadFile(filepath.Join(repo, def))
	if err != nil {
		t.Fatal(err)
	}
	d0, err := bundle.LoadDefinition(raw)
	if err != nil {
		t.Fatal(err)
	}
	d0.Source.Revision = strings.Repeat("e", 40)
	a, err := bundle.Build(d0, os.DirFS(repo), time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	d, payload, err := bundle.Unpack(a.Layer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := FromDescriptor(v1alpha1.BundleReference{Name: d.Name, Digest: a.ManifestDigest}, d, payload)
	if err != nil {
		t.Fatal(err)
	}
	built[def] = c
	return c
}

// selecting selects the named policies of c.
func selecting(c Content, names ...string) Selection {
	s := Selection{Bundle: c.Bundle, Policies: []SelectedPolicy{}}
	for _, n := range names {
		s.Policies = append(s.Policies, SelectedPolicy{Name: n})
	}
	return s
}

// fixture is synthetic content: files by path, declared entry points and
// policies. Its handle inventories exactly its files.
type fixture struct {
	files    map[string][]byte
	oscal    []bundle.OSCALDocument
	policies []bundle.Policy
}

func (f *fixture) put(p string, v any) {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		panic(err)
	}
	f.files[p] = b
}

func (f *fixture) content(t testing.TB) Content {
	t.Helper()
	d := &bundle.Descriptor{Name: "fixture", OSCAL: f.oscal, Policies: f.policies}
	payload := fstest.MapFS{}
	for p, b := range f.files {
		payload[p] = &fstest.MapFile{Data: b}
		d.Files = append(d.Files, bundle.File{Path: p, Size: int64(len(b)), SHA256: strings.TrimPrefix(digest(b), "sha256:")})
	}
	c, err := FromDescriptor(v1alpha1.BundleReference{Name: "fixture", Digest: "sha256:" + strings.Repeat("f", 64)}, d, payload)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// limitationCodes are the codes of ls, in order.
func limitationCodes(ls []Limitation) []string {
	var out []string
	for _, l := range ls {
		out = append(out, l.Code)
	}
	return out
}

func hasCode(ls []Limitation, code string) bool {
	for _, l := range ls {
		if l.Code == code {
			return true
		}
	}
	return false
}

func unresolved(t *testing.T, err error) *UnresolvedError {
	t.Helper()
	ue, ok := err.(*UnresolvedError)
	if !ok {
		t.Fatalf("want *UnresolvedError, got %T %v", err, err)
	}
	return ue
}
