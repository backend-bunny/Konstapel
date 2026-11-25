package collector

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// The helpers below give the external tests of this directory (package
// collector_test) controller packages to validate with the storage
// backend, which imports this package and so cannot be imported here.

// ExportedPackage is a binding-scope Assessment package of a capture with
// failures, exported from the vendored content.
func ExportedPackage(t *testing.T) (string, publication.Descriptor) {
	t.Helper()
	req, d := exported(t)
	return req.Out, d
}

// NamespacePackage is a namespace-scope Assessment package of a projected
// capture.
func NamespacePackage(t *testing.T) (string, publication.Descriptor) {
	t.Helper()
	c, _ := mixedCapture(t)
	p, err := Project(c, "uid-shop-dev")
	if err != nil {
		t.Fatal(err)
	}
	run := publication.RunRef{ClusterID: p.Cluster, BindingUID: "uid-audit-all", RunUID: "run-ns"}
	req := ExportRequest{Root: repo(t), Out: filepath.Join(t.TempDir(), "pkg"), Run: run, BindingConfiguration: "b",
		Scope: publication.Scope{Kind: publication.ScopeNamespace, ClusterID: run.ClusterID, BindingUID: run.BindingUID,
			Request:       &publication.RequestRef{Namespace: "shop-dev", Name: "r", UID: "req-1", NamespaceUID: "uid-shop-dev"},
			NamespaceUIDs: []string{"uid-shop-dev"}, Revision: "s"},
		Capture: p, Evaluation: evaluate(t, p, nil, maxAge)}
	d, err := Export(context.Background(), req)
	if err != nil || d.PackageKind != publication.KindAssessment {
		t.Fatalf("%v %+v", err, d.Diagnostic)
	}
	return req.Out, d
}

// Rehash rewrites a package's descriptor inventory after an edit.
func Rehash(t *testing.T, dir string, d publication.Descriptor) { rehash(t, dir, d) }
