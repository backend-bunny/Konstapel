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
	dir, d := namespacePackage(t, nil)
	if d.PackageKind != publication.KindAssessment {
		t.Fatalf("%+v", d.Diagnostic)
	}
	return dir, d
}

// NamespaceDiagnosticPackage is a namespace-scope Diagnostic package of a
// projected capture whose run content failed with failure.
func NamespaceDiagnosticPackage(t *testing.T, failure *ContentFailure) (string, publication.Descriptor) {
	t.Helper()
	dir, d := namespacePackage(t, &RunContent{Failure: failure})
	if d.PackageKind != publication.KindDiagnostic {
		t.Fatalf("not a diagnostic package: %+v", d)
	}
	return dir, d
}

func namespacePackage(t *testing.T, content *RunContent) (string, publication.Descriptor) {
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
		Capture: p, Evaluation: evaluate(t, p, nil, maxAge), Content: content}
	d, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return req.Out, d
}

// Rehash rewrites a package's descriptor inventory after an edit.
func Rehash(t *testing.T, dir string, d publication.Descriptor) { rehash(t, dir, d) }
