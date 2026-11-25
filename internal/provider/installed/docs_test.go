package installed_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
)

var verifiedBlock = regexp.MustCompile("(?s)<!-- verified: ([a-z-]+) -->\n```json\n(.*?)\n```")

// documentedExamples computes every example docs/assessment-providers.md
// shows, from the installed registry and the Kyverno collection adapter.
func documentedExamples(t *testing.T) map[string]any {
	r := installed.Registry()
	_, rejected := r.Select(provider.Selection{Provider: "konstapel-kyverno/v1", Mode: v1alpha1.ModeDeny, Checks: []provider.CheckSelection{
		{Name: "disallow-privileged-containers", Kind: kyverno.CheckKind, Parameters: &apiextensionsv1.JSON{Raw: []byte(`{"allowPrivileged":true}`)}},
		{Name: "image-vulnerabilities", Kind: "scanner.example.io/v1/ImageReport"},
	}})
	_, unknown := r.Select(provider.Selection{Provider: "example-scanner/v1", Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{
		{Name: "disallow-privileged-containers", Kind: kyverno.CheckKind}}})
	captures, rejectedCaptures := captureExamples(t)
	return map[string]any{
		"kyverno-descriptor":             kyverno.Descriptor(),
		"installed-contracts":            r.Contracts(),
		"rejected-selection":             rejected,
		"unknown-provider":               unknown,
		"kyverno-collection-requests":    collectionRequests(t),
		"kyverno-collection-pages":       collectionPages(t),
		"reporttest-collection-requests": reportingRequests(t),
		"collection-limits":              documentedLimits(),
		"capability-matrix":              capabilityMatrix(t),
		"controller-role-writes":         controllerRoleWrites(t),
		"capture-headers":                captures,
		"capture-rejections":             rejectedCaptures,
		"retained-interpretations":       retainedInterpretations(t),
		"earlier-release-readers":        earlierReaders(t),
	}
}

// collectionRequests are the API requests the Kyverno collection adapter
// makes for a scope of two namespaces, seen by the recording fixture over a
// cluster that also has reports outside the scope.
func collectionRequests(t *testing.T) []conformance.Call {
	t.Helper()
	gvk := schema.GroupVersionKind{Group: "wgpolicyk8s.io", Version: "v1alpha2", Kind: "PolicyReport"}
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(gvk, meta.RESTScopeNamespace)
	var objs []client.Object
	for _, ns := range []string{"a", "b", "c"} {
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(gvk)
		u.SetNamespace(ns)
		u.SetName("r")
		objs = append(objs, u)
	}
	rec := conformance.NewRecordingClient(fake.NewClientBuilder().WithRESTMapper(mapper).WithObjects(objs...).Build())
	scope := provider.Scope{Cluster: "c", Namespaces: []provider.Namespace{{Name: "a", UID: "uid-a"}, {Name: "b", UID: "uid-b"}}}
	// The controller's path: the adapter under the host's bounds.
	reports, limits, err := provider.Collect(context.Background(), rec, kyverno.Descriptor(), scope, provider.DefaultLimits(),
		func(ctx context.Context, src provider.Sources) ([]assessment.Object, []string, error) {
			return kyverno.Collect(ctx, scope, src)
		})
	if err != nil || len(reports) != 2 || len(limits) != 0 {
		t.Fatalf("collection: %d reports, %v, %v", len(reports), limits, err)
	}
	return rec.Calls()
}

func TestDocumentedExamples(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join(repoRoot(t), "docs/assessment-providers.md"))
	if err != nil {
		t.Fatal(err)
	}
	want := documentedExamples(t)
	seen := map[string]bool{}
	for _, m := range verifiedBlock.FindAllSubmatch(doc, -1) {
		name := string(m[1])
		seen[name] = true
		actual, ok := want[name]
		if !ok {
			t.Errorf("documented example %q is not verified by this test", name)
			continue
		}
		var documented, computed any
		if err := json.Unmarshal(m[2], &documented); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		b, _ := json.Marshal(actual)
		_ = json.Unmarshal(b, &computed)
		if !reflect.DeepEqual(documented, computed) {
			pretty, _ := json.MarshalIndent(actual, "", "  ")
			t.Errorf("documented %s differs from the implementation; it is:\n%s", name, pretty)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("example %s is not in the guide", name)
		}
	}
}

// Every test the guide cites as a guarantee exists.
func TestDocumentedTestsExist(t *testing.T) {
	root := repoRoot(t)
	doc, err := os.ReadFile(filepath.Join(root, "docs/assessment-providers.md"))
	if err != nil {
		t.Fatal(err)
	}
	cited := regexp.MustCompile("`(Test[A-Za-z]+)`").FindAllStringSubmatch(string(doc), -1)
	if len(cited) == 0 {
		t.Fatal("the guide cites no tests; the check is not working")
	}
	var sources strings.Builder
	files, _ := filepath.Glob(filepath.Join(root, "internal/provider/*/*_test.go"))
	more, _ := filepath.Glob(filepath.Join(root, "internal/provider/*_test.go"))
	// The collection characterization and the provider watches live with
	// the controller; provider availability with the capability monitor.
	host, _ := filepath.Glob(filepath.Join(root, "internal/controller/*_test.go"))
	capabilities, _ := filepath.Glob(filepath.Join(root, "internal/capability/*_test.go"))
	// The collection limit flags and chart values.
	flags, _ := filepath.Glob(filepath.Join(root, "cmd/konstapel/*_test.go"))
	chart, _ := filepath.Glob(filepath.Join(root, "internal/charttest/*_test.go"))
	// The capture boundary lives with the collector, package validation
	// with the storage backend.
	captures, _ := filepath.Glob(filepath.Join(root, "internal/collector/*_test.go"))
	storage, _ := filepath.Glob(filepath.Join(root, "internal/s3store/*_test.go"))
	// Run content replay through the complete bundle stack, and the
	// package descriptor's closed set of file roles.
	stack, _ := filepath.Glob(filepath.Join(root, "internal/bundle/stack/*_test.go"))
	descriptors, _ := filepath.Glob(filepath.Join(root, "internal/publication/*_test.go"))
	for _, f := range slices.Concat(files, more, host, capabilities, flags, chart, captures, storage, stack, descriptors) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		sources.Write(b)
	}
	for _, c := range cited {
		if !strings.Contains(sources.String(), "func "+c[1]+"(") {
			t.Errorf("the guide cites %s, which does not exist", c[1])
		}
	}
}
