//go:build live

package controller

// Live CRD chart lifecycle (add-helm-oci-distribution 2.3, 2.4) with the
// pinned Helm against the disposable cluster:
//   - install the CRD chart (taking ownership of definitions an earlier test
//     applied directly, as an upgrade from kubectl-applied CRDs does);
//   - an unchanged-schema version bump and an additive schema change keep
//     every CRD's UID and an existing object's UID, spec, status, and
//     finalizers;
//   - uninstall keeps every CRD and the object;
//   - a release with another name is refused instead of adopting them;
//   - reinstall with the same name and namespace takes them back unchanged.
// Run through scripts/targeting-live.sh.

import (
	"fmt"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func (l *live) helm(args ...string) (string, error) {
	cmd := exec.CommandContext(l.ctx, "helm", append([]string{"--kubeconfig", os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"), "--kube-context", os.Getenv("KONSTAPEL_LIVE_CONTEXT")}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// chartCopy copies the CRD chart to a temporary directory, optionally with
// another version and an edit to one template.
func chartCopy(t *testing.T, version string, edit func(name string, body string) string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "konstapel-crds")
	if err := os.CopyFS(dir, os.DirFS(chartDir(t, "konstapel-crds"))); err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(dir, "Chart.yaml")
	raw, _ := os.ReadFile(meta)
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "version: ") {
			lines[i] = "version: " + version
		}
	}
	if err := os.WriteFile(meta, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		files, _ := filepath.Glob(filepath.Join(dir, "templates", "*.yaml"))
		for _, f := range files {
			body, _ := os.ReadFile(f)
			if err := os.WriteFile(f, []byte(edit(filepath.Base(f), string(body))), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return dir
}

func TestLiveCRDChartLifecycle(t *testing.T) {
	l := newLive(t)
	const release, ns = "konstapel-crds", "konstapel-crds-live"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	crdUIDs := func() map[string]string {
		var list apiextensionsv1.CustomResourceDefinitionList
		if err := l.c.List(l.ctx, &list); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, c := range list.Items {
			if c.Spec.Group == v1alpha1.GroupVersion.Group {
				out[c.Name] = string(c.UID)
			}
		}
		return out
	}
	files, _ := filepath.Glob(filepath.Join(chartDir(t, "konstapel-crds"), "templates/*.yaml"))

	// 1. Install. Earlier tests in the same cluster may have applied the
	// generated CRDs directly; the chart then takes ownership of them.
	args := []string{"install", release, chartCopy(t, "0.1.0", nil), "--namespace", ns, "--wait"}
	adopted := len(crdUIDs()) > 0
	// Directly applied definitions have other field managers. Server-side
	// apply would only share their fields and conflict on the next schema
	// change, so an adopted release uses client-side apply (the documented
	// adoption); later upgrades keep it through --server-side=auto.
	mode := []string{}
	if adopted {
		mode = []string{"--server-side=false"}
		args = append(args, "--take-ownership")
	}
	args = append(args, mode...)
	if out, err := l.helm(args...); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	installed := crdUIDs()
	if len(installed) != len(files) {
		t.Fatalf("installed CRDs %v, chart has %d", installed, len(files))
	}
	// Last: remove what this test created, including the retained CRDs, so
	// later tests in the same cluster (the installed-chart test) install
	// their own CRD release. Cleanups run in reverse, after the uninstall.
	// Every step is idempotent and repeated until the CRDs are gone: a
	// one-shot cleanup that ignored a transient API error under CI load left
	// an instance holding its finalizer, or a CRD never deleted, for good.
	t.Cleanup(func() {
		l.eventually("lifecycle CRDs removed", func() (bool, string) {
			ed := &v1alpha1.EvidenceDestination{}
			if err := l.c.Get(l.ctx, client.ObjectKey{Name: "crd-lifecycle"}, ed); err == nil && controllerutil.RemoveFinalizer(ed, "compliance.erenius.io/crd-lifecycle-test") {
				_ = l.c.Update(l.ctx, ed)
			}
			left := crdUIDs()
			if len(left) == 0 {
				return true, ""
			}
			// Delete what is not yet deleting, and say which CRDs are left
			// and why, so a recurrence is diagnosable.
			var detail []string
			for name := range left {
				crd := &apiextensionsv1.CustomResourceDefinition{}
				if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, crd); err != nil {
					detail = append(detail, name+": "+err.Error())
					continue
				}
				if crd.DeletionTimestamp.IsZero() {
					_ = l.c.Delete(l.ctx, crd)
				}
				var instances unstructured.UnstructuredList
				instances.SetGroupVersionKind(schema.GroupVersionKind{Group: crd.Spec.Group, Version: crd.Spec.Versions[0].Name, Kind: crd.Spec.Names.ListKind})
				_ = l.c.List(l.ctx, &instances)
				var held []string
				for _, o := range instances.Items {
					held = append(held, fmt.Sprintf("%s finalizers=%v deleting=%v", o.GetName(), o.GetFinalizers(), o.GetDeletionTimestamp() != nil))
				}
				detail = append(detail, fmt.Sprintf("%s deleting=%v finalizers=%v conditions=%v instances=%v", name, crd.DeletionTimestamp != nil, crd.Finalizers, toJSON(crd.Status.Conditions), held))
			}
			return false, fmt.Sprintf("%d left: %s", len(left), strings.Join(detail, "; "))
		})
	})
	t.Cleanup(func() { _, _ = l.helm("uninstall", release, "--namespace", ns) })
	l.record("installed", map[string]any{"crds": len(installed), "tookOwnership": adopted})

	// An object with spec, status, and a finalizer to follow through it all.
	ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "crd-lifecycle", Finalizers: []string{"compliance.erenius.io/crd-lifecycle-test"}},
		Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{Endpoint: "https://s3.example.internal", Bucket: "evidence", Region: "eu-north-1", Prefix: "crd-lifecycle",
			CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: "s3"}}}}}
	if err := l.c.Create(l.ctx, ed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		got := &v1alpha1.EvidenceDestination{}
		if l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got) == nil {
			controllerutil.RemoveFinalizer(got, "compliance.erenius.io/crd-lifecycle-test")
			_ = l.c.Update(l.ctx, got)
			_ = l.c.Delete(l.ctx, got)
		}
	})
	ed.Status.Conditions = []metav1.Condition{{Type: v1alpha1.ConditionDestinationReady, Status: metav1.ConditionTrue, Reason: "LifecycleTest", Message: "status survives", LastTransitionTime: metav1.Now()}}
	if err := l.c.Status().Update(l.ctx, ed); err != nil {
		t.Fatal(err)
	}
	snapshot := func() *v1alpha1.EvidenceDestination {
		got := &v1alpha1.EvidenceDestination{}
		if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got); err != nil {
			t.Fatalf("object lost: %v", err)
		}
		return got
	}
	before := snapshot()
	unchanged := func(step string) {
		t.Helper()
		if got := crdUIDs(); !equality.Semantic.DeepEqual(got, installed) {
			t.Fatalf("%s: CRDs replaced or removed: %v, want %v", step, got, installed)
		}
		got := snapshot()
		if got.UID != before.UID || !equality.Semantic.DeepEqual(got.Spec, before.Spec) || !equality.Semantic.DeepEqual(got.Status, before.Status) ||
			!equality.Semantic.DeepEqual(got.Finalizers, before.Finalizers) {
			t.Fatalf("%s: object changed: %s", step, toJSON(got))
		}
	}

	// 2. Unchanged-schema version bump.
	if out, err := l.helm("upgrade", release, chartCopy(t, "0.1.1", nil), "--namespace", ns, "--wait"); err != nil {
		t.Fatalf("version bump: %v\n%s", err, out)
	}
	unchanged("version bump")

	// 3. An additive, optional field in one schema.
	additive := chartCopy(t, "0.1.2", func(name, body string) string {
		if name != "compliance.erenius.io_evidencedestinations.yaml" {
			return body
		}
		return strings.Replace(body, "              orphan:\n", "              liveTestNote:\n                description: added by the CRD lifecycle test\n                type: string\n              orphan:\n", 1)
	})
	if out, err := l.helm("upgrade", release, additive, "--namespace", ns, "--wait"); err != nil {
		t.Fatalf("additive upgrade: %v\n%s", err, out)
	}
	unchanged("additive upgrade")
	crd := &apiextensionsv1.CustomResourceDefinition{}
	_ = l.c.Get(l.ctx, client.ObjectKey{Name: "evidencedestinations.compliance.erenius.io"}, crd)
	if _, ok := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"].Properties["liveTestNote"]; !ok {
		t.Fatal("additive schema change not applied")
	}
	l.record("upgraded", map[string]any{"versions": []string{"0.1.1", "0.1.2 (additive)"}})

	// 4. Uninstall keeps definitions and objects.
	if out, err := l.helm("uninstall", release, "--namespace", ns, "--wait"); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	unchanged("uninstall")

	// 5. A different release identity is refused, not adopted.
	out, err := l.helm("install", "other-crds", chartCopy(t, "0.1.0", nil), "--namespace", ns, "--wait")
	if err == nil {
		_, _ = l.helm("uninstall", "other-crds", "--namespace", ns)
		t.Fatal("a second release adopted the retained CRDs")
	}
	if !strings.Contains(out, "ownership") && !strings.Contains(out, "exists") {
		t.Fatalf("conflict not reported as ownership: %s", out)
	}
	unchanged("conflicting release")

	// 6. Reinstall with the same identity takes them back, current schema.
	if out, err := l.helm(append([]string{"install", release, chartCopy(t, "0.1.3", nil), "--namespace", ns, "--wait"}, mode...)...); err != nil {
		t.Fatalf("same-identity reinstall: %v\n%s", err, out)
	}
	unchanged("reinstall")
	_ = l.c.Get(l.ctx, client.ObjectKey{Name: "evidencedestinations.compliance.erenius.io"}, crd)
	if _, ok := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"].Properties["liveTestNote"]; ok {
		t.Fatal("reinstall did not apply the chart's schema")
	}
	l.record("retained", map[string]any{"uninstall": "kept", "conflictingRelease": "refused", "reinstall": "same UIDs"})
}
