package v1alpha1_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/crdtest"
)

func obj(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func copyObj(m map[string]any) map[string]any { return runtime.DeepCopyJSON(m) }

const request = `
apiVersion: compliance.erenius.io/v1alpha1
kind: AssessmentRequest
metadata: {name: r, namespace: team-a}
spec:
  bindingRef: {name: baseline-audit}
`

const bindingRun = `
apiVersion: compliance.erenius.io/v1alpha1
kind: AssessmentRun
metadata: {name: run}
spec:
  bindingRef: {name: baseline-audit}
  scope: Binding
`

const namespaceRun = `
apiVersion: compliance.erenius.io/v1alpha1
kind: AssessmentRun
metadata: {name: run}
spec:
  bindingRef: {name: baseline-audit}
  scope: Namespace
  request: {namespace: team-a, name: r, uid: req-uid}
  trigger: {type: Request}
`

func TestAssessmentExamplesAreAccepted(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	files, _ := filepath.Glob("../../testdata/assessments/examples/valid/*.yaml")
	if len(files) == 0 {
		t.Fatal("no assessment examples")
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			o := obj(t, string(raw))
			kind, _ := o["kind"].(string)
			if errs := crds[kind].Validate(o); len(errs) > 0 {
				t.Fatalf("rejected: %v", errs.ToAggregate())
			}
			var typed any = &v1alpha1.AssessmentRun{}
			if kind == "AssessmentRequest" {
				typed = &v1alpha1.AssessmentRequest{}
			}
			if err := yaml.UnmarshalStrict(raw, typed); err != nil {
				t.Fatalf("does not decode into Go type: %v", err)
			}
		})
	}
}

func TestAssessmentCreateValidation(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	cases := []struct {
		name, base, patch, expect string
	}{
		{"request needs binding", request, `{"spec": {"bindingRef": null}}`, "spec.bindingRef: Required value"},
		{"request empty binding name", request, `{"spec": {"bindingRef": {"name": ""}}}`, "spec.bindingRef.name"},
		{"request unknown field pruned, not scope", request, `{"spec": {"bindingRef": {"name": "b"}, "namespace": "team-b"}}`, ""},
		{"run needs scope", bindingRun, `{"spec": {"scope": null}}`, "spec.scope: Required value"},
		{"run invalid scope", bindingRun, `{"spec": {"bindingRef": {"name": "b"}, "scope": "Cluster"}}`, "spec.scope: Unsupported value"},
		{"binding run with request", bindingRun, `{"spec": {"request": {"namespace": "team-a", "name": "r", "uid": "u"}}}`, "request is required for and only allowed on Namespace scope"},
		{"namespace run without request", namespaceRun, `{"spec": {"request": null}}`, "request is required for and only allowed on Namespace scope"},
		{"namespace run without request trigger", namespaceRun, `{"spec": {"trigger": {"type": "Manual"}}}`, "Namespace scope requires a Request trigger"},
		{"binding run with request trigger", bindingRun, `{"spec": {"trigger": {"type": "Request"}}}`, "Namespace scope requires a Request trigger"},
		{"scheduled without time", bindingRun, `{"spec": {"trigger": {"type": "Scheduled"}}}`, "scheduledTime is required for and only allowed on Scheduled triggers"},
		{"manual with time", bindingRun, `{"spec": {"trigger": {"type": "Manual", "scheduledTime": "2026-11-05T00:00:00Z"}}}`, "scheduledTime is required for and only allowed on Scheduled triggers"},
		{"incomplete request ref", namespaceRun, `{"spec": {"request": {"namespace": "team-a", "name": "r"}}}`, "spec.request.uid: Required value"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := obj(t, c.base)
			mergePatch(t, o, c.patch)
			kind := o["kind"].(string)
			errs := crds[kind].Validate(o)
			if c.expect == "" {
				if len(errs) > 0 {
					t.Fatalf("rejected: %v", errs.ToAggregate())
				}
				if _, ok := o["spec"].(map[string]any)["namespace"]; ok {
					t.Fatal("unknown scope field was not pruned")
				}
				return
			}
			if len(errs) == 0 {
				t.Fatal("accepted, want rejection")
			}
			if got := errs.ToAggregate().Error(); !strings.Contains(got, c.expect) {
				t.Fatalf("want %q, got %q", c.expect, got)
			}
		})
	}
}

func TestAssessmentSpecsAreImmutable(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	cases := []struct{ name, base, patch string }{
		{"request binding", request, `{"spec": {"bindingRef": {"name": "other"}}}`},
		{"run binding", bindingRun, `{"spec": {"bindingRef": {"name": "other"}}}`},
		{"run scope widened", namespaceRun, `{"spec": {"scope": "Binding", "request": null, "trigger": null}}`},
		{"run request retargeted", namespaceRun, `{"spec": {"request": {"namespace": "team-b", "name": "r", "uid": "req-uid"}}}`},
		{"run trigger added", bindingRun, `{"spec": {"trigger": {"type": "Manual"}}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			old := obj(t, c.base)
			kind := old["kind"].(string)
			if errs := crds[kind].Validate(copyObj(old)); len(errs) > 0 {
				t.Fatal(errs.ToAggregate())
			}
			updated := copyObj(old)
			mergePatch(t, updated, c.patch)
			errs := crds[kind].ValidateUpdate(updated, copyObj(old))
			if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), "immutable") {
				t.Fatalf("spec change accepted: %v", errs.ToAggregate())
			}
		})
	}
	// Metadata-only updates (labels, finalizers) remain allowed.
	old := obj(t, bindingRun)
	updated := copyObj(old)
	mergePatch(t, updated, `{"metadata": {"labels": {"a": "b"}, "finalizers": ["compliance.erenius.io/retention"]}}`)
	if errs := crds["AssessmentRun"].ValidateUpdate(updated, copyObj(old)); len(errs) > 0 {
		t.Fatal(errs.ToAggregate())
	}
}

// TestResolvedFieldsAreStatusOnly checks that controller-resolved fields are
// absent from the user-writable spec and live behind the status subresource,
// which only the controller may write (see assessment_rbac_test.go).
func TestResolvedFieldsAreStatusOnly(t *testing.T) {
	resolved := []string{"uid", "namespaceUID", "binding", "scope", "summary", "publication", "window", "phase", "descriptorSha256", "enforcementRevisions", "artifactRef", "run"}
	for kind, file := range map[string]string{"AssessmentRequest": "assessmentrequests", "AssessmentRun": "assessmentruns"} {
		raw, err := os.ReadFile("../../config/crd/bases/compliance.erenius.io_" + file + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		crd := apiextensionsv1.CustomResourceDefinition{}
		if err = yaml.UnmarshalStrict(raw, &crd); err != nil {
			t.Fatal(err)
		}
		v := crd.Spec.Versions[0]
		if v.Subresources == nil || v.Subresources.Status == nil {
			t.Fatalf("%s must use the status subresource", kind)
		}
		spec := v.Schema.OpenAPIV3Schema.Properties["spec"]
		for _, f := range resolved {
			if f == "scope" && kind == "AssessmentRun" {
				continue // the requested scope kind, not the resolved scope
			}
			if _, ok := spec.Properties[f]; ok {
				t.Errorf("%s spec exposes controller-resolved field %q", kind, f)
			}
		}
		if p := v.Schema.OpenAPIV3Schema.Properties["spec"]; p.XValidations == nil {
			t.Errorf("%s spec has no immutability rule", kind)
		}
	}
}

func mergePatch(t *testing.T, o map[string]any, patch string) {
	t.Helper()
	var p map[string]any
	if err := yaml.Unmarshal([]byte(patch), &p); err != nil {
		t.Fatal(err)
	}
	var merge func(dst, src map[string]any)
	merge = func(dst, src map[string]any) {
		for k, v := range src {
			switch sv := v.(type) {
			case nil:
				delete(dst, k)
			case map[string]any:
				if dv, ok := dst[k].(map[string]any); ok && k != "request" && k != "bindingRef" && k != "trigger" {
					merge(dv, sv)
					continue
				}
				dst[k] = sv
			default:
				dst[k] = sv
			}
		}
	}
	merge(o, p)
}
