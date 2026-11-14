package charttest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/pruning"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/yaml"
)

// operatorCRDDir holds the Prometheus Operator CRDs, at the version pinned
// by KONSTAPEL_PROMETHEUS_OPERATOR_VERSION in scripts/runtime.env (task
// deps:check verifies their checksum). Rendered monitoring resources are
// validated against exactly these schemas.
const operatorCRDDir = "../../testdata/charts/prometheus-operator"

// operatorSchema validates one object against the v1 schema of an Operator
// CRD: types, enums, patterns and required fields, plus the unknown-field
// check the API server applies when pruning.
type operatorSchema struct {
	kind       string
	validator  validation.SchemaValidator
	structural *structuralschema.Structural
}

func loadOperatorSchema(t *testing.T, file, kind string) operatorSchema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(operatorCRDDir, file))
	if err != nil {
		t.Fatal(err)
	}
	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.UnmarshalStrict(raw, &crd); err != nil {
		t.Fatal(err)
	}
	if crd.Spec.Names.Kind != kind || crd.Spec.Group != "monitoring.coreos.com" {
		t.Fatalf("%s defines %s.%s", file, crd.Spec.Group, crd.Spec.Names.Kind)
	}
	for _, v := range crd.Spec.Versions {
		if v.Name != "v1" {
			continue
		}
		var internal apiextensions.JSONSchemaProps
		if err := apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(v.Schema.OpenAPIV3Schema, &internal, nil); err != nil {
			t.Fatal(err)
		}
		validator, _, err := validation.NewSchemaValidator(&internal)
		if err != nil {
			t.Fatal(err)
		}
		structural, err := structuralschema.NewStructural(&internal)
		if err != nil {
			t.Fatal(err)
		}
		return operatorSchema{kind: kind, validator: validator, structural: structural}
	}
	t.Fatalf("%s has no v1 schema", file)
	return operatorSchema{}
}

// problems returns every schema violation and unknown field of obj.
func (s operatorSchema) problems(t *testing.T, obj map[string]any) []string {
	t.Helper()
	// Pruning mutates its input; work on a copy.
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	var copied map[string]any
	if err := json.Unmarshal(raw, &copied); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range validation.ValidateCustomResource(field.NewPath(""), copied, s.validator) {
		out = append(out, e.Error())
	}
	for _, p := range pruning.PruneWithOptions(copied, s.structural, true, structuralschema.UnknownFieldPathOptions{TrackUnknownFieldPaths: true}) {
		out = append(out, "unknown field "+p)
	}
	return out
}

func (s operatorSchema) check(t *testing.T, obj map[string]any) {
	t.Helper()
	if got := s.problems(t, obj); len(got) > 0 {
		t.Errorf("%s does not satisfy the Operator schema: %v", s.kind, got)
	}
}

func serviceMonitorSchema(t *testing.T) operatorSchema {
	return loadOperatorSchema(t, "monitoring.coreos.com_servicemonitors.yaml", "ServiceMonitor")
}

func prometheusRuleSchema(t *testing.T) operatorSchema {
	return loadOperatorSchema(t, "monitoring.coreos.com_prometheusrules.yaml", "PrometheusRule")
}

// The schema check is not vacuous: it rejects wrong types, bad enums,
// missing required fields and fields the Operator does not define.
func TestOperatorSchemaRejectsInvalidObjects(t *testing.T) {
	sm := serviceMonitorSchema(t)
	valid := func() map[string]any {
		return map[string]any{
			"apiVersion": "monitoring.coreos.com/v1", "kind": "ServiceMonitor",
			"metadata": map[string]any{"name": "x"},
			"spec": map[string]any{
				"selector":  map[string]any{"matchLabels": map[string]any{"a": "b"}},
				"endpoints": []any{map[string]any{"port": "https", "interval": "30s"}},
			},
		}
	}
	sm.check(t, valid())
	for name, mutate := range map[string]func(map[string]any){
		"unknown endpoint field": func(o map[string]any) {
			at(o, "spec", "endpoints", 0).(map[string]any)["intervall"] = "30s"
		},
		"bad duration": func(o map[string]any) { at(o, "spec", "endpoints", 0).(map[string]any)["interval"] = "soon" },
		"wrong type":   func(o map[string]any) { at(o, "spec", "endpoints", 0).(map[string]any)["port"] = 443 },
		"bad scheme":   func(o map[string]any) { at(o, "spec", "endpoints", 0).(map[string]any)["scheme"] = "gopher" },
		"no selector":  func(o map[string]any) { delete(o["spec"].(map[string]any), "selector") },
	} {
		o := valid()
		mutate(o)
		if len(sm.problems(t, o)) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
}
