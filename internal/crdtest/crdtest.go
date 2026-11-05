// Package crdtest validates custom resources against generated CRDs the way
// the API server does on create, without a cluster. It is a test helper.
package crdtest

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	crdvalidation "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	schemaobjectmeta "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/objectmeta"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/pruning"
	apiservervalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// Validator reproduces the API server's create-time handling of a custom
// resource: null pruning, unknown-field pruning, defaulting, OpenAPI schema
// validation, and CEL validation rules. It needs no cluster.
type Validator struct {
	structural *structuralschema.Structural
	schema     apiservervalidation.SchemaValidator
	cel        *cel.Validator
}

// Load reads every CRD in dir, checks it as the API server would at creation,
// and returns a validator for each kind at the served v1alpha1 version.
func Load(t testing.TB, dir string) map[string]*Validator {
	t.Helper()
	scheme := runtime.NewScheme()
	install.Install(scheme)
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no CRDs found: %v", err)
	}
	out := map[string]*Validator{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		v1crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.UnmarshalStrict(raw, v1crd); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		scheme.Default(v1crd)
		crd := &apiextensions.CustomResourceDefinition{}
		if err := scheme.Convert(v1crd, crd, nil); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		// The same checks the API server applies when the CRD is created,
		// including CEL compilation and estimated cost limits.
		if errs := crdvalidation.ValidateCustomResourceDefinition(context.Background(), crd); len(errs) > 0 {
			t.Fatalf("%s is not a valid CRD: %v", f, errs.ToAggregate())
		}
		if crd.Spec.Group != v1alpha1.GroupVersion.Group || crd.Spec.Scope != apiextensions.ClusterScoped {
			t.Fatalf("%s: want cluster-scoped %s, got %s %s", f, v1alpha1.GroupVersion.Group, crd.Spec.Scope, crd.Spec.Group)
		}
		for _, ver := range crd.Spec.Versions {
			if ver.Name != v1alpha1.GroupVersion.Version {
				continue
			}
			props := crd.Spec.Validation
			if ver.Schema != nil {
				props = ver.Schema
			}
			s, err := structuralschema.NewStructural(props.OpenAPIV3Schema)
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			sv, _, err := apiservervalidation.NewSchemaValidator(props.OpenAPIV3Schema)
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			out[crd.Spec.Names.Kind] = &Validator{s, sv, cel.NewValidator(s, true, celconfig.PerCallLimit)}
		}
	}
	return out
}

// Validate defaults obj in place and returns every create-time field error.
func (v *Validator) Validate(obj map[string]any) field.ErrorList {
	defaulting.PruneNonNullableNullsWithoutDefaults(obj, v.structural)
	pruning.Prune(obj, v.structural, true)
	defaulting.Default(obj, v.structural)
	errs := apiservervalidation.ValidateCustomResource(nil, obj, v.schema)
	errs = append(errs, schemaobjectmeta.Validate(nil, obj, v.structural, true)...)
	celErrs, _ := v.cel.Validate(context.Background(), nil, v.structural, obj, nil, celconfig.RuntimeCELCostBudget)
	return append(errs, celErrs...)
}
