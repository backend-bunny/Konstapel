package installed_test

import (
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/crdtest"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

// add-external-assessment-providers 2.1: an AssessmentProvider registration
// never shadows a provider built into Konstapel. The CRD reserves konstapel
// and konstapel-* for built-in providers, and every provider this build
// compiles in (the production registry and the test-only reporting
// provider) has such a name, so a registration naming any of them is
// rejected by the API server before the controller sees it. A provider
// compiled into a later release must keep to the reserved names, or this
// test fails.
func TestRegistrationsCannotShadowBuiltInProviders(t *testing.T) {
	v := crdtest.Load(t, repoRoot(t)+"/config/crd/bases")["AssessmentProvider"]
	if v == nil {
		t.Fatal("no AssessmentProvider CRD")
	}
	registration := func(name string) map[string]any {
		return map[string]any{
			"apiVersion": "compliance.erenius.io/v1alpha1", "kind": "AssessmentProvider",
			"metadata": map[string]any{"name": "registration"},
			"spec": map[string]any{
				"provider": map[string]any{"name": name, "releaseDigest": "sha256:" + strings.Repeat("a", 64)},
				"endpoint": map[string]any{
					"service":     map[string]any{"namespace": "providers", "name": "provider", "port": int64(8443)},
					"serverName":  "provider.providers.svc",
					"serverTrust": map[string]any{"name": "provider-ca"},
				},
				"evaluatorEndpoint": map[string]any{
					"service":     map[string]any{"namespace": "providers", "name": "provider-evaluator", "port": int64(8443)},
					"serverName":  "provider-evaluator.providers.svc",
					"serverTrust": map[string]any{"name": "provider-ca"},
				},
				"compatibility": map[string]any{"protocol": "konstapel.provider.v1", "contractVersion": int64(1), "evaluatorVersion": int64(1), "payloadVersion": int64(1)},
				"capabilities":  []any{"Collect", "Evaluate"},
			},
		}
	}
	if errs := v.Validate(registration("example-reporting")); len(errs) > 0 {
		t.Fatalf("an external name is rejected: %v", errs.ToAggregate())
	}
	builtIn := []string{reporttest.Descriptor().Name}
	for _, d := range installed.Registry().Descriptors() {
		builtIn = append(builtIn, d.Name)
	}
	for _, name := range builtIn {
		errs := v.Validate(registration(name))
		if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), "reserved for built-in providers") {
			t.Errorf("a registration named after built-in provider %s: %v, want rejected as reserved", name, errs.ToAggregate())
		}
	}
}
