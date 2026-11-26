package v1alpha1_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/crdtest"
)

// add-external-assessment-providers 2.1: the generated AssessmentProvider
// CRD accepts a Service reference, explicit server name and controller-
// namespace trust, an expected provider identity and release digest, the
// four compatibility dimensions and allowed capabilities, and rejects
// malformed or cross-namespace references, built-in (reserved) names,
// compatibility changes and status that contradicts the registration. It
// carries no URL and no credential field anywhere. Who may write it, and
// that only the controller writes status, is RBAC and admission:
// assessment_provider_rbac_test.go here, internal/charttest, and
// TestLiveAssessmentProviderAPI against a real API server.

func assessmentProvider(t *testing.T) map[string]any {
	t.Helper()
	return obj(t, `apiVersion: compliance.erenius.io/v1alpha1
kind: AssessmentProvider
metadata: {name: example-reporting}
spec:
  provider:
    name: example-reporting
    releaseDigest: sha256:`+sha+`
  endpoint:
    service: {namespace: example-provider, name: example-reporting, port: 8443}
    serverName: example-reporting.example-provider.svc
    serverTrust: {name: example-reporting-ca}
  compatibility: {protocol: konstapel.provider.v1, contractVersion: 1, evaluatorVersion: 1, payloadVersion: 1}
  capabilities: [Collect, Evaluate]
`)
}

func TestAssessmentProviderCreateValidation(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["AssessmentProvider"]
	if v == nil {
		t.Fatal("no AssessmentProvider CRD")
	}

	o := assessmentProvider(t)
	if errs := v.Validate(o); len(errs) > 0 {
		t.Fatalf("minimal registration rejected: %v", errs.ToAggregate())
	}
	spec := o["spec"].(map[string]any)
	if spec["newRequests"] != "Enabled" {
		t.Errorf("newRequests defaulted to %v, want Enabled", spec["newRequests"])
	}
	if key := spec["endpoint"].(map[string]any)["serverTrust"].(map[string]any)["key"]; key != "ca.crt" {
		t.Errorf("serverTrust.key defaulted to %v, want ca.crt", key)
	}

	for name, patch := range map[string]string{
		"disabled":              `{"spec":{"newRequests":"Disabled"}}`,
		"every capability":      `{"spec":{"capabilities":["Collect","Scan","Evaluate"]}}`,
		"evaluate only":         `{"spec":{"capabilities":["Evaluate"]}}`,
		"scan only":             `{"spec":{"capabilities":["Scan"]}}`,
		"trust key":             `{"spec":{"endpoint":{"serverTrust":{"key":"bundle.pem"}}}}`,
		"dotted trust name":     `{"spec":{"endpoint":{"serverTrust":{"name":"provider.ca.v2"}}}}`,
		"single-label server":   `{"spec":{"endpoint":{"serverName":"provider"}}}`,
		"external server name":  `{"spec":{"endpoint":{"serverName":"reporting.provider.example.com"}}}`,
		"numeric label in name": `{"spec":{"endpoint":{"serverName":"r1.10.example.internal"}}}`,
		"highest port":          `{"spec":{"endpoint":{"service":{"port":65535}}}}`,
		"later versions":        `{"spec":{"compatibility":{"contractVersion":3,"evaluatorVersion":7,"payloadVersion":2}}}`,
		"name with konstapel":   `{"spec":{"provider":{"name":"acme-konstapel"}}}`,
		"longest server label":  `{"spec":{"endpoint":{"serverName":"` + strings.Repeat("a", 63) + `.svc"}}}`,
		"longest provider name": `{"spec":{"provider":{"name":"` + strings.Repeat("a", 63) + `"}}}`,
	} {
		o := assessmentProvider(t)
		mergePatch(t, o, patch)
		if errs := v.Validate(o); len(errs) > 0 {
			t.Errorf("%s rejected: %v", name, errs.ToAggregate())
		}
	}

	cases := []struct{ name, patch, expect string }{
		// Endpoint: a Service reference, never a URL.
		{"no endpoint", `{"spec":{"endpoint":null}}`, "spec.endpoint: Required"},
		{"no service", `{"spec":{"endpoint":{"service":null}}}`, "spec.endpoint.service: Required"},
		{"service without namespace", `{"spec":{"endpoint":{"service":{"namespace":null}}}}`, "spec.endpoint.service.namespace: Required"},
		{"service without name", `{"spec":{"endpoint":{"service":{"name":null}}}}`, "spec.endpoint.service.name: Required"},
		{"service without port", `{"spec":{"endpoint":{"service":{"port":null}}}}`, "spec.endpoint.service.port: Required"},
		{"uppercase service namespace", `{"spec":{"endpoint":{"service":{"namespace":"Provider"}}}}`, "spec.endpoint.service.namespace"},
		{"dotted service namespace", `{"spec":{"endpoint":{"service":{"namespace":"a.b"}}}}`, "spec.endpoint.service.namespace"},
		{"overlong service namespace", `{"spec":{"endpoint":{"service":{"namespace":"` + strings.Repeat("a", 64) + `"}}}}`, "spec.endpoint.service.namespace"},
		{"service name with a dot", `{"spec":{"endpoint":{"service":{"name":"reporting.svc"}}}}`, "spec.endpoint.service.name"},
		{"service name starting with a digit", `{"spec":{"endpoint":{"service":{"name":"1reporting"}}}}`, "spec.endpoint.service.name"},
		{"service name with a path", `{"spec":{"endpoint":{"service":{"name":"reporting/collect"}}}}`, "spec.endpoint.service.name"},
		{"port zero", `{"spec":{"endpoint":{"service":{"port":0}}}}`, "spec.endpoint.service.port"},
		{"port too high", `{"spec":{"endpoint":{"service":{"port":65536}}}}`, "spec.endpoint.service.port"},
		{"named port", `{"spec":{"endpoint":{"service":{"port":"grpc"}}}}`, "spec.endpoint.service.port"},

		// Server identity: an explicit DNS name.
		{"no server name", `{"spec":{"endpoint":{"serverName":null}}}`, "spec.endpoint.serverName: Required"},
		{"empty server name", `{"spec":{"endpoint":{"serverName":""}}}`, "spec.endpoint.serverName"},
		{"uppercase server name", `{"spec":{"endpoint":{"serverName":"Reporting.svc"}}}`, "spec.endpoint.serverName"},
		{"wildcard server name", `{"spec":{"endpoint":{"serverName":"*.example-provider.svc"}}}`, "spec.endpoint.serverName"},
		{"trailing dot", `{"spec":{"endpoint":{"serverName":"reporting.svc."}}}`, "spec.endpoint.serverName"},
		{"server name with a port", `{"spec":{"endpoint":{"serverName":"reporting.svc:8443"}}}`, "spec.endpoint.serverName"},
		{"server name as a URL", `{"spec":{"endpoint":{"serverName":"https://reporting.svc"}}}`, "spec.endpoint.serverName"},
		{"server name as a SPIFFE ID", `{"spec":{"endpoint":{"serverName":"spiffe://cluster.local/ns/p/sa/r"}}}`, "spec.endpoint.serverName"},
		{"IPv4 server name", `{"spec":{"endpoint":{"serverName":"10.96.0.12"}}}`, "serverName must be a DNS name, not an IP address"},
		{"IPv6 server name", `{"spec":{"endpoint":{"serverName":"fd00::12"}}}`, "spec.endpoint.serverName"},
		{"overlong server name label", `{"spec":{"endpoint":{"serverName":"` + strings.Repeat("a", 64) + `.svc"}}}`, "spec.endpoint.serverName"},
		{"overlong server name", `{"spec":{"endpoint":{"serverName":"` + strings.Repeat("a.", 127) + `ab"}}}`, "spec.endpoint.serverName"},

		// Server trust: roots in the controller namespace only.
		{"no server trust", `{"spec":{"endpoint":{"serverTrust":null}}}`, "spec.endpoint.serverTrust: Required"},
		{"trust without name", `{"spec":{"endpoint":{"serverTrust":{"name":null}}}}`, "spec.endpoint.serverTrust.name: Required"},
		{"trust in another namespace", `{"spec":{"endpoint":{"serverTrust":{"namespace":"example-provider"}}}}`, "references resolve in the controller namespace only"},
		{"trust in the controller namespace by name", `{"spec":{"endpoint":{"serverTrust":{"namespace":"konstapel-system"}}}}`, "references resolve in the controller namespace only"},
		{"uppercase trust name", `{"spec":{"endpoint":{"serverTrust":{"name":"Provider-CA"}}}}`, "spec.endpoint.serverTrust.name"},
		{"empty trust key", `{"spec":{"endpoint":{"serverTrust":{"key":""}}}}`, "spec.endpoint.serverTrust.key"},

		// Expected identity.
		{"no provider", `{"spec":{"provider":null}}`, "spec.provider: Required"},
		{"no provider name", `{"spec":{"provider":{"name":null}}}`, "spec.provider.name: Required"},
		{"no release digest", `{"spec":{"provider":{"releaseDigest":null}}}`, "spec.provider.releaseDigest: Required"},
		{"uppercase provider name", `{"spec":{"provider":{"name":"Example"}}}`, "spec.provider.name"},
		{"provider contract as name", `{"spec":{"provider":{"name":"example-reporting/v1"}}}`, "spec.provider.name"},
		{"dotted provider name", `{"spec":{"provider":{"name":"example.reporting"}}}`, "spec.provider.name"},
		{"overlong provider name", `{"spec":{"provider":{"name":"` + strings.Repeat("a", 64) + `"}}}`, "spec.provider.name"},
		{"built-in Kyverno", `{"spec":{"provider":{"name":"konstapel-kyverno"}}}`, "reserved for built-in providers"},
		{"built-in reporttest", `{"spec":{"provider":{"name":"konstapel-reporttest"}}}`, "reserved for built-in providers"},
		{"future built-in", `{"spec":{"provider":{"name":"konstapel-trivy"}}}`, "reserved for built-in providers"},
		{"reserved bare name", `{"spec":{"provider":{"name":"konstapel"}}}`, "reserved for built-in providers"},
		{"release tag", `{"spec":{"provider":{"releaseDigest":"v1.2.3"}}}`, "spec.provider.releaseDigest"},
		{"image reference", `{"spec":{"provider":{"releaseDigest":"ghcr.io/acme/reporting@sha256:` + sha + `"}}}`, "spec.provider.releaseDigest"},
		{"uppercase digest", `{"spec":{"provider":{"releaseDigest":"sha256:` + strings.ToUpper(sha) + `"}}}`, "spec.provider.releaseDigest"},
		{"short digest", `{"spec":{"provider":{"releaseDigest":"sha256:abcd"}}}`, "spec.provider.releaseDigest"},
		{"sha512 digest", `{"spec":{"provider":{"releaseDigest":"sha512:` + sha + sha + `"}}}`, "spec.provider.releaseDigest"},

		// Compatibility: four separate dimensions, each required.
		{"no compatibility", `{"spec":{"compatibility":null}}`, "spec.compatibility: Required"},
		{"no protocol", `{"spec":{"compatibility":{"protocol":null}}}`, "spec.compatibility.protocol: Required"},
		{"unknown protocol", `{"spec":{"compatibility":{"protocol":"konstapel.provider.v2"}}}`, "spec.compatibility.protocol: Unsupported value"},
		{"protocol revision as major", `{"spec":{"compatibility":{"protocol":"1"}}}`, "spec.compatibility.protocol: Unsupported value"},
		{"no contract version", `{"spec":{"compatibility":{"contractVersion":null}}}`, "spec.compatibility.contractVersion: Required"},
		{"no evaluator version", `{"spec":{"compatibility":{"evaluatorVersion":null}}}`, "spec.compatibility.evaluatorVersion: Required"},
		{"no payload version", `{"spec":{"compatibility":{"payloadVersion":null}}}`, "spec.compatibility.payloadVersion: Required"},
		{"contract version zero", `{"spec":{"compatibility":{"contractVersion":0}}}`, "spec.compatibility.contractVersion"},
		{"evaluator version zero", `{"spec":{"compatibility":{"evaluatorVersion":0}}}`, "spec.compatibility.evaluatorVersion"},
		{"payload version negative", `{"spec":{"compatibility":{"payloadVersion":-1}}}`, "spec.compatibility.payloadVersion"},

		// Capabilities.
		{"no capabilities", `{"spec":{"capabilities":null}}`, "spec.capabilities: Required"},
		{"empty capabilities", `{"spec":{"capabilities":[]}}`, "spec.capabilities"},
		{"unknown capability", `{"spec":{"capabilities":["Collect","Remediate"]}}`, "spec.capabilities[1]: Unsupported value"},
		{"wire capability name", `{"spec":{"capabilities":["CAPABILITY_COLLECT"]}}`, "spec.capabilities[0]: Unsupported value"},
		{"repeated capability", `{"spec":{"capabilities":["Collect","Collect"]}}`, "spec.capabilities[1]: Duplicate value"},
		{"unknown newRequests", `{"spec":{"newRequests":"Paused"}}`, "spec.newRequests: Unsupported value"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := assessmentProvider(t)
			mergePatch(t, o, c.patch)
			errs := v.Validate(o)
			if len(errs) == 0 {
				t.Fatal("accepted, want rejection")
			}
			if got := errs.ToAggregate().Error(); !strings.Contains(got, c.expect) {
				t.Fatalf("want %q, got %q", c.expect, got)
			}
		})
	}
}

// No URL, command, image, service account or credential can be carried by
// a registration: unsupported fields are pruned, so the stored object holds
// only the Service reference, names and versions, and its status only the
// observed identity.
func TestAssessmentProviderCarriesNoURLsOrCredentials(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["AssessmentProvider"]
	identity := `{"name":"example-reporting","releaseDigest":"sha256:` + sha + `","protocol":"konstapel.provider.v1",
		"protocolRevision":1,"contractVersion":1,"evaluatorVersion":1,"payloadVersion":1,"observedAt":"2026-11-26T10:00:00Z"}`
	o := assessmentProvider(t)
	mergePatch(t, o, `{"spec":{
		"url":"https://attacker.example",
		"image":"ghcr.io/acme/reporting:latest","command":["sh","-c","id"],"serviceAccountName":"cluster-admin",
		"provider":{"version":"1","token":"s3cr3t"},
		"endpoint":{"url":"https://attacker.example","insecureSkipVerify":true,"plaintext":true,
			"clientCertificate":{"name":"stolen"},"clientKey":"LS0t","caBundle":"LS0t",
			"service":{"url":"https://attacker.example"},"serverTrust":{"pem":"LS0t"}},
		"compatibility":{"protocolRevision":2},
		"credentials":{"secretName":"aws"}},
		"status":{"identity":{"clientKey":"LS0t","certificate":"LS0t"},"certificate":"LS0t","token":"s3cr3t"}}`)
	mergePatch(t, o, `{"status":{"identity":`+identity+`}}`)
	if errs := v.Validate(o); len(errs) > 0 {
		t.Fatal(errs.ToAggregate())
	}
	want := assessmentProvider(t)
	want["status"] = obj(t, `{"identity":`+identity+`}`)
	if errs := v.Validate(want); len(errs) > 0 {
		t.Fatal(errs.ToAggregate())
	}
	if !reflect.DeepEqual(o, want) {
		t.Fatalf("unsupported fields were kept:\n got %v\nwant %v", o, want)
	}
}

// The provider name, the release digest and every compatibility dimension
// are immutable, even for an administrator: a new release is a new
// registration. The endpoint, trust, capabilities and newRequests can change
// (a moved Service, a trust rotation, a drain).
func TestAssessmentProviderUpdateValidation(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["AssessmentProvider"]
	const immutable = "provider.name and compatibility are immutable; register an incompatible release as a new AssessmentProvider"
	for name, patch := range map[string]string{
		"provider name":     `{"spec":{"provider":{"name":"other-reporting"}}}`,
		"contract version":  `{"spec":{"compatibility":{"contractVersion":2}}}`,
		"evaluator version": `{"spec":{"compatibility":{"evaluatorVersion":2}}}`,
		"payload version":   `{"spec":{"compatibility":{"payloadVersion":2}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			old := assessmentProvider(t)
			o := copyObj(old)
			mergePatch(t, o, patch)
			errs := v.ValidateUpdate(o, old)
			if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), immutable) {
				t.Fatalf("want %q, got %v", immutable, errs.ToAggregate())
			}
		})
	}
	const release = "provider.releaseDigest is immutable; register a new release as a new AssessmentProvider"
	for name, patch := range map[string]string{
		"new release":           `{"spec":{"provider":{"releaseDigest":"sha256:` + strings.Repeat("b", 64) + `"}}}`,
		"new release and moved": `{"spec":{"provider":{"releaseDigest":"sha256:` + strings.Repeat("c", 64) + `"},"endpoint":{"service":{"name":"reporting-v2"}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			old := assessmentProvider(t)
			o := copyObj(old)
			mergePatch(t, o, patch)
			errs := v.ValidateUpdate(o, old)
			if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), release) {
				t.Fatalf("want %q, got %v", release, errs.ToAggregate())
			}
		})
	}
	for name, patch := range map[string]string{
		"unchanged release": `{"spec":{"provider":{"releaseDigest":"sha256:` + sha + `"}}}`,
		"trust rotation":    `{"spec":{"endpoint":{"serverTrust":{"name":"example-reporting-ca-2026","key":"roots.pem"}}}}`,
		"server name":       `{"spec":{"endpoint":{"serverName":"reporting.example-provider.svc.cluster.local"}}}`,
		"moved service":     `{"spec":{"endpoint":{"service":{"namespace":"providers","name":"reporting","port":9443}}}}`,
		"scan allowed":      `{"spec":{"capabilities":["Collect","Scan","Evaluate"]}}`,
		"collect revoked":   `{"spec":{"capabilities":["Evaluate"]}}`,
		"drained":           `{"spec":{"newRequests":"Disabled"}}`,
		"labels":            `{"metadata":{"labels":{"owner":"platform"}}}`,
	} {
		old := assessmentProvider(t)
		o := copyObj(old)
		mergePatch(t, o, patch)
		if errs := v.ValidateUpdate(o, old); len(errs) > 0 {
			t.Errorf("%s rejected: %v", name, errs.ToAggregate())
		}
	}
}

// Status is bounded and consistent with the registration: the observed
// identity names the registered provider at the registered compatibility,
// and nothing in it can carry an unbounded value.
func TestAssessmentProviderStatusValidation(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["AssessmentProvider"]
	identity := `{"name":"example-reporting","releaseDigest":"sha256:` + sha + `","protocol":"konstapel.provider.v1","protocolRevision":1,
		"contractVersion":1,"evaluatorVersion":1,"payloadVersion":1,"capabilities":["Collect","Evaluate"],"observedAt":"2026-11-26T10:00:00Z"}`
	condition := `{"type":"Available","status":"True","reason":"Compatible","message":"","lastTransitionTime":"2026-11-26T10:00:00Z"}`
	for name, status := range map[string]string{
		"empty":              `{}`,
		"observed":           `{"observedGeneration":3,"conditions":[` + condition + `],"identity":` + identity + `}`,
		"conditions only":    `{"observedGeneration":1,"conditions":[` + condition + `]}`,
		"later revision":     `{"identity":` + strings.Replace(identity, `"protocolRevision":1`, `"protocolRevision":4`, 1) + `}`,
		"other release seen": `{"identity":` + strings.Replace(identity, sha, strings.Repeat("c", 64), 1) + `}`,
	} {
		o := assessmentProvider(t)
		o["status"] = obj(t, status)
		if errs := v.Validate(o); len(errs) > 0 {
			t.Errorf("%s rejected: %v", name, errs.ToAggregate())
		}
	}
	nine := strings.TrimSuffix(strings.Repeat(condition+",", 9), ",")
	for i := range 9 {
		nine = strings.Replace(nine, `"type":"Available"`, `"type":"T`+string(rune('a'+i))+`"`, 1)
	}
	cases := []struct{ name, status, expect string }{
		{"identity of another provider", `{"identity":` + strings.Replace(identity, `"name":"example-reporting"`, `"name":"other"`, 1) + `}`, "status.identity must have the registration's provider name and compatibility"},
		{"identity at another contract", `{"identity":` + strings.Replace(identity, `"contractVersion":1`, `"contractVersion":2`, 1) + `}`, "status.identity must have the registration's provider name and compatibility"},
		{"identity at another evaluator", `{"identity":` + strings.Replace(identity, `"evaluatorVersion":1`, `"evaluatorVersion":2`, 1) + `}`, "status.identity must have the registration's provider name and compatibility"},
		{"identity at another payload", `{"identity":` + strings.Replace(identity, `"payloadVersion":1`, `"payloadVersion":2`, 1) + `}`, "status.identity must have the registration's provider name and compatibility"},
		{"identity without a release", `{"identity":` + strings.Replace(identity, `"releaseDigest":"sha256:`+sha+`",`, "", 1) + `}`, "status.identity.releaseDigest: Required"},
		{"identity with a tag", `{"identity":` + strings.Replace(identity, "sha256:"+sha, "latest", 1) + `}`, "status.identity.releaseDigest"},
		{"identity without a time", `{"identity":` + strings.Replace(identity, `,"observedAt":"2026-11-26T10:00:00Z"`, "", 1) + `}`, "status.identity.observedAt: Required"},
		{"identity revision zero", `{"identity":` + strings.Replace(identity, `"protocolRevision":1`, `"protocolRevision":0`, 1) + `}`, "status.identity.protocolRevision"},
		{"identity repeats a capability", `{"identity":` + strings.Replace(identity, `["Collect","Evaluate"]`, `["Collect","Collect"]`, 1) + `}`, "Duplicate value"},
		{"negative generation", `{"observedGeneration":-1}`, "status.observedGeneration"},
		{"too many conditions", `{"conditions":[` + nine + `]}`, "status.conditions"},
		{"repeated condition", `{"conditions":[` + condition + `,` + condition + `]}`, "Duplicate value"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := assessmentProvider(t)
			o["status"] = obj(t, c.status)
			errs := v.Validate(o)
			if len(errs) == 0 {
				t.Fatal("accepted, want rejection")
			}
			if got := errs.ToAggregate().Error(); !strings.Contains(got, c.expect) {
				t.Fatalf("want %q, got %q", c.expect, got)
			}
		})
	}
}
