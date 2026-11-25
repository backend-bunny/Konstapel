package charttest

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/internal/exception"
)

// webhookConfigs decodes the rendered exception webhook configurations.
func webhookConfigs(t *testing.T, docs []map[string]any) (*admissionregistrationv1.MutatingWebhookConfiguration, *admissionregistrationv1.ValidatingWebhookConfiguration) {
	t.Helper()
	var m *admissionregistrationv1.MutatingWebhookConfiguration
	var v *admissionregistrationv1.ValidatingWebhookConfiguration
	for _, d := range docs {
		var into any
		switch d["kind"] {
		case "MutatingWebhookConfiguration":
			m = &admissionregistrationv1.MutatingWebhookConfiguration{}
			into = m
		case "ValidatingWebhookConfiguration":
			v = &admissionregistrationv1.ValidatingWebhookConfiguration{}
			into = v
		default:
			continue
		}
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, into); err != nil {
			t.Fatal(err)
		}
	}
	return m, v
}

// sourceWebhooks decodes config/webhook/exceptions.yaml, the owner's
// manifest the chart must render unchanged.
func sourceWebhooks(t *testing.T) (*admissionregistrationv1.MutatingWebhookConfiguration, *admissionregistrationv1.ValidatingWebhookConfiguration) {
	t.Helper()
	raw, err := os.ReadFile("../../config/webhook/exceptions.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dec := utilyaml.NewYAMLOrJSONDecoder(strings.NewReader(string(raw)), 4096)
	m, v := &admissionregistrationv1.MutatingWebhookConfiguration{}, &admissionregistrationv1.ValidatingWebhookConfiguration{}
	if err := dec.Decode(m); err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(v); err != nil {
		t.Fatal(err)
	}
	return m, v
}

// The exception admission webhooks (docs/charts.md, "Exception admission
// webhooks"), with exceptions.webhooks.enabled, in each TLS mode: both
// configurations are config/webhook/exceptions.yaml unchanged except for
// the chart labels and the CA, so they pass the controller's own
// VerifyProtection (failurePolicy Fail, CREATE and UPDATE of v1alpha1
// complianceexceptions, no selectors or match conditions); they call the
// rendered konstapel-webhook Service, which selects every controller
// replica on its webhook port; every replica serves them with the mounted
// certificate, and the CA comes from cert-manager's injection
// (certManager) or the operator's caBundle (secret), never both.
func TestRuntimeChartExceptionWebhooks(t *testing.T) {
	srcM, srcV := sourceWebhooks(t)
	for name, c := range map[string]struct {
		set    []string
		secret string
		issuer string
	}{
		"chart CA":                         {set: []string{"exceptions.webhooks.enabled=true"}, secret: "konstapel-webhook-tls", issuer: "konstapel-ca"},
		"chart CA, revocation processing":  {set: []string{"exceptions.webhooks.enabled=true", "exceptions.revocationProcessing.enabled=true"}, secret: "konstapel-webhook-tls", issuer: "konstapel-ca"},
		"chart CA, no download or metrics": {set: []string{"exceptions.webhooks.enabled=true", "download.enabled=false"}, secret: "konstapel-webhook-tls", issuer: "konstapel-ca"},
		"platform issuer":                  {set: []string{"exceptions.webhooks.enabled=true", "tls.certManager.issuerRef.name=platform-ca", "tls.certManager.issuerRef.kind=ClusterIssuer"}, secret: "konstapel-webhook-tls", issuer: "platform-ca"},
		"operator TLS":                     {set: append([]string{"tls.mode=secret", "tls.secret.name=konstapel-tls"}, operatorWebhookTLS...), secret: "konstapel-webhook-tls"},
	} {
		t.Run(name, func(t *testing.T) {
			docs, out, err := render(t, controllerNS, append([]string{"image.digest=" + digest}, c.set...)...)
			if err != nil {
				t.Fatal(out)
			}
			m, v := webhookConfigs(t, docs)
			if m == nil || v == nil {
				t.Fatalf("webhook configurations %v %v", m, v)
			}
			// The controller's own check accepts exactly what is rendered.
			reader := fake.NewClientBuilder().WithScheme(func() *runtime.Scheme {
				s := runtime.NewScheme()
				_ = admissionregistrationv1.AddToScheme(s)
				return s
			}()).WithObjects(m.DeepCopy(), v.DeepCopy()).Build()
			if err := exception.VerifyProtection(context.Background(), reader); err != nil {
				t.Fatalf("VerifyProtection of the rendered webhooks: %v", err)
			}
			// Unchanged from the owner's manifest apart from labels and CA.
			operatorCA := c.issuer == ""
			for _, w := range m.Webhooks {
				if got := string(w.ClientConfig.CABundle); operatorCA != (got != "") || (operatorCA && got != fixtureCA) {
					t.Errorf("mutating caBundle %q", got)
				}
			}
			for _, w := range v.Webhooks {
				if got := string(w.ClientConfig.CABundle); operatorCA != (got != "") || (operatorCA && got != fixtureCA) {
					t.Errorf("validating caBundle %q", got)
				}
			}
			gotM, gotV := m.DeepCopy(), v.DeepCopy()
			gotM.Annotations, gotM.Labels, gotV.Annotations, gotV.Labels = nil, nil, nil, nil
			for i := range gotM.Webhooks {
				gotM.Webhooks[i].ClientConfig.CABundle = nil
			}
			for i := range gotV.Webhooks {
				gotV.Webhooks[i].ClientConfig.CABundle = nil
			}
			if !reflect.DeepEqual(gotM, srcM) || !reflect.DeepEqual(gotV, srcV) {
				t.Errorf("rendered webhooks differ from config/webhook/exceptions.yaml:\n%+v\n%+v", gotM, gotV)
			}
			for _, o := range [][2]map[string]string{{m.Annotations, m.Labels}, {v.Annotations, v.Labels}} {
				inject := o[0]["cert-manager.io/inject-ca-from"]
				if operatorCA != (inject == "") || (!operatorCA && inject != controllerNS+"/konstapel-webhook") || len(o[0]) > 1 {
					t.Errorf("annotations %v", o[0])
				}
				if o[1]["app.kubernetes.io/part-of"] != "konstapel" || o[1]["app.kubernetes.io/managed-by"] != "Helm" {
					t.Errorf("labels %v", o[1])
				}
			}

			// The Service the webhooks call selects every controller
			// replica on its webhook port.
			svc := find(docs, "Service", "konstapel-webhook")
			d := find(docs, "Deployment", "konstapel-controller")
			selector := at(d, "spec", "selector", "matchLabels")
			if svc == nil || !reflect.DeepEqual(at(svc, "spec", "selector"), selector) || at(svc, "spec", "ports", 0, "port") != float64(443) || at(svc, "spec", "ports", 0, "targetPort") != "webhook" {
				t.Fatalf("webhook Service %v", svc)
			}
			for _, cc := range []admissionregistrationv1.WebhookClientConfig{m.Webhooks[0].ClientConfig, v.Webhooks[0].ClientConfig} {
				if s := cc.Service; s == nil || s.Name != "konstapel-webhook" || s.Namespace != controllerNS || s.Port == nil || *s.Port != 443 {
					t.Errorf("clientConfig %+v", cc)
				}
			}
			ctr := at(d, "spec", "template", "spec", "containers", 0)
			args := at(ctr, "args").([]any)
			for _, a := range []string{"--webhook-cert-dir=/etc/konstapel/webhook-tls", "--webhook-port=9443"} {
				if !slices.Contains(args, any(a)) {
					t.Errorf("controller args lack %s: %v", a, args)
				}
			}
			ports := at(ctr, "ports").([]any)
			if !slices.ContainsFunc(ports, func(p any) bool { return at(p, "name") == "webhook" && at(p, "containerPort") == float64(9443) }) {
				t.Errorf("no webhook container port: %v", ports)
			}
			if at(ctr, "readinessProbe", "httpGet", "path") != "/readyz" {
				t.Error("readiness is not /readyz, which holds the webhook check")
			}
			mounted := false
			for _, vol := range at(d, "spec", "template", "spec", "volumes").([]any) {
				if at(vol, "name") == "webhook-tls" {
					mounted = at(vol, "secret", "secretName") == c.secret
				}
			}
			for _, vm := range at(ctr, "volumeMounts").([]any) {
				if at(vm, "name") == "webhook-tls" && (at(vm, "mountPath") != "/etc/konstapel/webhook-tls" || at(vm, "readOnly") != true) {
					mounted = false
				}
			}
			if !mounted {
				t.Errorf("the webhook certificate %s is not mounted read-only", c.secret)
			}

			// cert-manager issues the certificate for the Service name;
			// the operator mode renders no Certificate.
			cert := find(docs, "Certificate", "konstapel-webhook")
			if operatorCA {
				if cert != nil {
					t.Error("operator TLS renders a webhook Certificate")
				}
				return
			}
			want := []any{"konstapel-webhook", "konstapel-webhook." + controllerNS, "konstapel-webhook." + controllerNS + ".svc"}
			if cert == nil || at(cert, "spec", "secretName") != c.secret || !reflect.DeepEqual(at(cert, "spec", "dnsNames"), any(want)) ||
				at(cert, "spec", "issuerRef", "name") != c.issuer || at(cert, "spec", "privateKey", "rotationPolicy") != "Always" {
				t.Errorf("webhook Certificate %v", cert)
			}
			if (c.issuer == "konstapel-ca") != (find(docs, "Issuer", "konstapel-ca") != nil) {
				t.Error("the chart CA is rendered exactly when no platform issuer is set")
			}
		})
	}
}

// Without exceptions.webhooks.enabled the render has nothing of the
// feature: no webhook configuration, Service, Certificate, Secret mount,
// port or flag.
func TestRuntimeChartExceptionWebhooksOffByDefault(t *testing.T) {
	for name, set := range map[string][]string{
		"defaults":         nil,
		"explicitly false": {"exceptions.webhooks.enabled=false", "exceptions.revocationProcessing.enabled=false"},
		"operator TLS":     {"tls.mode=secret", "tls.secret.name=konstapel-tls"},
	} {
		t.Run(name, func(t *testing.T) {
			docs, out, err := render(t, controllerNS, append([]string{"image.digest=" + digest}, set...)...)
			if err != nil {
				t.Fatal(out)
			}
			if !strings.Contains(out, "konstapel-controller") || strings.Contains(out, "konstapel-webhook") || strings.Contains(out, "webhook-tls") ||
				strings.Contains(out, "exception-acceptance") || strings.Contains(out, "exception-revocation") || strings.Contains(out, "9443") {
				t.Error("the default render carries part of the exception webhook feature")
			}
			for _, d := range docs {
				if k := d["kind"]; k == "MutatingWebhookConfiguration" || k == "ValidatingWebhookConfiguration" {
					t.Errorf("%s rendered", k)
				}
			}
		})
	}
}
