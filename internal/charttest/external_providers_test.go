package charttest

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

const (
	clientCertSecret = "konstapel-external-provider-client-tls"
	clientCertDir    = "/etc/konstapel/external-provider-client-tls"
	clientCertFlag   = "--external-provider-client-cert-dir=" + clientCertDir
)

// add-external-assessment-providers 2.3: external providers are off by
// default. The default render is byte-identical to one with the section's
// defaults set explicitly and never mentions the client, so the controller
// runs without --external-provider-client-cert-dir and selects only built-in
// providers.
func TestRuntimeChartExternalProvidersOffByDefault(t *testing.T) {
	docs, plain, err := render(t, controllerNS, "image.digest="+digest)
	if err != nil {
		t.Fatal(plain)
	}
	_, explicit, err := render(t, controllerNS, "image.digest="+digest,
		"externalProviders.enabled=false", "externalProviders.clientCertSecretName=")
	if err != nil {
		t.Fatal(explicit)
	}
	if plain != explicit {
		t.Fatal("explicit externalProviders defaults change the render")
	}
	if strings.Contains(plain, "external-provider") {
		t.Fatalf("default render configures the external provider client:\n%s", plain)
	}
	pod, c := controllerContainer(t, docs)
	for _, a := range controllerArgs(t, docs) {
		if strings.HasPrefix(a, "--external-provider") {
			t.Errorf("default controller arg %s", a)
		}
	}
	names := func(list any) []string {
		var out []string
		for _, v := range list.([]any) {
			out = append(out, v.(map[string]any)["name"].(string))
		}
		return out
	}
	if got := names(pod["volumes"]); !reflect.DeepEqual(got, []string{"staging", "tmp"}) {
		t.Errorf("default controller volumes %v", got)
	}
	if got := names(c["volumeMounts"]); !reflect.DeepEqual(got, []string{"staging", "tmp"}) {
		t.Errorf("default controller mounts %v", got)
	}
}

// Enabled, the render adds exactly the flag, one read-only mount of the
// named Secret and its volume to the controller Deployment. Every other
// document, RBAC included, is unchanged: the chart installs no provider,
// binds no registration role and grants the controller nothing (the Secret
// is mounted by the kubelet, not read through the API).
func TestRuntimeChartExternalProvidersEnabled(t *testing.T) {
	for name, extra := range map[string][]string{
		"defaults":    nil,
		"bundles":     {"bundles.sourcesConfigMap=" + sourcesCM},
		"metrics":     {"metrics.enabled=true"},
		"operatorTLS": {"tls.mode=secret", "tls.secret.name=konstapel-tls"},
		"webhooks":    {"exceptions.webhooks.enabled=true"},
	} {
		t.Run(name, func(t *testing.T) {
			base := append([]string{"image.digest=" + digest}, extra...)
			off, out, err := render(t, controllerNS, base...)
			if err != nil {
				t.Fatal(out)
			}
			on, out, err := render(t, controllerNS, append(slices.Clone(base),
				"externalProviders.enabled=true", "externalProviders.clientCertSecretName="+clientCertSecret)...)
			if err != nil {
				t.Fatal(out)
			}

			pod, c := controllerContainer(t, on)
			args := c["args"].([]any)
			if n := slices.Index(args, any(clientCertFlag)); n < 0 || slices.Index(args[n+1:], any(clientCertFlag)) >= 0 {
				t.Fatalf("want %s exactly once: %v", clientCertFlag, args)
			}
			mount := map[string]any{"name": "external-provider-client-tls", "mountPath": clientCertDir, "readOnly": true}
			volume := map[string]any{"name": "external-provider-client-tls", "secret": map[string]any{"secretName": clientCertSecret}}
			if !slices.ContainsFunc(c["volumeMounts"].([]any), func(m any) bool { return reflect.DeepEqual(m, any(mount)) }) {
				t.Errorf("no read-only client certificate mount: %v", c["volumeMounts"])
			}
			if !slices.ContainsFunc(pod["volumes"].([]any), func(v any) bool { return reflect.DeepEqual(v, any(volume)) }) {
				t.Errorf("no client certificate Secret volume: %v", pod["volumes"])
			}

			// Remove exactly those three additions: what remains equals the
			// disabled render, document for document.
			c["args"] = slices.DeleteFunc(slices.Clone(args), func(a any) bool { return a == clientCertFlag })
			c["volumeMounts"] = slices.DeleteFunc(slices.Clone(c["volumeMounts"].([]any)), func(m any) bool { return reflect.DeepEqual(m, any(mount)) })
			pod["volumes"] = slices.DeleteFunc(slices.Clone(pod["volumes"].([]any)), func(v any) bool { return reflect.DeepEqual(v, any(volume)) })
			if !reflect.DeepEqual(on, off) {
				t.Error("enabling external providers changed more than the controller flag, mount and volume")
			}
			if !reflect.DeepEqual(grantStrings(controllerGrants(t, on)), grantStrings(controllerGrants(t, off))) {
				t.Error("enabling external providers changed the controller's grants")
			}
		})
	}
}
