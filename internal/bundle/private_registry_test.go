package bundle_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
)

// The private registry guide in docs/policy-bundles.md embeds these manifests
// verbatim. This test parses them with the real code and checks they agree with
// each other, so the documented setup cannot drift from what Konstapel accepts.

const (
	exampleDir = "../../testdata/bundles/private-registry"
	exampleDoc = "../../docs/policy-bundles.md"
	exampleNS  = "konstapel-system"
)

func readExample(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(exampleDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func strict(t *testing.T, name string, v any) {
	t.Helper()
	if err := yaml.UnmarshalStrict(readExample(t, name), v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func TestPrivateRegistryExamples(t *testing.T) {
	var sourcesCM, caCM corev1.ConfigMap
	var secret corev1.Secret
	var role rbacv1.Role
	strict(t, "sources-configmap.yaml", &sourcesCM)
	strict(t, "ca-configmap.yaml", &caCM)
	strict(t, "secret.yaml", &secret)
	strict(t, "role.yaml", &role)

	// Everything lives in the controller's namespace.
	for name, ns := range map[string]string{
		"sources ConfigMap": sourcesCM.Namespace, "CA ConfigMap": caCM.Namespace,
		"Secret": secret.Namespace, "Role": role.Namespace,
	} {
		if ns != exampleNS {
			t.Errorf("%s is in namespace %q, want the controller namespace %q", name, ns, exampleNS)
		}
	}

	// The central configuration is accepted by the real parser.
	sources, err := bundle.ParseConfigMapData(sourcesCM.Data)
	if err != nil {
		t.Fatalf("documented sources ConfigMap is rejected: %v", err)
	}
	if len(sources.Sources) != 1 {
		t.Fatalf("want one documented source, got %d", len(sources.Sources))
	}
	src := sources.Sources[0]

	// The credential Secret is the right type and its document is accepted for
	// exactly the source's registry host.
	if secret.Type != corev1.SecretTypeDockerConfigJson {
		t.Errorf("Secret type %q, want %q", secret.Type, corev1.SecretTypeDockerConfigJson)
	}
	host, _, _ := strings.Cut(src.Repository, "/")
	cred, err := kubeaccess.CredentialForHost([]byte(secret.StringData[bundle.DefaultCredentialKey]), host)
	if err != nil || cred.Username != "reader" {
		t.Errorf("documented credential is not accepted for %s: %v", host, err)
	}
	if secret.Name != src.CredentialSecret.Name {
		t.Errorf("Secret %q is not the source's credentialSecret %q", secret.Name, src.CredentialSecret.Name)
	}

	// The CA ConfigMap holds parseable roots under the key the source reads.
	key := src.CA.Key
	if key == "" {
		key = bundle.DefaultCAKey
	}
	certs, err := kubeaccess.ParseCABundle([]byte(caCM.Data[key]))
	if err != nil || len(certs) == 0 {
		t.Errorf("documented CA is not accepted: %v", err)
	}
	if caCM.Name != src.CA.Name || src.CA.Kind != bundle.KindConfigMap {
		t.Errorf("CA ConfigMap %q does not match the source's ca %+v", caCM.Name, *src.CA)
	}

	// The Role grants get, by name, on exactly the objects the configuration
	// references plus the configuration ConfigMap itself, and nothing else.
	want := map[string][]string{"secrets": {}, "configmaps": {sourcesCM.Name}}
	add := func(r *bundle.ObjectRef, kind string) {
		if r == nil {
			return
		}
		if r.Kind != "" {
			kind = r.Kind
		}
		res := map[string]string{bundle.KindSecret: "secrets", bundle.KindConfigMap: "configmaps"}[kind]
		want[res] = append(want[res], r.Name)
	}
	for _, s := range sources.Sources {
		add(s.CredentialSecret, bundle.KindSecret)
		add(s.CA, "")
		add(s.Publisher.TrustRoot, "")
		add(s.Publisher.PublicKey, "")
	}
	got := map[string][]string{}
	for _, rule := range role.Rules {
		if len(rule.APIGroups) != 1 || rule.APIGroups[0] != "" || len(rule.Resources) != 1 ||
			len(rule.Verbs) != 1 || rule.Verbs[0] != "get" || len(rule.ResourceNames) == 0 {
			t.Fatalf("rule %+v must be get, by resourceNames, on one core resource", rule)
		}
		got[rule.Resources[0]] = append(got[rule.Resources[0]], rule.ResourceNames...)
	}
	for res, names := range want {
		sort.Strings(names)
		sort.Strings(got[res])
		if strings.Join(names, ",") != strings.Join(got[res], ",") {
			t.Errorf("Role grants %s %v, but the configuration references %v", res, got[res], names)
		}
	}
	if len(got) != len(want) {
		t.Errorf("Role covers resources %v, want only %v", got, want)
	}
}

// Each example is shown in the guide exactly as tested.
func TestPrivateRegistryGuideEmbedsTheExamples(t *testing.T) {
	doc, err := os.ReadFile(exampleDoc)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sources-configmap.yaml", "secret.yaml", "ca-configmap.yaml", "role.yaml"} {
		if !strings.Contains(string(doc), strings.TrimSpace(string(readExample(t, name)))) {
			t.Errorf("docs/policy-bundles.md does not embed testdata/bundles/private-registry/%s verbatim", name)
		}
	}
}
