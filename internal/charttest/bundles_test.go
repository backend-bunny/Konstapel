package charttest

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const sourcesCM = "konstapel-bundle-sources"

// bundleRules are the exact rules of the Role the chart grants for OCI bundle sources.
func bundleRules(cms, secrets []string) []any {
	rules := []any{map[string]any{"apiGroups": []any{""}, "resources": []any{"configmaps"}, "verbs": []any{"get", "list", "watch"}, "resourceNames": []any{sourcesCM}}}
	names := func(s []string) []any {
		out := []any{}
		for _, n := range s {
			out = append(out, n)
		}
		return out
	}
	if len(cms) > 0 {
		rules = append(rules, map[string]any{"apiGroups": []any{""}, "resources": []any{"configmaps"}, "verbs": []any{"get"}, "resourceNames": names(cms)})
	}
	if len(secrets) > 0 {
		rules = append(rules, map[string]any{"apiGroups": []any{""}, "resources": []any{"secrets"}, "verbs": []any{"get"}, "resourceNames": names(secrets)})
	}
	return rules
}

func controllerContainer(t *testing.T, docs []map[string]any) (pod, c map[string]any) {
	t.Helper()
	d := find(docs, "Deployment", "konstapel-controller")
	if d == nil {
		t.Fatal("no controller Deployment")
	}
	pod = at(d, "spec", "template", "spec").(map[string]any)
	return pod, at(pod, "containers", 0).(map[string]any)
}

// Off by default: the chart renders nothing for bundles, and the explicit
// default values render byte-for-byte what the chart renders without them.
func TestRuntimeChartBundlesOffByDefault(t *testing.T) {
	_, plain, err := render(t, "konstapel-system", "image.digest="+digest)
	if err != nil {
		t.Fatal(plain)
	}
	_, explicit, err := render(t, "konstapel-system", "image.digest="+digest, "bundles.sourcesConfigMap=",
		"bundles.cache.capacity=2Gi", "bundles.cache.sizeLimit=3Gi", "bundles.refreshInterval=1m")
	if err != nil {
		t.Fatal(explicit)
	}
	if plain != explicit {
		t.Fatal("bundle values other than sourcesConfigMap change the render while the feature is off")
	}
	if strings.Contains(plain, "bundle") {
		t.Fatalf("default render mentions bundles:\n%s", plain)
	}
	docs := documents(t, []byte(plain))
	if find(docs, "Role", "konstapel-controller-bundles") != nil || find(docs, "RoleBinding", "konstapel-controller-bundles") != nil {
		t.Fatal("default render grants bundle access")
	}
	pod, c := controllerContainer(t, docs)
	if len(pod["volumes"].([]any)) != 2 || len(c["volumeMounts"].([]any)) != 2 {
		t.Fatalf("default controller volumes changed: %v", pod["volumes"])
	}
	if !reflect.DeepEqual(at(c, "env"), any([]any{map[string]any{"name": "POD_NAMESPACE", "valueFrom": map[string]any{"fieldRef": map[string]any{"fieldPath": "metadata.namespace"}}}})) {
		t.Fatalf("controller env: %v", at(c, "env"))
	}
}

// Enabled: the four flags, the cache emptyDir and POD_NAMESPACE from the
// downward API, and a Role granting exactly the named objects; nothing else
// in the render changes.
func TestRuntimeChartBundlesEnabled(t *testing.T) {
	off, _, err := render(t, "konstapel-system", "image.digest="+digest)
	if err != nil {
		t.Fatal(err)
	}
	docs, out, err := render(t, "konstapel-system", "image.digest="+digest, "bundles.sourcesConfigMap="+sourcesCM,
		"bundles.referencedSecrets={acme-registry,acme-bundle-signing-key}", "bundles.referencedConfigMaps={acme-registry-ca}")
	if err != nil {
		t.Fatal(out)
	}
	pod, c := controllerContainer(t, docs)
	args := c["args"].([]any)
	for _, want := range []string{"--bundle-sources-configmap=" + sourcesCM, "--bundle-cache-dir=/var/lib/konstapel/bundles",
		"--bundle-cache-capacity=1Gi", "--bundle-refresh-interval=30s"} {
		if !slices.Contains(args, any(want)) {
			t.Errorf("args lack %s: %v", want, args)
		}
	}
	if n := len(slices.DeleteFunc(slices.Clone(args), func(a any) bool { return !strings.HasPrefix(a.(string), "--bundle-") })); n != 4 {
		t.Errorf("%d bundle flags: %v", n, args)
	}
	if !slices.ContainsFunc(c["volumeMounts"].([]any), func(m any) bool {
		return reflect.DeepEqual(m, any(map[string]any{"name": "bundle-cache", "mountPath": "/var/lib/konstapel/bundles"}))
	}) {
		t.Errorf("no cache mount: %v", c["volumeMounts"])
	}
	if !slices.ContainsFunc(pod["volumes"].([]any), func(v any) bool {
		return reflect.DeepEqual(v, any(map[string]any{"name": "bundle-cache", "emptyDir": map[string]any{"sizeLimit": "1536Mi"}}))
	}) {
		t.Errorf("no bounded cache emptyDir: %v", pod["volumes"])
	}
	if at(c, "env", 0, "name") != "POD_NAMESPACE" || at(c, "env", 0, "valueFrom", "fieldRef", "fieldPath") != "metadata.namespace" {
		t.Errorf("POD_NAMESPACE is not the pod's namespace: %v", at(c, "env"))
	}
	if at(c, "securityContext", "readOnlyRootFilesystem") != true {
		t.Error("enabling bundles relaxed the read-only root")
	}

	role := find(docs, "Role", "konstapel-controller-bundles")
	if role == nil || metadata(role)["namespace"] != "konstapel-system" {
		t.Fatalf("bundle Role: %v", role)
	}
	if want := bundleRules([]string{"acme-registry-ca"}, []string{"acme-registry", "acme-bundle-signing-key"}); !reflect.DeepEqual(role["rules"], any(want)) {
		t.Errorf("bundle Role rules\n got %v\nwant %v", role["rules"], want)
	}
	rb := find(docs, "RoleBinding", "konstapel-controller-bundles")
	if rb == nil || metadata(rb)["namespace"] != "konstapel-system" ||
		!reflect.DeepEqual(rb["roleRef"], any(map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "konstapel-controller-bundles"})) ||
		!reflect.DeepEqual(rb["subjects"], any([]any{map[string]any{"kind": "ServiceAccount", "name": "konstapel-controller", "namespace": "konstapel-system"}})) {
		t.Fatalf("bundle RoleBinding: %v", rb)
	}

	// Nothing else changes: the same documents apart from the controller
	// Deployment and the two bundle objects; no ClusterRole gains anything.
	rest := func(docs []map[string]any) []map[string]any {
		return slices.DeleteFunc(slices.Clone(docs), func(d map[string]any) bool {
			name := metadata(d)["name"]
			return name == "konstapel-controller-bundles" || d["kind"] == "Deployment" && name == "konstapel-controller"
		})
	}
	if !reflect.DeepEqual(rest(docs), rest(off)) {
		t.Error("enabling bundles changed documents other than the controller Deployment and the bundle Role/RoleBinding")
	}
}

// RBAC exactness: every grant names its objects. An empty list renders no
// rule at all (an empty resourceNames would grant every object of the kind),
// and no rule ever uses a wildcard.
func TestRuntimeChartBundleRBACIsByName(t *testing.T) {
	for name, c := range map[string]struct {
		set          []string
		cms, secrets []string
	}{
		"no references":   {nil, nil, nil},
		"secrets only":    {[]string{"bundles.referencedSecrets={acme-registry}"}, nil, []string{"acme-registry"}},
		"configmaps only": {[]string{"bundles.referencedConfigMaps={acme-registry-ca,root}"}, []string{"acme-registry-ca", "root"}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			docs, out, err := render(t, "konstapel-system", append([]string{"image.digest=" + digest, "bundles.sourcesConfigMap=" + sourcesCM}, c.set...)...)
			if err != nil {
				t.Fatal(out)
			}
			role := find(docs, "Role", "konstapel-controller-bundles")
			if want := bundleRules(c.cms, c.secrets); !reflect.DeepEqual(role["rules"], any(want)) {
				t.Fatalf("rules\n got %v\nwant %v", role["rules"], want)
			}
			for _, r := range role["rules"].([]any) {
				rule := r.(map[string]any)
				names, _ := rule["resourceNames"].([]any)
				if len(names) == 0 || strings.Contains(fmt.Sprint(rule), "*") {
					t.Fatalf("rule is not by name: %v", rule)
				}
				if slices.Contains(rule["verbs"].([]any), any("watch")) && !reflect.DeepEqual(names, []any{sourcesCM}) {
					t.Fatalf("watch on anything but the sources ConfigMap: %v", rule)
				}
			}
		})
	}
}
