package charttest

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

const controllerNS = "konstapel-system"

// grant is one (namespace, resource, verb, name) the controller
// ServiceAccount is allowed; namespace "" is cluster-wide and name "" any
// object.
type grant struct{ ns, resource, verb, name string }

func (g grant) String() string {
	ns, name := g.ns, g.name
	if ns == "" {
		ns = "<cluster>"
	}
	if name == "" {
		name = "<any>"
	}
	return fmt.Sprintf("%s %s %s %s", ns, g.resource, g.verb, name)
}

// controllerGrants is the union of every rule bound to the controller
// ServiceAccount by any RoleBinding or ClusterRoleBinding in the render,
// expanded per resource, verb and name. It fails the test on wildcards.
func controllerGrants(t *testing.T, docs []map[string]any) []grant {
	t.Helper()
	var out []grant
	for _, b := range docs {
		if b["kind"] != "RoleBinding" && b["kind"] != "ClusterRoleBinding" {
			continue
		}
		bound := false
		for _, s := range at(b, "subjects").([]any) {
			s := s.(map[string]any)
			if s["kind"] == "ServiceAccount" && s["name"] == "konstapel-controller" && s["namespace"] == controllerNS {
				bound = true
			}
		}
		if !bound {
			continue
		}
		ns := ""
		if b["kind"] == "RoleBinding" {
			ns, _ = metadata(b)["namespace"].(string)
		}
		roleKind, roleName := at(b, "roleRef", "kind").(string), at(b, "roleRef", "name").(string)
		role := find(docs, roleKind, roleName)
		if role == nil {
			t.Fatalf("%s %s binds missing %s %s", b["kind"], metadata(b)["name"], roleKind, roleName)
		}
		if roleKind == "Role" && metadata(role)["namespace"] != ns {
			t.Fatalf("Role %s is in %v, bound in %s", roleName, metadata(role)["namespace"], ns)
		}
		for _, r := range role["rules"].([]any) {
			r := r.(map[string]any)
			if strings.Contains(fmt.Sprint(r), "*") {
				t.Fatalf("%s %s has a wildcard rule: %v", roleKind, roleName, r)
			}
			if r["nonResourceURLs"] != nil {
				t.Fatalf("%s %s grants non-resource URLs: %v", roleKind, roleName, r)
			}
			groups, _ := r["apiGroups"].([]any)
			names, _ := r["resourceNames"].([]any)
			if len(names) == 0 {
				names = []any{""}
			}
			for _, g := range groups {
				for _, res := range r["resources"].([]any) {
					resource := res.(string)
					if g != "" {
						resource = g.(string) + "/" + resource
					}
					for _, v := range r["verbs"].([]any) {
						for _, n := range names {
							out = append(out, grant{ns, resource, v.(string), n.(string)})
						}
					}
				}
			}
		}
	}
	return out
}

// allowed reports whether the grants authorize verb on resource in ns, for
// the named object ("" for a request without a name, such as an unselected
// list, a watch, or a create).
func allowed(gs []grant, ns, resource, verb, name string) bool {
	return slices.ContainsFunc(gs, func(g grant) bool {
		return (g.ns == "" || g.ns == ns) && g.resource == resource && g.verb == verb && (g.name == "" || g.name == name)
	})
}

// secretConfigMapGrants are the grants on core Secrets and ConfigMaps,
// sorted and de-duplicated.
func secretConfigMapGrants(gs []grant) []string {
	var out []string
	for _, g := range gs {
		if g.resource == "secrets" || g.resource == "configmaps" {
			out = append(out, g.String())
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// The effective Secret and ConfigMap access of the controller ServiceAccount
// is exactly what implemented features need (docs/charts.md, "Controller
// ServiceAccount boundary"): unrestricted get of Secrets and ConfigMaps and
// create of ConfigMaps in the controller namespace, because their names come
// from CR specs or are derived at runtime, plus the bundle Role's named
// grants. Nothing lists or watches Secrets, nothing lists or watches
// ConfigMaps other than the named bundle sources ConfigMap, nothing updates,
// patches or deletes either kind, and no ClusterRole grants either kind.
func TestRuntimeChartControllerSecretConfigMapAccess(t *testing.T) {
	base := []string{
		"konstapel-system configmaps create <any>",
		"konstapel-system configmaps get <any>",
		"konstapel-system secrets get <any>",
	}
	for name, c := range map[string]struct {
		set  []string
		want []string
	}{
		"bundles off": {nil, base},
		"bundles on": {
			[]string{"bundles.sourcesConfigMap=" + sourcesCM, "bundles.referencedConfigMaps={registry-ca}", "bundles.referencedSecrets={registry-cred,org-key}"},
			append(slices.Clone(base),
				"konstapel-system configmaps get konstapel-bundle-sources",
				"konstapel-system configmaps get registry-ca",
				"konstapel-system configmaps list konstapel-bundle-sources",
				"konstapel-system configmaps watch konstapel-bundle-sources",
				"konstapel-system secrets get org-key",
				"konstapel-system secrets get registry-cred",
			),
		},
	} {
		t.Run(name, func(t *testing.T) {
			docs, out, err := render(t, controllerNS, append([]string{"image.digest=" + digest}, c.set...)...)
			if err != nil {
				t.Fatal(out)
			}
			gs := controllerGrants(t, docs)
			want := slices.Clone(c.want)
			sort.Strings(want)
			if got := secretConfigMapGrants(gs); !reflect.DeepEqual(got, want) {
				t.Fatalf("effective Secret/ConfigMap grants\n got %q\nwant %q", got, want)
			}
			bundles := len(c.set) > 0
			for _, q := range []struct {
				ns, resource, verb, name string
				want                     bool
			}{
				// Needed: by-name reads and ConfigMap creation in the
				// controller namespace.
				{controllerNS, "secrets", "get", "s3-credentials", true},
				// EvidenceDestination spec.signing.secretRef, read by name.
				{controllerNS, "secrets", "get", "konstapel-evidence-signing-2026-11", true},
				{"default", "secrets", "get", "konstapel-evidence-signing-2026-11", false},
				{controllerNS, "configmaps", "get", "konstapel-evidence-destination", true},
				{controllerNS, "configmaps", "create", "", true},
				{controllerNS, "configmaps", "list", sourcesCM, bundles},
				{controllerNS, "configmaps", "watch", sourcesCM, bundles},
				// Not needed by any feature.
				{controllerNS, "secrets", "list", "", false},
				{controllerNS, "secrets", "watch", "", false},
				{controllerNS, "secrets", "create", "", false},
				{controllerNS, "secrets", "update", "s3-credentials", false},
				{controllerNS, "secrets", "patch", "s3-credentials", false},
				{controllerNS, "secrets", "delete", "s3-credentials", false},
				{controllerNS, "configmaps", "list", "", false},
				{controllerNS, "configmaps", "watch", "", false},
				{controllerNS, "configmaps", "list", "registry-ca", false},
				{controllerNS, "configmaps", "update", "konstapel-evidence-destination", false},
				{controllerNS, "configmaps", "patch", "konstapel-evidence-destination", false},
				{controllerNS, "configmaps", "delete", "konstapel-evidence-destination", false},
				{controllerNS, "configmaps", "deletecollection", "", false},
				{"default", "secrets", "get", "s3-credentials", false},
				{"kube-system", "secrets", "get", "s3-credentials", false},
				{"default", "configmaps", "get", "konstapel-evidence-destination", false},
				{"default", "configmaps", "create", "", false},
			} {
				if got := allowed(gs, q.ns, q.resource, q.verb, q.name); got != q.want {
					t.Errorf("%s %s %s %q: allowed=%v, want %v", q.ns, q.resource, q.verb, q.name, got, q.want)
				}
			}
		})
	}
}

// leaseGrants are the grants on coordination.k8s.io Leases, sorted and
// de-duplicated.
func leaseGrants(gs []grant) []string {
	var out []string
	for _, g := range gs {
		if g.resource == "coordination.k8s.io/leases" {
			out = append(out, g.String())
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// The effective Lease access of the controller ServiceAccount is exactly
// what the pinned client-go LeaseLock does with the one leader-election
// Lease (docs/charts.md, "Controller ServiceAccount boundary"): get and
// update of that Lease by name (acquire, renew, take over after expiry), and
// create (the first candidate), which RBAC cannot restrict by name. Nothing
// lists, watches, patches or deletes Leases, other Leases are neither read
// nor written, and no ClusterRole grants Leases.
func TestRuntimeChartControllerLeaseAccess(t *testing.T) {
	const lease = "konstapel-controller-leader-election"
	for name, set := range map[string][]string{
		"bundles off": nil,
		"bundles on":  {"bundles.sourcesConfigMap=" + sourcesCM, "bundles.referencedConfigMaps={registry-ca}", "bundles.referencedSecrets={registry-cred,org-key}"},
	} {
		t.Run(name, func(t *testing.T) {
			docs, out, err := render(t, controllerNS, append([]string{"image.digest=" + digest}, set...)...)
			if err != nil {
				t.Fatal(out)
			}
			gs := controllerGrants(t, docs)
			want := []string{
				"konstapel-system coordination.k8s.io/leases create <any>",
				"konstapel-system coordination.k8s.io/leases get " + lease,
				"konstapel-system coordination.k8s.io/leases update " + lease,
			}
			if got := leaseGrants(gs); !reflect.DeepEqual(got, want) {
				t.Fatalf("effective Lease grants\n got %q\nwant %q", got, want)
			}
			const r = "coordination.k8s.io/leases"
			for _, q := range []struct {
				ns, verb, name string
				want           bool
			}{
				{controllerNS, "get", lease, true},
				{controllerNS, "update", lease, true},
				{controllerNS, "create", "", true},
				{controllerNS, "get", "other-lease", false},
				{controllerNS, "update", "other-lease", false},
				{controllerNS, "get", "", false},
				{controllerNS, "list", "", false},
				{controllerNS, "list", lease, false},
				{controllerNS, "watch", "", false},
				{controllerNS, "watch", lease, false},
				{controllerNS, "patch", lease, false},
				{controllerNS, "delete", lease, false},
				{controllerNS, "deletecollection", "", false},
				{"default", "get", lease, false},
				{"default", "update", lease, false},
				{"default", "create", "", false},
				{"kube-system", "get", lease, false},
				{"", "list", "", false},
			} {
				if got := allowed(gs, q.ns, r, q.verb, q.name); got != q.want {
					t.Errorf("%s leases %s %q: allowed=%v, want %v", q.ns, q.verb, q.name, got, q.want)
				}
			}
		})
	}
}

// Until the exception owner's native grant path and its capability gate
// land, the runtime chart cannot activate an exception grant
// (add-helm-oci-distribution 4.3, docs/charts.md "Exception admission
// webhooks"): no rendered role lets any subject touch native Kyverno
// PolicyExceptions, in every supported configuration, the exception
// webhooks and revocation processing included, so a missing exception
// prerequisite cannot be bypassed through chart values. Without
// exceptions.webhooks.enabled no admission webhook is registered and the
// controller serves none; with it, only the two ComplianceException
// webhooks are, and they intercept complianceexceptions alone.
func TestRuntimeChartCannotActivateNativeExceptions(t *testing.T) {
	for name, c := range map[string]struct {
		set      []string
		webhooks bool
	}{
		"defaults":              {},
		"bundles on":            {set: []string{"bundles.sourcesConfigMap=" + sourcesCM, "bundles.referencedConfigMaps={registry-ca}", "bundles.referencedSecrets={registry-cred,org-key}"}},
		"metrics on":            {set: []string{"metrics.enabled=true", "metrics.readers[0].namespace=monitoring", "metrics.readers[0].name=prometheus-k8s"}},
		"operator TLS":          {set: []string{"tls.mode=secret", "tls.secret.name=konstapel-tls"}},
		"one replica":           {set: []string{"replicaCount=1"}},
		"exception webhooks":    {set: []string{"exceptions.webhooks.enabled=true"}, webhooks: true},
		"revocation processing": {set: []string{"exceptions.webhooks.enabled=true", "exceptions.revocationProcessing.enabled=true"}, webhooks: true},
		"operator TLS with revocation processing": {set: append([]string{"tls.mode=secret", "tls.secret.name=konstapel-tls"}, operatorWebhookTLS...), webhooks: true},
	} {
		t.Run(name, func(t *testing.T) {
			docs, out, err := render(t, controllerNS, append([]string{"image.digest=" + digest}, c.set...)...)
			if err != nil {
				t.Fatal(out)
			}
			registered := 0
			for _, d := range docs {
				switch d["kind"] {
				case "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration":
					if !c.webhooks || metadata(d)["name"] != "konstapel-exception-acceptance" {
						t.Errorf("%s %v registered before exception prerequisites", d["kind"], metadata(d)["name"])
					}
					registered++
					for _, w := range at(d, "webhooks").([]any) {
						for _, r := range at(w, "rules").([]any) {
							if !reflect.DeepEqual(at(r, "apiGroups"), any([]any{"compliance.erenius.io"})) || !reflect.DeepEqual(at(r, "resources"), any([]any{"complianceexceptions"})) {
								t.Errorf("%s %v intercepts %v %v", d["kind"], metadata(d)["name"], at(r, "apiGroups"), at(r, "resources"))
							}
						}
					}
				case "Role", "ClusterRole":
					rules, _ := d["rules"].([]any)
					for _, r := range rules {
						r := r.(map[string]any)
						groups, _ := r["apiGroups"].([]any)
						resources, _ := r["resources"].([]any)
						if slices.Contains(groups, any("policies.kyverno.io")) && slices.ContainsFunc(resources, func(x any) bool {
							return strings.HasPrefix(x.(string), "policyexceptions")
						}) {
							t.Errorf("%s %v grants native PolicyExceptions: %v", d["kind"], metadata(d)["name"], r)
						}
					}
				case "Deployment":
					for _, ctr := range at(d, "spec", "template", "spec", "containers").([]any) {
						for _, a := range at(ctr, "args").([]any) {
							if strings.HasPrefix(a.(string), "--webhook-") && (!c.webhooks || metadata(d)["name"] != "konstapel-controller") {
								t.Errorf("Deployment %v serves admission webhooks: %s", metadata(d)["name"], a)
							}
							if strings.Contains(strings.ToLower(a.(string)), "policyexception") || strings.Contains(a.(string), "native") {
								t.Errorf("Deployment %v configures native exceptions: %s", metadata(d)["name"], a)
							}
						}
					}
				}
			}
			if want := map[bool]int{false: 0, true: 2}[c.webhooks]; registered != want {
				t.Errorf("%d webhook configurations, want %d", registered, want)
			}
		})
	}
}

// operatorWebhookTLS is the operator-managed webhook TLS for tls.mode=secret.
var operatorWebhookTLS = []string{"exceptions.webhooks.enabled=true", "exceptions.revocationProcessing.enabled=true",
	"exceptions.webhooks.tls.secretName=konstapel-webhook-tls", "exceptions.webhooks.tls.caBundle=" + fixtureCA}

// fixtureCA is a placeholder PEM bundle; the render only copies it.
const fixtureCA = "-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n"

// Exception revocation processing (add-self-service-policy-exceptions task
// 3.6, docs/charts.md "Exception admission webhooks") is one switch,
// exceptions.revocationProcessing.enabled, off by default. Its grant lets
// the controller update exceptions, which only the fail-closed exception
// webhooks confine. So no configuration without it renders the grant, its
// identity lookup, its webhook-config reads or the controller flag, the
// webhooks alone included; turning it on without exceptions.webhooks.enabled
// fails the render in every configuration, before anything is applied; and
// turning it on with them adds exactly the gated ClusterRole's rules, its
// binding and the flag, nothing more.
func TestRuntimeChartExceptionRevocationGated(t *testing.T) {
	configs := map[string][]string{
		"defaults":         nil,
		"explicitly false": {"exceptions.revocationProcessing.enabled=false"},
		"bundles on":       {"bundles.sourcesConfigMap=" + sourcesCM, "bundles.referencedConfigMaps={registry-ca}", "bundles.referencedSecrets={registry-cred,org-key}"},
		"metrics on":       {"metrics.enabled=true", "metrics.readers[0].namespace=monitoring", "metrics.readers[0].name=prometheus-k8s"},
		"operator TLS":     {"tls.mode=secret", "tls.secret.name=konstapel-tls"},
		"one replica":      {"replicaCount=1"},
	}
	gatedGrants := []grant{
		{"team-a", "compliance.erenius.io/complianceexceptions", "update", "priv"},
		{"team-a", "compliance.erenius.io/complianceexceptions", "patch", "priv"},
		{"", "authentication.k8s.io/selfsubjectreviews", "create", ""},
		{"", "admissionregistration.k8s.io/validatingwebhookconfigurations", "get", "konstapel-exception-acceptance"},
		{"", "admissionregistration.k8s.io/mutatingwebhookconfigurations", "get", "konstapel-exception-acceptance"},
	}
	revocationArgs := func(docs []map[string]any) []string {
		var out []string
		for _, d := range docs {
			if d["kind"] != "Deployment" {
				continue
			}
			for _, c := range at(d, "spec", "template", "spec", "containers").([]any) {
				for _, a := range at(c, "args").([]any) {
					if strings.HasPrefix(a.(string), "--exception-revocation") {
						out = append(out, fmt.Sprintf("%v: %s", metadata(d)["name"], a))
					}
				}
			}
		}
		return out
	}
	disabled := maps.Clone(configs)
	disabled["webhooks only"] = []string{"exceptions.webhooks.enabled=true"}
	disabled["webhooks only, operator TLS"] = []string{"tls.mode=secret", "tls.secret.name=konstapel-tls", "exceptions.webhooks.enabled=true",
		"exceptions.webhooks.tls.secretName=konstapel-webhook-tls", "exceptions.webhooks.tls.caBundle=" + fixtureCA}
	for name, set := range disabled {
		t.Run(name, func(t *testing.T) {
			docs, out, err := render(t, controllerNS, append([]string{"image.digest=" + digest}, set...)...)
			if err != nil {
				t.Fatal(out)
			}
			gs := controllerGrants(t, docs)
			for _, verb := range []string{"create", "update", "patch", "delete", "deletecollection"} {
				if allowed(gs, "team-a", "compliance.erenius.io/complianceexceptions", verb, "priv") || allowed(gs, "team-a", "compliance.erenius.io/complianceexceptions", verb, "") {
					t.Errorf("the controller may %s complianceexceptions", verb)
				}
			}
			for _, q := range gatedGrants[2:] {
				if allowed(gs, q.ns, q.resource, q.verb, q.name) {
					t.Errorf("the controller is granted %s without revocation processing", q)
				}
			}
			// Still read-only on exceptions, and the status writer.
			if !allowed(gs, "team-a", "compliance.erenius.io/complianceexceptions", "get", "priv") ||
				!allowed(gs, "team-a", "compliance.erenius.io/complianceexceptions/status", "update", "priv") {
				t.Error("the controller lost its exception read or status write")
			}
			if find(docs, "ClusterRole", "konstapel-controller-exception-revocation") != nil || find(docs, "ClusterRoleBinding", "konstapel-controller-exception-revocation") != nil {
				t.Error("the gated revocation ClusterRole or its binding is rendered")
			}
			if a := revocationArgs(docs); len(a) != 0 {
				t.Errorf("revocation processing enabled: %v", a)
			}
		})
	}
	for name, set := range configs {
		if name == "explicitly false" {
			continue
		}
		t.Run("enabled without webhooks, "+name, func(t *testing.T) {
			_, out, err := render(t, controllerNS, append([]string{"image.digest=" + digest, "exceptions.revocationProcessing.enabled=true"}, set...)...)
			if err == nil || !strings.Contains(out, "exceptions.revocationProcessing.enabled needs exceptions.webhooks.enabled") {
				t.Fatalf("enabled without exception webhooks rendered: %v\n%s", err, out)
			}
		})
		t.Run("enabled with webhooks, "+name, func(t *testing.T) {
			set := append([]string{"image.digest=" + digest, "exceptions.webhooks.enabled=true", "exceptions.revocationProcessing.enabled=true"}, set...)
			if slices.Contains(set, "tls.mode=secret") {
				set = append(set, operatorWebhookTLS...)
			}
			docs, out, err := render(t, controllerNS, set...)
			if err != nil {
				t.Fatal(out)
			}
			base, _, err := render(t, controllerNS, slices.DeleteFunc(slices.Clone(set), func(s string) bool { return strings.HasPrefix(s, "exceptions.revocationProcessing.") })...)
			if err != nil {
				t.Fatal(err)
			}
			gs, before := controllerGrants(t, docs), controllerGrants(t, base)
			var added []grant
			for _, g := range gs {
				if !slices.Contains(before, g) {
					added = append(added, g)
				}
			}
			for _, q := range gatedGrants {
				if !allowed(gs, q.ns, q.resource, q.verb, q.name) {
					t.Errorf("the gated grant lacks %s", q)
				}
			}
			// Exactly the gated ClusterRole, cluster-wide.
			want := []grant{
				{"", "admissionregistration.k8s.io/mutatingwebhookconfigurations", "get", "konstapel-exception-acceptance"},
				{"", "admissionregistration.k8s.io/validatingwebhookconfigurations", "get", "konstapel-exception-acceptance"},
				{"", "authentication.k8s.io/selfsubjectreviews", "create", ""},
				{"", "compliance.erenius.io/complianceexceptions", "patch", ""},
				{"", "compliance.erenius.io/complianceexceptions", "update", ""},
			}
			sort.Slice(added, func(i, j int) bool { return added[i].String() < added[j].String() })
			if !reflect.DeepEqual(added, want) {
				t.Errorf("revocation processing adds %v, want exactly the gated ClusterRole %v", added, want)
			}
			for _, verb := range []string{"create", "delete", "deletecollection"} {
				if allowed(gs, "team-a", "compliance.erenius.io/complianceexceptions", verb, "") {
					t.Errorf("the controller may %s complianceexceptions", verb)
				}
			}
			b := find(docs, "ClusterRoleBinding", "konstapel-controller-exception-revocation")
			if b == nil || at(b, "roleRef", "name") != "konstapel-controller-exception-revocation" || at(b, "subjects", 0, "name") != "konstapel-controller" {
				t.Errorf("gated binding %v", b)
			}
			if a := revocationArgs(docs); !reflect.DeepEqual(a, []string{"konstapel-controller: --exception-revocation-processing"}) {
				t.Errorf("revocation flag %v", a)
			}
		})
	}
}
