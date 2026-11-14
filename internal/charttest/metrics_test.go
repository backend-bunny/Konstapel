package charttest

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// metricsGrants are the grants metrics.enabled adds to the controller
// ServiceAccount: exactly the two cluster-scoped review creations.
var metricsGrants = []string{
	"<cluster> authentication.k8s.io/tokenreviews create <any>",
	"<cluster> authorization.k8s.io/subjectaccessreviews create <any>",
}

func grantStrings(gs []grant) []string {
	var out []string
	for _, g := range gs {
		out = append(out, g.String())
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func controllerArgs(t *testing.T, docs []map[string]any) []string {
	t.Helper()
	_, c := controllerContainer(t, docs)
	var args []string
	for _, a := range c["args"].([]any) {
		args = append(args, a.(string))
	}
	return args
}

// Metrics are off by default: nothing is served, no Service or reader role
// exists, and the controller cannot create TokenReviews or
// SubjectAccessReviews.
func TestRuntimeChartMetricsOffByDefault(t *testing.T) {
	docs, _, err := render(t, controllerNS, "image.digest="+digest)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(controllerArgs(t, docs), "--metrics-bind-address=0") {
		t.Error("metrics served by default")
	}
	for _, kind := range []string{"Service", "ClusterRole", "ClusterRoleBinding", "Certificate"} {
		for _, name := range []string{"konstapel-controller-metrics", "konstapel-controller-metrics-auth", "konstapel-metrics-reader"} {
			if find(docs, kind, name) != nil {
				t.Errorf("%s %s rendered with metrics disabled", kind, name)
			}
		}
	}
	for _, g := range grantStrings(controllerGrants(t, docs)) {
		if strings.Contains(g, "tokenreviews") || strings.Contains(g, "subjectaccessreviews create") && !strings.Contains(g, "self") {
			t.Errorf("controller grant %s without metrics", g)
		}
	}
}

// Enabled metrics add exactly TokenReview and SubjectAccessReview create
// to the controller ServiceAccount, cluster-scoped, and nothing else; the
// reader role is get on /metrics bound only to the configured
// ServiceAccounts; namespace roles never include it.
func TestRuntimeChartMetricsEnabled(t *testing.T) {
	off, _, err := render(t, controllerNS, "image.digest="+digest)
	if err != nil {
		t.Fatal(err)
	}
	docs, _, err := render(t, controllerNS, "image.digest="+digest, "metrics.enabled=true",
		"metrics.readers[0].namespace=monitoring", "metrics.readers[0].name=prometheus-k8s",
		"metrics.readers[1].namespace=observability", "metrics.readers[1].name=vmagent")
	if err != nil {
		t.Fatal(err)
	}
	before, after := grantStrings(controllerGrants(t, off)), grantStrings(controllerGrants(t, docs))
	var added []string
	for _, g := range after {
		if !slices.Contains(before, g) {
			added = append(added, g)
		}
	}
	if fmt.Sprint(added) != fmt.Sprint(metricsGrants) {
		t.Errorf("metrics added controller grants %v, want exactly %v", added, metricsGrants)
	}
	for _, g := range before {
		if !slices.Contains(after, g) {
			t.Errorf("metrics removed controller grant %s", g)
		}
	}

	reader := find(docs, "ClusterRole", "konstapel-metrics-reader")
	if fmt.Sprint(reader["rules"]) != "[map[nonResourceURLs:[/metrics] verbs:[get]]]" {
		t.Errorf("reader rules %v", reader["rules"])
	}
	binding := find(docs, "ClusterRoleBinding", "konstapel-metrics-reader")
	if binding == nil || at(binding, "roleRef", "name") != "konstapel-metrics-reader" {
		t.Fatalf("reader binding %v", binding)
	}
	var subjects []string
	for _, s := range at(binding, "subjects").([]any) {
		s := s.(map[string]any)
		subjects = append(subjects, fmt.Sprintf("%s %s/%s", s["kind"], s["namespace"], s["name"]))
	}
	if fmt.Sprint(subjects) != "[ServiceAccount monitoring/prometheus-k8s ServiceAccount observability/vmagent]" {
		t.Errorf("reader subjects %v", subjects)
	}
	// No other role in the chart grants a non-resource URL, and no other
	// binding grants the reader role.
	for _, d := range docs {
		if (d["kind"] == "ClusterRole" || d["kind"] == "Role") && metadata(d)["name"] != "konstapel-metrics-reader" &&
			strings.Contains(fmt.Sprint(d["rules"]), "nonResourceURLs") {
			t.Errorf("%s %s grants non-resource URLs", d["kind"], metadata(d)["name"])
		}
		if (d["kind"] == "ClusterRoleBinding" || d["kind"] == "RoleBinding") && metadata(d)["name"] != "konstapel-metrics-reader" &&
			at(d, "roleRef", "name") == "konstapel-metrics-reader" {
			t.Errorf("%s %s binds the reader role", d["kind"], metadata(d)["name"])
		}
	}

	// HTTPS only, on the certificate issued for the Service name.
	args := controllerArgs(t, docs)
	for _, want := range []string{"--metrics-bind-address=:8443", "--metrics-cert-dir=/etc/konstapel/metrics-tls",
		"--metrics-server-name=konstapel-controller-metrics.konstapel-system.svc"} {
		if !slices.Contains(args, want) {
			t.Errorf("controller args %v lack %s", args, want)
		}
	}
	svc := find(docs, "Service", "konstapel-controller-metrics")
	if svc == nil || fmt.Sprint(at(svc, "spec", "ports")) != "[map[name:https port:443 protocol:TCP targetPort:metrics]]" {
		t.Errorf("metrics Service %v", svc)
	}
	cert := find(docs, "Certificate", "konstapel-controller-metrics")
	if cert == nil || !strings.Contains(fmt.Sprint(at(cert, "spec", "dnsNames")), "konstapel-controller-metrics.konstapel-system.svc") ||
		at(cert, "spec", "secretName") != "konstapel-controller-metrics-tls" {
		t.Errorf("metrics Certificate %v", cert)
	}
	pod, _ := controllerContainer(t, docs)
	if !strings.Contains(fmt.Sprint(pod["volumes"]), "secretName:konstapel-controller-metrics-tls") {
		t.Errorf("metrics certificate not mounted: %v", pod["volumes"])
	}

	// Operator-managed TLS mounts the named Secret and issues nothing.
	docs, _, err = render(t, controllerNS, "image.digest="+digest, "tls.mode=secret", "tls.secret.name=konstapel-download-tls",
		"metrics.enabled=true", "metrics.tls.secretName=metrics-tls")
	if err != nil {
		t.Fatal(err)
	}
	pod, _ = controllerContainer(t, docs)
	if !strings.Contains(fmt.Sprint(pod["volumes"]), "secretName:metrics-tls") || find(docs, "Certificate", "konstapel-controller-metrics") != nil {
		t.Errorf("operator TLS: volumes %v", pod["volumes"])
	}

	// Without download, cert-manager still gets the chart CA for metrics.
	docs, _, err = render(t, controllerNS, "image.digest="+digest, "download.enabled=false", "metrics.enabled=true")
	if err != nil {
		t.Fatal(err)
	}
	if find(docs, "Certificate", "konstapel-controller-metrics") == nil || find(docs, "Issuer", "konstapel-ca") == nil ||
		find(docs, "Certificate", "konstapel-download") != nil {
		t.Error("metrics certificate issuance without the download server")
	}
}
