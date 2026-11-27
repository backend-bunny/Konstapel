package charttest

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// add-external-assessment-providers 5.1: the example reporting provider's
// reference chart (examples/external-provider/reporting/chart,
// docs/integration/external-provider-chart.md). It installs a source worker
// and an evaluator under dedicated identities; the live acceptance
// (TestLiveReferenceProviderChart) installs the same chart.

const (
	referenceChart = "../../examples/external-provider/reporting/chart"
	referenceNS    = "providers"
	referenceHost  = "host.konstapel.example.test"
	workerName     = "ref-example-reporting-worker"
	evaluatorName  = "ref-example-reporting-evaluator"
)

func renderReference(t *testing.T, set ...string) ([]map[string]any, string, error) {
	t.Helper()
	args := []string{"template", "ref", referenceChart, "--namespace", referenceNS}
	for _, s := range set {
		args = append(args, "--set", s)
	}
	out, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		return nil, string(out), err
	}
	return documents(t, out), string(out), nil
}

func referenceBase(extra ...string) []string {
	return append([]string{"image.digest=" + digest, "worker.authorizedHosts[0]=" + referenceHost, "evaluator.authorizedHosts[0]=" + referenceHost}, extra...)
}

// podOf returns a Deployment's Pod spec and its one container.
func podOf(t *testing.T, docs []map[string]any, name string) (pod, c map[string]any) {
	t.Helper()
	d := find(docs, "Deployment", name)
	if d == nil {
		t.Fatalf("Deployment %s not rendered", name)
	}
	pod = at(d, "spec", "template", "spec").(map[string]any)
	cs := pod["containers"].([]any)
	if len(cs) != 1 || pod["initContainers"] != nil || pod["ephemeralContainers"] != nil {
		t.Fatalf("%s: want exactly one container, got %v", name, pod)
	}
	return pod, cs[0].(map[string]any)
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, fmt.Sprint(x))
	}
	return out
}

// Every rendered configuration grants exactly one permission, get on
// Namespaces, and only to the worker; the evaluator has no binding, no
// token and no source flag; both run the digest-pinned image, report it as
// their implementation, keep probes off the protocol port and mount their
// TLS Secrets read-only as whole volumes; the evaluator's NetworkPolicy
// denies all egress. Nothing registers the provider.
func TestReferenceProviderChartPermissions(t *testing.T) {
	for name, set := range map[string][]string{
		"defaults": nil,
		"replay host": {"evaluator.authorizedHosts[1]=replay.konstapel.example.test", "evaluator.hostNamespaces={konstapel-system,konstapel-replay}",
			"evaluator.replicaCount=2"},
		"own names": {"evaluator.serverName=evaluator.example.test",
			"tls.workerSecretName=w", "tls.evaluatorSecretName=e", "worker.hostNamespaces={a,b}", "evaluator.hostNamespaces={a,b}"},
		"ports": {"ports.protocol=9443", "ports.health=9090"},
	} {
		t.Run(name, func(t *testing.T) {
			docs, out, err := renderReference(t, referenceBase(set...)...)
			if err != nil {
				t.Fatal(out)
			}
			referencePermissions(t, docs, out)
		})
	}
}

func referencePermissions(t *testing.T, docs []map[string]any, out string) {
	t.Helper()
	kinds := map[string]int{}
	for _, d := range docs {
		kinds[fmt.Sprint(d["kind"])]++
		if strings.HasPrefix(fmt.Sprint(d["apiVersion"]), "compliance.erenius.io/") {
			t.Errorf("renders %v %v: the chart registers nothing", d["kind"], metadata(d)["name"])
		}
	}
	want := map[string]int{"ServiceAccount": 2, "ClusterRole": 1, "ClusterRoleBinding": 1, "Deployment": 2, "Service": 2, "NetworkPolicy": 2}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("rendered kinds %v, want %v", kinds, want)
	}
	if strings.Contains(out, "AssessmentProvider") {
		t.Error("the render mentions AssessmentProvider")
	}

	// Identities.
	worker, evaluator := find(docs, "ServiceAccount", workerName), find(docs, "ServiceAccount", evaluatorName)
	if worker == nil || evaluator == nil {
		t.Fatal("worker or evaluator ServiceAccount missing")
	}
	if worker["automountServiceAccountToken"] != true || evaluator["automountServiceAccountToken"] != false {
		t.Errorf("token automount: worker %v, evaluator %v", worker["automountServiceAccountToken"], evaluator["automountServiceAccountToken"])
	}

	// The one grant: get namespaces, to the worker.
	role := find(docs, "ClusterRole", workerName+"-"+referenceNS+"-source")
	if role == nil {
		t.Fatal("source ClusterRole missing")
	}
	if role["aggregationRule"] != nil {
		t.Error("the source role aggregates")
	}
	for k := range metadata(role)["labels"].(map[string]any) {
		if strings.HasPrefix(k, "rbac.authorization.k8s.io/aggregate-to-") {
			t.Errorf("the source role aggregates into a built-in role via %s", k)
		}
	}
	rules := role["rules"].([]any)
	wantRule := map[string]any{"apiGroups": []any{""}, "resources": []any{"namespaces"}, "verbs": []any{"get"}}
	if len(rules) != 1 || !reflect.DeepEqual(rules[0], wantRule) {
		t.Errorf("source rules %v, want only %v", rules, wantRule)
	}
	for _, d := range docs {
		if d["kind"] != "ClusterRoleBinding" && d["kind"] != "RoleBinding" {
			continue
		}
		if ref := at(d, "roleRef", "name"); ref != metadata(role)["name"] || at(d, "roleRef", "kind") != "ClusterRole" {
			t.Errorf("%v binds %v", metadata(d)["name"], ref)
		}
		subjects := at(d, "subjects").([]any)
		wantSubject := map[string]any{"kind": "ServiceAccount", "name": workerName, "namespace": referenceNS}
		if len(subjects) != 1 || !reflect.DeepEqual(subjects[0], wantSubject) {
			t.Errorf("%v subjects %v, want only the worker", metadata(d)["name"], subjects)
		}
	}

	// Pods.
	image := "localhost/konstapel-example-reporting@" + digest
	ports := map[string]float64{}
	for _, name := range []string{workerName, evaluatorName} {
		pod, c := podOf(t, docs, name)
		if pod["serviceAccountName"] != name {
			t.Errorf("%s runs as %v", name, pod["serviceAccountName"])
		}
		if c["image"] != image {
			t.Errorf("%s image %v, want %s", name, c["image"], image)
		}
		if c["env"] != nil || c["envFrom"] != nil || pod["hostNetwork"] == true || pod["enableServiceLinks"] != false {
			t.Errorf("%s: env %v envFrom %v hostNetwork %v serviceLinks %v", name, c["env"], c["envFrom"], pod["hostNetwork"], pod["enableServiceLinks"])
		}
		args := strs(c["args"])
		if !slices.Contains(args, "-implementation="+digest) {
			t.Errorf("%s does not report the image digest as its implementation: %v", name, args)
		}
		if at(pod, "securityContext", "runAsNonRoot") != true || at(c, "securityContext", "readOnlyRootFilesystem") != true ||
			at(c, "securityContext", "allowPrivilegeEscalation") != false || !reflect.DeepEqual(at(c, "securityContext", "capabilities", "drop"), []any{"ALL"}) ||
			at(pod, "securityContext", "seccompProfile", "type") != "RuntimeDefault" {
			t.Errorf("%s security context %v %v", name, pod["securityContext"], c["securityContext"])
		}
		for _, p := range c["ports"].([]any) {
			p := p.(map[string]any)
			ports[fmt.Sprint(p["name"])] = p["containerPort"].(float64)
		}
		for _, probe := range []string{"readinessProbe", "livenessProbe"} {
			if at(c, probe, "httpGet", "port") != "health" || at(c, probe, "tcpSocket") != nil || at(c, probe, "grpc") != nil {
				t.Errorf("%s %s %v is not on the health port", name, probe, c[probe])
			}
		}
		if ports["health"] == ports["protocol"] || ports["health"] == 0 {
			t.Errorf("%s ports %v", name, ports)
		}
		// Whole-Secret TLS volumes, read-only, so rotations reach the files.
		for _, m := range c["volumeMounts"].([]any) {
			m := m.(map[string]any)
			if m["readOnly"] != true || m["subPath"] != nil || !strings.HasPrefix(fmt.Sprint(m["mountPath"]), "/etc/example-reporting/") {
				t.Errorf("%s mount %v", name, m)
			}
		}
		for _, v := range pod["volumes"].([]any) {
			v := v.(map[string]any)
			if v["secret"] == nil || len(v) != 2 || at(v, "secret", "items") != nil {
				t.Errorf("%s volume %v is not a whole TLS Secret", name, v)
			}
		}
	}

	// The worker reads the source and forwards nothing; the evaluator reads
	// none.
	wpod, wc := podOf(t, docs, workerName)
	wargs := strs(wc["args"])
	for _, a := range []string{"-role=worker", "-source=kubernetes", "-authorized-hosts=" + referenceHost} {
		if !slices.Contains(wargs, a) {
			t.Errorf("worker args %v lack %s", wargs, a)
		}
	}
	if wpod["automountServiceAccountToken"] != true || len(wpod["volumes"].([]any)) != 1 {
		t.Errorf("worker pod %v, want only its serving TLS Secret: it has no evaluator client", wpod)
	}
	for _, a := range wargs {
		if strings.HasPrefix(a, "-evaluator-") {
			t.Errorf("worker arg %s: the worker never forwards evaluation", a)
		}
	}
	epod, ec := podOf(t, docs, evaluatorName)
	eargs := strs(ec["args"])
	if !slices.Contains(eargs, "-role=evaluator") {
		t.Errorf("evaluator args %v", eargs)
	}
	for _, a := range eargs {
		if strings.HasPrefix(a, "-source") || strings.HasPrefix(a, "-evaluator-") {
			t.Errorf("evaluator arg %s", a)
		}
	}
	if epod["automountServiceAccountToken"] != false {
		t.Errorf("evaluator token automount %v", epod["automountServiceAccountToken"])
	}
	if vs := epod["volumes"].([]any); len(vs) != 1 || at(vs[0], "projected") != nil {
		t.Errorf("evaluator volumes %v, want only its TLS Secret", vs)
	}
	if at(find(docs, "Deployment", workerName), "spec", "replicas") != float64(1) {
		t.Error("the worker stages results in memory and must run one replica")
	}

	// Services expose the protocol port only, never the probes.
	for _, name := range []string{workerName, evaluatorName} {
		s := find(docs, "Service", name)
		sp := at(s, "spec", "ports").([]any)
		if len(sp) != 1 || at(sp[0], "targetPort") != "protocol" || at(s, "spec", "type") != "ClusterIP" {
			t.Errorf("Service %s ports %v", name, sp)
		}
	}

	// The evaluator may open no connection at all and is reached only from
	// the host namespaces, never from the worker.
	np := find(docs, "NetworkPolicy", evaluatorName)
	if np == nil || !reflect.DeepEqual(at(np, "spec", "policyTypes"), []any{"Ingress", "Egress"}) ||
		!reflect.DeepEqual(at(np, "spec", "egress"), []any{}) {
		t.Fatalf("evaluator NetworkPolicy %v does not deny all egress", np)
	}
	if at(np, "spec", "podSelector", "matchLabels", "app.kubernetes.io/component") != "evaluator" {
		t.Errorf("evaluator NetworkPolicy selects %v", at(np, "spec", "podSelector"))
	}
	from := at(np, "spec", "ingress", 0, "from").([]any)
	if len(from) == 0 {
		t.Errorf("evaluator ingress %v admits no host namespace", from)
	}
	for _, f := range from {
		if at(f, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") == nil || at(f, "podSelector") != nil {
			t.Errorf("evaluator ingress peer %v", f)
		}
	}
	if len(at(np, "spec", "ingress").([]any)) != 1 {
		t.Errorf("evaluator ingress rules %v", at(np, "spec", "ingress"))
	}
	wnp := find(docs, "NetworkPolicy", workerName)
	if wnp == nil || !reflect.DeepEqual(at(wnp, "spec", "policyTypes"), []any{"Ingress"}) {
		t.Fatalf("worker NetworkPolicy %v", wnp)
	}
}

// The evaluator is the registration's separate evaluator endpoint
// (add-external-assessment-providers design Decision 11): it authorizes
// exactly the listed host identities, from the host namespaces, and never
// the worker, which has no client identity for it.
func TestReferenceProviderChartPeerNames(t *testing.T) {
	docs, out, err := renderReference(t, referenceBase()...)
	if err != nil {
		t.Fatal(out)
	}
	_, ec := podOf(t, docs, evaluatorName)
	if !slices.Contains(strs(ec["args"]), "-authorized-hosts="+referenceHost) {
		t.Errorf("evaluator args %v, want exactly the host", ec["args"])
	}
	np := find(docs, "NetworkPolicy", evaluatorName)
	if ns := at(np, "spec", "ingress", 0, "from", 0, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name"); ns != "konstapel-system" {
		t.Errorf("evaluator ingress from %v, want the host namespace", ns)
	}
	if strings.Contains(out, "client-tls") || strings.Contains(out, "evaluator-addr") {
		t.Error("the render still wires a worker-to-evaluator client")
	}

	docs, out, err = renderReference(t, referenceBase("evaluator.authorizedHosts[1]=replay.konstapel.example.test")...)
	if err != nil {
		t.Fatal(out)
	}
	_, ec = podOf(t, docs, evaluatorName)
	if !slices.Contains(strs(ec["args"]), "-authorized-hosts="+referenceHost+",replay.konstapel.example.test") {
		t.Errorf("evaluator args %v", ec["args"])
	}
}

// Unsafe or incomplete values fail the render.
func TestReferenceProviderChartRefusesUnsafeValues(t *testing.T) {
	host := "worker.authorizedHosts[0]=" + referenceHost
	for name, c := range map[string]struct {
		set  []string
		want string
	}{
		"no digest":                         {[]string{host}, "image.digest is required"},
		"a tag":                             {[]string{host, "image.digest=latest"}, "/image/digest"},
		"another algorithm":                 {[]string{host, "image.digest=sha512:" + strings.Repeat("a", 64)}, "/image/digest"},
		"repository with digest":            {[]string{host, "image.digest=" + digest, "image.repository=localhost/x@" + digest}, "/image/repository"},
		"no authorized host":                {[]string{"image.digest=" + digest}, "worker.authorizedHosts is required"},
		"no evaluator host":                 {[]string{"image.digest=" + digest, host}, "evaluator.authorizedHosts is required"},
		"evaluator without host namespaces": {referenceBase("evaluator.hostNamespaces={}"), "hostNamespaces"},
		"evaluator at the worker's name": {referenceBase("evaluator.serverName=" + workerName + "." + referenceNS + ".svc"),
			"evaluator.serverName must differ"},
		"worker client identity":  {referenceBase("worker.clientName=worker.example.test"), "clientName"},
		"wildcard host":           {[]string{"image.digest=" + digest, "worker.authorizedHosts[0]=*.example.test"}, "authorizedHosts"},
		"probes on protocol port": {referenceBase("ports.health=8443"), "must differ"},
		"unknown value":           {referenceBase("worker.serviceAccountName=default"), "serviceAccountName"},
		"evaluator source":        {referenceBase("evaluator.source=kubernetes"), "source"},
		"worker replicas":         {referenceBase("worker.replicaCount=2"), "replicaCount"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, out, err := renderReference(t, c.set...); err == nil || !strings.Contains(out, c.want) {
				t.Errorf("render: %v, want an error mentioning %q:\n%s", err, c.want, out)
			}
		})
	}
}

// The chart passes strict lint with its required values.
func TestReferenceProviderChartLints(t *testing.T) {
	args := []string{"lint", "--strict", referenceChart, "--namespace", referenceNS}
	for _, s := range referenceBase() {
		args = append(args, "--set", s)
	}
	if out, err := exec.Command("helm", args...).CombinedOutput(); err != nil {
		t.Fatalf("helm lint: %v\n%s", err, out)
	}
}

// referenceMarkers identify the example provider: its provider name, check
// group, module path, image and chart names.
var referenceMarkers = []string{"example-reporting", "reporting.example.test", "example.com/konstapel-reporting", "konstapel-example-reporting"}

// Default absence from production registration: neither Konstapel chart,
// with its defaults or any documented values example, renders an
// AssessmentProvider or names the example provider, its image or its chart.
// The bundles, binaries and image payload are checked by
// internal/provider/installed (TestReferenceProviderIsNotShipped) and
// scripts/image/test.sh.
func TestChartsRegisterNoReferenceProvider(t *testing.T) {
	scan := func(name, out string) {
		t.Helper()
		if !strings.Contains(out, "kind: ") {
			t.Fatalf("%s rendered nothing", name)
		}
		for _, d := range documents(t, []byte(out)) {
			if d["kind"] == "AssessmentProvider" {
				t.Errorf("%s registers provider %v", name, metadata(d)["name"])
			}
		}
		for _, m := range referenceMarkers {
			if strings.Contains(out, m) {
				t.Errorf("%s names the example provider (%q)", name, m)
			}
		}
	}
	crds, err := exec.Command("helm", "template", "konstapel-crds", "../../charts/konstapel-crds").CombinedOutput()
	if err != nil {
		t.Fatalf("render konstapel-crds: %v\n%s", err, crds)
	}
	scan("konstapel-crds", string(crds))
	_, out, err := render(t, controllerNS, "image.digest="+digest)
	if err != nil {
		t.Fatal(out)
	}
	scan("konstapel defaults", out)
	examples, _ := filepath.Glob("../../docs/examples/charts/*.yaml")
	if len(examples) == 0 {
		t.Fatal("no values examples")
	}
	for _, f := range examples {
		raw, err := exec.Command("helm", "template", "konstapel", "../../charts/konstapel", "--namespace", controllerNS,
			"--set", "image.digest="+digest, "-f", f).CombinedOutput()
		if err != nil {
			t.Fatalf("render %s: %v\n%s", f, err, raw)
		}
		scan("konstapel with "+filepath.Base(f), string(raw))
	}
	// The scan is real: the reference chart's own render shows the markers.
	_, ref, err := renderReference(t, referenceBase()...)
	if err != nil || !strings.Contains(ref, "konstapel-example-reporting") {
		t.Fatalf("the reference render does not show its markers: %v", err)
	}
}
