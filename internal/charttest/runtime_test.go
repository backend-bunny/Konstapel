package charttest

import (
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func render(t *testing.T, ns string, set ...string) ([]map[string]any, string, error) {
	t.Helper()
	args := []string{"template", "konstapel", "../../charts/konstapel", "--namespace", ns}
	for _, s := range set {
		args = append(args, "--set", s)
	}
	out, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		return nil, string(out), err
	}
	return documents(t, out), string(out), nil
}

func find(docs []map[string]any, kind, name string) map[string]any {
	for _, d := range docs {
		if d["kind"] == kind && metadata(d)["name"] == name {
			return d
		}
	}
	return nil
}

func at(o any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, _ := o.(map[string]any)
			o = m[k]
		case int:
			s, _ := o.([]any)
			if k >= len(s) {
				return nil
			}
			o = s[k]
		}
	}
	return o
}

// The default runtime render carries the availability and security
// defaults and binds only roles it ships.
func TestRuntimeChartDefaults(t *testing.T) {
	docs, _, err := render(t, "konstapel-system", "image.digest="+digest)
	if err != nil {
		t.Fatal(err)
	}
	d := find(docs, "Deployment", "konstapel-controller")
	if d == nil {
		t.Fatal("no controller Deployment")
	}
	spec := d["spec"].(map[string]any)
	selector := at(spec, "selector", "matchLabels").(map[string]any)
	for k := range selector {
		if strings.Contains(k, "version") || strings.Contains(k, "hash") {
			t.Errorf("selector carries a revision-specific label %s", k)
		}
	}
	pod := at(spec, "template", "spec").(map[string]any)
	c := at(pod, "containers", 0).(map[string]any)
	args := c["args"].([]any)
	checks := map[string]bool{
		"two replicas":                       at(spec, "replicas") == float64(2),
		"zero unavailable":                   at(spec, "strategy", "rollingUpdate", "maxUnavailable") == float64(0),
		"one surge":                          at(spec, "strategy", "rollingUpdate", "maxSurge") == float64(1),
		"60s grace":                          pod["terminationGracePeriodSeconds"] == float64(60),
		"preferred anti-affinity":            at(pod, "affinity", "podAntiAffinity", "preferredDuringSchedulingIgnoredDuringExecution", 0, "weight") == float64(100),
		"hostname topology":                  at(pod, "affinity", "podAntiAffinity", "preferredDuringSchedulingIgnoredDuringExecution", 0, "podAffinityTerm", "topologyKey") == "kubernetes.io/hostname",
		"no required separation":             at(pod, "affinity", "podAntiAffinity", "requiredDuringSchedulingIgnoredDuringExecution") == nil,
		"anti-affinity selects all replicas": reflect.DeepEqual(at(pod, "affinity", "podAntiAffinity", "preferredDuringSchedulingIgnoredDuringExecution", 0, "podAffinityTerm", "labelSelector", "matchLabels"), any(selector)),
		"digest image":                       c["image"] == "ghcr.io/backend-bunny/konstapel@"+digest,
		"controller entry point":             args[0] == "controller",
		"election on":                        slices.Contains(args, any("--leader-elect=true")),
		"45s shutdown":                       slices.Contains(args, any("--shutdown-timeout=45s")),
		"non-root":                           at(pod, "securityContext", "runAsNonRoot") == true,
		"read-only root":                     at(c, "securityContext", "readOnlyRootFilesystem") == true,
		"no escalation":                      at(c, "securityContext", "allowPrivilegeEscalation") == false,
		"capabilities dropped":               reflect.DeepEqual(at(c, "securityContext", "capabilities", "drop"), any([]any{"ALL"})),
		"liveness /healthz":                  at(c, "livenessProbe", "httpGet", "path") == "/healthz",
		"readiness /readyz":                  at(c, "readinessProbe", "httpGet", "path") == "/readyz",
		"bounded staging":                    at(pod, "volumes", 0, "emptyDir", "sizeLimit") == "2Gi",
		"pod namespace":                      at(c, "env", 0, "name") == "POD_NAMESPACE",
	}
	for name, ok := range checks {
		if !ok {
			t.Errorf("Deployment: %s", name)
		}
	}
	pdb := find(docs, "PodDisruptionBudget", "konstapel-controller")
	if pdb == nil || at(pdb, "spec", "minAvailable") != float64(1) || !reflect.DeepEqual(at(pdb, "spec", "selector", "matchLabels"), any(selector)) {
		t.Fatalf("PodDisruptionBudget: %v", pdb)
	}
	// Every binding refers to a role the chart renders, for the chart's
	// ServiceAccount.
	for _, d := range docs {
		if d["kind"] != "ClusterRoleBinding" && d["kind"] != "RoleBinding" {
			continue
		}
		roleKind := at(d, "roleRef", "kind").(string)
		if find(docs, roleKind, at(d, "roleRef", "name").(string)) == nil {
			t.Errorf("%v %v binds a %s the chart does not ship", d["kind"], metadata(d)["name"], roleKind)
		}
		if at(d, "subjects", 0, "name") != "konstapel-controller" || at(d, "subjects", 0, "namespace") != "konstapel-system" {
			t.Errorf("%v %v binds %v", d["kind"], metadata(d)["name"], d["subjects"])
		}
	}
	for _, kind := range []string{"MutatingAdmissionPolicy", "ValidatingAdmissionPolicy", "ServiceAccount"} {
		if !slices.ContainsFunc(docs, func(d map[string]any) bool { return d["kind"] == kind }) {
			t.Errorf("no %s rendered", kind)
		}
	}
}

// Development runs one replica, still elected, without the default PDB.
func TestRuntimeChartDevelopment(t *testing.T) {
	docs, _, err := render(t, "konstapel-system", "image.digest="+digest, "replicaCount=1")
	if err != nil {
		t.Fatal(err)
	}
	if find(docs, "PodDisruptionBudget", "konstapel-controller") != nil {
		t.Fatal("one replica renders a PodDisruptionBudget")
	}
	d := find(docs, "Deployment", "konstapel-controller")
	if at(d, "spec", "replicas") != float64(1) || !slices.Contains(at(d, "spec", "template", "spec", "containers", 0, "args").([]any), any("--leader-elect=true")) {
		t.Fatal("development Deployment")
	}
}

func TestRuntimeChartRefusesUnsafeInstalls(t *testing.T) {
	for name, c := range map[string]struct {
		ns   string
		set  []string
		want string
	}{
		"other namespace": {"konstapel", []string{"image.digest=" + digest}, "into the konstapel-system namespace"},
		"no digest":       {"konstapel-system", nil, "image.digest is required"},
	} {
		if _, out, err := render(t, c.ns, c.set...); err == nil || !strings.Contains(out, c.want) {
			t.Errorf("%s: %v %s", name, err, out)
		}
	}
}
