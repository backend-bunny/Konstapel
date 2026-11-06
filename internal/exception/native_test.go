package exception

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/cel-go/cel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	admissioncel "k8s.io/apiserver/pkg/admission/plugin/cel"
	apiservercel "k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/environment"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const (
	nativeRevA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	nativeRevB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	excNS      = "policy-exceptions"
	snapRef    = "konstapel-system/acceptance-ex-1-1"
	snapDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

func nativeSnapshot(sel metav1.LabelSelector) *Snapshot {
	s := &Snapshot{Version: SnapshotVersion, Cluster: cluster, AcceptanceRevision: 1,
		Namespace: targeting.NamespaceRef{Name: "team-a", UID: "ns-a-1"}, Policy: policy, WorkloadSelector: sel,
		Reason: "debugging", Actor: Actor{Username: "alice"}, AcceptedAt: metav1.NewTime(t0), ExpiresAt: metav1.NewTime(t0.Add(48 * time.Hour)),
		Eligibility: targeting.Eligibility{Namespace: targeting.NamespaceRef{Name: "team-a", UID: "ns-a-1"}, Policy: policy,
			Effective: v1alpha1.ExceptionsSelfService, MaxLifetime: &targeting.Duration{Duration: 720 * time.Hour},
			Contributors: []targeting.ContributionRef{
				{Binding: targeting.ObjectRevision{Name: "baseline", UID: "b-1", Generation: 1}, Mode: v1alpha1.ModeDeny, Revision: nativeRevA},
				{Binding: targeting.ObjectRevision{Name: "prod-extra", UID: "b-2", Generation: 3}, Mode: v1alpha1.ModeAudit, Revision: nativeRevB},
			}}}
	s.Exception.Name, s.Exception.Namespace, s.Exception.UID = "priv", "team-a", "ex-1"
	return s
}

func render(t *testing.T, s *Snapshot) *unstructured.Unstructured {
	t.Helper()
	obj, err := RenderNative(s, snapRef, snapDigest, excNS)
	if err != nil {
		t.Fatal(err)
	}
	return obj
}

func conditionsOf(t *testing.T, obj *unstructured.Unstructured) []map[string]any {
	t.Helper()
	raw, _, _ := unstructured.NestedSlice(obj.Object, "spec", "matchConditions")
	var out []map[string]any
	for _, c := range raw {
		out = append(out, c.(map[string]any))
	}
	return out
}

func TestNativeExceptionIsBoundedToTheAcceptance(t *testing.T) {
	s := nativeSnapshot(metav1.LabelSelector{MatchLabels: map[string]string{"app": "debug"}})
	before := *s
	obj := render(t, s)
	if !reflect.DeepEqual(before, *s) {
		t.Error("rendering changed the snapshot")
	}
	if obj.GroupVersionKind() != NativeExceptionGVK || obj.GetNamespace() != excNS || obj.GetName() != NativeName("ex-1", 1) {
		t.Errorf("identity = %s %s/%s", obj.GroupVersionKind(), obj.GetNamespace(), obj.GetName())
	}
	spec := obj.Object["spec"].(map[string]any)
	if spec["reportResult"] != "skip" {
		t.Errorf("reportResult = %v", spec["reportResult"])
	}
	for _, forbidden := range []string{"images", "allowedValues", "evaluationMode"} {
		if _, ok := spec[forbidden]; ok {
			t.Errorf("spec sets %s", forbidden)
		}
	}
	expires, err := time.Parse(time.RFC3339, spec["expiresAt"].(string))
	if err != nil || expires.After(s.ExpiresAt.Time) {
		t.Errorf("expiresAt %v is later than the acceptance %v (%v)", spec["expiresAt"], s.ExpiresAt, err)
	}
	// Exactly the engine policies rendered for the accepted revisions.
	var want []string
	for _, c := range s.Eligibility.Contributors {
		want = append(want, targeting.PolicyName(targeting.Contribution{Binding: c.Binding, Policy: s.Policy, Revision: c.Revision}))
	}
	var got []string
	for _, r := range spec["policyRefs"].([]any) {
		ref := r.(map[string]any)
		if ref["kind"] != "ValidatingPolicy" {
			t.Errorf("policyRef kind %v", ref["kind"])
		}
		got = append(got, ref["name"].(string))
	}
	if len(got) != 2 || !strings.Contains(strings.Join(want, ","), got[0]) || !strings.Contains(strings.Join(want, ","), got[1]) || got[0] == got[1] {
		t.Errorf("policyRefs = %v, want %v", got, want)
	}
	if obj.GetAnnotations()[AnnotationSnapshot] != snapRef || obj.GetAnnotations()[AnnotationSnapshotDigest] != snapDigest {
		t.Errorf("annotations = %v", obj.GetAnnotations())
	}
	props := spec["properties"].(map[string]any)
	if props[PropertySnapshot] != snapRef || props[PropertySnapshotDigest] != snapDigest {
		t.Errorf("properties = %v", props)
	}
	if l := obj.GetLabels(); l[LabelExceptionUID] != "ex-1" || l[LabelNamespaceUID] != "ns-a-1" || l[LabelAcceptanceRevision] != "1" ||
		l[targeting.LabelManagedBy] != targeting.ManagedByValue || l[LabelComponent] != ComponentNativeException {
		t.Errorf("labels = %v", l)
	}
}

func TestSiblingAcceptancesGetDistinctNativeExceptions(t *testing.T) {
	base := nativeSnapshot(metav1.LabelSelector{})
	renewed := nativeSnapshot(metav1.LabelSelector{})
	renewed.AcceptanceRevision = 2
	other := nativeSnapshot(metav1.LabelSelector{})
	other.Exception.UID = "ex-2"
	names := map[string]bool{}
	for _, s := range []*Snapshot{base, renewed, other} {
		names[render(t, s).GetName()] = true
	}
	if len(names) != 3 {
		t.Errorf("names collide: %v", names)
	}
	if n := NativeName("ex-1", 1); len(n) > 63 {
		t.Errorf("name %q is longer than 63", n)
	}
}

func TestNativeRenderRefusesUnboundedGrants(t *testing.T) {
	for name, mutate := range map[string]func(*Snapshot){
		"no namespace uid": func(s *Snapshot) { s.Namespace.UID = "" },
		"no namespace":     func(s *Snapshot) { s.Namespace.Name = "" },
		"no contributions": func(s *Snapshot) { s.Eligibility.Contributors = nil },
		"no expiry":        func(s *Snapshot) { s.ExpiresAt = metav1.Time{} },
		"bad operator": func(s *Snapshot) {
			s.WorkloadSelector.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "app", Operator: "Matches", Values: []string{"x"}}}
		},
		"in without values": func(s *Snapshot) {
			s.WorkloadSelector.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "app", Operator: metav1.LabelSelectorOpIn}}
		},
		"exists with values": func(s *Snapshot) {
			s.WorkloadSelector.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "app", Operator: metav1.LabelSelectorOpExists, Values: []string{"x"}}}
		},
		"invalid key": func(s *Snapshot) { s.WorkloadSelector.MatchLabels = map[string]string{`a" || true || "`: "x"} },
		"invalid value": func(s *Snapshot) { s.WorkloadSelector.MatchLabels = map[string]string{"app": `x" || true || "`} },
	} {
		t.Run(name, func(t *testing.T) {
			s := nativeSnapshot(metav1.LabelSelector{MatchLabels: map[string]string{"app": "debug"}})
			mutate(s)
			if _, err := RenderNative(s, snapRef, snapDigest, excNS); err == nil {
				t.Error("rendered")
			}
		})
	}
	if _, err := RenderNative(nativeSnapshot(metav1.LabelSelector{}), snapRef, snapDigest, ""); err == nil {
		t.Error("rendered without an exception namespace")
	}
}

// kyvernoEnv type-checks expressions the way Kyverno 1.19 compiles
// PolicyException matchConditions: the Kubernetes base CEL environment with a
// typed namespaceObject and dynamic object/oldObject.
func kyvernoEnv(t *testing.T) *cel.Env {
	t.Helper()
	ns, req := admissioncel.BuildNamespaceType(), admissioncel.BuildRequestType()
	base := environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion())
	stored, err := base.Env(environment.StoredExpressions)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := apiservercel.NewDeclTypeProvider(ns, req).EnvOptions(stored.CELTypeProvider())
	if err != nil {
		t.Fatal(err)
	}
	opts = append(opts, cel.Variable("namespaceObject", ns.CelType()), cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType), cel.Variable("request", req.CelType()))
	env, err := stored.Extend(opts...)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// dynEnv evaluates the same expressions with map-valued variables.
func dynEnv(t *testing.T) *cel.Env {
	t.Helper()
	stored, err := environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()).Env(environment.StoredExpressions)
	if err != nil {
		t.Fatal(err)
	}
	env, err := stored.Extend(cel.Variable("namespaceObject", cel.DynType), cel.Variable("object", cel.DynType))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

type selectorFixtures struct {
	Cases []struct {
		Name     string               `json:"name"`
		Note     string               `json:"note,omitempty"`
		Selector metav1.LabelSelector `json:"selector"`
		Probes   []struct {
			Namespace *struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			} `json:"namespace"`
			Labels map[string]string `json:"labels"`
			Match  bool              `json:"match"`
		} `json:"probes"`
	} `json:"cases"`
}

func TestNativeMatchConditionFixtures(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/exceptions/native/selectors.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var f selectorFixtures
	if err := yaml.UnmarshalStrict(raw, &f); err != nil {
		t.Fatal(err)
	}
	typed, dyn := kyvernoEnv(t), dynEnv(t)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			conds := conditionsOf(t, render(t, nativeSnapshot(c.Selector)))
			var programs []cel.Program
			for _, cond := range conds {
				expr := cond["expression"].(string)
				if _, iss := typed.Compile(expr); iss.Err() != nil {
					t.Fatalf("%s does not compile in the engine environment: %v", expr, iss.Err())
				}
				ast, iss := dyn.Compile(expr)
				if iss.Err() != nil {
					t.Fatal(iss.Err())
				}
				p, err := dyn.Program(ast)
				if err != nil {
					t.Fatal(err)
				}
				programs = append(programs, p)
			}
			for i, probe := range c.Probes {
				var ns any
				if probe.Namespace != nil {
					ns = map[string]any{"metadata": map[string]any{"name": probe.Namespace.Name, "uid": probe.Namespace.UID}}
				}
				meta := map[string]any{"name": "w", "namespace": "team-a"}
				if probe.Labels != nil {
					labels := map[string]any{}
					for k, v := range probe.Labels {
						labels[k] = v
					}
					meta["labels"] = labels
				}
				vars := map[string]any{"namespaceObject": ns, "object": map[string]any{"metadata": meta}}
				matched := true
				for j, p := range programs {
					out, _, err := p.Eval(vars)
					if err != nil {
						t.Fatalf("probe %d: %s: %v", i, conds[j]["expression"], err)
					}
					if out.Value() != true {
						matched = false
					}
				}
				if matched != probe.Match {
					t.Errorf("probe %d (%+v): matched=%v, want %v", i, probe, matched, probe.Match)
				}
			}
		})
	}
}

// Any string, including quotes, backslashes and control or non-ASCII bytes,
// round-trips through celString unchanged.
func TestCELStringLiteralsCannotEscape(t *testing.T) {
	env := dynEnv(t)
	for _, s := range []string{"", "plain", `quote"inside`, `back\slash`, `\"`, "new\nline", "tab\t", "uniécode", "\x00nul", `" || true || "`, "end\\"} {
		envX, _ := env.Extend(cel.Variable("x", cel.StringType))
		ast, iss := envX.Compile(celString(s) + " == x")
		if iss.Err() != nil {
			t.Fatalf("%q: %v", s, iss.Err())
		}
		p, err := envX.Program(ast)
		if err != nil {
			t.Fatal(err)
		}
		out, _, err := p.Eval(map[string]any{"x": s})
		if err != nil || out.Value() != true {
			t.Errorf("%q does not round-trip: %v %v", s, out, err)
		}
	}
}
