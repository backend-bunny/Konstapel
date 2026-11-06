//go:build live

package controller

// Live manager acceptance (tasks 4.1/4.2). Run through scripts/targeting-live.sh
// against a disposable cluster with Kyverno installed. The manager runs
// in-process with the vendored content.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

type live struct {
	t   *testing.T
	ctx context.Context
	cfg *rest.Config
	c   client.Client
	out string
	log []map[string]any
	// s3Container is the test-owned S3 service started by startS3, and its
	// endpoint and credentials.
	s3Container, s3Endpoint, s3Access, s3Secret string
}

func newLive(t *testing.T) *live {
	kc, kctx, out := os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"), os.Getenv("KONSTAPEL_LIVE_CONTEXT"), os.Getenv("KONSTAPEL_LIVE_OUTPUT")
	if kc == "" || kctx == "" || out == "" {
		t.Fatal("KONSTAPEL_LIVE_KUBECONFIG, KONSTAPEL_LIVE_CONTEXT and KONSTAPEL_LIVE_OUTPUT are required")
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{ExplicitPath: kc},
		&clientcmd.ConfigOverrides{CurrentContext: kctx}).ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	s := Scheme()
	_ = apiextensionsv1.AddToScheme(s)
	c, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	t.Cleanup(cancel)
	l := &live{t: t, ctx: ctx, cfg: cfg, c: c, out: out}
	t.Cleanup(func() {
		b, _ := json.MarshalIndent(l.log, "", "  ")
		// One evidence file per test, so a later test never overwrites it.
		_ = os.WriteFile(filepath.Join(out, t.Name()+".json"), b, 0o644)
	})
	return l
}

func (l *live) record(step string, f map[string]any) {
	f["step"], f["at"] = step, time.Now().UTC().Format(time.RFC3339)
	l.log = append(l.log, f)
	l.t.Logf("%s: %v", step, f)
}

func (l *live) eventually(what string, f func() (bool, string)) {
	l.t.Helper()
	deadline, last := time.Now().Add(3*time.Minute), ""
	for time.Now().Before(deadline) {
		ok, detail := f()
		if ok {
			return
		}
		last = detail
		time.Sleep(2 * time.Second)
	}
	l.t.Fatalf("timed out waiting for %s: %s", what, last)
}

// startManager runs a manager until the returned stop function is called.
func (l *live) startManager() (stop func()) {
	mgr, err := NewManager(l.cfg, Options{Content: content, MetricsAddr: "0", ProbeAddr: "0", EnginePoll: 2 * time.Second, SkipControllerNameValidation: true})
	if err != nil {
		l.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(l.ctx)
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	return func() {
		cancel()
		if err := <-done; err != nil {
			l.t.Errorf("manager exited: %v", err)
		}
	}
}

func (l *live) installCRDs() {
	files, _ := filepath.Glob("../../config/crd/bases/*.yaml")
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.UnmarshalStrict(raw, crd); err != nil {
			l.t.Fatal(err)
		}
		if err := l.c.Create(l.ctx, crd); err != nil && !apierrors.IsAlreadyExists(err) {
			l.t.Fatal(err)
		}
		l.eventually("CRD established", func() (bool, string) {
			got := &apiextensionsv1.CustomResourceDefinition{}
			if err := l.c.Get(l.ctx, client.ObjectKey{Name: crd.Name}, got); err != nil {
				return false, err.Error()
			}
			for _, c := range got.Status.Conditions {
				if c.Type == apiextensionsv1.Established && c.Status == apiextensionsv1.ConditionTrue {
					return true, ""
				}
			}
			return false, "pending"
		})
	}
}

// envLabel is unique to this test, so namespaces left by other live tests on
// the same cluster never match its bindings.
const envLabel = "manager-test.konstapel.dev/environment"

func (l *live) setNamespace(name, env string) {
	ns := &corev1.Namespace{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, ns); apierrors.IsNotFound(err) {
		ns.Name, ns.Labels = name, map[string]string{envLabel: env}
		if err := l.c.Create(l.ctx, ns); err != nil {
			l.t.Fatal(err)
		}
		return
	} else if err != nil {
		l.t.Fatal(err)
	}
	ns.Labels[envLabel] = env
	if err := l.c.Update(l.ctx, ns); err != nil {
		l.t.Fatal(err)
	}
}

func (l *live) binding(name string) *v1alpha1.ComplianceBinding {
	b := &v1alpha1.ComplianceBinding{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, b); err != nil {
		l.t.Fatal(err)
	}
	return b
}

// waitReady waits until the binding's status is current and EngineReady.
func (l *live) waitReady(name string, targets int32) *v1alpha1.ComplianceBinding {
	l.t.Helper()
	var b *v1alpha1.ComplianceBinding
	l.eventually(name+" ready", func() (bool, string) {
		b = l.binding(name)
		c := meta.FindStatusCondition(b.Status.Conditions, v1alpha1.ConditionEngineReady)
		if b.Status.ObservedGeneration != b.Generation || c == nil || c.Status != metav1.ConditionTrue || c.ObservedGeneration != b.Generation ||
			b.Status.TargetCount == nil || *b.Status.TargetCount != targets {
			return false, toJSON(b.Status)
		}
		return true, ""
	})
	return b
}

func (l *live) managedPolicies() map[string]string {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(targeting.ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
	if err := l.c.List(l.ctx, list, client.MatchingLabels{targeting.LabelManagedBy: targeting.ManagedByValue}); err != nil {
		l.t.Fatal(err)
	}
	out := map[string]string{}
	for _, o := range list.Items {
		out[o.GetName()] = o.GetResourceVersion() + "/" + toJSON(o.Object["spec"])
	}
	return out
}

func (l *live) denied(ns string) (bool, string) {
	privileged := true
	err := l.c.Create(l.ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "probe", Namespace: ns},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &privileged}}}}},
		client.DryRunAll)
	if err == nil {
		return false, ""
	}
	return true, err.Error()
}

// docCommands returns the troubleshooting commands from the targeting guide,
// with continuation lines joined and comments dropped, so the documented text
// is what runs.
func docCommands(t *testing.T) []string {
	raw, err := os.ReadFile("../../docs/integration/targeting-api.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(raw), "### Troubleshooting\n")
	_, rest, okFence := strings.Cut(section, "```sh\n")
	block, _, ok2 := strings.Cut(rest, "```")
	ok = ok && okFence
	if !ok || !ok2 {
		t.Fatal("troubleshooting block not found in docs/integration/targeting-api.md")
	}
	var cmds []string
	cur := ""
	for _, line := range strings.Split(block, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			cur += strings.TrimSuffix(line, "\\")
			continue
		}
		cmds = append(cmds, cur+line)
		cur = ""
	}
	return cmds
}

// runDocCommands runs the documented commands for one binding and policy with
// the disposable cluster's kubeconfig (whose current context is that cluster).
func (l *live) runDocCommands(binding, policy string) string {
	l.t.Helper()
	var out strings.Builder
	for _, c := range docCommands(l.t) {
		c = strings.ReplaceAll(strings.ReplaceAll(c, "BINDING", binding), "POLICY", policy)
		cmd := exec.CommandContext(l.ctx, "bash", "-c", c)
		cmd.Env = append(os.Environ(), "KUBECONFIG="+os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"))
		b, err := cmd.CombinedOutput()
		if err != nil {
			l.t.Fatalf("documented command failed: %s\n%s", c, b)
		}
		fmt.Fprintf(&out, "$ %s\n%s", c, b)
	}
	return out.String()
}

// runDocCommandsQuiet returns the binding's owned policy names via the
// documented label query, to find the policy argument for the other commands.
func (l *live) runDocCommandsQuiet(binding string) string {
	cmd := exec.CommandContext(l.ctx, "bash", "-c", "kubectl get validatingpolicies -l compliance.erenius.io/binding-uid=$(kubectl get compliancebinding "+binding+" -o jsonpath='{.metadata.uid}') -o name")
	cmd.Env = append(os.Environ(), "KUBECONFIG="+os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"))
	b, _ := cmd.CombinedOutput()
	return string(b)
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestLiveManager(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	l.setNamespace("manager-prod", "production")
	l.setNamespace("manager-dev", "development")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "manager-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	deny := bindingObj("manager-deny-prod", p.Name, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{envLabel: "production"})
	audit := bindingObj("manager-audit-dev", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "development"})
	for _, o := range []client.Object{p, deny, audit} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	// 1. The manager delivers and reports EngineReady.
	stop := l.startManager()
	l.waitReady(deny.Name, 1)
	l.waitReady(audit.Name, 1)
	l.eventually("denial in production", func() (bool, string) {
		ok, msg := l.denied("manager-prod")
		return ok && strings.Contains(msg, "konstapel-"), msg
	})
	if ok, msg := l.denied("manager-dev"); ok {
		t.Fatalf("development denied: %s", msg)
	}
	l.eventually("profile resolved", func() (bool, string) {
		got := &v1alpha1.ComplianceProfile{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(p), got)
		c := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionResolved)
		return c != nil && c.Status == metav1.ConditionTrue && c.ObservedGeneration == got.Generation, toJSON(got.Status)
	})
	before := l.managedPolicies()
	denyRV, auditRV := l.binding(deny.Name).ResourceVersion, l.binding(audit.Name).ResourceVersion
	l.record("ready", map[string]any{"policies": len(before)})

	// The documented troubleshooting commands tell resolved scope and engine
	// readiness apart, for a ready binding and for one whose profile is missing.
	var denyPolicy string
	for name := range before {
		if strings.Contains(l.runDocCommandsQuiet(deny.Name), name) {
			denyPolicy = name
		}
	}
	readyOut := l.runDocCommands(deny.Name, denyPolicy)
	for _, want := range []string{"Resolved=True Resolved", "EngineReady=True Ready", "not a compliance result", denyPolicy, "sha256:", "WebhookConfigured"} {
		if !strings.Contains(readyOut, want) {
			t.Fatalf("documented commands for a ready binding lack %q:\n%s", want, readyOut)
		}
	}
	orphan := bindingObj("manager-orphan", "absent-profile", v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{envLabel: "production"})
	orphan.SetUID("")
	orphan.SetGeneration(0)
	if err := l.c.Create(l.ctx, orphan); err != nil {
		t.Fatal(err)
	}
	var orphanOut string
	l.eventually("orphan status", func() (bool, string) {
		orphanOut = l.runDocCommands(orphan.Name, denyPolicy)
		return strings.Contains(orphanOut, "Resolved=False ProfileNotFound") && strings.Contains(orphanOut, "EngineReady=False StaleRevision"), orphanOut
	})
	_ = os.WriteFile(filepath.Join(l.out, "documented-commands.txt"), []byte(readyOut+"\n"+orphanOut), 0o644)
	if err := l.c.Delete(l.ctx, l.binding(orphan.Name)); err != nil {
		t.Fatal(err)
	}
	l.record("documented-commands", map[string]any{"ready": deny.Name, "stale": orphan.Name, "policy": denyPolicy})
	denyRV = l.binding(deny.Name).ResourceVersion

	// 2. A restart re-lists everything and writes nothing.
	stop()
	stop = l.startManager()
	time.Sleep(20 * time.Second) // several reconcile rounds after cache sync
	after := l.managedPolicies()
	if toJSON(before) != toJSON(after) {
		t.Fatalf("restart rewrote engine policies:\nbefore %v\nafter  %v", before, after)
	}
	if l.binding(deny.Name).ResourceVersion != denyRV || l.binding(audit.Name).ResourceVersion != auditRV {
		t.Fatal("restart rewrote binding status")
	}
	l.record("restart-no-writes", map[string]any{"policies": len(after)})

	// 3. A relabel updates status only.
	l.setNamespace("manager-dev", "production")
	l.waitReady(deny.Name, 2)
	l.waitReady(audit.Name, 0)
	if toJSON(l.managedPolicies()) != toJSON(after) {
		t.Fatal("a namespace relabel rewrote engine policies")
	}
	l.eventually("denial follows the label", func() (bool, string) { ok, msg := l.denied("manager-dev"); return ok, msg })
	l.record("relabel-status-only", map[string]any{})

	// 4. A profile change replaces policies and becomes ready again.
	_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(p), p)
	p.Spec.Policies[0].Exceptions = v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: time.Hour}}
	if err := l.c.Update(l.ctx, p); err != nil {
		t.Fatal(err)
	}
	l.eventually("replacement", func() (bool, string) {
		b := l.binding(deny.Name)
		got := l.managedPolicies()
		_, oldStill := func() (string, bool) {
			for name := range after {
				if _, ok := got[name]; ok {
					return name, true
				}
			}
			return "", false
		}()
		c := meta.FindStatusCondition(b.Status.Conditions, v1alpha1.ConditionEngineReady)
		return b.Status.Profile != nil && b.Status.Profile.Generation == p.Generation && !oldStill && c != nil && c.Status == metav1.ConditionTrue, toJSON(b.Status)
	})
	l.record("replaced", map[string]any{"profileGeneration": p.Generation})

	// 5. Deleting a binding removes its policies (owner-reference GC) and only those.
	b := l.binding(deny.Name)
	if err := l.c.Delete(l.ctx, b); err != nil {
		t.Fatal(err)
	}
	l.eventually("deny policies removed", func() (bool, string) {
		ok, _ := l.denied("manager-prod")
		return !ok && len(l.managedPolicies()) == 1, toJSON(l.managedPolicies())
	})
	l.record("binding-deleted", map[string]any{"remaining": len(l.managedPolicies())})

	stop()
	_ = l.c.Delete(l.ctx, l.binding(audit.Name))
	_ = l.c.Delete(l.ctx, p)
	// Leave no managed policies for later tests on the same cluster.
	l.eventually("cleanup", func() (bool, string) { return len(l.managedPolicies()) == 0, toJSON(l.managedPolicies()) })
	l.record("passed", map[string]any{})
}
