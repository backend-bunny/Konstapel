//go:build live

package controller

// Live enforcement-epoch acceptance (add-continuous-assessments tasks 2.2,
// 2.4, 2.5). Run through scripts/targeting-live.sh against a disposable
// cluster with Kyverno installed. Bindings are written with server-side apply
// by a "gitops" field manager that never sends spec.enforcementEpoch, as
// GitOps tools do.

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const epochPolicy = "../../config/admission/binding-enforcement-epoch.yaml"

func (l *live) kubectl(stdin string, args ...string) (string, error) {
	cmd := exec.CommandContext(l.ctx, "kubectl", append([]string{"--kubeconfig", os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"), "--context", os.Getenv("KONSTAPEL_LIVE_CONTEXT")}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// gitopsApply server-side applies a binding manifest that omits the epoch.
func (l *live) gitopsApply(name, profile, mode, env, interval string) {
	l.t.Helper()
	manifest := fmt.Sprintf(`apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata: {name: %s}
spec:
  profileRef: {name: %s}
  namespaceSelector: {matchLabels: {%q: %s}}
  mode: %s
`, name, profile, envLabel, env, mode)
	if interval != "" {
		manifest += "  assessment: {interval: " + interval + "}\n"
	}
	if out, err := l.kubectl(manifest, "apply", "--server-side", "--field-manager=gitops", "-f", "-"); err != nil {
		l.t.Fatalf("gitops apply: %v\n%s", err, out)
	}
}

func (l *live) epochPolicyInstalled(installed bool) {
	l.t.Helper()
	verb := "apply"
	if !installed {
		verb = "delete"
	}
	if out, err := l.kubectl("", verb, "-f", epochPolicy); err != nil && installed {
		l.t.Fatalf("%s epoch policy: %v\n%s", verb, err, out)
	}
	// Policies become effective asynchronously: probe with a dry-run create
	// carrying a forged epoch.
	l.eventually(fmt.Sprintf("epoch policy installed=%v", installed), func() (bool, string) {
		probe := &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "epoch-probe"},
			Spec: v1alpha1.ComplianceBindingSpec{ProfileRef: v1alpha1.ProfileReference{Name: "x"}, Mode: v1alpha1.ModeAudit,
				NamespaceSelector: &v1alpha1.NamespaceSelector{}, EnforcementEpoch: 42}}
		if err := l.c.Create(l.ctx, probe, client.DryRunAll); err != nil {
			return false, err.Error()
		}
		return (probe.Spec.EnforcementEpoch == 1) == installed, fmt.Sprint(probe.Spec.EnforcementEpoch)
	})
}

// enforcementIdentity maps each managed engine policy to its metadata
// generation and spec: what enforces. Kyverno status writes and provenance
// annotation updates change resourceVersion but not this identity.
func (l *live) enforcementIdentity(bindings ...string) map[string]string {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(targeting.ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
	if err := l.c.List(l.ctx, list, client.MatchingLabels{targeting.LabelManagedBy: targeting.ManagedByValue}); err != nil {
		l.t.Fatal(err)
	}
	out := map[string]string{}
	for _, o := range list.Items {
		if slices.Contains(bindings, o.GetAnnotations()[targeting.AnnotationBinding]) {
			out[o.GetName()] = fmt.Sprint(o.GetGeneration()) + "/" + toJSON(o.Object["spec"])
		}
	}
	return out
}

// policiesFor lists managed engine policies rendered for the named bindings.
func (l *live) policiesFor(bindings ...string) []string {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(targeting.ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
	_ = l.c.List(l.ctx, list, client.MatchingLabels{targeting.LabelManagedBy: targeting.ManagedByValue})
	var out []string
	for _, o := range list.Items {
		for _, b := range bindings {
			if o.GetAnnotations()[targeting.AnnotationBinding] == b {
				out = append(out, o.GetName())
			}
		}
	}
	return out
}

func names(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestLiveEnforcementEpoch(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	l.setNamespace("epoch-prod", "epoch-production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "epoch-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	if err := l.c.Create(l.ctx, p); err != nil {
		t.Fatal(err)
	}
	// Clean up on success and failure, so later live tests on the same
	// cluster see none of this test's bindings or engine policies.
	t.Cleanup(func() {
		_, _ = l.kubectl("", "delete", "--ignore-not-found", "-f", epochPolicy)
		_, _ = l.kubectl("", "delete", "--ignore-not-found", "compliancebindings", "epoch-legacy", "epoch-deny")
		_, _ = l.kubectl("", "delete", "--ignore-not-found", "complianceprofiles", p.Name)
		l.eventually("epoch test policies removed", func() (bool, string) {
			for _, o := range l.policiesFor("epoch-legacy", "epoch-deny") {
				return false, o
			}
			return true, ""
		})
	})

	// --- Migration (2.4): a binding written before the epoch policy existed.
	const legacy = "epoch-legacy"
	l.gitopsApply(legacy, p.Name, "Deny", "epoch-production", "")
	l.gitopsApply(legacy, p.Name, "Audit", "epoch-production", "")
	l.gitopsApply(legacy, p.Name, "Deny", "epoch-production", "") // generation 3, no epoch
	if b := l.binding(legacy); b.Spec.EnforcementEpoch != 0 || b.Generation != 3 {
		t.Fatalf("legacy binding: epoch %d generation %d", b.Spec.EnforcementEpoch, b.Generation)
	}
	stop := l.startManager()
	l.waitReady(legacy, 1)
	legacyPolicies := l.enforcementIdentity(legacy)
	l.record("legacy-applied", map[string]any{"policies": names(legacyPolicies), "generation": 3})

	l.epochPolicyInstalled(true)
	l.gitopsApply(legacy, p.Name, "Deny", "epoch-production", "6h") // reporting-only first write
	b := l.waitReady(legacy, 1)
	if b.Spec.EnforcementEpoch != 3 || b.Generation != 4 {
		t.Fatalf("migration: epoch %d generation %d, want epoch 3 (old generation) generation 4", b.Spec.EnforcementEpoch, b.Generation)
	}
	if len(legacyPolicies) != 1 || toJSON(legacyPolicies) != toJSON(l.enforcementIdentity(legacy)) {
		t.Fatalf("migration rotated engine policies: %v -> %v", names(legacyPolicies), names(l.enforcementIdentity(legacy)))
	}
	l.record("migration-kept-identity", map[string]any{"epoch": b.Spec.EnforcementEpoch, "generation": b.Generation})
	if err := l.c.Delete(l.ctx, l.binding(legacy)); err != nil {
		t.Fatal(err)
	}
	l.eventually("legacy policies removed", func() (bool, string) { got := l.policiesFor(legacy); return len(got) == 0, toJSON(got) })

	// --- New binding under the policy (2.2, 2.5).
	const name = "epoch-deny"
	l.gitopsApply(name, p.Name, "Deny", "epoch-production", "")
	b = l.waitReady(name, 1)
	if b.Spec.EnforcementEpoch != 1 {
		t.Fatalf("create: epoch %d, want 1", b.Spec.EnforcementEpoch)
	}
	if b.Spec.Assessment == nil || b.Spec.Assessment.Interval != "24h" || b.Spec.Assessment.Retention != "2160h" {
		t.Fatalf("assessment defaults not applied: %+v", b.Spec.Assessment)
	}
	l.eventually("denial in production", func() (bool, string) { ok, msg := l.denied("epoch-prod"); return ok, msg })
	before := l.enforcementIdentity(name)
	l.record("created", map[string]any{"epoch": 1, "policies": names(before)})

	// Reporting-only GitOps re-apply (omits the epoch): the epoch is carried
	// forward, generation advances, engine policies are untouched.
	l.gitopsApply(name, p.Name, "Deny", "epoch-production", "1h")
	b = l.waitReady(name, 1)
	if b.Spec.EnforcementEpoch != 1 || b.Generation != 2 || b.Spec.Assessment.Interval != "1h" {
		t.Fatalf("reporting-only apply: epoch %d generation %d interval %s", b.Spec.EnforcementEpoch, b.Generation, b.Spec.Assessment.Interval)
	}
	time.Sleep(10 * time.Second) // several reconcile rounds
	if toJSON(before) != toJSON(l.enforcementIdentity(name)) {
		t.Fatalf("reporting-only edit replaced or changed engine policies:\nbefore %v\nafter  %v", before, l.enforcementIdentity(name))
	}
	if ok, msg := l.denied("epoch-prod"); !ok {
		t.Fatalf("enforcement lost after reporting-only edit: %s", msg)
	}
	l.record("reporting-only-preserved", map[string]any{"generation": b.Generation, "epoch": b.Spec.EnforcementEpoch, "policies": names(before)})

	// A forged epoch is overwritten.
	b.Spec.EnforcementEpoch = 9
	b.Spec.Assessment.Retention = "720h"
	if err := l.c.Update(l.ctx, b); err != nil {
		t.Fatal(err)
	}
	if got := l.binding(name); got.Spec.EnforcementEpoch != 1 {
		t.Fatalf("forged epoch stored: %d", got.Spec.EnforcementEpoch)
	}
	l.record("forged-overwritten", map[string]any{"submitted": 9, "stored": 1})

	// A -> B -> A while the manager is stopped (missed watch events): the
	// restored configuration gets a new epoch and new engine policies.
	l.waitReady(name, 1)
	stop()
	l.gitopsApply(name, p.Name, "Audit", "epoch-production", "1h")
	l.gitopsApply(name, p.Name, "Deny", "epoch-production", "1h")
	if got := l.binding(name); got.Spec.EnforcementEpoch != 3 {
		t.Fatalf("A-B-A: epoch %d, want 3", got.Spec.EnforcementEpoch)
	}
	stop = l.startManager()
	l.waitReady(name, 1)
	l.eventually("A-B-A replaced policies", func() (bool, string) {
		now := l.enforcementIdentity(name)
		for n := range before {
			if _, still := now[n]; still {
				return false, toJSON(names(now))
			}
		}
		return len(now) == 1, toJSON(names(now))
	})
	l.eventually("denial after A-B-A", func() (bool, string) { ok, msg := l.denied("epoch-prod"); return ok, msg })
	l.record("aba-new-identity", map[string]any{"epoch": 3, "policies": names(l.enforcementIdentity(name))})

	// Without the policy, removing the epoch from a binding that has one is
	// rejected by the CRD: the missing prerequisite is loud, not silent.
	l.epochPolicyInstalled(false)
	out, err := l.kubectl(fmt.Sprintf(`{"apiVersion":"compliance.erenius.io/v1alpha1","kind":"ComplianceBinding","metadata":{"name":%q},"spec":{"profileRef":{"name":%q},"namespaceSelector":{"matchLabels":{%q:"epoch-production"}},"mode":"Audit"}}`, name, p.Name, envLabel),
		"replace", "-f", "-")
	if err == nil || !strings.Contains(out, "enforcementEpoch is maintained by admission") {
		t.Fatalf("enforcement edit without the epoch policy was not rejected: %v\n%s", err, out)
	}
	l.record("missing-policy-fails-closed", map[string]any{"error": strings.TrimSpace(out)})

	stop()
	_ = l.c.Delete(l.ctx, l.binding(name))
	_ = l.c.Delete(l.ctx, p)
	l.eventually("cleanup", func() (bool, string) { got := l.policiesFor(name); return len(got) == 0, toJSON(got) })
	_ = os.WriteFile(filepath.Join(l.out, "epoch-live.txt"), []byte(toJSON(l.log)), 0o644)
	l.record("passed", map[string]any{})
}
