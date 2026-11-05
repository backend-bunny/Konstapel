//go:build live

package targeting

// Live delivery acceptance (task 3.4). Run against a disposable cluster with
// Kyverno installed, through scripts/targeting-live.sh, which task acceptance
// calls. It installs the generated CRDs, creates real profiles and bindings
// (engine policies carry owner references, so the bindings must exist), and
// drives Resolve, Render and Delivery as the controller will.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
)

const liveTimeout = 3 * time.Minute

type liveEnv struct {
	t       *testing.T
	ctx     context.Context
	c       client.Client
	content LocalContent
	ref     v1alpha1.BundleReference
	cluster string
	out     string
	log     []map[string]any
}

func newLiveEnv(t *testing.T) *liveEnv {
	kubeconfig, context_, out := os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"), os.Getenv("KONSTAPEL_LIVE_CONTEXT"), os.Getenv("KONSTAPEL_LIVE_OUTPUT")
	if kubeconfig == "" || context_ == "" || out == "" {
		t.Fatal("KONSTAPEL_LIVE_KUBECONFIG, KONSTAPEL_LIVE_CONTEXT and KONSTAPEL_LIVE_OUTPUT are required")
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
		&clientcmd.ConfigOverrides{CurrentContext: context_}).ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, apiextensionsv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	t.Cleanup(cancel)
	e := &liveEnv{t: t, ctx: ctx, c: c, out: out, content: vendored()}
	sums, err := os.ReadFile("../../content/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	e.ref = v1alpha1.BundleReference{Name: e.content.Name, Digest: "sha256:" + hexSum(sums)}
	ks := &corev1.Namespace{}
	if err := c.Get(ctx, client.ObjectKey{Name: "kube-system"}, ks); err != nil {
		t.Fatal(err)
	}
	e.cluster = "kube-system:" + string(ks.UID) // the assessment loop's cluster identity
	return e
}

func (e *liveEnv) record(step string, fields map[string]any) {
	fields["step"] = step
	fields["at"] = time.Now().UTC().Format(time.RFC3339)
	e.log = append(e.log, fields)
	e.t.Logf("%s: %v", step, fields)
}

func (e *liveEnv) save() {
	b, _ := json.MarshalIndent(e.log, "", "  ")
	_ = os.WriteFile(filepath.Join(e.out, "targeting-live.json"), b, 0o644)
}

func (e *liveEnv) eventually(what string, f func() (bool, string)) {
	e.t.Helper()
	deadline := time.Now().Add(liveTimeout)
	last := ""
	for time.Now().Before(deadline) {
		ok, detail := f()
		if ok {
			return
		}
		last = detail
		time.Sleep(2 * time.Second)
	}
	e.t.Fatalf("timed out waiting for %s: %s", what, last)
}

func (e *liveEnv) installCRDs() {
	files, _ := filepath.Glob("../../config/crd/bases/*.yaml")
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		crd := &apiextensionsv1.CustomResourceDefinition{}
		if err := yaml.UnmarshalStrict(raw, crd); err != nil {
			e.t.Fatal(err)
		}
		if err := e.c.Create(e.ctx, crd); err != nil && !apierrors.IsAlreadyExists(err) {
			e.t.Fatalf("API server rejected %s: %v", f, err)
		}
		e.eventually("CRD "+crd.Name+" established", func() (bool, string) {
			got := &apiextensionsv1.CustomResourceDefinition{}
			if err := e.c.Get(e.ctx, client.ObjectKey{Name: crd.Name}, got); err != nil {
				return false, err.Error()
			}
			for _, cond := range got.Status.Conditions {
				if cond.Type == apiextensionsv1.Established && cond.Status == apiextensionsv1.ConditionTrue {
					return true, ""
				}
			}
			return false, "not established"
		})
	}
}

func (e *liveEnv) namespace(name, environment string) {
	ns := &corev1.Namespace{}
	ns.Name = name
	if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(ns), ns); apierrors.IsNotFound(err) {
		ns.Labels = map[string]string{"environment": environment}
		if err := e.c.Create(e.ctx, ns); err != nil {
			e.t.Fatal(err)
		}
		return
	} else if err != nil {
		e.t.Fatal(err)
	}
	ns.Labels["environment"] = environment
	if err := e.c.Update(e.ctx, ns); err != nil {
		e.t.Fatal(err)
	}
}

// deliver resolves the live configuration and syncs every binding until all
// desired policies are ready, as one controller pass would.
func (e *liveEnv) deliver() Result {
	e.t.Helper()
	var res Result
	e.eventually("delivery ready", func() (bool, string) {
		content, err := e.content.Content(e.ctx, e.ref)
		if err != nil {
			e.t.Fatal(err)
		}
		in := Input{Cluster: e.cluster, Bundles: []Bundle{content.Bundle}}
		var profiles v1alpha1.ComplianceProfileList
		var bindings v1alpha1.ComplianceBindingList
		var nss corev1.NamespaceList
		for _, l := range []client.ObjectList{&profiles, &bindings, &nss} {
			if err := e.c.List(e.ctx, l); err != nil {
				e.t.Fatal(err)
			}
		}
		in.Profiles, in.Bindings = profiles.Items, bindings.Items
		for _, ns := range nss.Items {
			in.Namespaces = append(in.Namespaces, Namespace{Name: ns.Name, UID: ns.UID, Labels: ns.Labels})
		}
		res = Resolve(in)
		d := &Delivery{Client: e.c}
		allReady, detail := true, ""
		for _, b := range res.Bindings {
			if len(b.Errors) > 0 {
				e.t.Fatalf("binding %s did not resolve: %+v", b.Binding.Name, b.Errors)
			}
			var desired []*unstructured.Unstructured
			for _, c := range b.Contributions {
				obj, err := Render(c, content.Policies[c.Policy])
				if err != nil {
					e.t.Fatal(err)
				}
				desired = append(desired, obj)
			}
			sync, err := d.Sync(e.ctx, b.Binding.UID, desired, nil)
			if err != nil {
				e.t.Fatal(err)
			}
			e.record("sync", map[string]any{"binding": b.Binding.Name, "current": sync.Current, "notReady": sync.NotReady, "retained": sync.Retained, "removed": sync.Removed, "conflicts": sync.Conflicts})
			if len(sync.Conflicts) > 0 {
				e.t.Fatalf("unexpected conflicts: %v", sync.Conflicts)
			}
			if !sync.Ready(len(desired)) || len(sync.Retained) > 0 {
				allReady = false
				detail = fmt.Sprintf("%s: %+v", b.Binding.Name, sync)
			}
		}
		return allReady, detail
	})
	return res
}

func (e *liveEnv) policyNames() []string {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
	if err := e.c.List(e.ctx, list, client.MatchingLabels{LabelManagedBy: ManagedByValue}); err != nil {
		e.t.Fatal(err)
	}
	var names []string
	for _, o := range list.Items {
		names = append(names, o.GetName())
	}
	slices.Sort(names)
	return names
}

func privilegedPod(namespace, name string) *corev1.Pod {
	privileged := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "c", Image: "registry.invalid/never-pulled:1",
			SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
		}}},
	}
}

// admission creates a privileged pod with a server-side dry run, which runs
// the admission webhooks without persisting anything.
func (e *liveEnv) admission(namespace string) error {
	return e.c.Create(e.ctx, privilegedPod(namespace, "probe"), client.DryRunAll)
}

// expectDenied waits until admission in namespace is denied by policy.
func (e *liveEnv) expectDenied(namespace, policy string) {
	e.t.Helper()
	e.eventually("denial in "+namespace, func() (bool, string) {
		err := e.admission(namespace)
		if err == nil {
			return false, "admitted"
		}
		return strings.Contains(err.Error(), policy), err.Error()
	})
	e.record("denied", map[string]any{"namespace": namespace, "policy": policy})
}

// expectAdmitted requires admission to succeed consistently.
func (e *liveEnv) expectAdmitted(namespace string) {
	e.t.Helper()
	e.eventually("admission in "+namespace, func() (bool, string) {
		if err := e.admission(namespace); err != nil {
			return false, err.Error()
		}
		return true, ""
	})
	for range 3 {
		if err := e.admission(namespace); err != nil {
			e.t.Fatalf("admission in %s became denied: %v", namespace, err)
		}
		time.Sleep(time.Second)
	}
	e.record("admitted", map[string]any{"namespace": namespace})
}

// expectAuditFinding waits for a background report failing pod under policy.
func (e *liveEnv) expectAuditFinding(namespace, pod, policy string) {
	e.t.Helper()
	e.eventually("audit finding for "+namespace+"/"+pod, func() (bool, string) {
		list := &unstructured.UnstructuredList{}
		list.SetAPIVersion("wgpolicyk8s.io/v1alpha2")
		list.SetKind("PolicyReportList")
		if err := e.c.List(e.ctx, list, client.InNamespace(namespace)); err != nil {
			return false, err.Error()
		}
		raw, _ := json.MarshalIndent(list.Items, "", "  ")
		_ = os.WriteFile(filepath.Join(e.out, "reports-"+namespace+".json"), raw, 0o644)
		for _, r := range list.Items {
			results, _, _ := unstructured.NestedSlice(r.Object, "results")
			for _, res := range results {
				m, _ := res.(map[string]any)
				// Kyverno names the resource per result or, more often, once
				// in the report-level scope (as the assessment loop handles).
				resources, _ := m["resources"].([]any)
				if len(resources) == 0 {
					if scope, ok := r.Object["scope"].(map[string]any); ok {
						resources = []any{scope}
					}
				}
				for _, ref := range resources {
					rm, _ := ref.(map[string]any)
					if m["policy"] == policy && m["result"] == "fail" && rm["name"] == pod {
						return true, ""
					}
				}
			}
		}
		return false, fmt.Sprintf("%d reports, no failing result for %s", len(list.Items), policy)
	})
	e.record("audited", map[string]any{"namespace": namespace, "pod": pod, "policy": policy})
}

func policyFor(r Result, binding string) Contribution {
	for _, b := range r.Bindings {
		if b.Binding.Name == binding && len(b.Contributions) == 1 {
			return b.Contributions[0]
		}
	}
	panic("no contribution for " + binding)
}

func TestLiveDelivery(t *testing.T) {
	e := newLiveEnv(t)
	t.Cleanup(e.save)
	e.installCRDs()
	e.namespace("targeting-prod", "production")
	e.namespace("targeting-dev", "development")

	// An unmanaged policy as the assessment-loop prototype delivers it. Every
	// step below runs next to it; it must end up unchanged.
	protoObj, err := assessment.Render("../..", "Audit", "targeting-prototype", "live-prototype")
	if err != nil {
		t.Fatal(err)
	}
	proto := &unstructured.Unstructured{Object: protoObj}
	if err := e.c.Create(e.ctx, proto); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.c.Delete(context.Background(), proto) })
	// Kyverno writes status, so compare generation and spec, not resourceVersion.
	protoGeneration, protoSpec := proto.GetGeneration(), proto.Object["spec"]

	profile := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "live-baseline"}, Spec: v1alpha1.ComplianceProfileSpec{
		Bundle:   e.ref,
		Policies: []v1alpha1.ProfilePolicy{{Name: pol}},
	}}
	sel := func(m map[string]v1alpha1.LabelValue) *v1alpha1.NamespaceSelector {
		return &v1alpha1.NamespaceSelector{MatchLabels: m}
	}
	auditAll := &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "live-audit-all"}, Spec: v1alpha1.ComplianceBindingSpec{
		ProfileRef: v1alpha1.ProfileReference{Name: profile.Name}, NamespaceSelector: sel(nil), Mode: v1alpha1.ModeAudit}}
	denyProd := &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "live-deny-production"}, Spec: v1alpha1.ComplianceBindingSpec{
		ProfileRef: v1alpha1.ProfileReference{Name: profile.Name}, NamespaceSelector: sel(map[string]v1alpha1.LabelValue{"environment": "production"}), Mode: v1alpha1.ModeDeny}}
	for _, o := range []client.Object{profile, auditAll, denyProd} {
		if err := e.c.Create(e.ctx, o); err != nil {
			t.Fatalf("API server rejected %s: %v", o.GetName(), err)
		}
	}
	// Leave nothing behind, even on failure, so the test reruns on the same
	// cluster. Bindings' engine policies are withdrawn explicitly.
	t.Cleanup(func() {
		ctx := context.Background()
		for _, b := range []*v1alpha1.ComplianceBinding{auditAll, denyProd} {
			_, _ = (&Delivery{Client: e.c}).Withdraw(ctx, b.UID)
			_ = e.c.Delete(ctx, b)
		}
		_ = e.c.Delete(ctx, profile)
	})
	// The API server must reject an absent selector, as the in-process tests claim.
	bad := &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "live-no-selector"}, Spec: v1alpha1.ComplianceBindingSpec{
		ProfileRef: v1alpha1.ProfileReference{Name: profile.Name}, Mode: v1alpha1.ModeDeny}}
	if err := e.c.Create(e.ctx, bad); err == nil || !strings.Contains(err.Error(), "namespaceSelector") {
		t.Fatalf("API server accepted a binding without a selector: %v", err)
	}

	// 1. Audit everywhere, deny in production.
	r := e.deliver()
	deny := PolicyName(policyFor(r, denyProd.Name))
	audit := PolicyName(policyFor(r, auditAll.Name))
	e.record("delivered", map[string]any{"policies": e.policyNames(), "deny": deny, "audit": audit, "bundleDigest": e.ref.Digest, "cluster": e.cluster})
	e.expectDenied("targeting-prod", deny)
	e.expectAdmitted("targeting-dev")
	audited := privilegedPod("targeting-dev", "audited")
	if err := e.c.Create(e.ctx, audited); err != nil {
		t.Fatal(err)
	}
	// Remove the pod even on failure, so the test can rerun on the same cluster.
	t.Cleanup(func() { _ = e.c.Delete(context.Background(), audited) })
	e.expectAuditFinding("targeting-dev", "audited", audit)

	// 2. A label change moves the namespace into the Deny scope without a new revision.
	e.namespace("targeting-dev", "production")
	r = e.deliver()
	if got := PolicyName(policyFor(r, denyProd.Name)); got != deny {
		t.Fatalf("namespace relabel changed the policy name: %s -> %s", deny, got)
	}
	e.expectDenied("targeting-dev", deny)
	e.namespace("targeting-dev", "development")
	e.expectAdmitted("targeting-dev")

	// 3. A profile change creates a new revision; the old one retires only when ready.
	if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(profile), profile); err != nil {
		t.Fatal(err)
	}
	profile.Spec.Policies[0].Exceptions = v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: time.Hour}}
	if err := e.c.Update(e.ctx, profile); err != nil {
		t.Fatal(err)
	}
	r = e.deliver()
	replacement := PolicyName(policyFor(r, denyProd.Name))
	if replacement == deny {
		t.Fatal("profile change kept the old engine policy name")
	}
	if names := e.policyNames(); slices.Contains(names, deny) || !slices.Contains(names, replacement) {
		t.Fatalf("superseded revision not retired after readiness: %v", names)
	}
	e.expectDenied("targeting-prod", replacement)
	e.record("replaced", map[string]any{"from": deny, "to": replacement})

	// 4. Withdrawing the Deny binding removes only its policies. Withdraw runs
	// before the binding is deleted, as the controller's finalizer will;
	// otherwise owner-reference garbage collection gets there first.
	if err := e.c.Get(e.ctx, client.ObjectKeyFromObject(denyProd), denyProd); err != nil {
		t.Fatal(err)
	}
	removed, err := (&Delivery{Client: e.c}).Withdraw(e.ctx, denyProd.UID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(removed, []string{replacement}) {
		t.Fatalf("withdraw removed %v, want [%s]", removed, replacement)
	}
	if err := e.c.Delete(e.ctx, denyProd); err != nil {
		t.Fatal(err)
	}
	e.record("withdrawn", map[string]any{"binding": denyProd.Name, "removed": removed})
	e.expectAdmitted("targeting-prod")
	if names := e.policyNames(); len(names) != 1 || names[0] == replacement {
		t.Fatalf("withdrawal left %v; want only the Audit policy", names)
	}

	// 5. The prototype-style unmanaged policy was never adopted or modified.
	after := &unstructured.Unstructured{}
	after.SetGroupVersionKind(ValidatingPolicyGVK)
	if err := e.c.Get(e.ctx, client.ObjectKey{Name: proto.GetName()}, after); err != nil {
		t.Fatalf("prototype policy removed: %v", err)
	}
	if after.GetGeneration() != protoGeneration || !equalJSON(after.Object["spec"], protoSpec) || after.GetLabels()[LabelManagedBy] != "" || len(after.GetOwnerReferences()) != 0 {
		t.Fatalf("prototype policy was modified or adopted: generation %d -> %d, labels %v, owners %v", protoGeneration, after.GetGeneration(), after.GetLabels(), after.GetOwnerReferences())
	}
	e.record("prototype-untouched", map[string]any{"name": proto.GetName(), "generation": protoGeneration})
	_ = e.c.Delete(e.ctx, after)

	// Clean up test resources; the cluster itself is disposable.
	_ = e.c.Delete(e.ctx, auditAll)
	if _, err := (&Delivery{Client: e.c}).Withdraw(e.ctx, auditAll.UID); err != nil {
		t.Fatal(err)
	}
	e.record("passed", map[string]any{})
}
