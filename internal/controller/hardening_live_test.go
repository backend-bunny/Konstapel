//go:build live

package controller

// Live admission for the Linux workload hardening bundle
// (add-linux-workload-hardening-bundle task 4.2). The in-process manager
// serves the vendored bundle; a profile of the four checks is bound in Deny
// mode to one namespace and in Audit mode to another. Every check must reject
// only its own violation, for its own policy-specific reason, on Pods,
// controller templates, init containers, workload UPDATEs and ephemeral
// containers; compliant workloads and the Audit namespace are admitted.

import (
	"fmt"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

var hzChecks = []string{"disallow-privilege-escalation", "disallow-capabilities-strict", "require-run-as-nonroot", "restrict-seccomp-strict"}

// hzSecurityContext satisfies all four checks.
func hzSecurityContext() *corev1.SecurityContext {
	f, t := false, true
	return &corev1.SecurityContext{AllowPrivilegeEscalation: &f, RunAsNonRoot: &t,
		Capabilities:   &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}
}

// hzViolate breaks exactly one check ("*" breaks all four).
func hzViolate(sc *corev1.SecurityContext, check string) {
	t, f := true, false
	for _, c := range hzChecks {
		if check != "*" && c != check {
			continue
		}
		switch c {
		case "disallow-privilege-escalation":
			sc.AllowPrivilegeEscalation = &t
		case "disallow-capabilities-strict":
			sc.Capabilities = &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN"}}
		case "require-run-as-nonroot":
			sc.RunAsNonRoot = &f
		case "restrict-seccomp-strict":
			sc.SeccompProfile = nil
		}
	}
}

func hzPodSpec(regular, init *corev1.SecurityContext) corev1.PodSpec {
	s := corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever,
		Containers: []corev1.Container{{Name: "app", Image: "registry.invalid/hz:1", SecurityContext: regular}}}
	if init != nil {
		s.InitContainers = []corev1.Container{{Name: "init", Image: "registry.invalid/hz:1", SecurityContext: init}}
	}
	return s
}

func hzWorkload(form, ns, name string, spec corev1.PodSpec) client.Object {
	labels := map[string]string{"app": name}
	switch form {
	case "Deployment":
		spec.RestartPolicy = corev1.RestartPolicyAlways
		return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}, Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: spec}}}
	case "CronJob":
		return &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}, Spec: batchv1.CronJobSpec{Schedule: "0 * * * *",
			JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: spec}}}}}
	}
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}, Spec: spec}
}

// hzPolicyNames returns the engine policies rendered for a binding, keyed by
// logical policy.
func (l *live) hzPolicyNames(binding string) map[string]string {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(targeting.ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
	if err := l.c.List(l.ctx, list, client.MatchingLabels{targeting.LabelManagedBy: targeting.ManagedByValue}); err != nil {
		l.t.Fatal(err)
	}
	out := map[string]string{}
	for _, o := range list.Items {
		if a := o.GetAnnotations(); a[targeting.AnnotationBinding] == binding {
			out[a[targeting.AnnotationPolicy]] = o.GetName()
		}
	}
	return out
}

// expectDenied asserts a denial naming exactly the expected engine policy.
func (l *live) expectDenied(what string, err error, policies map[string]string, check string) {
	l.t.Helper()
	if err == nil {
		l.t.Errorf("%s: admitted, want denial by %s", what, check)
		return
	}
	msg := err.Error()
	if !strings.Contains(msg, policies[check]) {
		l.t.Errorf("%s: denial does not name %s (%s): %s", what, check, policies[check], msg)
	}
	for c, name := range policies {
		if c != check && strings.Contains(msg, name) {
			l.t.Errorf("%s: also denied by unrelated %s: %s", what, c, msg)
		}
	}
	l.record("denied", map[string]any{"case": what, "policy": policies[check]})
}

func TestLiveHardeningAdmission(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	stop := l.startManager()
	defer stop()

	const denyNS, auditNS = "hz-deny", "hz-audit"
	l.setNamespace(denyNS, "hz-deny")
	l.setNamespace(auditNS, "hz-audit")
	p := profileObj(t, "hz-hardening", hzChecks...)
	deny := bindingObj("hz-deny", p.Name, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{envLabel: "hz-deny"})
	audit := bindingObj("hz-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "hz-audit"})
	for _, o := range []client.Object{p, deny, audit} {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	var created []client.Object
	t.Cleanup(func() {
		for _, o := range created {
			_ = l.c.Delete(l.ctx, o, client.PropagationPolicy(metav1.DeletePropagationBackground))
		}
		for _, o := range []client.Object{deny, audit, p} {
			_ = l.c.Delete(l.ctx, o)
		}
		// Later tests count managed policies: wait until ours are withdrawn.
		l.eventually("hardening policies withdrawn", func() (bool, string) {
			left := l.policiesFor(deny.Name, audit.Name)
			return len(left) == 0, fmt.Sprint(left)
		})
	})
	l.waitReady(deny.Name, 1)
	l.waitReady(audit.Name, 1)
	denyPolicies := l.hzPolicyNames(deny.Name)
	if len(denyPolicies) != len(hzChecks) {
		t.Fatalf("deny binding rendered %v", denyPolicies)
	}
	for _, c := range hzChecks {
		if !strings.HasPrefix(denyPolicies[c], "konstapel-"+c) {
			t.Fatalf("%s rendered as %q", c, denyPolicies[c])
		}
	}
	l.record("ready", map[string]any{"deny": denyPolicies})

	// Compliant workloads are admitted in Deny mode.
	for _, form := range []string{"Pod", "Deployment", "CronJob"} {
		w := hzWorkload(form, denyNS, "hz-compliant-"+strings.ToLower(form), hzPodSpec(hzSecurityContext(), hzSecurityContext()))
		l.eventually(form+" compliant admitted", func() (bool, string) {
			err := l.c.Create(l.ctx, w.DeepCopyObject().(client.Object), client.DryRunAll)
			return err == nil, fmt.Sprint(err)
		})
	}

	// Each check rejects only its own violation, for its own reason, on every
	// form and on init containers.
	for _, c := range hzChecks {
		for _, form := range []string{"Pod", "Deployment", "CronJob"} {
			sc := hzSecurityContext()
			hzViolate(sc, c)
			w := hzWorkload(form, denyNS, "hz-violates", hzPodSpec(sc, nil))
			l.expectDenied(form+"/"+c, l.c.Create(l.ctx, w, client.DryRunAll), denyPolicies, c)
		}
		sc := hzSecurityContext()
		hzViolate(sc, c)
		w := hzWorkload("Pod", denyNS, "hz-violates-init", hzPodSpec(hzSecurityContext(), sc))
		l.expectDenied("init/"+c, l.c.Create(l.ctx, w, client.DryRunAll), denyPolicies, c)
	}

	// Audit mode admits the otherwise-valid request that violates all four.
	all := hzSecurityContext()
	hzViolate(all, "*")
	if err := l.c.Create(l.ctx, hzWorkload("Pod", auditNS, "hz-audit-violates", hzPodSpec(all, nil)), client.DryRunAll); err != nil {
		t.Errorf("audit namespace denied: %v", err)
	}
	l.record("audit-admitted", map[string]any{"namespace": auditNS})

	// UPDATE: a compliant Deployment cannot be changed to violate a check.
	dep := hzWorkload("Deployment", denyNS, "hz-update", hzPodSpec(hzSecurityContext(), nil)).(*appsv1.Deployment)
	if err := l.c.Create(l.ctx, dep); err != nil {
		t.Fatal(err)
	}
	created = append(created, dep)
	for _, c := range hzChecks {
		err := l.updateRetry(&appsv1.Deployment{}, dep, func(o client.Object) error {
			d := o.(*appsv1.Deployment)
			hzViolate(d.Spec.Template.Spec.Containers[0].SecurityContext, c)
			return l.c.Update(l.ctx, d, client.DryRunAll)
		})
		l.expectDenied("update/"+c, err, denyPolicies, c)
	}

	// Ephemeral containers: adding a violating debug container to a running
	// compliant Pod through the subresource is denied by that check.
	pod := hzWorkload("Pod", denyNS, "hz-ephemeral", hzPodSpec(hzSecurityContext(), nil)).(*corev1.Pod)
	if err := l.c.Create(l.ctx, pod); err != nil {
		t.Fatal(err)
	}
	created = append(created, pod)
	for _, c := range hzChecks {
		sc := hzSecurityContext()
		hzViolate(sc, c)
		err := l.updateRetry(&corev1.Pod{}, pod, func(o client.Object) error {
			p := o.(*corev1.Pod)
			p.Spec.EphemeralContainers = append(p.Spec.EphemeralContainers, corev1.EphemeralContainer{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-" + strings.Split(c, "-")[1], Image: "registry.invalid/hz:1", SecurityContext: sc}})
			return l.c.SubResource("ephemeralcontainers").Update(l.ctx, p)
		})
		l.expectDenied("ephemeral/"+c, err, denyPolicies, c)
	}
	// A compliant ephemeral container is admitted.
	if err := l.updateRetry(&corev1.Pod{}, pod, func(o client.Object) error {
		p := o.(*corev1.Pod)
		p.Spec.EphemeralContainers = append(p.Spec.EphemeralContainers, corev1.EphemeralContainer{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug-ok", Image: "registry.invalid/hz:1", SecurityContext: hzSecurityContext()}})
		return l.c.SubResource("ephemeralcontainers").Update(l.ctx, p)
	}); err != nil {
		t.Errorf("compliant ephemeral container denied: %v", err)
	}
	l.record("ephemeral-compliant-admitted", map[string]any{"pod": pod.Name})
}

// updateRetry re-reads key into into and applies update, retrying only on
// optimistic-concurrency conflicts caused by controllers updating the object.
func (l *live) updateRetry(into, key client.Object, update func(client.Object) error) error {
	var err error
	for range 10 {
		if err = l.c.Get(l.ctx, client.ObjectKeyFromObject(key), into); err != nil {
			return err
		}
		if err = update(into); !apierrors.IsConflict(err) {
			return err
		}
	}
	return err
}
