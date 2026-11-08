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
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
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

// TestLiveHardeningUserNamespaces covers the changed non-root behavior (task
// 4.3): hostUsers false is no exemption. Admission evidence (required) and
// container-runtime evidence (recorded separately, never counted as policy
// evidence) are kept apart; if the node cannot run user-namespaced Pods the
// runtime result is recorded as unvalidated with the reason.
func TestLiveHardeningUserNamespaces(t *testing.T) {
	image := os.Getenv("KONSTAPEL_WORKLOAD_IMAGE")
	if image == "" {
		t.Fatal("KONSTAPEL_WORKLOAD_IMAGE is required (scripts/runtime.env)")
	}
	l := newLive(t)
	l.installCRDs()
	stop := l.startManager()
	defer stop()

	const denyNS, freeNS = "hz-userns-deny", "hz-userns-free"
	l.setNamespace(denyNS, "hz-userns-deny")
	l.setNamespace(freeNS, "hz-userns-free")
	p := profileObj(t, "hz-userns", "require-run-as-nonroot")
	b := bindingObj("hz-userns-deny", p.Name, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{envLabel: "hz-userns-deny"})
	for _, o := range []client.Object{p, b} {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	var created []client.Object
	t.Cleanup(func() {
		for _, o := range created {
			_ = l.c.Delete(l.ctx, o)
		}
		_ = l.c.Delete(l.ctx, b)
		_ = l.c.Delete(l.ctx, p)
		l.eventually("user-namespace policies withdrawn", func() (bool, string) {
			left := l.policiesFor(b.Name)
			return len(left) == 0, fmt.Sprint(left)
		})
	})
	l.waitReady(b.Name, 1)
	policies := l.hzPolicyNames(b.Name)

	f, tr, uid := false, true, int64(1000)
	userns := func(ns, name string, pod, ctr *corev1.SecurityContext, psc *corev1.PodSecurityContext) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}, Spec: corev1.PodSpec{
			HostUsers: &f, RestartPolicy: corev1.RestartPolicyNever, SecurityContext: psc,
			Containers: []corev1.Container{{Name: "app", Image: image, Command: []string{"sh", "-c", "cat /proc/self/uid_map; id -u; sleep 3600"}, SecurityContext: ctr}}}}
	}
	// Admission: without the flag, or with Pod-level false, hostUsers false
	// is denied by the non-root policy; with the flag it is admitted.
	l.expectDenied("userns/no-flag", l.c.Create(l.ctx, userns(denyNS, "hz-no-flag", nil, nil, nil), client.DryRunAll), policies, "require-run-as-nonroot")
	l.expectDenied("userns/pod-false", l.c.Create(l.ctx, userns(denyNS, "hz-pod-false", nil, nil, &corev1.PodSecurityContext{RunAsNonRoot: &f}), client.DryRunAll), policies, "require-run-as-nonroot")
	l.expectDenied("userns/container-false", l.c.Create(l.ctx, userns(denyNS, "hz-ctr-false", nil, &corev1.SecurityContext{RunAsNonRoot: &f}, &corev1.PodSecurityContext{RunAsNonRoot: &tr}), client.DryRunAll), policies, "require-run-as-nonroot")
	flagged := userns(denyNS, "hz-userns-ok", nil, nil, &corev1.PodSecurityContext{RunAsNonRoot: &tr, RunAsUser: &uid})
	if err := l.c.Create(l.ctx, flagged, client.DryRunAll); err != nil {
		t.Errorf("hostUsers false with runAsNonRoot denied: %v", err)
	}
	l.record("userns-admission", map[string]any{"policy": policies["require-run-as-nonroot"], "noFlag": "denied", "podFalse": "denied", "containerFalse": "denied", "withFlag": "admitted"})

	// Runtime (separate evidence): does this node run a user-namespaced Pod?
	// Outside any binding, so policy is not involved.
	unvalidated := func(fields map[string]any) {
		fields["result"] = "unvalidated"
		l.record("userns-runtime", fields)
		// task acceptance prepares its own kind node for user namespaces.
		// That environment must produce isolation evidence, not silently pass
		// after a runtime/setup regression. Standalone probes may still record
		// unsupported environments without claiming runtime isolation.
		if os.Getenv("KONSTAPEL_LIVE_REQUIRE_USERNS") == "true" {
			t.Fatalf("user-namespace runtime required but unvalidated: %v", fields)
		}
	}
	probe := userns(freeNS, "hz-userns-runtime", nil, nil, &corev1.PodSecurityContext{RunAsNonRoot: &tr, RunAsUser: &uid})
	if err := l.c.Create(l.ctx, probe); err != nil {
		unvalidated(map[string]any{"reason": "create: " + err.Error()})
		return
	}
	created = append(created, probe)
	var phase corev1.PodPhase
	var reason string
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		cur := &corev1.Pod{}
		if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(probe), cur); err == nil {
			phase = cur.Status.Phase
			for _, cs := range cur.Status.ContainerStatuses {
				if w := cs.State.Waiting; w != nil && w.Reason != "ContainerCreating" {
					reason = w.Reason + ": " + w.Message
				}
			}
			if phase == corev1.PodRunning || phase == corev1.PodFailed || strings.Contains(reason, "CreateContainerError") || strings.Contains(reason, "RunContainerError") {
				break
			}
		}
		time.Sleep(3 * time.Second)
	}
	if phase != corev1.PodRunning {
		events, _ := exec.CommandContext(l.ctx, "kubectl", "--kubeconfig", os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"), "--context", os.Getenv("KONSTAPEL_LIVE_CONTEXT"),
			"get", "events", "-n", freeNS, "--field-selector", "involvedObject.name="+probe.Name, "-o", "custom-columns=TYPE:.type,REASON:.reason,MESSAGE:.message", "--no-headers").CombinedOutput()
		reason = strings.TrimSpace(reason + "\n" + string(events))
		unvalidated(map[string]any{"phase": phase, "reason": reason})
		t.Logf("user-namespace runtime unvalidated on this node: phase %s %s", phase, reason)
		return
	}
	out, err := l.podLogs(freeNS, probe.Name)
	if err != nil {
		unvalidated(map[string]any{"reason": "logs: " + err.Error()})
		return
	}
	// In a user namespace, container UID 0 maps to a non-zero host UID.
	isolated := !strings.Contains(out, "         0          0 4294967295")
	l.record("userns-runtime", map[string]any{"result": map[bool]string{true: "isolated", false: "not-isolated"}[isolated], "uidMap": out})
	if !isolated {
		t.Errorf("hostUsers false Pod is running without a user namespace: %s", out)
	}
}

// podLogs reads a container's log through kubectl with the live kubeconfig.
func (l *live) podLogs(ns, name string) (string, error) {
	var out string
	var err error
	for range 20 {
		cmd := exec.CommandContext(l.ctx, "kubectl", "--kubeconfig", os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"), "--context", os.Getenv("KONSTAPEL_LIVE_CONTEXT"), "logs", "-n", ns, name)
		b, e := cmd.CombinedOutput()
		out, err = string(b), e
		if e == nil && strings.Contains(out, "\n") {
			return out, nil
		}
		time.Sleep(2 * time.Second)
	}
	return out, err
}

// TestLiveHardeningBackground covers background evidence (task 4.4): workloads
// that exist before the Deny policies are installed are evaluated in the
// background and collected through the controller's assessment pipeline; a
// violating create after installation is denied and is not a report subject.
func TestLiveHardeningBackground(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	ConfigureAssessments(AssessmentRuntime{Publisher: pub, StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: time.Minute, Workers: 2,
		Ready: func(ctx context.Context) error { _, err := pub.Ready(ctx); return err }})
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })

	const ns = "hz-bg"
	l.setNamespace(ns, "hz-bg")
	// Seed pre-existing subjects before any policy exists.
	seeded := map[string]string{"compliant": ""}
	for _, c := range hzChecks {
		seeded["violates-"+strings.Split(c, "-")[1]] = c
	}
	var created []client.Object
	for name, check := range seeded {
		sc := hzSecurityContext()
		if check != "" {
			hzViolate(sc, check)
		}
		pod := hzWorkload("Pod", ns, "hz-bg-"+name, hzPodSpec(sc, nil))
		if err := l.c.Create(l.ctx, pod); err != nil {
			t.Fatal(err)
		}
		created = append(created, pod)
	}
	// An explicit Windows workload (task 4.5) that sets none of the Linux
	// settings (the API rejects them for Windows), so the Linux rules would
	// fail it: the checks short-circuit instead, which must not read as
	// compliance. Zero replicas: the template is assessed, no Windows node
	// is needed.
	winSpec := hzPodSpec(nil, nil)
	winSpec.SecurityContext = nil
	winSpec.OS = &corev1.PodOS{Name: corev1.Windows}
	win := hzWorkload("Deployment", ns, "hz-bg-windows", winSpec).(*appsv1.Deployment)
	zero := int32(0)
	win.Spec.Replicas = &zero
	if err := l.c.Create(l.ctx, win); err != nil {
		t.Fatal(err)
	}
	created = append(created, win)
	p := profileObj(t, "hz-bg-hardening", hzChecks...)
	b := bindingObj("hz-bg-deny", p.Name, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{envLabel: "hz-bg"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "90s"}
	for _, o := range []client.Object{p, b} {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, o := range created {
			_ = l.c.Delete(l.ctx, o)
		}
		_ = l.c.Delete(l.ctx, b)
		_ = l.c.Delete(l.ctx, p)
		l.eventually("background test policies withdrawn", func() (bool, string) {
			left := l.policiesFor(b.Name)
			return len(left) == 0, fmt.Sprint(left)
		})
	})
	stop := l.startManager()
	defer stop()
	l.waitReady(b.Name, 1)
	policies := l.hzPolicyNames(b.Name)

	// A violating create after installation is denied and never becomes a
	// report subject.
	late := hzSecurityContext()
	hzViolate(late, "*")
	lateErr := l.c.Create(l.ctx, hzWorkload("Pod", ns, "hz-bg-late", hzPodSpec(late, nil)))
	if lateErr == nil {
		t.Fatal("a violating Pod was created under Deny")
	}

	// The scheduled run collects background evidence for the seeded subjects.
	var run *v1alpha1.AssessmentRun
	l.eventually("scheduled background run published", func() (bool, string) {
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(l.ctx, &runs)
		for i := range runs.Items {
			r := &runs.Items[i]
			if r.Spec.BindingRef.Name == b.Name && r.Status.Phase == v1alpha1.RunCompleted && r.Status.Publication != nil && r.Status.Publication.Phase == "Committed" {
				run = r
				return true, ""
			}
		}
		return false, toJSON(l.binding(b.Name).Status.Assessment)
	})
	// The published package keeps raw outcomes, source times, workload UIDs,
	// cluster and policy identities, and exactly the seeded inventory.
	rc, _, err := pub.Open(l.ctx, publication.RunRef{ClusterID: run.Status.Scope.ClusterID, BindingUID: run.Status.Binding.UID, RunUID: string(run.UID)})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	untar(t, archive, dir)
	if _, err := s3store.ValidatePackage(dir); err != nil {
		t.Fatalf("package does not validate: %v", err)
	}
	var capture collector.CaptureV2
	if err := assessment.Read(filepath.Join(dir, "capture.json"), &capture); err != nil {
		t.Fatal(err)
	}
	var evaluation collector.Evaluation
	if err := assessment.Read(filepath.Join(dir, "evaluation.json"), &evaluation); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"capture.json", "evaluation.json"} {
		if b, err := os.ReadFile(filepath.Join(dir, f)); err == nil {
			_ = os.WriteFile(filepath.Join(l.out, "TestLiveHardeningBackground-"+f), b, 0o644)
		}
	}
	// 6 validations x 7 workloads: 5 seeded Pods, the Windows Deployment and
	// the ReplicaSet it owns (zero replicas, same Windows template).
	//   - one failing validation per violating Pod (4 fail);
	//   - Kyverno stops evaluating a policy at its first failing validation,
	//     so the other validation of a failed two-validation policy
	//     (capabilities, seccomp) has no result: Missing, and the evidence is
	//     Incomplete rather than an invented pass (2 missing);
	//   - the Windows Deployment and ReplicaSet are not applicable (12),
	//     never passes;
	//   - every other check passes (24).
	sum := run.Status.Summary
	if sum == nil || sum.Export != "Assessment" || sum.Evidence.Completeness != "Incomplete" || sum.Evidence.Expected != 42 ||
		sum.Evidence.Missing != 2 || sum.Outcomes.Fail != 4 || sum.Outcomes.Pass != 24 || sum.Outcomes.NotApplicable != 12 {
		t.Fatalf("background run summary: %s", toJSON(run.Status))
	}

	ks := &corev1.Namespace{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: "kube-system"}, ks); err != nil {
		t.Fatal(err)
	}
	if capture.Cluster != "kube-system:"+string(ks.UID) {
		t.Errorf("capture cluster %s", capture.Cluster)
	}
	uids := map[string]string{}
	for _, o := range created {
		cur := o.DeepCopyObject().(client.Object)
		if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(o), cur); err != nil {
			t.Fatalf("seeded %s no longer exists: %v", o.GetName(), err)
		}
		uids[string(cur.GetUID())] = cur.GetName()
	}
	// The Windows Deployment's ReplicaSet carries the same template.
	var sets appsv1.ReplicaSetList
	_ = l.c.List(l.ctx, &sets, client.InNamespace(ns))
	for _, rs := range sets.Items {
		if owner := metav1.GetControllerOf(&rs); owner != nil && owner.Name == "hz-bg-windows" {
			uids[string(rs.UID)] = rs.Name
		}
	}
	inventory := map[string]bool{}
	for _, w := range capture.Workloads {
		if w.Namespace != ns {
			continue
		}
		if _, ok := uids[w.UID]; !ok {
			t.Errorf("unexpected subject %s/%s in the inventory", w.Namespace, w.Name)
		}
		inventory[w.UID] = true
	}
	if len(inventory) != len(uids) {
		t.Errorf("inventory has %d seeded workloads, want %d", len(inventory), len(uids))
	}
	engine := map[string]bool{}
	for _, n := range policies {
		engine[n] = true
	}
	expected := map[string]collector.Expected{}
	for _, e := range capture.Expected {
		expected[e.Key()] = e
	}
	failed := map[string]string{}
	for _, o := range evaluation.Observations {
		e, ok := expected[o.Key]
		if !ok {
			t.Errorf("observation %s has no expected entry", o.Key)
			continue
		}
		if o.State == collector.Missing {
			// Only the unevaluated sibling of a failed two-validation policy.
			if v := seeded[strings.TrimPrefix(uids[e.Workload.UID], "hz-bg-")]; v != e.Contribution.LogicalPolicy ||
				(v != "disallow-capabilities-strict" && v != "restrict-seccomp-strict") {
				t.Errorf("unexpected missing evidence for %s %s/%d", uids[e.Workload.UID], e.Contribution.LogicalPolicy, e.Check.Index)
			}
			continue
		}
		if o.State != collector.Attributable || o.Evaluated == nil || o.Report == "" {
			t.Errorf("observation of %s/%d: state %s evaluated %v report %q", e.Workload.Name, e.Check.Index, o.State, o.Evaluated, o.Report)
		}
		if !engine[e.Check.EnginePolicy] || e.Cluster != capture.Cluster {
			t.Errorf("observation of foreign identity: %+v", e)
		}
		windows := e.Workload.OS == "windows"
		if windows != (o.Applicability == collector.NotApplicable) || (windows && !strings.HasPrefix(uids[e.Workload.UID]+e.Workload.Name, "hz-bg-windows")) {
			t.Errorf("%s check %d: applicability %q, declared OS %q", uids[e.Workload.UID], e.Check.Index, o.Applicability, e.Workload.OS)
		}
		if o.Outcome == "fail" {
			failed[uids[e.Workload.UID]] = e.Contribution.LogicalPolicy
		}
	}
	for name, check := range seeded {
		if check != "" && failed["hz-bg-"+name] != check {
			t.Errorf("%s: failed check %q, want %q", name, failed["hz-bg-"+name], check)
		}
	}
	if _, bad := failed["hz-bg-compliant"]; bad {
		t.Error("the compliant Pod failed")
	}
	l.record("background", map[string]any{"run": run.Name, "expected": sum.Evidence.Expected, "fail": sum.Outcomes.Fail, "pass": sum.Outcomes.Pass, "notApplicable": sum.Outcomes.NotApplicable,
		"lateCreate": lateErr.Error(), "failedByWorkload": failed})
}
