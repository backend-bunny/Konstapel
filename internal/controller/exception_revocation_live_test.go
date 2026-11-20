//go:build live

package controller

// Live exception revocation (add-self-service-policy-exceptions tasks 2.6 and
// 2.5): the in-process manager serves the ComplianceException webhooks from
// config/webhook/exceptions.yaml to a real API server, requests are made as
// impersonated application identities, and the documented example and
// version-aware patches (docs/examples/policy-exceptions) are applied as
// written. Run through scripts/exception-admission-live.sh (assessments
// group).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/exception"
)

const revocationWebhookPort = 19446

const exceptionCRD = "complianceexceptions.compliance.erenius.io"

// patchOps is a JSON patch (RFC 6902).
type patchOps []map[string]any

func examplePatch(t *testing.T, file string) patchOps {
	t.Helper()
	raw, err := os.ReadFile("../../docs/examples/policy-exceptions/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var ops patchOps
	if err := json.Unmarshal(raw, &ops); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return ops
}

// withPreconditions returns the patch with its UID, resourceVersion and
// acceptanceRevision tests set to what the client read in seen, as the
// documented workflow does.
func (p patchOps) withPreconditions(seen *v1alpha1.ComplianceException) patchOps {
	out := make(patchOps, len(p))
	for i, op := range p {
		c := map[string]any{}
		for k, v := range op {
			c[k] = v
		}
		if c["op"] == "test" {
			switch c["path"] {
			case "/metadata/uid":
				c["value"] = string(seen.UID)
			case "/metadata/resourceVersion":
				c["value"] = seen.ResourceVersion
			case "/spec/acceptanceRevision":
				c["value"] = seen.Spec.AcceptanceRevision
			}
		}
		out[i] = c
	}
	return out
}

// set returns the patch with the value of the non-test op at path replaced.
func (p patchOps) set(path string, value any) patchOps {
	out := slices.Clone(p)
	for i, op := range out {
		if op["op"] != "test" && op["path"] == path {
			c := map[string]any{}
			for k, v := range op {
				c[k] = v
			}
			c["value"] = value
			out[i] = c
		}
	}
	return out
}

func (p patchOps) and(ops ...map[string]any) patchOps { return append(slices.Clone(p), ops...) }

// annotationPath is the JSON pointer of an annotation key.
func annotationPath(key string) string {
	return "/metadata/annotations/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
}

func (l *live) jsonPatch(c client.Client, ns, name string, ops patchOps, opts ...client.PatchOption) (*v1alpha1.ComplianceException, error) {
	raw, err := json.Marshal(ops)
	if err != nil {
		l.t.Fatal(err)
	}
	out := &v1alpha1.ComplianceException{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	return out, c.Patch(l.ctx, out, client.RawPatch(types.JSONPatchType, raw), opts...)
}

// patchTestFailed reports whether the API server rejected a JSON patch
// because one of its test operations failed: 422 Invalid with the generic
// message it uses for patch application errors, not a field validation
// error.
func patchTestFailed(err error) bool {
	return apierrors.IsInvalid(err) && strings.Contains(err.Error(), "the server rejected our request due to an error in our request")
}

// statusDetail is the API status of err, for the evidence log.
func statusDetail(err error) string {
	var se *apierrors.StatusError
	if errors.As(err, &se) {
		return toJSON(se.ErrStatus)
	}
	return fmt.Sprint(err)
}

func (l *live) mergePatch(c client.Client, ns, name, patch string) error {
	out := &v1alpha1.ComplianceException{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	return c.Patch(l.ctx, out, client.RawPatch(types.MergePatchType, []byte(patch)))
}

func (l *live) exception(ns, name string) *v1alpha1.ComplianceException {
	l.t.Helper()
	ex := &v1alpha1.ComplianceException{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: name}, ex); err != nil {
		l.t.Fatal(err)
	}
	return ex
}

// settled returns the exception once the controller has reconciled its
// current generation. Its status writes change resourceVersion, so a client
// that reads preconditions while one is pending sees its patch test fail and
// must re-read: the documented workflow, but not what a step tests.
func (l *live) settled(ns, name string) *v1alpha1.ComplianceException {
	l.t.Helper()
	var ex *v1alpha1.ComplianceException
	l.eventually("exception "+name+" reconciled", func() (bool, string) {
		ex = l.exception(ns, name)
		c := meta.FindStatusCondition(ex.Status.Conditions, v1alpha1.ConditionAcceptanceRecorded)
		return c != nil && c.ObservedGeneration == ex.Generation, toJSON(ex.Status)
	})
	return ex
}

func revocation(t *testing.T, ex *v1alpha1.ComplianceException) exception.Revocation {
	t.Helper()
	r, present, err := exception.ParseRevocation(ex)
	if !present || err != nil {
		t.Fatalf("revocation record on %s: present=%v err=%v", ex.Name, present, err)
	}
	return r
}

// lifecycle is the stored state revocation protects.
func lifecycle(ex *v1alpha1.ComplianceException) string {
	return toJSON(map[string]any{"uid": ex.UID, "spec": ex.Spec, "finalizers": ex.Finalizers,
		"acceptance": ex.Annotations[exception.AcceptanceAnnotation], "revocation": ex.Annotations[exception.RevocationAnnotation]})
}

// releaseRevocations removes the revocation finalizer from the exceptions a
// test left in namespaces and deletes them. It runs after the webhooks are
// removed: while they serve, no identity may remove the finalizer.
func (l *live) releaseRevocations(namespaces ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, ns := range namespaces {
		for {
			var list v1alpha1.ComplianceExceptionList
			err := l.c.List(ctx, &list, client.InNamespace(ns))
			if err == nil && len(list.Items) == 0 {
				break
			}
			for i := range list.Items {
				ex := &list.Items[i]
				if slices.Contains(ex.Finalizers, exception.RevocationFinalizer) {
					patch := client.MergeFrom(ex.DeepCopy())
					ex.Finalizers = slices.DeleteFunc(ex.Finalizers, func(f string) bool { return f == exception.RevocationFinalizer })
					_ = l.c.Patch(ctx, ex, patch)
				}
			}
			_ = l.c.DeleteAllOf(ctx, &v1alpha1.ComplianceException{}, client.InNamespace(ns))
			if ctx.Err() != nil {
				l.t.Errorf("exceptions in %s not released: %v", ns, err)
				break
			}
			time.Sleep(time.Second)
		}
	}
}

func TestLiveExceptionRevocation(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	host := webhookHost(t)
	certs := t.TempDir()
	ca := servingCert(t, certs, host)
	if err := l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: DefaultSnapshotNamespace}}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	mgr, err := NewManager(l.cfg, Options{Content: content, MetricsAddr: "0", ProbeAddr: "0", EnginePoll: 2 * time.Second,
		SkipControllerNameValidation: true, WebhookCertDir: certs, WebhookPort: revocationWebhookPort})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(l.ctx)
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("manager exited: %v", err)
		}
	})
	const ns, nsB = "exc-revoke", "exc-revoke-b"
	// Registered before the webhooks, so it runs after they are removed.
	t.Cleanup(func() { l.releaseRevocations(ns, nsB) })
	l.installExceptionWebhooksAt(host, revocationWebhookPort, ca)

	l.setNamespace(ns, "exc-revoke")
	l.setNamespace(nsB, "exc-revoke")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "exc-revoke-self-service"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)},
			Policies: []v1alpha1.ProfilePolicy{{Name: pol, Exceptions: v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: 720 * time.Hour}}}}}}
	b := bindingObj("exc-revoke-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "exc-revoke"})
	editor := l.shippedClusterRole("../../config/rbac/exception-editor.yaml", "konstapel-exception-editor")
	roleBinding := func(namespace, group string) *rbacv1.RoleBinding {
		return &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "exception-editors", Namespace: namespace},
			RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: editor},
			Subjects: []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: "Group", Name: group}}}
	}
	// The controller's shipped role: it reads exceptions and writes status only.
	controllerRole := l.shippedClusterRole("../../config/rbac/controller/role.yaml", "konstapel-controller")
	crb := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "exc-revoke-controller"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: controllerRole},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "konstapel-controller", Namespace: DefaultSnapshotNamespace}}}
	objs := []client.Object{p, b, roleBinding(ns, "rv-team-a"), roleBinding(nsB, "rv-team-b"), crb}
	for _, o := range objs {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, n := range []string{ns, nsB} {
			_ = l.c.DeleteAllOf(l.ctx, &v1alpha1.ComplianceException{}, client.InNamespace(n))
		}
		for i := len(objs) - 1; i >= 0; i-- {
			_ = l.c.Delete(l.ctx, objs[i])
		}
	})
	l.waitReady(b.Name, 2)

	alice := l.as("alice", "rv-team-a", "system:authenticated")
	dave := l.as("dave", "rv-team-a", "system:authenticated")
	argoUser := "system:serviceaccount:argocd:argocd-application-controller"
	argo := l.as(argoUser, "rv-team-a", "system:serviceaccounts", "system:authenticated")
	erin := l.as("erin", "rv-team-b", "system:authenticated")
	mallory := l.as("mallory", "system:authenticated")
	controllerSA := l.as("system:serviceaccount:konstapel-system:konstapel-controller", "system:serviceaccounts", "system:serviceaccounts:konstapel-system", "system:authenticated")
	expires := func(d time.Duration) metav1.Time { return metav1.NewTime(time.Now().Add(d).Truncate(time.Second)) }
	newEx := func(namespace, name string) *v1alpha1.ComplianceException {
		return &v1alpha1.ComplianceException{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: v1alpha1.ComplianceExceptionSpec{Policy: pol, WorkloadSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "debug"}},
				Reason: "live revocation check", ExpiresAt: expires(24 * time.Hour), AcceptanceRevision: 1}}
	}
	denied := func(what string, err error, reason string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "denied the request: "+reason+":") {
			t.Fatalf("%s: want a %s admission denial, got %v", what, reason, err)
		}
		l.record("denied", map[string]any{"attempt": what, "reason": reason})
	}
	forbidden := func(what string, err error) {
		t.Helper()
		if !apierrors.IsForbidden(err) || strings.Contains(err.Error(), "denied the request") {
			t.Fatalf("%s: want Forbidden by RBAC, got %v", what, err)
		}
		l.record("denied", map[string]any{"attempt": what, "reason": "RBAC"})
	}
	// unchanged asserts that a rejected write left the stored state as it was.
	unchanged := func(what string, before *v1alpha1.ComplianceException) {
		t.Helper()
		if got := l.exception(before.Namespace, before.Name); lifecycle(got) != lifecycle(before) {
			t.Fatalf("%s changed %s:\n%s\nwant\n%s", what, before.Name, lifecycle(got), lifecycle(before))
		}
	}
	revokeOps, renewOps := examplePatch(t, "revoke.json"), examplePatch(t, "renew.json")

	// 1. The documented example, created as written (namespace and a current
	// expiry substituted): revision 1, stored unrevoked by default.
	raw, err := os.ReadFile("../../docs/examples/policy-exceptions/exception.yaml")
	if err != nil {
		t.Fatal(err)
	}
	ex := &v1alpha1.ComplianceException{}
	if err := yaml.UnmarshalStrict(raw, ex); err != nil {
		t.Fatal(err)
	}
	ex.Namespace, ex.Spec.ExpiresAt = ns, expires(24*time.Hour)
	l.eventually("exception webhook serving", func() (bool, string) {
		err := alice.Create(l.ctx, ex.DeepCopy(), client.DryRunAll)
		return err == nil, fmt.Sprint(err)
	})
	if err := alice.Create(l.ctx, ex); err != nil {
		t.Fatalf("create the documented example: %v", err)
	}
	stored := &unstructured.Unstructured{}
	stored.SetGroupVersionKind(v1alpha1.GroupVersion.WithKind("ComplianceException"))
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(ex), stored); err != nil {
		t.Fatal(err)
	}
	if revoked, found, _ := unstructured.NestedBool(stored.Object, "spec", "revoked"); !found || revoked {
		t.Fatalf("stored spec.revoked = %v (present %v), want the default false", revoked, found)
	}
	if a := acceptance(t, ex); a.Actor.Username != "alice" || a.Revision != 1 || a.Claim != "carol, ticket SEC-7" {
		t.Fatalf("acceptance = %+v", a)
	}
	if _, present, _ := exception.ParseRevocation(ex); present || len(ex.Finalizers) != 0 {
		t.Fatalf("a new acceptance carries revocation history: %v %v", ex.Annotations, ex.Finalizers)
	}
	acceptedRecord := ex.Annotations[exception.AcceptanceAnnotation]
	snap1 := l.waitSnapshot(ex, 1)
	l.record("create-example", map[string]any{"name": ex.Name, "revoked": false, "snapshot": snap1.Name})

	// 2. A dry-run revocation returns the record it would store and stores
	// nothing.
	cur := l.settled(ns, ex.Name)
	dry, err := l.jsonPatch(dave, ns, ex.Name, revokeOps.withPreconditions(cur), client.DryRunAll)
	if err != nil {
		t.Fatal(err)
	}
	if r := revocation(t, dry); r.Actor.Username != "dave" || !dry.Spec.Revoked || !slices.Contains(dry.Finalizers, exception.RevocationFinalizer) {
		t.Fatalf("dry-run revocation = %+v %v", r, dry.Finalizers)
	}
	unchanged("a dry-run revocation", cur)
	l.record("dry-run-revoke", map[string]any{"stored": false})

	// 3. Version-aware patches fail on stale preconditions rather than
	// revoking or renewing what the client did not see.
	seen := l.exception(ns, ex.Name)
	if err := l.mergePatch(dave, ns, ex.Name, `{"metadata":{"labels":{"reviewed":"dave"}}}`); err != nil {
		t.Fatal(err)
	}
	current := l.exception(ns, ex.Name)
	staleErr := func() error { _, err := l.jsonPatch(alice, ns, ex.Name, revokeOps.withPreconditions(seen)); return err }()
	if !patchTestFailed(staleErr) {
		t.Fatalf("stale revocation: want a failed patch test, got %v", staleErr)
	}
	l.record("stale-revoke", map[string]any{"rejected": statusDetail(staleErr)})
	unchanged("a stale revocation", current)
	stale := renewOps.withPreconditions(seen).set("/spec/acceptanceRevision", seen.Spec.AcceptanceRevision+1).set("/spec/expiresAt", expires(48*time.Hour).UTC().Format(time.RFC3339))
	if _, err := l.jsonPatch(alice, ns, ex.Name, stale); !patchTestFailed(err) {
		t.Fatalf("stale renewal: want a failed patch test, got %v", err)
	}
	unchanged("a stale renewal", current)
	optimistic := seen.DeepCopy()
	optimistic.Spec.Revoked = true
	if err := alice.Patch(l.ctx, optimistic, client.MergeFromWithOptions(seen, client.MergeFromWithOptimisticLock{})); !apierrors.IsConflict(err) {
		t.Fatalf("stale resourceVersion merge patch: want Conflict, got %v", err)
	}
	unchanged("a stale merge patch", current)
	l.record("stale-preconditions", map[string]any{"jsonPatchTest": "rejected", "resourceVersionConflict": "rejected"})

	// 4. Revocation through GitOps, with forged attribution in the same patch:
	// admission records the authenticated service account and the request
	// time, and adds the finalizer. Nothing about the acceptance changes.
	forged := `{"exceptionUID":"other","revision":1,"requestedAt":"2020-01-01T00:00:00Z","actor":{"username":"platform-admin"}}`
	claim := "carol, ticket SEC-7 (revoked in commit def456)"
	before := time.Now().UTC().Truncate(time.Second)
	revokedEx, err := l.jsonPatch(argo, ns, ex.Name, revokeOps.withPreconditions(current).and(
		map[string]any{"op": "add", "path": annotationPath(exception.RevocationAnnotation), "value": forged},
		map[string]any{"op": "add", "path": annotationPath(exception.ClaimAnnotation), "value": claim}))
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	after := time.Now()
	r := revocation(t, revokedEx)
	l.record("revoke", map[string]any{"revocation": r})
	switch {
	case r.Actor.Username != argoUser || r.Actor.UID != "uid-"+argoUser || !slices.Contains(r.Actor.Groups, "system:serviceaccounts"):
		t.Fatalf("revoking actor = %+v", r.Actor)
	case r.ExceptionUID != current.UID || r.Revision != 1 || r.Claim != claim:
		t.Fatalf("revocation = %+v", r)
	case r.RequestedAt.Time.Before(before) || r.RequestedAt.Time.After(after):
		t.Fatalf("requestedAt %s outside the request [%s, %s]", r.RequestedAt, before, after)
	case !revokedEx.Spec.Revoked || !slices.Contains(revokedEx.Finalizers, exception.RevocationFinalizer):
		t.Fatalf("revoked = %v, finalizers %v", revokedEx.Spec.Revoked, revokedEx.Finalizers)
	case revokedEx.Annotations[exception.AcceptanceAnnotation] != acceptedRecord || revokedEx.Spec.AcceptanceRevision != 1 ||
		revokedEx.Spec.Reason != ex.Spec.Reason || !revokedEx.Spec.ExpiresAt.Equal(&ex.Spec.ExpiresAt):
		t.Fatalf("revocation changed the acceptance: %s", lifecycle(revokedEx))
	}
	if cm := l.snapshotConfigMap(snap1.Name); cm == nil || cm.ResourceVersion != snap1.ResourceVersion {
		t.Fatal("revocation changed or removed the acceptance snapshot")
	}

	// 5. Repeating the revocation, as another editor and as a full GitOps
	// re-apply, keeps the first actor and time.
	time.Sleep(1100 * time.Millisecond)
	cur = l.settled(ns, ex.Name)
	if _, err := l.jsonPatch(dave, ns, ex.Name, revokeOps.withPreconditions(cur)); err != nil {
		t.Fatalf("repeat revoke: %v", err)
	}
	reapply := l.settled(ns, ex.Name)
	reapply.Labels["synced"] = "argo"
	if err := argo.Update(l.ctx, reapply); err != nil {
		t.Fatalf("re-apply of the revoked exception: %v", err)
	}
	if got := l.exception(ns, ex.Name); got.Annotations[exception.RevocationAnnotation] != revokedEx.Annotations[exception.RevocationAnnotation] || !got.Spec.Revoked {
		t.Fatalf("a repeated revocation rewrote the record: %s", lifecycle(got))
	}
	revokedEx = l.settled(ns, ex.Name)
	l.record("repeat-revoke", map[string]any{"actor": r.Actor.Username, "requestedAt": r.RequestedAt})

	// 6. A revoked revision is never reactivated: neither by setting false
	// nor by an update that omits the field (it defaults to false).
	denied("same-revision reactivation", l.mergePatch(alice, ns, ex.Name, `{"spec":{"revoked":false}}`), exception.ReasonRenewalRequired)
	omitted := revokedEx.DeepCopy()
	omitted.Spec.Revoked = false // omitempty: the request omits the field
	denied("same-revision re-apply omitting revoked", alice.Update(l.ctx, omitted), exception.ReasonRenewalRequired)
	unchanged("reactivation", revokedEx)

	// 7. Renewal: the documented patch refuses to renew over a revocation it
	// did not expect; a deliberate renewal of the revoked revision waits for
	// its independent history (task 3.6); renewing into revoked is invalid.
	renew := renewOps.withPreconditions(revokedEx).set("/spec/acceptanceRevision", int64(2)).set("/spec/expiresAt", expires(48*time.Hour).UTC().Format(time.RFC3339))
	if _, err := l.jsonPatch(alice, ns, ex.Name, renew); !patchTestFailed(err) {
		t.Fatalf("renewal over an unseen revocation: want a failed patch test, got %v", err)
	}
	deliberate := fmt.Sprintf(`{"spec":{"acceptanceRevision":2,"revoked":false,"reason":"fresh acceptance","expiresAt":%q}}`, expires(48*time.Hour).UTC().Format(time.RFC3339))
	denied("renewal of a revoked revision", l.mergePatch(alice, ns, ex.Name, deliberate), exception.ReasonRevocationHistoryPending)
	denied("renewal into revoked", l.mergePatch(alice, ns, ex.Name, strings.Replace(deliberate, `"revoked":false`, `"revoked":true`, 1)), exception.ReasonInvalidRevocationTransition)
	unchanged("renewal of a revoked revision", revokedEx)

	// 8. The record and the finalizer are protected.
	rewritten := strings.Replace(revokedEx.Annotations[exception.RevocationAnnotation], argoUser, "platform-admin", 1)
	rewrite, _ := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": map[string]any{exception.RevocationAnnotation: rewritten}}})
	denied("rewrite the revocation record", l.mergePatch(alice, ns, ex.Name, string(rewrite)), exception.ReasonProtectedField)
	remove, _ := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": map[string]any{exception.RevocationAnnotation: nil}}})
	denied("remove the revocation record", l.mergePatch(alice, ns, ex.Name, string(remove)), exception.ReasonProtectedField)
	denied("remove the revocation finalizer", l.mergePatch(argo, ns, ex.Name, `{"metadata":{"finalizers":null}}`), exception.ReasonProtectedField)
	unchanged("protected history", revokedEx)

	// 9. Authorization: another team, an unbound identity and the controller
	// cannot revoke or release, and nobody reaches another namespace.
	forbidden("revoke as another team", l.mergePatch(erin, ns, ex.Name, `{"spec":{"revoked":true}}`))
	forbidden("revoke as an unbound identity", l.mergePatch(mallory, ns, ex.Name, `{"spec":{"revoked":true}}`))
	exB := newEx(nsB, "team-b")
	if err := erin.Create(l.ctx, exB); err != nil {
		t.Fatal(err)
	}
	forbidden("revoke another namespace's exception", l.mergePatch(alice, nsB, exB.Name, `{"spec":{"revoked":true}}`))
	unchanged("another namespace's exception", exB)
	l.eventually("controller identity bound", func() (bool, string) {
		got := &v1alpha1.ComplianceException{}
		err := controllerSA.Get(l.ctx, client.ObjectKeyFromObject(revokedEx), got)
		return err == nil, fmt.Sprint(err)
	})
	forbidden("release the finalizer as the controller", l.mergePatch(controllerSA, ns, ex.Name, `{"metadata":{"finalizers":null}}`))
	forbidden("revoke as the controller", l.mergePatch(controllerSA, nsB, exB.Name, `{"spec":{"revoked":true}}`))
	unchanged("unauthorized writes", revokedEx)

	// 10. Deletion with UID/resourceVersion preconditions: stale ones fail;
	// current ones are accepted, and the finalizer keeps the revoked resource
	// with its record, the only copy of the revocation until task 3.6.
	delStale := alice.Delete(l.ctx, l.exception(ns, ex.Name), client.Preconditions{UID: &current.UID, ResourceVersion: &current.ResourceVersion})
	if !apierrors.IsConflict(delStale) {
		t.Fatalf("delete with a stale resourceVersion: want Conflict, got %v", delStale)
	}
	otherUID := types.UID("00000000-0000-0000-0000-000000000000")
	if err := alice.Delete(l.ctx, l.exception(ns, ex.Name), client.Preconditions{UID: &otherUID}); !apierrors.IsConflict(err) {
		t.Fatalf("delete with another UID: want Conflict, got %v", err)
	}
	unchanged("a stale delete", revokedEx)
	fresh := l.settled(ns, ex.Name)
	if err := alice.Delete(l.ctx, fresh, client.Preconditions{UID: &fresh.UID, ResourceVersion: &fresh.ResourceVersion}); err != nil {
		t.Fatalf("delete with current preconditions: %v", err)
	}
	terminating := l.exception(ns, ex.Name)
	if terminating.DeletionTimestamp.IsZero() || terminating.Annotations[exception.RevocationAnnotation] != revokedEx.Annotations[exception.RevocationAnnotation] ||
		!slices.Contains(terminating.Finalizers, exception.RevocationFinalizer) {
		t.Fatalf("deleted revoked exception: %s deletion %v", lifecycle(terminating), terminating.DeletionTimestamp)
	}
	denied("remove the finalizer of a terminating revoked exception", l.mergePatch(alice, ns, ex.Name, `{"metadata":{"finalizers":null}}`), exception.ReasonProtectedField)
	l.record("delete-revoked", map[string]any{"retained": true, "finalizer": exception.RevocationFinalizer})

	// 11. A new acceptance starts unrevoked and carries no revocation history.
	createRevoked := newEx(ns, "create-revoked")
	createRevoked.Spec.Revoked = true
	denied("create revoked", alice.Create(l.ctx, createRevoked), exception.ReasonInvalidRevocationTransition)
	withRecord := newEx(ns, "create-with-record")
	withRecord.Annotations = map[string]string{exception.RevocationAnnotation: forged}
	denied("create with a revocation record", alice.Create(l.ctx, withRecord), exception.ReasonProtectedField)
	withFinalizer := newEx(ns, "create-with-finalizer")
	withFinalizer.Finalizers = []string{exception.RevocationFinalizer}
	denied("create with the revocation finalizer", alice.Create(l.ctx, withFinalizer), exception.ReasonProtectedField)
	active := newEx(ns, "active")
	if err := alice.Create(l.ctx, active); err != nil {
		t.Fatal(err)
	}
	renewRevoke := fmt.Sprintf(`{"spec":{"acceptanceRevision":2,"revoked":true,"expiresAt":%q}}`, expires(48*time.Hour).UTC().Format(time.RFC3339))
	denied("renew and revoke together", l.mergePatch(alice, ns, active.Name, renewRevoke), exception.ReasonInvalidRevocationTransition)
	for _, name := range []string{"create-revoked", "create-with-record", "create-with-finalizer"} {
		if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: name}, &v1alpha1.ComplianceException{}); !apierrors.IsNotFound(err) {
			t.Fatalf("%s was stored: %v", name, err)
		}
	}

	// 12. Expired, Forbidden and unresolved acceptances are revoked without
	// fresh eligibility or a future expiry.
	short := newEx(ns, "short")
	short.Spec.ExpiresAt = expires(6 * time.Second)
	forbiddenLater, unresolvedLater := newEx(ns, "forbidden-later"), newEx(ns, "unresolved-later")
	for _, e := range []*v1alpha1.ComplianceException{short, forbiddenLater, unresolvedLater} {
		if err := alice.Create(l.ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	revokeNow := func(what string, e *v1alpha1.ComplianceException) {
		t.Helper()
		got, err := l.jsonPatch(dave, ns, e.Name, revokeOps.withPreconditions(l.settled(ns, e.Name)))
		if err != nil {
			t.Fatalf("revoke %s: %v", what, err)
		}
		if r := revocation(t, got); r.Actor.Username != "dave" || r.Revision != 1 || !got.Spec.ExpiresAt.Equal(&e.Spec.ExpiresAt) {
			t.Fatalf("revocation of %s = %+v %s", what, r, lifecycle(got))
		}
		l.record("revoke-"+what, map[string]any{"revocation": revocation(t, got)})
	}
	for time.Now().Before(short.Spec.ExpiresAt.Add(time.Second)) {
		time.Sleep(500 * time.Millisecond)
	}
	revokeNow("expired", short)

	fp := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "exc-revoke-forbidden"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	fb := bindingObj("exc-revoke-pci", fp.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "exc-revoke"})
	up := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "exc-revoke-unresolved"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: "exc-revoke-unconfigured", Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	ub := bindingObj("exc-revoke-unresolved", up.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "exc-revoke"})
	t.Cleanup(func() {
		for _, o := range []client.Object{ub, up, fb, fp} {
			_ = l.c.Delete(l.ctx, o)
		}
	})
	gone := func(objs ...client.Object) {
		t.Helper()
		for _, o := range objs {
			if err := l.c.Delete(l.ctx, o); err != nil {
				t.Fatal(err)
			}
		}
		// Bindings may hold a finalizer while their policies are withdrawn;
		// admission resolves against them until they are gone.
		l.eventually("restrictions removed", func() (bool, string) {
			for _, o := range objs {
				if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(o), o.DeepCopyObject().(client.Object)); !apierrors.IsNotFound(err) {
					return false, o.GetName() + ": " + fmt.Sprint(err)
				}
			}
			return true, ""
		})
	}
	ineligible := func(reason string) {
		t.Helper()
		l.eventually("acceptance "+reason, func() (bool, string) {
			err := alice.Create(l.ctx, newEx(ns, "probe"), client.DryRunAll)
			return err != nil && strings.Contains(err.Error(), "denied the request: "+reason+":"), fmt.Sprint(err)
		})
	}
	for _, o := range []client.Object{fp, fb} {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	ineligible(exception.ReasonForbidden)
	revokeNow("forbidden", forbiddenLater)
	gone(fb, fp)
	for _, o := range []client.Object{up, ub} {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	ineligible(exception.ReasonUnresolved)
	revokeNow("unresolved", unresolvedLater)
	gone(ub, up)

	// 13. A resource stored before spec.revoked existed reads as unrevoked;
	// an edit that omits the field neither renews nor revokes it.
	l.legacyExceptionChecks(alice, dave, newEx(ns, "legacy"))
}

// legacyExceptionChecks stores an exception while the served CRD lacks
// spec.revoked, restores the CRD, and checks that the stored resource reads
// as unrevoked and keeps its acceptance through an edit that omits the
// field.
func (l *live) legacyExceptionChecks(creator, editor client.Client, ex *v1alpha1.ComplianceException) {
	t := l.t
	original := &apiextensionsv1.CustomResourceDefinition{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: exceptionCRD}, original); err != nil {
		t.Fatal(err)
	}
	setVersions := func(versions []apiextensionsv1.CustomResourceDefinitionVersion) {
		t.Helper()
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			crd := &apiextensionsv1.CustomResourceDefinition{}
			if err := l.c.Get(l.ctx, client.ObjectKey{Name: exceptionCRD}, crd); err != nil {
				return err
			}
			crd.Spec.Versions = versions
			return l.c.Update(l.ctx, crd)
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Later tests share the cluster: the CRD is restored whatever happens.
	restored := false
	t.Cleanup(func() {
		if !restored {
			setVersions(original.Spec.Versions)
		}
	})
	legacy := original.DeepCopy()
	for i := range legacy.Spec.Versions {
		spec := legacy.Spec.Versions[i].Schema.OpenAPIV3Schema.Properties["spec"]
		delete(spec.Properties, "revoked")
		spec.XValidations = slices.DeleteFunc(spec.XValidations, func(r apiextensionsv1.ValidationRule) bool { return strings.Contains(r.Rule, "revoked") })
		legacy.Spec.Versions[i].Schema.OpenAPIV3Schema.Properties["spec"] = spec
		legacy.Spec.Versions[i].AdditionalPrinterColumns = slices.DeleteFunc(legacy.Spec.Versions[i].AdditionalPrinterColumns,
			func(c apiextensionsv1.CustomResourceColumnDefinition) bool { return c.Name == "Revoked" })
	}
	// schema probes which schema the API server serves: a dry-run creation
	// with revoked true is admitted with the field pruned without it
	// ("pruned"), and rejected as a revoked creation with it ("served").
	schema := func(want string) func() (bool, string) {
		return func() (bool, string) {
			u := &unstructured.Unstructured{}
			raw, _ := json.Marshal(ex)
			_ = json.Unmarshal(raw, &u.Object)
			u.SetGroupVersionKind(v1alpha1.GroupVersion.WithKind("ComplianceException"))
			u.SetName(ex.Name + "-probe")
			_ = unstructured.SetNestedField(u.Object, true, "spec", "revoked")
			got := "unknown"
			err := creator.Create(l.ctx, u, client.DryRunAll)
			if _, found, _ := unstructured.NestedFieldNoCopy(u.Object, "spec", "revoked"); err == nil && !found {
				got = "pruned"
			} else if err != nil && strings.Contains(err.Error(), "denied the request: "+exception.ReasonInvalidRevocationTransition+":") {
				got = "served"
			}
			return got == want, got + ": " + fmt.Sprint(err)
		}
	}
	setVersions(legacy.Spec.Versions)
	l.eventually("CRD without spec.revoked served", schema("pruned"))
	if err := creator.Create(l.ctx, ex); err != nil {
		t.Fatal(err)
	}
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(v1alpha1.GroupVersion.WithKind("ComplianceException"))
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(ex), u); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := unstructured.NestedFieldNoCopy(u.Object, "spec", "revoked"); found {
		t.Fatal("the legacy exception was stored with spec.revoked")
	}
	setVersions(original.Spec.Versions)
	restored = true
	l.eventually("CRD with spec.revoked served", schema("served"))
	// Read from storage, the resource gets the default.
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(ex), u); err != nil {
		t.Fatal(err)
	}
	if revoked, found, _ := unstructured.NestedBool(u.Object, "spec", "revoked"); !found || revoked {
		t.Fatalf("the legacy exception reads spec.revoked = %v (present %v), want the default false", revoked, found)
	}

	got := l.exception(ex.Namespace, ex.Name)
	if got.Spec.Revoked || got.Spec.AcceptanceRevision != 1 || got.Annotations[exception.AcceptanceAnnotation] != ex.Annotations[exception.AcceptanceAnnotation] {
		t.Fatalf("legacy exception after the CRD upgrade: %s", lifecycle(got))
	}
	if err := l.mergePatch(editor, ex.Namespace, ex.Name, `{"metadata":{"labels":{"edited":"after-upgrade"}}}`); err != nil {
		t.Fatalf("metadata edit of the legacy exception: %v", err)
	}
	edited := l.exception(ex.Namespace, ex.Name)
	if edited.Spec.Revoked || edited.Spec.AcceptanceRevision != 1 || edited.Annotations[exception.AcceptanceAnnotation] != ex.Annotations[exception.AcceptanceAnnotation] ||
		edited.Annotations[exception.RevocationAnnotation] != "" || len(edited.Finalizers) != 0 {
		t.Fatalf("an edit omitting revoked changed the lifecycle: %s", lifecycle(edited))
	}
	l.record("legacy-omitted", map[string]any{"revoked": false, "renewed": false})
	if err := l.mergePatch(editor, ex.Namespace, ex.Name, `{"spec":{"revoked":true}}`); err != nil {
		t.Fatalf("revoke the legacy exception: %v", err)
	}
	if r := revocation(t, l.exception(ex.Namespace, ex.Name)); r.Revision != 1 || r.ExceptionUID != got.UID {
		t.Fatalf("legacy revocation = %+v", r)
	}
	l.record("legacy-revoke", map[string]any{"revoked": true})
}
