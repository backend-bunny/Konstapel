//go:build live

package controller

// Live read-only observation for the policy-change preview (tasks 2.1 to 2.4).
// The manager delivers real engine policies for a shared profile; the preview
// then observes the cluster as a get/list-only user, loaded from a kubeconfig
// like a caller's, while every request it sends on the wire is recorded.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/preview"
)

const previewEnvLabel = "preview-test.konstapel.dev/environment"

type wireRecorder struct {
	mu   sync.Mutex
	reqs []string
	next http.RoundTripper
}

func (w *wireRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	w.mu.Lock()
	w.reqs = append(w.reqs, r.Method+" "+r.URL.RequestURI())
	w.mu.Unlock()
	return w.next.RoundTrip(r)
}

// readerKubeconfig writes a kubeconfig whose context authenticates as the
// disposable cluster's admin but acts as user (impersonation), so the API
// server authorizes every request as that get/list-only user.
func (l *live) readerKubeconfig(user string) string {
	raw, err := clientcmd.LoadFromFile(os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"))
	if err != nil {
		l.t.Fatal(err)
	}
	admin := raw.Contexts[os.Getenv("KONSTAPEL_LIVE_CONTEXT")]
	if admin == nil {
		l.t.Fatal("live context not in kubeconfig")
	}
	auth := raw.AuthInfos[admin.AuthInfo].DeepCopy()
	auth.Impersonate, auth.ImpersonateGroups = user, []string{"system:authenticated"}
	raw.AuthInfos[user] = auth
	ctx := admin.DeepCopy()
	ctx.AuthInfo = user
	raw.Contexts[user] = ctx
	raw.CurrentContext = os.Getenv("KONSTAPEL_LIVE_CONTEXT")
	// Test-private: never in the uploaded output directory.
	path := filepath.Join(l.t.TempDir(), "kubeconfig")
	if err := clientcmd.WriteToFile(*raw, path); err != nil {
		l.t.Fatal(err)
	}
	return path
}

// can asks the API server whether user may perform the access.
func (l *live) can(user string, attrs authzv1.ResourceAttributes) bool {
	sar := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{User: user, Groups: []string{"system:authenticated"}, ResourceAttributes: &attrs}}
	if err := l.c.Create(l.ctx, sar); err != nil {
		l.t.Fatal(err)
	}
	return sar.Status.Allowed
}

func (l *live) observeAs(user, namespace string) (*preview.Snapshot, []string, error) {
	cfg, ctxName, err := preview.RESTConfig(l.readerKubeconfig(user), user)
	if err != nil {
		l.t.Fatal(err)
	}
	rec := &wireRecorder{}
	cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper { rec.next = rt; return rec })
	snap, err := preview.Observe(l.ctx, preview.ObserveOptions{Config: cfg, Context: ctxName, Namespace: namespace})
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return snap, slices.Clone(rec.reqs), err
}

func assertWireReadOnly(t *testing.T, reqs []string) {
	t.Helper()
	if len(reqs) == 0 {
		t.Fatal("no preview requests recorded")
	}
	for _, r := range reqs {
		method, uri, _ := strings.Cut(r, " ")
		if method != http.MethodGet || strings.Contains(uri, "dryRun") || strings.Contains(uri, "watch=") ||
			strings.HasPrefix(uri, "/api/v1/secrets") || strings.Contains(uri, "/secrets") ||
			strings.Contains(uri, "subjectaccessreviews") || strings.Contains(uri, "selfsubject") {
			t.Fatalf("preview sent a non-read request: %s", r)
		}
	}
}

func TestLivePolicyPreviewObservation(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	const ctrlNS = "preview-live-system"
	for _, ns := range []struct{ name, env string }{{ctrlNS, ""}, {"preview-prod", "production"}, {"preview-dev", "development"}} {
		o := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns.name}}
		if ns.env != "" {
			o.Labels = map[string]string{previewEnvLabel: ns.env}
		}
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(l.ctx, o) })
	}
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "preview-shared"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	deny := bindingObj("preview-deny-prod", p.Name, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{previewEnvLabel: "production"})
	audit := bindingObj("preview-audit-dev", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{previewEnvLabel: "development"})
	for _, o := range []client.Object{p, deny, audit} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, o := range []client.Object{deny, audit, p} {
			_ = l.c.Delete(l.ctx, o)
		}
	})
	stop := l.startManager()
	defer stop()
	denyB, auditB := l.waitReady(deny.Name, 1), l.waitReady(audit.Name, 1)

	// The documented reader RBAC, bound to a user with nothing else.
	const reader, partial = "konstapel-preview-reader", "konstapel-preview-partial"
	l.applyManifests("../../docs/examples/policy-preview/reader-rbac.yaml", func(u *unstructured.Unstructured) {
		if u.GetKind() == "Role" {
			u.SetNamespace(ctrlNS)
		}
	})
	l.bind("konstapel-preview-reader", reader, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-policy-preview-reader"}, "")
	l.bind("konstapel-preview-reader", reader, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "konstapel-policy-preview-reader"}, ctrlNS)

	// The identity is get/list only: no writes, no watch, no Secrets.
	for _, a := range []authzv1.ResourceAttributes{
		{Verb: "create", Group: "compliance.erenius.io", Resource: "compliancebindings"},
		{Verb: "patch", Group: "compliance.erenius.io", Resource: "complianceprofiles"},
		{Verb: "delete", Group: "policies.kyverno.io", Resource: "validatingpolicies"},
		{Verb: "update", Resource: "configmaps", Namespace: ctrlNS},
		{Verb: "watch", Group: "compliance.erenius.io", Resource: "compliancebindings"},
		{Verb: "get", Resource: "secrets", Namespace: ctrlNS},
		{Verb: "list", Resource: "secrets"},
	} {
		if l.can(reader, a) {
			t.Fatalf("reader may %s %s", a.Verb, a.Resource)
		}
	}
	if !l.can(reader, authzv1.ResourceAttributes{Verb: "list", Group: "policies.kyverno.io", Resource: "validatingpolicies"}) {
		t.Fatal("reader cannot list engine policies")
	}

	snap, reqs, err := l.observeAs(reader, ctrlNS)
	assertWireReadOnly(t, reqs)
	if err != nil || !snap.Complete {
		t.Fatalf("observation incomplete: %v", err)
	}
	ks := &corev1.Namespace{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: "kube-system"}, ks); err != nil {
		t.Fatal(err)
	}
	prod := &corev1.Namespace{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: "preview-prod"}, prod); err != nil {
		t.Fatal(err)
	}
	if snap.Cluster != "kube-system:"+string(ks.UID) || snap.Context != reader {
		t.Fatalf("cluster %s context %s", snap.Cluster, snap.Context)
	}
	var bindings []string
	for _, b := range snap.Live.Bindings {
		if b.Spec.ProfileRef.Name == p.Name {
			bindings = append(bindings, b.Name+"@"+string(b.UID))
		}
	}
	if !slices.Equal(bindings, []string{audit.Name + "@" + string(auditB.UID), deny.Name + "@" + string(denyB.UID)}) {
		t.Fatalf("shared-profile consumers: %v", bindings)
	}
	if i := slices.IndexFunc(snap.Namespaces, func(n preview.ObservedNamespace) bool { return n.Name == "preview-prod" }); i < 0 || snap.Namespaces[i].UID != prod.UID {
		t.Fatal("namespace instance not observed")
	}
	owned := map[string]bool{}
	for _, a := range snap.Applied {
		if a.Ownership == preview.Owned && a.Ready && a.Contribution != nil && (a.BindingUID == denyB.UID || a.BindingUID == auditB.UID) {
			owned[string(a.Contribution.Mode)] = true
		}
	}
	if !owned["Deny"] || !owned["Audit"] {
		t.Fatalf("owned engine policies: %+v", snap.Applied)
	}
	l.record("observed", map[string]any{"captures": snap.Captures, "objects": len(snap.Objects), "requests": len(reqs), "durationMs": snap.End.Sub(snap.Start).Milliseconds()})

	// A reader without engine-policy access gets an incomplete observation,
	// not an empty applied state.
	limited := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "konstapel-preview-partial"}, Rules: []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"get", "list"}},
		{APIGroups: []string{"compliance.erenius.io"}, Resources: []string{"complianceprofiles", "compliancebindings", "complianceexceptions"}, Verbs: []string{"list"}}}}
	if err := l.c.Create(l.ctx, limited); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, limited) })
	l.bind("konstapel-preview-partial", partial, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: limited.Name}, "")
	denied, dreqs, derr := l.observeAs(partial, ctrlNS)
	assertWireReadOnly(t, dreqs)
	if derr == nil || denied.Complete || len(denied.Errors) == 0 || denied.Errors[0].Code != preview.ObserveAccessDenied ||
		denied.Errors[0].Resource != "policies.kyverno.io/v1/validatingpolicies" || len(denied.Applied) != 0 {
		t.Fatalf("denied engine-policy read: err=%v snapshot=%+v", derr, denied)
	}

	evidence, _ := json.MarshalIndent(map[string]any{"snapshot": snap, "requests": reqs, "denied": denied, "deniedRequests": dreqs}, "", "  ")
	if err := os.WriteFile(filepath.Join(l.out, "preview-observation.json"), evidence, 0o644); err != nil {
		t.Fatal(err)
	}
}
