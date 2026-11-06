//go:build live

package controller

// Live exception acceptance admission (add-self-service-policy-exceptions
// task 2.2): the in-process manager serves the ComplianceException webhooks
// from config/webhook/exceptions.yaml to a real API server, and requests are
// made as impersonated application identities.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/exception"
)

const exceptionWebhookPort = 19443

// webhookHost is the address the kind API server reaches this test process
// at: KONSTAPEL_LIVE_WEBHOOK_HOST, or the IPv4 gateway of the "kind" network.
func webhookHost(t *testing.T) string {
	if h := os.Getenv("KONSTAPEL_LIVE_WEBHOOK_HOST"); h != "" {
		return h
	}
	out, err := exec.Command("docker", "network", "inspect", "kind", "-f", "{{range .IPAM.Config}}{{.Gateway}} {{end}}").Output()
	if err != nil {
		t.Fatalf("find the kind network gateway (or set KONSTAPEL_LIVE_WEBHOOK_HOST): %v", err)
	}
	for _, f := range strings.Fields(string(out)) {
		if ip := net.ParseIP(f); ip != nil && ip.To4() != nil {
			return f
		}
	}
	t.Fatalf("no IPv4 gateway on the kind network: %q", out)
	return ""
}

// servingCert writes a CA-signed tls.crt/tls.key for host into dir and
// returns the CA bundle.
func servingCert(t *testing.T, dir, host string) []byte {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "konstapel-live-webhook-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP(host)}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	write := func(name, typ string, der []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("tls.crt", "CERTIFICATE", leafDER)
	write("tls.key", "EC PRIVATE KEY", keyDER)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

// installExceptionWebhooks applies config/webhook/exceptions.yaml pointed at
// this process instead of the in-cluster Service.
func (l *live) installExceptionWebhooks(host string, caBundle []byte) {
	raw, err := os.ReadFile("../../config/webhook/exceptions.yaml")
	if err != nil {
		l.t.Fatal(err)
	}
	dec := utilyaml.NewYAMLOrJSONDecoder(strings.NewReader(string(raw)), 4096)
	url := func(path string) *string {
		u := fmt.Sprintf("https://%s:%d%s", host, exceptionWebhookPort, path)
		return &u
	}
	mut, val := &admissionregistrationv1.MutatingWebhookConfiguration{}, &admissionregistrationv1.ValidatingWebhookConfiguration{}
	if err := dec.Decode(mut); err != nil {
		l.t.Fatal(err)
	}
	if err := dec.Decode(val); err != nil {
		l.t.Fatal(err)
	}
	for i := range mut.Webhooks {
		mut.Webhooks[i].ClientConfig = admissionregistrationv1.WebhookClientConfig{URL: url(*mut.Webhooks[i].ClientConfig.Service.Path), CABundle: caBundle}
	}
	for i := range val.Webhooks {
		val.Webhooks[i].ClientConfig = admissionregistrationv1.WebhookClientConfig{URL: url(*val.Webhooks[i].ClientConfig.Service.Path), CABundle: caBundle}
	}
	for _, o := range []client.Object{mut, val} {
		_ = l.c.Delete(l.ctx, o)
		if err := l.c.Create(l.ctx, o); err != nil {
			l.t.Fatal(err)
		}
	}
	// Fail-closed webhooks must not outlive the process that serves them.
	l.t.Cleanup(func() {
		_ = l.c.Delete(l.ctx, mut)
		_ = l.c.Delete(l.ctx, val)
	})
}

// as returns a client that authenticates as the given identity.
func (l *live) as(user string, groups ...string) client.Client {
	cfg := rest.CopyConfig(l.cfg)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: user, UID: "uid-" + user, Groups: groups}
	c, err := client.New(cfg, client.Options{Scheme: l.c.Scheme()})
	if err != nil {
		l.t.Fatal(err)
	}
	return c
}

func acceptance(t *testing.T, ex *v1alpha1.ComplianceException) exception.Acceptance {
	t.Helper()
	var a exception.Acceptance
	if err := json.Unmarshal([]byte(ex.Annotations[exception.AcceptanceAnnotation]), &a); err != nil {
		t.Fatalf("acceptance annotation on %s: %v", ex.Name, err)
	}
	return a
}

func TestLiveExceptionAdmission(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	host := webhookHost(t)
	certs := t.TempDir()
	ca := servingCert(t, certs, host)

	if err := l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: DefaultSnapshotNamespace}}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	mgr, err := NewManager(l.cfg, Options{Content: content, MetricsAddr: "0", ProbeAddr: "0", EnginePoll: 2 * time.Second,
		SkipControllerNameValidation: true, WebhookCertDir: certs, WebhookPort: exceptionWebhookPort})
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
	l.installExceptionWebhooks(host, ca)

	ns := "exc-admission"
	l.setNamespace(ns, "exc-admission")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "exc-self-service"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)},
			Policies: []v1alpha1.ProfilePolicy{{Name: pol, Exceptions: v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: 720 * time.Hour}}}}}}
	b := bindingObj("exc-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "exc-admission"})
	// The shipped namespace self-service role, bound per namespace (task 2.4).
	editor := l.shippedClusterRole("../../config/rbac/exception-editor.yaml", "konstapel-exception-editor")
	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "exception-editors", Namespace: ns},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: editor},
		Subjects: []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: "Group", Name: "team-a-editors"}}}
	nsB := "exc-admission-b"
	l.setNamespace(nsB, "exc-admission-b")
	rbB := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "exception-editors", Namespace: nsB},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: editor},
		Subjects: []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: "Group", Name: "team-b-editors"}}}
	for _, o := range []client.Object{p, b, rb, rbB} {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = l.c.DeleteAllOf(l.ctx, &v1alpha1.ComplianceException{}, client.InNamespace(ns))
		for _, o := range []client.Object{rbB, rb, b, p} {
			_ = l.c.Delete(l.ctx, o)
		}
	})
	l.waitReady(b.Name, 1)
	nsObj := &corev1.Namespace{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: ns}, nsObj); err != nil {
		t.Fatal(err)
	}

	alice := l.as("alice", "team-a-editors", "system:authenticated")
	bob := l.as("bob", "team-a-editors", "system:authenticated")
	argo := l.as("system:serviceaccount:argocd:argocd-application-controller", "team-a-editors", "system:serviceaccounts", "system:authenticated")
	newEx := func(name string, annotations map[string]string) *v1alpha1.ComplianceException {
		return &v1alpha1.ComplianceException{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: annotations},
			Spec: v1alpha1.ComplianceExceptionSpec{Policy: pol, WorkloadSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "debug"}},
				Reason: "live admission check", ExpiresAt: metav1.NewTime(time.Now().Add(24 * time.Hour).Truncate(time.Second)), AcceptanceRevision: 1}}
	}

	// The webhook server starts with the manager; wait until admission answers.
	forged := `{"revision":1,"actor":{"username":"platform-admin"}}`
	created := newEx("priv", map[string]string{exception.AcceptanceAnnotation: forged})
	l.eventually("exception webhook serving", func() (bool, string) {
		err := alice.Create(l.ctx, created.DeepCopy(), client.DryRunAll)
		return err == nil, fmt.Sprint(err)
	})

	// 1. Creation: forged attribution is overwritten by the authenticated caller.
	if err := alice.Create(l.ctx, created); err != nil {
		t.Fatal(err)
	}
	a := acceptance(t, created)
	l.record("create", map[string]any{"acceptance": a})
	if a.Actor.Username != "alice" || a.Actor.UID != "uid-alice" || a.Revision != 1 || a.Namespace.UID != nsObj.UID {
		t.Fatalf("acceptance = %+v", a)
	}
	if a.Eligibility == nil || a.Eligibility.Effective != v1alpha1.ExceptionsSelfService || len(a.Eligibility.Contributors) != 1 || a.Eligibility.Contributors[0].Binding.Name != b.Name {
		t.Fatalf("resolved set = %+v", a.Eligibility)
	}
	// 1a. The controller persists an immutable snapshot of the acceptance
	// in the protected namespace before anything is granted (task 3.1).
	snap1 := l.waitSnapshot(created, 1)
	l.record("snapshot", map[string]any{"configmap": snap1.Name, "digest": snap1.Annotations[exception.AnnotationSnapshotDigest]})

	// 1b. Authorization (task 2.4): the team role writes only its own
	// namespace's exceptions; status, central configuration, the protected
	// namespace and native engine exceptions stay out of reach, while the
	// controller identity can write exception status.
	l.authorizationChecks(alice, created, nsB)

	// 2. Dry run: the would-be record is returned and nothing is stored.
	dry := newEx("dry", nil)
	if err := bob.Create(l.ctx, dry, client.DryRunAll); err != nil {
		t.Fatal(err)
	}
	if acceptance(t, dry).Actor.Username != "bob" {
		t.Errorf("dry-run acceptance = %+v", acceptance(t, dry))
	}
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(dry), &v1alpha1.ComplianceException{}); err == nil {
		t.Error("dry-run exception was stored")
	}
	l.record("dry-run", map[string]any{"stored": false})

	// 3. GitOps: the service account is the actor; the commit author is a claim.
	gitops := newEx("gitops", map[string]string{exception.ClaimAnnotation: "carol (commit abc123)"})
	if err := argo.Create(l.ctx, gitops); err != nil {
		t.Fatal(err)
	}
	g := acceptance(t, gitops)
	l.record("gitops", map[string]any{"acceptance": g})
	if !strings.HasPrefix(g.Actor.Username, "system:serviceaccount:argocd:") || g.Claim != "carol (commit abc123)" {
		t.Fatalf("gitops acceptance = %+v", g)
	}

	// 4. An explicit renewal records a new acceptance by the renewing caller.
	renewed := &v1alpha1.ComplianceException{}
	if err := bob.Get(l.ctx, client.ObjectKeyFromObject(created), renewed); err != nil {
		t.Fatal(err)
	}
	renewed.Spec.AcceptanceRevision = 2
	renewed.Spec.Reason = "renewed live"
	renewed.Spec.ExpiresAt = metav1.NewTime(time.Now().Add(48 * time.Hour).Truncate(time.Second))
	if err := l.patchException(bob, renewed); err != nil {
		t.Fatal(err)
	}
	r := acceptance(t, renewed)
	l.record("renewal", map[string]any{"acceptance": r})
	if r.Revision != 2 || r.Actor.Username != "bob" || r.Eligibility == nil || r.Eligibility.Effective != v1alpha1.ExceptionsSelfService {
		t.Fatalf("renewal = %+v", r)
	}
	accepted := renewed.Annotations[exception.AcceptanceAnnotation]

	snap2 := l.waitSnapshot(created, 2)
	if again := l.snapshotConfigMap(snap1.Name); again == nil || again.ResourceVersion != snap1.ResourceVersion {
		t.Error("the first acceptance snapshot changed or disappeared after renewal")
	}
	l.record("renewal-snapshot", map[string]any{"configmap": snap2.Name, "retained": snap1.Name})

	// 5. Lifetime: beyond the profile's 720h maximum is rejected (task 2.3).
	long := newEx("too-long", nil)
	long.Spec.ExpiresAt = metav1.NewTime(time.Now().Add(721 * time.Hour).Truncate(time.Second))
	err = alice.Create(l.ctx, long)
	if err == nil || !strings.Contains(err.Error(), exception.ReasonLifetimeExceeded) {
		t.Fatalf("over-limit exception: %v", err)
	}
	l.record("lifetime-exceeded", map[string]any{"rejected": err.Error()})

	// 6. A Forbidden contribution overlapping the namespace rejects new
	// acceptances and renewals, and names the restrictive binding.
	fp := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "exc-forbidden"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	fb := bindingObj("exc-pci", fp.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "exc-admission"})
	for _, o := range []client.Object{fp, fb} {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = l.c.Delete(l.ctx, fb)
		_ = l.c.Delete(l.ctx, fp)
	})
	l.waitReady(fb.Name, 1)
	err = alice.Create(l.ctx, newEx("blocked", nil))
	if err == nil || !strings.Contains(err.Error(), exception.ReasonForbidden) || !strings.Contains(err.Error(), `"exc-pci"`) {
		t.Fatalf("forbidden overlap: %v", err)
	}
	l.record("forbidden-overlap", map[string]any{"rejected": err.Error()})
	renewAgain := renewed.DeepCopy()
	renewAgain.Spec.AcceptanceRevision = 3
	renewAgain.Spec.Reason = "renew under forbidden"
	renewAgain.Spec.ExpiresAt = metav1.NewTime(time.Now().Add(72 * time.Hour).Truncate(time.Second))
	err = l.patchException(bob, renewAgain)
	if err == nil || !strings.Contains(err.Error(), exception.ReasonForbidden) {
		t.Fatalf("renewal under forbidden overlap: %v", err)
	}
	l.record("forbidden-renewal", map[string]any{"rejected": err.Error()})
	for _, o := range []client.Object{fb, fp} {
		if err := l.c.Delete(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	// 7. Later configuration does not replace the accepted set on metadata
	// edits, and a renewal needs a policy that still applies.
	if err := l.c.Delete(l.ctx, b); err != nil {
		t.Fatal(err)
	}
	l.eventually("bindings removed", func() (bool, string) {
		errB := l.c.Get(l.ctx, client.ObjectKeyFromObject(b), &v1alpha1.ComplianceBinding{})
		errF := l.c.Get(l.ctx, client.ObjectKeyFromObject(fb), &v1alpha1.ComplianceBinding{})
		return errB != nil && errF != nil, "still present"
	})
	current := &v1alpha1.ComplianceException{}
	if err := bob.Get(l.ctx, client.ObjectKeyFromObject(created), current); err != nil {
		t.Fatal(err)
	}
	edited := current.DeepCopy()
	edited.Labels = map[string]string{"edited-by": "bob"}
	if err := l.patchException(bob, edited); err != nil {
		t.Fatalf("metadata edit: %v", err)
	}
	if edited.Annotations[exception.AcceptanceAnnotation] != accepted {
		t.Error("a metadata edit changed the acceptance")
	}
	l.record("metadata-edit-after-binding-deleted", map[string]any{"unchanged": true})

	// 8. A caller cannot rewrite the record outside a renewal.
	tampered := edited.DeepCopy()
	tampered.Annotations[exception.AcceptanceAnnotation] = strings.Replace(accepted, `"username":"bob"`, `"username":"platform-admin"`, 1)
	err = l.patchException(bob, tampered)
	if err == nil || !strings.Contains(err.Error(), "protected") {
		t.Fatalf("tampered record: %v", err)
	}
	l.record("tamper", map[string]any{"rejected": err.Error()})

	unapplied := edited.DeepCopy()
	unapplied.Spec.AcceptanceRevision = 3
	unapplied.Spec.Reason = "renew without a binding"
	unapplied.Spec.ExpiresAt = metav1.NewTime(time.Now().Add(72 * time.Hour).Truncate(time.Second))
	err = l.patchException(bob, unapplied)
	if err == nil || !strings.Contains(err.Error(), exception.ReasonNotApplicable) {
		t.Fatalf("renewal without an applicable binding: %v", err)
	}
	l.record("unapplied-renewal", map[string]any{"rejected": err.Error()})
}

// shippedClusterRole creates the ClusterRole from a config/rbac manifest
// unless it already exists, and returns its name.
func (l *live) shippedClusterRole(file, name string) string {
	raw, err := os.ReadFile(file)
	if err != nil {
		l.t.Fatal(err)
	}
	dec := utilyaml.NewYAMLOrJSONDecoder(strings.NewReader(string(raw)), 4096)
	for {
		cr := &rbacv1.ClusterRole{}
		if err := dec.Decode(cr); err != nil {
			l.t.Fatalf("ClusterRole %s not found in %s: %v", name, file, err)
		}
		if cr.Kind != "ClusterRole" || cr.Name != name {
			continue
		}
		cr.ResourceVersion = ""
		err := l.c.Create(l.ctx, cr)
		switch {
		case err == nil:
			l.t.Cleanup(func() { _ = l.c.Delete(l.ctx, cr) })
		case apierrors.IsAlreadyExists(err):
			// Another test shipped it; it is identical by construction.
		default:
			l.t.Fatal(err)
		}
		return name
	}
}

func (l *live) authorizationChecks(team client.Client, ex *v1alpha1.ComplianceException, otherNS string) {
	t := l.t
	forbidden := func(what string, err error) {
		t.Helper()
		if !apierrors.IsForbidden(err) {
			t.Errorf("%s: want Forbidden by RBAC, got %v", what, err)
			return
		}
		l.record("denied", map[string]any{"attempt": what})
	}
	other := ex.DeepCopy()
	other.Namespace, other.ResourceVersion, other.UID, other.Name = otherNS, "", "", "cross-namespace"
	forbidden("create an exception in another namespace", team.Create(l.ctx, other))

	withStatus := &v1alpha1.ComplianceException{}
	if err := team.Get(l.ctx, client.ObjectKeyFromObject(ex), withStatus); err != nil {
		t.Fatal(err)
	}
	cond := metav1.Condition{Type: "Active", Status: metav1.ConditionTrue, Reason: "Forged", Message: "set by the team", LastTransitionTime: metav1.Now()}
	withStatus.Status.Conditions = []metav1.Condition{cond}
	forbidden("write exception status", team.Status().Update(l.ctx, withStatus.DeepCopy()))

	prof := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "team-owned"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	forbidden("create a ComplianceProfile", team.Create(l.ctx, prof))
	forbidden("create a ComplianceBinding", team.Create(l.ctx, bindingObj("team-owned", "team-owned", v1alpha1.ModeAudit, nil)))
	snapshot := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "forged-acceptance", Namespace: "konstapel-system"}}
	forbidden("write in the protected konstapel-system namespace", team.Create(l.ctx, snapshot))
	native := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "policies.kyverno.io/v1", "kind": "PolicyException",
		"metadata": map[string]any{"name": "bypass", "namespace": "policy-exceptions"},
		"spec":     map[string]any{"policyRefs": []any{map[string]any{"name": "any", "kind": "ValidatingPolicy"}}},
	}}
	forbidden("create a native Kyverno PolicyException", team.Create(l.ctx, native))

	// The controller's generated ClusterRole can write exception status.
	controllerRole := l.shippedClusterRole("../../config/rbac/controller/role.yaml", "konstapel-controller")
	sa := "konstapel-controller"
	crb := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "exc-live-controller"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: controllerRole},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: sa, Namespace: "konstapel-system"}}}
	if err := l.c.Create(l.ctx, crb); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, crb) })
	ctrlClient := l.as("system:serviceaccount:konstapel-system:"+sa, "system:serviceaccounts", "system:serviceaccounts:konstapel-system", "system:authenticated")
	l.eventually("controller may write exception status", func() (bool, string) {
		cur := &v1alpha1.ComplianceException{}
		if err := ctrlClient.Get(l.ctx, client.ObjectKeyFromObject(ex), cur); err != nil {
			return false, err.Error()
		}
		cur.Status.Conditions = []metav1.Condition{{Type: "Probe", Status: metav1.ConditionUnknown, Reason: "LiveTest", Message: "controller status write", LastTransitionTime: metav1.Now()}}
		err := ctrlClient.Status().Update(l.ctx, cur)
		return err == nil, fmt.Sprint(err)
	})
	l.record("controller-status-write", map[string]any{"allowed": true})
}

// patchException writes want's spec, labels and annotations as the given
// identity with a merge patch, so concurrent controller status writes do not
// conflict. want is updated from the response.
func (l *live) patchException(c client.Client, want *v1alpha1.ComplianceException) error {
	cur := &v1alpha1.ComplianceException{}
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(want), cur); err != nil {
		return err
	}
	mod := cur.DeepCopy()
	mod.Spec, mod.Labels, mod.Annotations = want.Spec, want.Labels, want.Annotations
	if err := c.Patch(l.ctx, mod, client.MergeFrom(cur)); err != nil {
		return err
	}
	*want = *mod
	return nil
}

func (l *live) snapshotConfigMap(name string) *corev1.ConfigMap {
	cm := &corev1.ConfigMap{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: DefaultSnapshotNamespace, Name: name}, cm); err != nil {
		return nil
	}
	return cm
}

// waitSnapshot waits until the exception's status references the snapshot
// of revision and returns the verified, immutable snapshot ConfigMap.
func (l *live) waitSnapshot(ex *v1alpha1.ComplianceException, revision int64) *corev1.ConfigMap {
	l.t.Helper()
	var ref *v1alpha1.AcceptanceSnapshotReference
	l.eventually(fmt.Sprintf("acceptance snapshot of revision %d", revision), func() (bool, string) {
		cur := &v1alpha1.ComplianceException{}
		if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(ex), cur); err != nil {
			return false, err.Error()
		}
		ref = cur.Status.Acceptance
		return ref != nil && ref.Revision == revision, toJSON(cur.Status)
	})
	cm := l.snapshotConfigMap(strings.TrimPrefix(ref.Snapshot, DefaultSnapshotNamespace+"/"))
	if cm == nil {
		l.t.Fatalf("snapshot %s not found", ref.Snapshot)
	}
	snap, digest, err := exception.SnapshotFrom(cm)
	if err != nil {
		l.t.Fatal(err)
	}
	if cm.Immutable == nil || !*cm.Immutable || digest != ref.Digest || snap.AcceptanceRevision != revision || snap.Exception.UID != ex.UID {
		l.t.Fatalf("snapshot %s: immutable=%v digest=%s ref=%+v snapshot=%+v", cm.Name, cm.Immutable, digest, ref, snap)
	}
	for _, c := range snap.Eligibility.Contributors {
		if cm.Labels[exception.RevisionLabel(c.Revision)] != "true" {
			l.t.Errorf("snapshot %s lacks the label for revision %s", cm.Name, c.Revision)
		}
	}
	return cm
}
