//go:build live

package controller

// Live requester attribution for every creator-recording admission policy:
// konstapel-assessment-requester (AssessmentRequest spec.requester),
// konstapel-evidence-attachment-registrant (EvidenceAttachment
// spec.registeredBy) and konstapel-evidence-signing-requester
// (EvidenceSigningRequest spec.requestedBy), as shipped, against the real
// API server. Two real credentials, no impersonation: the cluster
// administrator's kubeconfig certificate (an identity without a UID, like
// X.509 and OIDC users) and a ServiceAccount's bound credential holding the
// shipped creator roles (with a UID). Whatever requester a creator submits
// (none, another user, another user's UID, its own name with a forged UID,
// itself), the stored value is exactly the authenticated identity: the
// mutation replaces the field as a whole, so no forged UID survives for a
// user without one. Creates are dry runs; their responses are the stored
// objects. Offline: TestRequesterPoliciesRecordTheAuthenticatedUser. Run
// through scripts/targeting-live.sh (acceptance group "admission").

import (
	"context"
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func TestLiveRequesterAttribution(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	const platform, team, other = "rqa-platform", "rqa-team", "rqa-someone-else"
	for _, n := range []string{platform, team} {
		o := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}}
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatalf("create namespace %s (test-owned): %v", n, err)
		}
		t.Cleanup(func() { _ = l.c.Delete(context.Background(), o) })
	}
	suffix := func(u *unstructured.Unstructured) { u.SetName(u.GetName() + "-rqa-live") }
	for _, f := range []string{"assessment-requester", "evidence-attachments", "evidence-signing-recovery"} {
		l.applyManifests("../../config/rbac/"+f+".yaml", suffix)
	}
	role := func(name string) rbacv1.RoleRef {
		return rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name + "-rqa-live"}
	}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: platform, Name: "creator"}}
	if err := l.c.Create(l.ctx, sa); err != nil {
		t.Fatal(err)
	}
	l.bindSA("rqa-requester", platform, sa.Name, role("konstapel-assessment-requester"), team)
	l.bindSA("rqa-registrar", platform, sa.Name, role("konstapel-evidence-attachment-registrar"), "")
	l.bindSA("rqa-recoverer", platform, sa.Name, role("konstapel-evidence-signing-recoverer"), "")
	for _, f := range []string{"assessment-requester", "evidence-attachment-registrant", "evidence-signing-requester"} {
		l.applyManifests("../../config/admission/"+f+".yaml", nil)
	}

	type creator struct {
		key string
		c   client.Client
		as  v1alpha1.Requester
	}
	identify := func(key string, cfg *rest.Config) creator {
		t.Helper()
		if cfg.Impersonate.UserName != "" {
			t.Fatalf("%s: impersonation configured", key)
		}
		c, err := client.New(cfg, client.Options{Scheme: l.c.Scheme()})
		if err != nil {
			t.Fatal(err)
		}
		ssr := &authenticationv1.SelfSubjectReview{}
		if err := c.Create(l.ctx, ssr); err != nil {
			t.Fatal(err)
		}
		return creator{key, c, v1alpha1.Requester{Username: ssr.Status.UserInfo.Username, UID: ssr.Status.UserInfo.UID}}
	}
	saCfg := rest.AnonymousClientConfig(l.cfg)
	saCfg.BearerToken = l.apiToken(platform, sa.Name)
	creators := []creator{identify("cluster administrator (certificate, no UID)", rest.CopyConfig(l.cfg)), identify("ServiceAccount (bound credential, UID)", saCfg)}
	if creators[0].as.UID != "" || creators[1].as.UID == "" {
		t.Fatalf("identities %+v, want one without and one with a UID", creators)
	}

	// The creatable objects, each with its requester field.
	kinds := []struct {
		kind  string
		build func(*v1alpha1.Requester) (client.Object, func() *v1alpha1.Requester)
	}{
		{"AssessmentRequest", func(r *v1alpha1.Requester) (client.Object, func() *v1alpha1.Requester) {
			o := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Name: "rqa-probe", Namespace: team},
				Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: "rqa-binding"}, Requester: r}}
			return o, func() *v1alpha1.Requester { return o.Spec.Requester }
		}},
		{"EvidenceAttachment", func(r *v1alpha1.Requester) (client.Object, func() *v1alpha1.Requester) {
			o := &v1alpha1.EvidenceAttachment{ObjectMeta: metav1.ObjectMeta{Name: "rqa-probe"}, Spec: v1alpha1.EvidenceAttachmentSpec{
				Document: v1alpha1.AttachmentDocument{Title: "DC North physical access audit", MediaType: "application/pdf", Size: 482113, SHA256: "sha256:" + strings.Repeat("ab", 32)},
				Source:   v1alpha1.AttachmentSource{Issuer: "Example Audit AB"},
				Validity: v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)), ValidUntil: metav1.NewTime(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))},
				Associations: []v1alpha1.AttachmentAssociation{{Binding: v1alpha1.ExactBindingReference{Name: "rqa-binding", UID: "0b6c1f0e-2f39-4c1a-9a51-7d1d5f3c2a11"},
					CatalogDigest: "sha256:" + strings.Repeat("cd", 32), Controls: []v1alpha1.AttachmentControl{{ID: "pe-3"}}}},
				Scope:        v1alpha1.AttachmentScope{Description: "DC North halls A and B"},
				RegisteredBy: r,
			}}
			return o, func() *v1alpha1.Requester { return o.Spec.RegisteredBy }
		}},
		{"EvidenceSigningRequest", func(r *v1alpha1.Requester) (client.Object, func() *v1alpha1.Requester) {
			o := &v1alpha1.EvidenceSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: "rqa-probe"}, Spec: v1alpha1.EvidenceSigningRequestSpec{
				Run: v1alpha1.ExactRunReference{Name: "rqa-run", UID: "7d1c2a3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d"}, Reason: "Signing key Secret restored (live attribution)", RequestedBy: r}}
			return o, func() *v1alpha1.Requester { return o.Spec.RequestedBy }
		}},
	}
	l.eventually("requester policies effective", func() (bool, string) {
		for _, k := range kinds {
			o, got := k.build(&v1alpha1.Requester{Username: other})
			if err := creators[1].c.Create(l.ctx, o, client.DryRunAll); err != nil {
				return false, k.kind + ": " + err.Error()
			}
			if r := got(); r == nil || r.Username != creators[1].as.Username {
				return false, k.kind + ": " + toJSON(r)
			}
		}
		return true, ""
	})
	recorded := map[string]map[string]any{}
	for _, cr := range creators {
		recorded[cr.key] = map[string]any{"authenticated": cr.as}
		for name, supplied := range map[string]*v1alpha1.Requester{
			"absent":                         nil,
			"another user":                   {Username: other},
			"another user and UID":           {Username: other, UID: "uid-" + other},
			"its own name with a forged UID": {Username: cr.as.Username, UID: "uid-forged"},
			"itself":                         cr.as.DeepCopy(),
		} {
			for _, k := range kinds {
				var in *v1alpha1.Requester
				if supplied != nil {
					in = supplied.DeepCopy()
				}
				o, got := k.build(in)
				if err := cr.c.Create(l.ctx, o, client.DryRunAll); err != nil {
					t.Errorf("%s creates a %s supplying %s: %v", cr.key, k.kind, name, err)
					continue
				}
				if r := got(); r == nil || *r != cr.as {
					t.Errorf("%s creates a %s supplying %s %s: recorded %s, want %s", cr.key, k.kind, name, toJSON(supplied), toJSON(r), toJSON(cr.as))
				} else {
					recorded[cr.key][k.kind+", supplied "+name] = r
				}
			}
		}
	}
	l.record("attribution", map[string]any{"credentials": "real (no impersonation)", "creates": "dry run", "recorded": recorded})
}
