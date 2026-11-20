//go:build live

package controller

// Live private-source bundle resolution for the policy-change preview
// (add-policy-change-preview 4.2 to 4.4), in the bundles acceptance group. The
// bundle owner's organization-key fixture is served from the disposable TLS
// and htpasswd registry of TestLiveBundlesOrganization, configured with the
// documented names (docs/examples/charts/oci-bundles.yaml). The preview runs
// as a get-only user bound to docs/examples/policy-preview/reader-rbac.yaml:
// without the optional Secret Role the private bundle is content-access-denied
// and the comparison incomplete; with it, the bundle resolves under the
// publisher rule and the comparison completes. Only named Secret gets of the
// referenced Secrets are on the wire, and no credential reaches the report.
// No controller runs: the preview needs none.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/preview"
)

func TestLivePolicyPreviewPrivateBundle(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	f := loadOBFixture(t)
	reg := startOBRegistry(t, l)
	publishFixture(t, l, reg, f, "org/valid/"+obBundle, "org/mirror/"+obBundle)

	const ns = "preview-bundles-system"
	for _, n := range []struct{ name, env string }{{ns, ""}, {"preview-private-prod", "production"}} {
		o := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n.name}}
		if n.env != "" {
			o.Labels = map[string]string{previewEnvLabel: n.env}
		}
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(l.ctx, o) })
	}
	sources := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: obSourcesCM},
		Data: map[string]string{"sources.yaml": obSourcesYAML(t, obSource(f, reg.host+"/org/valid/"+obBundle, f.fpOrg))}}
	for _, o := range []client.Object{
		sources,
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: obCAConfig}, Data: map[string]string{"ca.crt": string(reg.caPEM)}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: obCredSecret}, Type: corev1.SecretTypeDockerConfigJson,
			Data: map[string][]byte{corev1.DockerConfigJsonKey: obDockerConfig(reg.host, "reader-a", reg.users["reader-a"])}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: obKeySecret}, Data: map[string][]byte{"cosign.pub": f.pubOrg}},
		// Not referenced: never requested.
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: obDecoy}, Data: map[string][]byte{"k": []byte(reg.users["reader-b"])}},
	} {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(l.ctx, o) })
	}
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "preview-private"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: obBundle, Digest: f.subject}, Policies: []v1alpha1.ProfilePolicy{{Name: obPolicy}}}}
	b := bindingObj("preview-private-deny", p.Name, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{previewEnvLabel: "production"})
	for _, o := range []client.Object{p, b} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(l.ctx, o) })
	}

	const reader = "konstapel-preview-private-reader"
	l.applyManifests("../../docs/examples/policy-preview/reader-rbac.yaml", func(u *unstructured.Unstructured) {
		if u.GetKind() == "Role" {
			u.SetNamespace(ns)
		}
	})
	l.bind("konstapel-preview-private-reader", reader, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-policy-preview-reader"}, "")
	l.bind("konstapel-preview-private-reader", reader, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "konstapel-policy-preview-reader"}, ns)

	proposedPath := filepath.Join(t.TempDir(), "proposed.yaml")
	if err := os.WriteFile(proposedPath, []byte(`apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: preview-private-deny
spec:
  profileRef: {name: preview-private}
  namespaceSelector: {matchLabels: {`+previewEnvLabel+`: production}}
  mode: Audit
`), 0o600); err != nil {
		t.Fatal(err)
	}
	set, _, err := preview.Load(preview.Inputs{Proposed: []string{proposedPath}}, nil, preview.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	ver, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	run := func(step string) (*preview.Comparison, []string) {
		t.Helper()
		cfg, ctxName, err := preview.RESTConfig(l.readerKubeconfig(reader), reader)
		if err != nil {
			t.Fatal(err)
		}
		rec := &wireRecorder{}
		cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper { rec.next = rt; return rec })
		snap, err := preview.Observe(l.ctx, preview.ObserveOptions{Config: cfg, Context: ctxName, Namespace: ns, SourcesConfigMap: obSourcesCM})
		if err != nil {
			t.Fatalf("%s: observation: %v", step, err)
		}
		bc, err := preview.OpenContent(l.ctx, snap, preview.ContentOptions{Vendored: content, ControllerVersion: strings.TrimSpace(string(ver))})
		if err != nil {
			t.Fatal(err)
		}
		defer bc.Close()
		c, err := preview.Compare(l.ctx, preview.CompareInput{Snapshot: snap, Proposed: set, Content: bc})
		if err != nil {
			t.Fatal(err)
		}
		rec.mu.Lock()
		reqs := slices.Clone(rec.reqs)
		rec.mu.Unlock()
		// Read-only, and Secrets only as gets of the two referenced names.
		for _, r := range reqs {
			method, uri, _ := strings.Cut(r, " ")
			if strings.Contains(uri, "/secrets") {
				if method != http.MethodGet || (uri != "/api/v1/namespaces/"+ns+"/secrets/"+obCredSecret && uri != "/api/v1/namespaces/"+ns+"/secrets/"+obKeySecret) {
					t.Fatalf("%s: Secret request outside the referenced names: %s", step, r)
				}
				continue
			}
			assertWireReadOnly(t, []string{r})
		}
		raw, _ := json.Marshal(map[string]any{"snapshot": snap, "comparison": c})
		for _, v := range reg.users {
			if strings.Contains(string(raw), v) {
				t.Fatalf("%s: a registry credential reached the report", step)
			}
		}
		if err := os.WriteFile(filepath.Join(l.out, "preview-private-"+step+".json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		return c, reqs
	}
	record := func(c *preview.Comparison) map[string]any {
		var codes []string
		for _, d := range c.Errors {
			codes = append(codes, string(d.Code)+":"+d.Name)
		}
		return map[string]any{"complete": c.Complete, "impactCount": c.ImpactCount, "content": c.Content, "errors": codes}
	}

	// Without the optional Secret Role: never complete, and never the
	// controller's access instead.
	denied, _ := run("denied")
	i := slices.IndexFunc(denied.Errors, func(d preview.Diagnostic) bool { return d.Code == preview.CompareContentAccessDenied })
	if denied.Complete || i < 0 || !strings.Contains(denied.Errors[i].Message, obCredSecret) || len(denied.Content) != 1 || denied.Content[0].Resolved {
		t.Fatalf("denied: %+v", denied)
	}
	l.record("preview-private-denied", record(denied))

	// The documented Secret Role: the bundle resolves under the publisher
	// rule with the referenced credential, typed as an OCI manifest digest.
	l.bind("konstapel-preview-private-secrets", reader, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "konstapel-policy-preview-bundle-secrets"}, ns)
	ok, reqs := run("granted")
	if !ok.Complete || ok.ImpactCount != 1 || len(ok.Content) != 1 || !ok.Content[0].Resolved || ok.Content[0].DigestKind != preview.DigestOCIManifest ||
		ok.Content[0].Digest != f.subject || ok.Content[0].Repository != reg.host+"/org/valid/"+obBundle {
		t.Fatalf("granted: %+v", ok)
	}
	var secretGets int
	for _, r := range reqs {
		if strings.Contains(r, "/secrets/") {
			secretGets++
		}
	}
	if secretGets == 0 {
		t.Fatal("the referenced Secrets were not read")
	}
	l.record("preview-private-granted", map[string]any{"comparison": record(ok), "secretGets": secretGets, "requests": len(reqs)})
}
