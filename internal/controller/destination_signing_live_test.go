//go:build live

package controller

// Live destination signing configuration (add-evidence-signing 2.1-2.4),
// against the real API server with the generated CRD and RBAC, and the
// manager running as an identity bound to the generated controller roles:
//   - the documented `cosign generate-key-pair k8s://...` command (pinned
//     Cosign) creates the key Secret, and the documented example destination
//     (relocated to the test S3 service) becomes SigningReady with the
//     fingerprint the documented command computes from cosign.pub;
//   - admission rejects Required without secretRef, cross-namespace
//     references, and KMS/keyless requests;
//   - application and viewer roles cannot read the key Secret or change the
//     policy; viewers can read the public fingerprint;
//   - a missing Secret is reported without affecting Ready, and installing
//     it is noticed without touching the destination;
//   - Required→Disabled is reported as such.
// Run through scripts/targeting-live.sh.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// documentedBlock returns the non-comment lines of the first ```sh block
// after marker in docs/integration/evidence-signing.md.
func documentedBlock(t *testing.T, marker string) []string {
	t.Helper()
	raw, err := os.ReadFile("../../docs/integration/evidence-signing.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(raw), marker)
	_, rest, ok2 := strings.Cut(section, "```sh\n")
	block, _, ok3 := strings.Cut(rest, "```")
	if !ok || !ok2 || !ok3 {
		t.Fatalf("%q block not found in docs/integration/evidence-signing.md", marker)
	}
	var out []string
	for _, l := range strings.Split(block, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func TestLiveDestinationSigning(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	pub := startS3(t, l)
	root, _ := filepath.Abs("../..")
	ns := "konstapel-system"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	const controllerUser, admin, viewer, team = "konstapel-live-signing-controller", "signing-admin", "signing-viewer", "signing-team"
	l.applyManifests("../../config/rbac/controller/role.yaml", nil)
	for _, f := range []string{"compliance-admin.yaml", "compliance-viewer.yaml", "assessment-requester.yaml"} {
		l.applyManifests("../../config/rbac/"+f, nil)
	}
	l.setNamespace("ds-team", "ds-team")
	l.bind("konstapel-live-signing-controller", controllerUser, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-controller"}, "")
	l.bind("konstapel-live-signing-controller", controllerUser, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "konstapel-controller"}, ns)
	l.bind("konstapel-live-signing-admin", admin, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-compliance-admin"}, "")
	l.bind("konstapel-live-signing-viewer", viewer, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-compliance-viewer"}, "")
	l.bind("konstapel-live-signing-team", team, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-assessment-requester"}, "ds-team")
	adminC, viewerC, teamC := l.as(admin, "system:authenticated"), l.as(viewer, "system:authenticated"), l.as(team, "system:authenticated")

	s3secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "ds-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	if err := l.c.Create(l.ctx, s3secret); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, s3secret) })

	// The documented example destination, relocated to the test service.
	raw, err := os.ReadFile("../../docs/examples/evidence-signing/destination.yaml")
	if err != nil {
		t.Fatal(err)
	}
	example := &v1alpha1.EvidenceDestination{}
	if err := yaml.UnmarshalStrict(raw, example); err != nil {
		t.Fatal(err)
	}
	keyName := example.Spec.Signing.SecretRef.Name
	newDest := func(name string, signing *v1alpha1.EvidenceSigning) *v1alpha1.EvidenceDestination {
		ed := example.DeepCopy()
		ed.Name = name
		ed.Spec.S3 = v1alpha1.S3Location{Endpoint: l.s3Endpoint, Bucket: pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/" + name, DevelopmentFixture: true,
			CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: s3secret.Name}}}
		if signing != nil {
			ed.Spec.Signing = signing
		}
		return ed
	}

	// Admission: invalid policies are rejected with a field message.
	for name, s := range map[string]string{
		"required without secretRef": `{"mode":"Required"}`,
		"cross-namespace secretRef":  `{"mode":"Required","secretRef":{"name":"k","namespace":"team-a"}}`,
		"kms":                        `{"mode":"Required","kms":{"keyID":"x"}}`,
		"keyless":                    `{"mode":"Required","keyless":{"issuer":"https://kubernetes.default.svc"}}`,
	} {
		u := newDest("ds-invalid", nil)
		obj, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(u)
		var signing map[string]any
		_ = yaml.Unmarshal([]byte(s), &signing)
		obj["spec"].(map[string]any)["signing"] = signing
		uo := &unstructured.Unstructured{Object: obj}
		uo.SetAPIVersion(v1alpha1.GroupVersion.String())
		uo.SetKind("EvidenceDestination")
		if err := adminC.Create(l.ctx, uo, client.DryRunAll); !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), "spec.signing") {
			t.Fatalf("%s: want Invalid naming spec.signing, got %v", name, err)
		}
	}
	if err := teamC.Create(l.ctx, newDest("ds-team-owned", nil), client.DryRunAll); !apierrors.IsForbidden(err) {
		t.Fatalf("an application role created a destination: %v", err)
	}
	l.record("admission", map[string]any{"invalid": "Invalid", "teamCreate": "Forbidden"})

	// The documented key generation, with the pinned Cosign, against this
	// cluster only (a minified kubeconfig whose current context is the test
	// cluster).
	work := t.TempDir()
	kc := filepath.Join(work, "kubeconfig")
	view, err := exec.CommandContext(l.ctx, "kubectl", "--kubeconfig", os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"), "--context", os.Getenv("KONSTAPEL_LIVE_CONTEXT"),
		"config", "view", "--minify", "--flatten").Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kc, view, 0o600); err != nil {
		t.Fatal(err)
	}
	password := "live-" + strings.ReplaceAll(time.Now().UTC().Format(time.RFC3339Nano), ":", "")
	t.Cleanup(func() {
		_ = l.c.Delete(l.ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: keyName}})
	})
	shell := func(line string, env ...string) string {
		t.Helper()
		cmd := exec.CommandContext(l.ctx, "sh", "-c", line)
		cmd.Dir = work
		cmd.Env = append(os.Environ(), append([]string{"KUBECONFIG=" + kc}, env...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("documented command %q: %v\n%s", line, err, out)
		}
		return string(out)
	}
	for _, line := range documentedBlock(t, "Create the signing key Secret:") {
		if !strings.Contains(line, "k8s://"+ns+"/"+keyName) {
			t.Fatalf("documented key command does not create the example's Secret %s: %s", keyName, line)
		}
		shell(line, "COSIGN_PASSWORD="+password)
	}
	keySecret := &corev1.Secret{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: keyName}, keySecret); err != nil {
		t.Fatal(err)
	}
	if keySecret.Immutable == nil || !*keySecret.Immutable || len(keySecret.Data["cosign.key"]) == 0 || string(keySecret.Data["cosign.password"]) != password {
		t.Fatalf("Cosign's Secret: immutable=%v entries=%d", keySecret.Immutable, len(keySecret.Data))
	}
	var fingerprint string
	for _, line := range documentedBlock(t, "Compute a public key's fingerprint:") {
		fingerprint = strings.TrimSpace(shell(line))
	}
	if !strings.HasPrefix(fingerprint, "sha256:") || len(fingerprint) != 71 {
		t.Fatalf("documented fingerprint command printed %q", fingerprint)
	}

	// Application identities cannot read the key or change the policy.
	for user, c := range map[string]client.Client{"viewer": viewerC, "team": teamC} {
		if err := c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: keyName}, &corev1.Secret{}); !apierrors.IsForbidden(err) {
			t.Fatalf("%s read the signing key Secret: %v", user, err)
		}
	}

	rt := AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: 5 * time.Minute, Workers: 2,
		ControllerNamespace: ns, Destinations: &DestinationPublishers{Reader: l.as(controllerUser, "system:authenticated"), Namespace: ns}}
	ConfigureAssessments(rt)
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	stop := l.startManagerAs(controllerUser)
	defer func() { stop() }()

	ed := newDest("ds-primary", nil)
	if err := adminC.Create(l.ctx, ed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		got := &v1alpha1.EvidenceDestination{}
		if l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got) == nil {
			controllerutil.RemoveFinalizer(got, DestinationFinalizer)
			_ = l.c.Update(l.ctx, got)
			_ = l.c.Delete(l.ctx, got)
		}
	})
	status := func() *v1alpha1.EvidenceDestination {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
		return got
	}
	signingIs := func(what string, s metav1.ConditionStatus, reason, fp string) {
		t.Helper()
		l.eventually(what, func() (bool, string) {
			got := status()
			c := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionDestinationSigningReady)
			ok := c != nil && c.Status == s && c.Reason == reason && c.ObservedGeneration == got.Generation &&
				got.Status.Signing != nil && got.Status.Signing.KeyFingerprint == fp &&
				meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionDestinationReady)
			return ok, toJSON(got.Status)
		})
	}
	signingIs("example destination signing ready under the controller's RBAC", metav1.ConditionTrue, v1alpha1.SigningReasonKeyLoaded, fingerprint)
	seen := &v1alpha1.EvidenceDestination{}
	if err := viewerC.Get(l.ctx, client.ObjectKeyFromObject(ed), seen); err != nil || seen.Status.Signing.KeyFingerprint != fingerprint {
		t.Fatalf("viewer cannot read the public fingerprint: %v", err)
	}
	if strings.Contains(toJSON(seen), password) {
		t.Fatal("destination exposes the key password")
	}
	patch := client.RawPatch("application/merge-patch+json", []byte(`{"spec":{"signing":{"mode":"Disabled","secretRef":null}}}`))
	for user, c := range map[string]client.Client{"viewer": viewerC, "team": teamC} {
		if err := c.Patch(l.ctx, ed.DeepCopy(), patch); !apierrors.IsForbidden(err) {
			t.Fatalf("%s changed the signing policy: %v", user, err)
		}
	}
	l.record("ready", map[string]any{"fingerprint": fingerprint, "secret": keyName, "immutable": true, "viewerReadsKey": "Forbidden", "teamPatch": "Forbidden"})

	// A missing key is reported without touching Ready; installing it is
	// noticed without another destination change.
	missing := "ds-signing-next"
	cur := status()
	cur.Spec.Signing.SecretRef.Name = missing
	if err := adminC.Update(l.ctx, cur); err != nil {
		t.Fatal(err)
	}
	signingIs("missing key reported", metav1.ConditionFalse, v1alpha1.SigningReasonSecretNotFound, "")
	next, nextFP := signingKeySecret(t, missing, "next-password")
	next.Namespace = ns
	if err := l.c.Create(l.ctx, next); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, next) })
	generation := status().Generation
	signingIs("installed key noticed", metav1.ConditionTrue, v1alpha1.SigningReasonKeyLoaded, nextFP)
	if status().Generation != generation {
		t.Fatal("the destination changed while waiting for the key")
	}
	l.record("missing-then-installed", map[string]any{"secret": missing, "fingerprint": nextFP})

	// Required → Disabled.
	if err := adminC.Patch(l.ctx, status(), patch); err != nil {
		t.Fatal(err)
	}
	signingIs("disabled reported", metav1.ConditionTrue, v1alpha1.SigningReasonDisabled, "")
	l.record("disabled", map[string]any{"mode": status().Status.Signing.Mode})
}
