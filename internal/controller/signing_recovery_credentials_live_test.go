//go:build live

package controller

// Live EvidenceSigningRequest admission and RBAC with real credentials
// (add-evidence-signing-recovery 5.3). TestLiveEvidenceSigningRequestAPI
// proves the same contract through impersonation; here every identity
// authenticates itself: ServiceAccounts with bound API-audience credentials
// from the TokenRequest API, a human recoverer with an X.509 client
// certificate issued by the cluster's kube-apiserver-client signer (no UID,
// role bound through its group), and the cluster administrator's own
// kubeconfig certificate. No request carries impersonation headers; the API
// server's SelfSubjectReview of each credential is the expected identity.
// Against the generated CRD, the shipped roles and admission policies, the
// shipped controller-identity ConfigMap and the generated controller RBAC:
//   - forged requester: without the mutation, the validation denies a
//     forged requester and an impersonation-style UID and admits only the
//     exact authenticated identity (the ServiceAccount's object UID); with
//     it, a forged requester is replaced by the authenticated one for
//     ServiceAccounts, the certificate user and the cluster administrator;
//     a credential without a UID that claims one is denied (the mutation
//     sets no UID, so the forged one remains and fails validation); the
//     controller copies only the recorded requester into status;
//   - spec edits: the recoverer, the reader and the controller are denied
//     by RBAC, and the cluster administrator by the CRD's immutability rule,
//     through update, merge patch and JSON patch;
//   - status writes: every identity but the configured controller is
//     denied, by RBAC or by the status-writer policy (the cluster
//     administrator, and a ServiceAccount of the controller's name in
//     another namespace that holds the controller role); the real recovery
//     reconciler running as that lookalike records nothing, and running as
//     the controller records the terminal outcome (RunNotFound), which even
//     the controller cannot rewrite or misattribute;
//   - each role: real get, list, watch, create, update, patch, delete,
//     deletecollection and status get/update/patch requests for the
//     recoverer (ServiceAccount and certificate user), the reader, the
//     compliance admin and viewer, the assessment operator, namespace users
//     (the assessment and exception roles, built-in admin and edit in their
//     namespace), built-in edit and view bound cluster-wide, an unbound
//     ServiceAccount, the controller, its lookalike and the cluster
//     administrator; neither recovery role writes run status, reads Secrets
//     or changes destinations.
// The API server's denial responses (code, reason, message, details) are
// kept as evidence; the test fails if any credential it issued appears in
// them. Run through scripts/targeting-live.sh (acceptance group "admission").

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// credentialIdentity is a client that authenticates with its own credential,
// and the identity the API server reported for that credential.
type credentialIdentity struct {
	key, credential string
	c               client.WithWatch
	user            authenticationv1.UserInfo
}

func TestLiveSigningRecoveryCredentials(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	const (
		ns, platform, team = "konstapel-system", "esrc-platform", "esrc-team"
		humanGroup         = "esrc-platform-recoverers"
		runName, runUID    = "esrc-retained-run", "7d1c2a3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
		other              = "esrc-someone-else"
		reason             = "Signing key Secret restored after CHG-5300 (live credentials acceptance)"
	)
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	for _, n := range []string{platform, team} {
		o := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}}
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatalf("create namespace %s (test-owned): %v", n, err)
		}
		t.Cleanup(func() { _ = l.c.Delete(context.Background(), o) })
	}

	// The shipped controller identity (konstapel-assessment-admission),
	// created test-owned.
	params := shippedAdmissionConfigMap(t)
	ctlNS, ctlSA := params.Data["controllerServiceAccountNamespace"], params.Data["controllerServiceAccountName"]
	if err := l.c.Create(l.ctx, params.DeepCopy()); err != nil {
		t.Fatalf("create the controller-identity ConfigMap (test-owned): %v", err)
	}
	t.Cleanup(func() { _ = l.c.Delete(context.Background(), params.DeepCopy()) })

	// Shipped roles under test-owned names; rules unchanged.
	suffix := func(u *unstructured.Unstructured) { u.SetName(u.GetName() + "-esrc-live") }
	for _, f := range []string{"evidence-signing-recovery", "assessment-requester", "exception-editor", "compliance-admin", "compliance-viewer", "assessment-operator"} {
		l.applyManifests("../../config/rbac/"+f+".yaml", suffix)
	}
	l.applyManifests("../../config/rbac/controller/role.yaml", suffix)
	shipped := func(name string) rbacv1.RoleRef {
		return rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name + "-esrc-live"}
	}
	builtIn := func(name string) rbacv1.RoleRef {
		return rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name}
	}

	// ServiceAccounts, test-owned. The controller's is the configured one,
	// unless an earlier test left it (then it is used and kept).
	accounts := []client.ObjectKey{{Namespace: ctlNS, Name: ctlSA}, {Namespace: platform, Name: ctlSA}}
	for _, sa := range []string{"recoverer", "reader", "compliance-admin", "compliance-viewer", "operator", "cluster-editor", "cluster-viewer", "nobody"} {
		accounts = append(accounts, client.ObjectKey{Namespace: platform, Name: sa})
	}
	for _, sa := range []string{"dev", "namespace-admin", "namespace-editor"} {
		accounts = append(accounts, client.ObjectKey{Namespace: team, Name: sa})
	}
	for _, k := range accounts {
		o := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: k.Namespace, Name: k.Name}}
		switch err := l.c.Create(l.ctx, o); {
		case err == nil:
			t.Cleanup(func() { _ = l.c.Delete(context.Background(), o) })
		case apierrors.IsAlreadyExists(err) && k.Namespace == ctlNS:
		default:
			t.Fatalf("create ServiceAccount %s: %v", k, err)
		}
	}
	l.bindSA("esrc-recoverer", platform, "recoverer", shipped("konstapel-evidence-signing-recoverer"), "")
	// A recoverer finds failed runs through the operator grant.
	l.bindSA("esrc-recoverer-operator", platform, "recoverer", shipped("konstapel-assessment-operator"), "")
	l.bindSA("esrc-reader", platform, "reader", shipped("konstapel-evidence-signing-recovery-reader"), "")
	l.bindSA("esrc-compliance-admin", platform, "compliance-admin", shipped("konstapel-compliance-admin"), "")
	l.bindSA("esrc-compliance-viewer", platform, "compliance-viewer", shipped("konstapel-compliance-viewer"), "")
	l.bindSA("esrc-operator", platform, "operator", shipped("konstapel-assessment-operator"), "")
	l.bindSA("esrc-cluster-editor", platform, "cluster-editor", builtIn("edit"), "")
	l.bindSA("esrc-cluster-viewer", platform, "cluster-viewer", builtIn("view"), "")
	l.bindSA("esrc-team-requester", team, "dev", shipped("konstapel-assessment-requester"), team)
	l.bindSA("esrc-team-exceptions", team, "dev", shipped("konstapel-exception-editor"), team)
	l.bindSA("esrc-namespace-admin", team, "namespace-admin", builtIn("admin"), team)
	l.bindSA("esrc-namespace-editor", team, "namespace-editor", builtIn("edit"), team)
	l.bindSA("esrc-controller", ctlNS, ctlSA, shipped("konstapel-controller"), "")
	// The controller's name in another namespace, with the controller role:
	// RBAC allows its status writes, the status-writer policy must not.
	l.bindSA("esrc-lookalike", platform, ctlSA, shipped("konstapel-controller"), "")
	// The human recoverer holds both roles through its certificate's group.
	for name, role := range map[string]string{"esrc-human-recoverer": "konstapel-evidence-signing-recoverer", "esrc-human-operator": "konstapel-assessment-operator"} {
		o := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}, RoleRef: shipped(role),
			Subjects: []rbacv1.Subject{{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: humanGroup}}}
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(context.Background(), o) })
	}

	// Real credentials. Everything they authenticate as comes from the API
	// server; the credentials themselves never leave this process.
	var issued []string
	ids := map[string]*credentialIdentity{}
	identify := func(key, credential string, cfg *rest.Config) *credentialIdentity {
		t.Helper()
		if cfg.Impersonate.UserName != "" || len(cfg.Impersonate.Groups) != 0 || cfg.Impersonate.UID != "" {
			t.Fatalf("%s: impersonation configured", key)
		}
		c, err := client.NewWithWatch(cfg, client.Options{Scheme: l.c.Scheme()})
		if err != nil {
			t.Fatal(err)
		}
		ssr := &authenticationv1.SelfSubjectReview{}
		if err := c.Create(l.ctx, ssr); err != nil {
			t.Fatalf("%s: SelfSubjectReview: %v", key, err)
		}
		id := &credentialIdentity{key: key, credential: credential, c: c, user: ssr.Status.UserInfo}
		ids[key] = id
		return id
	}
	serviceAccount := func(key, namespace, name string) *credentialIdentity {
		t.Helper()
		cfg := rest.AnonymousClientConfig(l.cfg)
		cfg.BearerToken = l.apiToken(namespace, name)
		issued = append(issued, cfg.BearerToken)
		id := identify(key, "bound ServiceAccount credential (TokenRequest, API server audience)", cfg)
		if want := "system:serviceaccount:" + namespace + ":" + name; id.user.Username != want {
			t.Fatalf("%s authenticated as %q, want %q", key, id.user.Username, want)
		}
		sa := &corev1.ServiceAccount{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: namespace, Name: name}, sa); err != nil {
			t.Fatal(err)
		}
		if id.user.UID != string(sa.UID) {
			t.Fatalf("%s authenticated with UID %q, want the ServiceAccount's %q", key, id.user.UID, sa.UID)
		}
		return id
	}
	recoverer := serviceAccount("recoverer", platform, "recoverer")
	reader := serviceAccount("reader", platform, "reader")
	for key, sa := range map[string]string{"compliance admin": "compliance-admin", "compliance viewer": "compliance-viewer", "assessment operator": "operator",
		"built-in edit, cluster-wide": "cluster-editor", "built-in view, cluster-wide": "cluster-viewer", "unbound ServiceAccount": "nobody"} {
		serviceAccount(key, platform, sa)
	}
	for key, sa := range map[string]string{"namespace assessment and exception roles": "dev", "built-in admin in its namespace": "namespace-admin",
		"built-in edit in its namespace": "namespace-editor"} {
		serviceAccount(key, team, sa)
	}
	ctl := serviceAccount("controller", ctlNS, ctlSA)
	lookalike := serviceAccount("controller name in another namespace", platform, ctlSA)
	humanCfg, humanKey := l.clientCertificate("esrc-human-recoverer", humanGroup)
	issued = append(issued, humanKey)
	human := identify("recoverer, certificate user", "X.509 client certificate (kubernetes.io/kube-apiserver-client signer)", humanCfg)
	if human.user.Username != "esrc-human-recoverer" || human.user.UID != "" || !slices.Contains(human.user.Groups, humanGroup) {
		t.Fatalf("certificate user authenticated as %s", toJSON(human.user))
	}
	admin := identify("cluster administrator", "the disposable cluster's kubeconfig client certificate", rest.CopyConfig(l.cfg))
	identities := map[string]any{}
	for key, id := range ids {
		identities[key] = map[string]any{"username": id.user.Username, "uid": id.user.UID, "groups": id.user.Groups, "credential": id.credential}
	}
	l.record("identities", map[string]any{"impersonation": false, "identities": identities})

	// The API server's denial responses, sanitized: status fields only.
	denials := map[string]map[string]any{}
	keep := func(what string, err error) map[string]any {
		t.Helper()
		var api apierrors.APIStatus
		if !errors.As(err, &api) {
			t.Fatalf("%s: not an API server response: %v", what, err)
		}
		st := api.Status()
		resp := map[string]any{"code": st.Code, "reason": st.Reason, "message": st.Message}
		if d := st.Details; d != nil {
			details := map[string]any{"group": d.Group, "kind": d.Kind, "name": d.Name}
			var causes []string
			for _, c := range d.Causes {
				causes = append(causes, fmt.Sprintf("%s: %s: %s", c.Field, c.Type, c.Message))
			}
			if causes != nil {
				details["causes"] = causes
			}
			resp["details"] = details
		}
		raw, _ := json.Marshal(resp)
		for _, s := range issued {
			if strings.Contains(string(raw), s) {
				t.Fatalf("%s: the API server's response contains an issued credential", what)
			}
		}
		denials[what] = resp
		return resp
	}
	deny := func(what string, err error, ok func(error) bool, contains string) {
		t.Helper()
		if err == nil || !ok(err) || !strings.Contains(err.Error(), contains) {
			t.Fatalf("%s: want a denial containing %q, got %v", what, contains, err)
		}
		keep(what, err)
	}
	const (
		forgedMsg = "spec.requestedBy must be the authenticated requester"
		writerMsg = "may write EvidenceSigningRequest status"
		immutable = "spec is immutable"
	)
	byRBAC := func(err error) bool {
		return apierrors.IsForbidden(err) && strings.Contains(err.Error(), " cannot ") && !strings.Contains(err.Error(), "AdmissionPolicy")
	}
	byWriterPolicy := func(err error) bool {
		return apierrors.IsForbidden(err) && strings.Contains(err.Error(), "konstapel-evidence-signing-status-writer")
	}
	newRequest := func(name string) *v1alpha1.EvidenceSigningRequest {
		return &v1alpha1.EvidenceSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.EvidenceSigningRequestSpec{
			Run: v1alpha1.ExactRunReference{Name: runName, UID: runUID}, Reason: reason}}
	}
	forgedRequest := func(name string, by *v1alpha1.Requester) *v1alpha1.EvidenceSigningRequest {
		r := newRequest(name)
		r.Spec.RequestedBy = by
		return r
	}
	requester := func(id *credentialIdentity) *v1alpha1.Requester {
		return &v1alpha1.Requester{Username: id.user.Username, UID: id.user.UID}
	}
	t.Cleanup(func() {
		var list v1alpha1.EvidenceSigningRequestList
		_ = l.c.List(context.Background(), &list)
		for i := range list.Items {
			if strings.HasPrefix(list.Items[i].Name, "esrc-") {
				_ = l.c.Delete(context.Background(), &list.Items[i])
			}
		}
	})
	l.eventually("recoverer bindings effective", func() (bool, string) {
		err := recoverer.c.List(l.ctx, &v1alpha1.EvidenceSigningRequestList{})
		return err == nil, errString(err)
	})

	// Forged requester, the validation alone: only the exact authenticated
	// identity is admitted, by the credential's real UID.
	l.applyKinds("../../config/admission/evidence-signing-requester.yaml", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding")
	l.eventually("requester validation effective", func() (bool, string) {
		err := recoverer.c.Create(l.ctx, newRequest("esrc-probe"), client.DryRunAll)
		return apierrors.IsForbidden(err) && strings.Contains(err.Error(), forgedMsg), errString(err)
	})
	deny("recoverer omits the requester, validation only", recoverer.c.Create(l.ctx, newRequest("esrc-unattributed"), client.DryRunAll), apierrors.IsForbidden, forgedMsg)
	deny("recoverer names another user, validation only", recoverer.c.Create(l.ctx, forgedRequest("esrc-forged", &v1alpha1.Requester{Username: other, UID: "uid-" + other}), client.DryRunAll),
		apierrors.IsForbidden, forgedMsg)
	deny("recoverer names itself with an impersonation-style UID, validation only",
		recoverer.c.Create(l.ctx, forgedRequest("esrc-uid", &v1alpha1.Requester{Username: recoverer.user.Username, UID: "uid-" + recoverer.user.Username}), client.DryRunAll),
		apierrors.IsForbidden, forgedMsg)
	deny("recoverer names another user with its own UID, validation only",
		recoverer.c.Create(l.ctx, forgedRequest("esrc-name", &v1alpha1.Requester{Username: other, UID: recoverer.user.UID}), client.DryRunAll), apierrors.IsForbidden, forgedMsg)
	deny("certificate user claims a UID, validation only",
		human.c.Create(l.ctx, forgedRequest("esrc-human-uid", &v1alpha1.Requester{Username: human.user.Username, UID: "uid-" + human.user.Username}), client.DryRunAll),
		apierrors.IsForbidden, forgedMsg)
	for _, id := range []*credentialIdentity{recoverer, human} {
		if err := id.c.Create(l.ctx, forgedRequest("esrc-self", requester(id)), client.DryRunAll); err != nil {
			t.Fatalf("%s: exact self-attribution denied: %v", id.key, err)
		}
	}

	// With the mutation, every creator is recorded as authenticated.
	l.applyKinds("../../config/admission/evidence-signing-requester.yaml", "MutatingAdmissionPolicy", "MutatingAdmissionPolicyBinding")
	l.eventually("requester mutation effective", func() (bool, string) {
		probe := forgedRequest("esrc-probe", &v1alpha1.Requester{Username: other})
		if err := recoverer.c.Create(l.ctx, probe, client.DryRunAll); err != nil {
			return false, err.Error()
		}
		return probe.Spec.RequestedBy != nil && probe.Spec.RequestedBy.Username == recoverer.user.Username, toJSON(probe.Spec.RequestedBy)
	})
	attribution := map[string]any{}
	stored := func(name string) *v1alpha1.EvidenceSigningRequest {
		t.Helper()
		got := &v1alpha1.EvidenceSigningRequest{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	for _, c := range []struct {
		name   string
		id     *credentialIdentity
		forged *v1alpha1.Requester
	}{
		{"esrc-forged-sa", recoverer, &v1alpha1.Requester{Username: other, UID: "uid-" + other}},
		{"esrc-forged-sa-name", recoverer, &v1alpha1.Requester{Username: other}},
		{"esrc-forged-human", human, &v1alpha1.Requester{Username: other}},
		{"esrc-forged-admin", admin, &v1alpha1.Requester{Username: other}},
		{"esrc-unattributed-admin", admin, nil},
	} {
		r := forgedRequest(c.name, c.forged)
		r.Status = v1alpha1.EvidenceSigningRequestStatus{Phase: v1alpha1.SigningRequestSucceeded, Reason: v1alpha1.RecoveryRecovered, RequestedBy: c.forged}
		if err := c.id.c.Create(l.ctx, r); err != nil {
			t.Fatalf("%s creates a request with a forged requester: %v", c.id.key, err)
		}
		got := stored(c.name)
		if want := requester(c.id); got.Spec.RequestedBy == nil || *got.Spec.RequestedBy != *want {
			t.Fatalf("%s: forged requester %s stored as %s, want %s", c.id.key, toJSON(c.forged), toJSON(got.Spec.RequestedBy), toJSON(want))
		}
		if got.Status.Phase != "" || got.Status.RequestedBy != nil || len(got.OwnerReferences) != 0 {
			t.Fatalf("%s: create stored status %s or owners %v", c.id.key, toJSON(got.Status), got.OwnerReferences)
		}
		attribution[c.name] = map[string]any{"creator": c.id.key, "forged": c.forged, "stored": got.Spec.RequestedBy, "statusOnCreate": "dropped"}
	}
	// A credential without a UID that claims one: the mutation sets the
	// name only, and the validation rejects the remaining forged UID. This
	// fails closed; nothing is stored under a forged identity.
	deny("certificate user claims another user's UID", human.c.Create(l.ctx, forgedRequest("esrc-forged-human-uid", &v1alpha1.Requester{Username: other, UID: "uid-" + other}), client.DryRunAll),
		apierrors.IsForbidden, forgedMsg)
	deny("cluster administrator claims another user's UID", admin.c.Create(l.ctx, forgedRequest("esrc-forged-admin-uid", &v1alpha1.Requester{Username: other, UID: "uid-" + other}), client.DryRunAll),
		apierrors.IsForbidden, forgedMsg)
	l.record("attribution", map[string]any{"requests": attribution})

	// Spec edits after creation: RBAC denies the recovery roles and the
	// controller; immutability denies the cluster administrator.
	target := stored("esrc-forged-sa")
	edited := func(edit func(*v1alpha1.EvidenceSigningRequest)) *v1alpha1.EvidenceSigningRequest {
		r := stored(target.Name)
		edit(r)
		return r
	}
	reasonPatch := client.RawPatch(types.MergePatchType, []byte(`{"spec":{"reason":"a different justification"}}`))
	for _, id := range []*credentialIdentity{recoverer, human, reader, ctl} {
		deny(id.key+" updates the reason", id.c.Update(l.ctx, edited(func(r *v1alpha1.EvidenceSigningRequest) { r.Spec.Reason = "a different justification" })), byRBAC, "cannot update")
		deny(id.key+" patches the reason", id.c.Patch(l.ctx, stored(target.Name), reasonPatch), byRBAC, "cannot patch")
	}
	for what, edit := range map[string]func(*v1alpha1.EvidenceSigningRequest){
		"reason":   func(r *v1alpha1.EvidenceSigningRequest) { r.Spec.Reason = "a different justification" },
		"run name": func(r *v1alpha1.EvidenceSigningRequest) { r.Spec.Run.Name = "esrc-other-run" },
		"run uid":  func(r *v1alpha1.EvidenceSigningRequest) { r.Spec.Run.UID = "11111111-2222-4333-8444-555555555555" },
		"requester": func(r *v1alpha1.EvidenceSigningRequest) {
			r.Spec.RequestedBy = &v1alpha1.Requester{Username: admin.user.Username}
		},
		"key confirmation": func(r *v1alpha1.EvidenceSigningRequest) {
			r.Spec.ExpectedKeyFingerprint = "sha256:" + strings.Repeat("1", 64)
		},
	} {
		deny("cluster administrator updates the "+what, admin.c.Update(l.ctx, edited(edit)), apierrors.IsInvalid, immutable)
	}
	deny("cluster administrator merge-patches the requester", admin.c.Patch(l.ctx, stored(target.Name),
		client.RawPatch(types.MergePatchType, []byte(`{"spec":{"requestedBy":{"username":"`+other+`","uid":null}}}`))), apierrors.IsInvalid, immutable)
	deny("cluster administrator JSON-patches the requester away", admin.c.Patch(l.ctx, stored(target.Name),
		client.RawPatch(types.JSONPatchType, []byte(`[{"op":"remove","path":"/spec/requestedBy"}]`))), apierrors.IsInvalid, immutable)
	deny("cluster administrator JSON-patches the run uid", admin.c.Patch(l.ctx, stored(target.Name),
		client.RawPatch(types.JSONPatchType, []byte(`[{"op":"replace","path":"/spec/run/uid","value":"11111111-2222-4333-8444-555555555555"}]`))), apierrors.IsInvalid, immutable)
	if got := stored(target.Name); got.Generation != 1 || toJSON(got.Spec) != toJSON(target.Spec) {
		t.Fatalf("a denied edit changed the request: generation %d, spec %s", got.Generation, toJSON(got.Spec))
	}

	// Status writes: only the configured controller.
	l.applyKinds("../../config/admission/evidence-signing-status-writer.yaml", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding")
	accepted := func(r *v1alpha1.EvidenceSigningRequest) *v1alpha1.EvidenceSigningRequest {
		r = r.DeepCopy()
		now := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
		run := r.Spec.Run
		r.Status = v1alpha1.EvidenceSigningRequestStatus{Phase: v1alpha1.SigningRequestPending, Reason: v1alpha1.RecoveryAccepted,
			RequestedBy: r.Spec.RequestedBy, Run: &run, AcceptedAt: &now,
			Conditions: []metav1.Condition{{Type: v1alpha1.ConditionSigningRequestComplete, Status: metav1.ConditionFalse, Reason: string(v1alpha1.RecoveryAccepted), Message: "accepted", LastTransitionTime: now}}}
		return r
	}
	statusPatch := func(r *v1alpha1.EvidenceSigningRequest) (client.Object, client.Patch) {
		return accepted(r), client.MergeFrom(r)
	}
	pending := stored("esrc-forged-sa-name")
	l.eventually("status-writer policy effective", func() (bool, string) {
		err := admin.c.Status().Update(l.ctx, accepted(pending), client.DryRunAll)
		return byWriterPolicy(err), errString(err)
	})
	for _, id := range []*credentialIdentity{admin, lookalike} {
		deny(id.key+" updates status", id.c.Status().Update(l.ctx, accepted(pending)), byWriterPolicy, writerMsg)
		obj, patch := statusPatch(pending)
		deny(id.key+" patches status", id.c.Status().Patch(l.ctx, obj, patch), byWriterPolicy, writerMsg)
	}
	for _, id := range []*credentialIdentity{recoverer, human, reader, ids["compliance admin"], ids["namespace assessment and exception roles"], ids["unbound ServiceAccount"]} {
		deny(id.key+" updates status", id.c.Status().Update(l.ctx, accepted(pending)), byRBAC, "cannot update")
		obj, patch := statusPatch(pending)
		deny(id.key+" patches status", id.c.Status().Patch(l.ctx, obj, patch), byRBAC, "cannot patch")
	}
	misattributed := accepted(pending)
	misattributed.Status.RequestedBy = &v1alpha1.Requester{Username: other}
	deny("controller misattributes a request", ctl.c.Status().Update(l.ctx, misattributed, client.DryRunAll), apierrors.IsInvalid, "status.requestedBy must be spec.requestedBy")
	if err := ctl.c.Status().Update(l.ctx, accepted(pending), client.DryRunAll); err != nil {
		t.Fatalf("the configured controller cannot write status: %v", err)
	}

	// The real recovery reconciler: as the lookalike it records nothing; as
	// the controller it records the terminal outcome with the
	// admission-recorded requester.
	reconcileAs := func(id *credentialIdentity) error {
		rec := &SigningRecoveryReconciler{Client: id.c, Reader: id.c, Runtime: AssessmentRuntime{ControllerNamespace: ns}}
		_, err := rec.Reconcile(l.ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(target)})
		return err
	}
	deny("lookalike runs the recovery reconciler", reconcileAs(lookalike), byWriterPolicy, writerMsg)
	if got := stored(target.Name); got.Status.Phase != "" {
		t.Fatalf("the lookalike recorded %s", toJSON(got.Status))
	}
	if err := reconcileAs(ctl); err != nil {
		t.Fatalf("the controller's recovery reconciler: %v", err)
	}
	ended := stored(target.Name)
	if st := ended.Status; st.Phase != v1alpha1.SigningRequestFailed || st.Reason != v1alpha1.RecoveryRunNotFound || st.RequestedBy == nil ||
		*st.RequestedBy != *requester(recoverer) || st.Run == nil || st.Run.UID != runUID || st.CompletedAt == nil {
		t.Fatalf("the controller recorded %s", toJSON(st))
	}
	rewrite := ended.DeepCopy()
	rewrite.Status.Reason = v1alpha1.RecoveryKeyMismatch
	for i := range rewrite.Status.Conditions {
		rewrite.Status.Conditions[i].Reason = string(v1alpha1.RecoveryKeyMismatch)
	}
	deny("controller rewrites the terminal outcome", ctl.c.Status().Update(l.ctx, rewrite), apierrors.IsInvalid, "a terminal outcome is never rewritten")
	l.record("controller", map[string]any{"writer": ctl.user.Username, "lookalike": lookalike.user.Username, "status": ended.Status})

	// Each role, with real requests. Mutations are dry runs against the
	// pending request; deletecollection also selects nothing.
	type outcome = string
	const (
		allowed   outcome = "allowed"
		rbac      outcome = "denied by RBAC"
		admission outcome = "denied by admission"
	)
	classify := func(err error) outcome {
		switch {
		case err == nil:
			return allowed
		case byRBAC(err):
			return rbac
		case apierrors.IsForbidden(err) && strings.Contains(err.Error(), "ValidatingAdmissionPolicy"):
			return admission
		}
		return "unexpected: " + err.Error()
	}
	verbs := []string{"create", "get", "list", "watch", "update", "patch", "delete", "deletecollection", "get status", "update status", "patch status"}
	probe := func(id *credentialIdentity, verb string) error {
		label := client.RawPatch(types.MergePatchType, []byte(`{"metadata":{"labels":{"change":"CHG-5300"}}}`))
		switch verb {
		case "create":
			return id.c.Create(l.ctx, newRequest("esrc-matrix"), client.DryRunAll)
		case "get":
			return id.c.Get(l.ctx, client.ObjectKeyFromObject(pending), &v1alpha1.EvidenceSigningRequest{})
		case "list":
			return id.c.List(l.ctx, &v1alpha1.EvidenceSigningRequestList{})
		case "watch":
			w, err := id.c.Watch(l.ctx, &v1alpha1.EvidenceSigningRequestList{})
			if err == nil {
				w.Stop()
			}
			return err
		case "update":
			r := stored(pending.Name)
			r.Labels = map[string]string{"change": "CHG-5300"}
			return id.c.Update(l.ctx, r, client.DryRunAll)
		case "patch":
			return id.c.Patch(l.ctx, stored(pending.Name), label, client.DryRunAll)
		case "delete":
			return id.c.Delete(l.ctx, stored(pending.Name), client.DryRunAll)
		case "deletecollection":
			return id.c.DeleteAllOf(l.ctx, &v1alpha1.EvidenceSigningRequest{}, client.MatchingLabels{"esrc-live/selects": "nothing"}, client.DryRunAll)
		case "get status":
			return id.c.SubResource("status").Get(l.ctx, stored(pending.Name), &v1alpha1.EvidenceSigningRequest{})
		case "update status":
			return id.c.Status().Update(l.ctx, accepted(stored(pending.Name)), client.DryRunAll)
		case "patch status":
			obj, patch := statusPatch(stored(pending.Name))
			return id.c.Status().Patch(l.ctx, obj, patch, client.DryRunAll)
		}
		t.Fatalf("unknown verb %s", verb)
		return nil
	}
	only := func(set map[string]outcome) map[string]outcome {
		m := map[string]outcome{}
		for _, v := range verbs {
			m[v] = rbac
		}
		for v, o := range set {
			m[v] = o
		}
		return m
	}
	recovererWants := only(map[string]outcome{"create": allowed, "get": allowed, "list": allowed, "watch": allowed, "get status": allowed})
	readerWants := only(map[string]outcome{"get": allowed, "list": allowed, "watch": allowed, "get status": allowed})
	controllerWants := only(map[string]outcome{"get": allowed, "list": allowed, "watch": allowed, "get status": allowed, "update status": allowed, "patch status": allowed})
	lookalikeWants := only(map[string]outcome{"get": allowed, "list": allowed, "watch": allowed, "get status": allowed, "update status": admission, "patch status": admission})
	adminWants := map[string]outcome{}
	for _, v := range verbs {
		adminWants[v] = allowed
	}
	adminWants["update status"], adminWants["patch status"] = admission, admission
	want := map[string]map[string]outcome{
		recoverer.key: recovererWants, human.key: recovererWants, reader.key: readerWants,
		ctl.key: controllerWants, lookalike.key: lookalikeWants, admin.key: adminWants,
	}
	for key := range ids {
		if want[key] == nil {
			want[key] = only(nil)
		}
	}
	matrix := map[string]map[string]outcome{}
	for key, wants := range want {
		id := ids[key]
		matrix[key] = map[string]outcome{}
		for _, verb := range verbs {
			err := probe(id, verb)
			got := classify(err)
			matrix[key][verb] = got
			if got != wants[verb] {
				t.Errorf("%s %s evidencesigningrequests: %s, want %s", key, verb, got, wants[verb])
			} else if err != nil {
				keep(key+" "+verb+" evidencesigningrequests", err)
			}
		}
	}

	// Neither recovery role reaches run status, signing Secrets or
	// destinations; the recoverer reads runs through the operator grant.
	runStatus := client.RawPatch(types.MergePatchType, []byte(`{"status":{"phase":"Completed"}}`))
	destPatch := client.RawPatch(types.MergePatchType, []byte(`{"spec":{"signing":{"mode":"Disabled"}}}`))
	for _, id := range []*credentialIdentity{recoverer, human, reader} {
		for what, err := range map[string]error{
			"patch assessmentruns/status":       id.c.Status().Patch(l.ctx, &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: runName}}, runStatus, client.DryRunAll),
			"update assessmentruns/status":      id.c.Status().Update(l.ctx, &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: runName, ResourceVersion: "1"}}, client.DryRunAll),
			"get secrets":                       id.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: "esrc-signing-key"}, &corev1.Secret{}),
			"list secrets":                      id.c.List(l.ctx, &corev1.SecretList{}, client.InNamespace(ns)),
			"create evidencedestinations":       id.c.Create(l.ctx, &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "esrc-denied"}}, client.DryRunAll),
			"patch evidencedestinations":        id.c.Patch(l.ctx, &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "esrc-destination"}}, destPatch, client.DryRunAll),
			"delete evidencedestinations":       id.c.Delete(l.ctx, &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "esrc-destination"}}, client.DryRunAll),
			"patch evidencedestinations/status": id.c.Status().Patch(l.ctx, &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "esrc-destination"}}, runStatus, client.DryRunAll),
		} {
			got := classify(err)
			matrix[id.key][what] = got
			if got != rbac {
				t.Errorf("%s %s: %s, want %s", id.key, what, got, rbac)
			} else {
				keep(id.key+" "+what, err)
			}
		}
		err := id.c.List(l.ctx, &v1alpha1.AssessmentRunList{})
		got, wantRuns := classify(err), allowed
		if id == reader {
			wantRuns = rbac
		}
		matrix[id.key]["list assessmentruns"] = got
		if got != wantRuns {
			t.Errorf("%s list assessmentruns: %s, want %s", id.key, got, wantRuns)
		} else if err != nil {
			keep(id.key+" list assessmentruns", err)
		}
	}
	l.record("authority", map[string]any{"credentials": "real (no impersonation)", "matrix": matrix})

	// Requests outlive any run and are removed only with a grant outside
	// the recovery roles (here: the cluster administrator).
	if err := admin.c.Delete(l.ctx, ended); err != nil {
		t.Fatalf("cluster administrator cannot delete a request: %v", err)
	}
	keys := make([]string, 0, len(denials))
	for k := range denials {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	l.record("denials", map[string]any{"order": keys, "responses": denials})
	raw, _ := json.Marshal(l.log)
	for _, s := range issued {
		if strings.Contains(string(raw), s) {
			t.Fatal("the evidence contains an issued credential")
		}
	}
}

// clientCertificate issues a client certificate for user in groups through
// the cluster's kube-apiserver-client signer and returns a client
// configuration that authenticates with it, and the PEM private key (kept in
// memory only, so the caller can check evidence for it).
func (l *live) clientCertificate(user string, groups ...string) (*rest.Config, string) {
	l.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		l.t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: user, Organization: groups}}, key)
	if err != nil {
		l.t.Fatal(err)
	}
	expiry := int32(3600)
	csr := &certificatesv1.CertificateSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: user}, Spec: certificatesv1.CertificateSigningRequestSpec{
		Request:           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
		SignerName:        certificatesv1.KubeAPIServerClientSignerName,
		ExpirationSeconds: &expiry,
		Usages:            []certificatesv1.KeyUsage{certificatesv1.UsageClientAuth},
	}}
	if err := l.c.Create(l.ctx, csr); err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { _ = l.c.Delete(context.Background(), csr) })
	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{Type: certificatesv1.CertificateApproved,
		Status: corev1.ConditionTrue, Reason: "KonstapelLiveAcceptance", Message: "disposable acceptance identity"})
	if err := l.c.SubResource("approval").Update(l.ctx, csr); err != nil {
		l.t.Fatal(err)
	}
	var cert []byte
	l.eventually("client certificate for "+user+" issued", func() (bool, string) {
		got := &certificatesv1.CertificateSigningRequest{}
		if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(csr), got); err != nil {
			return false, err.Error()
		}
		cert = got.Status.Certificate
		return len(cert) > 0, toJSON(got.Status.Conditions)
	})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		l.t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cfg := rest.AnonymousClientConfig(l.cfg)
	cfg.CertData, cfg.KeyData = cert, keyPEM
	return cfg, string(keyPEM)
}
