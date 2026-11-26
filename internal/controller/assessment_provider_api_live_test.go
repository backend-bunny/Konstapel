//go:build live

package controller

// Live AssessmentProvider API (add-external-assessment-providers 2.1),
// against the real API server with the generated CRD, the shipped
// registration roles, the status-writer admission policy, the shipped
// controller-identity ConfigMap and the generated controller RBAC:
//   - CRD validation rejects reserved (built-in) provider names,
//     cross-namespace trust, IP server names, tags as release digests and
//     unknown capabilities; a URL or credential field is an unknown field;
//     the provider name and compatibility are immutable even for an
//     administrator, while the release, trust, capabilities and newRequests
//     can change; status sent with a create is dropped;
//   - only the provider admin creates, changes and deletes registrations;
//     namespace users (a team ServiceAccount with the namespace assessment
//     and exception roles, and users bound to the built-in admin and edit
//     roles in their namespace), the compliance admin, the assessment
//     operator, the viewer, an unbound user and the controller cannot
//     (SubjectAccessReview and real requests); the built-in cluster
//     admin/edit/view roles do not aggregate any registration access;
//   - only the configured controller identity writes status, a cluster
//     administrator included; status naming another provider is invalid
//     even for the controller; an empty or missing ConfigMap fails closed.
// The API server's denial responses are kept as evidence. Run through
// scripts/targeting-live.sh (acceptance group "admission").

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func TestLiveAssessmentProviderAPI(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	const (
		ns, teamNS                                 = "konstapel-system", "apr-team"
		providerAdmin, viewer, complianceAdmin     = "apr-provider-admin", "apr-provider-viewer", "apr-compliance-admin"
		operator, nobody, teamAdmin, teamEditor    = "apr-assessment-operator", "apr-nobody", "apr-team-admin", "apr-team-editor"
		clusterEditor, clusterViewer, clusterAdmin = "apr-cluster-editor", "apr-cluster-viewer", "apr-cluster-namespace-admin"
		team                                       = "system:serviceaccount:apr-team:dev"
		digest1                                    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		digest2                                    = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	)
	for _, n := range []string{ns, teamNS} {
		_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
	}

	// The shipped controller identity (konstapel-assessment-admission, from
	// the run-scope policy file), created test-owned.
	params := shippedAdmissionConfigMap(t)
	controllerUser := "system:serviceaccount:" + params.Data["controllerServiceAccountNamespace"] + ":" + params.Data["controllerServiceAccountName"]
	if err := l.c.Create(l.ctx, params.DeepCopy()); err != nil {
		t.Fatalf("create the controller-identity ConfigMap (test-owned): %v", err)
	}
	t.Cleanup(func() { _ = l.c.Delete(context.Background(), params.DeepCopy()) })

	// Shipped roles under test-owned names; rules and labels unchanged.
	suffix := func(u *unstructured.Unstructured) { u.SetName(u.GetName() + "-apr-live") }
	for _, f := range []string{"assessment-providers", "compliance-admin", "compliance-viewer", "assessment-operator", "assessment-requester", "exception-editor"} {
		l.applyManifests("../../config/rbac/"+f+".yaml", suffix)
	}
	l.applyManifests("../../config/rbac/controller/role.yaml", suffix)
	shipped := func(name string) rbacv1.RoleRef {
		return rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name + "-apr-live"}
	}
	builtIn := func(name string) rbacv1.RoleRef {
		return rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name}
	}
	l.bind("apr-admin", providerAdmin, shipped("konstapel-assessment-provider-admin"), "")
	l.bind("apr-viewer", viewer, shipped("konstapel-assessment-provider-viewer"), "")
	l.bind("apr-compliance-admin", complianceAdmin, shipped("konstapel-compliance-admin"), "")
	l.bind("apr-compliance-viewer", complianceAdmin, shipped("konstapel-compliance-viewer"), "")
	l.bind("apr-operator", operator, shipped("konstapel-assessment-operator"), "")
	l.bind("apr-team-requester", team, shipped("konstapel-assessment-requester"), teamNS)
	l.bind("apr-team-exceptions", team, shipped("konstapel-exception-editor"), teamNS)
	l.bind("apr-team-admin", teamAdmin, builtIn("admin"), teamNS)
	l.bind("apr-team-editor", teamEditor, builtIn("edit"), teamNS)
	// Cluster-wide bindings of the built-in namespace roles: they would
	// reach registrations only through aggregation.
	l.bind("apr-cluster-editor", clusterEditor, builtIn("edit"), "")
	l.bind("apr-cluster-viewer", clusterViewer, builtIn("view"), "")
	l.bind("apr-cluster-namespace-admin", clusterAdmin, builtIn("admin"), "")
	l.bind("apr-controller", controllerUser, shipped("konstapel-controller"), "")

	authenticated := []string{"system:authenticated"}
	clients := map[string]client.Client{}
	for _, who := range []string{providerAdmin, viewer, complianceAdmin, operator, nobody, teamAdmin, teamEditor, clusterEditor, clusterViewer, clusterAdmin} {
		clients[who] = l.as(who, authenticated...)
	}
	clients[team] = l.as(team, "system:serviceaccounts", "system:serviceaccounts:"+teamNS, "system:authenticated")
	clients[controllerUser] = l.as(controllerUser, "system:serviceaccounts", "system:serviceaccounts:"+ns, "system:authenticated")
	adminC, ctlC := clients[providerAdmin], clients[controllerUser]

	registration := func(name string) *v1alpha1.AssessmentProvider {
		return &v1alpha1.AssessmentProvider{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.AssessmentProviderSpec{
			Provider: v1alpha1.ExpectedProvider{Name: "apr-reporting", ReleaseDigest: digest1},
			Endpoint: v1alpha1.ProviderEndpoint{
				Service:     v1alpha1.ProviderServiceReference{Namespace: "apr-provider", Name: "apr-reporting", Port: 8443},
				ServerName:  "apr-reporting.apr-provider.svc",
				ServerTrust: v1alpha1.CATrust{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: "apr-reporting-ca"}},
			},
			Compatibility: v1alpha1.ProviderCompatibility{Protocol: v1alpha1.ProviderProtocolV1, ContractVersion: 1, EvaluatorVersion: 1, PayloadVersion: 1},
			Capabilities:  []v1alpha1.AssessmentProviderCapability{v1alpha1.ProviderCapabilityCollect, v1alpha1.ProviderCapabilityEvaluate},
		}}
	}
	t.Cleanup(func() {
		var list v1alpha1.AssessmentProviderList
		_ = l.c.List(context.Background(), &list)
		for i := range list.Items {
			if strings.HasPrefix(list.Items[i].Name, "apr-") {
				_ = l.c.Delete(context.Background(), &list.Items[i])
			}
		}
	})
	denials := map[string]string{}
	deny := func(what string, err error, ok func(error) bool, contains string) {
		t.Helper()
		if err == nil || !ok(err) || !strings.Contains(err.Error(), contains) {
			t.Fatalf("%s: want a denial containing %q, got %v", what, contains, err)
		}
		denials[what] = err.Error()
	}

	// Validation against the API server: invalid references, reserved
	// names and unsupported fields, as the provider admin, dry run.
	l.eventually("provider admin can create registrations", func() (bool, string) {
		err := adminC.Create(l.ctx, registration("apr-probe"), client.DryRunAll)
		return err == nil, errString(err)
	})
	for name, c := range map[string]struct {
		edit func(*v1alpha1.AssessmentProvider)
		want string
	}{
		"built-in Kyverno name": {func(p *v1alpha1.AssessmentProvider) { p.Spec.Provider.Name = "konstapel-kyverno" }, "reserved for built-in providers"},
		"reserved prefix":       {func(p *v1alpha1.AssessmentProvider) { p.Spec.Provider.Name = "konstapel-trivy" }, "reserved for built-in providers"},
		"trust in another namespace": {func(p *v1alpha1.AssessmentProvider) { p.Spec.Endpoint.ServerTrust.Namespace = "apr-provider" },
			"references resolve in the controller namespace only"},
		"IP server name":      {func(p *v1alpha1.AssessmentProvider) { p.Spec.Endpoint.ServerName = "10.96.0.12" }, "serverName must be a DNS name"},
		"wildcard server":     {func(p *v1alpha1.AssessmentProvider) { p.Spec.Endpoint.ServerName = "*.apr-provider.svc" }, "spec.endpoint.serverName"},
		"service with a path": {func(p *v1alpha1.AssessmentProvider) { p.Spec.Endpoint.Service.Name = "apr/collect" }, "spec.endpoint.service.name"},
		"port zero":           {func(p *v1alpha1.AssessmentProvider) { p.Spec.Endpoint.Service.Port = 0 }, "spec.endpoint.service.port"},
		"tag as release":      {func(p *v1alpha1.AssessmentProvider) { p.Spec.Provider.ReleaseDigest = "v1.2.3" }, "spec.provider.releaseDigest"},
		"unknown protocol":    {func(p *v1alpha1.AssessmentProvider) { p.Spec.Compatibility.Protocol = "konstapel.provider.v2" }, "spec.compatibility.protocol"},
		"unknown capability": {func(p *v1alpha1.AssessmentProvider) {
			p.Spec.Capabilities = []v1alpha1.AssessmentProviderCapability{"Remediate"}
		}, "spec.capabilities"},
		"no capability": {func(p *v1alpha1.AssessmentProvider) { p.Spec.Capabilities = nil }, "spec.capabilities"},
	} {
		p := registration("apr-invalid")
		c.edit(p)
		deny("create with "+name, adminC.Create(l.ctx, p, client.DryRunAll), apierrors.IsInvalid, c.want)
	}
	for _, field := range [][]string{{"spec", "endpoint", "url"}, {"spec", "endpoint", "clientKey"}, {"spec", "image"}, {"spec", "credentials"}} {
		raw, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(registration("apr-unknown"))
		u := &unstructured.Unstructured{Object: raw}
		u.SetAPIVersion(v1alpha1.GroupVersion.String())
		u.SetKind("AssessmentProvider")
		_ = unstructured.SetNestedField(u.Object, "https://attacker.example", field...)
		deny("create with "+strings.Join(field, "."), adminC.Create(l.ctx, u, client.DryRunAll, client.FieldValidation("Strict")), func(error) bool { return true }, "unknown field")
	}

	// The valid registration: defaults applied, status sent with it dropped.
	created := registration("apr-reporting")
	created.Status = v1alpha1.AssessmentProviderStatus{ObservedGeneration: 9,
		Conditions: []metav1.Condition{{Type: "Available", Status: metav1.ConditionTrue, Reason: "Forged", Message: "forged", LastTransitionTime: metav1.Now()}}}
	if err := adminC.Create(l.ctx, created); err != nil {
		t.Fatal(err)
	}
	stored := &v1alpha1.AssessmentProvider{}
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(created), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Spec.NewRequests != v1alpha1.ProviderNewRequestsEnabled || stored.Spec.Endpoint.ServerTrust.Key != "ca.crt" {
		t.Fatalf("defaults not applied: %s", toJSON(stored.Spec))
	}
	if stored.Status.ObservedGeneration != 0 || len(stored.Status.Conditions) != 0 || stored.Status.Identity != nil {
		t.Fatalf("create stored status %s", toJSON(stored.Status))
	}
	l.record("registration", map[string]any{"spec": stored.Spec, "statusOnCreate": "dropped"})

	// Immutable identity and compatibility, even for a cluster
	// administrator; compatible changes are accepted from the provider admin.
	for name, edit := range map[string]func(*v1alpha1.AssessmentProvider){
		"provider name":     func(p *v1alpha1.AssessmentProvider) { p.Spec.Provider.Name = "apr-other" },
		"contract version":  func(p *v1alpha1.AssessmentProvider) { p.Spec.Compatibility.ContractVersion = 2 },
		"evaluator version": func(p *v1alpha1.AssessmentProvider) { p.Spec.Compatibility.EvaluatorVersion = 2 },
		"payload version":   func(p *v1alpha1.AssessmentProvider) { p.Spec.Compatibility.PayloadVersion = 2 },
	} {
		p := stored.DeepCopy()
		edit(p)
		deny("cluster administrator changes the "+name, l.c.Update(l.ctx, p, client.DryRunAll), apierrors.IsInvalid, "provider.name and compatibility are immutable")
	}
	changed := stored.DeepCopy()
	changed.Spec.Provider.ReleaseDigest = digest2
	changed.Spec.Endpoint.ServerTrust.Name = "apr-reporting-ca-2026"
	changed.Spec.Capabilities = append(changed.Spec.Capabilities, v1alpha1.ProviderCapabilityScan)
	changed.Spec.NewRequests = v1alpha1.ProviderNewRequestsDisabled
	if err := adminC.Update(l.ctx, changed); err != nil {
		t.Fatalf("provider admin cannot record a compatible upgrade, trust rotation and drain: %v", err)
	}
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(stored), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Generation != 2 {
		t.Fatalf("a configuration change left generation %d", stored.Generation)
	}

	// Authority, with real requests and SubjectAccessReview. Nobody but the
	// provider admin may register, change or remove a provider.
	for _, who := range []string{team, teamAdmin, teamEditor, clusterEditor, clusterViewer, clusterAdmin, complianceAdmin, operator, viewer, nobody, controllerUser} {
		c := clients[who]
		deny(who+" creates a registration", c.Create(l.ctx, registration("apr-denied"), client.DryRunAll), apierrors.IsForbidden, "forbidden")
		edit := stored.DeepCopy()
		edit.Spec.Endpoint.Service.Namespace = "apr-elsewhere"
		deny(who+" redirects the registration", c.Update(l.ctx, edit, client.DryRunAll), apierrors.IsForbidden, "forbidden")
		deny(who+" deletes the registration", c.Delete(l.ctx, stored.DeepCopy(), client.DryRunAll), apierrors.IsForbidden, "forbidden")
	}
	if err := clients[viewer].List(l.ctx, &v1alpha1.AssessmentProviderList{}); err != nil {
		t.Fatalf("viewer cannot list registrations: %v", err)
	}
	if err := ctlC.Get(l.ctx, client.ObjectKeyFromObject(stored), &v1alpha1.AssessmentProvider{}); err != nil {
		t.Fatalf("controller cannot read registrations: %v", err)
	}
	can := func(user string, groups []string, resource, sub, namespace, verb string) bool {
		sar := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{User: user, Groups: groups,
			ResourceAttributes: &authorizationv1.ResourceAttributes{Group: v1alpha1.GroupVersion.Group, Resource: resource, Subresource: sub, Namespace: namespace, Verb: verb}}}
		if resource == "secrets" || resource == "configmaps" {
			sar.Spec.ResourceAttributes.Group = ""
		}
		if err := l.c.Create(l.ctx, sar); err != nil {
			t.Fatal(err)
		}
		return sar.Status.Allowed
	}
	type probe struct{ verb, sub string }
	writes := []probe{{"create", ""}, {"update", ""}, {"patch", ""}, {"delete", ""}, {"deletecollection", ""}, {"update", "status"}, {"patch", "status"}}
	reads := []probe{{"get", ""}, {"list", ""}, {"watch", ""}, {"get", "status"}}
	matrix := map[string]map[probe]bool{}
	for _, who := range []string{team, teamAdmin, teamEditor, clusterEditor, clusterViewer, clusterAdmin, complianceAdmin, operator, nobody} {
		matrix[who] = map[probe]bool{}
		for _, p := range append(slices.Clone(writes), reads...) {
			matrix[who][p] = false
		}
	}
	matrix[providerAdmin] = map[probe]bool{{"create", ""}: true, {"update", ""}: true, {"patch", ""}: true, {"delete", ""}: true,
		{"deletecollection", ""}: false, {"update", "status"}: false, {"patch", "status"}: false,
		{"get", ""}: true, {"list", ""}: true, {"watch", ""}: true, {"get", "status"}: true}
	matrix[viewer] = map[probe]bool{{"get", ""}: true, {"list", ""}: true, {"watch", ""}: true, {"get", "status"}: true}
	for _, p := range writes {
		matrix[viewer][p] = false
	}
	matrix[controllerUser] = map[probe]bool{{"get", ""}: true, {"list", ""}: true, {"watch", ""}: true, {"get", "status"}: true,
		{"update", "status"}: true, {"patch", "status"}: true,
		{"create", ""}: false, {"update", ""}: false, {"patch", ""}: false, {"delete", ""}: false, {"deletecollection", ""}: false}
	groupsOf := func(who string) []string {
		switch who {
		case team:
			return []string{"system:serviceaccounts", "system:serviceaccounts:" + teamNS, "system:authenticated"}
		case controllerUser:
			return []string{"system:serviceaccounts", "system:serviceaccounts:" + ns, "system:authenticated"}
		}
		return authenticated
	}
	results := map[string]map[string]bool{}
	for user, probes := range matrix {
		results[user] = map[string]bool{}
		for p, want := range probes {
			got := can(user, groupsOf(user), "assessmentproviders", p.sub, "", p.verb)
			results[user][p.verb+" "+p.sub] = got
			if got != want {
				t.Errorf("%s %s assessmentproviders/%s = %v, want %v", user, p.verb, p.sub, got, want)
			}
		}
	}
	// Neither provider role reaches the controller namespace's Secrets or
	// ConfigMaps: registration grants no access to trust or credentials.
	for _, user := range []string{providerAdmin, viewer} {
		for _, c := range []struct{ resource, verb string }{{"secrets", "get"}, {"secrets", "list"}, {"configmaps", "get"}, {"configmaps", "list"}} {
			got := can(user, authenticated, c.resource, "", ns, c.verb)
			results[user][c.verb+" "+c.resource] = got
			if got {
				t.Errorf("%s may %s %s in %s", user, c.verb, c.resource, ns)
			}
		}
	}
	l.record("authority", map[string]any{"subjectAccessReviews": results})

	// Only the configured controller writes status.
	l.applyKinds("../../config/admission/assessment-provider-status-writer.yaml", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding")
	observed := func(p *v1alpha1.AssessmentProvider) *v1alpha1.AssessmentProvider {
		p = p.DeepCopy()
		now := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
		p.Status = v1alpha1.AssessmentProviderStatus{ObservedGeneration: p.Generation,
			Conditions: []metav1.Condition{{Type: "Available", Status: metav1.ConditionTrue, Reason: "Compatible", Message: "compatible", LastTransitionTime: now}},
			Identity: &v1alpha1.ObservedProviderIdentity{Name: p.Spec.Provider.Name, ReleaseDigest: p.Spec.Provider.ReleaseDigest,
				Protocol: v1alpha1.ProviderProtocolV1, ProtocolRevision: 1, ContractVersion: 1, EvaluatorVersion: 1, PayloadVersion: 1,
				Capabilities: p.Spec.Capabilities, ObservedAt: now}}
		return p
	}
	const writerMsg = "may write AssessmentProvider status"
	l.eventually("status-writer policy effective", func() (bool, string) {
		err := l.c.Status().Update(l.ctx, observed(stored), client.DryRunAll)
		return apierrors.IsForbidden(err) && strings.Contains(err.Error(), writerMsg), errString(err)
	})
	deny("cluster administrator writes status", l.c.Status().Update(l.ctx, observed(stored), client.DryRunAll), apierrors.IsForbidden, writerMsg)
	for _, who := range []string{providerAdmin, viewer, team, clusterAdmin, complianceAdmin} {
		deny(who+" writes status", clients[who].Status().Update(l.ctx, observed(stored), client.DryRunAll), apierrors.IsForbidden, "forbidden")
	}
	impostor := observed(stored)
	impostor.Status.Identity.Name = "apr-impostor"
	deny("controller records another provider's identity", ctlC.Status().Update(l.ctx, impostor), apierrors.IsInvalid,
		"status.identity must have the registration's provider name and compatibility")
	if err := ctlC.Status().Update(l.ctx, observed(stored)); err != nil {
		t.Fatalf("the configured controller cannot write status: %v", err)
	}
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(stored), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.Identity == nil || stored.Status.Identity.ReleaseDigest != digest2 || stored.Status.ObservedGeneration != stored.Generation {
		t.Fatalf("controller status not stored: %s", toJSON(stored.Status))
	}
	// Status written through the main resource is ignored.
	through := stored.DeepCopy()
	through.Status.Conditions[0].Reason = "Forged"
	if err := adminC.Update(l.ctx, through); err != nil {
		t.Fatal(err)
	}
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(stored), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.Conditions[0].Reason != "Compatible" {
		t.Fatalf("status written through the main resource was stored: %s", toJSON(stored.Status))
	}
	l.record("status", map[string]any{"identity": stored.Status.Identity, "writer": controllerUser})

	// Missing configuration fails closed.
	empty := params.DeepCopy()
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(empty), empty); err != nil {
		t.Fatal(err)
	}
	empty.Data["controllerServiceAccountName"] = ""
	if err := l.c.Update(l.ctx, empty); err != nil {
		t.Fatal(err)
	}
	l.eventually("empty controller identity denies the controller", func() (bool, string) {
		err := ctlC.Status().Update(l.ctx, observed(stored), client.DryRunAll)
		if apierrors.IsForbidden(err) && strings.Contains(err.Error(), "not configured") {
			denials["controller writes status with an empty identity"] = err.Error()
			return true, ""
		}
		return false, errString(err)
	})
	if err := l.c.Delete(l.ctx, empty); err != nil {
		t.Fatal(err)
	}
	const missingMsg = "no params found"
	byWriter := func(err error) bool {
		return strings.Contains(err.Error(), "konstapel-assessment-provider-status-writer")
	}
	l.eventually("missing controller identity denies the controller", func() (bool, string) {
		err := ctlC.Status().Update(l.ctx, observed(stored), client.DryRunAll)
		if err != nil && byWriter(err) && strings.Contains(err.Error(), missingMsg) {
			denials["controller writes status without the ConfigMap"] = err.Error()
			return true, ""
		}
		return false, errString(err)
	})
	deny("cluster administrator writes status without the ConfigMap", l.c.Status().Update(l.ctx, observed(stored), client.DryRunAll), byWriter, missingMsg)

	// The provider admin removes the registration.
	if err := adminC.Delete(l.ctx, stored.DeepCopy()); err != nil {
		t.Fatalf("provider admin cannot delete a registration: %v", err)
	}
	keys := make([]string, 0, len(denials))
	for k := range denials {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	l.record("denials", map[string]any{"order": keys, "responses": denials})
}
