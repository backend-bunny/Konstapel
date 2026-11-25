//go:build live

package controller

// Live EvidenceSigningRequest API (add-evidence-signing-recovery 1.1-1.4),
// against the real API server with the generated CRD, the shipped recovery
// roles, the requester and status-writer admission policies, the shipped
// controller-identity ConfigMap, and the generated controller RBAC:
//   - CRD validation rejects malformed run references, blank reasons and
//     malformed fingerprints, and the spec is immutable even for a cluster
//     administrator; status sent with a create is dropped;
//   - without the mutation, the validation alone denies a missing or forged
//     requester; with it, a forged requester is overwritten;
//   - only the recoverer creates requests; namespace roles, the compliance
//     admin, the assessment operator and the reader cannot, and neither
//     recovery role updates, deletes, writes status, reads Secrets, writes
//     run status or changes destinations (SubjectAccessReview and real
//     requests);
//   - only the configured controller identity writes status, a cluster
//     administrator included; an empty or missing ConfigMap fails closed;
//     even the controller cannot misattribute a request or rewrite a
//     terminal outcome.
// The API server's denial responses are kept as evidence. Run through
// scripts/targeting-live.sh (acceptance group "admission").

import (
	"context"
	"os"
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
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func TestLiveEvidenceSigningRequestAPI(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	const (
		ns, teamNS                       = "konstapel-system", "esr-team"
		recoverer, reader, admin, other  = "esr-recoverer", "esr-recovery-reader", "esr-compliance-admin", "esr-someone-else"
		operator, team                   = "esr-assessment-operator", "system:serviceaccount:esr-team:dev"
		runName, runUID, retainedRunNote = "esr-retained-run", "0b1c2d3e-4f50-4617-8899-aabbccddeeff", "admission never looks the run up"
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

	// Shipped roles under test-owned names; rules unchanged.
	suffix := func(u *unstructured.Unstructured) { u.SetName(u.GetName() + "-esr-live") }
	for _, f := range []string{"evidence-signing-recovery", "assessment-requester", "exception-editor", "compliance-admin", "assessment-operator"} {
		l.applyManifests("../../config/rbac/"+f+".yaml", suffix)
	}
	l.applyManifests("../../config/rbac/controller/role.yaml", suffix)
	cluster := func(name string) rbacv1.RoleRef {
		return rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name + "-esr-live"}
	}
	l.bind("esr-recoverer", recoverer, cluster("konstapel-evidence-signing-recoverer"), "")
	l.bind("esr-reader", reader, cluster("konstapel-evidence-signing-recovery-reader"), "")
	l.bind("esr-admin", admin, cluster("konstapel-compliance-admin"), "")
	l.bind("esr-operator", operator, cluster("konstapel-assessment-operator"), "")
	// A recoverer finds failed runs through the operator grant.
	l.bind("esr-recoverer-operator", recoverer, cluster("konstapel-assessment-operator"), "")
	l.bind("esr-team-requester", team, cluster("konstapel-assessment-requester"), teamNS)
	l.bind("esr-team-exceptions", team, cluster("konstapel-exception-editor"), teamNS)
	l.bind("esr-controller", controllerUser, cluster("konstapel-controller"), "")

	recC, readC := l.as(recoverer, "system:authenticated"), l.as(reader, "system:authenticated")
	ctlC := l.as(controllerUser, "system:serviceaccounts", "system:serviceaccounts:"+ns, "system:authenticated")
	newRequest := func(name string) *v1alpha1.EvidenceSigningRequest {
		return &v1alpha1.EvidenceSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.EvidenceSigningRequestSpec{
			Run: v1alpha1.ExactRunReference{Name: runName, UID: runUID}, Reason: "Signing key Secret restored after CHG-1234 (live acceptance)"}}
	}
	t.Cleanup(func() {
		var list v1alpha1.EvidenceSigningRequestList
		_ = l.c.List(context.Background(), &list)
		for i := range list.Items {
			if strings.HasPrefix(list.Items[i].Name, "esr-") {
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

	// 1.2, validation alone: a missing or forged requester fails closed even
	// when the mutation is absent.
	l.applyKinds("../../config/admission/evidence-signing-requester.yaml", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding")
	const forgedMsg = "spec.requestedBy must be the authenticated requester"
	l.eventually("requester validation effective", func() (bool, string) {
		err := recC.Create(l.ctx, newRequest("esr-probe"), client.DryRunAll)
		return apierrors.IsForbidden(err) && strings.Contains(err.Error(), forgedMsg), errString(err)
	})
	deny("missing requester without the mutation", recC.Create(l.ctx, newRequest("esr-unattributed"), client.DryRunAll), apierrors.IsForbidden, forgedMsg)
	forged := newRequest("esr-forged")
	forged.Spec.RequestedBy = &v1alpha1.Requester{Username: other, UID: "uid-" + other}
	deny("forged requester without the mutation", recC.Create(l.ctx, forged.DeepCopy(), client.DryRunAll), apierrors.IsForbidden, forgedMsg)
	wrongUID := newRequest("esr-wrong-uid")
	wrongUID.Spec.RequestedBy = &v1alpha1.Requester{Username: recoverer, UID: "uid-" + other}
	deny("requester with another uid", recC.Create(l.ctx, wrongUID, client.DryRunAll), apierrors.IsForbidden, forgedMsg)
	self := newRequest("esr-self")
	self.Spec.RequestedBy = &v1alpha1.Requester{Username: recoverer, UID: "uid-" + recoverer}
	if err := recC.Create(l.ctx, self, client.DryRunAll); err != nil {
		t.Fatalf("exact self-attribution denied: %v", err)
	}

	// With the mutation, a forged requester is overwritten.
	l.applyKinds("../../config/admission/evidence-signing-requester.yaml", "MutatingAdmissionPolicy", "MutatingAdmissionPolicyBinding")
	l.eventually("requester mutation effective", func() (bool, string) {
		probe := forged.DeepCopy()
		if err := recC.Create(l.ctx, probe, client.DryRunAll); err != nil {
			return false, err.Error()
		}
		return probe.Spec.RequestedBy != nil && probe.Spec.RequestedBy.Username == recoverer, toJSON(probe.Spec.RequestedBy)
	})
	created := forged.DeepCopy()
	created.Status = v1alpha1.EvidenceSigningRequestStatus{Phase: v1alpha1.SigningRequestSucceeded, Reason: v1alpha1.RecoveryRecovered}
	if err := recC.Create(l.ctx, created); err != nil {
		t.Fatal(err)
	}
	stored := &v1alpha1.EvidenceSigningRequest{}
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(created), stored); err != nil {
		t.Fatal(err)
	}
	if got := stored.Spec.RequestedBy; got == nil || got.Username != recoverer || got.UID != "uid-"+recoverer {
		t.Fatalf("forged requester stored as %+v", got)
	}
	if stored.Status.Phase != "" || stored.Status.Reason != "" || len(stored.OwnerReferences) != 0 {
		t.Fatalf("create stored status %s or owners %v", toJSON(stored.Status), stored.OwnerReferences)
	}
	l.record("attribution", map[string]any{"requestedBy": stored.Spec.RequestedBy, "forged": other, "statusOnCreate": "dropped", "runLookup": retainedRunNote})

	// 1.1: CRD validation and immutability against the API server.
	for name, edit := range map[string]func(*v1alpha1.EvidenceSigningRequest){
		"blank reason":         func(r *v1alpha1.EvidenceSigningRequest) { r.Spec.Reason = " \t " },
		"uppercase run name":   func(r *v1alpha1.EvidenceSigningRequest) { r.Spec.Run.Name = "Retained" },
		"run uid not a UUID":   func(r *v1alpha1.EvidenceSigningRequest) { r.Spec.Run.UID = "run-uid" },
		"malformed key digest": func(r *v1alpha1.EvidenceSigningRequest) { r.Spec.ExpectedKeyFingerprint = "sha256:XYZ" },
	} {
		r := newRequest("esr-invalid")
		edit(r)
		deny("create with "+name, recC.Create(l.ctx, r, client.DryRunAll), apierrors.IsInvalid, "")
	}
	u := &unstructured.Unstructured{}
	raw, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(newRequest("esr-unknown"))
	u.Object = raw
	u.SetAPIVersion(v1alpha1.GroupVersion.String())
	u.SetKind("EvidenceSigningRequest")
	_ = unstructured.SetNestedField(u.Object, "other-key", "spec", "secretName")
	deny("create with an unsupported field", recC.Create(l.ctx, u, client.DryRunAll, client.FieldValidation("Strict")), func(error) bool { return true }, "unknown field")
	for name, edit := range map[string]func(*v1alpha1.EvidenceSigningRequest){
		"reason":    func(r *v1alpha1.EvidenceSigningRequest) { r.Spec.Reason = "a different justification" },
		"run uid":   func(r *v1alpha1.EvidenceSigningRequest) { r.Spec.Run.UID = "11111111-2222-4333-8444-555555555555" },
		"requester": func(r *v1alpha1.EvidenceSigningRequest) { r.Spec.RequestedBy = &v1alpha1.Requester{Username: other} },
		"key confirmed": func(r *v1alpha1.EvidenceSigningRequest) {
			r.Spec.ExpectedKeyFingerprint = "sha256:" + strings.Repeat("1", 64)
		},
	} {
		r := stored.DeepCopy()
		edit(r)
		deny("administrator edits the "+name, l.c.Update(l.ctx, r), apierrors.IsInvalid, "spec is immutable")
	}

	// 1.3: authority, with real requests and SubjectAccessReview.
	for _, who := range []string{team, admin, operator, reader} {
		c := l.as(who, "system:authenticated")
		deny(who+" creates a request", c.Create(l.ctx, newRequest("esr-denied"), client.DryRunAll), apierrors.IsForbidden, "forbidden")
	}
	edit := stored.DeepCopy()
	edit.Labels = map[string]string{"change": "CHG-1234"}
	deny("recoverer updates a request", recC.Update(l.ctx, edit), apierrors.IsForbidden, "forbidden")
	deny("recoverer deletes a request", recC.Delete(l.ctx, stored.DeepCopy()), apierrors.IsForbidden, "forbidden")
	deny("reader deletes a request", readC.Delete(l.ctx, stored.DeepCopy()), apierrors.IsForbidden, "forbidden")
	deny("recoverer reads a Secret", recC.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: "signing-key"}, &corev1.Secret{}), apierrors.IsForbidden, "forbidden")
	if err := readC.List(l.ctx, &v1alpha1.EvidenceSigningRequestList{}); err != nil {
		t.Fatalf("reader cannot list requests: %v", err)
	}
	can := func(user, group, resource, sub, namespace, verb string) bool {
		sar := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{User: user, Groups: []string{"system:authenticated"},
			ResourceAttributes: &authorizationv1.ResourceAttributes{Group: group, Resource: resource, Subresource: sub, Namespace: namespace, Verb: verb}}}
		if err := l.c.Create(l.ctx, sar); err != nil {
			t.Fatal(err)
		}
		return sar.Status.Allowed
	}
	type probe struct{ verb, sub string }
	matrix := map[string]map[probe]bool{
		recoverer: {{"create", ""}: true, {"get", ""}: true, {"list", ""}: true, {"watch", ""}: true, {"update", ""}: false, {"patch", ""}: false,
			{"delete", ""}: false, {"deletecollection", ""}: false, {"get", "status"}: true, {"update", "status"}: false, {"patch", "status"}: false},
		reader: {{"create", ""}: false, {"get", ""}: true, {"list", ""}: true, {"watch", ""}: true, {"update", ""}: false, {"delete", ""}: false,
			{"get", "status"}: true, {"update", "status"}: false, {"patch", "status"}: false},
		team:     {{"create", ""}: false, {"get", ""}: false, {"list", ""}: false},
		admin:    {{"create", ""}: false, {"get", ""}: false, {"list", ""}: false, {"delete", ""}: false},
		operator: {{"create", ""}: false, {"get", ""}: false, {"list", ""}: false},
		controllerUser: {{"get", ""}: true, {"list", ""}: true, {"watch", ""}: true, {"create", ""}: false, {"update", ""}: false, {"delete", ""}: false,
			{"update", "status"}: true, {"patch", "status"}: true},
	}
	results := map[string]map[string]bool{}
	for user, probes := range matrix {
		results[user] = map[string]bool{}
		for p, want := range probes {
			got := can(user, v1alpha1.GroupVersion.Group, "evidencesigningrequests", p.sub, "", p.verb)
			results[user][p.verb+" "+p.sub] = got
			if got != want {
				t.Errorf("%s %s evidencesigningrequests/%s = %v, want %v", user, p.verb, p.sub, got, want)
			}
		}
	}
	// Neither recovery role reaches run status, signing Secrets or
	// destinations (the recoverer also holds the operator's run reads).
	for _, user := range []string{recoverer, reader} {
		for _, c := range []struct{ group, resource, sub, namespace, verb string }{
			{v1alpha1.GroupVersion.Group, "assessmentruns", "status", "", "update"},
			{v1alpha1.GroupVersion.Group, "assessmentruns", "status", "", "patch"},
			{"", "secrets", "", ns, "get"},
			{"", "secrets", "", ns, "list"},
			{v1alpha1.GroupVersion.Group, "evidencedestinations", "", "", "create"},
			{v1alpha1.GroupVersion.Group, "evidencedestinations", "", "", "update"},
			{v1alpha1.GroupVersion.Group, "evidencedestinations", "", "", "patch"},
			{v1alpha1.GroupVersion.Group, "evidencedestinations", "", "", "delete"},
			{v1alpha1.GroupVersion.Group, "evidencedestinations", "status", "", "update"},
		} {
			got := can(user, c.group, c.resource, c.sub, c.namespace, c.verb)
			results[user][c.verb+" "+c.resource+"/"+c.sub] = got
			if got {
				t.Errorf("%s may %s %s/%s", user, c.verb, c.resource, c.sub)
			}
		}
	}
	l.record("authority", map[string]any{"subjectAccessReviews": results})

	// 1.2: only the configured controller writes status.
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
	const writerMsg = "may write EvidenceSigningRequest status"
	l.eventually("status-writer policy effective", func() (bool, string) {
		err := l.c.Status().Update(l.ctx, accepted(stored), client.DryRunAll)
		return apierrors.IsForbidden(err) && strings.Contains(err.Error(), writerMsg), errString(err)
	})
	deny("cluster administrator writes status", l.c.Status().Update(l.ctx, accepted(stored), client.DryRunAll), apierrors.IsForbidden, writerMsg)
	deny("recoverer writes status", recC.Status().Update(l.ctx, accepted(stored)), apierrors.IsForbidden, "forbidden")
	deny("reader writes status", readC.Status().Update(l.ctx, accepted(stored)), apierrors.IsForbidden, "forbidden")
	misattributed := accepted(stored)
	misattributed.Status.RequestedBy = &v1alpha1.Requester{Username: other}
	deny("controller misattributes a request", ctlC.Status().Update(l.ctx, misattributed), apierrors.IsInvalid, "status.requestedBy must be spec.requestedBy")
	if err := ctlC.Status().Update(l.ctx, accepted(stored)); err != nil {
		t.Fatalf("the configured controller cannot write status: %v", err)
	}
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(stored), stored); err != nil {
		t.Fatal(err)
	}
	// A terminal outcome is final, for the controller too.
	terminal := stored.DeepCopy()
	done := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	terminal.Status.Phase, terminal.Status.Reason, terminal.Status.Message, terminal.Status.CompletedAt = v1alpha1.SigningRequestFailed, v1alpha1.RecoveryRunNotFound, "run "+runName+" not found", &done
	terminal.Status.Conditions = []metav1.Condition{{Type: v1alpha1.ConditionSigningRequestComplete, Status: metav1.ConditionTrue, Reason: string(v1alpha1.RecoveryRunNotFound), Message: "run not found", LastTransitionTime: done}}
	if err := ctlC.Status().Update(l.ctx, terminal); err != nil {
		t.Fatalf("controller cannot record a terminal outcome: %v", err)
	}
	rewrite := terminal.DeepCopy()
	rewrite.Status.Phase, rewrite.Status.Reason = v1alpha1.SigningRequestFailed, v1alpha1.RecoveryKeyMismatch
	rewrite.Status.Conditions[0].Reason = string(v1alpha1.RecoveryKeyMismatch)
	deny("controller rewrites a terminal outcome", ctlC.Status().Update(l.ctx, rewrite), apierrors.IsInvalid, "a terminal outcome is never rewritten")
	reopen := terminal.DeepCopy()
	reopen.Status.Phase, reopen.Status.Reason, reopen.Status.CompletedAt = v1alpha1.SigningRequestRunning, v1alpha1.RecoverySigning, nil
	reopen.Status.Conditions = []metav1.Condition{{Type: v1alpha1.ConditionSigningRequestComplete, Status: metav1.ConditionFalse, Reason: string(v1alpha1.RecoverySigning), Message: "retrying", LastTransitionTime: done}}
	deny("controller reopens a terminal outcome", ctlC.Status().Update(l.ctx, reopen), apierrors.IsInvalid, "a terminal outcome is never rewritten")
	l.record("status", map[string]any{"terminal": terminal.Status.Reason, "writer": controllerUser})

	// Missing configuration fails closed. A second, pending request.
	second := newRequest("esr-pending")
	if err := recC.Create(l.ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := ctlC.Status().Update(l.ctx, accepted(second)); err != nil {
		t.Fatal(err)
	}
	_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(second), second)
	running := second.DeepCopy()
	started := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	running.Status.Phase, running.Status.Reason, running.Status.StartedAt = v1alpha1.SigningRequestRunning, v1alpha1.RecoverySigning, &started
	running.Status.Conditions[0].Reason = string(v1alpha1.RecoverySigning)
	if err := ctlC.Status().Update(l.ctx, running.DeepCopy(), client.DryRunAll); err != nil {
		t.Fatalf("controller progress denied: %v", err)
	}
	empty := params.DeepCopy()
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(empty), empty); err != nil {
		t.Fatal(err)
	}
	empty.Data["controllerServiceAccountName"] = ""
	if err := l.c.Update(l.ctx, empty); err != nil {
		t.Fatal(err)
	}
	l.eventually("empty controller identity denies the controller", func() (bool, string) {
		err := ctlC.Status().Update(l.ctx, running.DeepCopy(), client.DryRunAll)
		if apierrors.IsForbidden(err) && strings.Contains(err.Error(), "not configured") {
			denials["controller writes status with an empty identity"] = err.Error()
			return true, ""
		}
		return false, errString(err)
	})
	if err := l.c.Delete(l.ctx, empty); err != nil {
		t.Fatal(err)
	}
	// The binding's parameterNotFoundAction Deny is a configuration error,
	// which the API server reports as Invalid naming the policy.
	const missingMsg = "no params found"
	byWriter := func(err error) bool { return strings.Contains(err.Error(), "konstapel-evidence-signing-status-writer") }
	l.eventually("missing controller identity denies the controller", func() (bool, string) {
		err := ctlC.Status().Update(l.ctx, running.DeepCopy(), client.DryRunAll)
		if err != nil && byWriter(err) && strings.Contains(err.Error(), missingMsg) {
			denials["controller writes status without the ConfigMap"] = err.Error()
			return true, ""
		}
		return false, errString(err)
	})
	deny("cluster administrator writes status without the ConfigMap", l.c.Status().Update(l.ctx, running.DeepCopy(), client.DryRunAll), byWriter, missingMsg)

	// Requests outlive any run and are removed only with a grant outside the
	// recovery roles (here: the cluster administrator).
	if err := l.c.Delete(l.ctx, stored.DeepCopy()); err != nil {
		t.Fatalf("cluster administrator cannot delete a request: %v", err)
	}
	keys := make([]string, 0, len(denials))
	for k := range denials {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	l.record("denials", map[string]any{"order": keys, "responses": denials})
}

func errString(err error) string {
	if err == nil {
		return "allowed"
	}
	return err.Error()
}

// shippedAdmissionConfigMap returns the controller-identity ConfigMap shipped
// with the run-scope admission policy.
func shippedAdmissionConfigMap(t *testing.T) *corev1.ConfigMap {
	t.Helper()
	raw, err := os.ReadFile("../../config/admission/assessment-run-scope.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, doc := range strings.Split(string(raw), "\n---") {
		var meta struct{ Kind string }
		if yaml.Unmarshal([]byte(doc), &meta) != nil || meta.Kind != "ConfigMap" {
			continue
		}
		cm := &corev1.ConfigMap{}
		if err := yaml.UnmarshalStrict([]byte(doc), cm); err != nil {
			t.Fatal(err)
		}
		return cm
	}
	t.Fatal("no ConfigMap in config/admission/assessment-run-scope.yaml")
	return nil
}

// applyKinds creates the objects of the given kinds from a multi-document
// YAML file, test-owned like applyManifests, so a test can install one
// policy of a file before another.
func (l *live) applyKinds(path string, kinds ...string) {
	l.t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		l.t.Fatal(err)
	}
	applied := 0
	for _, doc := range strings.Split(string(raw), "\n---") {
		u := &unstructured.Unstructured{}
		if err := yaml.Unmarshal([]byte(doc), &u.Object); err != nil || len(u.Object) == 0 || !slices.Contains(kinds, u.GetKind()) {
			continue
		}
		if err := l.c.Create(l.ctx, u); err != nil {
			l.t.Fatalf("apply %s %s: %v", u.GetKind(), u.GetName(), err)
		}
		applied++
		l.t.Cleanup(func() { _ = l.c.Delete(context.Background(), u) })
	}
	if applied != len(kinds) {
		l.t.Fatalf("%s: applied %d objects of kinds %v", path, applied, kinds)
	}
}
