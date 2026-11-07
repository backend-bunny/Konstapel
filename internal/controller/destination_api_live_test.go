//go:build live

package controller

// Live destination API (add-s3-evidence-publishing 9.2), against the real
// API server with the generated CRD, RBAC, and admission resources:
//   - CRD validation rejects Orphan without a reason and location changes;
//   - only platform administrators manage destinations;
//   - the orphan admission policy records the real requester and replaces a
//     forged actor;
//   - the manager runs as an identity bound to the generated controller
//     RBAC, first without permission to create the inventory: the handoff
//     is accepted and fenced but the inventory is pending, a run already
//     pending deletion and the destination keep their finalizers;
//   - after a restart with the permission granted, the inventory is saved,
//     every run pinned to the destination (including one started
//     concurrently with the deletion) is handed off, and the destination is
//     finalized;
//   - engine policies and exceptions are not changed by any of it.
// Run through scripts/targeting-live.sh.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// applyManifests creates every object in a multi-document YAML file after
// edit, and deletes them when the test ends. It fails if one exists.
func (l *live) applyManifests(path string, edit func(*unstructured.Unstructured)) {
	raw, err := os.ReadFile(path)
	if err != nil {
		l.t.Fatal(err)
	}
	for _, doc := range strings.Split(string(raw), "\n---") {
		u := &unstructured.Unstructured{}
		if err := yaml.Unmarshal([]byte(doc), &u.Object); err != nil || len(u.Object) == 0 {
			continue
		}
		if edit != nil {
			edit(u)
		}
		// Test-owned only: an existing object (for example another test's
		// ClusterRole of the same name) is never adopted or deleted.
		if err := l.c.Create(l.ctx, u); err != nil {
			l.t.Fatalf("apply %s %s: %v", u.GetKind(), u.GetName(), err)
		}
		l.t.Cleanup(func() { _ = l.c.Delete(l.ctx, u) })
	}
}

// startManagerAs runs the manager authenticated as user.
func (l *live) startManagerAs(user string) (stop func()) {
	cfg := rest.CopyConfig(l.cfg)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: user, UID: "uid-" + user, Groups: []string{"system:authenticated"}}
	saved := l.cfg
	l.cfg = cfg
	defer func() { l.cfg = saved }()
	return l.startManager()
}

func (l *live) bind(name, user string, role rbacv1.RoleRef, namespace string) {
	subjects := []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: user}}
	var o client.Object
	if namespace == "" {
		o = &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}, Subjects: subjects, RoleRef: role}
	} else {
		o = &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Subjects: subjects, RoleRef: role}
	}
	if err := l.c.Create(l.ctx, o); err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { _ = l.c.Delete(l.ctx, o) })
}

func TestLiveDestinationAPI(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	ns := "konstapel-system"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	const controllerUser, admin = "konstapel-live-controller", "platform-admin"

	// Generated RBAC: the controller's namespaced Role without permission
	// to create ConfigMaps (the inventory), and the platform admin role.
	l.applyManifests("../../config/rbac/controller/role.yaml", func(u *unstructured.Unstructured) {
		if u.GetKind() != "Role" {
			return
		}
		rules, _, _ := unstructured.NestedSlice(u.Object, "rules")
		for _, r := range rules {
			m := r.(map[string]any)
			if res, _ := m["resources"].([]any); len(res) == 1 && res[0] == "configmaps" {
				m["verbs"] = []any{"get", "list"}
			}
		}
		_ = unstructured.SetNestedSlice(u.Object, rules, "rules")
	})
	l.applyManifests("../../config/rbac/compliance-admin.yaml", nil)
	l.applyManifests("../../config/admission/evidence-destination-orphan.yaml", nil)
	l.bind("konstapel-live-controller", controllerUser, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-controller"}, "")
	l.bind("konstapel-live-controller", controllerUser, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "konstapel-controller"}, ns)
	l.bind("konstapel-live-admin", admin, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-compliance-admin"}, "")
	adminC, devC := l.as(admin, "system:authenticated"), l.as("dev", "system:authenticated")

	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "da-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	if err := l.c.Create(l.ctx, secret); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, secret) })
	newDest := func(name string) *v1alpha1.EvidenceDestination {
		return &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{
			Endpoint: l.s3Endpoint, Bucket: pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/" + name, DevelopmentFixture: true,
			CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: secret.Name}}}}}
	}

	// Validation and authorization at the API server.
	if err := devC.Create(l.ctx, newDest("da-dev")); !apierrors.IsForbidden(err) {
		t.Fatalf("non-admin created a destination: %v", err)
	}
	noReason := newDest("da-noreason")
	noReason.Spec.DeletionPolicy = v1alpha1.DeletionOrphan
	if err := adminC.Create(l.ctx, noReason); !apierrors.IsInvalid(err) {
		t.Fatalf("Orphan without a reason accepted: %v", err)
	}
	ed := newDest("da-dest")
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
	moved := ed.DeepCopy()
	moved.Spec.S3.Prefix = "konstapel-test/elsewhere"
	if err := adminC.Update(l.ctx, moved); !apierrors.IsInvalid(err) {
		t.Fatalf("location change accepted: %v", err)
	}
	l.record("validation", map[string]any{"devCreate": "Forbidden", "orphanWithoutReason": "Invalid", "locationChange": "Invalid"})

	l.setNamespace("da-prod", "da-production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "da-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("da-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "da-production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "20s", DestinationRef: &v1alpha1.DestinationReference{Name: ed.Name, UID: string(ed.UID)}}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "da-prod"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	for _, o := range []client.Object{p, pod, b} {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	var runs []string
	t.Cleanup(func() {
		for _, r := range runs {
			got := &v1alpha1.AssessmentRun{}
			if l.c.Get(l.ctx, client.ObjectKey{Name: r}, got) == nil {
				got.Finalizers = nil
				_ = l.c.Update(l.ctx, got)
				_ = l.c.Delete(l.ctx, got)
			}
		}
		_ = l.c.Delete(l.ctx, pod)
		_ = l.c.Delete(l.ctx, b)
		_ = l.c.Delete(l.ctx, p)
		l.eventually("destination API test policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
		var cms corev1.ConfigMapList
		_ = l.c.List(l.ctx, &cms, client.InNamespace(ns), client.MatchingLabels{LabelOrphanHandoff: string(ed.UID)})
		for i := range cms.Items {
			_ = l.c.Delete(l.ctx, &cms.Items[i])
		}
	})
	controllerC := l.as(controllerUser, "system:authenticated")
	ConfigureAssessments(AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: 5 * time.Minute, Workers: 2,
		ControllerNamespace: ns, Destinations: &DestinationPublishers{Reader: controllerC, Namespace: ns}})
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	stop := l.startManagerAs(controllerUser)
	defer func() { stop() }()

	get := func(name string) *v1alpha1.AssessmentRun {
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, r); err != nil {
			return nil
		}
		return r
	}
	l.eventually("destination ready under the controller's RBAC", func() (bool, string) {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
		return meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionDestinationReady), toJSON(got.Status)
	})
	var retained string
	l.eventually("scheduled run published", func() (bool, string) {
		s := l.binding(b.Name).Status.Assessment
		if s != nil && s.LatestRun != nil {
			retained = s.LatestRun.Name
		}
		r := get(retained)
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted && r.Status.Publication != nil, toJSON(s)
	})
	runs = append(runs, retained)
	policies := l.managedPolicies()
	exceptions := func() map[string]string {
		var list v1alpha1.ComplianceExceptionList
		if err := l.c.List(l.ctx, &list); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, e := range list.Items {
			out[e.Namespace+"/"+e.Name] = e.ResourceVersion
		}
		return out
	}
	exceptionsBefore := exceptions()

	// The retained run's record is deleted: retention keeps it pending.
	if err := l.c.Delete(l.ctx, get(retained)); err != nil {
		t.Fatal(err)
	}
	if r := get(retained); r == nil || r.DeletionTimestamp.IsZero() {
		t.Fatal("setup: retained run not pending deletion")
	}

	// A forged actor is replaced by the authenticated requester.
	got := &v1alpha1.EvidenceDestination{}
	_ = adminC.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
	got.Spec.DeletionPolicy = v1alpha1.DeletionOrphan
	got.Spec.Orphan = &v1alpha1.OrphanRequest{Reason: "bucket handed to the archive team", Actor: "someone-else"}
	if err := adminC.Update(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
	if got.Spec.Orphan == nil || got.Spec.Orphan.Actor != admin {
		t.Fatalf("forged actor stored: %+v", got.Spec.Orphan)
	}
	l.record("orphan-actor", map[string]any{"submitted": "someone-else", "stored": got.Spec.Orphan.Actor})

	// A manual run is started concurrently with the deletion: it is either
	// refused or pinned and then handed off — never left owning storage.
	concurrent := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "da-audit-concurrent"},
		Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}, Scope: v1alpha1.RunScopeBinding}}
	var wg sync.WaitGroup
	var createErr, deleteErr error
	wg.Add(2)
	go func() { defer wg.Done(); createErr = l.c.Create(l.ctx, concurrent) }()
	go func() { defer wg.Done(); deleteErr = adminC.Delete(l.ctx, got) }()
	wg.Wait()
	if err := errors.Join(createErr, deleteErr); err != nil {
		t.Fatal(err)
	}
	runs = append(runs, concurrent.Name)

	// Without permission to create the inventory: accepted and fenced, but
	// pending; the destination and the retained run keep their finalizers.
	l.eventually("inventory pending without permission", func() (bool, string) {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
		c := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionDestinationRetiring)
		return got.Status.OrphanIntent != nil && got.Status.OrphanHandoff != nil && got.Status.OrphanHandoff.Inventory == nil &&
			c != nil && c.Reason == "OrphanInventoryPending" && strings.Contains(c.Message, "forbidden"), toJSON(got.Status)
	})
	time.Sleep(10 * time.Second)
	_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
	if !controllerutil.ContainsFinalizer(got, DestinationFinalizer) || got.Status.OrphanIntent.Actor != admin {
		t.Fatalf("destination released or misattributed without an inventory: %s", toJSON(got))
	}
	if r := get(retained); r == nil || !controllerutil.ContainsFinalizer(r, RetentionFinalizer) ||
		r.Status.Publication.Phase != v1alpha1.PublicationPhase(publication.PhaseCommitted) || r.Status.Destination.OrphanedAt != nil {
		t.Fatalf("retained run released before the inventory: %s", toJSON(r))
	}
	l.record("inventory-forbidden", map[string]any{"destination": "held", "retainedRun": "held"})

	// Restart with the permission granted.
	stop()
	role := &rbacv1.Role{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: "konstapel-controller"}, role); err != nil {
		t.Fatal(err)
	}
	for i := range role.Rules {
		if len(role.Rules[i].Resources) == 1 && role.Rules[i].Resources[0] == "configmaps" {
			role.Rules[i].Verbs = []string{"create", "get", "list"}
		}
	}
	if err := l.c.Update(l.ctx, role); err != nil {
		t.Fatal(err)
	}
	stop = l.startManagerAs(controllerUser)
	l.eventually("destination finalized after the inventory was saved", func() (bool, string) {
		err := l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), &v1alpha1.EvidenceDestination{})
		return apierrors.IsNotFound(err), fmt.Sprint(err)
	})
	header := &corev1.ConfigMap{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: inventoryName(string(ed.UID), -1)}, header); err != nil {
		t.Fatal(err)
	}
	chunk := &corev1.ConfigMap{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: inventoryName(string(ed.UID), 0)}, chunk); err != nil {
		t.Fatal(err)
	}
	if h := header.Data[inventoryKey]; !strings.Contains(h, `"actor": "`+admin+`"`) {
		t.Fatalf("inventory header: %s", h)
	}
	if c := chunk.Data[inventoryKey]; !strings.Contains(c, retained) || !strings.Contains(c, `"pendingDeletion":true`) {
		t.Fatalf("retained run pending deletion missing from the inventory: %s", c)
	}
	if get(retained) != nil {
		t.Fatal("run pending deletion not released after the inventory")
	}
	r := get(concurrent.Name)
	switch {
	case r == nil:
		t.Fatal("concurrent run vanished")
	case r.Status.Destination == nil:
		// Refused or not admitted (scheduling is disabled while the selected
		// destination retires): it owns nothing and published nowhere.
		if r.Labels[LabelRunDestination] != "" || r.Status.Publication != nil || r.Status.Phase == v1alpha1.RunCompleted {
			t.Fatalf("unpinned concurrent run: %s", toJSON(r))
		}
	case r.Status.Destination.OrphanedAt == nil || !strings.Contains(chunk.Data[inventoryKey], string(r.UID)):
		t.Fatalf("concurrent run pinned but not handed off: %s", toJSON(r.Status))
	}
	if after := l.managedPolicies(); toJSON(after) != toJSON(policies) {
		t.Fatalf("handoff changed engine policies:\nbefore %v\nafter  %v", policies, after)
	}
	if after := exceptions(); toJSON(after) != toJSON(exceptionsBefore) {
		t.Fatalf("handoff changed exceptions:\nbefore %v\nafter  %v", exceptionsBefore, after)
	}
	l.record("handoff-after-restart", map[string]any{"concurrentPinned": r.Status.Destination != nil, "concurrentPhase": r.Status.Phase, "policiesUnchanged": len(policies)})
}
