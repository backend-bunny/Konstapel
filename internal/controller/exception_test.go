package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/exception"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const (
	revA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	revB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var exT0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func acceptedException(t *testing.T, rev int64, actor string, contributionRevs ...string) *v1alpha1.ComplianceException {
	t.Helper()
	el := &targeting.Eligibility{Namespace: targeting.NamespaceRef{Name: "team-a", UID: "ns-a-1"}, Policy: pol,
		Effective: v1alpha1.ExceptionsSelfService, MaxLifetime: &targeting.Duration{Duration: 720 * time.Hour}}
	for _, r := range contributionRevs {
		el.Contributors = append(el.Contributors, targeting.ContributionRef{Binding: targeting.ObjectRevision{Name: "baseline", UID: "b-1", Generation: 1}, Mode: v1alpha1.ModeDeny, Revision: r})
	}
	a := exception.Acceptance{Revision: rev, AcceptedAt: metav1.NewTime(exT0.Add(time.Duration(rev) * time.Hour)), Actor: exception.Actor{Username: actor, UID: "u-" + actor},
		Cluster: "kube-system:test", Namespace: el.Namespace, Policy: pol, Eligibility: el}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return &v1alpha1.ComplianceException{
		ObjectMeta: metav1.ObjectMeta{Name: "priv", Namespace: "team-a", UID: "ex-1", Generation: rev, Annotations: map[string]string{exception.AcceptanceAnnotation: string(raw)}},
		Spec: v1alpha1.ComplianceExceptionSpec{Policy: pol, WorkloadSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "debug"}},
			Reason: "reason " + actor, ExpiresAt: metav1.NewTime(exT0.Add(48 * time.Hour)), AcceptanceRevision: rev},
	}
}

func exceptionEnv(t *testing.T, objs ...client.Object) (client.Client, *ExceptionReconciler) {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(Scheme()).WithObjects(objs...).WithStatusSubresource(&v1alpha1.ComplianceException{}).Build()
	return c, &ExceptionReconciler{Client: c, Reader: c, Namespace: DefaultSnapshotNamespace}
}

func reconcileException(t *testing.T, c client.Client, r *ExceptionReconciler) *v1alpha1.ComplianceException {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "team-a", Name: "priv"}}); err != nil {
		t.Fatal(err)
	}
	ex := &v1alpha1.ComplianceException{}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "team-a", Name: "priv"}, ex); err != nil {
		t.Fatal(err)
	}
	return ex
}

func snapshotConfigMaps(t *testing.T, c client.Client, opts ...client.ListOption) []corev1.ConfigMap {
	t.Helper()
	var l corev1.ConfigMapList
	if err := c.List(context.Background(), &l, append(opts, client.InNamespace(DefaultSnapshotNamespace))...); err != nil {
		t.Fatal(err)
	}
	return l.Items
}

func recorded(t *testing.T, ex *v1alpha1.ComplianceException) metav1.Condition {
	t.Helper()
	c := meta.FindStatusCondition(ex.Status.Conditions, v1alpha1.ConditionAcceptanceRecorded)
	if c == nil {
		t.Fatalf("no %s condition: %+v", v1alpha1.ConditionAcceptanceRecorded, ex.Status)
	}
	return *c
}

func TestAcceptanceSnapshotIsRecorded(t *testing.T) {
	c, r := exceptionEnv(t, acceptedException(t, 1, "alice", revA))
	ex := reconcileException(t, c, r)
	cms := snapshotConfigMaps(t, c)
	if len(cms) != 1 {
		t.Fatalf("snapshots = %d", len(cms))
	}
	cm := cms[0]
	if cm.Immutable == nil || !*cm.Immutable || cm.Name != "acceptance-ex-1-1" {
		t.Errorf("snapshot configmap %s immutable=%v", cm.Name, cm.Immutable)
	}
	for k, v := range map[string]string{
		targeting.LabelManagedBy: targeting.ManagedByValue, exception.LabelExceptionUID: "ex-1",
		exception.LabelNamespaceUID: "ns-a-1", exception.LabelAcceptanceRevision: "1", exception.RevisionLabel(revA): "true",
	} {
		if cm.Labels[k] != v {
			t.Errorf("label %s = %q, want %q", k, cm.Labels[k], v)
		}
	}
	snap, digest, err := exception.SnapshotFrom(&cm)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Actor.Username != "alice" || snap.Reason != "reason alice" || snap.Namespace.UID != "ns-a-1" || snap.Cluster != "kube-system:test" ||
		snap.WorkloadSelector.MatchLabels["app"] != "debug" || !snap.AcceptedAt.Time.Equal(exT0.Add(time.Hour)) || !snap.ExpiresAt.Time.Equal(exT0.Add(48*time.Hour)) ||
		len(snap.Eligibility.Contributors) != 1 || snap.Eligibility.Contributors[0].Revision != revA || snap.Exception.UID != "ex-1" {
		t.Errorf("snapshot = %+v", snap)
	}
	want := v1alpha1.AcceptanceSnapshotReference{Revision: 1, Snapshot: "konstapel-system/acceptance-ex-1-1", Digest: digest}
	if ex.Status.Acceptance == nil || *ex.Status.Acceptance != want {
		t.Errorf("status.acceptance = %+v, want %+v", ex.Status.Acceptance, want)
	}
	if cond := recorded(t, ex); cond.Status != metav1.ConditionTrue || cond.Reason != v1alpha1.ReasonSnapshotRecorded {
		t.Errorf("condition = %+v", cond)
	}
	// The assessment collector selects snapshots by contribution revision.
	if got := snapshotConfigMaps(t, c, client.HasLabels{exception.RevisionLabel(revA)}); len(got) != 1 {
		t.Errorf("selection by revision found %d", len(got))
	}
	if got := snapshotConfigMaps(t, c, client.HasLabels{exception.RevisionLabel(revB)}); len(got) != 0 {
		t.Errorf("selection by another revision found %d", len(got))
	}
}

// A restarted controller re-reads the snapshot; it never rewrites it or
// refreshes the accepted set.
func TestAcceptanceSnapshotSurvivesRestart(t *testing.T) {
	c, r := exceptionEnv(t, acceptedException(t, 1, "alice", revA))
	first := reconcileException(t, c, r)
	before := snapshotConfigMaps(t, c)[0]

	// A metadata edit and a new reconciler instance.
	first.Labels = map[string]string{"edited": "true"}
	if err := c.Update(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	restarted := &ExceptionReconciler{Client: c, Reader: c, Namespace: DefaultSnapshotNamespace}
	again := reconcileException(t, c, restarted)
	after := snapshotConfigMaps(t, c)
	if len(after) != 1 || after[0].ResourceVersion != before.ResourceVersion || after[0].Data[exception.SnapshotDataKey] != before.Data[exception.SnapshotDataKey] {
		t.Error("the snapshot was rewritten")
	}
	if *again.Status.Acceptance != *first.Status.Acceptance {
		t.Errorf("status changed: %+v -> %+v", first.Status.Acceptance, again.Status.Acceptance)
	}
}

func TestRenewalGetsANewSnapshotAndKeepsTheOld(t *testing.T) {
	c, r := exceptionEnv(t, acceptedException(t, 1, "alice", revA))
	first := reconcileException(t, c, r)
	renewed := acceptedException(t, 2, "dave", revA, revB)
	first.Spec, first.Annotations = renewed.Spec, renewed.Annotations
	if err := c.Update(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := reconcileException(t, c, r)
	cms := snapshotConfigMaps(t, c)
	if len(cms) != 2 {
		t.Fatalf("snapshots = %d", len(cms))
	}
	if second.Status.Acceptance.Revision != 2 || second.Status.Acceptance.Snapshot != "konstapel-system/acceptance-ex-1-2" {
		t.Errorf("status = %+v", second.Status.Acceptance)
	}
	for _, cm := range cms {
		snap, _, err := exception.SnapshotFrom(&cm)
		if err != nil {
			t.Fatal(err)
		}
		switch snap.AcceptanceRevision {
		case 1:
			if snap.Actor.Username != "alice" || len(snap.Eligibility.Contributors) != 1 {
				t.Errorf("first snapshot changed: %+v", snap)
			}
		case 2:
			if snap.Actor.Username != "dave" || len(snap.Eligibility.Contributors) != 2 {
				t.Errorf("renewal snapshot = %+v", snap)
			}
		}
	}
	if got := snapshotConfigMaps(t, c, client.HasLabels{exception.RevisionLabel(revB)}); len(got) != 1 || got[0].Name != "acceptance-ex-1-2" {
		t.Errorf("revision B selects %v", got)
	}
}

func TestNoSnapshotWithoutAMatchingRecord(t *testing.T) {
	missing := acceptedException(t, 1, "alice", revA)
	missing.Annotations = nil
	c, r := exceptionEnv(t, missing)
	ex := reconcileException(t, c, r)
	if cond := recorded(t, ex); cond.Status != metav1.ConditionFalse || cond.Reason != v1alpha1.ReasonAcceptanceMissing || ex.Status.Acceptance != nil {
		t.Errorf("missing record: %+v %+v", cond, ex.Status.Acceptance)
	}

	pending := acceptedException(t, 1, "alice", revA)
	pending.Spec.AcceptanceRevision = 2
	c, r = exceptionEnv(t, pending)
	ex = reconcileException(t, c, r)
	if cond := recorded(t, ex); cond.Reason != v1alpha1.ReasonAcceptancePending {
		t.Errorf("pending record: %+v", cond)
	}
	if n := len(snapshotConfigMaps(t, c)); n != 0 {
		t.Errorf("%d snapshots without a matching record", n)
	}
}

func TestExistingSnapshotIsNeverOverwritten(t *testing.T) {
	ex := acceptedException(t, 1, "alice", revA)
	immutable := true
	for name, cm := range map[string]*corev1.ConfigMap{
		"different content": {ObjectMeta: metav1.ObjectMeta{Name: "acceptance-ex-1-1", Namespace: DefaultSnapshotNamespace,
			Labels:      map[string]string{targeting.LabelManagedBy: targeting.ManagedByValue},
			Annotations: map[string]string{exception.AnnotationSnapshotDigest: "sha256:" + strings.Repeat("0", 64)}},
			Immutable: &immutable, Data: map[string]string{exception.SnapshotDataKey: `{"version":1}`}},
		"unmanaged": {ObjectMeta: metav1.ObjectMeta{Name: "acceptance-ex-1-1", Namespace: DefaultSnapshotNamespace}, Data: map[string]string{"x": "y"}},
	} {
		t.Run(name, func(t *testing.T) {
			c, r := exceptionEnv(t, ex.DeepCopy(), cm.DeepCopy())
			got := reconcileException(t, c, r)
			if cond := recorded(t, got); cond.Status != metav1.ConditionFalse || cond.Reason != v1alpha1.ReasonSnapshotConflict || got.Status.Acceptance != nil {
				t.Errorf("conflict: %+v %+v", cond, got.Status.Acceptance)
			}
			after := &corev1.ConfigMap{}
			if err := c.Get(context.Background(), client.ObjectKeyFromObject(cm), after); err != nil {
				t.Fatal(err)
			}
			if after.Data[exception.SnapshotDataKey] != cm.Data[exception.SnapshotDataKey] || after.Data["x"] != cm.Data["x"] {
				t.Error("an existing configmap was overwritten")
			}
		})
	}
}
