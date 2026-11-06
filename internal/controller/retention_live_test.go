//go:build live

package controller

// Live retention lifecycle (add-s3-evidence-publishing task 5.5) with a
// short binding retention instead of 90 days: publish to the test-owned S3
// service, download, expire, refuse new downloads, delete storage, and
// release or tombstone the run record. Run through scripts/targeting-live.sh.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/download"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// ownedKeys lists every object version or marker for a run UID.
func ownedKeys(t *testing.T, l *live, pub *s3store.Publisher, runUID string) []string {
	v, err := pub.Client.ListObjectVersions(l.ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(pub.Dest.Bucket), Prefix: aws.String(pub.Dest.KeyPrefix() + "evidence/")})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, o := range v.Versions {
		if strings.Contains(aws.ToString(o.Key), runUID) {
			out = append(out, aws.ToString(o.Key))
		}
	}
	for _, o := range v.DeleteMarkers {
		if strings.Contains(aws.ToString(o.Key), runUID) {
			out = append(out, aws.ToString(o.Key)+" (marker)")
		}
	}
	return out
}

func TestLiveRetentionLifecycle(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	ConfigureAssessments(AssessmentRuntime{Publisher: pub, StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: time.Minute, Workers: 2,
		Ready: func(ctx context.Context) error { _, err := pub.Ready(ctx); return err }, IntegrityInterval: 10 * time.Second})
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	l.applyFile("../../config/rbac/assessment-operator.yaml")

	l.setNamespace("rl-team", "rl-production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "rl-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("rl-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "rl-production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "20s", Retention: "45s"}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "rl-team"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "rl-team", Name: "auditor"}}
	crb := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "rl-auditor"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-assessment-operator"},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "rl-team", Name: sa.Name}}}
	manual := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "rl-audit-manual"},
		Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}, Scope: v1alpha1.RunScopeBinding}}
	t.Cleanup(func() {
		for _, o := range []client.Object{crb, sa, pod, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: b.Name}}, p} {
			_ = l.c.Delete(l.ctx, o)
		}
		l.eventually("retention test policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
	})
	for _, o := range []client.Object{p, b, pod, sa, crb} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	stop := l.startManager()
	defer stop()
	l.waitReady(b.Name, 1)

	get := func(name string) (*v1alpha1.AssessmentRun, error) {
		r := &v1alpha1.AssessmentRun{}
		return r, l.c.Get(l.ctx, client.ObjectKey{Name: name}, r)
	}
	var scheduled string
	l.eventually("scheduled run published", func() (bool, string) {
		s := l.binding(b.Name).Status.Assessment
		if s != nil && s.Schedule != nil && s.Schedule.ActiveRun != nil {
			scheduled = s.Schedule.ActiveRun.Name
		}
		r, err := get(scheduled)
		return err == nil && r.Status.Phase == v1alpha1.RunCompleted && s.Schedule.ActiveRun == nil, toJSON(s)
	})
	if err := l.c.Create(l.ctx, manual); err != nil {
		t.Fatal(err)
	}
	l.eventually("manual run published", func() (bool, string) {
		r, err := get(manual.Name)
		return err == nil && r.Status.Phase == v1alpha1.RunCompleted, toJSON(r.Status)
	})
	sched, _ := get(scheduled)
	man, _ := get(manual.Name)
	for _, r := range []*v1alpha1.AssessmentRun{sched, man} {
		p := r.Status.Publication
		if !controllerutil.ContainsFinalizer(r, RetentionFinalizer) || p.Retention == nil || p.Retention.Duration != "45s" ||
			!p.ExpiresAt.Time.Equal(p.PublishedAt.Add(45*time.Second)) || len(ownedKeys(t, l, pub, string(r.UID))) == 0 {
			t.Fatalf("run %s not retained as published: %s", r.Name, toJSON(r.Status.Publication))
		}
	}

	srv := &download.Server{Reader: l.c, Reviews: download.KubeReviewer{Client: l.c, Audience: downloadAudience}, Publisher: pub, TempDir: t.TempDir()}
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()
	tok := l.token("rl-team", sa.Name, downloadAudience)
	url := ts.URL + "/v1/assessmentruns/" + string(sched.UID) + "/download"
	if code, body := fetch(t, ts.Client(), url, tok); code != http.StatusOK {
		t.Fatalf("platform download before expiry: %d %s", code, body)
	}
	l.record("published", map[string]any{"scheduled": scheduled, "manual": manual.Name, "expiresAt": sched.Status.Publication.ExpiresAt})

	// Deleting the scheduled run before expiry keeps its record and cleanup.
	if err := l.c.Delete(l.ctx, sched); err != nil {
		t.Fatal(err)
	}
	if r, err := get(scheduled); err != nil || r.DeletionTimestamp.IsZero() {
		t.Fatalf("deleted run record not retained before expiry: %v", err)
	}
	l.eventually("expired package refused", func() (bool, string) {
		code, body := fetch(t, ts.Client(), url, tok)
		return code == http.StatusGone || code == http.StatusForbidden, string(body) // 403 once the record is released
	})
	l.eventually("deleted run's storage removed and record released", func() (bool, string) {
		_, err := get(scheduled)
		keys := ownedKeys(t, l, pub, string(sched.UID))
		return apierrors.IsNotFound(err) && len(keys) == 0, toJSON(keys)
	})
	// The manual run was not deleted: storage is removed and a tombstone stays.
	l.eventually("manual run tombstoned", func() (bool, string) {
		r, err := get(manual.Name)
		if err != nil {
			return false, err.Error()
		}
		p := r.Status.Publication
		return p.Phase == "Deleted" && p.Cleanup.State == "Deleted" && p.Availability == "Expired" && !controllerutil.ContainsFinalizer(r, RetentionFinalizer) &&
			len(ownedKeys(t, l, pub, string(r.UID))) == 0, toJSON(p)
	})
	l.record("retention-lifecycle", map[string]any{"scheduled": "released", "manual": "tombstone"})
	_ = l.c.Delete(l.ctx, man)
}
