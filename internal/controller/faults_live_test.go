//go:build live

package controller

// Live assessment faults (add-continuous-assessments task 6.2): a controller
// restart and workload mutation during collection, an engine reporting
// outage leaving evidence missing, and a storage outage during publication.
// Each run must stay one snapshot: recorded gaps, honest freshness, bounded
// failure, and no duplicate or rewritten publication. Run through
// scripts/targeting-live.sh.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/download"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// commits counts commit objects (current versions) stored for a run UID.
func commits(t *testing.T, l *live, pub *s3store.Publisher, runUID string) int {
	out, err := pub.Client.ListObjectsV2(l.ctx, &s3.ListObjectsV2Input{Bucket: aws.String(pub.Dest.Bucket), Prefix: aws.String(pub.Dest.KeyPrefix() + "evidence/")})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, o := range out.Contents {
		if k := aws.ToString(o.Key); strings.Contains(k, runUID) && strings.HasSuffix(k, "/commit.json") {
			n++
		}
	}
	return n
}

func TestLiveAssessmentFaults(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	ConfigureAssessments(AssessmentRuntime{Publisher: pub, StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: 3 * time.Minute, Workers: 2,
		Ready: func(ctx context.Context) error { _, err := pub.Ready(ctx); return err }, ReadyInterval: 5 * time.Second})
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	l.applyFile("../../config/rbac/assessment-operator.yaml")
	l.setNamespace("ft-prod", "ft-production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "ft-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("ft-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "ft-production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "60s"}
	yes := true
	privileged := func(name string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ft-prod"},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	}
	pod := privileged("original")
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "ft-prod", Name: "operator"}}
	crb := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "ft-operator"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-assessment-operator"},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "ft-prod", Name: sa.Name}}}
	objs := []client.Object{p, b, pod, sa, crb}
	t.Cleanup(func() {
		_ = exec.Command("docker", "unpause", l.s3Container).Run()
		l.scaleKyverno("kyverno-reports-controller", 1)
		l.scaleKyverno("kyverno-background-controller", 1)
		for i := len(objs) - 1; i >= 0; i-- {
			_ = l.c.Delete(l.ctx, objs[i])
		}
		l.eventually("fault test policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
	})
	for _, o := range objs {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	get := func(name string) *v1alpha1.AssessmentRun {
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, r); err != nil {
			return nil
		}
		return r
	}
	runsOf := func() []v1alpha1.AssessmentRun {
		var list v1alpha1.AssessmentRunList
		_ = l.c.List(l.ctx, &list)
		var out []v1alpha1.AssessmentRun
		for _, r := range list.Items {
			if r.Spec.BindingRef.Name == b.Name {
				out = append(out, r)
			}
		}
		return out
	}
	stop := l.startManager()
	l.waitReady(b.Name, 1)

	// 1. Controller restart and workload mutation during collection.
	var scheduled string
	l.eventually("scheduled run collecting", func() (bool, string) {
		for _, r := range runsOf() {
			if r.Spec.Trigger != nil && r.Spec.Trigger.Type == v1alpha1.TriggerScheduled && r.Status.Phase == v1alpha1.RunCollecting {
				scheduled = r.Name
				return true, ""
			}
		}
		return false, toJSON(runsOf())
	})
	added := privileged("added")
	if err := l.c.Create(l.ctx, added); err != nil {
		t.Fatal(err)
	}
	objs = append(objs, added)
	stop()
	time.Sleep(5 * time.Second)
	stop = l.startManager()
	defer func() { stop() }()
	l.eventually("restarted run completes", func() (bool, string) {
		r := get(scheduled)
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted, toJSON(r.Status)
	})
	r := get(scheduled)
	if r.Status.Scope.NamespaceCount != 1 || r.Status.Summary.Evidence.Expected != 1 || r.Status.Publication.Phase != "Committed" {
		t.Fatalf("restarted run: %s", toJSON(r.Status))
	}
	srv := &download.Server{Reader: l.c, Reviews: download.KubeReviewer{Client: l.c, Audience: downloadAudience}, Publisher: pub, TempDir: t.TempDir()}
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()
	tok := l.token("ft-prod", sa.Name, downloadAudience)
	capture := func(run *v1alpha1.AssessmentRun) collector.CaptureV2 {
		code, body := fetch(t, ts.Client(), ts.URL+"/v1/assessmentruns/"+string(run.UID)+"/download", tok)
		if code != http.StatusOK {
			t.Fatalf("download %s: %d %s", run.Name, code, body)
		}
		dir := t.TempDir()
		untar(t, body, dir)
		raw, err := os.ReadFile(filepath.Join(dir, "capture.json"))
		if err != nil {
			t.Fatal(err)
		}
		var c collector.CaptureV2
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := capture(r)
	kinds := map[collector.ChangeKind]int{}
	for _, ch := range c.ScopeChanges {
		kinds[ch.Kind]++
	}
	if kinds[collector.WatchDiscontinuity] == 0 || kinds[collector.WorkloadAdded] == 0 || len(c.Expected) != 1 {
		t.Fatalf("restart or mutation not recorded, or scope not frozen: changes %v, expected %d", kinds, len(c.Expected))
	}
	if commits(t, l, pub, string(r.UID)) != 1 {
		t.Fatal("restarted run committed more than once")
	}
	l.record("restart", map[string]any{"run": scheduled, "changes": kinds, "evidence": r.Status.Summary.Evidence})

	// 2. Engine reporting outage: no new evaluation can arrive, so evidence is
	// missing and the snapshot is published as Incomplete, never Complete.
	l.scaleKyverno("kyverno-reports-controller", 0)
	l.scaleKyverno("kyverno-background-controller", 0)
	outage := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "ft-audit-outage"},
		Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}, Scope: v1alpha1.RunScopeBinding}}
	if err := l.c.Create(l.ctx, outage); err != nil {
		t.Fatal(err)
	}
	objs = append(objs, outage)
	l.eventually("engine-outage run published", func() (bool, string) {
		r := get(outage.Name)
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted, toJSON(r)
	})
	r = get(outage.Name)
	ev := r.Status.Summary.Evidence
	if ev.Completeness != "Incomplete" || ev.Attributable == ev.Expected || ev.Missing+ev.Rejected+ev.Unresolved == 0 || r.Status.Summary.Export != "Assessment" {
		t.Fatalf("engine outage claimed evidence: %s", toJSON(r.Status.Summary))
	}
	l.record("engine-outage", map[string]any{"run": outage.Name, "evidence": ev})
	l.scaleKyverno("kyverno-reports-controller", 1)
	l.scaleKyverno("kyverno-background-controller", 1)

	// 3. Storage outage while publishing: the run retries within its bound
	// and commits the same frozen package exactly once.
	interrupted := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "ft-audit-interrupted"},
		Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}, Scope: v1alpha1.RunScopeBinding}}
	if err := l.c.Create(l.ctx, interrupted); err != nil {
		t.Fatal(err)
	}
	objs = append(objs, interrupted)
	l.eventually("interrupted run collecting", func() (bool, string) {
		r := get(interrupted.Name)
		return r != nil && r.Status.Phase == v1alpha1.RunCollecting, toJSON(r)
	})
	if out, err := exec.Command("docker", "pause", l.s3Container).CombinedOutput(); err != nil {
		t.Fatalf("pause S3: %v %s", err, out)
	}
	var frozen string
	l.eventually("publication retrying during outage", func() (bool, string) {
		r := get(interrupted.Name)
		if r == nil || r.Status.Phase != v1alpha1.RunPublishing {
			return false, toJSON(r)
		}
		frozen = r.Status.DescriptorSHA256
		return frozen != "", ""
	})
	time.Sleep(20 * time.Second) // several failed attempts
	if r := get(interrupted.Name); r.Status.Phase != v1alpha1.RunPublishing || r.Status.DescriptorSHA256 != frozen {
		t.Fatalf("outage changed the frozen package or phase: %s", toJSON(r.Status))
	}
	if out, err := exec.Command("docker", "unpause", l.s3Container).CombinedOutput(); err != nil {
		t.Fatalf("unpause S3: %v %s", err, out)
	}
	l.eventually("interrupted run published after recovery", func() (bool, string) {
		r := get(interrupted.Name)
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted, toJSON(r.Status)
	})
	r = get(interrupted.Name)
	if r.Status.DescriptorSHA256 != frozen || r.Status.Publication.DescriptorSHA256 != frozen || commits(t, l, pub, string(r.UID)) != 1 {
		t.Fatalf("recovered publication differs from the frozen package or committed twice: %s", toJSON(r.Status))
	}
	l.record("storage-outage", map[string]any{"run": interrupted.Name, "descriptor": frozen})

	// No duplicate snapshots: exactly the three runs, each committed once.
	if got := runsOf(); len(got) != 3 {
		t.Fatalf("want 3 runs, got %d: %s", len(got), toJSON(got))
	}
	for _, r := range runsOf() {
		if commits(t, l, pub, string(r.UID)) != 1 {
			t.Fatalf("run %s committed %d times", r.Name, commits(t, l, pub, string(r.UID)))
		}
	}
}
