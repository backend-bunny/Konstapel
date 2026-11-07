//go:build live

package controller

// Live orphan handoff (add-s3-evidence-publishing 8.3–8.6): a
// run pinned to an EvidenceDestination on the test-owned S3 service; the
// backend becomes unreachable; the administrator escalates to Orphan and
// deletes the destination. The handoff is accepted and fenced without
// contacting the backend, the inventory is saved during the outage, the
// interrupted run ends Orphaned (never Published) and frees its binding
// slot, the destination is finalized, and once the backend returns
// Konstapel still issues nothing there — even with a destination recreated
// under the same name at the same location. Run through scripts/targeting-live.sh.

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

func TestLiveOrphanFence(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	ns := "konstapel-system"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "of-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "of-dest"}, Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{
		Endpoint: l.s3Endpoint, Bucket: pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/of-dest", DevelopmentFixture: true,
		CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: secret.Name}}}}}
	l.setNamespace("of-prod", "of-production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "of-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("of-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "of-production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "40s"}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "of-prod"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	for _, o := range []client.Object{secret, ed, p, pod} {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), ed)
	b.Spec.Assessment.DestinationRef = &v1alpha1.DestinationReference{Name: ed.Name, UID: string(ed.UID)}
	b.SetUID("")
	if err := l.c.Create(l.ctx, b); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "unpause", l.s3Container).Run()
		_ = l.c.Delete(l.ctx, pod)
		_ = l.c.Delete(l.ctx, b)
		_ = l.c.Delete(l.ctx, p)
		l.eventually("orphan test policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
	})
	ConfigureAssessments(AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: 10 * time.Minute, Workers: 2,
		ControllerNamespace: ns, Destinations: &DestinationPublishers{Reader: l.c, Namespace: ns}})
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	stop := l.startManager()
	defer stop()
	l.eventually("destination ready", func() (bool, string) {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
		return meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionDestinationReady), toJSON(got.Status)
	})
	var name string
	l.eventually("run pinned and collecting", func() (bool, string) {
		s := l.binding(b.Name).Status.Assessment
		if s != nil && s.Schedule != nil && s.Schedule.ActiveRun != nil {
			name = s.Schedule.ActiveRun.Name
		}
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, r); err != nil {
			return false, err.Error()
		}
		return r.Status.Destination != nil && r.Status.Phase == v1alpha1.RunCollecting, toJSON(r.Status)
	})
	// The backend becomes unreachable; the administrator escalates to Orphan.
	// (Admission records the actor in a cluster; this harness sets it.)
	if out, err := exec.Command("docker", "pause", l.s3Container).CombinedOutput(); err != nil {
		t.Fatalf("pause S3: %v %s", err, out)
	}
	got := &v1alpha1.EvidenceDestination{}
	_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
	got.Spec.DeletionPolicy = v1alpha1.DeletionOrphan
	got.Spec.Orphan = &v1alpha1.OrphanRequest{Reason: "backend decommissioned", Actor: "platform-admin"}
	if err := l.c.Update(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	if err := l.c.Delete(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	// The whole handoff can finish within one poll (the destination is then
	// gone), so it is observed through its durable record: the inventory
	// header, written last, exists only after acceptance and the fence. It
	// is saved while the backend is still unreachable.
	inv := &v1alpha1.OrphanInventoryRef{Header: "konstapel-orphan-" + string(ed.UID)}
	l.eventually("handoff accepted and its inventory saved during the outage", func() (bool, string) {
		err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: inv.Header}, &corev1.ConfigMap{})
		return err == nil, fmt.Sprint(err)
	})
	header := &corev1.ConfigMap{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: inv.Header}, header); err != nil {
		t.Fatal(err)
	}
	if h := header.Data["inventory.json"]; header.Immutable == nil || !*header.Immutable || len(header.OwnerReferences) != 0 ||
		!strings.Contains(h, `"actor": "platform-admin"`) || !strings.Contains(h, `"reason": "backend decommissioned"`) ||
		!strings.Contains(h, "fencedAt") || !strings.Contains(h, "NotEnumerated") {
		t.Fatalf("inventory header %s: %s", toJSON(inv), toJSON(header))
	}
	chunk := &corev1.ConfigMap{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: inv.Header + "-0"}, chunk); err != nil || !strings.Contains(chunk.Data["inventory.json"], name) {
		t.Fatalf("inventory chunk missing run %s: %v %s", name, err, toJSON(chunk))
	}
	// Once the inventory is saved, the interrupted run ends Failed
	// (DestinationOrphaned), never Published, its binding slot is released,
	// and the destination is finalized — all while the backend is down.
	l.eventually("interrupted run ended as orphaned", func() (bool, string) {
		r := &v1alpha1.AssessmentRun{}
		_ = l.c.Get(l.ctx, client.ObjectKey{Name: name}, r)
		c := meta.FindStatusCondition(r.Status.Conditions, v1alpha1.ConditionPublished)
		committed := r.Status.Publication != nil && r.Status.Publication.Phase == v1alpha1.PublicationPhase(publication.PhaseCommitted)
		return r.Status.Phase == v1alpha1.RunFailed && c != nil && c.Reason == v1alpha1.ReasonDestinationOrphaned && !committed &&
			r.Status.Destination != nil && r.Status.Destination.OrphanedAt != nil && !controllerutil.ContainsFinalizer(r, RetentionFinalizer), toJSON(r)
	})
	l.eventually("binding slot released", func() (bool, string) {
		s := l.binding(b.Name).Status.Assessment
		return s != nil && s.Schedule != nil && (s.Schedule.ActiveRun == nil || s.Schedule.ActiveRun.Name != name), toJSON(s)
	})
	l.eventually("destination finalized", func() (bool, string) {
		err := l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), &v1alpha1.EvidenceDestination{})
		return apierrors.IsNotFound(err), fmt.Sprint(err)
	})
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: inv.Header}, &corev1.ConfigMap{}); err != nil {
		t.Fatalf("inventory did not survive finalization: %v", err)
	}
	// A destination recreated under the same name at the same location is a
	// new owner: it becomes ready, owes nothing for the handed-off run, and
	// never adopts it.
	repl := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: ed.Name}, Spec: *ed.Spec.DeepCopy()}
	repl.Spec.DeletionPolicy, repl.Spec.Orphan = "", nil
	if err := l.c.Create(l.ctx, repl); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, repl) })
	// Well past the collection timeout and after the backend returns,
	// nothing for the run reaches storage and Orphaned is not cleared.
	time.Sleep(50 * time.Second)
	if out, err := exec.Command("docker", "unpause", l.s3Container).CombinedOutput(); err != nil {
		t.Fatalf("unpause S3: %v %s", err, out)
	}
	time.Sleep(15 * time.Second)
	r := &v1alpha1.AssessmentRun{}
	_ = l.c.Get(l.ctx, client.ObjectKey{Name: name}, r)
	if r.Status.Phase != v1alpha1.RunFailed || r.Status.Destination == nil || r.Status.Destination.OrphanedAt == nil {
		t.Fatalf("orphaned run changed after the backend returned: %s", toJSON(r.Status))
	}
	l.eventually("replacement destination ready without adopting the run", func() (bool, string) {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(repl), got)
		return got.UID != ed.UID && meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionDestinationReady) &&
			got.Status.OutstandingRuns == 0 && got.Status.OutstandingPackages == 0, toJSON(got.Status)
	})
	if r.Status.Destination.UID != string(ed.UID) {
		t.Fatalf("orphaned run re-pinned: %s", toJSON(r.Status.Destination))
	}
	out, err := pub.Client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{Bucket: aws.String(pub.Dest.Bucket), Prefix: aws.String("konstapel-test/of-dest/")})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range out.Contents {
		if k := aws.ToString(o.Key); strings.Contains(k, string(r.UID)) {
			t.Fatalf("storage written for a fenced run: %s", k)
		}
	}
	l.record("orphan-fence", map[string]any{"run": name, "phase": r.Status.Phase})
}
