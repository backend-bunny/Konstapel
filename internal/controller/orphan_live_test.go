//go:build live

package controller

// Live orphan fence (add-s3-evidence-publishing 8.3): a run pinned to an
// EvidenceDestination on the test-owned S3 service; the backend becomes
// unreachable; the administrator escalates to Orphan and deletes the
// destination. The handoff is accepted and fenced without contacting the
// backend, the run is held, and once the backend returns Konstapel still
// issues nothing there. Run through scripts/targeting-live.sh.

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
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
	l.eventually("handoff accepted and fenced without the backend", func() (bool, string) {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
		c := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionDestinationReady)
		return got.Status.OrphanIntent != nil && got.Status.OrphanHandoff != nil && c != nil && c.Reason == "HandedOff", toJSON(got.Status)
	})
	// The run may already have closed collection (a local step) before the
	// fence; from the fence on its phase never changes and nothing reaches
	// storage, well past the collection timeout and after the backend returns.
	fencedAt := &v1alpha1.AssessmentRun{}
	_ = l.c.Get(l.ctx, client.ObjectKey{Name: name}, fencedAt)
	time.Sleep(50 * time.Second)
	if out, err := exec.Command("docker", "unpause", l.s3Container).CombinedOutput(); err != nil {
		t.Fatalf("unpause S3: %v %s", err, out)
	}
	time.Sleep(15 * time.Second)
	r := &v1alpha1.AssessmentRun{}
	_ = l.c.Get(l.ctx, client.ObjectKey{Name: name}, r)
	if r.Status.Phase != fencedAt.Status.Phase || r.Status.Publication != nil {
		t.Fatalf("fenced run progressed from %s: %s", fencedAt.Status.Phase, toJSON(r.Status))
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
