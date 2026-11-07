//go:build live

package controller

// Live destination pins (add-s3-evidence-publishing 7.4 / 3.4): two
// EvidenceDestinations on the test-owned S3 service, a credential Secret in
// the controller namespace, and the central default ConfigMap. The real
// destination reconciler probes them; a run pins the default and publishes
// there through the real publisher even after the default switches, and the
// next run publishes at the new destination. Credential rotation (3.4):
// a missing Secret is a visible, retryable problem with no fallback, and
// switching to a rotated Secret serves history again; retirement (8.1) on a
// versioned bucket deletes every version of the expired packages using the
// rotated credentials. Run through scripts/targeting-live.sh.

import (
	"context"
	"fmt"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func TestLiveDestinationPins(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l) // creates the bucket; its client lists objects below
	// A versioned bucket: retirement must remove every version it owns.
	if _, err := pub.Client.PutBucketVersioning(l.ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(pub.Dest.Bucket),
		VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	ns := "konstapel-system"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	creds := func(name string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	}
	// Each destination has its own Secret so dp-primary's can be rotated
	// away and deleted while dp-secondary keeps working.
	secret, primarySecret := creds("dp-s3"), creds("dp-s3-primary")
	dests := map[string]*v1alpha1.EvidenceDestination{}
	for name, ref := range map[string]string{"dp-primary": primarySecret.Name, "dp-secondary": secret.Name} {
		dests[name] = &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{
			Endpoint: l.s3Endpoint, Bucket: pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/" + name, DevelopmentFixture: true,
			CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: ref}}}}}
	}
	l.setNamespace("dp-prod", "dp-production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "dp-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("dp-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "dp-production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "30s", Retention: "150s"}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "dp-prod"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	objs := []client.Object{secret, primarySecret, dests["dp-primary"], dests["dp-secondary"], p, b, pod}
	for _, o := range objs {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	setDefault := func(name string) {
		ed := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKey{Name: name}, ed)
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: DefaultDestinationConfigMap}}
		data := map[string]string{DefaultDestinationNameKey: name, DefaultDestinationUIDKey: string(ed.UID)}
		if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(cm), cm); err != nil {
			cm.Data = data
			_ = l.c.Create(l.ctx, cm)
			return
		}
		cm.Data = data
		_ = l.c.Update(l.ctx, cm)
	}
	setDefault("dp-primary")
	var runs []string
	t.Cleanup(func() {
		for _, r := range runs {
			_ = l.c.Delete(l.ctx, &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: r}})
		}
		_ = l.c.Delete(l.ctx, pod)
		_ = l.c.Delete(l.ctx, b)
		_ = l.c.Delete(l.ctx, p)
		_ = l.c.Delete(l.ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: DefaultDestinationConfigMap}})
		l.eventually("pin test policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
	})
	ConfigureAssessments(AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: time.Minute, Workers: 2,
		ControllerNamespace: ns, Destinations: &DestinationPublishers{Reader: l.c, Namespace: ns}})
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	stop := l.startManager()
	defer stop()

	// The real destination reconciler probes both destinations.
	for name := range dests {
		l.eventually(name+" ready", func() (bool, string) {
			ed := &v1alpha1.EvidenceDestination{}
			_ = l.c.Get(l.ctx, client.ObjectKey{Name: name}, ed)
			return meta.IsStatusConditionTrue(ed.Status.Conditions, v1alpha1.ConditionDestinationReady), toJSON(ed.Status)
		})
	}
	l.waitReady(b.Name, 1)
	run := func(name string) *v1alpha1.AssessmentRun {
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, r); err != nil {
			return nil
		}
		return r
	}
	var first string
	l.eventually("scheduled run pinned", func() (bool, string) {
		s := l.binding(b.Name).Status.Assessment
		if s != nil && s.Schedule != nil && s.Schedule.ActiveRun != nil {
			first = s.Schedule.ActiveRun.Name
		}
		r := run(first)
		return r != nil && r.Status.Destination != nil, toJSON(s)
	})
	runs = append(runs, first)
	if r := run(first); r.Status.Destination.Name != "dp-primary" || r.Labels[LabelRunDestination] != r.Status.Destination.UID {
		t.Fatalf("pin %+v", r.Status.Destination)
	}
	primary := &v1alpha1.EvidenceDestination{}
	_ = l.c.Get(l.ctx, client.ObjectKey{Name: "dp-primary"}, primary)
	if !controllerutil.ContainsFinalizer(primary, DestinationFinalizer) {
		t.Fatal("pinned destination has no finalizer")
	}
	// Switch the default while the run collects.
	setDefault("dp-secondary")
	l.eventually("first run published", func() (bool, string) {
		r := run(first)
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted, toJSON(r.Status)
	})
	manual := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "dp-audit-manual"}, Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}, Scope: v1alpha1.RunScopeBinding}}
	if err := l.c.Create(l.ctx, manual); err != nil {
		t.Fatal(err)
	}
	runs = append(runs, manual.Name)
	l.eventually("second run published", func() (bool, string) {
		r := run(manual.Name)
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted, toJSON(r)
	})
	if r := run(manual.Name); r.Status.Destination == nil || r.Status.Destination.Name != "dp-secondary" {
		t.Fatalf("later run pin %+v", r.Status.Destination)
	}
	commitsUnder := func(prefix, runUID string) int {
		out, err := pub.Client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{Bucket: aws.String(pub.Dest.Bucket), Prefix: aws.String(prefix + "/")})
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
	r1, r2 := run(first), run(manual.Name)
	if commitsUnder("konstapel-test/dp-primary", string(r1.UID)) != 1 || commitsUnder("konstapel-test/dp-secondary", string(r1.UID)) != 0 ||
		commitsUnder("konstapel-test/dp-secondary", string(r2.UID)) != 1 || commitsUnder("konstapel-test/dp-primary", string(r2.UID)) != 0 {
		t.Fatal("packages are not at their pinned destinations")
	}
	l.record("pins", map[string]any{"first": r1.Status.Destination.Name, "second": r2.Status.Destination.Name})

	// Rotation: dp-primary's credentials go missing — a visible problem with
	// no fallback to dp-secondary's Secret — then it is pointed at a rotated
	// Secret and its old Secret is deleted. The retained package (r1) is
	// later deleted through the rotated reference.
	rotate := func(ref string) {
		ed := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKey{Name: "dp-primary"}, ed)
		ed.Spec.S3.CredentialSecret.Name = ref
		if err := l.c.Update(l.ctx, ed); err != nil {
			t.Fatal(err)
		}
	}
	readyReason := func() (bool, string) {
		ed := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKey{Name: "dp-primary"}, ed)
		c := meta.FindStatusCondition(ed.Status.Conditions, v1alpha1.ConditionDestinationReady)
		if c == nil || c.ObservedGeneration != ed.Generation && ed.Status.ObservedGeneration != ed.Generation {
			return false, toJSON(ed.Status)
		}
		return c.Status == metav1.ConditionTrue, c.Reason + ": " + c.Message
	}
	rotate("dp-s3-missing")
	l.eventually("missing credentials reported", func() (bool, string) {
		ok, msg := readyReason()
		return !ok && msg != "" && strings.Contains(msg, "dp-s3-missing"), msg
	})
	if strings.Contains(fmt.Sprint(readyReason()), l.s3Secret) {
		t.Fatal("status exposes credential material")
	}
	rotated := creds("dp-s3-rotated")
	if err := l.c.Create(l.ctx, rotated); err != nil {
		t.Fatal(err)
	}
	rotate(rotated.Name)
	l.eventually("rotated credentials ready", func() (bool, string) { return readyReason() })
	if err := l.c.Delete(l.ctx, primarySecret); err != nil {
		t.Fatal(err)
	}
	l.record("rotation", map[string]any{"missing": "NotReady", "rotated": rotated.Name})

	// Retirement (8.1): deleting both destinations keeps each until its
	// retained package expires and is deleted, then releases it.
	for name := range dests {
		ed := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKey{Name: name}, ed)
		if err := l.c.Delete(l.ctx, ed); err != nil {
			t.Fatal(err)
		}
	}
	l.eventually("retiring destinations report their packages", func() (bool, string) {
		ed := &v1alpha1.EvidenceDestination{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: "dp-primary"}, ed); err != nil {
			return false, err.Error()
		}
		c := meta.FindStatusCondition(ed.Status.Conditions, v1alpha1.ConditionDestinationRetiring)
		return c != nil && ed.Status.OutstandingPackages == 1 && ed.Status.LatestRetainedExpiry != nil, toJSON(ed.Status)
	})
	if commitsUnder("konstapel-test/dp-primary", string(r1.UID)) != 1 {
		t.Fatal("retirement removed a package before its expiry")
	}
	versionsOf := func(prefix, runUID string) int {
		out, err := pub.Client.ListObjectVersions(context.Background(), &s3.ListObjectVersionsInput{Bucket: aws.String(pub.Dest.Bucket), Prefix: aws.String(prefix + "/")})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, v := range out.Versions {
			if strings.Contains(aws.ToString(v.Key), runUID) {
				n++
			}
		}
		for _, m := range out.DeleteMarkers {
			if strings.Contains(aws.ToString(m.Key), runUID) {
				n++
			}
		}
		return n
	}
	if versionsOf("konstapel-test/dp-primary", string(r1.UID)) == 0 {
		t.Fatal("setup: no versions recorded for the retained package")
	}
	for name, uid := range map[string]string{"dp-primary": string(r1.UID), "dp-secondary": string(r2.UID)} {
		l.eventually(name+" released after every version of its package was deleted", func() (bool, string) {
			err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, &v1alpha1.EvidenceDestination{})
			return apierrors.IsNotFound(err) && versionsOf("konstapel-test/"+name, uid) == 0, fmt.Sprint(err)
		})
	}
	_ = l.c.Delete(l.ctx, rotated)
	l.record("retired", map[string]any{"destinations": 2, "bucket": "versioned", "credentials": "rotated"})
}
