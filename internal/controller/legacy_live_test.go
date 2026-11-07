//go:build live

package controller

// Live legacy upgrade (add-s3-evidence-publishing 9.1/9.3): a run publishes
// through the legacy file-configured destination on the test-owned S3
// service. The controller is upgraded to EvidenceDestinations only (no
// legacy publisher). The run stays visibly blocked, touching nothing, until
// one destination declares its legacy ID; then the receipt, the preserved
// legacy configuration (for the region), and the destination are verified
// against each other and the run is pinned with the recorded association.
// Its receipt and stored objects are unchanged, and expiry deletes them
// through the destination. Run through scripts/targeting-live.sh.

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

func TestLiveLegacyMigration(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l) // the legacy destination: id "live"
	ns := "konstapel-system"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: pub.Dest.CredentialSecret.Name},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	if err := l.c.Create(l.ctx, secret); err != nil {
		t.Fatal(err)
	}
	l.setNamespace("lm-prod", "lm-production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "lm-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	b := bindingObj("lm-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "lm-production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "20s", Retention: "150s"}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "lm-prod"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	for _, o := range []client.Object{p, pod, b} {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "lm-dest"}}
	preserved := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "lm-legacy-destination"}}
	var runName string
	t.Cleanup(func() {
		if runName != "" {
			r := &v1alpha1.AssessmentRun{}
			if l.c.Get(l.ctx, client.ObjectKey{Name: runName}, r) == nil {
				r.Finalizers = nil
				_ = l.c.Update(l.ctx, r)
				_ = l.c.Delete(l.ctx, r)
			}
		}
		for _, o := range []client.Object{b, pod, p} {
			_ = l.c.Delete(l.ctx, o)
		}
		l.eventually("legacy test policies removed", func() (bool, string) { got := l.policiesFor(b.Name); return len(got) == 0, toJSON(got) })
		got := &v1alpha1.EvidenceDestination{}
		if l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got) == nil {
			got.Finalizers = nil
			_ = l.c.Update(l.ctx, got)
			_ = l.c.Delete(l.ctx, got)
		}
		_ = l.c.Delete(l.ctx, preserved)
		_ = l.c.Delete(l.ctx, secret)
	})
	get := func() *v1alpha1.AssessmentRun {
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: runName}, r); err != nil {
			return nil
		}
		return r
	}

	// 1. Before the upgrade: the legacy file destination publishes.
	ConfigureAssessments(AssessmentRuntime{Publisher: pub, StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: time.Minute, Workers: 2,
		Ready: func(ctx context.Context) error { _, err := pub.Ready(ctx); return err }})
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	stop := l.startManager()
	l.eventually("legacy run published", func() (bool, string) {
		s := l.binding(b.Name).Status.Assessment
		if s != nil && s.LatestRun != nil {
			runName = s.LatestRun.Name
		}
		r := get()
		return r != nil && r.Status.Phase == v1alpha1.RunCompleted && r.Status.Publication != nil, toJSON(s)
	})
	stop()
	legacy := get()
	receipt := legacy.Status.Publication.DeepCopy()
	if legacy.Status.Destination != nil || receipt.Destination == nil || receipt.Destination.ID != pub.Dest.ID {
		t.Fatalf("setup: not a legacy publication: %s", toJSON(legacy.Status))
	}
	objects := func() map[string]string {
		out, err := pub.Client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{Bucket: aws.String(pub.Dest.Bucket), Prefix: aws.String(pub.Dest.KeyPrefix() + "evidence/")})
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]string{}
		for _, o := range out.Contents {
			if k := aws.ToString(o.Key); strings.Contains(k, string(legacy.UID)) {
				m[k] = aws.ToString(o.ETag)
			}
		}
		return m
	}
	stored := objects()
	if len(stored) == 0 {
		t.Fatal("setup: no stored objects for the legacy run")
	}

	// 2. Upgrade: destinations only. Without a declaring destination the
	// run is blocked and nothing is touched.
	ConfigureAssessments(AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: time.Minute, Workers: 2,
		ControllerNamespace: ns, Destinations: &DestinationPublishers{Reader: l.c, Namespace: ns}})
	stop = l.startManager()
	defer func() { stop() }()
	l.eventually("legacy run blocked without a declaring destination", func() (bool, string) {
		c := meta.FindStatusCondition(get().Status.Conditions, ConditionLegacyMigrated)
		return c != nil && c.Status == metav1.ConditionFalse && c.Reason == ReasonLegacyNoDestination, toJSON(c)
	})
	l.record("blocked", map[string]any{"run": runName, "reason": ReasonLegacyNoDestination})

	// 3. The administrator preserves the legacy file and declares it.
	raw, err := yaml.Marshal(pub.Dest)
	if err != nil {
		t.Fatal(err)
	}
	preserved.Data = map[string]string{"destination.yaml": string(raw)}
	if err := l.c.Create(l.ctx, preserved); err != nil {
		t.Fatal(err)
	}
	ed.Spec = v1alpha1.EvidenceDestinationSpec{
		S3: v1alpha1.S3Location{Endpoint: pub.Dest.Endpoint, Bucket: pub.Dest.Bucket, Region: pub.Dest.Region, Prefix: pub.Dest.Prefix, DevelopmentFixture: true,
			CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: secret.Name}}},
		Legacy: &v1alpha1.LegacyDestination{DestinationID: pub.Dest.ID,
			Configuration: v1alpha1.LegacyConfiguration{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: preserved.Name}}},
	}
	if err := l.c.Create(l.ctx, ed); err != nil {
		t.Fatal(err)
	}
	l.eventually("legacy run migrated", func() (bool, string) {
		r := get()
		pin := r.Status.Destination
		return pin != nil && pin.Source == v1alpha1.DestinationMigrated && pin.UID == string(ed.UID) && pin.Legacy != nil &&
			pin.Legacy.DestinationID == pub.Dest.ID && r.Labels[LabelRunDestination] == string(ed.UID), toJSON(r.Status)
	})
	migrated := get()
	if !equality.Semantic.DeepEqual(migrated.Status.Publication, receipt) {
		t.Fatalf("migration rewrote the receipt:\n%s\n%s", toJSON(receipt), toJSON(migrated.Status.Publication))
	}
	if got := objects(); toJSON(got) != toJSON(stored) {
		t.Fatalf("migration changed stored objects:\n%v\n%v", stored, got)
	}
	got := &v1alpha1.EvidenceDestination{}
	_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
	if !controllerutil.ContainsFinalizer(got, DestinationFinalizer) {
		t.Fatal("destination does not hold the migrated run")
	}
	l.record("migrated", map[string]any{"run": runName, "destination": ed.Name, "legacyID": pub.Dest.ID})

	// 4. Retention finishes through the destination with the original expiry.
	l.eventually("expired legacy package deleted through the destination", func() (bool, string) {
		r := get()
		return r != nil && r.Status.Publication.Cleanup.State == v1alpha1.CleanupState(publication.CleanupDeleted) && len(objects()) == 0,
			fmt.Sprintf("%s %d objects", toJSON(r.Status.Publication.Cleanup), len(objects()))
	})
	l.record("expired", map[string]any{"run": runName, "expiresAt": receipt.ExpiresAt})
}
