package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

const legacyFile = `id: legacy
endpoint: https://s3.example.internal
bucket: evidence
region: %s
prefix: konstapel
addressing: path
credentialSecret:
  name: s3
`

// legacyEnv publishes a run through the legacy publisher (as the removed
// --evidence-destination file did), gives its receipt the legacy location,
// and then upgrades: no legacy publisher, destinations only.
func legacyEnv(t *testing.T) (*runEnv, string) {
	e, name := completedRun(t, "1h")
	r := e.run(name)
	r.Status.Publication.Destination = &v1alpha1.PublicationDestination{ID: "legacy", Endpoint: "https://s3.example.internal", Bucket: "evidence", Prefix: "konstapel/"}
	if err := e.c.Status().Update(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	store := e.pub
	dp := &DestinationPublishers{Reader: e.c, New: func(context.Context, s3store.Destination, client.Reader, string) (publication.Publisher, error) {
		return store, nil
	}}
	e.rr.Runtime.Publisher, e.ar.Runtime.Publisher = nil, nil
	e.rr.Runtime.Destinations, e.ar.Runtime.Destinations = dp, dp
	e.restart()
	return e, name
}

func (e *runEnv) legacyDestination(t *testing.T, name, uid, legacyID, prefix string) *v1alpha1.EvidenceDestination {
	t.Helper()
	ed := evidenceDestination(name, true)
	ed.UID = types.UID(uid)
	ed.Spec.S3.Endpoint, ed.Spec.S3.Prefix = "https://s3.example.internal", prefix
	ed.Spec.Legacy = &v1alpha1.LegacyDestination{DestinationID: legacyID,
		Configuration: v1alpha1.LegacyConfiguration{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: "legacy-destination"}}}
	status := ed.Status
	ed.Status = v1alpha1.EvidenceDestinationStatus{}
	if err := e.c.Create(context.Background(), ed); err != nil {
		t.Fatal(err)
	}
	ed.Status = status
	if err := e.c.Status().Update(context.Background(), ed); err != nil {
		t.Fatal(err)
	}
	return ed
}

func (e *runEnv) preserveLegacy(t *testing.T, region string) {
	t.Helper()
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "konstapel-system", Name: "legacy-destination"}}
	_ = e.c.Delete(context.Background(), cm)
	cm.Data = map[string]string{"destination.yaml": strings.Replace(legacyFile, "%s", region, 1)}
	if err := e.c.Create(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
}

func legacyCondition(r *v1alpha1.AssessmentRun) *metav1.Condition {
	return meta.FindStatusCondition(r.Status.Conditions, ConditionLegacyMigrated)
}

func (e *runEnv) storageOps() int {
	n := 0
	for _, op := range []fake.Op{fake.OpStage, fake.OpPublish, fake.OpInspect, fake.OpDelete, fake.OpCleanup, fake.OpOpen} {
		n += e.pub.Calls(op)
	}
	return n
}

// A legacy run is attached only to the one destination declaring its legacy
// ID, after the receipt, the preserved configuration (for the region), and
// the destination agree; until then it is visibly blocked and untouched.
// The association is idempotent, keeps the original receipt, and lets
// retention finish through the destination.
func TestLegacyRunMigratesAfterVerification(t *testing.T) {
	e, name := legacyEnv(t)
	receipt := e.run(name).Status.Publication.DeepCopy()
	ops := e.storageOps()
	block := func(reason string) {
		t.Helper()
		res := e.step(name)
		r := e.run(name)
		c := legacyCondition(r)
		if c == nil || c.Status != metav1.ConditionFalse || c.Reason != reason || res.RequeueAfter != legacyMigrationRetry ||
			r.Status.Destination != nil || !controllerutil.ContainsFinalizer(r, RetentionFinalizer) || e.storageOps() != ops {
			t.Fatalf("want blocked %s: %+v %+v", reason, c, res)
		}
	}
	block(ReasonLegacyNoDestination)
	// A destination at the same location without a legacy declaration is
	// never matched by location or name.
	_ = e.c.Create(context.Background(), func() *v1alpha1.EvidenceDestination {
		ed := evidenceDestination("same-place", true)
		ed.Spec.S3.Endpoint, ed.Spec.S3.Prefix = "https://s3.example.internal", "konstapel"
		return ed
	}())
	block(ReasonLegacyNoDestination)
	e.legacyDestination(t, "primary", "uid-primary", "legacy", "konstapel")
	block(ReasonLegacyConfiguration) // no preserved configuration yet
	e.preserveLegacy(t, "us-east-1") // the destination says eu-north-1
	block(ReasonLegacyLocationMismatch)
	if c := legacyCondition(e.run(name)); !strings.Contains(c.Message, "region") {
		t.Fatalf("mismatch does not name the region: %s", c.Message)
	}
	e.preserveLegacy(t, "eu-north-1")
	e.step(name)
	r := e.run(name)
	pin := r.Status.Destination
	if pin == nil || pin.UID != "uid-primary" || pin.Source != v1alpha1.DestinationMigrated || pin.Legacy == nil || pin.Legacy.DestinationID != "legacy" ||
		r.Labels[LabelRunDestination] != "uid-primary" || legacyCondition(r).Status != metav1.ConditionTrue {
		t.Fatalf("not migrated: %+v labels %v", pin, r.Labels)
	}
	ed := &v1alpha1.EvidenceDestination{}
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: "primary"}, ed)
	if !controllerutil.ContainsFinalizer(ed, DestinationFinalizer) {
		t.Fatal("destination holds no finalizer for the migrated run")
	}
	if !equality.Semantic.DeepEqual(r.Status.Publication, receipt) {
		t.Fatalf("receipt rewritten:\n%s\n%s", mustJSON(receipt), mustJSON(r.Status.Publication))
	}
	// Idempotent: a later reconcile keeps the recorded association.
	e.step(name)
	if again := e.run(name).Status.Destination; !equality.Semantic.DeepEqual(again, pin) {
		t.Fatalf("association changed: %+v", again)
	}
	// Retention finishes through the destination: expiry deletes and
	// releases the record.
	e.now = receipt.ExpiresAt.Add(time.Second)
	e.step(name)
	if got := e.run(name).Status.Publication; got.Cleanup.State != v1alpha1.CleanupState(publication.CleanupDeleted) || e.pub.Calls(fake.OpDelete) != 1 {
		t.Fatalf("expiry after migration: %+v", got.Cleanup)
	}
}

// Two destinations declaring the same legacy ID block migration; neither is
// chosen.
func TestLegacyMigrationRefusesAmbiguity(t *testing.T) {
	e, name := legacyEnv(t)
	e.preserveLegacy(t, "eu-north-1")
	e.legacyDestination(t, "primary", "uid-primary", "legacy", "konstapel")
	e.legacyDestination(t, "secondary", "uid-secondary", "legacy", "konstapel")
	e.step(name)
	r := e.run(name)
	if c := legacyCondition(r); c == nil || c.Reason != ReasonLegacyAmbiguous || r.Status.Destination != nil || r.Labels[LabelRunDestination] != "" {
		t.Fatalf("ambiguous legacy destination resolved: %+v %v", c, r.Labels)
	}
}

// A legacy run without a receipt either stored nothing yet (collecting: it
// ends so a new run can start) or may own attempts at an unknown location
// (publishing: it stays blocked with its finalizer).
func TestLegacyRunsWithoutReceipt(t *testing.T) {
	b := epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{CollectionTimeout: "5m"}
	e := newRunEnv(t, b)
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name) // collecting under the legacy publisher
	e.rr.Runtime.Publisher = nil
	e.rr.Runtime.Destinations = &DestinationPublishers{Reader: e.c}
	publishing := e.run(name).DeepCopy()
	e.step(name)
	if r := e.run(name); r.Status.Phase != v1alpha1.RunFailed {
		t.Fatalf("interrupted legacy run: %s", r.Status.Phase)
	}
	// The same run as if it had reached Publishing before the upgrade.
	p := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "legacy-publishing", Finalizers: []string{RetentionFinalizer}}, Spec: publishing.Spec}
	if err := e.c.Create(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	p.Status = publishing.Status
	p.Status.Phase = v1alpha1.RunPublishing
	if err := e.c.Status().Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	e.step(p.Name)
	r := e.run(p.Name)
	if c := legacyCondition(r); c == nil || c.Reason != ReasonLegacyReceiptMissing || r.Status.Phase != v1alpha1.RunPublishing || !controllerutil.ContainsFinalizer(r, RetentionFinalizer) {
		t.Fatalf("publishing legacy run without receipt: %+v %s", c, r.Status.Phase)
	}
}
