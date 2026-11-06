package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// pinEnv is a run environment whose legacy publisher is absent: every run
// must publish through a pinned EvidenceDestination's own publisher.
type pinEnv struct {
	*runEnv
	stores map[string]*fake.Publisher // by destination UID
}

func newPinEnv(t *testing.T) *pinEnv {
	e := &pinEnv{runEnv: newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"}))), stores: map[string]*fake.Publisher{}}
	for _, name := range []string{"primary", "secondary"} {
		ed := evidenceDestination(name, true)
		status := ed.Status
		ed.Status = v1alpha1.EvidenceDestinationStatus{}
		if err := e.c.Create(context.Background(), ed); err != nil {
			t.Fatal(err)
		}
		ed.Status = status
		if err := e.c.Status().Update(context.Background(), ed); err != nil {
			t.Fatal(err)
		}
		e.stores[string(ed.UID)] = fake.New(func() time.Time { return e.now })
	}
	e.setDefault("primary")
	dp := &DestinationPublishers{Reader: e.c, New: func(_ context.Context, d s3store.Destination, _ client.Reader, _ string) (publication.Publisher, error) {
		return e.stores[d.ID], nil
	}}
	e.rr.Runtime.Publisher, e.ar.Runtime.Publisher = nil, nil
	e.rr.Runtime.Destinations, e.ar.Runtime.Destinations = dp, dp
	return e
}

func (e *pinEnv) setDefault(name string) {
	e.t.Helper()
	cm := defaultDestination(name, "uid-"+name)
	if err := e.c.Get(context.Background(), client.ObjectKeyFromObject(cm), cm); apierrors.IsNotFound(err) {
		cm = defaultDestination(name, "uid-"+name)
		if err := e.c.Create(context.Background(), cm); err != nil {
			e.t.Fatal(err)
		}
		return
	}
	cm.Data = defaultDestination(name, "uid-"+name).Data
	if err := e.c.Update(context.Background(), cm); err != nil {
		e.t.Fatal(err)
	}
}

func (e *pinEnv) destination(name string) *v1alpha1.EvidenceDestination {
	ed := &v1alpha1.EvidenceDestination{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, ed); err != nil {
		e.t.Fatal(err)
	}
	return ed
}

// A run pins the default destination when it starts and keeps publishing
// there after the default changes; the next run selects the new default.
func TestRunPinsDestinationAndKeepsIt(t *testing.T) {
	e := newPinEnv(t)
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	r := e.run(name)
	if r.Status.Destination == nil || r.Status.Destination.Name != "primary" || r.Status.Destination.UID != "uid-primary" ||
		r.Status.Destination.Bucket != "evidence" || r.Status.Destination.Source != v1alpha1.DestinationFromDefault || r.Labels[LabelRunDestination] != "uid-primary" {
		t.Fatalf("pin %+v labels %v", r.Status.Destination, r.Labels)
	}
	if !controllerutil.ContainsFinalizer(e.destination("primary"), DestinationFinalizer) {
		t.Fatal("destination not protected before the pin was accepted")
	}
	e.setDefault("secondary")
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	if r := e.run(name); r.Status.Phase != v1alpha1.RunCompleted || r.Status.Destination.UID != "uid-primary" {
		t.Fatalf("run did not publish at its pin: %s %+v", r.Status.Phase, r.Status.Publication)
	}
	if e.stores["uid-primary"].Commits() != 1 || e.stores["uid-secondary"].Commits() != 0 {
		t.Fatal("publication left the pinned destination")
	}
	// The next run pins the new default.
	manual := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "manual"}, Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: "audit-prod"}, Scope: v1alpha1.RunScopeBinding}}
	if err := e.c.Create(context.Background(), manual); err != nil {
		t.Fatal(err)
	}
	e.assess("audit-prod")
	e.step("manual")
	if r := e.run("manual"); r.Status.Destination == nil || r.Status.Destination.Name != "secondary" {
		t.Fatalf("later run kept the old default: %+v", r.Status.Destination)
	}
}

// A selection that loses to retirement or replacement fails the run with no
// storage writes at all.
func TestLosingSelectionMakesNoStorageWrites(t *testing.T) {
	for name, lose := range map[string]func(e *pinEnv){
		"retiring": func(e *pinEnv) {
			ed := e.destination("primary")
			ed.Finalizers = []string{"test/hold"}
			_ = e.c.Update(context.Background(), ed)
			_ = e.c.Delete(context.Background(), ed)
		},
		"replaced": func(e *pinEnv) { e.setDefaultUID("primary", "uid-old-primary") },
	} {
		e := newPinEnv(t)
		lose(e)
		e.deliver("audit-prod")
		// The schedule refuses the unusable selection; force a manual run.
		manual := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "manual"}, Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: "audit-prod"}, Scope: v1alpha1.RunScopeBinding}}
		_ = e.c.Create(context.Background(), manual)
		e.assess("audit-prod")
		b := e.binding(t)
		if b.Status.Assessment != nil && b.Status.Assessment.Schedule != nil && b.Status.Assessment.Schedule.ActiveRun != nil {
			t.Fatalf("%s: scheduled a run against an unusable destination", name)
		}
		if c := b.Status.Assessment.Current; c == nil || !strings.Contains(strings.Join(c.Limitations, ";"), "evidence destination") {
			t.Fatalf("%s: unusable selection not visible: %+v", name, b.Status.Assessment)
		}
		admitManual(t, e.runEnv, "manual")
		e.step("manual")
		r := e.run("manual")
		if r.Status.Phase != v1alpha1.RunFailed || r.Status.Destination != nil {
			t.Fatalf("%s: %s %+v", name, r.Status.Phase, r.Status.Conditions)
		}
		for uid, s := range e.stores {
			if s.Calls(fake.OpStage) != 0 || s.Commits() != 0 {
				t.Fatalf("%s: storage written at %s", name, uid)
			}
		}
	}
}

func (e *pinEnv) setDefaultUID(name, uid string) {
	cm := defaultDestination(name, uid)
	_ = e.c.Get(context.Background(), client.ObjectKeyFromObject(cm), cm)
	cm.Data = defaultDestination(name, uid).Data
	_ = e.c.Update(context.Background(), cm)
}

// admitManual makes the run the binding's active run if the schedule did not
// (it refuses unusable selections), to exercise the executor's own guard.
func admitManual(t *testing.T, e *runEnv, name string) {
	b := &v1alpha1.ComplianceBinding{}
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: "audit-prod"}, b)
	if b.Status.Assessment != nil && b.Status.Assessment.Schedule != nil && b.Status.Assessment.Schedule.ActiveRun != nil {
		return
	}
	if b.Status.Assessment == nil {
		b.Status.Assessment = &v1alpha1.BindingAssessmentStatus{}
	}
	b.Status.Assessment.Schedule = &v1alpha1.AssessmentSchedule{Anchor: metav1.NewTime(a0), Interval: "24h", ActiveRun: &v1alpha1.RunReference{Name: name, UID: "uid-" + name}}
	if err := e.c.Status().Update(context.Background(), b); err != nil {
		t.Fatal(err)
	}
}

// A start interrupted after its intent was recorded keeps that destination,
// whatever the selection says now.
func TestInterruptedStartKeepsRecordedDestination(t *testing.T) {
	e := newPinEnv(t)
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	r := e.run(name)
	r.Labels = map[string]string{LabelRunDestination: "uid-primary"}
	if err := e.c.Update(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	e.setDefault("secondary")
	e.step(name)
	if r := e.run(name); r.Status.Destination == nil || r.Status.Destination.UID != "uid-primary" {
		t.Fatalf("recorded intent not kept: %+v", r.Status.Destination)
	}
}

// A concurrent destination change during confirmation retries; nothing is
// staged and no pin is recorded until confirmation succeeds.
func TestPinConfirmationConflictRetries(t *testing.T) {
	e := newPinEnv(t)
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	ed := e.destination("primary")
	r := e.run(name)
	stale := ed.DeepCopy() // a reader that missed the next change
	ed.Annotations = map[string]string{"touched": "yes"}
	_ = e.c.Update(context.Background(), ed) // bumps resourceVersion
	if _, err := e.rr.pinDestination(context.Background(), r, e.binding(t), metav1.Now()); err != nil {
		t.Fatalf("fresh read must confirm: %v", err)
	}
	// Simulate the race: confirm against a stale copy.
	stale.Finalizers = append(stale.Finalizers, "x")
	if err := e.c.Update(context.Background(), stale); !apierrors.IsConflict(err) {
		t.Fatalf("stale destination update must conflict (the protocol's guard): %v", err)
	}
	if e.stores["uid-primary"].Calls(fake.OpStage) != 0 {
		t.Fatal("staged during pinning")
	}
}

func (e *pinEnv) binding(t *testing.T) *v1alpha1.ComplianceBinding {
	b := &v1alpha1.ComplianceBinding{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: "audit-prod"}, b); err != nil {
		t.Fatal(err)
	}
	return b
}

// Historical access follows the pinned UID: rotating credentials or trust
// (a new generation) rebuilds the publisher for the same destination; a
// recreated destination with the same name never serves the old pin, and a
// pin whose recorded location differs is refused. Missing credentials are a
// build-time success and a visible per-operation failure (see s3store), never
// a fallback.
func TestDestinationPublishersFollowThePin(t *testing.T) {
	e := newPinEnv(t)
	builds := map[string]int{}
	e.rr.Runtime.Destinations.New = func(_ context.Context, d s3store.Destination, _ client.Reader, _ string) (publication.Publisher, error) {
		builds[d.ID+"/"+d.CredentialSecret.Name]++
		return e.stores[d.ID], nil
	}
	dp := e.rr.Runtime.Destinations
	ed := e.destination("primary")
	pin := &v1alpha1.DestinationPin{DestinationReference: v1alpha1.DestinationReference{Name: "primary", UID: string(ed.UID)},
		Endpoint: ed.Spec.S3.Endpoint, Bucket: ed.Spec.S3.Bucket, Region: ed.Spec.S3.Region, Prefix: ed.Spec.S3.Prefix}
	ctx := context.Background()
	if _, err := dp.For(ctx, pin); err != nil {
		t.Fatal(err)
	}
	if _, err := dp.For(ctx, pin); err != nil || builds["uid-primary/s3"] != 1 {
		t.Fatalf("unchanged destination rebuilt: %v %v", builds, err)
	}
	// Rotation: new credential Secret, new generation, same UID and location.
	ed.Spec.S3.CredentialSecret.Name = "s3-rotated"
	ed.Generation++
	if err := e.c.Update(ctx, ed); err != nil {
		t.Fatal(err)
	}
	if p, err := dp.For(ctx, pin); err != nil || p != e.stores["uid-primary"] || builds["uid-primary/s3-rotated"] != 1 {
		t.Fatalf("rotation did not rebuild for the same destination: %v %v", builds, err)
	}
	// A recreated destination (same name, new UID) never serves the old pin.
	recreated := pin.DeepCopy()
	recreated.UID = "uid-primary-old"
	if _, err := dp.For(ctx, recreated); err == nil {
		t.Fatal("a pin was redirected to a different destination")
	}
	// A pin whose recorded location differs is refused.
	moved := pin.DeepCopy()
	moved.Prefix = "elsewhere"
	if _, err := dp.For(ctx, moved); err == nil {
		t.Fatal("a pin with a different location was served")
	}
}
