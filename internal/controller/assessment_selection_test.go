package controller

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// otherBundle is a selection the binding's profile could change to.
var otherBundle = v1alpha1.BundleReference{Name: "other-bundle", Digest: "sha256:" + strings.Repeat("b", 64)}

// startedSelectionRun creates and starts the binding's scheduled run (frozen at a0).
func startedSelectionRun(t *testing.T) (*runEnv, string) {
	t.Helper()
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	if r := e.run(name); r.Status.Phase != v1alpha1.RunCollecting {
		t.Fatalf("not collecting: %+v", r.Status)
	}
	return e, name
}

// selectBundle sets the binding's profile selection.
func (e *runEnv) selectBundle(ref v1alpha1.BundleReference) {
	e.t.Helper()
	p := &v1alpha1.ComplianceProfile{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: "baseline"}, p); err != nil {
		e.t.Fatal(err)
	}
	p.Spec.Bundle = ref
	if err := e.c.Update(context.Background(), p); err != nil {
		e.t.Fatal(err)
	}
}

func (e *runEnv) frozenBundle() v1alpha1.BundleReference {
	return v1alpha1.BundleReference{Name: content.Name, Digest: digest(e.t)}
}

func TestNoSelectionChangeRecordsNothing(t *testing.T) {
	e, name := startedSelectionRun(t)
	e.now = a0.Add(30 * time.Second)
	e.step(name)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted {
		t.Fatalf("not completed: %+v", r.Status)
	}
	if r.Status.ObservedSelectionChange != nil {
		t.Fatalf("recorded a change none was made: %+v", r.Status.ObservedSelectionChange)
	}
}

func TestObservedSelectionChangeIsRecordedOnce(t *testing.T) {
	e, name := startedSelectionRun(t)
	frozen := e.frozenBundle()
	staged := func() []byte {
		b, err := os.ReadFile(filepath.Join(e.rr.staging(e.run(name)), runSelectionFile))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	before := staged()

	e.selectBundle(otherBundle)
	observedAt := a0.Add(30 * time.Second)
	e.now = observedAt
	e.step(name)
	r := e.run(name)
	got := r.Status.ObservedSelectionChange
	if got == nil || !got.ObservedTime.Time.Equal(observedAt) || got.Frozen == nil || *got.Frozen != frozen ||
		got.Observed == nil || *got.Observed != otherBundle {
		t.Fatalf("observed change %+v", got)
	}
	if r.Status.Phase != v1alpha1.RunCollecting {
		t.Fatalf("the observation changed the run's lifecycle: %s", r.Status.Phase)
	}
	if !bytes.Equal(staged(), before) {
		t.Fatal("the frozen selection record changed")
	}
	recorded := r.ResourceVersion

	// A further change, a revert and more observations neither rewrite
	// the record nor write status again.
	third := v1alpha1.BundleReference{Name: "third-bundle", Digest: "sha256:" + strings.Repeat("c", 64)}
	for i, ref := range []v1alpha1.BundleReference{third, frozen, otherBundle} {
		e.selectBundle(ref)
		e.now = observedAt.Add(time.Duration(i+1) * 30 * time.Second)
		e.step(name)
		r = e.run(name)
		if r.ResourceVersion != recorded || r.Status.ObservedSelectionChange == nil || *r.Status.ObservedSelectionChange.Observed != otherBundle ||
			!r.Status.ObservedSelectionChange.ObservedTime.Time.Equal(observedAt) {
			t.Fatalf("observation %d rewrote the run (%s -> %s): %+v", i, recorded, r.ResourceVersion, r.Status.ObservedSelectionChange)
		}
	}
	if !bytes.Equal(staged(), before) {
		t.Fatal("the frozen selection record changed")
	}

	// Closing keeps the record and the run's frozen selection.
	e.selectBundle(frozen)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	r = e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted || r.Status.ObservedSelectionChange == nil || !r.Status.ObservedSelectionChange.ObservedTime.Time.Equal(observedAt) {
		t.Fatalf("closed run %+v", r.Status)
	}
	// The published package names the frozen selection, never the
	// observed one.
	rc, _, err := e.pub.Open(context.Background(), publication.RunRef{ClusterID: r.Status.Scope.ClusterID, BindingUID: r.Status.Binding.UID, RunUID: string(r.UID)})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(archive, []byte(otherBundle.Name)) || bytes.Contains(archive, []byte(strings.TrimPrefix(otherBundle.Digest, "sha256:"))) {
		t.Fatal("the package names the observed selection")
	}
}

func TestSelectionChangeRevertedBetweenObservationsIsNotClaimed(t *testing.T) {
	e, name := startedSelectionRun(t)
	e.selectBundle(otherBundle)
	e.selectBundle(e.frozenBundle())
	e.now = a0.Add(30 * time.Second)
	e.step(name)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	if r := e.run(name); r.Status.Phase != v1alpha1.RunCompleted || r.Status.ObservedSelectionChange != nil {
		t.Fatalf("claimed an unobserved change: %+v", r.Status)
	}
}

func TestRemovedProfileIsObservedAsNoSelection(t *testing.T) {
	e, name := startedSelectionRun(t)
	if err := e.c.Delete(context.Background(), &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "baseline"}}); err != nil {
		t.Fatal(err)
	}
	e.now = a0.Add(30 * time.Second)
	e.step(name)
	got := e.run(name).Status.ObservedSelectionChange
	if got == nil || got.Frozen == nil || got.Observed != nil {
		t.Fatalf("observed change %+v", got)
	}
}

// A run whose frozen bundle is unknown (staged by an earlier controller)
// records nothing: no change is inferred.
func TestUnknownFrozenSelectionRecordsNothing(t *testing.T) {
	e, name := startedSelectionRun(t)
	r := e.run(name)
	rec, err := e.rr.readSelection(r)
	if err != nil {
		t.Fatal(err)
	}
	rec.Bundle = nil
	if err := assessment.Write(filepath.Join(e.rr.staging(r), runSelectionFile), rec); err != nil {
		t.Fatal(err)
	}
	e.selectBundle(otherBundle)
	e.now = a0.Add(30 * time.Second)
	e.step(name)
	if got := e.run(name).Status.ObservedSelectionChange; got != nil {
		t.Fatalf("inferred a change: %+v", got)
	}
}
