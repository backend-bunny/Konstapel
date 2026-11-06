package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
)

// publishingRun returns a run held in Publishing (stage failures) for a
// binding whose retention is 720h.
func publishingRun(t *testing.T) (*runEnv, string) {
	b := epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{CollectionTimeout: "5m", Retention: "720h"}
	e := newRunEnv(t, b)
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	e.pub.Fail(fake.OpStage, publication.ErrUnavailable)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	if r := e.run(name); r.Status.Phase != v1alpha1.RunPublishing || r.Status.Retention != "720h0m0s" {
		t.Fatalf("setup: %s retention %q", r.Status.Phase, r.Status.Retention)
	}
	return e, name
}

func TestDeletedBindingPublishesWithRecordedRetention(t *testing.T) {
	e, name := publishingRun(t)
	if err := e.c.Delete(context.Background(), &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "audit-prod"}}); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Minute)
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted || r.Status.Publication.Retention == nil || r.Status.Publication.Retention.Duration != "720h0m0s" ||
		!strings.Contains(r.Status.Publication.Retention.BindingConfiguration, "recorded at closure") {
		t.Fatalf("deleted binding: %s %+v", r.Status.Phase, r.Status.Publication)
	}
}

func TestReplacedBindingIsNotAdopted(t *testing.T) {
	e, name := publishingRun(t)
	_ = e.c.Delete(context.Background(), &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "audit-prod"}})
	replacement := epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})
	replacement.UID = types.UID("uid-audit-prod-2")
	replacement.Spec.Assessment = &v1alpha1.BindingAssessment{Retention: "24h"}
	if err := e.c.Create(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Minute)
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted || r.Status.Publication.Retention.Duration != "720h0m0s" {
		t.Fatalf("replacement binding's retention adopted: %+v", r.Status.Publication.Retention)
	}
}

func TestRetentionReadAtFirstCommit(t *testing.T) {
	e, name := publishingRun(t)
	b := &v1alpha1.ComplianceBinding{}
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: "audit-prod"}, b)
	b.Spec.Assessment.Retention = "48h"
	if err := e.c.Update(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(time.Minute)
	e.step(name)
	if r := e.run(name); r.Status.Phase != v1alpha1.RunCompleted || r.Status.Publication.Retention.Duration != "48h0m0s" {
		t.Fatalf("first commit did not use the binding's current retention: %+v", r.Status.Publication.Retention)
	}
}

func TestNotReadyBackendDisablesScheduling(t *testing.T) {
	e := newRunEnv(t, epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"}))
	e.deliver("audit-prod")
	ready := errors.New("conditional create overwrote an existing key (If-None-Match: * not enforced)")
	e.ar.Runtime.Ready = func(context.Context) error { return ready }
	e.ar.Runtime.ReadyInterval = time.Nanosecond
	e.assess("audit-prod")
	if cur := e.current("audit-prod"); !strings.Contains(strings.Join(cur.Limitations, ";"), "evidence backend is not ready: conditional create") {
		t.Fatalf("not-ready backend not surfaced: %v", cur.Limitations)
	}
	if len(e.runs()) != 0 {
		t.Fatal("runs created against a backend that is not ready")
	}
	ready = nil
	e.assess("audit-prod")
	if len(e.runs()) != 1 {
		t.Fatal("scheduling did not resume once the backend was ready")
	}
}
