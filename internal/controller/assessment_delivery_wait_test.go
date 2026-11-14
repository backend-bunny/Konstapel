package controller

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// A scheduled run planned before targeting delivered the binding's engine
// policies waits instead of freezing them as stale scope, and starts with
// the full scope once they are delivered (the CI race behind flaky
// TestLiveIntegratedAssessments and TestLiveHardeningBackground).
func TestRunWaitsForEnginePolicyDelivery(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.assess("audit-prod") // plans the initial run; nothing is delivered yet
	name := e.schedule("audit-prod").ActiveRun.Name

	res := e.step(name)
	r := e.run(name)
	if res.RequeueAfter <= 0 || r.Status.Phase != "" && r.Status.Phase != v1alpha1.RunPending || r.Status.Scope != nil {
		t.Fatalf("run froze before delivery: requeue %v phase %q scope %+v", res.RequeueAfter, r.Status.Phase, r.Status.Scope)
	}
	if _, err := os.Stat(filepath.Join(e.rr.staging(r), "capture.json")); !os.IsNotExist(err) {
		t.Fatal("a capture was staged before delivery")
	}

	e.deliver("audit-prod")
	e.now = a0.Add(10 * time.Second)
	e.step(name)
	r = e.run(name)
	if r.Status.Phase != v1alpha1.RunCollecting || r.Status.Scope == nil || r.Status.Scope.NamespaceCount != 1 {
		t.Fatalf("run did not start with the delivered scope: %+v", r.Status)
	}
	if c := e.staged(r); len(c.Stale) != 0 || len(c.Expected) != 1 {
		t.Fatalf("frozen capture: stale %+v expected %d", c.Stale, len(c.Expected))
	}
}

// The wait is bounded by the collection timeout: a policy that never
// arrives still yields an honest incomplete run, never none.
func TestDeliveryWaitIsBounded(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.now = a0.Add(4 * time.Minute)
	if res := e.step(name); res.RequeueAfter <= 0 || res.RequeueAfter > time.Minute {
		t.Fatalf("wait before the bound: %+v", res)
	}
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunCollecting || r.Status.Scope == nil {
		t.Fatalf("run never started after the bound: %+v", r.Status)
	}
	c := e.staged(r)
	if len(c.Stale) == 0 || c.Stale[0].Reason != reasonEngineNotDelivered {
		t.Fatalf("undelivered policy not recorded as stale scope: %+v", c.Stale)
	}
}
