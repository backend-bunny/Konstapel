package controller

import (
	"context"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/capability"
)

func unavailable(reason capability.Reason, msg string) EngineAvailable {
	return func(context.Context) (bool, error) {
		return false, &capability.Error{Result: capability.Result{Reason: reason, Message: msg}}
	}
}

// EngineReady names the precise delivery capability failure, and an outage
// keeps already applied engine policies in place.
func TestDeliveryCapabilityReasons(t *testing.T) {
	e := newEnv(t, nsObj("prod"), profileObj(t, "baseline", pol), bindingObj("all", "baseline", v1alpha1.ModeAudit, nil))
	e.reconcile("all")
	if len(e.policies()) != 1 {
		t.Fatal("setup: policy not delivered")
	}
	for reason, want := range map[capability.Reason]string{
		capability.APINotServed:        ReasonEngineAPINotServed,
		capability.ResourceMissing:     ReasonEngineResourceMissing,
		capability.UnsupportedResource: ReasonEngineUnsupported,
		capability.AccessDenied:        ReasonEngineAccessDenied,
		capability.Unavailable:         ReasonEngineUnavailable,
	} {
		e.r.Engine = unavailable(reason, "PolicyDelivery: "+string(reason))
		if res := e.reconcile("all"); res.RequeueAfter == 0 {
			t.Fatalf("%s: not retried", reason)
		}
		requireNotCurrent(t, e.binding("all"), want)
		if len(e.policies()) != 1 {
			t.Fatalf("%s: applied policies removed during the outage", reason)
		}
	}
}

// Without policy reports the assessment is never complete, the reason is
// shown, scheduling is disabled, and delivery is unaffected.
func TestAssessmentCapabilityGate(t *testing.T) {
	e := newRunEnv(t, epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"}))
	e.deliver("audit-prod")
	e.ar.Reports = unavailable(capability.AccessDenied, "Assessment: the service account may not watch policyreports.wgpolicyk8s.io")
	e.assess("audit-prod")
	cur := e.current("audit-prod")
	joined := strings.Join(cur.Limitations, ";")
	if !strings.Contains(joined, "policy reports unavailable: Assessment: the service account may not watch") ||
		!strings.Contains(joined, "scheduled snapshots are disabled: policy reports are unavailable") {
		t.Fatalf("limitations: %v", cur.Limitations)
	}
	if cur.Evidence.Completeness == "Complete" {
		t.Fatal("missing reports reported complete evidence")
	}
	var runs v1alpha1.AssessmentRunList
	_ = e.c.List(context.Background(), &runs)
	if len(runs.Items) != 0 {
		t.Fatal("a snapshot was scheduled without reports")
	}
	// Reports return: scheduling resumes.
	e.ar.Reports = nil
	e.assess("audit-prod")
	if s := e.schedule("audit-prod"); s.ActiveRun == nil {
		t.Fatal("scheduling did not resume with reports available")
	}
}
