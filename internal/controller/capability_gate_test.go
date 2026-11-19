package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/capability"
	"github.com/backend-bunny/Konstapel/internal/targeting"
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

// An unavailable delivery capability is an assessment limitation with its
// reason, not a reconcile failure.
func TestAssessmentWithUnavailableEngine(t *testing.T) {
	e := newRunEnv(t, epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"}))
	e.deliver("audit-prod")
	e.ar.Engine = unavailable(capability.AccessDenied, "PolicyDelivery: the service account may not list validatingpolicies.policies.kyverno.io")
	e.assess("audit-prod")
	cur := e.current("audit-prod")
	if !strings.Contains(strings.Join(cur.Limitations, ";"), "PolicyDelivery: the service account may not list validatingpolicies.policies.kyverno.io; no engine policies or reports can be read") ||
		cur.Evidence.Completeness == "Complete" {
		t.Fatalf("limitations %v completeness %s", cur.Limitations, cur.Evidence.Completeness)
	}
}

// Unavailable reports cannot establish compliance (add-helm-oci-distribution
// 4.3). A passing, attributable report is in the cluster, but whatever the
// assessment capability's reason, it is never read: current evidence stays
// incomplete without a pass, the active run keeps collecting and closes
// Incomplete at its timeout with no pass counted, and policy delivery, an
// independent capability, still reconciles and keeps the applied policy.
// Once reports are available again the same report is evidence, so the
// capability gate, not the report, withheld compliance.
func TestUnavailableReportsCannotEstablishCompliance(t *testing.T) {
	for _, reason := range []capability.Reason{capability.APINotServed, capability.ResourceMissing,
		capability.UnsupportedResource, capability.AccessDenied, capability.Unavailable} {
		t.Run(string(reason), func(t *testing.T) {
			e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
			e.deliver("audit-prod")
			policy := e.enginePolicy()
			applied := policyVersion(t, e)
			e.assess("audit-prod")
			name := e.schedule("audit-prod").ActiveRun.Name
			e.step(name)

			e.ar.Reports = unavailable(reason, "Assessment: "+string(reason))
			e.report("prod", "pod-1", policy, "pass", a0.Add(time.Minute))
			e.now = a0.Add(90 * time.Second)
			if e.step(name); e.run(name).Status.Phase != v1alpha1.RunCollecting {
				t.Fatalf("run closed on unreadable reports: %+v", e.run(name).Status)
			}
			e.assess("audit-prod")
			cur := e.current("audit-prod")
			if cur.Evidence.Completeness == "Complete" || cur.Outcomes.Pass != 0 ||
				!strings.Contains(strings.Join(cur.Limitations, ";"), "policy reports unavailable: Assessment: "+string(reason)) {
				t.Fatalf("current evidence without reports: %+v %+v %v", cur.Evidence, cur.Outcomes, cur.Limitations)
			}

			e.now = a0.Add(5*time.Minute + time.Second)
			e.step(name)
			r := e.run(name)
			if r.Status.Phase != v1alpha1.RunCompleted || r.Status.Summary == nil ||
				r.Status.Summary.Evidence.Completeness != "Incomplete" || r.Status.Summary.Outcomes.Pass != 0 {
				t.Fatalf("run without reports: %+v", r.Status)
			}

			// Delivery is independent: it reconciles and the policy stays.
			e.deliver("audit-prod")
			b := &v1alpha1.ComplianceBinding{}
			if err := e.c.Get(context.Background(), client.ObjectKey{Name: "audit-prod"}, b); err != nil {
				t.Fatal(err)
			}
			if c := meta.FindStatusCondition(b.Status.Conditions, v1alpha1.ConditionEngineReady); c == nil || c.Status != metav1.ConditionTrue {
				t.Fatalf("delivery affected by the assessment capability: %+v", c)
			}
			if got := policyVersion(t, e); got != applied {
				t.Fatalf("applied policy changed: %s, want %s", got, applied)
			}

			// Control: the same report is evidence once reports are readable.
			e.ar.Reports = nil
			e.assess("audit-prod")
			if cur = e.current("audit-prod"); cur.Evidence.Completeness != "Complete" || cur.Outcomes.Pass != 1 {
				t.Fatalf("report not evidence with the capability restored: %+v %+v", cur.Evidence, cur.Outcomes)
			}
		})
	}
}

// policyVersion is the single applied engine policy's name and resource
// version.
func policyVersion(t *testing.T, e *runEnv) string {
	t.Helper()
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(targeting.ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
	if err := e.c.List(context.Background(), list); err != nil || len(list.Items) != 1 {
		t.Fatalf("want one engine policy: %v", err)
	}
	return list.Items[0].GetName() + "@" + list.Items[0].GetResourceVersion()
}
