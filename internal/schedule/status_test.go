package schedule

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/crdtest"
)

// Persisted state survives a restart: planning from the restored state makes
// the same decision as planning from the in-memory state.
func TestStatusRoundTripPreservesDecisions(t *testing.T) {
	s := newSim(t, time.Hour)
	s.step(t0, false)
	for i := 1; i <= 14; i++ {
		s.step(t0.Add(time.Duration(3*i)*time.Hour), true)
	}
	persisted := ToStatus(s.st, t0.Add(48*time.Hour), "run-uid")
	b, _ := json.Marshal(persisted)
	var decoded v1alpha1.AssessmentSchedule
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	restored, err := FromStatus(&decoded)
	if err != nil {
		t.Fatal(err)
	}
	now := t0.Add(50 * time.Hour)
	a := Plan(Input{Now: now, BindingName: s.name, BindingUID: s.uid, Interval: s.every, State: s.st, ActiveDone: true})
	r := Plan(Input{Now: now, BindingName: s.name, BindingUID: s.uid, Interval: s.every, State: restored, ActiveDone: true})
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(r)
	if string(x) != string(y) {
		t.Fatalf("restart changed the decision:\n%s\n%s", x, y)
	}
	if len(decoded.Gaps) != MaxGaps {
		t.Fatalf("persisted %d gaps", len(decoded.Gaps))
	}
}

func TestPersistedScheduleFitsCRD(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	s := newSim(t, time.Hour)
	s.step(t0, false)
	for i := 1; i <= 14; i++ {
		s.step(t0.Add(time.Duration(3*i)*time.Hour), true)
	}
	b := v1alpha1.ComplianceBinding{Spec: v1alpha1.ComplianceBindingSpec{ProfileRef: v1alpha1.ProfileReference{Name: "p"}, Mode: v1alpha1.ModeAudit, NamespaceSelector: &v1alpha1.NamespaceSelector{}}}
	b.APIVersion, b.Kind, b.Name = v1alpha1.GroupVersion.String(), "ComplianceBinding", "b"
	b.Status.Assessment = &v1alpha1.BindingAssessmentStatus{Schedule: ToStatus(s.st, t0, "run-uid")}
	raw, _ := json.Marshal(b)
	var o map[string]any
	_ = json.Unmarshal(raw, &o)
	if errs := crds["ComplianceBinding"].Validate(o); len(errs) > 0 {
		t.Fatal(errs.ToAggregate())
	}
	if _, err := FromStatus(&v1alpha1.AssessmentSchedule{Interval: "nonsense"}); err == nil {
		t.Fatal("invalid persisted interval accepted")
	}
}
