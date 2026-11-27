package observability

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// add-evidence-signing-recovery 3.1.

// The request gauge's labels are the API's fixed status vocabulary, pair
// for pair as the CRD enforces it.
func TestRecoveryVocabularyMatchesTheAPI(t *testing.T) {
	phases := []v1alpha1.SigningRequestPhase{v1alpha1.SigningRequestPending, v1alpha1.SigningRequestRunning, v1alpha1.SigningRequestSucceeded, v1alpha1.SigningRequestFailed}
	if len(phases) != len(v1alpha1.SigningRecoveryReasons) {
		t.Fatalf("the API has %d phases with reasons", len(v1alpha1.SigningRecoveryReasons))
	}
	var reasons, states []string
	for i, p := range phases {
		if RecoveryPhases[i] != string(p) {
			t.Errorf("phase %d = %s, want %s", i, RecoveryPhases[i], p)
		}
		for _, r := range v1alpha1.SigningRecoveryReasons[p] {
			reasons = append(reasons, string(r))
			states = append(states, string(p)+"/"+string(r))
		}
	}
	if !slices.Equal(RecoveryReasons, reasons) {
		t.Errorf("reasons %v, want %v", RecoveryReasons, reasons)
	}
	var got []string
	for _, s := range RecoveryStates() {
		got = append(got, s.Phase+"/"+s.Reason)
	}
	if !slices.Equal(got, states) {
		t.Errorf("states %v, want %v", got, states)
	}
}

func signingRequest(name string, phase v1alpha1.SigningRequestPhase, reason v1alpha1.SigningRecoveryReason) v1alpha1.EvidenceSigningRequest {
	r := v1alpha1.EvidenceSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: name}}
	r.Status.Phase, r.Status.Reason = phase, reason
	return r
}

// Requests are counted by their recorded status alone; unaccepted requests
// and pairs outside the vocabulary are not counted.
func TestRecoveryRequestsFrom(t *testing.T) {
	got := RecoveryRequestsFrom([]v1alpha1.EvidenceSigningRequest{
		signingRequest("new", "", ""),
		signingRequest("a", v1alpha1.SigningRequestPending, v1alpha1.RecoveryAccepted),
		signingRequest("b", v1alpha1.SigningRequestPending, v1alpha1.RecoveryWaiting),
		signingRequest("c", v1alpha1.SigningRequestPending, v1alpha1.RecoveryWaiting),
		signingRequest("d", v1alpha1.SigningRequestSucceeded, v1alpha1.RecoveryRecovered),
		signingRequest("e", v1alpha1.SigningRequestFailed, v1alpha1.RecoverySigningFailed),
		signingRequest("mismatched", v1alpha1.SigningRequestFailed, v1alpha1.RecoveryRecovered),
		signingRequest("free-text", v1alpha1.SigningRequestFailed, "the key Secret was gone"),
	})
	want := map[RecoveryState]int{{"Pending", "Accepted"}: 1, {"Pending", "Waiting"}: 2, {"Succeeded", "Recovered"}: 1, {"Failed", "SigningFailed"}: 1}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("counts %v, want %v", got, want)
	}
	if s := (StorageSnapshot{RecoveryRequests: got}); s.validate() != nil {
		t.Error(s.validate())
	}
	if (StorageSnapshot{PublicationFailed: 1, RetainedSigningFailures: 2}).validate() == nil || (StorageSnapshot{RetainedSigningFailures: -1}).validate() == nil {
		t.Error("retained signing failures outside the failed publications accepted")
	}
	for _, bad := range []map[RecoveryState]int{{{"Failed", "Recovered"}: 1}, {{"Failed", "free text"}: 1}, {{"Pending", "Accepted"}: -1}} {
		if (StorageSnapshot{RecoveryRequests: bad}).validate() == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

// The gauge exposes every allowed pair as a known value while the storage
// projection is ready, nothing else, and nothing while it is not.
func TestRecoveryRequestGauge(t *testing.T) {
	const name = "konstapel_evidence_signing_recovery_requests"
	requests := func(got map[string]float64) map[string]float64 {
		out := map[string]float64{}
		for k, v := range got {
			if strings.HasPrefix(k, name+"{") {
				out[k] = v
			}
		}
		return out
	}
	h, clk := newHub(t, Domains...)
	term := h.Acquire()
	counts := map[RecoveryState]int{{"Running", "Signing"}: 2, {"Failed", "Expired"}: 1}
	mustOK(t, h.PublishStorage(term, t0, StorageSnapshot{RecoveryRequests: counts}))
	counts[RecoveryState{"Running", "Signing"}] = 9 // a published snapshot is immutable
	got := requests(scrape(t, h))
	if len(got) != len(RecoveryStates()) {
		t.Errorf("%d request series, want one per allowed pair (%d): %v", len(got), len(RecoveryStates()), got)
	}
	for _, st := range RecoveryStates() {
		k := fmt.Sprintf("%s{phase=%q,reason=%q}", name, st.Phase, st.Reason)
		want := map[RecoveryState]float64{{"Running", "Signing"}: 2, {"Failed", "Expired"}: 1}[st]
		if v, ok := got[k]; !ok || v != want {
			t.Errorf("%s = %v, %v; want %v", k, v, ok, want)
		}
	}

	// A stale projection, and one released on leadership loss, is absent,
	// not a zero.
	clk.SetTime(t0.Add(DefaultMaxAge + time.Second))
	if got := requests(scrape(t, h)); len(got) != 0 {
		t.Errorf("stale projection exposes %v", got)
	}
	clk.SetTime(t0)
	h.Release(term)
	if got := requests(scrape(t, h)); len(got) != 0 {
		t.Errorf("released projection exposes %v", got)
	}
}
