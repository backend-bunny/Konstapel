package controller

import (
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/observability"
)

// add-evidence-signing-recovery 3.1: the recovery request gauge and the
// storage backlog of retained signing failures.

const (
	recoveryRequestsMetric = "konstapel_evidence_signing_recovery_requests"
	retainedMetric         = "konstapel_publication_retained_signing_failures{}"
)

// recoveryRequests returns the request gauge's series, failing on any
// series outside the fixed phase/reason vocabulary.
func recoveryRequests(t *testing.T, m map[string]float64) map[string]float64 {
	t.Helper()
	allowed := map[string]bool{}
	for _, s := range observability.RecoveryStates() {
		allowed[fmt.Sprintf("%s{phase=%q,reason=%q}", recoveryRequestsMetric, s.Phase, s.Reason)] = true
	}
	out := map[string]float64{}
	for k, v := range m {
		if !strings.HasPrefix(k, recoveryRequestsMetric+"{") {
			continue
		}
		if !allowed[k] {
			t.Fatalf("series %s is outside the phase/reason vocabulary", k)
		}
		out[k] = v
	}
	if len(out) != len(allowed) {
		t.Fatalf("%d request series, want every allowed phase/reason pair (%d)", len(out), len(allowed))
	}
	return out
}

// wantRequests checks the request gauge: the named pairs have their
// counts, every other allowed pair is a known zero.
func wantRequests(t *testing.T, m map[string]float64, want map[[2]string]float64) {
	t.Helper()
	for k, v := range recoveryRequests(t, m) {
		var w float64
		for pr, n := range want {
			if k == fmt.Sprintf("%s{phase=%q,reason=%q}", recoveryRequestsMetric, pr[0], pr[1]) {
				w = n
			}
		}
		if v != w {
			t.Errorf("%s = %v, want %v", k, v, w)
		}
	}
}

// A retained signing failure is one failed publication (and one retained
// signing failure) until recovery publishes it; the recovered run is then
// a committed package, counted once, and past its (unchanged) expiry one
// pending cleanup. The request
// gauge follows the requests' recorded status, keeps terminal requests,
// and is rebuilt from the records by a restarted or new leader.
func TestSigningRecoveryObservability(t *testing.T) {
	e := newRecoveryEnv(t)
	m := storageMetrics(t, e.runEnv)
	if b := backlog(m); b != [4]float64{0, 1, 0, 0} || m[retainedMetric] != 1 {
		t.Fatalf("a retained SigningFailed run before its expiry is one failed publication: %v retained %v", b, m[retainedMetric])
	}
	wantRequests(t, m, nil)

	// Unaccepted requests record no phase and are not counted.
	_, fp := e.installKey("pw-b")
	e.requestKey("holder", e.name, e.uid(), fp)
	e.request("late", e.name, e.uid())
	wantRequests(t, storageMetrics(t, e.runEnv), nil)

	e.reconcile("holder")
	e.reconcile("late")
	m = storageMetrics(t, e.runEnv)
	wantRequests(t, m, map[[2]string]float64{{"Pending", "Accepted"}: 1, {"Pending", "Waiting"}: 1})
	if b := backlog(m); b != [4]float64{0, 1, 0, 0} || m[retainedMetric] != 1 {
		t.Fatalf("a run under recovery stays one failed publication until it is published: %v retained %v", b, m[retainedMetric])
	}

	e.now = e.now.Add(2 * time.Minute)
	e.reconcile("holder")
	e.wantRecovered("holder", v1alpha1.RecoveryRecovered, "holder")
	e.reconcile("late")
	e.wantSucceeded("late", v1alpha1.RecoveryAlreadyRecovered)
	e.requestKey("unknown-run", "missing", "00000000-0000-0000-0000-0000000000ff", fp)
	e.reconcile("unknown-run")
	m = storageMetrics(t, e.runEnv)
	recovered := map[[2]string]float64{{"Succeeded", "Recovered"}: 1, {"Succeeded", "AlreadyRecovered"}: 1, {"Failed", "RunNotFound"}: 1}
	wantRequests(t, m, recovered)
	if b := backlog(m); b != [4]float64{} || m[retainedMetric] != 0 {
		t.Fatalf("a recovered run before its expiry is still counted: %v retained %v", b, m[retainedMetric])
	}

	// A new leader (or a restarted controller) rebuilds the same gauges.
	before := maps.Clone(m)
	e.restart()
	if after := storageMetrics(t, e.runEnv); !maps.Equal(recoveryRequests(t, after), recoveryRequests(t, before)) || backlog(after) != backlog(before) || after[retainedMetric] != before[retainedMetric] {
		t.Fatalf("after restart:\n%v\n%v", after, before)
	}

	// Past the recorded expiry the recovered package is one pending cleanup,
	// not a retained failure as well.
	expires := e.run_().Status.Publication.ExpiresAt.Time
	if !expires.Equal(e.failed.Publication.ExpiresAt.Time) {
		t.Fatalf("recovery changed the expiry: %s -> %s", e.failed.Publication.ExpiresAt, expires)
	}
	e.now = expires.Add(time.Second)
	m = storageMetrics(t, e.runEnv)
	if b := backlog(m); b != [4]float64{0, 0, 1, 0} || m[retainedMetric] != 0 || m["konstapel_cleanup_oldest_expiry_timestamp_seconds{}"] != float64(expires.Unix()) {
		t.Fatalf("expired recovered package: %v oldest %v", b, m["konstapel_cleanup_oldest_expiry_timestamp_seconds{}"])
	}
	wantRequests(t, m, recovered)
}

// Retained signing failures share the package lifecycle: until their expiry
// they are failed publications; past it they are pending cleanup until the deletion is confirmed, and a confirmed
// deletion leaves no backlog. A request for an expired run ends Expired.
func TestRetainedSigningFailureCleanupBacklog(t *testing.T) {
	e := newRecoveryEnv(t)
	expires := e.failed.Publication.ExpiresAt.Time
	e.now = expires.Add(-time.Second)
	if m := storageMetrics(t, e.runEnv); backlog(m) != [4]float64{0, 1, 0, 0} || m[retainedMetric] != 1 {
		t.Fatalf("retained failure just before expiry: %v retained %v", backlog(m), m[retainedMetric])
	}
	e.now = expires.Add(time.Second)
	m := storageMetrics(t, e.runEnv)
	if b := backlog(m); b != [4]float64{0, 0, 1, 0} || m[retainedMetric] != 0 || m["konstapel_cleanup_oldest_expiry_timestamp_seconds{}"] != float64(expires.Unix()) {
		t.Fatalf("expired retained failure: %v oldest %v", b, m["konstapel_cleanup_oldest_expiry_timestamp_seconds{}"])
	}
	e.request("too-late", e.name, e.uid())
	e.reconcile("too-late")
	wantRequests(t, storageMetrics(t, e.runEnv), map[[2]string]float64{{"Failed", "Expired"}: 1})

	e.step(e.name)
	if r := e.run_(); !retainedSigningFailure(r) || r.Status.Publication.Cleanup.State != "Deleted" {
		t.Fatalf("retention did not delete the retained failure: %s", js(r.Status.Publication))
	}
	if b := backlog(storageMetrics(t, e.runEnv)); b != [4]float64{} {
		t.Fatalf("backlog after confirmed deletion: %v", b)
	}
}
