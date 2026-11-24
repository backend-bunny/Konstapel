package controller

import (
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/rest"

	"github.com/backend-bunny/Konstapel/internal/provider"
)

func TestElectionTimings(t *testing.T) {
	if err := (Election{}).withDefaults().Validate(); err != nil {
		t.Fatalf("defaults rejected: %v", err)
	}
	if d := (Election{}).withDefaults(); d.LeaseDuration != 15*time.Second || d.RenewDeadline != 10*time.Second || d.RetryPeriod != 2*time.Second {
		t.Fatalf("defaults %+v", d)
	}
	for name, c := range map[string]struct {
		e    Election
		want string
	}{
		"negative":           {Election{LeaseDuration: -time.Second, RenewDeadline: 10 * time.Second, RetryPeriod: 2 * time.Second}, "positive"},
		"lease not > renew":  {Election{LeaseDuration: 10 * time.Second, RenewDeadline: 10 * time.Second, RetryPeriod: 2 * time.Second}, "must exceed the renew deadline"},
		"renew not > jitter": {Election{LeaseDuration: 15 * time.Second, RenewDeadline: 2 * time.Second, RetryPeriod: 2 * time.Second}, "1.2 x the retry period"},
	} {
		if err := c.e.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Invalid timings fail before startup; election is never disabled instead.
	_, err := NewManager(&rest.Config{Host: "https://127.0.0.1:1"}, Options{LeaderElection: true, Election: Election{LeaseDuration: 5 * time.Second}})
	if err == nil || !strings.Contains(err.Error(), "must exceed the renew deadline") {
		t.Fatalf("manager accepted invalid timings: %v", err)
	}
}

// Revocation processing is confined only by the exception webhooks this
// manager serves, so it is refused without them.
func TestRevocationProcessingNeedsTheWebhooks(t *testing.T) {
	_, err := NewManager(&rest.Config{Host: "https://127.0.0.1:1"}, Options{ExceptionRevocation: true})
	if err == nil || !strings.Contains(err.Error(), "--webhook-cert-dir") {
		t.Fatalf("revocation processing without webhooks accepted: %v", err)
	}
}

func TestShutdownTimeoutValidated(t *testing.T) {
	_, err := NewManager(&rest.Config{Host: "https://127.0.0.1:1"}, Options{ShutdownTimeout: -time.Second})
	if err == nil || !strings.Contains(err.Error(), "shutdown timeout") {
		t.Fatalf("negative shutdown timeout accepted: %v", err)
	}
}

// Background workers that act on the cluster run only on the elected
// leader (add-controller-high-availability 2.2). controller-runtime starts
// and syncs the caches before leader election, and every controller here
// is leader-elected by default, so a leader never acts on an unsynced view.
func TestBackgroundWorkersNeedLeadership(t *testing.T) {
	for name, r := range map[string]manager.LeaderElectionRunnable{
		"deferred engine watch": &deferredWatch{},
		"capability trigger":    &capabilityTrigger{},
	} {
		if !r.NeedLeaderElection() {
			t.Errorf("%s runs on followers", name)
		}
	}
}

// Configured collection limits are checked before startup, never clamped.
func TestCollectionLimitsValidated(t *testing.T) {
	_, err := NewManager(&rest.Config{Host: "https://127.0.0.1:1"}, Options{CollectionLimits: provider.Limits{PageSize: 500, MaxPages: 20_000, MaxObjects: 100, MaxBytes: 1 << 30}})
	if err == nil || !strings.Contains(err.Error(), "collection limits: --collection-page-size 500 must not exceed --collection-max-objects 100") {
		t.Fatalf("invalid collection limits accepted: %v", err)
	}
}
