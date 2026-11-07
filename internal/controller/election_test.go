package controller

import (
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/rest"
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

func TestShutdownTimeoutValidated(t *testing.T) {
	_, err := NewManager(&rest.Config{Host: "https://127.0.0.1:1"}, Options{ShutdownTimeout: -time.Second})
	if err == nil || !strings.Contains(err.Error(), "shutdown timeout") {
		t.Fatalf("negative shutdown timeout accepted: %v", err)
	}
}
