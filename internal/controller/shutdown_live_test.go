//go:build live

package controller

// Live shutdown and leadership loss (add-controller-high-availability 2.3,
// 4.4) against the disposable cluster:
//   - once termination begins, readiness fails while the process drains;
//   - a runnable that ignores cancellation cannot hold shutdown past the
//     configured budget;
//   - when another holder takes the Lease, the leader's work is cancelled
//     and the manager exits within the renew deadline instead of
//     continuing as an unelected process. (The controller runs no C2P child
//     processes; only the CLI does.)
// Run through scripts/targeting-live.sh.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

type leaderRunnable struct{ cancelled chan time.Time }

func (r *leaderRunnable) NeedLeaderElection() bool { return true }
func (r *leaderRunnable) Start(ctx context.Context) error {
	<-ctx.Done()
	r.cancelled <- time.Now()
	return nil
}

func TestLiveBoundedShutdown(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	const ns = "konstapel-system"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})

	// 1. Readiness fails once termination begins; a stuck runnable cannot
	// hold the process past the 3s budget.
	probe := freeAddr(t)
	var stopping atomic.Bool
	mgr, err := NewManager(l.cfg, Options{Content: content, MetricsAddr: "0", ProbeAddr: probe, EnginePoll: 2 * time.Second, SkipControllerNameValidation: true,
		ShutdownTimeout: 3 * time.Second, Stopping: stopping.Load})
	if err != nil {
		t.Fatal(err)
	}
	_ = mgr.Add(manager.RunnableFunc(func(context.Context) error { select {} })) // ignores cancellation
	ctx, cancel := context.WithCancel(l.ctx)
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	ready := func() int {
		resp, err := http.Get("http://" + probe + "/readyz")
		if err != nil {
			return 0
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	l.eventually("ready", func() (bool, string) { return ready() == http.StatusOK, "" })
	stopping.Store(true)
	l.eventually("unready while stopping", func() (bool, string) { return ready() == http.StatusInternalServerError, "" })
	begin := time.Now()
	cancel()
	var stopErr error
	select {
	case stopErr = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("a stuck runnable held shutdown open")
	}
	took := time.Since(begin)
	if took > 8*time.Second {
		t.Fatalf("shutdown took %s with a 3s budget", took)
	}
	l.record("bounded-shutdown", map[string]any{"budget": "3s", "seconds": took.Seconds(), "readyWhileStopping": false, "result": fmt.Sprint(stopErr)})

	// 2. Leadership loss: another holder takes the Lease. The leader's work
	// is cancelled and the manager exits with an error within the renew
	// deadline.
	lead, err := NewManager(l.cfg, Options{Content: content, MetricsAddr: "0", ProbeAddr: "0", EnginePoll: 2 * time.Second, SkipControllerNameValidation: true,
		LeaderElection: true, LeaderElectionNamespace: ns, Election: Election{LeaseDuration: 6 * time.Second, RenewDeadline: 4 * time.Second, RetryPeriod: time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	work := &leaderRunnable{cancelled: make(chan time.Time, 1)}
	_ = lead.Add(work)
	lctx, lcancel := context.WithCancel(l.ctx)
	defer lcancel()
	ldone := make(chan error, 1)
	go func() { ldone <- lead.Start(lctx) }()
	select {
	case <-lead.Elected():
	case <-time.After(time.Minute):
		t.Fatal("not elected")
	}
	t.Cleanup(func() {
		_ = l.c.Delete(l.ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: LeaderElectionID}})
	})
	lease := &coordinationv1.Lease{}
	l.eventually("lease held", func() (bool, string) {
		err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: LeaderElectionID}, lease)
		return err == nil && lease.Spec.HolderIdentity != nil, ""
	})
	other, long := "another-replica", int32(3600)
	now := metav1.NewMicroTime(time.Now())
	lease.Spec.HolderIdentity, lease.Spec.LeaseDurationSeconds, lease.Spec.AcquireTime, lease.Spec.RenewTime = &other, &long, &now, &now
	if err := l.c.Update(l.ctx, lease); err != nil {
		t.Fatal(err)
	}
	stolen := time.Now()
	select {
	case at := <-work.cancelled:
		if d := at.Sub(stolen); d > 10*time.Second {
			t.Fatalf("leader work ran %s after losing the Lease", d)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("leader work not cancelled after losing the Lease")
	}
	select {
	case err := <-ldone:
		if err == nil || !strings.Contains(err.Error(), "leader election lost") {
			t.Fatalf("manager after leadership loss: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the former leader kept running")
	}
	l.record("leadership-loss", map[string]any{"cancelledWithin": time.Since(stolen).Seconds(), "exit": "leader election lost"})
}
