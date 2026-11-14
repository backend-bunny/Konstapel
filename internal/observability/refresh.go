package observability

import (
	"context"
	"errors"
	"time"

	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// DefaultRefreshInterval is how often owners republish without an event.
// It is well inside DefaultMaxAge, so one late refresh does not cost
// readiness while a stalled owner still loses it.
const DefaultRefreshInterval = 30 * time.Second

// Refresher republishes one owner domain from synchronized owner state:
// once synchronized, on every Trigger and at Interval. A failure to read
// that state withdraws the domain's projection instead of keeping an old
// one alive. It runs only on the elected leader and only publishes for
// the Hub's current leadership term.
type Refresher struct {
	Name   string
	Hub    *Hub
	Domain Domain
	// Interval defaults to DefaultRefreshInterval.
	Interval time.Duration
	// Retry is how soon to look again while the Hub's term has not started;
	// it defaults to one second.
	Retry time.Duration
	// Synced blocks until the owner's state is synchronized and reports
	// whether it is; nil means it always is.
	Synced func(ctx context.Context) bool
	// Publish reads the owner's state and publishes it for term t as
	// produced at now.
	Publish func(ctx context.Context, t Term, now time.Time) error
	// Trigger requests an early refresh; nil uses Interval only.
	Trigger <-chan struct{}
	// Clock defaults to the real clock.
	Clock clock.WithTicker
}

// NeedLeaderElection implements manager.LeaderElectionRunnable.
func (*Refresher) NeedLeaderElection() bool { return true }

// Start implements manager.Runnable.
func (r *Refresher) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName(r.Name)
	clk := r.Clock
	if clk == nil {
		clk = clock.RealClock{}
	}
	interval, retry := r.Interval, r.Retry
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	if retry <= 0 {
		retry = time.Second
	}
	if r.Synced != nil && !r.Synced(ctx) {
		return nil
	}
	for {
		wait := interval
		if t, ok := r.Hub.Term(); !ok {
			wait = retry
		} else if err := r.Publish(ctx, t, clk.Now()); err != nil && !errors.Is(err, ErrNotLeading) {
			logger.Info("owner state unavailable; projection withdrawn", "domain", r.Domain, "error", err.Error())
			_ = r.Hub.Withdraw(t, r.Domain)
		}
		timer := clk.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-r.Trigger:
		case <-timer.C():
		}
		timer.Stop()
	}
}

// Notifier returns a coalescing trigger channel and the function that
// signals it without blocking.
func Notifier() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	return ch, func() {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
