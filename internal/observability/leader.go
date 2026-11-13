package observability

import "context"

// Leadership is a leader-elected manager runnable bounding the Hub's
// leadership term by the manager's existing election: the term starts when
// the manager elects this replica and ends, clearing every owner
// projection, as soon as the leader context is cancelled.
type Leadership struct{ Hub *Hub }

// NeedLeaderElection implements manager.LeaderElectionRunnable.
func (Leadership) NeedLeaderElection() bool { return true }

// Start implements manager.Runnable.
func (l Leadership) Start(ctx context.Context) error {
	t := l.Hub.Acquire()
	<-ctx.Done()
	l.Hub.Release(t)
	return nil
}
