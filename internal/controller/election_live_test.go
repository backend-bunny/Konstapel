//go:build live

package controller

// Live leader election (add-controller-high-availability 2.1): candidates
// share the namespace-local Lease konstapel-controller-leader-election.
//   - two managers started together elect exactly one leader, and the
//     leader stays the leader;
//   - when the leader stops, the other takes over and reconciles;
//   - a candidate without Lease access never leads and never reconciles;
//     election is not bypassed, and granting access lets it lead.
// Run through scripts/targeting-live.sh.

import (
	"context"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

type candidate struct {
	mgr    manager.Manager
	cancel context.CancelFunc
	done   chan error
}

func (c *candidate) elected() bool {
	select {
	case <-c.mgr.Elected():
		return true
	default:
		return false
	}
}

func (c *candidate) stop() {
	c.cancel()
	<-c.done
}

// candidateAs starts an elected manager, impersonating user when set.
func (l *live) candidateAs(user string) *candidate {
	l.t.Helper()
	cfg := rest.CopyConfig(l.cfg)
	if user != "" {
		cfg.Impersonate = rest.ImpersonationConfig{UserName: user, UID: "uid-" + user, Groups: []string{"system:authenticated"}}
	}
	mgr, err := NewManager(cfg, Options{Content: content, MetricsAddr: "0", ProbeAddr: "0", EnginePoll: 2 * time.Second, SkipControllerNameValidation: true,
		LeaderElection: true, LeaderElectionNamespace: "konstapel-system"})
	if err != nil {
		l.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(l.ctx)
	c := &candidate{mgr: mgr, cancel: cancel, done: make(chan error, 1)}
	go func() { c.done <- mgr.Start(ctx) }()
	return c
}

func TestLiveLeaderElection(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	const ns = "konstapel-system"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	holder := func() string {
		lease := &coordinationv1.Lease{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: LeaderElectionID}, lease); err != nil || lease.Spec.HolderIdentity == nil {
			return ""
		}
		return *lease.Spec.HolderIdentity
	}
	l.setNamespace("le-prod", "le-production")
	p := profileObj(t, "le-baseline", pol)
	b := bindingObj("le-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "le-production"})
	for _, o := range []client.Object{p, b} {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = l.c.Delete(l.ctx, b)
		_ = l.c.Delete(l.ctx, p)
		_ = l.c.Delete(l.ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: LeaderElectionID}})
	})

	// 1. Simultaneous candidates: exactly one leader, and it stays.
	a, bb := l.candidateAs(""), l.candidateAs("")
	var leader, follower *candidate
	l.eventually("one candidate elected", func() (bool, string) {
		switch {
		case a.elected() && !bb.elected():
			leader, follower = a, bb
		case bb.elected() && !a.elected():
			leader, follower = bb, a
		case a.elected() && bb.elected():
			t.Fatal("both candidates elected")
		}
		return leader != nil, holder()
	})
	first := holder()
	for i := 0; i < 10; i++ {
		time.Sleep(2 * time.Second)
		if follower.elected() || holder() != first {
			t.Fatalf("leadership changed without a failure: holder %q -> %q", first, holder())
		}
	}
	l.waitReady(b.Name, 1)
	l.record("elected", map[string]any{"holder": first})

	// 2. The leader stops (the Lease is not released early): the follower
	// takes over once it expires and reconciles a new generation.
	leader.stop()
	start := time.Now()
	l.eventually("follower takes over", func() (bool, string) { return follower.elected(), holder() })
	takeover := time.Since(start)
	if h := holder(); h == first || h == "" {
		t.Fatalf("Lease holder after takeover: %q", h)
	}
	got := l.binding(b.Name)
	got.Spec.Mode = v1alpha1.ModeDeny
	if err := l.c.Update(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	l.waitReady(b.Name, 1)
	follower.stop()
	l.record("takeover", map[string]any{"holder": holder(), "seconds": takeover.Seconds()})

	// 3. A candidate whose identity may not use the Lease never leads and
	// never reconciles; granting access lets it lead.
	l.applyManifests("../../config/rbac/controller/role.yaml", nil)
	const user = "konstapel-live-no-lease"
	l.bind("konstapel-live-no-lease", user, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-controller"}, "")
	denied := l.candidateAs(user)
	defer denied.stop()
	got = l.binding(b.Name)
	got.Spec.Mode = v1alpha1.ModeAudit
	if err := l.c.Update(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Second) // well past the previous Lease's expiry
	if denied.elected() {
		t.Fatal("a candidate without Lease access was elected")
	}
	if cur := l.binding(b.Name); cur.Status.ObservedGeneration == cur.Generation {
		t.Fatal("a candidate without Lease access reconciled")
	}
	l.bind("konstapel-live-no-lease", user, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "konstapel-controller"}, ns)
	l.eventually("granted candidate elected", func() (bool, string) { return denied.elected(), holder() })
	l.waitReady(b.Name, 1)
	l.record("lease-access", map[string]any{"withoutAccess": "never elected, no reconcile", "granted": "elected"})
}
