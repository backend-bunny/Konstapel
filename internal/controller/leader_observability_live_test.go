//go:build live

package controller

// Live leadership transitions of the observability projections
// (add-controller-high-availability 2.5), in-process against the disposable
// cluster with the real Lease election and the manager's own owner
// refreshers. Two candidates share the Lease, each with its own Hub; both
// Hubs are sampled every 25ms throughout:
//   - the follower exposes no owner series while it is not elected;
//   - when the leader loses the Lease (another holder takes it), its Hub
//     clears every owner projection, a delayed write for its old term is
//     refused, nothing reappears, and the manager exits;
//   - the successor never exposes a ready domain without the state it
//     summarizes (no partial or empty "ready" projection) and, once ready,
//     exposes the same binding series the former leader did, rebuilt from
//     the API rather than remembered;
//   - at no sample do both Hubs expose owner projections, and the
//     successor's Hub clears when it stops.
// The election, clearing and reconstruction times are recorded. The
// Helm-installed equivalent through Prometheus is TestLiveHelmMonitoring
// (leader killed, no leader).
// Run through scripts/targeting-live.sh.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/observability"
)

// ownerSeries reports the owner-projection series in s: anything but the
// enabled flags, readiness 0 and process counters.
func ownerSeries(s map[string]float64) []string {
	var out []string
	for k, v := range s {
		switch {
		case strings.HasPrefix(k, "konstapel_observation_enabled"):
		case strings.HasPrefix(k, "konstapel_observation_ready") && v == 0:
		case strings.HasPrefix(k, "konstapel_operation_"):
		default:
			out = append(out, k)
		}
	}
	return out
}

func bindingSeries(s map[string]float64, binding string) map[string]float64 {
	out := map[string]float64{}
	for k, v := range s {
		if strings.Contains(k, fmt.Sprintf("binding=%q", binding)) {
			out[k] = v
		}
	}
	return out
}

// partial names a domain that is ready while the state it summarizes is
// missing from its projection.
func partial(s map[string]float64, binding string) string {
	has := func(prefix string) bool {
		for k := range s {
			if strings.HasPrefix(k, prefix) {
				return true
			}
		}
		return false
	}
	ready := func(d string) bool { return s[fmt.Sprintf("konstapel_observation_ready{domain=%q}", d)] == 1 }
	switch {
	case ready("targeting") && !has(fmt.Sprintf("konstapel_binding_target_namespaces{binding=%q}", binding)):
		return "targeting"
	case ready("assessment") && !has(fmt.Sprintf("konstapel_binding_assessment_status{binding=%q", binding)):
		return "assessment"
	case ready("evidence_storage") && !has("konstapel_publication_failed{"):
		return "evidence_storage"
	}
	return ""
}

func ownersReady(s map[string]float64) bool {
	for _, d := range []string{"targeting", "assessment", "evidence_storage"} {
		if s[fmt.Sprintf("konstapel_observation_ready{domain=%q}", d)] != 1 {
			return false
		}
	}
	return true
}

func TestLiveLeaderObservability(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	const ns, binding = "konstapel-system", "lo-audit"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	_ = l.c.Delete(l.ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: LeaderElectionID}})
	l.setNamespace("lo-prod", "lo-production")
	p := profileObj(t, "lo-baseline", pol)
	b := bindingObj(binding, p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "lo-production"})
	for _, o := range []client.Object{p, b} {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = l.c.Delete(context.Background(), b)
		_ = l.c.Delete(context.Background(), p)
		_ = l.c.Delete(context.Background(), &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: LeaderElectionID}})
	})

	hub := func() *observability.Hub {
		h, err := observability.NewHub(observability.Options{Enabled: []observability.Domain{observability.DomainTargeting, observability.DomainAssessment, observability.DomainEvidenceStorage}})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	hubA, hubB := hub(), hub()
	with := func(h *observability.Hub) func(*Options) {
		return func(o *Options) {
			o.Observability = h
			o.Election = Election{LeaseDuration: 6 * time.Second, RenewDeadline: 4 * time.Second, RetryPeriod: time.Second}
		}
	}
	a := l.candidateWith("", "lo-candidate-a", with(hubA))
	aStopped := false
	t.Cleanup(func() {
		if !aStopped {
			a.stop()
		}
	})
	l.eventually("candidate A elected", func() (bool, string) { return a.elected(), "" })
	bb := l.candidateWith("", "lo-candidate-b", with(hubB))
	bStopped := false
	t.Cleanup(func() {
		if !bStopped {
			bb.stop()
		}
	})
	l.waitReady(binding, 1)
	var before map[string]float64
	l.eventually("the leader's projections ready with the binding", func() (bool, string) {
		s := liveSeries(t, hubA)
		before = bindingSeries(s, binding)
		return ownersReady(s) && partial(s, binding) == "" && len(before) > 0, fmt.Sprint(s)
	})
	termA, ok := hubA.Term()
	if !ok {
		t.Fatal("the leader's Hub has no term")
	}

	// Sample both Hubs. Election is monotonic: a candidate that is not
	// elected after a sample was not elected during it. At no sample may
	// both Hubs expose owner projections.
	var (
		mu                      sync.Mutex
		violations              []string
		bElectedAt, bReadyAt    time.Time
		aClearedAt              time.Time
		bReadyValues            map[string]float64
		stolen                  time.Time
		samples                 int
		stopSampling, samplerOK = make(chan struct{}), make(chan struct{})
	)
	go func() {
		defer close(samplerOK)
		for {
			select {
			case <-stopSampling:
				return
			case <-time.After(25 * time.Millisecond):
			}
			sa, sb := liveSeries(t, hubA), liveSeries(t, hubB)
			eb, now := bb.elected(), time.Now()
			mu.Lock()
			samples++
			if !eb && len(ownerSeries(sb)) > 0 {
				violations = append(violations, fmt.Sprintf("follower B exposes %v", ownerSeries(sb)))
			}
			if d := partial(sb, binding); d != "" {
				violations = append(violations, "successor B ready without its state: "+d)
			}
			if d := partial(sa, binding); d != "" {
				violations = append(violations, "leader A ready without its state: "+d)
			}
			if eb && bElectedAt.IsZero() {
				bElectedAt = now
			}
			if eb && bReadyAt.IsZero() && ownersReady(sb) {
				bReadyAt, bReadyValues = now, bindingSeries(sb, binding)
			}
			if !stolen.IsZero() {
				switch owned := ownerSeries(sa); {
				case len(owned) == 0 && aClearedAt.IsZero():
					aClearedAt = now
				case len(owned) > 0 && !aClearedAt.IsZero():
					violations = append(violations, fmt.Sprintf("former leader A exposes %v again", owned))
				}
			}
			if len(ownerSeries(sa)) > 0 && len(ownerSeries(sb)) > 0 {
				violations = append(violations, "both replicas expose owner projections")
			}
			mu.Unlock()
		}
	}()
	stopSampler := func() {
		select {
		case <-stopSampling:
		default:
			close(stopSampling)
			<-samplerOK
		}
	}
	t.Cleanup(stopSampler)
	time.Sleep(3 * time.Second) // B synchronized and contending, still a follower

	// The leader loses the Lease: another holder takes it for one lease
	// duration, after which B can acquire it.
	other, six := "lo-another-replica", int32(6)
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		lease := &coordinationv1.Lease{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: LeaderElectionID}, lease); err != nil {
			return err
		}
		now := metav1.NewMicroTime(time.Now())
		lease.Spec.HolderIdentity, lease.Spec.LeaseDurationSeconds, lease.Spec.AcquireTime, lease.Spec.RenewTime = &other, &six, &now, &now
		return l.c.Update(l.ctx, lease)
	}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	stolen = time.Now()
	mu.Unlock()
	select {
	case err := <-a.done:
		aStopped = true
		if err == nil || !strings.Contains(err.Error(), "leader election lost") {
			t.Fatalf("former leader exited with %v", err)
		}
	case <-time.After(time.Minute):
		t.Fatal("the former leader kept running")
	}
	exited := time.Since(stolen)
	// The leader context is cancelled during the manager's stop; the
	// projections are gone at the latest just after it returns.
	for deadline := time.Now().Add(2 * time.Second); len(ownerSeries(liveSeries(t, hubA))) > 0; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the former leader still exposes %v", ownerSeries(liveSeries(t, hubA)))
		}
	}
	// An owner write still in flight for the old term is refused.
	if err := hubA.PublishTargeting(termA, time.Now(), observability.TargetingSnapshot{}); !errors.Is(err, observability.ErrNotLeading) {
		t.Fatalf("a delayed write for the former term: %v", err)
	}
	if owned := ownerSeries(liveSeries(t, hubA)); len(owned) > 0 {
		t.Fatalf("a delayed write reappeared: %v", owned)
	}

	l.eventually("successor B elected and reconstructed", func() (bool, string) {
		mu.Lock()
		defer mu.Unlock()
		return !bReadyAt.IsZero(), fmt.Sprint(bindingSeries(liveSeries(t, hubB), binding))
	})
	l.eventually("successor's binding series equal the former leader's", func() (bool, string) {
		got := bindingSeries(liveSeries(t, hubB), binding)
		return fmt.Sprint(got) == fmt.Sprint(before), fmt.Sprint(got) + " want " + fmt.Sprint(before)
	})
	time.Sleep(2 * time.Second)
	stopSampler()
	mu.Lock()
	defer mu.Unlock()
	if len(violations) > 0 {
		t.Fatalf("%d violations, first: %s", len(violations), violations[0])
	}
	if aClearedAt.IsZero() {
		t.Fatal("the sampler never saw the former leader cleared")
	}
	if missing := len(before) - len(bReadyValues); missing != 0 {
		t.Fatalf("the successor's first ready projection lacks %d binding series: %v", missing, bReadyValues)
	}

	bb.stop()
	bStopped = true
	if owned := ownerSeries(liveSeries(t, hubB)); len(owned) > 0 {
		t.Fatalf("the stopped successor still exposes %v", owned)
	}
	l.record("leader-observability", map[string]any{
		"samples": samples, "violations": 0, "bindingSeries": len(before),
		"formerLeaderClearedAfterSeconds": aClearedAt.Sub(stolen).Seconds(), "formerLeaderExitedAfterSeconds": exited.Seconds(),
		"successorElectedAfterSeconds": bElectedAt.Sub(stolen).Seconds(), "successorReadyAfterElectionSeconds": bReadyAt.Sub(bElectedAt).Seconds(),
		"leaseDuration": "6s", "delayedWrite": "ErrNotLeading",
	})
}
