package controller

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/capability"
)

// Every binding is re-reconciled when a capability result changes (an
// engine appears, disappears, or its permissions change), and only then.
func TestCapabilityTriggerEnqueuesBindingsOnChange(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(Scheme()).WithObjects(
		bindingObj("a", "baseline", v1alpha1.ModeAudit, nil), bindingObj("b", "baseline", v1alpha1.ModeAudit, nil)).Build()
	var reason atomic.Value
	reason.Store(capability.Available)
	check := func(context.Context) (bool, error) {
		r := reason.Load().(capability.Reason)
		if r == capability.Available {
			return true, nil
		}
		return false, &capability.Error{Result: capability.Result{Reason: r, Message: string(r)}}
	}
	out := make(chan event.GenericEvent, 16)
	trig := &capabilityTrigger{name: "test", client: c, checks: []EngineAvailable{check}, out: []chan<- event.GenericEvent{out}, poll: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = trig.Start(ctx) }()
	drain := func(want int, within time.Duration) {
		t.Helper()
		got := 0
		deadline := time.After(within)
		for {
			select {
			case <-out:
				got++
			case <-deadline:
				if got != want {
					t.Fatalf("got %d binding events, want %d", got, want)
				}
				return
			}
		}
	}
	drain(2, 200*time.Millisecond) // initial state
	drain(0, 100*time.Millisecond) // unchanged: nothing
	reason.Store(capability.AccessDenied)
	drain(2, 200*time.Millisecond)
	reason.Store(capability.Available)
	drain(2, 200*time.Millisecond)
}
