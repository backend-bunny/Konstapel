package external_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/external"
	"github.com/backend-bunny/Konstapel/internal/provider/external/externaltest"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

// stager is a test provider's Collector and Results behind the kit's
// Server over mutual TLS: every Collect stages doc.
type stager struct {
	mu       sync.Mutex
	doc      string
	requests []*providerv1.CollectRequest
	releases int
	// collect runs before staging; an error fails the Collect.
	collect func(context.Context) error
	// result runs before a staged result is returned; an error fails it.
	result func(context.Context) error
	// serve replaces the bytes served for a reference.
	serve func([]byte) []byte
}

func (s *stager) Collect(ctx context.Context, req *providerv1.CollectRequest) (*providerv1.ResultReference, error) {
	s.mu.Lock()
	s.requests = append(s.requests, proto.CloneOf(req))
	s.mu.Unlock()
	if s.collect != nil {
		if err := s.collect(ctx); err != nil {
			return nil, err
		}
	}
	return s.ref(), nil
}

func (s *stager) ref() *providerv1.ResultReference {
	return &providerv1.ResultReference{ResultId: "result-1", Provider: &providerv1.ProviderContract{Name: externaltest.Provider, Version: 1},
		PayloadVersion: 1, SizeBytes: uint64(len(s.doc)), Sha256: providerkit.Digest([]byte(s.doc)),
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)), Limitations: []string{"the source lists no archived workloads"}}
}

func (s *stager) Result(ctx context.Context, id string) (*providerv1.ResultReference, []byte, error) {
	if s.result != nil {
		if err := s.result(ctx); err != nil {
			return nil, nil, err
		}
	}
	data := []byte(s.doc)
	if s.serve != nil {
		data = s.serve(data)
	}
	return s.ref(), data, nil
}

// Evaluate is never called: collection does not evaluate.
func (s *stager) Evaluate(context.Context, *providerv1.EvaluateStart, []byte) (*providerkit.Evaluation, error) {
	return nil, errors.New("collection never evaluates")
}

func (s *stager) Release(context.Context, string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releases++
	return nil
}

// collection is one provider endpoint, its registration and the host's
// collection inputs.
type collection struct {
	w      *world
	srv    *externaltest.Server
	st     *stager
	ap     *v1alpha1.AssessmentProvider
	frozen external.Frozen
	inv    external.Inventory
	limits provider.Limits
}

const (
	nsA, nsB      = "6f1c7a52-0000-4000-8000-00000000000a", "6f1c7a52-0000-4000-8000-00000000000b"
	webA, webB    = "9a0e0001-0000-4000-8000-0000000000a1", "9a0e0001-0000-4000-8000-0000000000b1"
	ownerLabel    = "owner-label"
	imagePosture  = "image-posture"
	outsideUID    = "9a0e0001-0000-4000-8000-00000000ffff"
	providerKnows = "sibling-team-secret-name"
)

func testInventory() external.Inventory {
	return external.Inventory{
		Scope: provider.Scope{Cluster: "cluster-uid", Namespaces: []provider.Namespace{{Name: "team-a", UID: nsA}, {Name: "team-b", UID: nsB}}},
		Subjects: []external.Subject{
			{UID: nsA, NamespaceUID: nsA, Resource: providerkit.NamespaceResource, Name: "team-a", Revision: "rev-ns-a", Checks: []string{ownerLabel}},
			{UID: webA, NamespaceUID: nsA, Resource: "apps/v1/deployments", Name: "web", Revision: "rev-web-a", Checks: []string{imagePosture}},
			{UID: webB, NamespaceUID: nsB, Resource: "apps/v1/deployments", Name: "web", Revision: "rev-web-b", Checks: []string{imagePosture}},
		},
	}
}

func newCollection(t *testing.T, doc string, mutate ...func(*externaltest.ServerOptions)) *collection {
	t.Helper()
	c := &collection{w: newWorld(t), st: &stager{doc: doc}, ap: externaltest.Registration("reporting"), inv: testInventory(), limits: provider.DefaultLimits()}
	o := externaltest.ServerOptions{Handlers: &providerkit.Handlers{Collector: c.st, Results: c.st, Evaluator: c.st}}
	for _, m := range mutate {
		m(&o)
	}
	c.srv = c.w.serve(o)
	c.frozen = external.Expected(c.ap)
	c.w.dialer.Registration = func(_ context.Context, name string) (*v1alpha1.AssessmentProvider, error) {
		if name != c.ap.Name {
			return nil, nil
		}
		return c.ap.DeepCopy(), nil
	}
	return c
}

func (c *collection) run(t *testing.T, deadline time.Time) *external.Collection {
	t.Helper()
	got, err := external.Collect(context.Background(), c.w.dialer, c.frozen, c.inv, c.limits, deadline)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// wantStop requires an incomplete collection: no evidence, payload or
// capture, every expectation missing, and one bounded limitation.
func wantStop(t *testing.T, got *external.Collection, reason external.StopReason, contains string) {
	t.Helper()
	switch {
	case got.Stop == nil:
		t.Fatalf("collection is complete (%d evidence items), want %s", len(got.Evidence), reason)
	case got.Stop.Reason != reason || !strings.Contains(got.Stop.Message, contains):
		t.Fatalf("stopped %s: %s; want %s containing %q", got.Stop.Reason, got.Stop.Message, reason, contains)
	case got.Payload != nil || got.Capture != nil || got.Result != nil || len(got.Evidence) != 0 || len(got.Missing) != 0:
		t.Fatalf("an incomplete collection carries evidence: %+v", got)
	case len(got.Stop.Message) > 520 || !strings.HasPrefix(got.Stop.Limitation(got.Frozen.Contract()), "example-reporting/v1 evidence is not used"):
		t.Fatalf("limitation %q", got.Stop.Limitation(got.Frozen.Contract()))
	}
}

func evidence(id string, observed string, attributions ...[2]string) map[string]any {
	var at []map[string]string
	for _, a := range attributions {
		at = append(at, map[string]string{"subject": a[0], "check": a[1]})
	}
	return map[string]any{"id": id, "attributions": at, "observed": observed, "details": map[string]any{"note": providerKnows}}
}

func document(t *testing.T, doc map[string]any) string {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A collection is attributed against the host's frozen inventory: only
// items whose every attribution names an inventory subject and a check
// expected for it are evidence, a mixed-scope item is withheld whole, and
// what is not attributed stays missing.
func TestCollectAttributesAgainstTheFrozenInventory(t *testing.T) {
	doc := document(t, map[string]any{
		"evidence": []any{
			evidence("e-owner", "2026-11-27T10:00:00Z", [2]string{nsA, ownerLabel}),
			evidence("e-web-a", "2026-11-27T10:00:00Z", [2]string{webA, imagePosture}),
			evidence("e-mixed", "2026-11-27T10:00:00Z", [2]string{webA, imagePosture}, [2]string{outsideUID, imagePosture}),
			evidence("e-wrong-check", "2026-11-27T10:00:00Z", [2]string{webB, ownerLabel}),
		},
		"limitations": []any{
			map[string]string{"subject": webB, "message": "the registry of team-b's image is unreachable"},
			map[string]string{"subject": outsideUID, "message": "about " + providerKnows},
		},
	})
	c := newCollection(t, doc)
	got := c.run(t, time.Time{})
	if got.Stop != nil {
		t.Fatalf("stopped: %+v", got.Stop)
	}
	var ids []string
	for _, e := range got.Evidence {
		ids = append(ids, e.ID)
	}
	if !slices.Equal(ids, []string{"e-owner", "e-web-a"}) || got.Withheld != 2 {
		t.Fatalf("accepted %v, withheld %d", ids, got.Withheld)
	}
	want := []external.Missing{{Expectation: external.Expectation{Subject: webB, Check: imagePosture}, Limitation: "the registry of team-b's image is unreachable"}}
	if !slices.Equal(got.Missing, want) {
		t.Fatalf("missing %+v, want %+v", got.Missing, want)
	}
	var reasons []string
	for _, d := range got.Diagnostics {
		reasons = append(reasons, string(d.Reason)+" "+d.Item)
		if strings.Contains(d.Message, outsideUID) || strings.Contains(d.Message, providerKnows) || strings.Contains(d.Item, outsideUID) {
			t.Errorf("a diagnostic repeats provider-supplied data: %+v", d)
		}
	}
	if !slices.Equal(reasons, []string{"OutOfScope evidence[2]", "UnexpectedCheck evidence[3]", "OutOfScope limitations[1]"}) {
		t.Fatalf("diagnostics %v", reasons)
	}
	if !slices.Equal(got.Limitations, []string{"the source lists no archived workloads"}) {
		t.Fatalf("result limitations %v", got.Limitations)
	}

	// The provider received the frozen inventory and the deadline, and was
	// never asked to release the result: acknowledgement is 3.2's, after
	// durable capture.
	if len(c.st.requests) != 1 {
		t.Fatalf("%d collections", len(c.st.requests))
	}
	req := c.st.requests[0]
	if len(req.GetInventory().GetSubjects()) != 3 || req.GetInventory().GetSupplements() != providerv1.Supplements_SUPPLEMENTS_NONE ||
		req.GetHeader().GetProtocolVersion() != providerkit.ProtocolVersion || req.GetDeadline() == nil {
		t.Fatalf("request %v", req)
	}
	if c.st.releases != 0 || c.srv.Calls.Load() != 3 {
		t.Fatalf("releases %d, calls %d: want Describe, Collect and ReadResult only", c.st.releases, c.srv.Calls.Load())
	}

	// The capture keeps the staged bytes exactly and records the frozen
	// registration; it reads back only for that registration.
	if string(got.Payload) != doc || providerkit.Digest(got.Payload) != got.Result.GetSha256() {
		t.Fatal("the payload is not the staged bytes")
	}
	read, err := collector.ReadCapture(got.Capture, c.frozen.CaptureReaders())
	if err != nil || string(read.Payload) != doc || read.Header.Registration == nil || *read.Header.Registration != c.frozen.CaptureRegistration() {
		t.Fatalf("capture reads as %+v: %v", read.Header, err)
	}
	if r := read.Header.Registration; r.Name != "reporting" || r.UID != "uid-reporting" || r.Revision != 1 || r.ReleaseDigest != externaltest.Release ||
		r.Protocol != "konstapel.provider.v1" || r.ProtocolRevision != int(providerkit.ProtocolVersion) {
		t.Fatalf("registration %+v", r)
	}
	if _, err := collector.ReadCapture(got.Capture, installed.Registry()); !errors.Is(err, collector.ErrUnsupportedCapture) {
		t.Fatalf("the built-in registry reads a registered provider's capture: %v", err)
	}
	other := c.ap.DeepCopy()
	other.UID, other.Generation = types.UID("uid-replaced"), 2
	if _, err := collector.ReadCapture(got.Capture, external.Expected(other).CaptureReaders()); !errors.Is(err, collector.ErrUnsupportedCapture) {
		t.Fatalf("another registration reads the capture: %v", err)
	}
}

// Supplements are accepted only when the inventory allows them and only
// under an inventory workload, and they never complete a frozen
// expectation.
func TestCollectSupplementRules(t *testing.T) {
	doc := document(t, map[string]any{
		"supplements": []any{
			map[string]string{"id": "web-a/nginx", "parent": webA, "kind": "container", "name": "nginx"},
			map[string]string{"id": "ns-a/part", "parent": nsA, "kind": "container"},
			map[string]string{"id": webB, "parent": webA, "kind": "container"},
			map[string]string{"id": "elsewhere", "parent": outsideUID, "kind": "container"},
			map[string]string{"id": "web-a/sidecar", "parent": webA, "kind": "container", "name": "sidecar"},
		},
		"evidence": []any{evidence("e-nginx", "2026-11-27T10:00:00Z", [2]string{"web-a/nginx", imagePosture})},
	})
	c := newCollection(t, doc)
	c.inv.Supplements = true
	got := c.run(t, time.Time{})
	if got.Stop != nil {
		t.Fatalf("stopped: %+v", got.Stop)
	}
	if len(got.Supplements) != 2 || got.Supplements[0].ID != "web-a/nginx" || got.Supplements[1].ID != "web-a/sidecar" {
		t.Fatalf("supplements %+v", got.Supplements)
	}
	var reasons []string
	for _, d := range got.Diagnostics {
		reasons = append(reasons, string(d.Reason))
	}
	if !slices.Equal(reasons, []string{"OrphanSupplement", "SupplementCollision", "OrphanSupplement"}) {
		t.Fatalf("diagnostics %v", reasons)
	}
	if len(got.Evidence) != 1 {
		t.Fatalf("evidence %+v", got.Evidence)
	}
	// The workload's own expectation is still missing: supplement evidence
	// never completes it. The unassessed supplement is reported apart.
	missing := func(m []external.Missing) []external.Expectation {
		var out []external.Expectation
		for _, x := range m {
			out = append(out, x.Expectation)
		}
		return out
	}
	if want := []external.Expectation{{Subject: nsA, Check: ownerLabel}, {Subject: webA, Check: imagePosture}, {Subject: webB, Check: imagePosture}}; !slices.Equal(missing(got.Missing), want) {
		t.Fatalf("missing %v", missing(got.Missing))
	}
	if want := []external.Expectation{{Subject: "web-a/sidecar", Check: imagePosture}}; !slices.Equal(missing(got.SupplementalMissing), want) {
		t.Fatalf("supplemental missing %v", missing(got.SupplementalMissing))
	}

	// Without the inventory's permission, no supplement is accepted, and
	// evidence attributed to one is out of scope.
	c = newCollection(t, doc)
	got = c.run(t, time.Time{})
	if got.Stop != nil || len(got.Supplements) != 0 || len(got.Evidence) != 0 || got.Withheld != 1 {
		t.Fatalf("without supplements: %+v", got)
	}
	if got.Diagnostics[0].Reason != external.DiagnosticSupplementNotAllowed || got.Diagnostics[len(got.Diagnostics)-1].Reason != external.DiagnosticOutOfScope {
		t.Fatalf("diagnostics %+v", got.Diagnostics)
	}
	if c.st.requests[0].GetInventory().GetSupplements() != providerv1.Supplements_SUPPLEMENTS_NONE {
		t.Fatal("the request allows supplements")
	}
}

// Continue runs before anything is dispatched: work frozen to a removed,
// replaced or unreadable registration contacts no endpoint.
func TestCollectContinuesTheFrozenRegistrationFirst(t *testing.T) {
	for name, tc := range map[string]struct {
		read func(*v1alpha1.AssessmentProvider) (*v1alpha1.AssessmentProvider, error)
		want string
	}{
		"removed": {func(*v1alpha1.AssessmentProvider) (*v1alpha1.AssessmentProvider, error) { return nil, nil }, "RegistrationRemoved"},
		"replaced": {func(ap *v1alpha1.AssessmentProvider) (*v1alpha1.AssessmentProvider, error) {
			ap.UID = "uid-other"
			return ap, nil
		}, "RegistrationReplaced"},
		"collection no longer allowed by a later revision only": {func(ap *v1alpha1.AssessmentProvider) (*v1alpha1.AssessmentProvider, error) {
			ap.Generation, ap.Spec.Capabilities = 2, []v1alpha1.AssessmentProviderCapability{v1alpha1.ProviderCapabilityEvaluate}
			return ap, nil
		}, ""},
		"unreadable": {func(*v1alpha1.AssessmentProvider) (*v1alpha1.AssessmentProvider, error) {
			return nil, errors.New("the API server is unavailable")
		}, "could not be read"},
	} {
		t.Run(name, func(t *testing.T) {
			c := newCollection(t, `{}`)
			c.w.dialer.Registration = func(context.Context, string) (*v1alpha1.AssessmentProvider, error) { return tc.read(c.ap.DeepCopy()) }
			got := c.run(t, time.Time{})
			if tc.want == "" {
				// A later revision does not narrow frozen work.
				if got.Stop != nil {
					t.Fatalf("stopped: %+v", got.Stop)
				}
				return
			}
			wantStop(t, got, external.StopRegistration, tc.want)
			if c.srv.Calls.Load() != 0 {
				t.Fatalf("%d calls reached the provider", c.srv.Calls.Load())
			}
		})
	}
	// Work frozen without the capability never collects.
	c := newCollection(t, `{}`)
	c.frozen.Capabilities = []v1alpha1.AssessmentProviderCapability{v1alpha1.ProviderCapabilityEvaluate}
	wantStop(t, c.run(t, time.Time{}), external.StopRegistration, "CapabilityNotFrozen")
}

// The stricter of the host's and the provider's bounds applies. An
// inventory beyond them is never dispatched, or truncated.
func TestCollectBounds(t *testing.T) {
	c := newCollection(t, `{}`)
	c.limits.MaxObjects = 2
	wantStop(t, c.run(t, time.Time{}), external.StopLimit, "not dispatched")
	if c.srv.Calls.Load() != 0 {
		t.Fatal("an inventory beyond the host's bound reached the provider")
	}

	c = newCollection(t, `{}`, func(o *externaltest.ServerOptions) {
		o.Description = externaltest.Description()
		o.Description.Limits = &providerv1.Limits{MaxSubjects: 2}
	})
	wantStop(t, c.run(t, time.Time{}), external.StopLimit, "inventory has 3 subjects, more than 2")
	if c.srv.Calls.Load() != 1 || len(c.st.requests) != 0 {
		t.Fatalf("calls %d: an inventory beyond the provider's bound was sent", c.srv.Calls.Load())
	}

	big := document(t, map[string]any{"evidence": []any{evidence("e-web-a", "2026-11-27T10:00:00Z", [2]string{webA, imagePosture})}})
	c = newCollection(t, big)
	c.limits.MaxBytes = int64(len(big) - 1)
	wantStop(t, c.run(t, time.Time{}), external.StopLimit, "more than")

	two := document(t, map[string]any{"evidence": []any{
		evidence("e-1", "2026-11-27T10:00:00Z", [2]string{webA, imagePosture}), evidence("e-2", "2026-11-27T10:00:00Z", [2]string{webB, imagePosture})}})
	c = newCollection(t, two, func(o *externaltest.ServerOptions) {
		o.Description = externaltest.Description()
		o.Description.Limits = &providerv1.Limits{MaxEvidence: 1}
	})
	// The provider's own server refuses to send a result beyond its bound.
	wantStop(t, c.run(t, time.Time{}), external.StopLimit, "evidence items")
}

// Malformed, altered, lost and late results are explicit incomplete
// collections, never evidence.
func TestCollectFailuresAreIncomplete(t *testing.T) {
	good := document(t, map[string]any{"evidence": []any{evidence("e-web-a", "2026-11-27T10:00:00Z", [2]string{webA, imagePosture})}})
	t.Run("malformed result", func(t *testing.T) {
		for name, doc := range map[string]string{
			"not a CollectionResult": `{"reports":[]}`,
			"untimed evidence":       `{"evidence":[{"id":"e","attributions":[{"subject":"` + webA + `","check":"` + imagePosture + `"}]}]}`,
			"surrounding whitespace": good + "\n",
		} {
			t.Run(name, func(t *testing.T) {
				wantStop(t, newCollection(t, doc).run(t, time.Time{}), external.StopMalformed, "ReadResult")
			})
		}
	})
	t.Run("digest mismatch", func(t *testing.T) {
		c := newCollection(t, good)
		c.st.serve = func(b []byte) []byte { return []byte(strings.Replace(string(b), "e-web-a", "e-web-b", 1)) }
		wantStop(t, c.run(t, time.Time{}), external.StopDigestMismatch, "ReadResult")
	})
	t.Run("expired result", func(t *testing.T) {
		c := newCollection(t, good)
		c.st.result = func(context.Context) error {
			return providerkit.Errorf(providerv1.ErrorReason_ERROR_REASON_RESULT_EXPIRED, "result expired unacknowledged")
		}
		wantStop(t, c.run(t, time.Time{}), external.StopResultLost, "RESULT_EXPIRED")
	})
	t.Run("provider refuses", func(t *testing.T) {
		c := newCollection(t, good)
		c.st.collect = func(context.Context) error {
			return providerkit.Errorf(providerv1.ErrorReason_ERROR_REASON_UNAVAILABLE, "source unavailable")
		}
		wantStop(t, c.run(t, time.Time{}), external.StopUnavailable, "source unavailable")
	})
	t.Run("deadline during collection", func(t *testing.T) {
		c := newCollection(t, good)
		c.st.collect = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
		start := time.Now()
		wantStop(t, c.run(t, start.Add(500*time.Millisecond)), external.StopDeadline, "deadline")
		if time.Since(start) > 5*time.Second {
			t.Fatal("the deadline did not bound the collection")
		}
	})
	t.Run("limits timeout during transfer", func(t *testing.T) {
		c := newCollection(t, good)
		c.limits.Timeout = 500 * time.Millisecond
		c.st.result = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
		wantStop(t, c.run(t, time.Now().Add(time.Hour)), external.StopDeadline, "deadline")
	})
	t.Run("provider gone mid-transfer", func(t *testing.T) {
		c := newCollection(t, good)
		started := make(chan struct{})
		c.st.result = func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}
		go func() { <-started; c.srv.Stop() }()
		wantStop(t, c.run(t, time.Now().Add(time.Minute)), external.StopUnavailable, "ReadResult")
	})
	t.Run("endpoint unavailable", func(t *testing.T) {
		c := newCollection(t, good)
		c.w.addrs[externaltest.ServiceName] = externaltest.Closed(t)
		wantStop(t, c.run(t, time.Now().Add(5*time.Second)), external.StopUnavailable, "EndpointUnavailable")
	})
	t.Run("endpoint reports another release", func(t *testing.T) {
		c := newCollection(t, good, func(o *externaltest.ServerOptions) {
			o.Description = externaltest.Description()
			o.Description.Implementation = externaltest.OtherRelease
		})
		wantStop(t, c.run(t, time.Time{}), external.StopIncompatible, "ReleaseMismatch")
		if len(c.st.requests) != 0 {
			t.Fatal("collected from an endpoint of another release")
		}
	})
}

// When the host's own context ends, nothing of the collection may be
// recorded: Collect returns the context's error, not an incomplete
// collection.
func TestCollectHostContextEnds(t *testing.T) {
	c := newCollection(t, `{}`)
	ctx, cancel := context.WithCancel(context.Background())
	c.st.collect = func(pctx context.Context) error { cancel(); <-pctx.Done(); return pctx.Err() }
	got, err := external.Collect(ctx, c.w.dialer, c.frozen, c.inv, c.limits, time.Time{})
	if !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("got %+v, %v", got, err)
	}

	if _, err := external.Collect(context.Background(), &external.Dialer{}, c.frozen, c.inv, c.limits, time.Time{}); err == nil {
		t.Fatal("collected without a registration reader")
	}
	if _, err := external.Collect(context.Background(), c.w.dialer, c.frozen, c.inv, provider.Limits{}, time.Time{}); err == nil {
		t.Fatal("collected without limits")
	}
}
