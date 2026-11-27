package external_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/provider/external"
	"github.com/backend-bunny/Konstapel/internal/provider/external/externaltest"
	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

// split serves the default registration's two endpoints as separate
// processes with their own server names: the source endpoint describing
// sourceCaps, the evaluator endpoint evaluatorCaps.
func split(t *testing.T, w *world, sourceCaps, evaluatorCaps []providerv1.Capability, evaluatorNames ...string) (source, evaluator *externaltest.Server) {
	t.Helper()
	describe := func(caps []providerv1.Capability) *providerv1.DescribeResponse {
		d := externaltest.Description()
		d.Capabilities = caps
		return d
	}
	source = externaltest.Serve(t, externaltest.ServerOptions{CA: w.ca, Description: describe(sourceCaps), ServerNames: []string{externaltest.ServerName}})
	if len(evaluatorNames) == 0 {
		evaluatorNames = []string{externaltest.EvaluatorServerName}
	}
	evaluator = externaltest.Serve(t, externaltest.ServerOptions{CA: w.ca, Description: describe(evaluatorCaps), ServerNames: evaluatorNames})
	w.addrs[externaltest.ServiceName], w.addrs[externaltest.EvaluatorServiceName] = source.Addr, evaluator.Addr
	return source, evaluator
}

var (
	collectOnly  = []providerv1.Capability{providerv1.Capability_CAPABILITY_COLLECT}
	evaluateOnly = []providerv1.Capability{providerv1.Capability_CAPABILITY_EVALUATE}
)

// Each endpoint is authenticated and described on its own, against the
// capabilities it serves: a worker that serves Collect only and an
// evaluator that serves Evaluate only make a Ready registration.
func TestProbeDescribesEachEndpoint(t *testing.T) {
	w := newWorld(t)
	source, evaluator := split(t, w, collectOnly, evaluateOnly)
	ap := externaltest.Registration("reporting")
	if obs := w.probe(ap, 5*time.Second); obs.Problem != nil {
		t.Fatalf("problem %+v", obs.Problem)
	}
	if source.Describes.Load() != 1 || evaluator.Describes.Load() != 1 {
		t.Fatalf("describes: source %d, evaluator %d", source.Describes.Load(), evaluator.Describes.Load())
	}
	st := external.Status(ap, w.probe(ap, 5*time.Second), nil)
	for _, c := range st.Conditions {
		if c.Type == v1alpha1.ProviderConditionAvailable && (!strings.Contains(c.Message, "source endpoint") || !strings.Contains(c.Message, "evaluator endpoint")) {
			t.Errorf("Available names %q, want both endpoints", c.Message)
		}
	}
}

// A healthy source endpoint does not make the registration usable when its
// evaluator endpoint fails: the problem names the evaluator endpoint.
func TestProbeFailsOnTheEvaluatorEndpoint(t *testing.T) {
	ap := externaltest.Registration("reporting")
	for name, tc := range map[string]struct {
		evaluatorCaps []providerv1.Capability
		names         []string
		condition     string
		reason        string
	}{
		// The evaluator's certificate is the worker's identity.
		"another identity": {evaluateOnly, []string{externaltest.ServerName}, v1alpha1.ProviderConditionAvailable, v1alpha1.ProviderReasonAuthenticationFailed},
		// The evaluator endpoint does not evaluate.
		"no evaluation": {collectOnly, nil, v1alpha1.ProviderConditionCompatible, v1alpha1.ProviderReasonUnsupportedCapability},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			split(t, w, collectOnly, tc.evaluatorCaps, tc.names...)
			obs := w.probe(ap, 5*time.Second)
			wantProblem(t, obs, tc.condition, tc.reason)
			if !strings.Contains(obs.Problem.Message, "evaluator endpoint "+externaltest.EvaluatorServiceName) {
				t.Fatalf("problem %q does not name the evaluator endpoint", obs.Problem.Message)
			}
			st := external.Status(ap, obs, nil)
			for _, c := range st.Conditions {
				if c.Type == v1alpha1.ProviderConditionReady && c.Status != "False" {
					t.Fatalf("Ready %s with a failing evaluator endpoint", c.Status)
				}
			}
		})
	}
	// A source endpoint that does not collect fails on the source.
	w := newWorld(t)
	split(t, w, evaluateOnly, evaluateOnly)
	obs := w.probe(ap, 5*time.Second)
	wantProblem(t, obs, v1alpha1.ProviderConditionCompatible, v1alpha1.ProviderReasonUnsupportedCapability)
	if !strings.Contains(obs.Problem.Message, "source endpoint") {
		t.Fatalf("problem %q", obs.Problem.Message)
	}
}

// Evaluation goes only to the evaluator endpoint and collection only to the
// source endpoint: each connection's client refuses the other endpoint's
// operations before sending anything.
func TestEachEndpointCarriesOnlyItsOperations(t *testing.T) {
	w := newWorld(t)
	source, evaluator := split(t, w, collectOnly, evaluateOnly)
	f := external.Expected(externaltest.Registration("reporting"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sc, err := w.dialer.Connect(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	_, err = sc.Client.Evaluate(ctx, providerkit.EvaluateInput{PayloadVersion: 1, EvaluatorVersion: 1, Payload: []byte(`{}`), At: time.Now(),
		Scope: &providerv1.Scope{Cluster: "c", Namespaces: []*providerv1.Namespace{{Name: "a", Uid: "u"}}}})
	if providerkit.ReasonOf(err) != providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CAPABILITY {
		t.Fatalf("evaluation through the source endpoint: %v", err)
	}
	ec, err := w.dialer.ConnectEvaluator(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	defer ec.Close()
	_, err = ec.Client.Collect(ctx, &providerv1.Scope{Cluster: "c", Namespaces: []*providerv1.Namespace{{Name: "a", Uid: "u"}}},
		&providerv1.Inventory{Supplements: providerv1.Supplements_SUPPLEMENTS_NONE, Subjects: []*providerv1.InventorySubject{
			{Uid: "u", NamespaceUid: "u", Resource: providerkit.NamespaceResource, Name: "a", Revision: "r", Checks: []string{"c"}}}}, time.Now().Add(time.Minute))
	if providerkit.ReasonOf(err) != providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CAPABILITY {
		t.Fatalf("collection through the evaluator endpoint: %v", err)
	}
	// Only the two Describes reached the providers.
	if source.Calls.Load() != 1 || evaluator.Calls.Load() != 1 {
		t.Fatalf("calls: source %d, evaluator %d", source.Calls.Load(), evaluator.Calls.Load())
	}
}

// An Evaluate-only registration (replay after the worker is gone) has no
// source endpoint: only its evaluator is probed, and nothing connects to a
// source endpoint for it.
func TestEvaluateOnlyRegistration(t *testing.T) {
	w := newWorld(t)
	_, evaluator := split(t, w, collectOnly, evaluateOnly)
	w.addrs[externaltest.ServiceName] = externaltest.Closed(t)
	ap := externaltest.Registration("replay", func(ap *v1alpha1.AssessmentProvider) {
		ap.Spec.Endpoint = nil
		ap.Spec.Capabilities = []v1alpha1.AssessmentProviderCapability{v1alpha1.ProviderCapabilityEvaluate}
	})
	if obs := w.probe(ap, 5*time.Second); obs.Problem != nil || evaluator.Describes.Load() != 1 {
		t.Fatalf("problem %+v, evaluator describes %d", obs.Problem, evaluator.Describes.Load())
	}
	f := external.Expected(ap)
	if f.Endpoint != nil || f.EvaluatorEndpoint == nil {
		t.Fatalf("frozen endpoints %+v %+v", f.Endpoint, f.EvaluatorEndpoint)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := w.dialer.Connect(ctx, f); err == nil || !strings.Contains(err.Error(), "has no source endpoint") {
		t.Fatalf("connect to the missing source endpoint: %v", err)
	}
}

// Work keeps its revision's evaluator endpoint: a later revision that
// moves it is used only by new work.
func TestFrozenEvaluatorEndpoint(t *testing.T) {
	ap := externaltest.Registration("reporting")
	f := external.Expected(ap)
	moved := ap.DeepCopy()
	moved.Generation = 2
	moved.Spec.EvaluatorEndpoint.Service.Name = "example-reporting-evaluator-next"
	if err := f.Continue(moved, v1alpha1.ProviderCapabilityEvaluate); err != nil {
		t.Fatalf("a moved evaluator endpoint ends frozen work: %v", err)
	}
	if f.EvaluatorEndpoint.Service != externaltest.EvaluatorServiceName || external.Expected(moved).EvaluatorEndpoint.Service != "example-reporting-evaluator-next" {
		t.Fatalf("frozen %v, current %v", f.EvaluatorEndpoint, external.Expected(moved).EvaluatorEndpoint)
	}
}
