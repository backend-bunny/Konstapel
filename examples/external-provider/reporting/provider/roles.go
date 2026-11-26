package provider

import (
	"context"
	"fmt"
	"regexp"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

// Role is the part of the provider one process serves.
type Role string

const (
	// RoleCombined collects from a source and evaluates in one process:
	// the quickstart.
	RoleCombined Role = "combined"
	// RoleWorker is the reference deployment's source worker. It reads the
	// source, stages results and serves the registered endpoint. It
	// evaluates nothing itself: every Evaluate is forwarded, unchanged, to
	// the evaluator (Forward).
	RoleWorker Role = "worker"
	// RoleEvaluator is the reference deployment's evaluator. It serves
	// Evaluate only and holds no source, no source credential and no
	// Kubernetes API token; its chart denies it all egress.
	RoleEvaluator Role = "evaluator"
)

// ParseRole parses a role name.
func ParseRole(s string) (Role, error) {
	switch r := Role(s); r {
	case RoleCombined, RoleWorker, RoleEvaluator:
		return r, nil
	}
	return "", fmt.Errorf("role %q is not combined, worker or evaluator", s)
}

// releaseDigest is the form of a deployed release's implementation: the
// digest its registration names as releaseDigest.
var releaseDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidRelease reports whether implementation is a release digest.
func ValidRelease(implementation string) bool { return releaseDigest.MatchString(implementation) }

// Service is what one process serves: its description and its handlers.
type Service struct {
	Description *providerv1.DescribeResponse
	Handlers    providerkit.Handlers
}

// EvaluatorService is the evaluator process: Evaluate only, nothing to
// read but each evaluation's input.
func EvaluatorService(implementation string) Service {
	return Service{Description: Describe(RoleEvaluator, implementation), Handlers: providerkit.Handlers{Evaluator: Evaluator{}}}
}

// WorkerService is the source worker: collection from p and every
// evaluation forwarded to the evaluator through f.
func WorkerService(implementation string, p *Provider, f *Forward) Service {
	return Service{Description: Describe(RoleWorker, implementation), Handlers: providerkit.Handlers{Collector: p, Results: p, Evaluator: f}}
}

// CombinedService is the quickstart's single process.
func CombinedService(p *Provider) Service {
	return Service{Description: Description(), Handlers: p.Handlers()}
}

// EvaluatorExpectation is what the worker expects of its evaluator: this
// provider and its versions, serving Evaluate.
func EvaluatorExpectation() providerkit.Compatibility {
	return providerkit.Compatibility{Provider: Name, ContractVersion: ContractVersion, PayloadVersion: PayloadVersion,
		EvaluatorVersion: EvaluatorVersion, Capabilities: []providerv1.Capability{providerv1.Capability_CAPABILITY_EVALUATE}}
}

// Forward is the worker's Evaluator. It sends each evaluation, unchanged,
// to the evaluator deployment over mutual TLS and returns the evaluator's
// observations; the worker's kit server checks them again before they
// reach the host. The evaluator must describe the worker's own release, so
// a worker never forwards to an evaluator of another release.
type Forward struct {
	// Client reaches the evaluator; its expectation is
	// EvaluatorExpectation.
	Client *providerkit.Client
	// Implementation is the release the evaluator must report.
	Implementation string
}

// Evaluate forwards one evaluation within ctx's deadline, which is the
// host's.
func (f *Forward) Evaluate(ctx context.Context, start *providerv1.EvaluateStart, payload []byte) (*providerkit.Evaluation, error) {
	d, err := f.Client.Describe(ctx)
	if err != nil {
		return nil, forwarded("describe the evaluator", err)
	}
	if d.GetImplementation() != f.Implementation {
		return nil, providerkit.Errorf(providerv1.ErrorReason_ERROR_REASON_UNAVAILABLE,
			"the evaluator reports implementation %q, not this worker's release %s", d.GetImplementation(), f.Implementation)
	}
	ev, err := f.Client.Evaluate(ctx, providerkit.EvaluateInput{
		PayloadVersion:   start.GetPayloadVersion(),
		EvaluatorVersion: start.GetEvaluatorVersion(),
		Payload:          payload,
		At:               start.GetEvaluationTime().AsTime(),
		Scope:            start.GetScope(),
		Content:          start.GetContent(),
		Checks:           start.GetChecks(),
	})
	if err != nil {
		return nil, forwarded("evaluate", err)
	}
	return ev, nil
}

// forwarded keeps the evaluator's error reason; an evaluator that gave no
// protocol answer is unavailable.
func forwarded(what string, err error) error {
	reason := providerkit.ReasonOf(err)
	if reason == providerv1.ErrorReason_ERROR_REASON_UNSPECIFIED {
		reason = providerv1.ErrorReason_ERROR_REASON_UNAVAILABLE
	}
	return providerkit.Errorf(reason, "%s: %v", what, err)
}
