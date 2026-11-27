package provider

import (
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
	// RoleWorker is the reference deployment's source worker, the
	// registration's source endpoint. It reads the source, stages results
	// and serves collection only: it evaluates nothing and forwards
	// nothing.
	RoleWorker Role = "worker"
	// RoleEvaluator is the reference deployment's evaluator, the
	// registration's separate evaluator endpoint, which the host calls
	// directly. It serves Evaluate only and holds no source, no source
	// credential and no Kubernetes API token; its chart denies it all
	// egress.
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

// WorkerService is the source worker: collection from p, nothing else.
func WorkerService(implementation string, p *Provider) Service {
	return Service{Description: Describe(RoleWorker, implementation), Handlers: providerkit.Handlers{Collector: p, Results: p}}
}

// CombinedService is the quickstart's single process.
func CombinedService(p *Provider) Service {
	return Service{Description: Description(), Handlers: p.Handlers()}
}

// EvaluatorExpectation is what a host expects of the evaluator endpoint:
// this provider and its versions, serving Evaluate.
func EvaluatorExpectation() providerkit.Compatibility {
	return providerkit.Compatibility{Provider: Name, ContractVersion: ContractVersion, PayloadVersion: PayloadVersion,
		EvaluatorVersion: EvaluatorVersion, Capabilities: []providerv1.Capability{providerv1.Capability_CAPABILITY_EVALUATE}}
}
