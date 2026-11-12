package controller

import (
	"errors"
	"fmt"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Requeue policy for unavailable bundle content. Configuration and trust
// changes re-trigger the affected profiles and bindings through their
// events, so classes that only such a change can fix are not retried on a
// timer; classes that the outside world (a registry, the cache) can fix
// are retried at a bounded interval, never in a hot loop.
const (
	// StaleContentRequeue: the configuration changed during resolution;
	// resolve again promptly.
	StaleContentRequeue = time.Second
	// TransientContentRequeue: retrieval, evidence retrieval or cache
	// capacity can recover without any Kubernetes change.
	TransientContentRequeue = time.Minute
	// UntrustedContentRequeue: retained evidence does not satisfy current
	// trust and fresh evidence could not be retrieved or did not either;
	// a re-published proof can fix that without a configuration change.
	UntrustedContentRequeue = 5 * time.Minute
)

// ContentRequeue returns how soon a reconcile that failed with err is
// retried. Zero means only an event (a profile edit, a source
// configuration or trust change, a restart) retries it: Config,
// Incompatible, DigestMismatch and Malformed content, and errors without a
// class (LocalContent, whose behavior is unchanged).
func ContentRequeue(err error) time.Duration {
	switch targeting.ContentErrorClassOf(err) {
	case targeting.ContentErrorStale:
		return StaleContentRequeue
	case targeting.ContentErrorContentUnavailable, targeting.ContentErrorProofUnavailable,
		targeting.ContentErrorCapacity, targeting.ContentErrorUnresolved:
		return TransientContentRequeue
	case targeting.ContentErrorUntrusted:
		return UntrustedContentRequeue
	}
	return 0
}

// contentMessage explains unavailable content: for a classified error its
// class and bounded, credential-free detail; otherwise the error, exactly
// as before.
func contentMessage(err error) string {
	var ce *targeting.ContentError
	if errors.As(err, &ce) {
		return truncate(fmt.Sprintf("bundle content unavailable (%s): %s", ce.Class, ce.Detail))
	}
	return truncate(err.Error())
}

// ParameterValidator checks one profile policy's parameters against the
// policy's declared contract; content.ValidateParameters implements it.
// It must return nil for a source without a contract
// (src.ParametersValidated false).
type ParameterValidator func(src targeting.PolicySource, policy string, raw []byte) error

// parameterProblem explains why a policy's parameters are rejected, for
// content that declares a parameter contract; "" when the content declares
// none, no validator is configured, or there are no parameters. Content
// without a contract keeps the resolver's generic rejection.
func parameterProblem(validate ParameterValidator, c *targeting.Content, bp targeting.BundlePolicy, pol v1alpha1.ProfilePolicy) string {
	if validate == nil || c == nil || !targeting.HasParameters(pol) {
		return ""
	}
	src, ok := c.Policies[pol.Name]
	if !ok || !src.ParametersValidated {
		return ""
	}
	if err := validate(src, pol.Name, pol.Parameters.Raw); err != nil {
		return fmt.Sprintf("policy %q parameters: %v", pol.Name, err)
	}
	if !bp.Parameters {
		return fmt.Sprintf("policy %q parameters satisfy its schema but are not rendered by this controller; they are rejected, never dropped", pol.Name)
	}
	return ""
}
