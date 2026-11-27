package external

import (
	"context"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// maxConditionMessage bounds a condition message.
const maxConditionMessage = 1024

// Observation is one probe of a registration's current revision.
type Observation struct {
	// Generation is the revision probed.
	Generation int64
	// At is when the probe ended.
	At time.Time
	// Problem is why the endpoint cannot be used; nil when it was
	// authenticated, described itself and matched the registration.
	Problem *Problem
}

// BuiltInObservation is the observation of a registration naming a
// built-in provider: it is never contacted.
func BuiltInObservation(ap *v1alpha1.AssessmentProvider, at time.Time) Observation {
	return Observation{Generation: ap.Generation, At: at, Problem: incompatible(v1alpha1.ProviderReasonBuiltInProvider,
		"provider %s is built into Konstapel; a registration never shadows it, and its endpoint is not contacted", ap.Spec.Provider.Name)}
}

// Probe connects to each endpoint of the registration's current revision,
// the source endpoint first, within ctx's deadline, describes it against
// that endpoint's expectation and closes the connection. It sends nothing
// but Describe. The first failing endpoint is the observation's problem,
// named in its message; the revision is usable only when every endpoint
// it names is.
func (d *Dialer) Probe(ctx context.Context, ap *v1alpha1.AssessmentProvider, now func() time.Time) Observation {
	obs := Observation{Generation: ap.Generation}
	f := Expected(ap)
	for _, role := range []EndpointRole{SourceEndpoint, EvaluatorEndpoint} {
		ep := f.EndpointOf(role)
		if ep == nil {
			continue
		}
		conn, err := d.connect(ctx, f, role)
		if err != nil {
			p, ok := err.(*Problem)
			if !ok {
				p = unavailable(v1alpha1.ProviderReasonEndpointUnavailable, "%s", bound(err.Error(), 512))
			}
			named := *p
			named.Message = fmt.Sprintf("%s endpoint %s: %s", role, ep.Address(), p.Message)
			obs.At, obs.Problem = now(), &named
			return obs
		}
		_ = conn.Close()
	}
	obs.At = now()
	return obs
}

// endpoints describes the revision's endpoints for condition messages.
func endpoints(f Frozen) string {
	var out []string
	for _, role := range []EndpointRole{SourceEndpoint, EvaluatorEndpoint} {
		if ep := f.EndpointOf(role); ep != nil {
			out = append(out, fmt.Sprintf("%s endpoint %s authenticated as %s", role, ep.Address(), ep.ServerName))
		}
	}
	return strings.Join(out, "; ")
}

// Status is the registration's status after an observation: the
// Available, Compatible and Ready conditions for the observed revision and,
// only while compatible, the observed identity. conflicts are the other
// Enabled registrations of the same contract (Catalog.Conflicts).
// Condition transition times are kept from the current status.
func Status(ap *v1alpha1.AssessmentProvider, obs Observation, conflicts []string) v1alpha1.AssessmentProviderStatus {
	st := v1alpha1.AssessmentProviderStatus{ObservedGeneration: obs.Generation, Conditions: append([]metav1.Condition(nil), ap.Status.Conditions...)}
	gen := obs.Generation
	set := func(typ string, status metav1.ConditionStatus, reason, format string, a ...any) {
		meta.SetStatusCondition(&st.Conditions, metav1.Condition{Type: typ, Status: status, Reason: reason,
			Message: bound(fmt.Sprintf(format, a...), maxConditionMessage), ObservedGeneration: gen})
	}
	// Only the three conditions of this controller are kept.
	for _, c := range ap.Status.Conditions {
		switch c.Type {
		case v1alpha1.ProviderConditionAvailable, v1alpha1.ProviderConditionCompatible, v1alpha1.ProviderConditionReady:
		default:
			meta.RemoveStatusCondition(&st.Conditions, c.Type)
		}
	}
	f := Expected(ap)
	p := obs.Problem
	switch {
	case p == nil:
		set(v1alpha1.ProviderConditionAvailable, metav1.ConditionTrue, v1alpha1.ProviderReasonAvailable,
			"%s; each described itself", endpoints(f))
		set(v1alpha1.ProviderConditionCompatible, metav1.ConditionTrue, v1alpha1.ProviderReasonCompatible,
			"the endpoint serves %s release %s, protocol %s revision %d, evaluator %d, payload %d and %v",
			f.Contract(), f.ReleaseDigest, f.Protocol, f.ProtocolRevision, f.EvaluatorVersion, f.PayloadVersion, f.Capabilities)
	case p.Condition == v1alpha1.ProviderConditionCompatible:
		if p.Reason == v1alpha1.ProviderReasonBuiltInProvider {
			set(v1alpha1.ProviderConditionAvailable, metav1.ConditionUnknown, v1alpha1.ProviderReasonNotChecked, "%s", p.Message)
		} else {
			set(v1alpha1.ProviderConditionAvailable, metav1.ConditionTrue, v1alpha1.ProviderReasonAvailable,
				"every endpoint probed, up to the incompatible one, was authenticated and described itself")
		}
		set(v1alpha1.ProviderConditionCompatible, metav1.ConditionFalse, p.Reason, "%s", p.Message)
	default:
		set(v1alpha1.ProviderConditionAvailable, metav1.ConditionFalse, p.Reason, "%s", p.Message)
		set(v1alpha1.ProviderConditionCompatible, metav1.ConditionUnknown, v1alpha1.ProviderReasonNotChecked,
			"compatibility is not checked while the endpoint is unavailable")
	}
	switch {
	case p != nil && p.Condition == v1alpha1.ProviderConditionCompatible:
		set(v1alpha1.ProviderConditionReady, metav1.ConditionFalse, v1alpha1.ProviderReasonIncompatible, "%s", p.Message)
	case p != nil:
		set(v1alpha1.ProviderConditionReady, metav1.ConditionFalse, v1alpha1.ProviderReasonUnavailable, "%s", p.Message)
	case ap.Spec.NewRequests == v1alpha1.ProviderNewRequestsDisabled:
		set(v1alpha1.ProviderConditionReady, metav1.ConditionFalse, v1alpha1.ProviderReasonNewRequestsDisabled,
			"newRequests is Disabled: no new work selects this registration; work already frozen to it can drain")
	case len(conflicts) > 0:
		set(v1alpha1.ProviderConditionReady, metav1.ConditionFalse, v1alpha1.ProviderReasonAmbiguousRegistration,
			"registrations %s also name %s with newRequests Enabled; no new work selects any of them until all but one are Disabled", list(conflicts), f.Contract())
	default:
		set(v1alpha1.ProviderConditionReady, metav1.ConditionTrue, v1alpha1.ProviderReasonReady, "new work may select this registration for %s", f.Contract())
	}
	if p == nil {
		st.Identity = &v1alpha1.ObservedProviderIdentity{Name: f.Provider, ReleaseDigest: f.ReleaseDigest, Protocol: f.Protocol,
			ProtocolRevision: f.ProtocolRevision, ContractVersion: f.ContractVersion, EvaluatorVersion: f.EvaluatorVersion,
			PayloadVersion: f.PayloadVersion, Capabilities: f.Capabilities, ObservedAt: metav1.NewTime(obs.At.UTC().Truncate(time.Second))}
	}
	return st
}
