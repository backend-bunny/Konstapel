package exception

import (
	"fmt"
	"strings"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// Denial reasons. They match the lifecycle fixture vocabulary
// (testdata/exceptions) and prefix the admission message.
const (
	ReasonNotApplicable    = "UnknownPolicy"
	ReasonUnresolved       = "Unresolved"
	ReasonForbidden        = "Forbidden"
	ReasonExpiryElapsed    = "ExpiryElapsed"
	ReasonLifetimeExceeded = "LifetimeExceeded"
)

// Denial is an acceptance that current eligibility or lifetime limits do not
// permit.
type Denial struct {
	Reason  string
	Message string
}

func (d *Denial) Error() string { return d.Reason + ": " + d.Message }

// admissible checks an acceptance against the eligibility resolved for it:
// every applicable contribution must permit SelfService, configuration must
// be resolved, and expiresAt must be after the acceptance time and within the
// shortest applicable maxLifetime measured from it. restrictive names the
// contributions that forbid exceptions, when known.
func admissible(a Acceptance, expiresAt time.Time, restrictive []string) *Denial {
	el := a.Eligibility
	switch {
	case el == nil:
		return &Denial{ReasonNotApplicable, fmt.Sprintf("no ComplianceBinding applies policy %q in namespace %q; there is nothing to accept", a.Policy, a.Namespace.Name)}
	case len(el.Errors) > 0:
		var reasons []string
		for _, e := range el.Errors {
			reasons = append(reasons, fmt.Sprintf("%s (binding %q)", e.Reason, e.Binding))
		}
		return &Denial{ReasonUnresolved, fmt.Sprintf("policy %q has unresolved configuration in namespace %q: %s", a.Policy, a.Namespace.Name, strings.Join(reasons, ", "))}
	case el.Effective != v1alpha1.ExceptionsSelfService || el.MaxLifetime == nil:
		msg := fmt.Sprintf("policy %q does not permit self-service exceptions in namespace %q", a.Policy, a.Namespace.Name)
		if len(restrictive) > 0 {
			msg += "; restricted by ComplianceBinding " + strings.Join(quoteAll(restrictive), ", ")
		}
		return &Denial{ReasonForbidden, msg}
	}
	at := a.AcceptedAt.Time
	if !expiresAt.After(at) {
		return &Denial{ReasonExpiryElapsed, fmt.Sprintf("expiresAt %s is not after the acceptance time %s", expiresAt.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339))}
	}
	if limit := el.MaxLifetime.Duration; expiresAt.Sub(at) > limit {
		return &Denial{ReasonLifetimeExceeded, fmt.Sprintf("expiresAt %s exceeds the maximum lifetime %s from %s (latest %s)",
			expiresAt.UTC().Format(time.RFC3339), limit, at.UTC().Format(time.RFC3339), at.Add(limit).UTC().Format(time.RFC3339))}
	}
	return nil
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
}
