package preview

import (
	"cmp"
	"slices"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// This file correlates observed engine policies with desired contributions
// (task 3.4). Observed applied state is kept apart from the desired
// configuration: a lagging, held or superseded policy is reported as what it
// is, never as a new desired impact, and a requested withdrawal is never
// reported as an immediate one.

// AppliedCondition is how an observed engine policy relates to the live
// desired configuration.
type AppliedCondition string

const (
	// AppliedCurrent: the policy is at the revision the live configuration desires.
	AppliedCurrent AppliedCondition = "current"
	// AppliedSuperseded: an earlier revision of a logical policy the binding
	// still desires. Delivery keeps it until every desired revision is ready,
	// so old and new revisions can overlap temporarily.
	AppliedSuperseded AppliedCondition = "superseded"
	// AppliedHeld: the binding or this logical policy does not resolve in the
	// live configuration; the controller keeps what it last applied.
	AppliedHeld AppliedCondition = "held"
	// AppliedNotDesired: the binding resolves but no longer desires this
	// logical policy; the controller removes it on its next reconcile.
	AppliedNotDesired AppliedCondition = "not-desired"
	// AppliedWithdrawing: the owning binding is being deleted; garbage
	// collection removes the policy.
	AppliedWithdrawing AppliedCondition = "withdrawing"
	// AppliedOrphaned: no observed binding has the owner UID; the policy may
	// enforce until garbage collection removes it.
	AppliedOrphaned AppliedCondition = "orphaned"
	// AppliedUnknown: the recorded contribution cannot be read. This is
	// unknown applied state, never an absent policy.
	AppliedUnknown AppliedCondition = "unknown"
)

// ProposedOutcome is what the candidate configuration asks of an observed
// engine policy. It is a request to the controller, not a convergence claim.
type ProposedOutcome string

const (
	// OutcomeKept: the candidate desires exactly this revision.
	OutcomeKept ProposedOutcome = "kept"
	// OutcomeReplaced: the candidate desires another revision of this logical
	// policy from the binding. This policy stays until the replacement is
	// ready, so both can enforce at the same time.
	OutcomeReplaced ProposedOutcome = "replacement-pending"
	// OutcomeWithdrawalRequested: the candidate no longer desires this
	// logical policy from the binding, or removes the binding. Removal follows
	// application and reconciliation; it is not immediate.
	OutcomeWithdrawalRequested ProposedOutcome = "withdrawal-requested"
	// OutcomeHeld: the candidate does not resolve this policy, so the
	// controller would keep this policy enforcing.
	OutcomeHeld ProposedOutcome = "held"
	// OutcomeNotAttributable: orphaned, withdrawing or unreadable policies are
	// outside what the candidate controls.
	OutcomeNotAttributable ProposedOutcome = "not-attributable"
)

// AppliedEntry is one observed Konstapel-owned engine policy.
type AppliedEntry struct {
	Policy      ObjectRef                `json:"policy"`
	Binding     string                   `json:"binding,omitempty"`
	BindingUID  types.UID                `json:"bindingUID"`
	Logical     string                   `json:"logicalPolicy,omitempty"`
	Revision    string                   `json:"revision,omitempty"`
	Mode        v1alpha1.EnforcementMode `json:"mode,omitempty"`
	Ready       bool                     `json:"ready"`
	Terminating bool                     `json:"terminating,omitempty"`
	Condition   AppliedCondition         `json:"condition"`
	Proposed    ProposedOutcome          `json:"proposed"`
	// Scope is the observed namespace instances the policy's own recorded
	// selector matches now. For a policy that is not current this is a
	// stale scope that can differ from any desired scope.
	Scope []targeting.NamespaceRef `json:"scope"`
}

// PendingDelivery is a desired live contribution with no ready engine
// policy at its revision: reconciliation lag, informational only.
type PendingDelivery struct {
	Key ContributionKey `json:"key"`
	// Applied is true when the policy exists but the engine has not accepted it.
	Applied bool `json:"applied"`
}

// AppliedState is the observed engine state correlated with both sides.
type AppliedState struct {
	Policies []AppliedEntry    `json:"policies"`
	Pending  []PendingDelivery `json:"pending,omitempty"`
	// Unowned are Konstapel-labelled policies without a matching controller
	// reference; never treated as owned.
	Unowned []ObjectRef `json:"unowned,omitempty"`
}

// unresolvedFor reports whether a binding's policy does not resolve on a
// side: a binding-level error holds everything, a policy error holds that
// policy.
func (s *side) unresolvedFor(binding, policy string) bool {
	br := s.results[binding]
	if br == nil {
		return false
	}
	for _, e := range s.errorsOf(binding) {
		if e.Policy == "" || e.Policy == policy {
			return true
		}
	}
	return false
}

func (a *adapter) scopeOf(sel v1alpha1.NamespaceSelector) []targeting.NamespaceRef {
	out := []targeting.NamespaceRef{}
	s, err := sel.AsSelector()
	if err != nil {
		return out
	}
	for _, n := range a.namespaces {
		if s.Matches(labels.Set(n.Labels)) {
			out = append(out, targeting.NamespaceRef{Name: n.Name, UID: n.UID})
		}
	}
	slices.SortFunc(out, func(x, y targeting.NamespaceRef) int {
		return cmp.Or(cmp.Compare(x.Name, y.Name), cmp.Compare(x.UID, y.UID))
	})
	return out
}

func (a *adapter) appliedState() AppliedState {
	st := AppliedState{Policies: []AppliedEntry{}, Unowned: a.snap.Unowned}
	// readyAt records, per binding UID and logical policy, the revisions
	// with a ready engine policy, and which exist at all.
	type at struct {
		uid    types.UID
		policy string
		rev    string
	}
	applied, ready := map[at]bool{}, map[at]bool{}
	for _, p := range a.snap.Applied {
		e := AppliedEntry{Policy: p.ObjectRef, BindingUID: p.BindingUID, Ready: p.Ready, Terminating: p.Terminating, Scope: []targeting.NamespaceRef{}}
		live := a.liveBinding[p.BindingUID]
		switch {
		case p.Contribution == nil:
			e.Condition, e.Proposed = AppliedUnknown, OutcomeNotAttributable
			st.Policies = append(st.Policies, e)
			continue
		case p.Ownership == Orphaned || live == nil:
			e.Condition, e.Proposed = AppliedOrphaned, OutcomeNotAttributable
		case live.DeletionTimestamp != nil:
			e.Condition, e.Proposed = AppliedWithdrawing, OutcomeNotAttributable
		}
		c := p.Contribution
		e.Binding, e.Logical, e.Revision, e.Mode = c.Binding.Name, c.Policy, c.Revision, c.Mode
		e.Scope = a.scopeOf(c.NamespaceSelector)
		k := at{p.BindingUID, c.Policy, c.Revision}
		applied[k] = true
		if p.Ready && !p.Terminating {
			ready[k] = true
		}
		if e.Condition != "" {
			st.Policies = append(st.Policies, e)
			continue
		}
		name := live.Name
		desired := a.base.contribs[[2]string{name, c.Policy}]
		switch {
		case a.base.unresolvedFor(name, c.Policy):
			e.Condition = AppliedHeld
		case desired == nil:
			e.Condition = AppliedNotDesired
		case desired.Revision == c.Revision:
			e.Condition = AppliedCurrent
		default:
			e.Condition = AppliedSuperseded
		}
		next := a.next.contribs[[2]string{name, c.Policy}]
		be := a.entry(KindBinding, name)
		switch {
		case be != nil && be.Disposition == Removed:
			e.Proposed = OutcomeWithdrawalRequested
		case a.next.unresolvedFor(name, c.Policy):
			e.Proposed = OutcomeHeld
		case next == nil:
			e.Proposed = OutcomeWithdrawalRequested
		case next.Revision == c.Revision:
			// Equality with the candidate's provisional revision is used only
			// to decide this; the value itself is never reported.
			e.Proposed = OutcomeKept
		default:
			e.Proposed = OutcomeReplaced
		}
		st.Policies = append(st.Policies, e)
	}
	slices.SortFunc(st.Policies, func(x, y AppliedEntry) int { return compareRef(x.Policy, y.Policy) })
	for _, br := range a.base.res.Bindings {
		for _, c := range br.Contributions {
			if a.base.unresolvedFor(br.Binding.Name, c.Policy) {
				continue
			}
			k := at{br.Binding.UID, c.Policy, c.Revision}
			if !ready[k] {
				st.Pending = append(st.Pending, PendingDelivery{Key: a.contributionKey(br.Binding.Name, c.Policy), Applied: applied[k]})
			}
		}
	}
	return st
}
