package preview

import (
	"fmt"
	"slices"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// Live is the observed desired state: the cluster's ComplianceProfiles and
// ComplianceBindings as read by the caller. This package never reads a cluster.
type Live struct {
	Profiles []v1alpha1.ComplianceProfile
	Bindings []v1alpha1.ComplianceBinding
	// StoredSpecs is each object's spec as the API server returned it, by
	// identity. Without it, whether a restating proposal would be stored
	// unchanged is unknown, and the comparison assumes it would not be.
	StoredSpecs map[Identity]map[string]any
}

// Disposition says what the candidate does to one identity.
type Disposition string

const (
	// Unchanged objects survive as observed, including proposed objects whose
	// normalized configuration equals the live one. Such a proposal is a
	// configuration no-op, but not necessarily a server no-op: Entry.StoredSpec
	// says whether the API server would store a different spec, which advances
	// the generation and can rotate enforcement revisions.
	Unchanged Disposition = "unchanged"
	// Created objects exist only in the proposal.
	Created Disposition = "created"
	// Replaced objects take the proposed complete specification.
	Replaced Disposition = "replaced"
	// Removed objects are declared by before-minus-after and exist live.
	Removed Disposition = "removed"
)

// Entry is one identity in the candidate with both sides kept apart.
type Entry struct {
	Identity    Identity
	Disposition Disposition
	// LiveProfile/LiveBinding are the observed object (nil when Created).
	LiveProfile *v1alpha1.ComplianceProfile
	LiveBinding *v1alpha1.ComplianceBinding
	// Proposed is the validated proposed object (nil for Removed and for
	// untouched live objects). Before is the previous-set object that declared
	// a removal.
	Proposed *Object
	Before   *Object
	// LiveFingerprint and CandidateFingerprint are set when the side exists.
	// Equal fingerprints mean equal normalized configuration only; they are
	// not enforcement revisions.
	LiveFingerprint      string
	CandidateFingerprint string
	// StoredSpec compares the proposal with the live stored spec for live
	// objects that a proposal restates (Unchanged or Replaced).
	StoredSpec StoredSpecChange
}

// Candidate is the proposed configuration: live desired state, plus proposed
// complete specifications, minus declared removals.
type Candidate struct {
	// Entries cover every live or proposed identity, sorted by kind then name.
	Entries []Entry
	// AbsentRemovals are declared removals of objects that do not exist live;
	// they create no removal impact.
	AbsentRemovals []Identity
	// Profiles and Bindings are the surviving objects, sorted by name. Unchanged
	// objects carry their observed metadata. Created and Replaced objects carry
	// only their name and candidate spec: their server identity (UID,
	// generation, epoch) is pending and is NOT copied from the live object, so
	// a Replaced object cannot be mistaken for the observed revision.
	Profiles []v1alpha1.ComplianceProfile
	Bindings []v1alpha1.ComplianceBinding
}

// BuildCandidate applies the explicit input model of the design: each
// proposed object replaces the live object of the same identity as its complete
// specification, identities in before but not in proposed are removed, and
// every other live object is preserved. A nil before or proposed set is empty.
// An invalid candidate (a duplicate live identity, a profile removed or missing
// while a binding needs it) returns InputErrors and no candidate.
func BuildCandidate(live Live, proposed, before *Set) (*Candidate, error) {
	var errs InputErrors
	liveProfiles := map[string]*v1alpha1.ComplianceProfile{}
	for i := range live.Profiles {
		p := &live.Profiles[i]
		if liveProfiles[p.Name] != nil {
			errs = append(errs, InputError{Code: CodeDuplicateLive, Identity: Identity{Kind: KindProfile, Name: p.Name}.String(), Message: "the observed state lists this object twice"})
		}
		liveProfiles[p.Name] = p
	}
	liveBindings := map[string]*v1alpha1.ComplianceBinding{}
	for i := range live.Bindings {
		b := &live.Bindings[i]
		if liveBindings[b.Name] != nil {
			errs = append(errs, InputError{Code: CodeDuplicateLive, Identity: Identity{Kind: KindBinding, Name: b.Name}.String(), Message: "the observed state lists this object twice"})
		}
		liveBindings[b.Name] = b
	}
	if len(errs) > 0 {
		return nil, errs
	}

	group := v1alpha1.GroupVersion.Group
	entries := map[Identity]*Entry{}
	for name, p := range liveProfiles {
		id := Identity{group, KindProfile, name}
		entries[id] = &Entry{Identity: id, Disposition: Unchanged, LiveProfile: p, LiveFingerprint: Fingerprint(p, nil)}
		entries[id].CandidateFingerprint = entries[id].LiveFingerprint
	}
	for name, b := range liveBindings {
		id := Identity{group, KindBinding, name}
		entries[id] = &Entry{Identity: id, Disposition: Unchanged, LiveBinding: b, LiveFingerprint: Fingerprint(nil, b)}
		entries[id].CandidateFingerprint = entries[id].LiveFingerprint
	}

	var absent []Identity
	if before != nil {
		for _, o := range before.Objects {
			if proposed.Get(o.Identity) != nil {
				continue
			}
			e := entries[o.Identity]
			if e == nil {
				absent = append(absent, o.Identity)
				continue
			}
			e.Disposition, e.Before, e.CandidateFingerprint = Removed, o, ""
		}
	}
	if proposed != nil {
		for _, o := range proposed.Objects {
			e := entries[o.Identity]
			if e != nil {
				e.StoredSpec = compareStored(o.Identity.Kind, live.StoredSpecs[o.Identity], o.Spec)
			}
			switch {
			case e == nil:
				entries[o.Identity] = &Entry{Identity: o.Identity, Disposition: Created, Proposed: o, CandidateFingerprint: o.Fingerprint}
			case e.LiveFingerprint == o.Fingerprint:
				// The proposal restates the live configuration: a no-op that
				// keeps the observed object and its identity.
				e.Proposed = o
			default:
				e.Disposition, e.Proposed, e.CandidateFingerprint = Replaced, o, o.Fingerprint
			}
		}
	}

	c := &Candidate{AbsentRemovals: absent}
	for _, e := range entries {
		c.Entries = append(c.Entries, *e)
	}
	slices.SortFunc(c.Entries, func(a, b Entry) int { return compareIdentity(a.Identity, b.Identity) })
	slices.SortFunc(c.AbsentRemovals, compareIdentity)

	for _, e := range c.Entries {
		switch {
		case e.Disposition == Removed:
		case e.Identity.Kind == KindProfile:
			c.Profiles = append(c.Profiles, survivingProfile(e))
		default:
			c.Bindings = append(c.Bindings, survivingBinding(e))
		}
	}

	if errs = c.checkReferences(); len(errs) > 0 {
		return nil, errs
	}
	return c, nil
}

func survivingProfile(e Entry) v1alpha1.ComplianceProfile {
	if e.Disposition == Unchanged {
		return *e.LiveProfile.DeepCopy()
	}
	p := e.Proposed.Profile.DeepCopy()
	return *p
}

func survivingBinding(e Entry) v1alpha1.ComplianceBinding {
	if e.Disposition == Unchanged {
		return *e.LiveBinding.DeepCopy()
	}
	return *e.Proposed.Binding.DeepCopy()
}

// checkReferences attributes unresolvable profile references to the proposal.
// A pre-existing dangling reference that the proposal does not touch is a
// baseline condition the resolver reports (ProfileNotFound), not an input error.
func (c *Candidate) checkReferences() InputErrors {
	profiles := map[string]bool{}
	removed := map[string]*Entry{}
	for i := range c.Entries {
		e := &c.Entries[i]
		if e.Identity.Kind != KindProfile {
			continue
		}
		if e.Disposition == Removed {
			removed[e.Identity.Name] = e
		} else {
			profiles[e.Identity.Name] = true
		}
	}
	var errs InputErrors
	for _, e := range c.Entries {
		if e.Identity.Kind != KindBinding || e.Disposition == Removed {
			continue
		}
		var ref string
		if e.Disposition == Unchanged {
			ref = e.LiveBinding.Spec.ProfileRef.Name
		} else {
			ref = e.Proposed.Binding.Spec.ProfileRef.Name
		}
		if profiles[ref] {
			continue
		}
		ie := InputError{Identity: e.Identity.String(), Field: "spec.profileRef.name"}
		if r := removed[ref]; r != nil {
			ie.Code = CodeProfileRemoved
			ie.Message = fmt.Sprintf("ComplianceProfile %q is removed by the proposal (declared in %s) but this binding still references it; remove or update the binding too. Policies already applied for it may remain enforcing until the binding is removed or re-resolved", ref, r.Before.Source)
			if r.Before != nil {
				ie.Source, ie.Document, ie.Line = e.sourceOf()
			}
			errs = append(errs, ie)
			continue
		}
		if e.Disposition == Unchanged {
			continue
		}
		ie.Code = CodeProfileNotFound
		ie.Message = fmt.Sprintf("ComplianceProfile %q is neither in the observed state nor in the proposal", ref)
		ie.Source, ie.Document, ie.Line = e.sourceOf()
		errs = append(errs, ie)
	}
	return errs
}

func (e Entry) sourceOf() (string, int, int) {
	if e.Proposed != nil {
		return e.Proposed.Source, e.Proposed.Document, e.Proposed.Line
	}
	return "", 0, 0
}
