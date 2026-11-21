package preview

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// This file is the shared resolution and semantic comparison (tasks 3.1 to
// 3.3). The observed live configuration (the baseline) and the candidate are
// resolved by the controller's own targeting.Resolve, with content from the
// same ContentSource seam, and compared per contribution and per namespace
// instance. Observed identities stay separate from the provisional values a
// private resolver adapter needs for new or changed objects: those values
// and everything derived from them (revisions, engine policy names) never
// leave this file.

// RevisionEffect says what a proposal does to a contribution's enforcement
// revision. Revisions themselves are assigned by the controller after
// application; the preview never states a future revision value.
type RevisionEffect string

const (
	// RevisionUnchanged: the controller would compute the observed revision.
	RevisionUnchanged RevisionEffect = "unchanged"
	// RevisionReplacement: the controller would compute a new revision. The
	// engine policy is replaced under a new name and anything bound to the
	// old revision, such as an accepted exception, no longer matches it.
	RevisionReplacement RevisionEffect = "replacement-required"
	// RevisionNew: the contribution does not exist in the live configuration.
	RevisionNew RevisionEffect = "new"
)

// ChangeKind is how a contribution differs between baseline and candidate.
type ChangeKind string

const (
	ChangeAdded   ChangeKind = "added"
	ChangeRemoved ChangeKind = "removed"
	ChangeChanged ChangeKind = "changed"
)

// Category is a framework-neutral impact category. Categories describe what
// changes and in which direction; they carry no compliance score and do not
// judge a change as good or bad.
type Category string

const (
	CategoryContributionAdded   Category = "contribution-added"
	CategoryContributionRemoved Category = "contribution-removed"
	CategoryProfile             Category = "profile-changed"
	CategoryBundlePin           Category = "bundle-pin-changed"
	CategoryParameters          Category = "parameters-changed"
	CategorySelector            Category = "selector-changed"
	CategoryNamespaceAdded      Category = "namespace-added"
	CategoryNamespaceRemoved    Category = "namespace-removed"
	CategoryMode                Category = "mode-changed"
	CategoryRevision            Category = "revision-replaced"
	CategoryExceptionRule       Category = "exception-rule-changed"
	CategoryEligibility         Category = "eligibility-changed"
)

// Area groups categories: policy and configuration, namespace scope,
// enforcement, and exception changes.
type Area string

const (
	AreaPolicy      Area = "policy"
	AreaScope       Area = "scope"
	AreaEnforcement Area = "enforcement"
	AreaException   Area = "exception"
)

// AreaOf returns the area of a category.
func AreaOf(c Category) Area {
	switch c {
	case CategorySelector, CategoryNamespaceAdded, CategoryNamespaceRemoved:
		return AreaScope
	case CategoryMode, CategoryRevision:
		return AreaEnforcement
	case CategoryExceptionRule, CategoryEligibility:
		return AreaException
	}
	return AreaPolicy
}

// Impact is one classified difference with its before and after values.
type Impact struct {
	Category Category `json:"category"`
	Area     Area     `json:"area"`
	Before   string   `json:"before,omitempty"`
	After    string   `json:"after,omitempty"`
	Reason   string   `json:"reason"`
}

// ContributionKey is the stable comparison key of a contribution: the
// cluster, the binding by name (and its observed UID when it exists live),
// and the logical policy.
type ContributionKey struct {
	Cluster string `json:"cluster"`
	Binding string `json:"binding"`
	// BindingUID is the observed UID; empty for a binding pending creation.
	BindingUID types.UID `json:"bindingUID,omitempty"`
	Policy     string    `json:"policy"`
}

// ContributionSide is one side of a contribution. Observed fields (profile
// UID and generation, the desired revision) are set only on the baseline
// side; the proposed side carries configuration values only.
type ContributionSide struct {
	Profile           string    `json:"profile"`
	ProfileUID        types.UID `json:"profileUID,omitempty"`
	ProfileGeneration int64     `json:"profileGeneration,omitempty"`
	BundleName        string    `json:"bundleName"`
	BundleDigest      string    `json:"bundleDigest"`
	// BundleDigestKind says whether BundleDigest is a vendored
	// checksum-manifest digest or an OCI manifest digest.
	BundleDigestKind DigestKind `json:"bundleDigestKind"`
	// ConfigurationDigest is targeting.ConfigurationDigest of the policy's
	// parameters and exception settings: a function of the configuration,
	// not a server-assigned value.
	ConfigurationDigest string                     `json:"configurationDigest"`
	Parameters          any                        `json:"parameters,omitempty"`
	Mode                v1alpha1.EnforcementMode   `json:"mode"`
	NamespaceSelector   v1alpha1.NamespaceSelector `json:"namespaceSelector"`
	Exceptions          v1alpha1.ExceptionSettings `json:"exceptions"`
	// DesiredRevision is the revision the controller computes from the live
	// configuration (baseline only). Whether it is applied is AppliedState.
	DesiredRevision string `json:"desiredRevision,omitempty"`
	// Targets are the observed namespace instances the binding selects.
	Targets     []targeting.NamespaceRef `json:"targets"`
	TargetCount int                      `json:"targetCount"`
}

// Responsible names an input behind a change.
type Responsible struct {
	Identity    string      `json:"identity"`
	Disposition Disposition `json:"disposition"`
	Source      string      `json:"source,omitempty"`
	Document    int         `json:"document,omitempty"`
	Line        int         `json:"line,omitempty"`
}

// ContributionChange is one configuration-level row: one binding's
// contribution of one logical policy. It exists even when the binding
// selects no namespace.
type ContributionChange struct {
	Key            ContributionKey `json:"key"`
	Change         ChangeKind      `json:"change"`
	RevisionEffect RevisionEffect  `json:"revisionEffect,omitempty"`
	// SemanticallyEquivalent is true when the configuration is the same but
	// the revision is still replaced, for example after reordered selector
	// expressions or another edit of a shared profile.
	SemanticallyEquivalent bool                     `json:"semanticallyEquivalent,omitempty"`
	Before                 *ContributionSide        `json:"before,omitempty"`
	After                  *ContributionSide        `json:"after,omitempty"`
	NamespacesAdded        []targeting.NamespaceRef `json:"namespacesAdded,omitempty"`
	NamespacesRemoved      []targeting.NamespaceRef `json:"namespacesRemoved,omitempty"`
	Responsible            []Responsible            `json:"responsible,omitempty"`
	Impacts                []Impact                 `json:"impacts"`
}

// ContributorRef is one contribution applying to a namespace and policy.
type ContributorRef struct {
	Binding    string                   `json:"binding"`
	BindingUID types.UID                `json:"bindingUID,omitempty"`
	Mode       v1alpha1.EnforcementMode `json:"mode"`
	// RevisionEffect is set on the candidate side.
	RevisionEffect RevisionEffect `json:"revisionEffect,omitempty"`
}

// EligibilitySide is the effective exception eligibility on one side.
type EligibilitySide struct {
	Effective   v1alpha1.ExceptionEligibility `json:"effective"`
	MaxLifetime *targeting.Duration           `json:"maxLifetime,omitempty"`
	Errors      []targeting.Reason            `json:"errors,omitempty"`
}

// NamespaceChange is one observed namespace instance and logical policy
// whose applicable contributions or effective eligibility change. Remaining
// lists the contributions that keep applying, so overlap stays visible.
type NamespaceChange struct {
	Namespace targeting.NamespaceRef `json:"namespace"`
	Policy    string                 `json:"policy"`
	Added     []ContributorRef       `json:"added,omitempty"`
	Removed   []ContributorRef       `json:"removed,omitempty"`
	Replaced  []ContributorRef       `json:"replaced,omitempty"`
	Remaining []ContributorRef       `json:"remaining,omitempty"`
	Before    *EligibilitySide       `json:"before,omitempty"`
	After     *EligibilitySide       `json:"after,omitempty"`
	Impacts   []Impact               `json:"impacts"`
}

// ObservedIdentity is a live object's server identity.
type ObservedIdentity struct {
	UID              types.UID `json:"uid"`
	Generation       int64     `json:"generation"`
	EnforcementEpoch int64     `json:"enforcementEpoch,omitempty"`
}

// ObjectChange is one profile or binding that the proposal touches.
type ObjectChange struct {
	Identity    string      `json:"identity"`
	Disposition Disposition `json:"disposition"`
	// Observed is the live identity; nil for an object pending creation.
	Observed *ObservedIdentity `json:"observed,omitempty"`
	// PendingIdentity is true when the server identity or revision inputs
	// after application are assigned by the API server and not known here.
	PendingIdentity bool `json:"pendingIdentity,omitempty"`
	// ConfigurationChanged compares normalized configuration fingerprints.
	ConfigurationChanged bool `json:"configurationChanged"`
	// StoredSpec compares what the API server would store.
	StoredSpec StoredSpecChange `json:"storedSpec,omitempty"`
	// ReportingOnly: a binding change outside profileRef, namespaceSelector
	// and mode. It is informational, never an impact by itself.
	ReportingOnly bool `json:"reportingOnly,omitempty"`
	// Fingerprints are semantic-equivalence aids, not revisions and not
	// acceptance tokens.
	LiveFingerprint      string   `json:"liveConfigurationFingerprint,omitempty"`
	CandidateFingerprint string   `json:"candidateConfigurationFingerprint,omitempty"`
	Source               string   `json:"source,omitempty"`
	Document             int      `json:"document,omitempty"`
	Line                 int      `json:"line,omitempty"`
	Notes                []string `json:"notes,omitempty"`
}

// Comparison codes. Errors make a comparison incomplete; limitations do not.
const (
	CompareContentFailed       ObserveCode = "content-failed"
	CompareContentMismatch     ObserveCode = "content-mismatch"
	CompareUnresolvedBaseline  ObserveCode = "unresolved-baseline"
	CompareUnresolvedCandidate ObserveCode = "unresolved-candidate"

	LimitBaselineUnresolved  ObserveCode = "baseline-unresolved"
	LimitEpochUnavailable    ObserveCode = "enforcement-epoch-unavailable"
	LimitRenderedInput       ObserveCode = "rendered-input-assumptions"
	LimitNoWorkloadEvaluated ObserveCode = "no-workload-evaluation"
)

// Comparison is the semantic comparison of the observed baseline and the
// candidate. Only a Complete comparison supports a statement that no impact
// exists; an incomplete one still lists what it could determine.
type Comparison struct {
	Complete  bool           `json:"complete"`
	Cluster   string         `json:"cluster"`
	Contracts map[string]int `json:"contracts"`
	// ImpactCount counts contribution and namespace rows with at least one
	// impact. It is not a count of workloads, failures or controls.
	ImpactCount int            `json:"impactCount"`
	Objects     []ObjectChange `json:"objects"`
	// Content is every pinned bundle read, with its typed digest.
	Content        []ContentRecord      `json:"content"`
	AbsentRemovals []string             `json:"absentRemovals,omitempty"`
	Contributions  []ContributionChange `json:"contributions"`
	Namespaces     []NamespaceChange    `json:"namespaces"`
	Applied        AppliedState         `json:"appliedState"`
	Limitations    []Diagnostic         `json:"limitations,omitempty"`
	Errors         []Diagnostic         `json:"errors,omitempty"`
	// subjects are the expected-evidence subjects of the observed bindings
	// the proposal involves, for the report's evidence part (evidence.go).
	subjects map[string]*bindingSubjects
}

// CompareInput is a complete observation, the validated input sets and the
// verified content seam. Content is the same targeting.ContentSource the
// controller resolves through; it must not fall back to unverified content.
type CompareInput struct {
	Snapshot *Snapshot
	Proposed *Set
	Before   *Set
	Content  targeting.ContentSource
}

// Compare resolves the baseline and the candidate and compares them. It
// returns an error, and no comparison, for an incomplete observation, a
// missing content source or an invalid candidate (InputErrors). Otherwise it
// returns the comparison, which is incomplete when content could not be read
// or an affected contribution does not resolve on either side.
func Compare(ctx context.Context, in CompareInput) (*Comparison, error) {
	snap := in.Snapshot
	switch {
	case snap == nil || !snap.Complete:
		return nil, errors.New("a complete cluster observation is required; an incomplete one cannot be compared")
	case in.Content == nil:
		return nil, errors.New("a verified content source is required")
	}
	cand, err := BuildCandidate(snap.Live, in.Proposed, in.Before)
	if err != nil {
		return nil, err
	}
	a := newAdapter(snap, cand)
	if err := a.resolve(ctx, in.Content); err != nil {
		return nil, err
	}
	c := &Comparison{Cluster: snap.Cluster, Contracts: map[string]int{"targeting": targeting.ContractVersion},
		Objects: a.objectChanges(), Contributions: []ContributionChange{}, Namespaces: []NamespaceChange{}}
	for _, id := range cand.AbsentRemovals {
		c.AbsentRemovals = append(c.AbsentRemovals, id.String())
	}
	c.Contributions = a.contributionChanges()
	for _, r := range c.Contributions {
		for _, side := range []*ContributionSide{r.Before, r.After} {
			if side != nil {
				side.BundleDigestKind = contentKind(in.Content, side.BundleName)
			}
		}
	}
	c.Content = a.content
	c.Namespaces = a.namespaceChanges()
	c.Applied = a.appliedState()
	for _, r := range c.Contributions {
		if len(r.Impacts) > 0 {
			c.ImpactCount++
		}
	}
	for _, r := range c.Namespaces {
		if len(r.Impacts) > 0 {
			c.ImpactCount++
		}
	}
	live := map[string]bool{}
	for _, b := range a.base.in.Bindings {
		live[b.Name] = true
	}
	c.subjects = a.expectedEvidence(evidenceBindings(c, live))
	c.Errors = sortDiagnostics(a.errors)
	c.Complete = len(c.Errors) == 0
	c.Limitations = sortDiagnostics(append(slices.Clone(snap.Limitations), append(a.limitations,
		Diagnostic{Code: LimitRenderedInput, Message: "each proposed object is treated as its complete specification; server-side apply field ownership, merge patches, GitOps prune settings and admission other than schema defaults and the enforcement epoch are not reproduced, and nothing here is guaranteed at apply time"},
		Diagnostic{Code: LimitNoWorkloadEvaluated, Message: "configuration effects only: no workload is evaluated, so nothing here says that a workload will pass, fail or be evicted"})...))
	return c, nil
}

// side is one resolved configuration.
type side struct {
	in       targeting.Input
	res      targeting.Result
	profiles map[string]*v1alpha1.ComplianceProfile
	// bindings by name, with their result.
	results map[string]*targeting.BindingResult
	// contributions by binding name and policy.
	contribs map[[2]string]*targeting.Contribution
	// render errors by binding name: controller would hold these policies.
	renderErrs map[string][]targeting.ResolutionError
}

type adapter struct {
	content []ContentRecord
	// resolved is the verified content of every pin that resolved.
	resolved    map[v1alpha1.BundleReference]*targeting.Content
	snap        *Snapshot
	cand        *Candidate
	entries     map[Identity]*Entry
	liveBinding map[types.UID]*v1alpha1.ComplianceBinding
	namespaces  []targeting.Namespace
	base, next  side
	// epochUnavailable lists bindings rewritten without an observed epoch.
	epochUnavailable map[string]bool
	errors           []Diagnostic
	limitations      []Diagnostic
}

func newAdapter(snap *Snapshot, cand *Candidate) *adapter {
	a := &adapter{snap: snap, cand: cand, entries: map[Identity]*Entry{}, liveBinding: map[types.UID]*v1alpha1.ComplianceBinding{},
		epochUnavailable: map[string]bool{}}
	for i := range cand.Entries {
		e := &cand.Entries[i]
		a.entries[e.Identity] = e
	}
	for i := range snap.Live.Bindings {
		a.liveBinding[snap.Live.Bindings[i].UID] = &snap.Live.Bindings[i]
	}
	// The controller resolves only namespaces that are not terminating.
	for _, n := range snap.Namespaces {
		if !n.Terminating {
			a.namespaces = append(a.namespaces, targeting.Namespace{Name: n.Name, UID: n.UID, Labels: n.Labels})
		}
	}
	return a
}

func (a *adapter) entry(kind, name string) *Entry {
	return a.entries[Identity{Group: v1alpha1.GroupVersion.Group, Kind: kind, Name: name}]
}

// plain is an entry the candidate keeps exactly as stored: no generation or
// epoch change can follow from the proposal.
func plain(e *Entry) bool {
	return e == nil || (e.Disposition == Unchanged && (e.StoredSpec == StoredSpecNotProposed || e.StoredSpec == StoredSpecEqual))
}

// pendingUID is a provisional UID for an object pending creation. It is used
// only inside the resolver adapter and is never reported.
func pendingUID(id Identity) types.UID {
	return types.UID("preview-pending/" + id.Kind + "/" + id.Name)
}

// candidateProfile returns the profile the resolver sees for the candidate.
// A profile whose stored spec changes gets the next generation, which is
// what the API server assigns; a created one gets a provisional identity.
func (a *adapter) candidateProfile(p v1alpha1.ComplianceProfile) v1alpha1.ComplianceProfile {
	e := a.entry(KindProfile, p.Name)
	switch {
	case plain(e):
		return p
	case e.Proposed != nil:
		// The spec as proposed, not the equivalent live one: list order is
		// what the server stores.
		p.Spec = *e.Proposed.Profile.Spec.DeepCopy()
	}
	switch {
	case e.Disposition == Created:
		p.UID, p.Generation = pendingUID(e.Identity), 1
	default:
		p.UID, p.Generation = e.LiveProfile.UID, e.LiveProfile.Generation+1
	}
	return p
}

// candidateBinding returns the binding the resolver sees for the candidate,
// with the enforcement epoch the konstapel-binding-enforcement-epoch policy
// would assign. Without an observed epoch the preview cannot see whether
// that policy is installed; it then assumes the generation fallback, under
// which every stored change rotates revisions.
func (a *adapter) candidateBinding(b v1alpha1.ComplianceBinding) v1alpha1.ComplianceBinding {
	e := a.entry(KindBinding, b.Name)
	switch {
	case plain(e):
		return b
	case e.Proposed != nil:
		// EnforcementRevision hashes the selector as written, so the
		// proposed spelling counts even when it is equivalent to the live one.
		b.Spec = *e.Proposed.Binding.Spec.DeepCopy()
	}
	switch {
	case e.Disposition == Created:
		b.UID, b.Generation, b.Spec.EnforcementEpoch = pendingUID(e.Identity), 1, 1
		return b
	}
	live := e.LiveBinding
	b.UID, b.Generation = live.UID, live.Generation+1
	var proposed map[string]any
	if e.Proposed != nil {
		proposed = e.Proposed.Spec
	}
	changed := enforcementFieldsChanged(a.snap.Live.StoredSpecs[e.Identity], proposed)
	switch {
	case live.Spec.EnforcementEpoch > 0 && changed:
		b.Spec.EnforcementEpoch = live.Spec.EnforcementEpoch + 1
	case live.Spec.EnforcementEpoch > 0:
		b.Spec.EnforcementEpoch = live.Spec.EnforcementEpoch
	default:
		b.Spec.EnforcementEpoch = 0
		a.epochUnavailable[b.Name] = true
	}
	return b
}

func (a *adapter) resolve(ctx context.Context, src targeting.ContentSource) error {
	var baseBindings, nextBindings []v1alpha1.ComplianceBinding
	// A terminating binding is not reconciled; its policies are withdrawn by
	// garbage collection (AppliedState).
	for _, b := range a.snap.Live.Bindings {
		if b.DeletionTimestamp == nil {
			baseBindings = append(baseBindings, b)
		}
	}
	for _, b := range a.cand.Bindings {
		if e := a.entry(KindBinding, b.Name); e != nil && e.LiveBinding != nil && e.LiveBinding.DeletionTimestamp != nil {
			continue
		}
		nextBindings = append(nextBindings, a.candidateBinding(b))
	}
	nextProfiles := make([]v1alpha1.ComplianceProfile, 0, len(a.cand.Profiles))
	for _, p := range a.cand.Profiles {
		nextProfiles = append(nextProfiles, a.candidateProfile(p))
	}
	a.base.in = targeting.Input{Cluster: a.snap.Cluster, Profiles: slices.Clone(a.snap.Live.Profiles), Bindings: baseBindings, Namespaces: a.namespaces}
	a.next.in = targeting.Input{Cluster: a.snap.Cluster, Profiles: nextProfiles, Bindings: nextBindings, Namespaces: a.namespaces}

	// Content for every bundle a binding needs on either side, read once
	// through the verified seam, exactly by name and digest.
	refs := map[v1alpha1.BundleReference]bool{}
	for _, s := range []*side{&a.base, &a.next} {
		profiles := map[string]v1alpha1.ComplianceProfile{}
		for _, p := range s.in.Profiles {
			profiles[p.Name] = p
		}
		for _, b := range s.in.Bindings {
			if p, ok := profiles[b.Spec.ProfileRef.Name]; ok {
				refs[p.Spec.Bundle] = true
			}
		}
	}
	contents := map[v1alpha1.BundleReference]*targeting.Content{}
	unavailable := map[v1alpha1.BundleReference]error{}
	for _, ref := range slices.SortedFunc(maps.Keys(refs), func(x, y v1alpha1.BundleReference) int {
		return cmp.Or(cmp.Compare(x.Name, y.Name), cmp.Compare(x.Digest, y.Digest))
	}) {
		got, err := src.Content(ctx, ref)
		rec := ContentRecord{Name: ref.Name, Digest: ref.Digest, DigestKind: contentKind(src, ref.Name), ErrorClass: targeting.ContentErrorClassOf(err), Error: boundedError(err)}
		if bc, ok := src.(*BundleContent); ok {
			rec.Repository = bc.Repository(ref.Name)
		}
		var denied *ContentAccessError
		switch {
		case ctx.Err() != nil:
			return fmt.Errorf("resolving content: %w", ctx.Err())
		case errors.As(err, &denied):
			// The caller's access, not the cluster, is why this content is
			// unavailable: never a complete comparison, whoever pins it.
			a.errors = append(a.errors, Diagnostic{Code: CompareContentAccessDenied, Name: ref.Name + "@" + ref.Digest, Message: denied.Error()})
			unavailable[ref] = err
		case errors.Is(err, targeting.ErrContentUnavailable):
			unavailable[ref] = err
		case err != nil:
			a.errors = append(a.errors, Diagnostic{Code: CompareContentFailed, Name: ref.Name + "@" + ref.Digest, Message: "content could not be read: " + err.Error()})
			unavailable[ref] = err
		case got == nil || got.Bundle.Ref() != ref:
			// Content is never substituted: what resolved must be exactly the pin.
			a.errors = append(a.errors, Diagnostic{Code: CompareContentMismatch, Name: ref.Name + "@" + ref.Digest, Message: "the content source returned content for another reference"})
			unavailable[ref] = errors.New("content mismatch")
		default:
			rec.Resolved = true
			contents[ref] = got
			a.base.in.Bundles = append(a.base.in.Bundles, got.Bundle)
			a.next.in.Bundles = append(a.next.in.Bundles, got.Bundle)
		}
		a.content = append(a.content, rec)
	}
	if bc, ok := src.(*BundleContent); ok {
		a.limitations = append(a.limitations, bc.Limitations()...)
	}
	a.resolved = contents
	for _, s := range []*side{&a.base, &a.next} {
		s.res = targeting.Resolve(s.in)
		s.profiles = map[string]*v1alpha1.ComplianceProfile{}
		for i := range s.in.Profiles {
			s.profiles[s.in.Profiles[i].Name] = &s.in.Profiles[i]
		}
		s.results = map[string]*targeting.BindingResult{}
		s.contribs = map[[2]string]*targeting.Contribution{}
		s.renderErrs = map[string][]targeting.ResolutionError{}
		for i := range s.res.Bindings {
			br := &s.res.Bindings[i]
			s.results[br.Binding.Name] = br
			for j := range br.Contributions {
				c := &br.Contributions[j]
				s.contribs[[2]string{br.Binding.Name, c.Policy}] = c
				// The controller renders each contribution and holds the
				// policy when rendering fails.
				if ct := contents[v1alpha1.BundleReference{Name: c.BundleName, Digest: c.BundleDigest}]; ct != nil {
					if _, err := targeting.Render(*c, ct.Policies[c.Policy]); err != nil {
						s.renderErrs[br.Binding.Name] = append(s.renderErrs[br.Binding.Name], targeting.ResolutionError{
							Reason: targeting.ReasonInvalidConfiguration, Binding: br.Binding.Name, Policy: c.Policy, Message: "policy cannot be rendered: " + err.Error()})
					}
				}
			}
		}
	}
	a.diagnoseResolution(unavailable)
	for _, name := range slices.Sorted(maps.Keys(a.epochUnavailable)) {
		a.limitations = append(a.limitations, Diagnostic{Code: LimitEpochUnavailable, Resource: resourceString(gvrBindings), Name: name,
			Message: "the live binding has no enforcementEpoch, so whether the konstapel-binding-enforcement-epoch admission policy keeps its revisions cannot be observed; the preview assumes the generation fallback, under which this edit replaces every revision of the binding"})
	}
	return nil
}

// affected reports whether a binding's resolution can differ between the
// baseline and the candidate: the binding or a profile it references on
// either side is created, removed or stored differently.
func (a *adapter) affected(binding string) bool {
	e := a.entry(KindBinding, binding)
	if !plain(e) {
		return true
	}
	for _, s := range []*side{&a.base, &a.next} {
		for _, b := range s.in.Bindings {
			if b.Name == binding && !plain(a.entry(KindProfile, b.Spec.ProfileRef.Name)) {
				return true
			}
		}
	}
	return false
}

func (s *side) errorsOf(binding string) []targeting.ResolutionError {
	var out []targeting.ResolutionError
	if br := s.results[binding]; br != nil {
		out = append(out, br.Errors...)
	}
	return append(out, s.renderErrs[binding]...)
}

// diagnoseResolution makes the comparison incomplete when an affected
// binding does not resolve on either side: its contributions there cannot be
// determined, and the controller keeps what it last applied. Unresolved
// bindings the proposal cannot change are informational.
func (a *adapter) diagnoseResolution(unavailable map[v1alpha1.BundleReference]error) {
	names := map[string]bool{}
	for _, s := range []*side{&a.base, &a.next} {
		for n := range s.results {
			names[n] = true
		}
	}
	detail := func(e targeting.ResolutionError, s *side) string {
		msg := fmt.Sprintf("%s: %s", e.Reason, e.Message)
		if e.Reason == targeting.ReasonContentUnavailable {
			if p := s.profiles[e.Profile]; p != nil {
				if err := unavailable[p.Spec.Bundle]; err != nil {
					if class := targeting.ContentErrorClassOf(err); class != "" {
						msg += " (" + string(class) + ")"
					}
				}
			}
		}
		return msg
	}
	for _, n := range slices.Sorted(maps.Keys(names)) {
		baseErrs, nextErrs := a.base.errorsOf(n), a.next.errorsOf(n)
		if !a.affected(n) {
			for _, e := range baseErrs {
				if e.Reason == targeting.ReasonContentUnavailable && a.environmentDependent(e, unavailable) {
					// The preview reads content itself, from where it runs
					// and with its own vendored tree. A failure that depends
					// on that is not a known baseline condition: whether the
					// controller resolves it is not observed, so this
					// binding's overlap with the proposal is unknown.
					a.errors = append(a.errors, Diagnostic{Code: CompareContentUnavailable, Resource: resourceString(gvrBindings), Name: n,
						Message: "the preview could not read the content this live binding pins, for a reason that depends on where the preview runs, so its contributions and their overlap with the proposal cannot be determined; whether the controller resolves it is not observed: " + detail(e, &a.base)})
					continue
				}
				a.limitations = append(a.limitations, Diagnostic{Code: LimitBaselineUnresolved, Resource: resourceString(gvrBindings), Name: n,
					Message: "the live configuration does not resolve and the proposal does not change it; previously applied policies may remain enforcing: " + detail(e, &a.base)})
			}
			continue
		}
		for _, e := range baseErrs {
			a.errors = append(a.errors, Diagnostic{Code: CompareUnresolvedBaseline, Resource: resourceString(gvrBindings), Name: n,
				Message: "the live configuration of an affected binding does not resolve, so its current contributions cannot be determined; previously applied policies may remain enforcing: " + detail(e, &a.base)})
		}
		for _, e := range nextErrs {
			a.errors = append(a.errors, Diagnostic{Code: CompareUnresolvedCandidate, Resource: resourceString(gvrBindings), Name: n,
				Message: "the proposed configuration does not resolve; the controller would keep the previously applied policies for it: " + detail(e, &a.next)})
		}
	}
}

// environmentDependent reports whether a content failure behind a baseline
// resolution error depends on where the preview runs rather than on the
// observed configuration and the content: a retrieval, proof, cache or
// vendored-tree failure, or one without a class. A verdict the controller
// reaches the same way under the observed sources and trust (no source,
// untrusted, incompatible, a digest mismatch, malformed content) is not.
func (a *adapter) environmentDependent(e targeting.ResolutionError, unavailable map[v1alpha1.BundleReference]error) bool {
	p := a.base.profiles[e.Profile]
	if p == nil {
		return true
	}
	switch targeting.ContentErrorClassOf(unavailable[p.Spec.Bundle]) {
	case targeting.ContentErrorConfig, targeting.ContentErrorUntrusted, targeting.ContentErrorIncompatible,
		targeting.ContentErrorDigestMismatch, targeting.ContentErrorMalformed:
		return false
	}
	return true
}

func (a *adapter) objectChanges() []ObjectChange {
	out := []ObjectChange{}
	for _, e := range a.cand.Entries {
		if e.Disposition == Unchanged && e.StoredSpec == StoredSpecNotProposed {
			continue
		}
		o := ObjectChange{Identity: e.Identity.String(), Disposition: e.Disposition, StoredSpec: e.StoredSpec,
			ConfigurationChanged: e.LiveFingerprint != e.CandidateFingerprint, LiveFingerprint: e.LiveFingerprint, CandidateFingerprint: e.CandidateFingerprint}
		switch {
		case e.LiveProfile != nil:
			o.Observed = &ObservedIdentity{UID: e.LiveProfile.UID, Generation: e.LiveProfile.Generation}
		case e.LiveBinding != nil:
			o.Observed = &ObservedIdentity{UID: e.LiveBinding.UID, Generation: e.LiveBinding.Generation, EnforcementEpoch: e.LiveBinding.Spec.EnforcementEpoch}
		}
		switch {
		case e.Proposed != nil:
			o.Source, o.Document, o.Line = e.Proposed.Source, e.Proposed.Document, e.Proposed.Line
		case e.Before != nil:
			o.Source, o.Document, o.Line = e.Before.Source, e.Before.Document, e.Before.Line
		}
		if e.Disposition != Removed && !plain(&e) {
			o.PendingIdentity = true
		}
		if e.Disposition == Replaced && e.Identity.Kind == KindBinding && e.Proposed != nil &&
			!enforcementFieldsChanged(a.snap.Live.StoredSpecs[e.Identity], e.Proposed.Spec) {
			o.ReportingOnly = true
			o.Notes = append(o.Notes, "only reporting settings change; with an enforcement epoch this keeps every revision and needs no exception renewal")
		}
		switch {
		case e.Disposition == Unchanged && e.StoredSpec == StoredSpecDifferent:
			o.Notes = append(o.Notes, "the configuration is semantically unchanged, but the API server would store a different specification (list order or spelling), so the generation advances; see revisionEffect for the contributions this replaces")
		case e.Disposition == Unchanged && e.StoredSpec == StoredSpecUnknown:
			o.Notes = append(o.Notes, "the live stored specification was not observed, so the preview cannot show that the API server would store this proposal unchanged; it assumes a generation change")
		}
		if a.epochUnavailable[e.Identity.Name] && e.Identity.Kind == KindBinding {
			o.Notes = append(o.Notes, "the live binding has no enforcementEpoch; revisions are assumed to rotate")
		}
		out = append(out, o)
	}
	return out
}

func (a *adapter) responsible(binding string) []Responsible {
	var out []Responsible
	add := func(e *Entry) {
		if plain(e) || slices.ContainsFunc(out, func(r Responsible) bool { return r.Identity == e.Identity.String() }) {
			return
		}
		r := Responsible{Identity: e.Identity.String(), Disposition: e.Disposition}
		switch {
		case e.Proposed != nil:
			r.Source, r.Document, r.Line = e.Proposed.Source, e.Proposed.Document, e.Proposed.Line
		case e.Before != nil:
			r.Source, r.Document, r.Line = e.Before.Source, e.Before.Document, e.Before.Line
		}
		out = append(out, r)
	}
	add(a.entry(KindBinding, binding))
	for _, s := range []*side{&a.base, &a.next} {
		for _, b := range s.in.Bindings {
			if b.Name == binding {
				add(a.entry(KindProfile, b.Spec.ProfileRef.Name))
			}
		}
	}
	return out
}

func parametersOf(p *v1alpha1.ComplianceProfile, policy string) any {
	if p == nil {
		return nil
	}
	for _, pol := range p.Spec.Policies {
		if pol.Name == policy && pol.Parameters != nil && len(pol.Parameters.Raw) > 0 {
			var v any
			if json.Unmarshal(pol.Parameters.Raw, &v) == nil {
				if m, ok := v.(map[string]any); ok && len(m) == 0 {
					return nil
				}
				return v
			}
		}
	}
	return nil
}

// sideOf builds the reported side. Observed values are included only for
// the baseline; the candidate's provisional identity is never copied out.
func (s *side) sideOf(c *targeting.Contribution, observed bool) *ContributionSide {
	br := s.results[c.Binding.Name]
	out := &ContributionSide{Profile: c.Profile.Name, BundleName: c.BundleName, BundleDigest: c.BundleDigest, ConfigurationDigest: c.ConfigurationDigest,
		Parameters: parametersOf(s.profiles[c.Profile.Name], c.Policy), Mode: c.Mode, NamespaceSelector: c.NamespaceSelector, Exceptions: c.Exceptions,
		Targets: slices.Clone(br.Targets), TargetCount: br.TargetCount}
	if observed {
		out.ProfileUID, out.ProfileGeneration, out.DesiredRevision = c.Profile.UID, c.Profile.Generation, c.Revision
	}
	return out
}

func selectorString(s v1alpha1.NamespaceSelector) string {
	sel, err := s.AsSelector()
	if err != nil {
		return "invalid"
	}
	if sel.Empty() {
		return "{} (every namespace)"
	}
	return sel.String()
}

func exceptionString(e v1alpha1.ExceptionSettings) string {
	if e.MaxLifetime != nil {
		return fmt.Sprintf("%s (maxLifetime %s)", e.Eligibility, e.MaxLifetime.Duration)
	}
	return string(e.Eligibility)
}

func exceptionsEqual(x, y v1alpha1.ExceptionSettings) bool {
	if x.Eligibility != y.Eligibility || (x.MaxLifetime == nil) != (y.MaxLifetime == nil) {
		return false
	}
	return x.MaxLifetime == nil || x.MaxLifetime.Duration == y.MaxLifetime.Duration
}

func nsDiff(before, after []targeting.NamespaceRef) (added, removed []targeting.NamespaceRef) {
	has := func(list []targeting.NamespaceRef, n targeting.NamespaceRef) bool { return slices.Contains(list, n) }
	for _, n := range after {
		if !has(before, n) {
			added = append(added, n)
		}
	}
	for _, n := range before {
		if !has(after, n) {
			removed = append(removed, n)
		}
	}
	return added, removed
}

func nsNames(ns []targeting.NamespaceRef) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = n.Name + " (" + string(n.UID) + ")"
	}
	return strings.Join(parts, ", ")
}

func (a *adapter) contributionKey(binding, policy string) ContributionKey {
	k := ContributionKey{Cluster: a.snap.Cluster, Binding: binding, Policy: policy}
	if e := a.entry(KindBinding, binding); e != nil && e.LiveBinding != nil {
		k.BindingUID = e.LiveBinding.UID
	}
	return k
}

// revisionEffect compares the candidate's provisional revision with the
// baseline's. Both come from targeting.EnforcementRevision; the provisional
// value is used for this equality only.
func (a *adapter) revisionEffect(binding, policy string) RevisionEffect {
	n := a.next.contribs[[2]string{binding, policy}]
	if n == nil {
		return ""
	}
	b := a.base.contribs[[2]string{binding, policy}]
	switch {
	case b == nil:
		return RevisionNew
	case b.Revision == n.Revision:
		return RevisionUnchanged
	}
	return RevisionReplacement
}

func (a *adapter) contributionChanges() []ContributionChange {
	keys := map[[2]string]bool{}
	for k := range a.base.contribs {
		keys[k] = true
	}
	for k := range a.next.contribs {
		keys[k] = true
	}
	out := []ContributionChange{}
	for _, k := range slices.SortedFunc(maps.Keys(keys), func(x, y [2]string) int { return cmp.Or(cmp.Compare(x[0], y[0]), cmp.Compare(x[1], y[1])) }) {
		b, n := a.base.contribs[k], a.next.contribs[k]
		row := ContributionChange{Key: a.contributionKey(k[0], k[1]), Impacts: []Impact{}}
		impact := func(c Category, before, after, reason string) {
			row.Impacts = append(row.Impacts, Impact{Category: c, Area: AreaOf(c), Before: before, After: after, Reason: reason})
		}
		switch {
		case n == nil:
			row.Change, row.Before = ChangeRemoved, a.base.sideOf(b, true)
			row.NamespacesRemoved = slices.Clone(row.Before.Targets)
			impact(CategoryContributionRemoved, string(b.Mode), "",
				"the proposal removes this contribution; this requests withdrawal of its engine policy, which the controller or garbage collection removes after application, not immediately")
		case b == nil:
			row.Change, row.After, row.RevisionEffect = ChangeAdded, a.next.sideOf(n, false), RevisionNew
			row.NamespacesAdded = slices.Clone(row.After.Targets)
			impact(CategoryContributionAdded, "", string(n.Mode), fmt.Sprintf("the proposal adds this contribution; it selects %d observed namespaces now, and its revision is assigned after application", row.After.TargetCount))
		default:
			row.Change, row.Before, row.After = ChangeChanged, a.base.sideOf(b, true), a.next.sideOf(n, false)
			row.RevisionEffect = a.revisionEffect(k[0], k[1])
			semantic := false
			if b.BundleName != n.BundleName || b.BundleDigest != n.BundleDigest {
				semantic = true
				impact(CategoryBundlePin, b.BundleName+"@"+b.BundleDigest, n.BundleName+"@"+n.BundleDigest,
					"the pinned content changes; this is a change even if the rendered rules look identical")
			}
			if !reflect.DeepEqual(row.Before.Parameters, row.After.Parameters) {
				semantic = true
				impact(CategoryParameters, "", "", "policy parameters change; see the before and after values")
			}
			if !exceptionsEqual(b.Exceptions, n.Exceptions) {
				semantic = true
				impact(CategoryExceptionRule, exceptionString(b.Exceptions), exceptionString(n.Exceptions), "the profile's exception rule for this policy changes")
			}
			if b.Mode != n.Mode {
				semantic = true
				impact(CategoryMode, string(b.Mode), string(n.Mode), "the enforcement mode changes; Audit does not override an overlapping Deny contribution")
			}
			if !reflect.DeepEqual(canonicalSelector(&b.NamespaceSelector), canonicalSelector(&n.NamespaceSelector)) {
				semantic = true
				impact(CategorySelector, selectorString(b.NamespaceSelector), selectorString(n.NamespaceSelector), "the namespace selector changes")
			}
			row.NamespacesAdded, row.NamespacesRemoved = nsDiff(row.Before.Targets, row.After.Targets)
			if len(row.NamespacesAdded) > 0 {
				impact(CategoryNamespaceAdded, "", nsNames(row.NamespacesAdded), "these observed namespace instances become subject to this contribution")
			}
			if len(row.NamespacesRemoved) > 0 {
				impact(CategoryNamespaceRemoved, nsNames(row.NamespacesRemoved), "", "these observed namespace instances leave this contribution; other contributions may still apply there")
			}
			if b.Profile.Name != n.Profile.Name {
				semantic = true
				impact(CategoryProfile, b.Profile.Name, n.Profile.Name, "the binding now takes this policy from another profile")
			}
			if row.RevisionEffect == RevisionReplacement {
				reason := "the controller computes a new enforcement revision: the engine policy is replaced under a new name and anything bound to the current revision, such as an accepted exception, no longer matches it"
				if !semantic && len(row.NamespacesAdded)+len(row.NamespacesRemoved) == 0 {
					row.SemanticallyEquivalent = true
					reason += "; the configuration is semantically unchanged (for example reordered selector expressions, a respelled value, a rollback to earlier values, or another edit of a shared profile), but the API server advances the generation or enforcement epoch"
				}
				impact(CategoryRevision, "", "", reason)
			}
			if len(row.Impacts) == 0 {
				continue
			}
		}
		row.Responsible = a.responsible(k[0])
		out = append(out, row)
	}
	return out
}

func eligibilitySide(e *targeting.Eligibility) *EligibilitySide {
	if e == nil {
		return nil
	}
	s := &EligibilitySide{Effective: e.Effective, MaxLifetime: e.MaxLifetime}
	for _, err := range e.Errors {
		if !slices.Contains(s.Errors, err.Reason) {
			s.Errors = append(s.Errors, err.Reason)
		}
	}
	slices.Sort(s.Errors)
	return s
}

func (a *adapter) namespaceChanges() []NamespaceChange {
	type key struct {
		uid    types.UID
		policy string
	}
	index := func(s *side) map[key]*targeting.Eligibility {
		m := map[key]*targeting.Eligibility{}
		for i := range s.res.Eligibility {
			e := &s.res.Eligibility[i]
			m[key{e.Namespace.UID, e.Policy}] = e
		}
		return m
	}
	before, after := index(&a.base), index(&a.next)
	keys := map[key]targeting.NamespaceRef{}
	for k, e := range before {
		keys[k] = e.Namespace
	}
	for k, e := range after {
		keys[k] = e.Namespace
	}
	out := []NamespaceChange{}
	for k, ns := range keys {
		b, n := before[k], after[k]
		row := NamespaceChange{Namespace: ns, Policy: k.policy, Before: eligibilitySide(b), After: eligibilitySide(n), Impacts: []Impact{}}
		prev := map[string]targeting.ContributionRef{}
		if b != nil {
			for _, c := range b.Contributors {
				prev[c.Binding.Name] = c
			}
		}
		ref := func(c targeting.ContributionRef, withEffect bool) ContributorRef {
			r := ContributorRef{Binding: c.Binding.Name, Mode: c.Mode}
			if e := a.entry(KindBinding, c.Binding.Name); e != nil && e.LiveBinding != nil {
				r.BindingUID = e.LiveBinding.UID
			}
			if withEffect {
				r.RevisionEffect = a.revisionEffect(c.Binding.Name, k.policy)
			}
			return r
		}
		if n != nil {
			for _, c := range n.Contributors {
				p, had := prev[c.Binding.Name]
				delete(prev, c.Binding.Name)
				switch {
				case !had:
					row.Added = append(row.Added, ref(c, true))
				case p.Revision == c.Revision:
					row.Remaining = append(row.Remaining, ref(c, true))
				default:
					row.Replaced = append(row.Replaced, ref(c, true))
				}
			}
		}
		for _, name := range slices.Sorted(maps.Keys(prev)) {
			row.Removed = append(row.Removed, ref(prev[name], false))
		}
		if b != nil && n != nil && (b.Effective != n.Effective || !reflect.DeepEqual(b.MaxLifetime, n.MaxLifetime)) {
			row.Impacts = append(row.Impacts, Impact{Category: CategoryEligibility, Area: AreaException,
				Before: eligibilityString(b), After: eligibilityString(n),
				Reason: "effective self-service exception eligibility changes across all contributions here (Forbidden takes precedence; the shortest lifetime applies)"})
		}
		if len(row.Added)+len(row.Removed)+len(row.Replaced) == 0 && len(row.Impacts) == 0 && reflect.DeepEqual(row.Before, row.After) {
			continue
		}
		out = append(out, row)
	}
	slices.SortFunc(out, func(x, y NamespaceChange) int {
		return cmp.Or(cmp.Compare(x.Namespace.Name, y.Namespace.Name), cmp.Compare(x.Namespace.UID, y.Namespace.UID), cmp.Compare(x.Policy, y.Policy))
	})
	return out
}

func eligibilityString(e *targeting.Eligibility) string {
	if e.MaxLifetime != nil {
		return fmt.Sprintf("%s (maxLifetime %s)", e.Effective, e.MaxLifetime.Duration)
	}
	return string(e.Effective)
}
