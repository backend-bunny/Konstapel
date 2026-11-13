package observability

import (
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Status is a one-hot condition status.
type Status string

const (
	StatusTrue    Status = "true"
	StatusFalse   Status = "false"
	StatusUnknown Status = "unknown"
)

// Capability is an engine prerequisite reported by the targeting owner.
type Capability string

const (
	CapabilityPolicyDelivery Capability = "policy_delivery"
	CapabilityAssessment     Capability = "assessment"
	CapabilityExceptions     Capability = "exceptions"
)

// Operation is a bounded operation whose attempts every replica counts.
type Operation string

const (
	OperationBundleResolution    Operation = "bundle_resolution"
	OperationEvidencePublication Operation = "evidence_publication"
	OperationEvidenceCleanup     Operation = "evidence_cleanup"
)

// Result is the result of one completed attempt.
type Result string

const (
	ResultSuccess Result = "success"
	ResultFailure Result = "failure"
)

// AssessmentStatus is the one-hot availability of one assessment view.
type AssessmentStatus string

const (
	// AssessmentKnown: a nonempty known inventory with per-state counts.
	AssessmentKnown AssessmentStatus = "known"
	// AssessmentNoTargets: known empty scope; zero counts, never a pass.
	AssessmentNoTargets AssessmentStatus = "no_targets"
	// AssessmentNone: no full-binding run has closed yet (latest_closed only).
	AssessmentNone AssessmentStatus = "no_assessment"
	// AssessmentUnknown: the inventory, its consistency or (for the current
	// view) its validity cannot be established; counts are omitted.
	AssessmentUnknown AssessmentStatus = "unknown"
)

// View names a binding summary view.
type View string

const (
	ViewCurrent      View = "current"
	ViewLatestClosed View = "latest_closed"
)

// BindingRef identifies one binding object. Projections match on UID; the
// name is the only identity exposed as a label.
type BindingRef struct {
	Name string
	UID  string
}

// BindingTargeting is the targeting owner's state of one binding. Producers
// report StatusUnknown for a Condition whose observed generation is stale.
type BindingTargeting struct {
	Binding     BindingRef
	Created     time.Time
	Resolved    Status
	EngineReady Status
	// TargetNamespaces is the known target count; nil when the target
	// inventory is unknown.
	TargetNamespaces *int
}

// TargetingSnapshot is one coherent targeting projection.
type TargetingSnapshot struct {
	Bindings []BindingTargeting
	// Capabilities holds only enabled capabilities.
	Capabilities map[Capability]Status
}

// Summary is the assessment owner's normalized summary of one view. It
// reuses the owner's types: the projection only renames their counts.
type Summary struct {
	Evidence publication.EvidenceSummary
	Outcomes publication.OutcomeCounts
	// InventoryUnknown marks a summary without a trustworthy inventory, such
	// as a run whose capture was lost.
	InventoryUnknown bool
	// OldestEvaluated is the oldest attributable source evaluation, when the
	// owner records it. It is never a collection, upload or scrape time.
	OldestEvaluated *time.Time
}

// CurrentView is the binding's current evidence.
type CurrentView struct {
	Summary
	// ValidUntil is the owner's next validity deadline (its next evidence
	// expiry). From then on the view is unknown until the owner re-evaluates;
	// republishing the same summary never extends it.
	ValidUntil *time.Time
}

// ClosedRun is the latest closed full-binding run, including incomplete and
// diagnostic closures.
type ClosedRun struct {
	Summary
	CollectionStarted time.Time
	Closed            time.Time
}

// BindingAssessment is the assessment owner's state of one binding.
type BindingAssessment struct {
	Binding BindingRef
	// Current is nil before the owner first evaluates current evidence.
	Current *CurrentView
	// LatestClosed is nil when no full-binding run has closed for this UID.
	LatestClosed      *ClosedRun
	Interval          time.Duration
	MaxEvidenceAge    time.Duration
	CollectionTimeout time.Duration
	// Due is the earliest outstanding scheduled due time, or the next due
	// time when none is outstanding; nil when the scheduler has none.
	Due *time.Time
}

// AssessmentSnapshot is one coherent assessment projection.
type AssessmentSnapshot struct {
	Bindings []BindingAssessment
}

// StorageSnapshot is the storage owner's durable backlog, reconstructed
// from its retained records rather than bucket listings.
type StorageSnapshot struct {
	PublicationPending int
	PublicationFailed  int
	CleanupPending     int
	CleanupBlocked     int
	// OldestCleanupExpiry is the expiry of the oldest package with pending
	// or blocked cleanup; nil when there is none.
	OldestCleanupExpiry *time.Time
}

func validRef(seen map[string]string, uids map[string]bool, r BindingRef) error {
	if r.Name == "" || r.UID == "" {
		return errors.New("binding name and UID are required")
	}
	if _, dup := seen[r.Name]; dup {
		return fmt.Errorf("binding %s appears twice", r.Name)
	}
	if uids[r.UID] {
		return fmt.Errorf("binding UID of %s appears twice", r.Name)
	}
	seen[r.Name], uids[r.UID] = r.UID, true
	return nil
}

func validStatus(s Status) bool {
	return s == StatusTrue || s == StatusFalse || s == StatusUnknown
}

func (s TargetingSnapshot) validate() error {
	seen, uids := map[string]string{}, map[string]bool{}
	for _, b := range s.Bindings {
		if err := validRef(seen, uids, b.Binding); err != nil {
			return err
		}
		if !validStatus(b.Resolved) || !validStatus(b.EngineReady) {
			return fmt.Errorf("binding %s: invalid condition status", b.Binding.Name)
		}
		if b.TargetNamespaces != nil && *b.TargetNamespaces < 0 {
			return fmt.Errorf("binding %s: negative target count", b.Binding.Name)
		}
	}
	for c, st := range s.Capabilities {
		if c != CapabilityPolicyDelivery && c != CapabilityAssessment && c != CapabilityExceptions {
			return fmt.Errorf("unknown capability %q", c)
		}
		if !validStatus(st) {
			return fmt.Errorf("capability %s: invalid status", c)
		}
	}
	return nil
}

func (s AssessmentSnapshot) validate() error {
	seen, uids := map[string]string{}, map[string]bool{}
	for _, b := range s.Bindings {
		if err := validRef(seen, uids, b.Binding); err != nil {
			return err
		}
		if b.Interval < 0 || b.MaxEvidenceAge < 0 || b.CollectionTimeout < 0 {
			return fmt.Errorf("binding %s: negative duration", b.Binding.Name)
		}
		if r := b.LatestClosed; r != nil && r.Closed.Before(r.CollectionStarted) {
			return fmt.Errorf("binding %s: run closed before it started", b.Binding.Name)
		}
	}
	return nil
}

func (s StorageSnapshot) validate() error {
	if s.PublicationPending < 0 || s.PublicationFailed < 0 || s.CleanupPending < 0 || s.CleanupBlocked < 0 {
		return errors.New("negative backlog")
	}
	if s.OldestCleanupExpiry != nil && s.CleanupPending+s.CleanupBlocked == 0 {
		return errors.New("oldest cleanup expiry without pending or blocked cleanup")
	}
	return nil
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func (s TargetingSnapshot) clone() TargetingSnapshot {
	out := TargetingSnapshot{Bindings: make([]BindingTargeting, len(s.Bindings)), Capabilities: maps.Clone(s.Capabilities)}
	for i, b := range s.Bindings {
		b.TargetNamespaces = clonePtr(b.TargetNamespaces)
		out.Bindings[i] = b
	}
	return out
}

func (s Summary) clone() Summary {
	s.OldestEvaluated = clonePtr(s.OldestEvaluated)
	return s
}

func (s AssessmentSnapshot) clone() AssessmentSnapshot {
	out := AssessmentSnapshot{Bindings: make([]BindingAssessment, len(s.Bindings))}
	for i, b := range s.Bindings {
		if b.Current != nil {
			c := CurrentView{Summary: b.Current.Summary.clone(), ValidUntil: clonePtr(b.Current.ValidUntil)}
			b.Current = &c
		}
		if b.LatestClosed != nil {
			r := *b.LatestClosed
			r.Summary = r.Summary.clone()
			b.LatestClosed = &r
		}
		b.Due = clonePtr(b.Due)
		out.Bindings[i] = b
	}
	return out
}

func (s StorageSnapshot) clone() StorageSnapshot {
	s.OldestCleanupExpiry = clonePtr(s.OldestCleanupExpiry)
	return s
}
