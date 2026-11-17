package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Duration is a positive Kubernetes/Go duration string such as "24h" or
// "2160h". Days ("90d"), cron expressions, zero, negative, and values that
// overflow a duration are rejected.
// +kubebuilder:validation:MinLength=2
// +kubebuilder:validation:MaxLength=32
// +kubebuilder:validation:XValidation:rule="self.matches('^([0-9]+(\\\\.[0-9]+)?(ns|us|ms|s|m|h))+$')",message="must be a duration such as 24h, 90m or 2160h; days, cron expressions and signs are not supported"
// +kubebuilder:validation:XValidation:rule="!self.matches('^([0-9]+(\\\\.[0-9]+)?(ns|us|ms|s|m|h))+$') || duration(self) > duration('0s')",message="must be a positive duration"
type Duration string

// BindingAssessment configures continuous assessment of a binding. Changing
// it is a reporting-only edit: it never changes the enforcement epoch, engine
// policy identities, or accepted exceptions. An explicit null is equivalent to
// omitting a setting: the API server prunes it and applies the default (CEL
// cannot distinguish null from an absent field), so null is never stored.
type BindingAssessment struct {
	// interval between scheduled snapshots, measured from a persisted anchor.
	// +optional
	// +kubebuilder:default="24h"
	Interval Duration `json:"interval,omitempty"`
	// maxEvidenceAge is the oldest source evaluation accepted as current
	// evidence at snapshot closure.
	// +optional
	// +kubebuilder:default="2h"
	MaxEvidenceAge Duration `json:"maxEvidenceAge,omitempty"`
	// collectionTimeout bounds how long a run waits for evidence.
	// +optional
	// +kubebuilder:default="5m"
	CollectionTimeout Duration `json:"collectionTimeout,omitempty"`
	// retention is how long published packages are kept, fixed at
	// publication. 90 days is 2160h.
	// +optional
	// +kubebuilder:default="2160h"
	Retention Duration `json:"retention,omitempty"`
	// destinationRef overrides the central default evidence destination for
	// this binding by name and UID. Requests inherit it. An unusable
	// selection fails visibly and never falls back to the default.
	// +optional
	DestinationRef *DestinationReference `json:"destinationRef,omitempty"`
}

// BindingAssessmentStatus is written only by the assessment controller
// (server-side apply, field manager konstapel-assessments). The targeting
// controller carries it forward unchanged. It is bounded and holds no
// inventory.
type BindingAssessmentStatus struct {
	// schedule is the persisted snapshot schedule.
	// +optional
	Schedule *AssessmentSchedule `json:"schedule,omitempty"`
	// current is the continuously reconciled evidence state. It is separate
	// from historical snapshots and from EngineReady, which never asserts
	// compliance.
	// +optional
	Current *CurrentEvidence `json:"current,omitempty"`
	// latestRun is the newest run started for this binding.
	// +optional
	LatestRun *RunReference `json:"latestRun,omitempty"`
	// destination is the resolved evidence destination selection.
	// +optional
	Destination *DestinationSelection `json:"destination,omitempty"`
}

// AssessmentSchedule persists the schedule anchor so restarts and leader
// changes resume the same cadence. Scheduled times are anchor + k*interval.
type AssessmentSchedule struct {
	Anchor metav1.Time `json:"anchor"`
	// interval in effect when anchor was set.
	Interval Duration `json:"interval"`
	// lastScheduled is the scheduled time of the newest scheduled run.
	// +optional
	LastScheduled *metav1.Time `json:"lastScheduled,omitempty"`
	// +optional
	NextDue *metav1.Time `json:"nextDue,omitempty"`
	// outstandingSince is the earliest scheduled time, including missed
	// times coalesced into a later run, whose obligation has not yet been
	// met by a scheduled run that closed with an assessment export
	// (complete or incomplete). A diagnostic or lost capture does not meet
	// it; manual and namespace runs never do. Absent when nothing is
	// outstanding. It is an observation of the schedule and never changes
	// when runs start.
	// +optional
	OutstandingSince *metav1.Time `json:"outstandingSince,omitempty"`
	// activeRun holds the binding's single run slot.
	// +optional
	ActiveRun *RunReference `json:"activeRun,omitempty"`
	// missedTotal counts every missed scheduled time, including gaps
	// dropped from the bounded list.
	// +optional
	// +kubebuilder:validation:Minimum=0
	MissedTotal int32 `json:"missedTotal,omitempty"`
	// gaps are the most recent missed intervals, oldest first. Each was
	// coalesced into one later run; none was assessed.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=10
	Gaps []MissedInterval `json:"gaps,omitempty"`
}

// MissedInterval is a range of scheduled times that were not run.
type MissedInterval struct {
	From metav1.Time `json:"from"`
	To   metav1.Time `json:"to"`
	// +kubebuilder:validation:Minimum=1
	Missed int32 `json:"missed"`
}

// CurrentEvidence is the binding's current evidence state.
type CurrentEvidence struct {
	Evidence EvidenceSummary `json:"evidence"`
	Outcomes OutcomeCounts   `json:"outcomes"`
	// evaluatedAt is when the controller last evaluated current evidence.
	EvaluatedAt metav1.Time `json:"evaluatedAt"`
	// nextExpiry is when the oldest attributable evidence becomes stale.
	// +optional
	NextExpiry *metav1.Time `json:"nextExpiry,omitempty"`
	// oldestEvaluation is the source evaluation time of the oldest
	// attributable observation: when the engine evaluated it, never a
	// collection, upload or report-update time. Absent when no observation
	// is attributable, and on status recorded before this field existed.
	// +optional
	OldestEvaluation *metav1.Time `json:"oldestEvaluation,omitempty"`

	// limitations explain why evidence is incomplete, most significant first.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MaxLength=256
	Limitations []string `json:"limitations,omitempty"`

	// coverage is the binding's newest published full-binding coverage
	// report, judged against the binding's current scope and clock. It is
	// never re-evaluated and never changes the evidence above.
	// +optional
	Coverage *CurrentCoverage `json:"coverage,omitempty"`
}

// CurrentCoverageState is whether a published coverage report still
// describes the binding now.
// +kubebuilder:validation:Enum=Current;Expired;ScopeChanged;NoReport
type CurrentCoverageState string

const (
	// CoverageCurrent: the report's scope and selection are the binding's
	// current ones and its attributable evidence has not aged out.
	CoverageCurrent CurrentCoverageState = "Current"
	// CoverageExpired: the report's validUntil has passed, or its package
	// is no longer served. It still describes its own closure time.
	CoverageExpired CurrentCoverageState = "Expired"
	// CoverageScopeChanged: the binding's namespaces or profile selection
	// differ from what the report assessed, or the report's inputs were
	// not recorded.
	CoverageScopeChanged CurrentCoverageState = "ScopeChanged"
	// CoverageNoReport: no committed full-binding run exists, or the
	// newest one's package carries no coverage report.
	CoverageNoReport CurrentCoverageState = "NoReport"
)

// CurrentCoverage references the newest committed full-binding run's
// coverage report and states whether it is current.
type CurrentCoverage struct {
	State CurrentCoverageState `json:"state"`
	// run is the full-binding run whose published package holds the
	// report; download it to inspect the controls.
	// +optional
	Run *RunReference `json:"run,omitempty"`
	// summary is that run's coverage summary, as recorded at closure.
	// +optional
	Summary *CoverageSummary `json:"summary,omitempty"`
}
