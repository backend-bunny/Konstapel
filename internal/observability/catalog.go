// Package observability is Konstapel's Prometheus metric contract and the
// pure projections that turn owner-provided snapshots into metrics
// (add-prometheus-observability). Collectors read immutable snapshots; a
// scrape never queries reports, registries or storage.
package observability

// MetricType is a Prometheus metric type.
type MetricType string

const (
	Gauge     MetricType = "gauge"
	Counter   MetricType = "counter"
	Histogram MetricType = "histogram"
)

// Domain is an independently observed source of truth.
type Domain string

const (
	DomainTargeting        Domain = "targeting"
	DomainAssessment       Domain = "assessment"
	DomainBundleResolution Domain = "bundle_resolution"
	DomainEvidenceStorage  Domain = "evidence_storage"
	// DomainProcess marks per-process attempt metrics, exposed by every
	// replica rather than projected from an owner's state.
	DomainProcess Domain = "process"
)

// Domains lists the owner domains that publish readiness.
var Domains = []Domain{DomainTargeting, DomainAssessment, DomainBundleResolution, DomainEvidenceStorage}

// Label is one metric label. Binding is the only label whose values are not a
// fixed enum; it carries the binding name (bounded by configured bindings).
type Label struct {
	Name   string
	Values []string // nil only for LabelBinding
}

// LabelBinding names the binding label.
const LabelBinding = "binding"

// Metric describes one metric family of the contract.
type Metric struct {
	Name   string
	Type   MetricType
	Unit   string // base unit, "" for counts and states
	Help   string
	Labels []Label
	// Domain is the owner whose snapshot supplies the value.
	Domain Domain
	// Availability states when the family is emitted at all.
	Availability string
	// Reset states counter/gauge reset semantics.
	Reset string
}

// Label vocabularies.
var (
	domainValues     = []string{string(DomainTargeting), string(DomainAssessment), string(DomainBundleResolution), string(DomainEvidenceStorage)}
	statusValues     = []string{"true", "false", "unknown"}
	conditionValues  = []string{"Resolved", "EngineReady"}
	capabilityValues = []string{"policy_delivery", "assessment", "exceptions"}
	viewValues       = []string{"current", "latest_closed"}
	// AssessmentStatuses are the mutually exclusive summary availability states.
	AssessmentStatuses = []string{"known", "no_targets", "no_assessment", "unknown"}
	// CheckStates are the mutually exclusive display states of one check
	// instance (design §3).
	CheckStates     = []string{"pass", "fail", "accepted_risk", "error", "warn", "skip", "unknown", "stale", "out_of_scope"}
	operationValues = []string{"bundle_resolution", "evidence_publication", "evidence_cleanup"}
	resultValues    = []string{"success", "failure"}
)

var (
	binding    = Label{Name: LabelBinding}
	domain     = Label{Name: "domain", Values: domainValues}
	status     = Label{Name: "status", Values: statusValues}
	condition  = Label{Name: "condition", Values: conditionValues}
	capability = Label{Name: "capability", Values: capabilityValues}
	view       = Label{Name: "view", Values: viewValues}
	operation  = Label{Name: "operation", Values: operationValues}
	result     = Label{Name: "result", Values: resultValues}
)

const (
	onlyWhenReady   = "Only while the domain's projection is fresh and ready; absent otherwise."
	stateGauge      = "Gauge reflecting current owner state; reconstructed from owner state after restart."
	processCounter  = "Process-local counter; resets to zero on restart; never reconstructed."
	bindingLifetime = "Per binding UID: removed when the binding is deleted; a recreated name starts without old values."
)

// Catalog is the documented metric contract (task 1.1). Controller-runtime's
// reconciliation, workqueue, Go and process collectors are retained as
// upstream provides them and are not part of this catalog.
var Catalog = []Metric{
	{Name: "konstapel_observation_enabled", Type: Gauge, Labels: []Label{domain}, Domain: DomainProcess,
		Help:         "1 when the observation domain's feature is enabled and expected to report, 0 when disabled.",
		Availability: "Always, for every domain.", Reset: "Configuration state; constant for a process."},
	{Name: "konstapel_observation_ready", Type: Gauge, Labels: []Label{domain}, Domain: DomainProcess,
		Help:         "1 when the domain has a synchronized projection within its maximum age, otherwise 0.",
		Availability: "Always, for every enabled domain; unknown or stale domains are 0, never healthy zeroes elsewhere.", Reset: stateGauge},
	{Name: "konstapel_observation_updated_timestamp_seconds", Type: Gauge, Unit: "seconds", Labels: []Label{domain}, Domain: DomainProcess,
		Help:         "Unix time the domain's projection was last refreshed from synchronized owner state.",
		Availability: "After the domain's first synchronized projection.", Reset: stateGauge},

	{Name: "konstapel_binding_created_timestamp_seconds", Type: Gauge, Unit: "seconds", Labels: []Label{binding}, Domain: DomainTargeting,
		Help:         "Creation time of the current binding object with this name.",
		Availability: onlyWhenReady, Reset: bindingLifetime},
	{Name: "konstapel_binding_condition", Type: Gauge, Labels: []Label{binding, condition, status}, Domain: DomainTargeting,
		Help:         "One-hot binding condition state: 1 for the current status of Resolved and EngineReady.",
		Availability: onlyWhenReady, Reset: bindingLifetime},
	{Name: "konstapel_binding_target_namespaces", Type: Gauge, Labels: []Label{binding}, Domain: DomainTargeting,
		Help:         "Known number of target namespaces, even when content is unresolved.",
		Availability: "Only when the target inventory is known.", Reset: bindingLifetime},
	{Name: "konstapel_capability_condition", Type: Gauge, Labels: []Label{capability, status}, Domain: DomainTargeting,
		Help:         "One-hot prerequisite state of an enabled capability.",
		Availability: onlyWhenReady, Reset: stateGauge},

	{Name: "konstapel_binding_assessment_status", Type: Gauge, Labels: []Label{binding, view, Label{Name: "status", Values: AssessmentStatuses}}, Domain: DomainAssessment,
		Help:         "One-hot summary availability per view: known, no_targets, no_assessment or unknown.",
		Availability: onlyWhenReady, Reset: bindingLifetime},
	{Name: "konstapel_binding_assessment_checks", Type: Gauge, Labels: []Label{binding, view, Label{Name: "state", Values: CheckStates}}, Domain: DomainAssessment,
		Help:         "Independently identified check instances per display state; for a known inventory the states sum to it.",
		Availability: "Only for a known inventory; omitted when the inventory is unknown.", Reset: bindingLifetime},
	{Name: "konstapel_binding_assessment_complete", Type: Gauge, Labels: []Label{binding, view}, Domain: DomainAssessment,
		Help:         "1 when every expected observation in the view is attributable, otherwise 0.",
		Availability: "Only for a known nonempty summary.", Reset: bindingLifetime},
	{Name: "konstapel_binding_oldest_evaluation_timestamp_seconds", Type: Gauge, Unit: "seconds", Labels: []Label{binding, view}, Domain: DomainAssessment,
		Help:         "Oldest attributable source evaluation time in the view.",
		Availability: "Only when the view has an attributable observation.", Reset: bindingLifetime},
	{Name: "konstapel_binding_snapshot_collection_started_timestamp_seconds", Type: Gauge, Unit: "seconds", Labels: []Label{binding}, Domain: DomainAssessment,
		Help:         "Collection start of the latest closed full-binding run.",
		Availability: "Only after a full-binding run has closed.", Reset: bindingLifetime},
	{Name: "konstapel_binding_last_closed_timestamp_seconds", Type: Gauge, Unit: "seconds", Labels: []Label{binding}, Domain: DomainAssessment,
		Help:         "Closure time of the latest full-binding run, including incomplete and diagnostic closures.",
		Availability: "Only after a full-binding run has closed.", Reset: bindingLifetime},
	{Name: "konstapel_binding_assessment_interval_seconds", Type: Gauge, Unit: "seconds", Labels: []Label{binding}, Domain: DomainAssessment,
		Help:         "Effective scheduled assessment cadence.",
		Availability: onlyWhenReady, Reset: bindingLifetime},
	{Name: "konstapel_binding_max_evidence_age_seconds", Type: Gauge, Unit: "seconds", Labels: []Label{binding}, Domain: DomainAssessment,
		Help:         "Effective evidence-age limit.",
		Availability: onlyWhenReady, Reset: bindingLifetime},
	{Name: "konstapel_binding_scheduled_due_timestamp_seconds", Type: Gauge, Unit: "seconds", Labels: []Label{binding}, Domain: DomainAssessment,
		Help:         "Earliest outstanding scheduled due time, or the next due time when none is outstanding.",
		Availability: onlyWhenReady, Reset: bindingLifetime},
	{Name: "konstapel_binding_collection_timeout_seconds", Type: Gauge, Unit: "seconds", Labels: []Label{binding}, Domain: DomainAssessment,
		Help:         "Configured collection limit, used with the overdue grace period.",
		Availability: onlyWhenReady, Reset: bindingLifetime},

	{Name: "konstapel_operation_attempts_total", Type: Counter, Labels: []Label{operation, result}, Domain: DomainProcess,
		Help:         "Completed attempts of a bounded operation; each retry is a separate attempt.",
		Availability: "Always; zero until the first attempt.", Reset: processCounter},
	{Name: "konstapel_operation_duration_seconds", Type: Histogram, Unit: "seconds", Labels: []Label{operation, result}, Domain: DomainProcess,
		Help:         "Duration of completed attempts of a bounded operation.",
		Availability: "Always; empty until the first attempt.", Reset: processCounter},

	{Name: "konstapel_publication_pending", Type: Gauge, Domain: DomainEvidenceStorage,
		Help:         "Closed runs whose evidence package is not yet committed and is still being attempted.",
		Availability: onlyWhenReady, Reset: stateGauge},
	{Name: "konstapel_publication_failed", Type: Gauge, Domain: DomainEvidenceStorage,
		Help:         "Closed runs whose publication currently fails and needs action.",
		Availability: onlyWhenReady, Reset: stateGauge},
	{Name: "konstapel_cleanup_pending", Type: Gauge, Domain: DomainEvidenceStorage,
		Help:         "Retained packages past expiry whose deletion is not yet confirmed.",
		Availability: onlyWhenReady, Reset: stateGauge},
	{Name: "konstapel_cleanup_blocked", Type: Gauge, Domain: DomainEvidenceStorage,
		Help:         "Retained packages whose deletion is blocked and needs action.",
		Availability: onlyWhenReady, Reset: stateGauge},
	{Name: "konstapel_cleanup_oldest_expiry_timestamp_seconds", Type: Gauge, Unit: "seconds", Domain: DomainEvidenceStorage,
		Help:         "Expiry of the oldest package with pending cleanup.",
		Availability: "Only while cleanup is pending.", Reset: stateGauge},
}

// DurationBuckets are the operation-duration histogram buckets, in seconds,
// for bounded operations (resolution, publication, cleanup).
var DurationBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300}
