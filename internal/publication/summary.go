package publication

import "time"

// ExportState records whether a run produced assessment OSCAL.
type ExportState string

const (
	ExportAssessment ExportState = "Assessment"
	ExportDiagnostic ExportState = "Diagnostic"
	// ExportCaptureLost means frozen bytes were lost before durable staging;
	// the run keeps its diagnostic record and is never recollected.
	ExportCaptureLost ExportState = "CaptureLost"
)

// RunSummary is the sanitized summary a run or request status may expose.
// Evidence completeness, check outcomes, and publication state are reported
// separately; none is derived from another. It carries no inventory, scope
// UID lists, storage locations, or credentials. ArtifactRef is an opaque
// handle; downloads still authorize through the request or run.
type RunSummary struct {
	Scope        ScopeKind       `json:"scope"`
	Evidence     EvidenceSummary `json:"evidence"`
	Outcomes     OutcomeCounts   `json:"outcomes"`
	Export       ExportState     `json:"export"`
	Publication  Phase           `json:"publication"`
	Availability Availability    `json:"availability"`
	ArtifactRef  string          `json:"artifactRef,omitempty"`
	// Coverage summarizes the package's coverage report; nil when the
	// package carries none. The descriptor does not record it: the
	// producer sets it from the report it packaged.
	Coverage *CoverageSummary `json:"coverage,omitempty"`
}

// Summarize derives a run summary from a frozen descriptor and its
// publication status.
func Summarize(d Descriptor, s Status) RunSummary {
	sum := RunSummary{Scope: d.Scope.Kind, Evidence: d.Evidence, Outcomes: d.Outcomes, Export: ExportAssessment, Publication: s.Phase, Availability: s.Availability}
	if d.PackageKind == KindDiagnostic {
		sum.Export = ExportDiagnostic
	}
	if s.Phase == PhaseCommitted {
		sum.ArtifactRef = s.PublicationID
	}
	return sum
}

// CaptureLostSummary is the summary of a run whose package bytes were lost.
// Its evidence is unknown and it is never published.
func CaptureLostSummary(scope ScopeKind) RunSummary {
	return RunSummary{Scope: scope, Evidence: EvidenceSummary{Completeness: Incomplete}, Export: ExportCaptureLost, Publication: PhaseFailed, Availability: AvailabilityUnavailable}
}

// CoverageSummary is the bounded summary of a package's control coverage
// report (coverage.json, RoleCoverage). It counts the selected baseline's
// controls by automation state and never counts satisfied or passing
// controls; the rows stay in the package. internal/coverage derives it
// from a report; v1alpha1.CoverageSummary is its status form.
type CoverageSummary struct {
	AsOf time.Time `json:"asOf"`
	// SHA256 is the lowercase hex sha256 of coverage.json.
	SHA256 string `json:"sha256"`
	// InputsSHA256 identifies the binding, namespaces and profile
	// selection the report assessed; empty when they were not recorded.
	InputsSHA256      string           `json:"inputsSha256,omitempty"`
	Bundle            *CoverageBundle  `json:"bundle,omitempty"`
	InventoryResolved bool             `json:"inventoryResolved"`
	MappingsResolved  bool             `json:"mappingsResolved"`
	Controls          int              `json:"controls"`
	Enhancements      int              `json:"enhancements"`
	Automation        AutomationCounts `json:"automation"`
	TechnicalEvidence string           `json:"technicalEvidence"`
	// ValidUntil is the run's evidence expiry evaluated at closure; nil
	// when no observation is attributable.
	ValidUntil    *time.Time `json:"validUntil,omitempty"`
	Limitations   int        `json:"limitations"`
	BlockingCodes []string   `json:"blockingCodes,omitempty"`
}

// CoverageBundle is the pinned content a coverage report read.
type CoverageBundle struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

// AutomationCounts counts controls by automation state.
type AutomationCounts struct {
	None       int `json:"none"`
	Unselected int `json:"unselected"`
	Partial    int `json:"partial"`
	Unknown    int `json:"unknown"`
}

// MaxBlockingCodes bounds CoverageSummary.BlockingCodes.
const MaxBlockingCodes = 8
