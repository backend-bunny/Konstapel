package publication

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
