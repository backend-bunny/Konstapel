package kyverno

import (
	"context"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Inventory and collection adapters around the existing Kyverno path
// (add-assessment-provider-contract 2.1). They move no behavior: the
// inventory is collector.FreezeScope and collection is the PolicyReport
// listing the assessment controller has always done, now reached only
// through the host's narrow readers.

// InventoryInput is what the host froze for one snapshot. The host owns all
// of it: targeting resolves the subjects and stale scopes, the host reads
// and verifies the delivered engine policies (whose validations are the
// expected checks) and lists the workloads in the scope's namespaces.
type InventoryInput struct {
	Cluster       string
	Started       time.Time
	MappingSHA256 string
	Subjects      []targeting.EvidenceSubject
	Stale         []targeting.StaleScope
	// EnginePolicies are the delivered engine policies of the subjects.
	EnginePolicies []assessment.Object
	// Workloads are the workloads the host listed for the subjects.
	Workloads []collector.ListedObject
}

// Inventory derives the expected inventory from the host-frozen input
// alone, never from reports: every subject's checks against every listed
// workload it matches. A subject whose resources the host does not list
// (an unsupported subject) has no expected observation, and the host
// records that limitation.
func Inventory(in InventoryInput) (collector.CaptureV2, error) {
	return collector.FreezeScope(in.Cluster, in.Started, in.MappingSHA256, in.Subjects, in.Stale, in.EnginePolicies, in.Workloads)
}

// Collect lists the PolicyReports of each scope namespace, in scope order,
// through the provider's declared read. Reports are returned unevaluated
// and unfiltered; collector.CaptureV2.Evaluate attributes them by workload
// UID, engine policy and validation index, so a report about another
// workload, a replaced workload or an unsupported resource establishes
// nothing. A failed list ends collection with a limitation and keeps what
// earlier namespaces returned; the namespaces not read have missing
// evidence, never a pass. An empty scope reads nothing. Collection never
// reads ClusterPolicyReports, triggers the engine or writes.
func Collect(ctx context.Context, scope provider.Scope, sources provider.Sources) ([]assessment.Object, []string, error) {
	if len(scope.Namespaces) == 0 {
		return nil, nil, nil
	}
	reader, err := sources.Source(Reports())
	if err != nil {
		return nil, nil, err
	}
	var reports []assessment.Object
	for _, ns := range scope.Namespaces {
		rs, err := reader.List(ctx, ns.Name)
		if err != nil {
			return reports, []string{"policy reports unavailable: " + err.Error()}, nil
		}
		reports = append(reports, rs...)
	}
	return reports, nil, nil
}
