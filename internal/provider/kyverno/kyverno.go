// Package kyverno declares the installed Kyverno evidence provider: the
// existing konstapel-kyverno contract that bundle descriptors already name
// as compatibility.provider "konstapel-kyverno/v1". It describes today's
// behavior and changes none of it: ValidatingPolicy delivery stays with
// internal/targeting, PolicyReport collection and evaluation with
// internal/collector, and C2P conversion with internal/assessment.
package kyverno

import (
	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
)

const (
	// Name is the provider identity, the C2P provider ID.
	Name = assessment.ProviderID
	// Version is the provider contract version bundles select.
	Version = 1
	// Contract is the compatibility.provider value of Kyverno bundles.
	Contract = Name + "/v1"
	// EvaluatorVersion versions the evaluation semantics of
	// collector.CaptureV2.Evaluate and collector.Tally as of Konstapel 0.3.0.
	EvaluatorVersion = 1
	// CheckKind is the only check definition the provider evaluates.
	CheckKind = "policies.kyverno.io/v1/ValidatingPolicy"
)

// Descriptor is the Kyverno provider's capability contract.
func Descriptor() provider.Descriptor {
	return provider.Descriptor{
		Name:             Name,
		Version:          Version,
		EvaluatorVersion: EvaluatorVersion,
		Checks: []provider.CheckKind{{
			Kind:     CheckKind,
			Delivery: true,
			Modes:    []v1alpha1.EnforcementMode{v1alpha1.ModeAudit, v1alpha1.ModeDeny},
			// Bundle content declares each policy's parameter schema;
			// delivery does not render parameters yet, so any are rejected.
			Parameters: provider.ParameterContract{Source: provider.ParametersFromContent},
		}},
		// The prototype's single-policy capture (1) and the controller's
		// CaptureV2 (2) are both read; the controller writes 2.
		Capture: provider.CaptureCompatibility{Write: collector.CaptureV2Version, Read: []int{1, collector.CaptureV2Version}},
		// The collector reads namespaced PolicyReports only. Workload and
		// namespace listing is host-owned; ValidatingPolicy writes belong to
		// delivery (capability.Delivery), not to evidence collection.
		Reads: []provider.Read{Reports()},
		// ClusterPolicyReports are served alongside by the same reports
		// API and required, never read.
		Requires: []provider.Prerequisite{ClusterReports()},
	}
}

// Reports is the provider's only evidence-source read: namespaced
// wgpolicyk8s.io/v1alpha2 PolicyReports. ClusterPolicyReports are never read.
func Reports() provider.Read {
	return provider.Read{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "policyreports", Kind: "PolicyReport", Namespaced: true,
		Verbs: []string{"get", "list", "watch"}}
}

// ClusterReports is the provider's only prerequisite that it does not read:
// cluster-scoped wgpolicyk8s.io/v1alpha2 ClusterPolicyReports, served by the
// same reports API. Discovery requires them; no access is reviewed and no
// reader is granted.
func ClusterReports() provider.Prerequisite {
	return provider.Prerequisite{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "clusterpolicyreports", Kind: "ClusterPolicyReport",
		Verbs: []string{"get", "list", "watch"}}
}
