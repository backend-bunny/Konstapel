package assessment

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	oscal "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/oscal-compass/compliance-to-policy-go/v2/framework/actions"
	"github.com/oscal-compass/compliance-to-policy-go/v2/plugin"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
	"github.com/oscal-compass/oscal-sdk-go/models/components"
	"github.com/oscal-compass/oscal-sdk-go/settings"
	"github.com/oscal-compass/oscal-sdk-go/transformers"
)

// InputFrom builds the C2P input context and assessment plan from several
// component definitions (relative to root), each validated against the
// shipped catalog, Moderate profile, and vendored policies. Components with
// the same type and title in different definitions (the workload component
// and the konstapel-kyverno validation component) are merged into one, so
// C2P attaches each check's subjects once; rule-set identifiers of later
// definitions are suffixed so they stay distinct. Input stays the
// first-loop, single-check path used by `konstapel acceptance` and the C2P
// provider plugin.
//
// rules limits the plan to the checks a package assesses (nil means every
// check): other rule sets, statements, requirements, and definitions are
// dropped, so the plan and results never mention or "satisfy" a control
// through a check that was not assessed.
func InputFrom(root string, defs, rules []string) (*actions.InputContext, *oscal.AssessmentPlan, error) {
	var merged *oscal.ComponentDefinition
	byKey := map[string]int{}
	for i, rel := range defs {
		def, _, err := ValidateDefinition(root, rel, ShippedPolicies)
		if err != nil {
			return nil, nil, err
		}
		if rules != nil {
			if def = scopeDefinition(*def, rules); def == nil {
				continue
			}
		}
		if merged == nil {
			copied := *def
			copied.Components = &[]oscal.DefinedComponent{}
			merged = &copied
		}
		for _, c := range *def.Components {
			if i > 0 && c.Props != nil {
				props := slices.Clone(*c.Props)
				for j := range props {
					if strings.HasPrefix(props[j].Remarks, "rule_set_") {
						props[j].Remarks = fmt.Sprintf("%s_d%d", props[j].Remarks, i)
					}
				}
				c.Props = &props
			}
			key := c.Type + "\x00" + c.Title
			k, ok := byKey[key]
			if !ok {
				byKey[key] = len(*merged.Components)
				*merged.Components = append(*merged.Components, c)
				continue
			}
			into := &(*merged.Components)[k]
			if c.Props != nil {
				props := []oscal.Property{}
				if into.Props != nil {
					props = append(props, *into.Props...)
				}
				props = append(props, *c.Props...)
				into.Props = &props
			}
			if c.ControlImplementations != nil {
				cis := []oscal.ControlImplementationSet{}
				if into.ControlImplementations != nil {
					cis = append(cis, *into.ControlImplementations...)
				}
				cis = append(cis, *c.ControlImplementations...)
				into.ControlImplementations = &cis
			}
		}
	}
	if merged == nil {
		return nil, nil, fmt.Errorf("no component definitions")
	}
	plan, err := transformers.ComponentDefinitionsToAssessmentPlan(context.Background(), []oscal.ComponentDefinition{*merged}, "nist_800_53")
	if err != nil {
		return nil, nil, err
	}
	var comps []components.Component
	var implementations []oscal.ControlImplementationSet
	for _, c := range *merged.Components {
		comps = append(comps, components.NewDefinedComponentAdapter(c))
		if c.ControlImplementations != nil {
			implementations = append(implementations, (*c.ControlImplementations)...)
		}
	}
	input, err := actions.NewContextFromComponents(comps)
	if err != nil {
		return nil, nil, err
	}
	selected, _, err := settings.ByFramework("nist_800_53", implementations)
	if err != nil {
		return nil, nil, err
	}
	input.Settings = selected.AllSettings()
	if _, err = input.ProviderTitle(plugin.ID(ProviderID)); err != nil {
		return nil, nil, fmt.Errorf("required validation provider absent: %w", err)
	}
	plan.ImportSsp.Href = "system-security-plan.json"
	return input, plan, nil
}

func Input(root string) (*actions.InputContext, *oscal.AssessmentPlan, error) {
	def, err := ValidateMapping(root)
	if err != nil {
		return nil, nil, err
	}
	plan, err := transformers.ComponentDefinitionsToAssessmentPlan(context.Background(), []oscal.ComponentDefinition{*def}, "nist_800_53")
	if err != nil {
		return nil, nil, err
	}
	var comps []components.Component
	var implementations []oscal.ControlImplementationSet
	for _, c := range *def.Components {
		comps = append(comps, components.NewDefinedComponentAdapter(c))
		if c.ControlImplementations != nil {
			implementations = append(implementations, (*c.ControlImplementations)...)
		}
	}
	input, err := actions.NewContextFromComponents(comps)
	if err != nil {
		return nil, nil, err
	}
	selected, _, err := settings.ByFramework("nist_800_53", implementations)
	if err != nil {
		return nil, nil, err
	}
	input.Settings = selected.AllSettings()
	if _, err = input.ProviderTitle(plugin.ID(ProviderID)); err != nil {
		return nil, nil, fmt.Errorf("required validation provider absent: %w", err)
	}
	plan.ImportSsp.Href = "system-security-plan.json"
	return input, plan, nil
}
func StartProvider(manifestPath string, config map[string]string) (policy.Provider, error) {
	var m plugin.Manifest
	if err := Read(manifestPath, &m); err != nil {
		return nil, err
	}
	if m.ID != plugin.ID(ProviderID) {
		return nil, fmt.Errorf("wrong provider id %s", m.ID)
	}
	if err := m.ResolvePath(filepath.Dir(manifestPath)); err != nil {
		return nil, err
	}
	opts, err := m.ResolveOptions(config, hclog.NewNullLogger())
	if err != nil {
		return nil, err
	}
	p, err := plugin.NewPolicyPlugin(m, plugin.ClientFactory(hclog.NewNullLogger()))
	if err != nil {
		return nil, err
	}
	if err = p.Configure(context.Background(), opts); err != nil {
		return nil, err
	}
	return p, nil
}
func Export(ctx context.Context, root, out string, input *actions.InputContext, plan *oscal.AssessmentPlan, results []policy.PVPResult, c Capture) error {
	if _, err := os.Stat(filepath.Join(out, "content")); err == nil {
		return fmt.Errorf("output package already exists; choose a fresh directory")
	}
	ev, _, err := Reconcile(c)
	if err != nil {
		return err
	}
	if c.MappingDigest != FileHash(filepath.Join(root, "content/component-definition.json")) {
		return fmt.Errorf("capture mapping revision mismatch")
	}
	rendered, err := VerifyPolicy(root, c)
	if err != nil {
		return err
	}
	if err = Write(filepath.Join(out, "rendered-policy.json"), rendered); err != nil {
		return err
	}
	renderedHash := FileHash(filepath.Join(out, "rendered-policy.json"))
	if err = Write(filepath.Join(out, "content-manifest.json"), Object{"sourcePolicySha256": FileHash(filepath.Join(root, SourcePolicy)), "renderedPolicySha256": renderedHash, "policySpecSha256": c.PolicyDigest}); err != nil {
		return err
	}
	if err = Write(filepath.Join(out, "capture.json"), c); err != nil {
		return err
	}
	if err = Write(filepath.Join(out, "evidence.json"), ev); err != nil {
		return err
	}
	if err = Write(filepath.Join(out, "run-manifest.json"), Object{"cluster": c.Cluster, "policySpecSha256": c.PolicyDigest, "appliedPolicySha256": Digest(c.Policy), "sourcePolicySha256": FileHash(filepath.Join(root, SourcePolicy)), "mappingSha256": c.MappingDigest, "evaluationBoundary": c.Boundary, "collected": c.Collected, "complete": ev.Complete, "coverage": Coverage, "expected": c.Expected, "policyRevision": "fac1ccda72ab53594921ca1c040ac90b80afadcd", "nistRevision": "f0de6d8d8c059d374f15e0ae07508d82e370fc1d"}); err != nil {
		return err
	}
	if err = os.CopyFS(filepath.Join(out, "content"), os.DirFS(filepath.Join(root, "content"))); err != nil {
		return err
	}
	// The source is packaged at its original relative path under content.
	if plan.BackMatter != nil && plan.BackMatter.Resources != nil {
		for i := range *plan.BackMatter.Resources {
			r := &(*plan.BackMatter.Resources)[i]
			if r.Rlinks != nil {
				for j := range *r.Rlinks {
					(*r.Rlinks)[j].Href = "content/upstream/nist/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
				}
			}
		}
	}
	plan.Metadata.Title = "Bounded AC-6 privileged-container assessment plan"
	plan.Metadata.OscalVersion = "1.1.3"
	if err = Write(filepath.Join(out, "assessment-plan.json"), Object{"assessment-plan": plan}); err != nil {
		return err
	}
	ar, err := actions.Report(ctx, input, "assessment-plan.json", *plan, results)
	if err != nil {
		return err
	}
	ar.Metadata.Title = "Bounded AC-6 technical evidence (partial coverage)"
	ar.Metadata.OscalVersion = "1.1.3"
	props := []oscal.Property{{Name: "coverage", Ns: "https://konstapel.dev/ns", Value: "partial"}, {Name: "complete", Ns: "https://konstapel.dev/ns", Value: fmt.Sprint(ev.Complete)}, {Name: "cluster-id", Ns: "https://konstapel.dev/ns", Value: c.Cluster}, {Name: "policy-spec-sha256", Ns: "https://konstapel.dev/ns", Value: c.PolicyDigest}, {Name: "mapping-sha256", Ns: "https://konstapel.dev/ns", Value: c.MappingDigest}}
	ar.Metadata.Props = &props
	*ar.Metadata.Props = append(*ar.Metadata.Props, oscal.Property{Name: "rendered-policy-sha256", Ns: "https://konstapel.dev/ns", Value: renderedHash}, oscal.Property{Name: "source-policy-sha256", Ns: "https://konstapel.dev/ns", Value: FileHash(filepath.Join(root, SourcePolicy))})
	ar.Metadata.Links = &[]oscal.Link{{Href: "content/component-definition.json", Rel: "related", Text: "Authored partial mapping"}, {Href: "content/provenance.json", Rel: "related", Text: "Pinned source revisions"}, {Href: "run-manifest.json", Rel: "related", Text: "Capture identity and content checksums"}, {Href: "evidence.json", Rel: "related", Text: "Completeness and rejected evidence"}}
	*ar.Metadata.Links = append(*ar.Metadata.Links, oscal.Link{Href: "rendered-policy.json", Rel: "related", Text: "Verified rendered policy"}, oscal.Link{Href: "content-manifest.json", Rel: "related", Text: "Source and rendered policy checksums"})
	for i := range ar.Results {
		r := &ar.Results[i]
		if !ev.Complete && len(ev.Evaluations) == 0 {
			// Missing evidence is not an observed violation of the control.
			r.Findings = nil
		}
		// C2P initializes optional inventory properties to an empty slice, which
		// violates OSCAL's minItems constraint. Omit empty optional properties.
		if r.LocalDefinitions != nil && r.LocalDefinitions.InventoryItems != nil {
			for j := range *r.LocalDefinitions.InventoryItems {
				item := &(*r.LocalDefinitions.InventoryItems)[j]
				if item.Props != nil && len(*item.Props) == 0 {
					item.Props = nil
				}
			}
		}
		r.Title = "Privileged-container technical check"
		r.Description = Coverage
		if r.Findings != nil {
			for j := range *r.Findings {
				f := &(*r.Findings)[j]
				f.Title = "Partial privileged-container evidence"
				f.Description = Coverage
				f.Target.Description = Coverage
			}
		}
		if r.Observations != nil {
			for j := range *r.Observations {
				obs := &(*r.Observations)[j]
				obs.Description = Coverage
				obs.Collected = c.Collected
				if obs.Subjects != nil {
					for k := range *obs.Subjects {
						subject := &(*obs.Subjects)[k]
						if subject.Props == nil {
							continue
						}
						missing := false
						for _, prop := range *subject.Props {
							if prop.Name == "source-outcome" && prop.Value == "missing" {
								missing = true
							}
						}
						filtered := []oscal.Property{}
						for _, prop := range *subject.Props {
							if strings.TrimSpace(prop.Value) == "" || (missing && prop.Name == "evaluated-on") {
								continue
							}
							filtered = append(filtered, prop)
						}
						subject.Props = &filtered
					}
				}
			}
		}
	}
	if err = Write(filepath.Join(out, "assessment-results.json"), Object{"assessment-results": ar}); err != nil {
		return err
	}
	if err = Write(filepath.Join(out, "system-security-plan.json"), SupportSSP(c.Cluster, c.Collected)); err != nil {
		return err
	}
	return ValidatePackage(root, out)
}
func FileHash(p string) string {
	b, e := os.ReadFile(p)
	if e != nil {
		return ""
	}
	return Hash(b)
}
func SupportSSP(cluster string, now time.Time) Object {
	id := func() string { return uuid.NewString() }
	return Object{"system-security-plan": Object{"uuid": id(), "metadata": Object{"title": "Disposable assessment target context; not a production SSP", "last-modified": now, "version": "1.0.0", "oscal-version": "1.1.3"}, "import-profile": Object{"href": "content/upstream/nist/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"}, "system-characteristics": Object{"system-ids": []any{Object{"id": cluster}}, "system-name": "Konstapel disposable assessment target", "description": Coverage, "system-information": Object{"information-types": []any{Object{"uuid": id(), "title": "Synthetic test workloads", "description": "No production data; controlled policy evaluation fixtures."}}}, "status": Object{"state": "under-development"}, "authorization-boundary": Object{"description": "Explicitly selected disposable cluster " + cluster}}, "system-implementation": Object{"users": []any{Object{"uuid": id(), "title": "Acceptance operator", "description": "Operator of disposable fixtures."}}, "components": []any{Object{"uuid": id(), "type": "this-system", "title": "Assessment target", "description": cluster, "status": Object{"state": "operational"}}}}, "control-implementation": Object{"description": Coverage, "implemented-requirements": []any{Object{"uuid": id(), "control-id": "ac-6", "remarks": Coverage}}}}}
}
func ValidatePackage(root, out string) error {
	for _, name := range []string{"assessment-plan", "assessment-results", "system-security-plan"} {
		if err := Schema(filepath.Join(out, name+".json"), filepath.Join(root, "content/schemas/oscal-1.1.3.json")); err != nil {
			return fmt.Errorf("%s schema: %w", name, err)
		}
	}
	var capture Capture
	if err := Read(filepath.Join(out, "capture.json"), &capture); err != nil {
		return err
	}
	if _, _, err := Reconcile(capture); err != nil {
		return err
	}
	if _, err := VerifyPolicy(out, capture); err != nil {
		return err
	}
	var manifest Object
	if err := Read(filepath.Join(out, "content-manifest.json"), &manifest); err != nil {
		return err
	}
	if manifest["renderedPolicySha256"] != FileHash(filepath.Join(out, "rendered-policy.json")) || manifest["sourcePolicySha256"] != FileHash(filepath.Join(out, SourcePolicy)) || manifest["policySpecSha256"] != capture.PolicyDigest || capture.MappingDigest != FileHash(filepath.Join(out, "content/component-definition.json")) {
		return fmt.Errorf("package policy or mapping checksum mismatch")
	}
	return ValidateReferences(out)
}

// scopeDefinition keeps only the given rules' rule sets and the control
// statements that reference them. It returns nil when none remain.
func scopeDefinition(def oscal.ComponentDefinition, rules []string) *oscal.ComponentDefinition {
	keep := func(id string) bool { return slices.Contains(rules, id) }
	var comps []oscal.DefinedComponent
	kept := false
	for _, c := range *def.Components {
		if c.Props != nil {
			drop := map[string]bool{}
			for _, p := range *c.Props {
				if p.Name == ruleIDName && !keep(p.Value) {
					drop[p.Remarks] = true
				}
			}
			var props []oscal.Property
			for _, p := range *c.Props {
				if !drop[p.Remarks] || p.Remarks == "" {
					props = append(props, p)
					kept = kept || (p.Name == ruleIDName && c.Type != "validation")
				}
			}
			c.Props = &props
		}
		if c.ControlImplementations != nil {
			var sets []oscal.ControlImplementationSet
			for _, ci := range *c.ControlImplementations {
				var reqs []oscal.ImplementedRequirementControlImplementation
				for _, req := range ci.ImplementedRequirements {
					if req.Statements == nil {
						continue
					}
					var stmts []oscal.ControlStatementImplementation
					for _, st := range *req.Statements {
						if st.Props == nil {
							continue
						}
						var props []oscal.Property
						referenced := false
						for _, p := range *st.Props {
							if p.Name == ruleIDName {
								if !keep(p.Value) {
									continue
								}
								referenced = true
							}
							props = append(props, p)
						}
						if referenced {
							st.Props = &props
							stmts = append(stmts, st)
						}
					}
					if len(stmts) > 0 {
						req.Statements = &stmts
						reqs = append(reqs, req)
					}
				}
				if len(reqs) > 0 {
					ci.ImplementedRequirements = reqs
					sets = append(sets, ci)
				}
			}
			if len(sets) == 0 {
				c.ControlImplementations = nil
			} else {
				c.ControlImplementations = &sets
			}
		}
		comps = append(comps, c)
	}
	if !kept {
		return nil
	}
	def.Components = &comps
	return &def
}
