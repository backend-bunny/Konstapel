package assessment

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	ar.Metadata.Links = &[]oscal.Link{{Href: "content/component-definition.json", Rel: "related", Text: "Authored partial mapping"}, {Href: "content/provenance.json", Rel: "related", Text: "Pinned source revisions"}, {Href: "run-manifest.json", Rel: "related", Text: "Capture identity and content checksums"}, {Href: "evidence.json", Rel: "related", Text: "Completeness and rejected evidence"}}
	for i := range ar.Results {
		r := &ar.Results[i]
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
	return ValidateReferences(out)
}
