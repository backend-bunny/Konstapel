package assessment

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	oscal "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
)

// ComponentDefinitions are the shipped mapping documents, relative to the
// repository root. The first loop's privileged-container check and the Linux
// hardening bundle are separate documents composed by reference; neither
// copies the other's checks.
var ComponentDefinitions = []string{
	"content/component-definition.json",
	"content/linux-hardening/component-definition.json",
}

const (
	catalogFile = NIST + "NIST_SP-800-53_rev5_catalog.json"
	profileFile = NIST + "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"
	ruleIDName  = "Rule_Id"
	checkIDName = "Check_Id"
)

// Mapping is one check's bounded mapping to one catalog statement.
type Mapping struct {
	Rule        string `json:"rule"`
	ControlID   string `json:"controlId"`
	StatementID string `json:"statementId"`
	// Rationale is the rule's Rule_Description: its partial-coverage limits.
	Rationale  string `json:"rationale"`
	Definition string `json:"definition"`
}

type nistContent struct {
	ids      map[string]bool // every id in the catalog
	moderate map[string]bool // controls the Moderate profile includes
}

// loadNIST reads the shipped catalog and Moderate profile at their declared
// OSCAL 1.2.3 schema, verifies that the profile's import resolves to the
// shipped catalog, and indexes their identifiers.
func loadNIST(root string) (*nistContent, error) {
	for _, f := range []string{catalogFile, profileFile} {
		if e := Schema(filepath.Join(root, f), filepath.Join(root, "content/schemas/oscal-1.2.3.json")); e != nil {
			return nil, fmt.Errorf("schema %s: %w", f, e)
		}
	}
	var catalog, profile Object
	if e := Read(filepath.Join(root, catalogFile), &catalog); e != nil {
		return nil, e
	}
	if e := Read(filepath.Join(root, profileFile), &profile); e != nil {
		return nil, e
	}
	n := &nistContent{ids: map[string]bool{}, moderate: map[string]bool{}}
	var visit func(any)
	visit = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if id := Str(x["id"]); id != "" {
				n.ids[id] = true
			}
			for _, y := range x {
				visit(y)
			}
		case []any:
			for _, y := range x {
				visit(y)
			}
		}
	}
	visit(catalog)
	imports, _ := At(profile, "profile", "imports").([]any)
	ref := ""
	for _, i := range imports {
		m := Map(i)
		ref = Str(m["href"])
		incs, _ := m["include-controls"].([]any)
		for _, inc := range incs {
			list, _ := Map(inc)["with-ids"].([]any)
			for _, id := range list {
				n.moderate[Str(id)] = true
			}
		}
	}
	resources, _ := At(profile, "profile", "back-matter", "resources").([]any)
	resolved := false
	for _, r := range resources {
		if "#"+Str(Map(r)["uuid"]) != ref {
			continue
		}
		links, _ := Map(r)["rlinks"].([]any)
		for _, l := range links {
			href := Str(Map(l)["href"])
			if strings.HasSuffix(href, "/json/NIST_SP-800-53_rev5_catalog.json") &&
				filepath.Clean(filepath.Join(root, NIST, href)) == filepath.Clean(filepath.Join(root, catalogFile)) {
				resolved = true
			}
		}
	}
	if !resolved || len(n.moderate) == 0 {
		return nil, fmt.Errorf("Moderate membership/catalog reference unresolved")
	}
	return n, nil
}

// ValidateDefinition validates one shipped component definition without
// decoding NIST content through the older C2P OSCAL model:
//   - the document is valid OSCAL 1.1.3 and its control source resolves to the
//     shipped catalog;
//   - every implemented control is in the catalog and the Moderate profile,
//     and every statement exists and belongs to its control;
//   - every statement names at least one rule, every rule the software
//     component declares (with a description) is mapped at least once and has
//     a Check_Id in the konstapel-kyverno validation provider, and nothing
//     maps an undeclared rule;
//   - every rule is a vendored policy (policies maps rule -> manifest path).
func ValidateDefinition(root, rel string, policies map[string]string) (*oscal.ComponentDefinition, []Mapping, error) {
	nist, err := loadNIST(root)
	if err != nil {
		return nil, nil, err
	}
	return validateDefinition(root, rel, policies, nist)
}

func validateDefinition(root, rel string, policies map[string]string, nist *nistContent) (*oscal.ComponentDefinition, []Mapping, error) {
	path := filepath.Join(root, rel)
	if e := Schema(path, filepath.Join(root, "content/schemas/oscal-1.1.3.json")); e != nil {
		return nil, nil, fmt.Errorf("schema %s: %w", rel, e)
	}
	var env struct {
		Definition oscal.ComponentDefinition `json:"component-definition"`
	}
	if e := Read(path, &env); e != nil {
		return nil, nil, e
	}
	if env.Definition.Components == nil {
		return nil, nil, fmt.Errorf("%s: no components", rel)
	}
	declared := map[string]string{} // rule -> description
	checks := map[string]bool{}
	provider := false
	var out []Mapping
	for _, comp := range *env.Definition.Components {
		if comp.Type == "validation" && comp.Title == ProviderID {
			provider = true
			if comp.Props != nil {
				for _, p := range *comp.Props {
					if p.Name == checkIDName {
						checks[p.Value] = true
					}
				}
			}
		}
		if comp.Type != "software" {
			continue
		}
		if comp.Props != nil {
			sets := map[string]string{}
			for _, p := range *comp.Props {
				if p.Name == ruleIDName {
					sets[p.Remarks] = p.Value
					declared[p.Value] = ""
				}
			}
			for _, p := range *comp.Props {
				if p.Name == "Rule_Description" && sets[p.Remarks] != "" {
					declared[sets[p.Remarks]] = p.Value
				}
			}
		}
		if comp.ControlImplementations == nil {
			continue
		}
		for _, ci := range *comp.ControlImplementations {
			if filepath.Clean(filepath.Join(filepath.Dir(path), ci.Source)) != filepath.Clean(filepath.Join(root, catalogFile)) {
				return nil, nil, fmt.Errorf("%s: mapping catalog source unresolved: %s", rel, ci.Source)
			}
			for _, req := range ci.ImplementedRequirements {
				if !nist.ids[req.ControlId] {
					return nil, nil, fmt.Errorf("%s: unsupported control %s: not in the catalog", rel, req.ControlId)
				}
				if !nist.moderate[req.ControlId] {
					return nil, nil, fmt.Errorf("%s: control %s is not in the Moderate baseline", rel, req.ControlId)
				}
				if req.Statements == nil || len(*req.Statements) == 0 {
					return nil, nil, fmt.Errorf("%s: control %s maps no statement", rel, req.ControlId)
				}
				for _, stmt := range *req.Statements {
					if !nist.ids[stmt.StatementId] || !strings.HasPrefix(stmt.StatementId, req.ControlId+"_smt") {
						return nil, nil, fmt.Errorf("%s: invalid statement %s for control %s", rel, stmt.StatementId, req.ControlId)
					}
					n := 0
					if stmt.Props != nil {
						for _, p := range *stmt.Props {
							if p.Name == ruleIDName {
								n++
								out = append(out, Mapping{Rule: p.Value, ControlID: req.ControlId, StatementID: stmt.StatementId, Definition: rel})
							}
						}
					}
					if n == 0 {
						return nil, nil, fmt.Errorf("%s: statement %s maps no rule", rel, stmt.StatementId)
					}
				}
			}
		}
	}
	if !provider {
		return nil, nil, fmt.Errorf("%s: missing validation provider %s", rel, ProviderID)
	}
	if len(out) == 0 {
		return nil, nil, fmt.Errorf("%s: missing bounded mapping", rel)
	}
	mapped := map[string]bool{}
	for i, m := range out {
		desc, ok := declared[m.Rule]
		if !ok {
			return nil, nil, fmt.Errorf("%s: statement %s maps undeclared rule %s", rel, m.StatementID, m.Rule)
		}
		out[i].Rationale = desc
		mapped[m.Rule] = true
	}
	for rule, desc := range declared {
		switch {
		case desc == "":
			return nil, nil, fmt.Errorf("%s: rule %s has no Rule_Description", rel, rule)
		case !mapped[rule]:
			return nil, nil, fmt.Errorf("%s: rule %s is not mapped to any statement", rel, rule)
		case !checks[rule]:
			return nil, nil, fmt.Errorf("%s: rule %s has no Check_Id in %s", rel, rule, ProviderID)
		case policies[rule] == "":
			return nil, nil, fmt.Errorf("%s: rule %s is not a vendored policy", rel, rule)
		}
		if _, e := os.Stat(filepath.Join(root, policies[rule])); e != nil {
			return nil, nil, fmt.Errorf("%s: rule %s policy: %w", rel, rule, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Rule+out[i].StatementID < out[j].Rule+out[j].StatementID
	})
	return &env.Definition, out, nil
}

// ShippedPolicies maps every logical check the shipped component definitions
// may reference to its shipped policy manifest.
var ShippedPolicies = map[string]string{
	PolicyName:                      SourcePolicy,
	"disallow-privilege-escalation": "content/linux-hardening/variants/disallow-privilege-escalation.yaml",
	"disallow-capabilities-strict":  "content/linux-hardening/variants/disallow-capabilities-strict.yaml",
	"require-run-as-nonroot":        "content/linux-hardening/variants/require-run-as-nonroot.yaml",
	"restrict-seccomp-strict":       "content/linux-hardening/variants/restrict-seccomp-strict.yaml",
}

// Mappings validates every shipped component definition and returns each
// logical check's bounded mappings, keyed by rule. A rule may appear in only
// one definition, so composing them never duplicates a check.
func Mappings(root string) (map[string][]Mapping, error) {
	nist, err := loadNIST(root)
	if err != nil {
		return nil, err
	}
	out := map[string][]Mapping{}
	owner := map[string]string{}
	for _, rel := range ComponentDefinitions {
		_, ms, err := validateDefinition(root, rel, ShippedPolicies, nist)
		if err != nil {
			return nil, err
		}
		for _, m := range ms {
			if o, ok := owner[m.Rule]; ok && o != rel {
				return nil, fmt.Errorf("rule %s is mapped by both %s and %s", m.Rule, o, rel)
			}
			owner[m.Rule] = rel
			out[m.Rule] = append(out[m.Rule], m)
		}
	}
	for rule := range out {
		slices.SortFunc(out[rule], func(a, b Mapping) int { return strings.Compare(a.StatementID, b.StatementID) })
	}
	return out, nil
}
