package coverage

import (
	"encoding/json"
	"slices"
	"strings"
)

// C2P property names the reader follows. Rule and parameter declarations
// are grouped into rule sets by their remarks, as C2P/compliance-trestle
// author them.
const (
	propRuleID           = "Rule_Id"
	propRuleDescription  = "Rule_Description"
	propCheckID          = "Check_Id"
	propCheckDescription = "Check_Description"
	propParameterID      = "Parameter_Id"
	propParameterDesc    = "Parameter_Description"
	propParameterAlts    = "Parameter_Value_Alternatives"
	componentValidation  = "validation"
)

// Mappings are the authored rule/check mappings of the content's component
// definitions, validated against one resolved baseline.
type Mappings struct {
	// Resolved is false when a declared component definition could not be
	// read or a control-implementation source could not be resolved: then
	// no control can be said to lack a mapping.
	Resolved bool
	// Definitions are the component definitions read, in declaration order.
	Definitions []DocumentRef
	// Limitations are not attributable to a selected control.
	Limitations []Limitation

	edges map[string][]*edge // selected control -> its mapping edges
}

// edge is one authored mapping of a rule to a control statement (or, with
// an empty statement, to the whole requirement).
type edge struct {
	control, statement string
	rule               string
	ruleDescription    string
	requirementDesc    string
	statementDesc      string
	definitions        []string
	checkIDs           []string
	checkDescription   string
	ruleParams         []RuleParameter
	oscalParams        []ParameterSetting
	problems           []Limitation // blocking: the edge is unresolved
}

// RuleParameter is a parameter a rule declares (C2P Parameter_Id), with any
// value the mapping sets for it. It configures the rule, not the control.
type RuleParameter struct {
	ID           string   `json:"id"`
	Description  string   `json:"description,omitempty"`
	Alternatives string   `json:"alternatives,omitempty"`
	Values       []string `json:"values,omitempty"`
}

// ParameterSetting is an authored set-parameter that names one of the
// control's OSCAL parameters.
type ParameterSetting struct {
	ParamID string   `json:"paramId"`
	Values  []string `json:"values,omitempty"`
}

// OSCAL component-definition subset.
type cdBody struct {
	Components []struct {
		Type                   string `json:"type"`
		Title                  string `json:"title"`
		Props                  []prop `json:"props"`
		ControlImplementations []struct {
			Source                  string `json:"source"`
			ImplementedRequirements []struct {
				ControlID     string `json:"control-id"`
				Description   string `json:"description"`
				Props         []prop `json:"props"`
				SetParameters []struct {
					ParamID string   `json:"param-id"`
					Values  []string `json:"values"`
				} `json:"set-parameters"`
				Statements []struct {
					StatementID string `json:"statement-id"`
					Description string `json:"description"`
					Props       []prop `json:"props"`
				} `json:"statements"`
			} `json:"implemented-requirements"`
		} `json:"control-implementations"`
	} `json:"components"`
}

type ruleSet struct {
	description string
	params      []RuleParameter
}

type checkSet struct {
	ids         []string
	description string
}

// ReadMappings reads every declared component definition of the content
// and validates its mappings against b (resolved from the same content).
func ReadMappings(c Content, o Options, b *Baseline) *Mappings {
	return readMappings(newLoader(c, o), b)
}

func readMappings(l *loader, b *Baseline) *Mappings {
	m := &Mappings{Resolved: true, edges: map[string][]*edge{}}
	checks := map[string]string{} // rule -> descriptor checkID
	for _, p := range l.c.Policies {
		for _, c := range p.Checks {
			checks[c.RuleID] = c.CheckID
		}
	}
	add := func(lim *Limitation) {
		m.Limitations = append(m.Limitations, *lim)
		if lim.Blocking {
			m.Resolved = false
		}
	}
	// Sources that qualify mappings to the baseline's catalog.
	sameCatalog := map[string]bool{b.Catalog.Digest: true, b.Profile.Digest: true}
	for _, d := range b.Imports {
		sameCatalog[d.Digest] = true
	}
	seen := map[[3]string]*edge{}
	for _, entry := range l.c.OSCAL {
		model, lim := l.model(entry.Path)
		if lim != nil {
			add(lim)
			continue
		}
		if model != ModelComponentDefinition {
			continue
		}
		doc, lim := l.load(entry.Path, ModelComponentDefinition)
		if lim != nil {
			add(lim)
			continue
		}
		m.Definitions = append(m.Definitions, doc.Ref)
		var cd cdBody
		if err := json.Unmarshal(doc.body, &cd); err != nil {
			add(blocking(CodeDocumentInvalid, entry.Path, "", "component definition: %v", err))
			continue
		}
		declaredChecks := map[string]*checkSet{}
		for _, comp := range cd.Components {
			if comp.Type != componentValidation {
				continue
			}
			for rule, cs := range checkSets(comp.Props) {
				if declaredChecks[rule] == nil {
					declaredChecks[rule] = &checkSet{}
				}
				declaredChecks[rule].ids = append(declaredChecks[rule].ids, cs.ids...)
				if declaredChecks[rule].description == "" {
					declaredChecks[rule].description = cs.description
				}
			}
		}
		for _, comp := range cd.Components {
			if comp.Type == componentValidation {
				continue
			}
			rules := ruleSets(comp.Props)
			for _, ci := range comp.ControlImplementations {
				src, lim := l.resolveHref(entry.Path, ci.Source)
				if lim != nil {
					add(blocking(CodeMappingSourceUnresolved, entry.Path, ci.Source, "control-implementation source: %s", lim.Message))
					continue
				}
				_, dig, err := l.raw(src)
				if err != nil {
					add(blocking(CodeMappingSourceUnresolved, entry.Path, ci.Source, "control-implementation source: %v", err))
					continue
				}
				if !sameCatalog[dig] {
					add(notice(CodeMappingCatalogMismatch, entry.Path, ci.Source, "source %s is not the baseline's catalog or profile (%s); its mappings are not attributed", src, b.Catalog.Path))
					continue
				}
				for _, req := range ci.ImplementedRequirements {
					id := req.ControlID
					if _, ok := b.Control(id); !ok {
						if b.InCatalog(id) {
							add(notice(CodeMappingControlNotSelected, entry.Path, id, "%s is in the catalog but not selected by the baseline; its mapping is not attributed", id))
						} else {
							add(notice(CodeMappingControlUnknown, entry.Path, id, "%s is not a control of catalog %s; its mapping is not attributed", id, b.Catalog.Path))
						}
						continue
					}
					var reqEdges []*edge
					newEdge := func(stmt, stmtDesc, rule string) {
						key := [3]string{id, stmt, rule}
						if e, ok := seen[key]; ok {
							add(notice(CodeDuplicateMapping, entry.Path, id, "rule %s is mapped to %s more than once; counted once", rule, orControl(stmt, id)))
							if !slices.Contains(e.definitions, entry.Path) {
								e.definitions = append(e.definitions, entry.Path)
							}
							return
						}
						e := &edge{control: id, statement: stmt, rule: rule, requirementDesc: req.Description,
							statementDesc: stmtDesc, definitions: []string{entry.Path}}
						if stmt != "" && !b.HasStatement(id, stmt) {
							e.problems = append(e.problems, *blocking(CodeStatementNotInControl, entry.Path, stmt, "%s is not a statement of %s in catalog %s", stmt, id, b.Catalog.Path))
						}
						rs, declared := rules[rule]
						switch {
						case !declared:
							e.problems = append(e.problems, *blocking(CodeRuleUndeclared, entry.Path, rule, "rule %s is not declared with a %s by the mapping component", rule, propRuleDescription))
						default:
							e.ruleDescription = rs.description
							e.ruleParams = slices.Clone(rs.params)
						}
						checkID, inContent := checks[rule]
						switch cs := declaredChecks[rule]; {
						case !inContent:
							e.problems = append(e.problems, *blocking(CodeRuleNotInContent, entry.Path, rule, "rule %s is not a check of any policy in the content", rule))
						case cs == nil || !slices.Contains(cs.ids, checkID):
							e.problems = append(e.problems, *blocking(CodeCheckUndeclared, entry.Path, rule, "no validation component declares check %s for rule %s", checkID, rule))
						default:
							e.checkIDs, e.checkDescription = []string{checkID}, cs.description
						}
						seen[key] = e
						m.edges[id] = append(m.edges[id], e)
						reqEdges = append(reqEdges, e)
					}
					for _, r := range propValues(req.Props, propRuleID) {
						newEdge("", "", r)
					}
					for _, st := range req.Statements {
						for _, r := range propValues(st.Props, propRuleID) {
							newEdge(st.StatementID, st.Description, r)
						}
					}
					for _, sp := range req.SetParameters {
						matched := false
						if b.HasParameter(id, sp.ParamID) {
							matched = true
							for _, e := range reqEdges {
								e.oscalParams = append(e.oscalParams, ParameterSetting{ParamID: sp.ParamID, Values: sp.Values})
							}
						}
						for _, e := range reqEdges {
							for i := range e.ruleParams {
								if e.ruleParams[i].ID == sp.ParamID {
									matched = true
									e.ruleParams[i].Values = sp.Values
								}
							}
						}
						if !matched {
							for _, e := range reqEdges {
								e.problems = append(e.problems, *blocking(CodeParameterUnresolved, entry.Path, sp.ParamID, "set-parameter %s is neither an OSCAL parameter of %s nor a parameter of a mapped rule", sp.ParamID, id))
							}
							if len(reqEdges) == 0 {
								add(notice(CodeParameterUnresolved, entry.Path, sp.ParamID, "set-parameter %s of %s has no mapped rule", sp.ParamID, id))
							}
						}
					}
				}
			}
		}
	}
	m.Limitations = sortLimitations(m.Limitations)
	return m
}

func orControl(stmt, control string) string {
	if stmt == "" {
		return control
	}
	return stmt
}

func propValues(props []prop, name string) []string {
	var out []string
	for _, p := range props {
		if p.Name == name && p.Value != "" {
			out = append(out, p.Value)
		}
	}
	return out
}

// ruleSets groups a component's rule declarations by rule set (remarks).
func ruleSets(props []prop) map[string]*ruleSet {
	bySet := map[string]string{} // remarks -> rule
	for _, p := range props {
		if p.Name == propRuleID {
			bySet[p.Remarks] = p.Value
		}
	}
	out := map[string]*ruleSet{}
	for _, rule := range bySet {
		out[rule] = &ruleSet{}
	}
	for _, p := range props {
		rule, ok := bySet[p.Remarks]
		if !ok {
			continue
		}
		rs := out[rule]
		switch p.Name {
		case propRuleDescription:
			rs.description = p.Value
		case propParameterID:
			rs.params = append(rs.params, RuleParameter{ID: p.Value})
		case propParameterDesc:
			if n := len(rs.params); n > 0 {
				rs.params[n-1].Description = p.Value
			}
		case propParameterAlts:
			if n := len(rs.params); n > 0 {
				rs.params[n-1].Alternatives = p.Value
			}
		}
	}
	// A rule without a description is not declared: its coverage limits
	// would be unknown.
	for rule, rs := range out {
		if strings.TrimSpace(rs.description) == "" {
			delete(out, rule)
		}
	}
	return out
}

// checkSets groups a validation component's checks by rule set.
func checkSets(props []prop) map[string]*checkSet {
	bySet := map[string]string{}
	for _, p := range props {
		if p.Name == propRuleID {
			bySet[p.Remarks] = p.Value
		}
	}
	out := map[string]*checkSet{}
	for _, p := range props {
		rule, ok := bySet[p.Remarks]
		if !ok {
			continue
		}
		if out[rule] == nil {
			out[rule] = &checkSet{}
		}
		switch p.Name {
		case propCheckID:
			out[rule].ids = append(out[rule].ids, p.Value)
		case propCheckDescription:
			out[rule].description = p.Value
		}
	}
	return out
}
