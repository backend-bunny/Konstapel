// Package assessment implements the bounded, single-check integration experiment.
package assessment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	oscal "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

const PolicyName = "disallow-privileged-containers"
const ProviderID = "konstapel-kyverno"
const Coverage = "Partial technical evidence for ac-6/ac-6_smt: prohibiting privileged containers reduces unnecessary process privileges; does not assess authorization, all process privileges, organizational procedures, or full AC-6/Moderate satisfaction."
const SourcePolicy = "content/upstream/kyverno/disallow-privileged-containers/disallow-privileged-containers.yaml"
const NIST = "content/upstream/nist/nist.gov/SP800-53/rev5/json/"
const OwnerLabel = "konstapel.io/owner"

type Object = map[string]any

func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func Digest(v any) string  { b, _ := json.Marshal(v); return Hash(b) }
func Read(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func Write(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0644)
}
func Map(v any) Object { m, _ := v.(map[string]any); return m }
func Str(v any) string { s, _ := v.(string); return s }
func At(m Object, keys ...string) any {
	var v any = m
	for _, k := range keys {
		v = Map(v)[k]
	}
	return v
}
func Schema(path, schema string) error {
	s, e := jsonschema.Compile(schema)
	if e != nil {
		return e
	}
	var doc any
	if e = Read(path, &doc); e != nil {
		return e
	}
	err := s.Validate(doc)
	if err != nil {
		if ve, ok := err.(*jsonschema.ValidationError); ok {
			return fmt.Errorf("%s", ve.GoString())
		}
	}
	return err
}

// ValidateMapping resolves identifiers in authoritative content without decoding it
// through the older C2P OSCAL model. Validation is independent of report presence.
func ValidateMapping(root string) (*oscal.ComponentDefinition, error) {
	for _, x := range []struct{ path, version string }{{"content/component-definition.json", "1.1.3"}, {NIST + "NIST_SP-800-53_rev5_catalog.json", "1.2.3"}, {NIST + "NIST_SP-800-53_rev5_MODERATE-baseline_profile.json", "1.2.3"}} {
		if e := Schema(filepath.Join(root, x.path), filepath.Join(root, "content/schemas/oscal-"+x.version+".json")); e != nil {
			return nil, fmt.Errorf("schema %s: %w", x.path, e)
		}
	}
	var catalog, profile Object
	if e := Read(filepath.Join(root, NIST+"NIST_SP-800-53_rev5_catalog.json"), &catalog); e != nil {
		return nil, e
	}
	if e := Read(filepath.Join(root, NIST+"NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"), &profile); e != nil {
		return nil, e
	}
	ids := map[string]bool{}
	var visit func(any)
	visit = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if id := Str(x["id"]); id != "" {
				ids[id] = true
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
	var env struct {
		Definition oscal.ComponentDefinition `json:"component-definition"`
	}
	if e := Read(filepath.Join(root, "content/component-definition.json"), &env); e != nil {
		return nil, e
	}
	if env.Definition.Components == nil {
		return nil, fmt.Errorf("mapping has no components")
	}
	found := false
	provider := false
	for _, comp := range *env.Definition.Components {
		if comp.Type == "validation" && comp.Title == ProviderID {
			provider = true
		}
		if comp.ControlImplementations == nil {
			continue
		}
		for _, ci := range *comp.ControlImplementations {
			source := filepath.Clean(filepath.Join(root, "content", ci.Source))
			want := filepath.Clean(filepath.Join(root, NIST+"NIST_SP-800-53_rev5_catalog.json"))
			if source != want {
				return nil, fmt.Errorf("mapping catalog source unresolved: %s", ci.Source)
			}
			for _, req := range ci.ImplementedRequirements {
				if req.ControlId != "ac-6" || !ids[req.ControlId] {
					return nil, fmt.Errorf("unsupported control %s", req.ControlId)
				}
				if req.Statements == nil {
					return nil, fmt.Errorf("missing statement")
				}
				for _, stmt := range *req.Statements {
					if stmt.StatementId != "ac-6_smt" || !ids[stmt.StatementId] {
						return nil, fmt.Errorf("invalid statement %s", stmt.StatementId)
					}
					found = true
				}
			}
		}
	}
	if !found || !provider {
		return nil, fmt.Errorf("missing bounded mapping or validation provider")
	}
	// Verify explicit selection and that the imported reference resolves to the shipped catalog.
	imports, _ := At(profile, "profile", "imports").([]any)
	member := false
	ref := ""
	for _, i := range imports {
		m := Map(i)
		ref = Str(m["href"])
		incs, _ := m["include-controls"].([]any)
		for _, inc := range incs {
			list, _ := Map(inc)["with-ids"].([]any)
			for _, id := range list {
				if id == "ac-6" {
					member = true
				}
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
			if strings.HasSuffix(href, "/json/NIST_SP-800-53_rev5_catalog.json") {
				p := filepath.Clean(filepath.Join(root, NIST, href))
				if p == filepath.Clean(filepath.Join(root, NIST+"NIST_SP-800-53_rev5_catalog.json")) {
					resolved = true
				}
			}
		}
	}
	if !member || !resolved {
		return nil, fmt.Errorf("Moderate membership/catalog reference unresolved")
	}
	return &env.Definition, nil
}

// Render leaves the upstream copy unchanged. Namespace selection is evaluated on
// the namespaced workload request, including ephemeral-container subresources.
func Render(root, action, namespace, owner string) (Object, error) {
	if action == "" {
		action = "Deny"
	}
	if action != "Deny" && action != "Audit" {
		return nil, fmt.Errorf("unsupported validation action %q", action)
	}
	if len(namespace) > 63 || !regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`).MatchString(namespace) || owner == "" {
		return nil, fmt.Errorf("valid namespace and owner are required")
	}
	b, e := os.ReadFile(filepath.Join(root, SourcePolicy))
	if e != nil {
		return nil, e
	}
	var p Object
	if e = yaml.Unmarshal(b, &p); e != nil {
		return nil, e
	}
	if p["apiVersion"] != "policies.kyverno.io/v1" || p["kind"] != "ValidatingPolicy" {
		return nil, fmt.Errorf("unsupported policy API")
	}
	meta := Map(p["metadata"])
	meta["labels"] = Object{OwnerLabel: owner}
	spec := Map(p["spec"])
	spec["validationActions"] = []any{action}
	spec["evaluation"] = Object{"background": Object{"enabled": true}}
	Map(spec["matchConstraints"])["namespaceSelector"] = Object{"matchLabels": Object{"kubernetes.io/metadata.name": namespace}}
	return p, nil
}

// VerifyPolicy compares the full captured spec with the shipped source and
// selected overlay. A self-consistent capture digest alone is not provenance.
func VerifyPolicy(root string, c Capture) (Object, error) {
	actions, ok := At(c.Policy, "spec", "validationActions").([]any)
	if !ok || len(actions) != 1 {
		return nil, fmt.Errorf("policy provenance: expected one validation action")
	}
	ns := Str(At(c.Policy, "spec", "matchConstraints", "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name"))
	owner := Str(At(c.Policy, "metadata", "labels", OwnerLabel))
	expected, err := Render(root, Str(actions[0]), ns, owner)
	if err != nil {
		return nil, fmt.Errorf("policy provenance: %w", err)
	}
	// Canonical JSON ignores object key order and server metadata/status. Unknown
	// spec fields fail closed; the pinned runtime adds no spec defaults.
	if Digest(c.Policy["spec"]) != Digest(expected["spec"]) {
		return nil, fmt.Errorf("policy provenance mismatch: captured spec differs from shipped source and configuration")
	}
	return expected, nil
}
