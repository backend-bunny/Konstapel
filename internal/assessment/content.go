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

	oscal "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/santhosh-tekuri/jsonschema/v6"
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
	s, e := jsonschema.NewCompiler().Compile(schema)
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

// ValidateMapping validates the first loop's component definition
// (content/component-definition.json) with ValidateDefinition and requires the
// bounded privileged-container mapping to ac-6_smt that the single-check
// acceptance path exports. Validation is independent of report presence.
func ValidateMapping(root string) (*oscal.ComponentDefinition, error) {
	def, ms, err := ValidateDefinition(root, "content/component-definition.json", map[string]string{PolicyName: SourcePolicy})
	if err != nil {
		return nil, err
	}
	for _, m := range ms {
		if m.Rule == PolicyName && m.StatementID == "ac-6_smt" {
			return def, nil
		}
	}
	return nil, fmt.Errorf("missing bounded %s mapping to ac-6_smt", PolicyName)
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
