package bundle

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// EngineContract is the one provider contract whose policy documents are
// engine policies: modern Kyverno ValidatingPolicies, delivered by the
// targeting owner. Under every other contract a policy document is a
// reporting-only check definition (CheckDefinition).
const EngineContract = providerContract

// engineGroup is the API group of engine policy content. A check
// definition never uses it: definitions carry no engine resource.
const engineGroup = "policies.kyverno.io"

// CheckDefinition is a reporting-only check definition: the declarative
// document a policies entry names under any contract but EngineContract.
// It is pure data. Its only members are the check kind (APIVersion and
// Kind), the logical name and the resources the check expects evidence
// for; ParseCheckDefinition rejects any other member at any level, so a
// definition cannot carry an executable, image, command, endpoint, service
// account, permission, engine rule or parameter values. Its parameter
// contract is the check kind's descriptor schema, never content.
type CheckDefinition struct {
	APIVersion string              `yaml:"apiVersion" json:"apiVersion"`
	Kind       string              `yaml:"kind" json:"kind"`
	Metadata   CheckMetadata       `yaml:"metadata" json:"metadata"`
	Spec       CheckDefinitionSpec `yaml:"spec" json:"spec"`
}

// CheckMetadata names the check.
type CheckMetadata struct {
	Name string `yaml:"name" json:"name"`
}

// CheckDefinitionSpec is what a check definition declares.
type CheckDefinitionSpec struct {
	// Resources are the resources the check expects evidence for. The host
	// derives a run's expected inventory from them; a provider report never
	// defines it.
	Resources []CheckResource `yaml:"resources" json:"resources"`
}

// CheckResource is one resource a check expects evidence for. Group is
// empty for the core API group.
type CheckResource struct {
	Group    string `yaml:"group" json:"group"`
	Version  string `yaml:"version" json:"version"`
	Resource string `yaml:"resource" json:"resource"`
}

// String is "<resource>.<group>/<version>" ("<resource>/<version>" for core).
func (r CheckResource) String() string {
	if r.Group == "" {
		return r.Resource + "/" + r.Version
	}
	return r.Resource + "." + r.Group + "/" + r.Version
}

// CheckKind is "<group>/<version>/<Kind>", the kind provider descriptors
// declare and selection looks up.
func (c *CheckDefinition) CheckKind() string { return c.APIVersion + "/" + c.Kind }

var (
	groupPattern    = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)+$`)
	apiVerPattern   = regexp.MustCompile(`^v[0-9]+((alpha|beta)[0-9]+)?$`)
	kindPattern     = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,62}$`)
	resourcePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	coreOrGroup     = regexp.MustCompile(`^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*)?$`)
)

// ParseCheckDefinition strictly decodes one check definition document
// (YAML or JSON) and validates it on its own. Unknown or repeated members,
// more than one document, an engine policy group, and malformed kinds,
// names or resources are rejected.
func ParseCheckDefinition(raw []byte) (*CheckDefinition, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var c CheckDefinition
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("check definition: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("check definition: exactly one document is allowed")
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *CheckDefinition) validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	group, version, ok := strings.Cut(c.APIVersion, "/")
	switch {
	case !ok || !groupPattern.MatchString(group) || len(group) > 253 || !apiVerPattern.MatchString(version):
		fail("apiVersion %q must be <group>/<version> with a DNS subdomain group", c.APIVersion)
	case group == engineGroup || strings.HasSuffix(group, "."+engineGroup) || group == "kyverno.io" || strings.HasSuffix(group, ".kyverno.io"):
		fail("apiVersion %q is engine policy content; a reporting-only check definition carries no engine resource", c.APIVersion)
	}
	if !kindPattern.MatchString(c.Kind) {
		fail("kind %q must be a Kubernetes kind name", c.Kind)
	}
	if !namePattern.MatchString(c.Metadata.Name) {
		fail("metadata.name %q must be a DNS label", c.Metadata.Name)
	}
	if len(c.Spec.Resources) == 0 {
		fail("spec.resources must name at least one resource the check expects evidence for")
	}
	seen := map[CheckResource]bool{}
	for i, r := range c.Spec.Resources {
		if !coreOrGroup.MatchString(r.Group) || len(r.Group) > 253 || !apiVerPattern.MatchString(r.Version) || !resourcePattern.MatchString(r.Resource) {
			fail("spec.resources[%d] %+v must be a group (empty for core), a version and a lowercase plural resource", i, r)
			continue
		}
		if seen[r] {
			fail("spec.resources[%d] %s is listed twice", i, r)
		}
		seen[r] = true
	}
	if len(errs) > 0 {
		return fmt.Errorf("check definition %q: %w", c.Metadata.Name, errors.Join(errs...))
	}
	return nil
}
