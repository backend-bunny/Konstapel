// Package provider is the installed assessment-provider contract
// (add-assessment-provider-contract): code-registered, versioned descriptors
// of the evidence providers this build contains, and the selection checks
// that decide whether a binding's checks may use one.
//
// Registration is code, not data. A Registry is built from descriptors
// compiled into the binary; verified bundle content only names a provider
// contract ("name/vN") and check kinds, and selection looks them up here. No
// bundle, profile or binding can name a Go module, executable, command path
// or plugin manifest, add a provider, or change a provider's declared reads.
//
// This package holds only the shared, provider-neutral types. Each provider's
// descriptor lives with that provider (internal/provider/kyverno), and the
// production registry is assembled in internal/provider/installed.
package provider

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// Descriptor is one installed provider's versioned capability contract.
type Descriptor struct {
	// Name is the provider identity, a DNS-label-like name such as
	// "konstapel-kyverno". It is unique within a registry.
	Name string `json:"name"`
	// Version is the provider contract version. Bundle descriptors select
	// it as compatibility.provider "<name>/v<version>"; another version of an
	// installed provider is incompatible, never adapted.
	Version int `json:"version"`
	// EvaluatorVersion versions the provider's evaluation semantics. It is a
	// separate dimension from the contract and capture versions.
	EvaluatorVersion int `json:"evaluatorVersion"`
	// Checks are the check kinds the provider evaluates.
	Checks []CheckKind `json:"checks"`
	// Capture is the provider's capture payload compatibility.
	Capture CaptureCompatibility `json:"capture"`
	// Reads are the external evidence-source API operations the provider's
	// collection performs. They are read-only. They document and bound the
	// provider's own access; the controller service account's RBAC is
	// shared and may be broader. Host-owned reads (namespaces, workload
	// listing for the expected inventory) and engine delivery are not
	// provider reads.
	Reads []Read `json:"reads"`
	// Requires are APIs the provider's evidence source must serve, in the
	// declared shape and with the declared verbs, that its collection never
	// reads: for example a report kind served alongside the one it reads.
	// Discovery checks them, but no access is reviewed or granted for them,
	// and Sources never grants a reader for one. Together with Reads they
	// are the provider's capability prerequisites
	// (capability.ForProvider).
	Requires []Prerequisite `json:"requires,omitempty"`
	// TestOnly marks a synthetic provider used only by tests. The production
	// registry never contains one (internal/provider/installed).
	TestOnly bool `json:"testOnly,omitempty"`
}

// Contract is the selection identity "<name>/v<version>".
func (d Descriptor) Contract() string { return d.Name + "/v" + strconv.Itoa(d.Version) }

// CheckKind is one kind of check definition a provider evaluates, such as
// a Kyverno ValidatingPolicy. A kind is owned by exactly one installed
// provider, which is how a selection's checks identify their provider.
type CheckKind struct {
	// Kind is "<group>/<version>/<Kind>" of the check definition in content.
	Kind string `json:"kind"`
	// Delivery is true when the host's delivery owner renders engine
	// resources for these checks (enforcement-capable). Reporting-only kinds
	// are false: no engine policy, scanner job or workload write is produced
	// for them, and they accept only Audit.
	Delivery bool `json:"delivery"`
	// Modes are the binding modes the kind accepts.
	Modes []v1alpha1.EnforcementMode `json:"modes"`
	// Parameters is the kind's parameter contract.
	Parameters ParameterContract `json:"parameters"`
}

// ParameterSource says who defines a check's parameter contract.
type ParameterSource string

const (
	// ParametersNone: the kind accepts no parameters.
	ParametersNone ParameterSource = "None"
	// ParametersFromContent: verified bundle content declares the contract
	// per check (a parameter schema), and delivery decides whether it renders
	// parameters (targeting.BundlePolicy.Parameters). This is the existing
	// Kyverno behavior.
	ParametersFromContent ParameterSource = "Content"
	// ParametersFromDescriptor: the descriptor's Schema is the contract for
	// every check of the kind.
	ParametersFromDescriptor ParameterSource = "Descriptor"
)

// ParameterContract is a check kind's parameter contract.
type ParameterContract struct {
	Source ParameterSource `json:"source"`
	// Schema is a self-contained JSON Schema describing an object, set
	// only for ParametersFromDescriptor.
	Schema json.RawMessage `json:"schema,omitempty"`
}

// CaptureCompatibility states which capture payload versions the provider
// writes and reads. Write must be readable: readers ship before writers.
type CaptureCompatibility struct {
	Write int   `json:"write"`
	Read  []int `json:"read"`
}

// Read is one external API operation set a provider's collection uses.
// Kind and Namespaced are the served resource shape: the host lists the
// resource by kind, and a namespaced read is only ever made inside the
// host-frozen scope's namespaces (see Sources).
type Read struct {
	Group      string   `json:"group"`
	Version    string   `json:"version"`
	Resource   string   `json:"resource"`
	Kind       string   `json:"kind"`
	Namespaced bool     `json:"namespaced"`
	Verbs      []string `json:"verbs"`
}

// ID is "<resource>.<group>/<version>", the read's identity.
func (r Read) ID() string { return r.Resource + "." + r.Group + "/" + r.Version }

// Prerequisite is an API a provider needs served in a given shape but never
// reads. Verbs are the discovery verbs the resource must advertise; they
// grant nothing.
type Prerequisite struct {
	Group      string   `json:"group"`
	Version    string   `json:"version"`
	Resource   string   `json:"resource"`
	Kind       string   `json:"kind"`
	Namespaced bool     `json:"namespaced"`
	Verbs      []string `json:"verbs"`
}

// ID is "<resource>.<group>/<version>", the prerequisite's identity.
func (p Prerequisite) ID() string { return p.Resource + "." + p.Group + "/" + p.Version }

var (
	namePattern     = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	contractPattern = regexp.MustCompile(`^([a-z0-9]+(?:-[a-z0-9]+)*)/v([0-9]+)$`)
	kindPattern     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?/v[0-9][a-z0-9]*/[A-Z][A-Za-z0-9]*$`)
	readKindPattern = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)
	readVerbs       = map[string]bool{"get": true, "list": true, "watch": true}
)

// ParseContract splits "<name>/v<version>". It accepts exactly the
// compatibility.provider grammar bundle descriptors use.
func ParseContract(s string) (name string, version int, err error) {
	m := contractPattern.FindStringSubmatch(s)
	if m == nil {
		return "", 0, fmt.Errorf("provider contract %q must look like name/vN", s)
	}
	v, err := strconv.Atoi(m[2])
	if err != nil {
		return "", 0, fmt.Errorf("provider contract %q: %v", s, err)
	}
	return m[1], v, nil
}

// Validate checks the descriptor on its own.
func (d Descriptor) Validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if !namePattern.MatchString(d.Name) || len(d.Name) > 63 {
		fail("name %q must be a lowercase DNS label", d.Name)
	}
	if d.Version < 1 {
		fail("version %d must be at least 1", d.Version)
	}
	if d.EvaluatorVersion < 1 {
		fail("evaluatorVersion %d must be at least 1", d.EvaluatorVersion)
	}
	if len(d.Checks) == 0 {
		fail("declares no check kinds")
	}
	seen := map[string]bool{}
	for _, k := range d.Checks {
		if err := k.validate(); err != nil {
			fail("check kind %q: %v", k.Kind, err)
		}
		if seen[k.Kind] {
			fail("check kind %q is declared twice", k.Kind)
		}
		seen[k.Kind] = true
	}
	if d.Capture.Write < 1 {
		fail("capture.write %d must be at least 1", d.Capture.Write)
	}
	if !slices.Contains(d.Capture.Read, d.Capture.Write) {
		fail("capture.read %v must include capture.write %d: readers ship before writers", d.Capture.Read, d.Capture.Write)
	}
	apis := map[string]bool{}
	for _, r := range d.Reads {
		if r.Version == "" || r.Resource == "" || len(r.Verbs) == 0 || !readKindPattern.MatchString(r.Kind) {
			fail("read %s/%s %s must name a version, a resource, its kind and verbs", r.Group, r.Version, r.Resource)
		}
		if apis[r.ID()] {
			fail("read %s is declared twice", r.ID())
		}
		apis[r.ID()] = true
		for _, v := range r.Verbs {
			if !readVerbs[v] {
				fail("read %s/%s %s: verb %q is not read-only (get, list, watch)", r.Group, r.Version, r.Resource, v)
			}
		}
	}
	for _, p := range d.Requires {
		if p.Version == "" || p.Resource == "" || len(p.Verbs) == 0 || !readKindPattern.MatchString(p.Kind) {
			fail("prerequisite %s/%s %s must name a version, a resource, its kind and verbs", p.Group, p.Version, p.Resource)
		}
		if apis[p.ID()] {
			fail("prerequisite %s is declared twice or is also a read", p.ID())
		}
		apis[p.ID()] = true
		for _, v := range p.Verbs {
			if !readVerbs[v] {
				fail("prerequisite %s/%s %s: verb %q is not read-only (get, list, watch)", p.Group, p.Version, p.Resource, v)
			}
		}
	}
	return joinErrors(d.Contract(), errs)
}

func (k CheckKind) validate() error {
	if !kindPattern.MatchString(k.Kind) {
		return fmt.Errorf("must look like group/version/Kind")
	}
	if len(k.Modes) == 0 {
		return fmt.Errorf("declares no modes")
	}
	for i, m := range k.Modes {
		switch {
		case m != v1alpha1.ModeAudit && m != v1alpha1.ModeDeny:
			return fmt.Errorf("mode %q is not Audit or Deny", m)
		case slices.Contains(k.Modes[:i], m):
			return fmt.Errorf("mode %q is declared twice", m)
		case m == v1alpha1.ModeDeny && !k.Delivery:
			return fmt.Errorf("a reporting-only kind (delivery false) cannot accept Deny")
		}
	}
	switch k.Parameters.Source {
	case ParametersNone, ParametersFromContent:
		if len(k.Parameters.Schema) > 0 {
			return fmt.Errorf("parameters.schema is only for source %s", ParametersFromDescriptor)
		}
	case ParametersFromDescriptor:
		if _, err := compileSchema(k.Kind, k.Parameters.Schema); err != nil {
			return err
		}
	default:
		return fmt.Errorf("parameters.source %q is not None, Content or Descriptor", k.Parameters.Source)
	}
	return nil
}

// compileSchema compiles a descriptor parameter schema: a self-contained
// JSON Schema describing an object, with no remote references.
func compileSchema(kind string, raw []byte) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytesReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parameters.schema: %v", err)
	}
	if m, _ := doc.(map[string]any); m == nil || m["type"] != "object" {
		return nil, fmt.Errorf("parameters.schema must describe an object")
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(denyLoader{})
	url := "provider:///" + kind + "/parameters.json"
	if err := c.AddResource(url, doc); err != nil {
		return nil, fmt.Errorf("parameters.schema: %w", err)
	}
	s, err := c.Compile(url)
	if err != nil {
		return nil, fmt.Errorf("parameters.schema: %w", err)
	}
	return s, nil
}

// denyLoader refuses every external schema reference.
type denyLoader struct{}

func (denyLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external schema reference %s is not allowed", url)
}

// KindOf is the check kind of a content manifest with the given apiVersion
// ("group/version") and kind. It is "" when either is missing or the
// apiVersion has no group, which no installed provider evaluates.
func KindOf(apiVersion, kind string) string {
	if apiVersion == "" || kind == "" || !strings.Contains(apiVersion, "/") {
		return ""
	}
	return apiVersion + "/" + kind
}
