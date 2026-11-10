package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

// Supported declarative content: the one installed provider contract and the
// ValidatingPolicy API it evaluates. Bundle data cannot name another provider.
const (
	providerContract = assessment.ProviderID + "/v1"
	policyAPIVersion = "policies.kyverno.io/v1"
	policyKind       = "ValidatingPolicy"
	// authoredOSCAL is the C2P-compatible version of authored component
	// definitions; official NIST documents keep their own (newer) version.
	authoredOSCAL = "1.1.3"
)

func schemaPath(version string) string { return "content/schemas/oscal-" + version + ".json" }

// noDuplicateJSONKeys rejects any object that repeats a key. encoding/json
// silently keeps the last one, which would let two readers see different
// documents.
func noDuplicateJSONKeys(data []byte) error {
	type frame struct {
		keys      map[string]bool
		expectKey bool
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []*frame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var top *frame
		if n := len(stack); n > 0 {
			top = stack[n-1]
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{':
				stack = append(stack, &frame{keys: map[string]bool{}, expectKey: true})
			case '[':
				stack = append(stack, &frame{})
			default:
				stack = stack[:len(stack)-1]
				if n := len(stack); n > 0 && stack[n-1].keys != nil {
					stack[n-1].expectKey = true
				}
			}
			continue
		}
		if top != nil && top.keys != nil {
			if top.expectKey {
				key := tok.(string)
				if top.keys[key] {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				top.keys[key] = true
				top.expectKey = false
			} else {
				top.expectKey = true
			}
		}
	}
}

// materialize writes the payload to a private directory so the existing
// path-based OSCAL validation can run on exactly the shipped bytes. Paths were
// already validated by Unpack/Descriptor.Validate; they are re-checked here.
func materialize(payload fs.FS) (string, func(), error) {
	dir, err := os.MkdirTemp("", "konstapel-bundle-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	err = fs.WalkDir(payload, ".", func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		if !e.Type().IsRegular() || !fs.ValidPath(p) {
			return fmt.Errorf("%s: unsafe payload entry", p)
		}
		data, err := fs.ReadFile(payload, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o644)
	})
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return dir, cleanup, nil
}

// noExternalRefs rejects a JSON Schema that points anywhere outside itself.
func noExternalRefs(name string, v any) error {
	switch x := v.(type) {
	case map[string]any:
		if ref, ok := x["$ref"].(string); ok && !strings.HasPrefix(ref, "#") {
			return fmt.Errorf("%s: external schema reference %q is not allowed", name, ref)
		}
		for _, y := range x {
			if err := noExternalRefs(name, y); err != nil {
				return err
			}
		}
	case []any:
		for _, y := range x {
			if err := noExternalRefs(name, y); err != nil {
				return err
			}
		}
	}
	return nil
}

func isRemote(s string) bool {
	return strings.Contains(s, "://") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "mailto:")
}

// requiredLocal reports every href/source that must resolve inside the archive:
// imports, component-definition imports and control sources. Informational
// links (`links`, `rlinks`) may be remote URLs; they are never fetched.
func requiredLocal(v any, key string, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, y := range x {
			if s, ok := y.(string); ok && (k == "source" || (k == "href" && (key == "imports" || key == "import-component-definitions"))) {
				*out = append(*out, s)
				continue
			}
			requiredLocal(y, k, out)
		}
	case []any:
		for _, y := range x {
			requiredLocal(y, key, out)
		}
	}
}

// ValidateContent checks that the unpacked payload's declarative content is
// internally consistent and agrees with the descriptor. It reads only the
// payload: no network or registry access. It does not re-verify file digests
// (VerifyPayload does) and never applies or runs any packaged content.
//
// Checked: only the installed provider contract; each declared OSCAL entry
// point exists, is valid against the schema for its declared version, and
// states that version (authored component definitions use C2P-compatible
// 1.1.3, official NIST documents keep their own); every import and source
// resolves inside the archive while informational URLs stay unfetched; no JSON
// or YAML key repeats; the NIST catalog and Moderate profile are present and
// consistent; the component definitions' control, statement and rule
// references close and use only Moderate controls (through the existing
// prototype validation); the descriptor's logical checks equal the mapped
// rules; and every policy is a ValidatingPolicy named as the descriptor says.
func ValidateContent(d *Descriptor, payload fs.FS) error {
	if d.Compatibility.Provider != providerContract {
		return fmt.Errorf("compatibility.provider %q: only %q is installed", d.Compatibility.Provider, providerContract)
	}
	read := func(p string) ([]byte, error) {
		b, err := fs.ReadFile(payload, p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		return b, nil
	}
	exists := func(p string) bool { _, err := fs.Stat(payload, p); return err == nil }

	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	// Schemas: pinned, self-contained, and one per declared OSCAL version.
	checkedSchema := map[string]bool{}
	for _, o := range d.OSCAL {
		sp := schemaPath(o.Version)
		if !exists(sp) {
			fail("oscal %s declares version %s but %s is not in the archive", o.Path, o.Version, sp)
			continue
		}
		if checkedSchema[sp] {
			continue
		}
		checkedSchema[sp] = true
		raw, err := read(sp)
		if err != nil {
			fail("%v", err)
			continue
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			fail("%s: %v", sp, err)
		} else if err := noExternalRefs(sp, doc); err != nil {
			fail("%v", err)
		}
	}

	// Declared OSCAL entry points.
	componentDefs := []string{}
	for _, o := range d.OSCAL {
		raw, err := read(o.Path)
		if err != nil {
			fail("%v", err)
			continue
		}
		if err := noDuplicateJSONKeys(raw); err != nil {
			fail("%s: %v", o.Path, err)
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil || len(doc) != 1 {
			fail("%s: not a single-root OSCAL document", o.Path)
			continue
		}
		for root, body := range doc {
			got, _ := assessment.At(assessment.Map(body), "metadata", "oscal-version").(string)
			if got != o.Version {
				fail("%s: document says oscal-version %q but the descriptor declares %q", o.Path, got, o.Version)
			}
			if root == "component-definition" {
				componentDefs = append(componentDefs, o.Path)
				if o.Version != authoredOSCAL {
					fail("%s: authored component definitions must declare OSCAL %s, not %s", o.Path, authoredOSCAL, o.Version)
				}
			}
			var refs []string
			requiredLocal(body, root, &refs)
			for _, ref := range refs {
				switch {
				case strings.HasPrefix(ref, "#"):
				case isRemote(ref):
					fail("%s: required reference %q is external; imports and sources must resolve inside the archive", o.Path, ref)
				default:
					target := path.Clean(path.Join(path.Dir(o.Path), strings.SplitN(ref, "#", 2)[0]))
					if !exists(target) {
						fail("%s: reference %q does not resolve inside the archive", o.Path, ref)
					}
				}
			}
		}
	}
	if len(componentDefs) == 0 {
		fail("oscal must declare a component definition")
	}

	// Policies: parse as declarative data, never apply.
	rules := map[string]string{} // rule -> policy path
	for _, p := range d.Policies {
		raw, err := read(p.Path)
		if err != nil {
			fail("%v", err)
			continue
		}
		var obj map[string]any
		if err := yaml.Unmarshal(raw, &obj); err != nil { // yaml.v3 rejects duplicate keys
			fail("%s: %v", p.Path, err)
			continue
		}
		if obj["apiVersion"] != policyAPIVersion || obj["kind"] != policyKind {
			fail("%s: only %s %s is supported, found %v %v", p.Path, policyAPIVersion, policyKind, obj["apiVersion"], obj["kind"])
		}
		if name, _ := assessment.At(obj, "metadata", "name").(string); name != p.Name {
			fail("%s: descriptor names the policy %q but metadata.name is %q", p.Path, p.Name, name)
		}
		for _, c := range p.Checks {
			if c.CheckID != c.RuleID {
				fail("policy %q: checkID %q must equal ruleID %q (the C2P convention the provider matches on)", p.Name, c.CheckID, c.RuleID)
			}
			rules[c.RuleID] = p.Path
		}
		if p.ParameterSchema != "" {
			if _, err := compileParameterSchema(p, payload); err != nil {
				fail("%v", err)
			}
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	// Reference closure and Moderate membership through the existing validation.
	root, cleanup, err := materialize(payload)
	if err != nil {
		return err
	}
	defer cleanup()
	mapped := map[string]bool{}
	for _, rel := range componentDefs {
		_, ms, err := assessment.ValidateDefinition(root, rel, rules)
		if err != nil {
			fail("%v", err)
			continue
		}
		for _, m := range ms {
			mapped[m.Rule] = true
		}
	}
	for r := range rules {
		if !mapped[r] {
			fail("descriptor check %q is not mapped by any declared component definition", r)
		}
	}
	return errors.Join(errs...)
}

// denyLoader refuses every external load: parameter schemas must be
// self-contained.
type denyLoader struct{}

func (denyLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external schema load %q is not allowed", url)
}

func compileParameterSchema(p Policy, payload fs.FS) (*jsonschema.Schema, error) {
	raw, err := fs.ReadFile(payload, p.ParameterSchema)
	if err != nil {
		return nil, fmt.Errorf("policy %q parameter schema: %w", p.Name, err)
	}
	if err := noDuplicateJSONKeys(raw); err != nil {
		return nil, fmt.Errorf("%s: %v", p.ParameterSchema, err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %v", p.ParameterSchema, err)
	}
	if err := noExternalRefs(p.ParameterSchema, doc); err != nil {
		return nil, err
	}
	if m, _ := doc.(map[string]any); m == nil || m["type"] != "object" {
		return nil, fmt.Errorf("%s: a parameter schema must describe an object", p.ParameterSchema)
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(denyLoader{})
	const url = "bundle:///parameters.json"
	if err := c.AddResource(url, doc); err != nil {
		return nil, fmt.Errorf("%s: %w", p.ParameterSchema, err)
	}
	s, err := c.Compile(url)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.ParameterSchema, err)
	}
	return s, nil
}

// ValidateParameters validates a profile's parameters for one bundled policy
// against that policy's declared schema. A policy without a schema accepts no
// parameters at all, so unknown parameters never reach the engine.
func ValidateParameters(d *Descriptor, payload fs.FS, policy string, params map[string]any) error {
	for _, p := range d.Policies {
		if p.Name != policy {
			continue
		}
		if p.ParameterSchema == "" {
			if len(params) > 0 {
				return fmt.Errorf("policy %q declares no parameters", policy)
			}
			return nil
		}
		s, err := compileParameterSchema(p, payload)
		if err != nil {
			return err
		}
		if params == nil {
			params = map[string]any{}
		}
		if err := s.Validate(params); err != nil {
			return fmt.Errorf("policy %q parameters: %w", policy, err)
		}
		return nil
	}
	return fmt.Errorf("bundle %q has no policy %q", d.Name, policy)
}
