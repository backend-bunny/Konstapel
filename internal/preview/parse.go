package preview

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// Supported kinds. The preview accepts only the cluster-scoped compliance API
// at the served version; anything else is an error, never a skipped document.
const (
	KindProfile = "ComplianceProfile"
	KindBinding = "ComplianceBinding"
)

// Identity is the group/kind/name identity of a cluster-scoped object. The
// group is implied by the supported API and kept for explicitness.
type Identity struct {
	Group string `json:"group"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
}

func (i Identity) String() string { return i.Kind + "/" + i.Name }

func compareIdentity(a, b Identity) int {
	return strings.Compare(a.Kind+"\x00"+a.Name, b.Kind+"\x00"+b.Name)
}

// Object is one validated proposed (or previous) object. Only the spec is
// authority: UID, generation, resourceVersion, managedFields, status and the
// admission-maintained enforcementEpoch are never carried over.
type Object struct {
	Identity Identity
	Source   string
	Document int
	Line     int
	// Profile or Binding is set according to Identity.Kind. It holds only the
	// name and the defaulted, validated spec.
	Profile *v1alpha1.ComplianceProfile
	Binding *v1alpha1.ComplianceBinding
	// Ignored lists exported server-owned fields that were present and
	// discarded, sorted, for provenance.
	Ignored []string
	// Fingerprint identifies the normalized configuration. It is not an
	// acceptance token and not an enforcement revision.
	Fingerprint string
}

// Set is the validated objects of one input role, sorted by identity.
type Set struct {
	Objects []*Object
}

// Get returns the object with the identity, or nil.
func (s *Set) Get(id Identity) *Object {
	if s == nil {
		return nil
	}
	i, ok := slices.BinarySearchFunc(s.Objects, id, func(o *Object, id Identity) int { return compareIdentity(o.Identity, id) })
	if !ok {
		return nil
	}
	return s.Objects[i]
}

// Parse decodes one stream of YAML or JSON documents (JSON is a YAML subset;
// separate JSON documents with `---`). It never panics on adversarial input.
// Empty and null documents are skipped, so an explicitly empty stream yields no
// objects and no error. Duplicate identities inside the stream are errors.
func Parse(source string, data []byte, lim Limits) ([]*Object, InputErrors) {
	lim = lim.withDefaults()
	p := &parser{source: source, lim: lim}
	p.run(data)
	return p.objects, p.errs
}

type parser struct {
	source  string
	lim     Limits
	objects []*Object
	errs    InputErrors
	stop    bool
	seen    map[Identity]*Object
}

func (p *parser) fail(e InputError) {
	if p.stop {
		return
	}
	if len(p.errs) >= p.lim.MaxErrors {
		p.errs = append(p.errs, InputError{Code: CodeTooManyErrors, Source: p.source, Message: fmt.Sprintf("more than %d problems; stopped", p.lim.MaxErrors)})
		p.stop = true
		return
	}
	e.Source = p.source
	p.errs = append(p.errs, e)
}

func (p *parser) run(data []byte) {
	p.seen = map[Identity]*Object{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for doc := 1; !p.stop; doc++ {
		var n yaml.Node
		err := dec.Decode(&n)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A syntax error leaves the stream unsynchronized; stop here.
			p.fail(InputError{Code: CodeSyntax, Document: doc, Line: errLine(err), Message: cleanYAMLError(err)})
			return
		}
		if n.Kind != yaml.DocumentNode || len(n.Content) == 0 {
			continue
		}
		root := n.Content[0]
		if root.Kind == yaml.ScalarNode && root.ShortTag() == "!!null" {
			continue
		}
		p.document(doc, root)
	}
}

var yamlLine = regexp.MustCompile(`line (\d+)`)

func errLine(err error) int {
	if m := yamlLine.FindStringSubmatch(err.Error()); m != nil {
		var n int
		fmt.Sscanf(m[1], "%d", &n)
		return n
	}
	return 0
}

func cleanYAMLError(err error) string {
	s := strings.TrimPrefix(err.Error(), "yaml: ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// convError is a structural problem with a node, positioned at the node.
type convError struct {
	code Code
	line int
	msg  string
}

// toValue converts a node into plain JSON-compatible values. It rejects
// aliases and merge keys (no amplification), non-string keys, non-standard
// tags, duplicate keys at every level, and excessive nesting.
func toValue(n *yaml.Node, depth, max int) (any, *convError) {
	if depth > max {
		return nil, &convError{CodeTooDeep, n.Line, fmt.Sprintf("nesting deeper than %d", max)}
	}
	switch n.Kind {
	case yaml.AliasNode:
		return nil, &convError{CodeAliasNotAllowed, n.Line, "YAML aliases and anchors are not allowed in rendered input"}
	case yaml.MappingNode:
		out := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind == yaml.AliasNode {
				return nil, &convError{CodeAliasNotAllowed, k.Line, "YAML aliases and anchors are not allowed in rendered input"}
			}
			if k.Kind != yaml.ScalarNode || k.ShortTag() != "!!str" {
				if k.Kind == yaml.ScalarNode && k.ShortTag() == "!!merge" {
					return nil, &convError{CodeAliasNotAllowed, k.Line, "YAML merge keys are not allowed in rendered input"}
				}
				return nil, &convError{CodeNonStringKey, k.Line, "mapping keys must be strings"}
			}
			if amb := ambiguousPlainScalar(k); amb != nil {
				return nil, amb
			}
			if _, dup := out[k.Value]; dup {
				return nil, &convError{CodeDuplicateKey, k.Line, fmt.Sprintf("duplicate key %q", k.Value)}
			}
			val, err := toValue(v, depth+1, max)
			if err != nil {
				return nil, err
			}
			out[k.Value] = val
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			val, err := toValue(c, depth+1, max)
			if err != nil {
				return nil, err
			}
			out = append(out, val)
		}
		return out, nil
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!null":
			return nil, nil
		case "!!bool":
			var b bool
			if err := n.Decode(&b); err != nil {
				return nil, &convError{CodeInvalidNumber, n.Line, "invalid boolean"}
			}
			return b, nil
		case "!!int":
			var i int64
			if err := n.Decode(&i); err != nil {
				return nil, &convError{CodeInvalidNumber, n.Line, fmt.Sprintf("integer %q is out of range", clip(n.Value))}
			}
			return i, nil
		case "!!float":
			var f float64
			if err := n.Decode(&f); err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
				return nil, &convError{CodeInvalidNumber, n.Line, fmt.Sprintf("number %q is not a finite JSON number", clip(n.Value))}
			}
			return f, nil
		case "!!str", "!!timestamp":
			if amb := ambiguousPlainScalar(n); amb != nil {
				return nil, amb
			}
			// An unquoted date is still text in Kubernetes JSON.
			return n.Value, nil
		default:
			return nil, &convError{CodeUnsupportedTag, n.Line, fmt.Sprintf("tag %q is not supported", clip(n.Tag))}
		}
	}
	return nil, &convError{CodeNotAnObject, n.Line, "unsupported YAML node"}
}

// yaml11Bool lists the words YAML 1.1 reads as booleans. kubectl, Argo CD and
// Flux decode with a YAML 1.1 library (sigs.k8s.io/yaml), so an unquoted `y`,
// `yes` or `on` is the boolean there and a string for this parser. Rather than
// guess which reading the applier will use, require quotes.
var yaml11Bool = map[string]bool{}

func init() {
	for _, w := range []string{"y", "n", "yes", "no", "on", "off"} {
		yaml11Bool[w], yaml11Bool[strings.ToUpper(w)] = true, true
		yaml11Bool[strings.ToUpper(w[:1])+w[1:]] = true
	}
}

// yaml11Number matches plain scalars that YAML 1.1 reads as numbers but a
// YAML 1.2 resolver keeps as text (digit separators, sexagesimal).
var yaml11Number = regexp.MustCompile(`^[-+]?([0-9][0-9_]*_[0-9_]*|[0-9]+(:[0-5]?[0-9])+)(\.[0-9_]*)?$`)

func ambiguousPlainScalar(n *yaml.Node) *convError {
	if n.Kind != yaml.ScalarNode || n.Style != 0 || n.ShortTag() != "!!str" {
		return nil
	}
	if yaml11Bool[n.Value] || yaml11Number.MatchString(n.Value) {
		return &convError{CodeAmbiguousScalar, n.Line, fmt.Sprintf("unquoted %q is read differently by YAML 1.1 and 1.2 parsers; quote it", clip(n.Value))}
	}
	return nil
}

func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

var allowedTop = map[string]bool{"apiVersion": true, "kind": true, "metadata": true, "spec": true, "status": true}

func (p *parser) document(doc int, root *yaml.Node) {
	at := func(code Code, line int, id, field, format string, args ...any) {
		p.fail(InputError{Code: code, Document: doc, Line: line, Identity: id, Field: field, Message: fmt.Sprintf(format, args...)})
	}
	if root.Kind != yaml.MappingNode {
		at(CodeNotAnObject, root.Line, "", "", "a document must be a single Kubernetes object, not a list or scalar")
		return
	}
	v, cerr := toValue(root, 1, p.lim.MaxDepth)
	if cerr != nil {
		at(cerr.code, cerr.line, "", "", "%s", cerr.msg)
		return
	}
	m := v.(map[string]any)
	line := root.Line

	apiVersion, _ := m["apiVersion"].(string)
	kind, _ := m["kind"].(string)
	if apiVersion == "" || kind == "" {
		at(CodeMissingType, line, "", "", "apiVersion and kind are required")
		return
	}
	group, version := splitAPIVersion(apiVersion)
	if group != v1alpha1.GroupVersion.Group || (kind != KindProfile && kind != KindBinding) {
		at(CodeUnsupportedKind, line, "", "", "%s %s is not supported; only %s and %s of %s", apiVersion, clip(kind), KindProfile, KindBinding, v1alpha1.GroupVersion.Group)
		return
	}
	if version != v1alpha1.GroupVersion.Version {
		at(CodeUnsupportedVersion, line, "", "", "apiVersion %s is not supported; use %s", clip(apiVersion), v1alpha1.GroupVersion.String())
		return
	}

	meta, ok := m["metadata"].(map[string]any)
	if !ok {
		at(CodeInvalidMetadata, line, kind, "metadata", "metadata with a name is required")
		return
	}
	if _, has := meta["generateName"]; has {
		at(CodeInvalidMetadata, line, kind, "metadata.generateName", "generateName is not supported; objects must be explicitly named")
		return
	}
	if ns, has := meta["namespace"]; has && ns != nil && ns != "" {
		at(CodeInvalidMetadata, line, kind, "metadata.namespace", "%s is cluster-scoped; metadata.namespace must be empty", kind)
		return
	}
	name, _ := meta["name"].(string)
	if name == "" {
		at(CodeInvalidName, line, kind, "metadata.name", "an explicit metadata.name is required")
		return
	}
	id := kind + "/" + clip(name)
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		at(CodeInvalidName, line, id, "metadata.name", "%s", strings.Join(errs, "; "))
		return
	}
	identity := Identity{Group: group, Kind: kind, Name: name}
	id = identity.String()

	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !allowedTop[k] {
			at(CodeUnknownField, line, id, k, "unknown field %q", clip(k))
			return
		}
	}
	var ignored []string
	for k := range meta {
		if k != "name" && k != "namespace" {
			ignored = append(ignored, "metadata."+k)
		}
	}
	if _, has := m["status"]; has {
		ignored = append(ignored, "status")
	}

	spec, ok := m["spec"].(map[string]any)
	if !ok {
		at(CodeInvalidSpec, line, id, "spec", "spec is required and must be an object")
		return
	}
	if kind == KindBinding {
		if _, has := spec["enforcementEpoch"]; has {
			// Maintained by admission from profileRef, namespaceSelector and mode.
			delete(spec, "enforcementEpoch")
			ignored = append(ignored, "spec.enforcementEpoch")
		}
	}
	slices.Sort(ignored)

	if first := explicitEmpty(kind, spec); first != "" {
		at(CodeInvalidSpec, line, id, first, "an explicitly empty value is invalid; omit the field to use its default")
		return
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		at(CodeInvalidSpec, line, id, "spec", "spec cannot be encoded: %v", err)
		return
	}
	obj := &Object{Identity: identity, Source: p.source, Document: doc, Line: line, Ignored: ignored}
	var problems []fieldProblem
	switch kind {
	case KindProfile:
		pr := &v1alpha1.ComplianceProfile{}
		pr.Name = name
		if err := strictDecode(raw, &pr.Spec); err != nil {
			code, field, msg := decodeProblem(err)
			at(code, line, id, field, "%s", msg)
			return
		}
		DefaultProfile(pr)
		problems = ValidateProfileSpec(&pr.Spec)
		obj.Profile = pr
	case KindBinding:
		b := &v1alpha1.ComplianceBinding{}
		b.Name = name
		if err := strictDecode(raw, &b.Spec); err != nil {
			code, field, msg := decodeProblem(err)
			at(code, line, id, field, "%s", msg)
			return
		}
		DefaultBinding(b)
		problems = ValidateBindingSpec(&b.Spec)
		obj.Binding = b
	}
	if len(problems) > 0 {
		for _, fp := range problems {
			at(CodeInvalidSpec, line, id, fp.Field, "%s", fp.Message)
		}
		return
	}
	if prev := p.seen[identity]; prev != nil {
		at(CodeDuplicateIdentity, line, id, "", "duplicate object; first defined at document %d line %d", prev.Document, prev.Line)
		return
	}
	obj.Fingerprint = Fingerprint(obj.Profile, obj.Binding)
	p.seen[identity] = obj
	p.objects = append(p.objects, obj)
}

func splitAPIVersion(v string) (group, version string) {
	if g, ver, ok := strings.Cut(v, "/"); ok {
		return g, ver
	}
	return "", v
}

func strictDecode(raw []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after spec")
	}
	return nil
}

var unknownField = regexp.MustCompile(`unknown field "([^"]*)"`)

func decodeProblem(err error) (Code, string, string) {
	if m := unknownField.FindStringSubmatch(err.Error()); m != nil {
		return CodeUnknownField, "spec." + clip(m[1]), fmt.Sprintf("unknown field %q", clip(m[1]))
	}
	var ute *json.UnmarshalTypeError
	if errors.As(err, &ute) {
		return CodeInvalidSpec, "spec." + ute.Field, fmt.Sprintf("must be %s, not %s", ute.Type, ute.Value)
	}
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return CodeInvalidSpec, "spec", msg
}

// explicitEmpty finds values the API server would reject as present but empty
// where the typed decode could not tell them from an omitted field (and would
// silently default them). Returns the field path or "".
func explicitEmpty(kind string, spec map[string]any) string {
	switch kind {
	case KindBinding:
		if a, ok := spec["assessment"].(map[string]any); ok {
			for _, k := range []string{"interval", "maxEvidenceAge", "collectionTimeout", "retention"} {
				if s, ok := a[k].(string); ok && s == "" {
					return "spec.assessment." + k
				}
			}
		}
	case KindProfile:
		pols, _ := spec["policies"].([]any)
		for i, e := range pols {
			pm, _ := e.(map[string]any)
			ex, _ := pm["exceptions"].(map[string]any)
			if s, ok := ex["eligibility"].(string); ok && s == "" {
				return fmt.Sprintf("spec.policies[%d].exceptions.eligibility", i)
			}
		}
	}
	return ""
}
