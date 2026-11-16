package coverage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// SupportedOSCAL are the OSCAL versions the reader decodes: C2P-compatible
// authored component definitions (1.1.3) and the official NIST documents
// (1.2.3). A document is read only when the caller also supplies the trusted
// schema for its version (Options.Schemas).
var SupportedOSCAL = []string{"1.1.3", "1.2.3"}

// OSCAL model names (a document's single root key).
const (
	ModelCatalog             = "catalog"
	ModelProfile             = "profile"
	ModelComponentDefinition = "component-definition"
)

// Options configure reading a content handle.
type Options struct {
	// Profile is the path of the baseline profile entry point. Empty selects
	// the content's single declared profile entry point; none or several is
	// an unresolved inventory, never a guess.
	Profile string
	// Schemas maps each OSCAL version to the trusted schema bytes the
	// controller ships (its own content/schemas/oscal-<version>.json, never
	// the bundle's copy). A document of a version without a schema here, or
	// outside SupportedOSCAL, is unsupported.
	Schemas map[string][]byte
}

// DocumentRef identifies one OSCAL document read from the content.
type DocumentRef struct {
	Path         string `json:"path"`
	Model        string `json:"model"`
	Digest       string `json:"digest"`
	OSCALVersion string `json:"oscalVersion"`
	Title        string `json:"title,omitempty"`
	Version      string `json:"version,omitempty"`
}

type document struct {
	Ref  DocumentRef
	body json.RawMessage
}

// loader reads and validates OSCAL documents from one content handle,
// caching each by path for one read.
type loader struct {
	c        Content
	o        Options
	declared map[string]string // entry-point path -> declared version
	schemas  map[string]*jsonschema.Schema
	docs     map[string]*document
	failed   map[string]*Limitation
	raws     map[string]rawFile
}

type rawFile struct {
	data   []byte
	digest string
	err    error
}

// raw reads a file of the handle once per loader.
func (l *loader) raw(p string) ([]byte, string, error) {
	f, ok := l.raws[p]
	if !ok {
		f.data, f.digest, f.err = l.c.read(p)
		l.raws[p] = f
	}
	return f.data, f.digest, f.err
}

func newLoader(c Content, o Options) *loader {
	l := &loader{c: c, o: o, declared: map[string]string{}, schemas: map[string]*jsonschema.Schema{},
		docs: map[string]*document{}, failed: map[string]*Limitation{}, raws: map[string]rawFile{}}
	for _, d := range c.OSCAL {
		l.declared[d.Path] = d.Version
	}
	return l
}

// load reads p and checks, in order: closure and digest, unique JSON keys,
// a single root of an expected model, a supported OSCAL version that agrees
// with the declared one, and validity against the trusted schema of that
// version. Any failure is a blocking limitation naming p.
func (l *loader) load(p string, models ...string) (*document, *Limitation) {
	if d, ok := l.docs[p]; ok {
		if !slices.Contains(models, d.Ref.Model) {
			return nil, blocking(CodeDocumentInvalid, p, "", "is a %s, not a %s", d.Ref.Model, strings.Join(models, " or "))
		}
		return d, nil
	}
	if f, ok := l.failed[p]; ok {
		return nil, f
	}
	d, lim := l.read(p)
	if lim != nil {
		l.failed[p] = lim
		return nil, lim
	}
	l.docs[p] = d
	if !slices.Contains(models, d.Ref.Model) {
		return nil, blocking(CodeDocumentInvalid, p, "", "is a %s, not a %s", d.Ref.Model, strings.Join(models, " or "))
	}
	return d, nil
}

func (l *loader) read(p string) (*document, *Limitation) {
	raw, dig, err := l.raw(p)
	if err != nil {
		return nil, blocking(CodeDocumentUnavailable, p, "", "%v", err)
	}
	if err := bundle.NoDuplicateJSONKeys(raw); err != nil {
		return nil, blocking(CodeDocumentInvalid, p, "", "%v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, blocking(CodeDocumentInvalid, p, "", "not a JSON object: %v", err)
	}
	delete(top, "$schema")
	if len(top) != 1 {
		return nil, blocking(CodeDocumentInvalid, p, "", "not a single-root OSCAL document")
	}
	d := &document{Ref: DocumentRef{Path: p, Digest: dig}}
	for k, v := range top {
		d.Ref.Model, d.body = k, v
	}
	var head struct {
		Metadata struct {
			Title        string `json:"title"`
			Version      string `json:"version"`
			OSCALVersion string `json:"oscal-version"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(d.body, &head); err != nil {
		return nil, blocking(CodeDocumentInvalid, p, "", "metadata: %v", err)
	}
	m := head.Metadata
	d.Ref.Title, d.Ref.Version, d.Ref.OSCALVersion = m.Title, m.Version, m.OSCALVersion
	if want, ok := l.declared[p]; ok && want != m.OSCALVersion {
		return nil, blocking(CodeSchemaVersionMismatch, p, "", "document states OSCAL %q but the content declares %q", m.OSCALVersion, want)
	}
	s, lim := l.schema(p, m.OSCALVersion)
	if lim != nil {
		return nil, lim
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, blocking(CodeDocumentInvalid, p, "", "%v", err)
	}
	if err := s.Validate(inst); err != nil {
		return nil, blocking(CodeDocumentInvalid, p, "", "not valid OSCAL %s: %s", m.OSCALVersion, firstLine(err.Error()))
	}
	return d, nil
}

// schema compiles the trusted schema of version once per read.
func (l *loader) schema(p, version string) (*jsonschema.Schema, *Limitation) {
	if s, ok := l.schemas[version]; ok {
		return s, nil
	}
	raw, ok := l.o.Schemas[version]
	if !ok || !slices.Contains(SupportedOSCAL, version) {
		return nil, blocking(CodeSchemaVersionUnsupported, p, "", "OSCAL %q is not supported (supported: %s, with a trusted schema)", version, strings.Join(SupportedOSCAL, ", "))
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, blocking(CodeSchemaVersionUnsupported, p, "", "trusted OSCAL %s schema: %v", version, err)
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(denyLoader{})
	url := "konstapel:///oscal-" + version + ".json"
	if err := c.AddResource(url, doc); err != nil {
		return nil, blocking(CodeSchemaVersionUnsupported, p, "", "trusted OSCAL %s schema: %v", version, err)
	}
	s, err := c.Compile(url)
	if err != nil {
		return nil, blocking(CodeSchemaVersionUnsupported, p, "", "trusted OSCAL %s schema: %v", version, err)
	}
	l.schemas[version] = s
	return s, nil
}

type denyLoader struct{}

func (denyLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("external schema load %q is not allowed", url)
}

// resolveHref resolves a required reference of the document at from. Only
// a relative path that stays inside the payload and names an inventoried
// file resolves; remote references are never fetched.
func (l *loader) resolveHref(from, href string) (string, *Limitation) {
	target, _, _ := strings.Cut(href, "#")
	switch {
	case isRemote(href):
		return "", blocking(CodeImportExternal, from, href, "reference %q is external; imports resolve only inside the content", href)
	case target == "" || path.IsAbs(target):
		return "", blocking(CodeImportUnresolved, from, href, "reference %q is not a relative path", href)
	}
	p := path.Join(path.Dir(from), target)
	if p == ".." || strings.HasPrefix(p, "../") {
		return "", blocking(CodeImportOutsideContent, from, href, "reference %q leaves the content", href)
	}
	if !l.c.inClosure(p) {
		return "", blocking(CodeImportUnresolved, from, href, "reference %q does not resolve to an inventoried file", href)
	}
	return p, nil
}

func isRemote(s string) bool {
	return strings.Contains(s, "://") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "mailto:") || strings.HasPrefix(s, "urn:")
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}
