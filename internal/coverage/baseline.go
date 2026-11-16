package coverage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Semantics names the supported subset of OSCAL profile resolution. It
// changes whenever the supported semantics change, so a report states the
// rules its inventory was resolved under.
//
// Supported, for profile documents of a SupportedOSCAL version:
//
//   - imports of a catalog or of another profile inside the content's
//     closure: a relative href, or "#uuid" naming a back-matter resource
//     whose single JSON rlink resolves to an inventoried file (remote links
//     are never fetched);
//   - include-all, or include-controls by with-ids (with-child-controls yes
//     or no); exclude-controls by with-ids;
//   - merge as-is, flat or absent, with combine use-first or keep (the
//     inventory is a set of catalog control IDs, so structuring does not
//     change membership);
//   - every import of the closure resolving to the same catalog.
//
// Unsupported, making the inventory unresolved: selection by matching
// patterns, custom merge, combine merge, any modify (alters or
// set-parameters), imports of other models, and import cycles or chains
// deeper than maxImportDepth.
const Semantics = "konstapel.io/oscal-profile-selection/v1"

const maxImportDepth = 8

// ErrUnresolved: the baseline inventory could not be resolved. Errors from
// ReadBaseline match it with errors.Is and are *UnresolvedError.
var ErrUnresolved = errors.New("baseline inventory unresolved")

// UnresolvedError explains an unresolved inventory. No control list
// accompanies it: a partial or guessed inventory is never returned.
type UnresolvedError struct {
	// Documents are the OSCAL documents read before resolution stopped.
	Documents []DocumentRef
	// Limitations include at least one blocking limitation.
	Limitations []Limitation
}

func (e *UnresolvedError) Error() string {
	var first *Limitation
	for i := range e.Limitations {
		if e.Limitations[i].Blocking {
			first = &e.Limitations[i]
			break
		}
	}
	if first == nil {
		return ErrUnresolved.Error()
	}
	msg := fmt.Sprintf("%v: %s: %s", ErrUnresolved, first.Code, first.Message)
	if first.Document != "" {
		msg = fmt.Sprintf("%v: %s: %s: %s", ErrUnresolved, first.Code, first.Document, first.Message)
	}
	if n := len(e.Limitations) - 1; n > 0 {
		msg += fmt.Sprintf(" (and %d more)", n)
	}
	return msg
}

// Is makes every UnresolvedError an ErrUnresolved.
func (e *UnresolvedError) Is(target error) bool { return target == ErrUnresolved }

// Baseline is a resolved control inventory: every control the profile
// selects, independent of mappings, policy selection and findings.
type Baseline struct {
	// Profile is the baseline profile entry point.
	Profile DocumentRef
	// Catalog is the one catalog the profile closure resolves to. Control
	// and statement identity is qualified by its digest.
	Catalog DocumentRef
	// Imports are the intermediate profiles of the closure, by path.
	Imports []DocumentRef
	// Controls are the selected controls and enhancements, ordered by
	// identifier (compareIDs).
	Controls []Control
	// Limitations are non-blocking (deduplicated selection edges).
	Limitations []Limitation

	index map[string]int
	stmts map[string]map[string]bool
	cat   *catalogIndex
}

// Control is one selected catalog control or enhancement.
type Control struct {
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
	Title string `json:"title"`
	Class string `json:"class,omitempty"`
	// Parent is the enclosing control of an enhancement; empty for a
	// top-level control. The parent need not be selected.
	Parent string `json:"parent,omitempty"`
	// Groups are the enclosing catalog groups, outermost first.
	Groups []Group `json:"groups,omitempty"`
	// Status is the control's status property (for example "withdrawn").
	Status string `json:"status,omitempty"`
	// Statements are the IDs of the control's statement part and its nested
	// item parts. Membership is per control, never a global bag of IDs.
	Statements []string `json:"statements"`
	// Parameters are the control's OSCAL parameters as the profile resolves
	// them. They are never policy-engine parameters.
	Parameters []Parameter `json:"parameters,omitempty"`
}

// Group is an enclosing catalog group.
type Group struct {
	ID    string `json:"id,omitempty"`
	Title string `json:"title"`
}

// Parameter is a control's OSCAL parameter.
type Parameter struct {
	ID     string   `json:"id"`
	Label  string   `json:"label,omitempty"`
	Values []string `json:"values,omitempty"`
}

// Control returns a selected control by ID.
func (b *Baseline) Control(id string) (Control, bool) {
	i, ok := b.index[id]
	if !ok {
		return Control{}, false
	}
	return b.Controls[i], true
}

// HasStatement reports whether statement is a statement part of the
// selected control.
func (b *Baseline) HasStatement(control, statement string) bool {
	return b.stmts[control][statement]
}

// HasParameter reports whether param is an OSCAL parameter of the selected
// control.
func (b *Baseline) HasParameter(control, param string) bool {
	c, ok := b.Control(control)
	return ok && slices.ContainsFunc(c.Parameters, func(p Parameter) bool { return p.ID == param })
}

// InCatalog reports whether id is a control of the baseline's catalog,
// selected or not.
func (b *Baseline) InCatalog(id string) bool {
	_, ok := b.cat.controls[id]
	return ok
}

// Qualified is the catalog-qualified identity of a control or statement ID.
func (b *Baseline) Qualified(id string) string { return b.Catalog.Digest + "#" + id }

// ReadBaseline resolves the content's baseline profile into its control
// inventory. Any blocking limitation returns an *UnresolvedError and no
// inventory; it never falls back to every catalog control or to the mapped
// subset.
func ReadBaseline(c Content, o Options) (*Baseline, error) {
	return readBaseline(newLoader(c, o))
}

func readBaseline(l *loader) (*Baseline, error) {
	r := &resolver{l: l, memo: map[string]*selection{}, catalogs: map[string]*catalogIndex{}}
	b := r.baseline()
	if b == nil || anyBlocking(r.lims) {
		return nil, &UnresolvedError{Documents: r.documents(), Limitations: sortLimitations(r.lims)}
	}
	b.Limitations = sortLimitations(r.lims)
	return b, nil
}

type resolver struct {
	l        *loader
	lims     []Limitation
	memo     map[string]*selection
	catalogs map[string]*catalogIndex
}

func (r *resolver) add(l *Limitation) {
	if l != nil {
		r.lims = append(r.lims, *l)
	}
}

// documents are the documents read so far, by path.
func (r *resolver) documents() []DocumentRef {
	var out []DocumentRef
	for _, p := range slices.Sorted(maps.Keys(r.l.docs)) {
		out = append(out, r.l.docs[p].Ref)
	}
	return out
}

// selection is a resolved profile: its catalog and selected control IDs.
type selection struct {
	cat *catalogIndex
	ids []string
	set map[string]bool
}

func (r *resolver) baseline() *Baseline {
	p := r.entryPoint()
	if p == "" {
		return nil
	}
	sel := r.profile(p, nil)
	if sel == nil || anyBlocking(r.lims) {
		return nil
	}
	if len(sel.ids) == 0 {
		r.add(blocking(CodeEmptySelection, p, "", "the profile selects no controls"))
		return nil
	}
	b := &Baseline{Profile: r.l.docs[p].Ref, Catalog: sel.cat.doc.Ref, index: map[string]int{}, stmts: map[string]map[string]bool{}, cat: sel.cat}
	for q, d := range r.l.docs {
		if q != p && d.Ref.Model == ModelProfile {
			b.Imports = append(b.Imports, d.Ref)
		}
	}
	slices.SortFunc(b.Imports, func(x, y DocumentRef) int { return strings.Compare(x.Path, y.Path) })
	ids := slices.Clone(sel.ids)
	slices.SortFunc(ids, compareIDs)
	for i, id := range ids {
		e := sel.cat.controls[id]
		b.Controls = append(b.Controls, e.c)
		b.index[id] = i
		b.stmts[id] = e.stmts
	}
	return b
}

// entryPoint is Options.Profile, or the single declared profile.
func (r *resolver) entryPoint() string {
	if p := r.l.o.Profile; p != "" {
		if _, ok := r.l.declared[p]; !ok {
			r.add(blocking(CodeProfileNotDeclared, p, "", "the content does not declare %s as an OSCAL entry point", p))
			return ""
		}
		return p
	}
	var profiles []string
	for _, d := range r.l.c.OSCAL {
		model, lim := r.l.model(d.Path)
		if lim != nil {
			r.add(lim)
			return ""
		}
		if model == ModelProfile {
			profiles = append(profiles, d.Path)
		}
	}
	switch len(profiles) {
	case 0:
		r.add(blocking(CodeProfileNotDeclared, "", "", "the content declares no profile entry point"))
		return ""
	case 1:
		return profiles[0]
	}
	r.add(blocking(CodeProfileAmbiguous, "", "", "the content declares %d profile entry points (%s); name one", len(profiles), strings.Join(profiles, ", ")))
	return ""
}

// OSCAL profile subset (both supported versions share it).
type profileBody struct {
	Imports []struct {
		Href            string          `json:"href"`
		IncludeAll      *struct{}       `json:"include-all"`
		IncludeControls []selectControl `json:"include-controls"`
		ExcludeControls []selectControl `json:"exclude-controls"`
	} `json:"imports"`
	Merge *struct {
		AsIs    *bool           `json:"as-is"`
		Flat    *struct{}       `json:"flat"`
		Custom  json.RawMessage `json:"custom"`
		Combine *struct {
			Method string `json:"method"`
		} `json:"combine"`
	} `json:"merge"`
	Modify *struct {
		SetParameters []json.RawMessage `json:"set-parameters"`
		Alters        []json.RawMessage `json:"alters"`
	} `json:"modify"`
	BackMatter struct {
		Resources []struct {
			UUID   string `json:"uuid"`
			Rlinks []struct {
				Href      string `json:"href"`
				MediaType string `json:"media-type"`
			} `json:"rlinks"`
		} `json:"resources"`
	} `json:"back-matter"`
}

type selectControl struct {
	WithChildControls string            `json:"with-child-controls"`
	WithIDs           []string          `json:"with-ids"`
	Matching          []json.RawMessage `json:"matching"`
}

// profile resolves the profile at p; stack holds the importing chain.
func (r *resolver) profile(p string, stack []string) *selection {
	if i := slices.Index(stack, p); i >= 0 {
		r.add(blocking(CodeImportCycle, p, p, "import cycle: %s -> %s", strings.Join(stack[i:], " -> "), p))
		return nil
	}
	if len(stack) > maxImportDepth {
		r.add(blocking(CodeImportDepth, p, p, "import chain deeper than %d profiles", maxImportDepth))
		return nil
	}
	if s, ok := r.memo[p]; ok {
		return s
	}
	doc, lim := r.l.load(p, ModelProfile)
	if lim != nil {
		r.add(lim)
		return nil
	}
	var prof profileBody
	if err := json.Unmarshal(doc.body, &prof); err != nil {
		r.add(blocking(CodeDocumentInvalid, p, "", "profile: %v", err))
		return nil
	}
	ok := true
	unsupported := func(format string, a ...any) {
		r.add(blocking(CodeSemanticsUnsupported, p, "", format, a...))
		ok = false
	}
	if m := prof.Modify; m != nil && (len(m.SetParameters) > 0 || len(m.Alters) > 0) {
		unsupported("modify (alters or set-parameters) is not supported")
	}
	if m := prof.Merge; m != nil {
		if len(m.Custom) > 0 {
			unsupported("merge custom is not supported")
		}
		if m.Combine != nil && m.Combine.Method != "" && m.Combine.Method != "use-first" && m.Combine.Method != "keep" {
			unsupported("merge combine %q is not supported", m.Combine.Method)
		}
	}
	if len(prof.Imports) == 0 {
		unsupported("the profile imports nothing")
	}
	out := &selection{set: map[string]bool{}}
	for _, imp := range prof.Imports {
		target := r.importTarget(p, imp.Href, &prof)
		if target == "" {
			ok = false
			continue
		}
		src, lim := r.source(target, append(slices.Clone(stack), p))
		if lim != nil {
			r.add(lim)
		}
		if src == nil {
			ok = false
			continue
		}
		if out.cat == nil {
			out.cat = src.cat
		} else if out.cat.doc.Ref.Digest != src.cat.doc.Ref.Digest {
			r.add(blocking(CodeMultipleCatalogs, p, imp.Href, "imports resolve to catalogs %s and %s; one catalog per baseline is supported", out.cat.doc.Ref.Path, src.cat.doc.Ref.Path))
			ok = false
			continue
		}
		picked, good := r.apply(p, imp.Href, src, imp.IncludeAll != nil, imp.IncludeControls, imp.ExcludeControls)
		ok = ok && good
		for _, id := range picked {
			if out.set[id] {
				r.add(notice(CodeDuplicateSelection, p, id, "%s is selected by more than one import; counted once", id))
				continue
			}
			out.set[id] = true
		}
	}
	if !ok || out.cat == nil {
		return nil
	}
	// Catalog document order: deterministic and independent of import order.
	for _, id := range out.cat.order {
		if out.set[id] {
			out.ids = append(out.ids, id)
		}
	}
	r.memo[p] = out
	return out
}

// importTarget resolves an import href of the profile at p to a content path.
func (r *resolver) importTarget(p, href string, prof *profileBody) string {
	uuid, ok := strings.CutPrefix(href, "#")
	if !ok {
		target, lim := r.l.resolveHref(p, href)
		r.add(lim)
		return target
	}
	for _, res := range prof.BackMatter.Resources {
		if res.UUID != uuid {
			continue
		}
		found := map[string]bool{}
		for _, l := range res.Rlinks {
			if !strings.Contains(l.MediaType, "json") && (l.MediaType != "" || !strings.HasSuffix(l.Href, ".json")) {
				continue
			}
			if t, lim := r.l.resolveHref(p, l.Href); lim == nil {
				found[t] = true
			}
		}
		switch len(found) {
		case 0:
			r.add(blocking(CodeImportUnresolved, p, href, "no JSON link of resource %s resolves to an inventoried file; remote links are never fetched", uuid))
			return ""
		case 1:
			for t := range found {
				return t
			}
		}
		r.add(blocking(CodeImportAmbiguous, p, href, "resource %s links %d different JSON documents (%s)", uuid, len(found), strings.Join(slices.Sorted(maps.Keys(found)), ", ")))
		return ""
	}
	r.add(blocking(CodeImportUnresolved, p, href, "no back-matter resource %s", uuid))
	return ""
}

// source resolves an import target: a catalog (every control available) or
// a profile (its selection available).
func (r *resolver) source(target string, stack []string) (*selection, *Limitation) {
	doc, lim := r.l.load(target, ModelCatalog, ModelProfile)
	if lim != nil {
		return nil, lim
	}
	if doc.Ref.Model == ModelProfile {
		return r.profile(target, stack), nil
	}
	cat, lim := r.catalog(doc)
	if lim != nil {
		return nil, lim
	}
	set := make(map[string]bool, len(cat.order))
	for _, id := range cat.order {
		set[id] = true
	}
	return &selection{cat: cat, ids: cat.order, set: set}, nil
}

// apply evaluates one import's include/exclude directives over src.
func (r *resolver) apply(p, href string, src *selection, all bool, include, exclude []selectControl) ([]string, bool) {
	ok := true
	fail := func(code, subject, format string, a ...any) {
		r.add(blocking(code, p, subject, format, a...))
		ok = false
	}
	if all && len(include) > 0 {
		fail(CodeSemanticsUnsupported, href, "an import cannot combine include-all with include-controls")
	}
	if !all && len(include) == 0 {
		fail(CodeSemanticsUnsupported, href, "the import names neither include-all nor include-controls")
	}
	picked := map[string]bool{}
	var order []string
	pick := func(id string) {
		if !picked[id] {
			picked[id] = true
			order = append(order, id)
		}
	}
	if all {
		for _, id := range src.ids {
			pick(id)
		}
	}
	children := func(sc selectControl) bool {
		switch sc.WithChildControls {
		case "", "no":
			return false
		case "yes":
			return true
		}
		fail(CodeSemanticsUnsupported, href, "with-child-controls %q is not supported", sc.WithChildControls)
		return false
	}
	for _, sc := range include {
		if len(sc.Matching) > 0 {
			fail(CodeSemanticsUnsupported, href, "selection by matching patterns is not supported")
		}
		kids := children(sc)
		for _, id := range sc.WithIDs {
			if !src.set[id] {
				fail(CodeSelectionNotInSource, id, "%s is not available from import %s (catalog %s)", id, href, src.cat.doc.Ref.Path)
				continue
			}
			if picked[id] {
				r.add(notice(CodeDuplicateSelection, p, id, "%s is selected more than once; counted once", id))
			}
			pick(id)
			if kids {
				for _, d := range src.cat.descendants(id) {
					if src.set[d] {
						pick(d)
					}
				}
			}
		}
	}
	for _, sc := range exclude {
		if len(sc.Matching) > 0 {
			fail(CodeSemanticsUnsupported, href, "exclusion by matching patterns is not supported")
		}
		kids := children(sc)
		for _, id := range sc.WithIDs {
			if _, known := src.cat.controls[id]; !known {
				fail(CodeSelectionNotInSource, id, "excluded %s is not a control of catalog %s", id, src.cat.doc.Ref.Path)
				continue
			}
			delete(picked, id)
			if kids {
				for _, d := range src.cat.descendants(id) {
					delete(picked, d)
				}
			}
		}
	}
	return slices.DeleteFunc(order, func(id string) bool { return !picked[id] }), ok
}

// catalogIndex indexes a catalog's controls recursively under its groups.
type catalogIndex struct {
	doc      *document
	controls map[string]*catalogEntry
	order    []string // document order
	children map[string][]string
}

type catalogEntry struct {
	c     Control
	stmts map[string]bool
}

// OSCAL catalog subset.
type (
	catGroup struct {
		ID       string       `json:"id"`
		Title    string       `json:"title"`
		Groups   []catGroup   `json:"groups"`
		Controls []catControl `json:"controls"`
	}
	catControl struct {
		ID       string       `json:"id"`
		Class    string       `json:"class"`
		Title    string       `json:"title"`
		Props    []prop       `json:"props"`
		Params   []catParam   `json:"params"`
		Parts    []catPart    `json:"parts"`
		Controls []catControl `json:"controls"`
	}
	catParam struct {
		ID     string   `json:"id"`
		Label  string   `json:"label"`
		Values []string `json:"values"`
	}
	catPart struct {
		ID    string    `json:"id"`
		Name  string    `json:"name"`
		Parts []catPart `json:"parts"`
	}
	prop struct {
		Name    string `json:"name"`
		Value   string `json:"value"`
		Class   string `json:"class"`
		NS      string `json:"ns"`
		Remarks string `json:"remarks"`
	}
)

func (r *resolver) catalog(doc *document) (*catalogIndex, *Limitation) {
	if c, ok := r.catalogs[doc.Ref.Path]; ok {
		return c, nil
	}
	var body struct {
		Groups   []catGroup   `json:"groups"`
		Controls []catControl `json:"controls"`
	}
	if err := json.Unmarshal(doc.body, &body); err != nil {
		return nil, blocking(CodeDocumentInvalid, doc.Ref.Path, "", "catalog: %v", err)
	}
	idx := &catalogIndex{doc: doc, controls: map[string]*catalogEntry{}, children: map[string][]string{}}
	var dup []string
	var visit func(cs []catControl, parent string, groups []Group)
	visit = func(cs []catControl, parent string, groups []Group) {
		for _, c := range cs {
			if _, ok := idx.controls[c.ID]; ok {
				dup = append(dup, c.ID)
				continue
			}
			e := &catalogEntry{c: Control{ID: c.ID, Title: c.Title, Class: c.Class, Parent: parent,
				Groups: slices.Clone(groups), Label: label(c.Props), Status: coreProp(c.Props, "status"),
				Statements: []string{}}, stmts: map[string]bool{}}
			for _, prm := range c.Params {
				e.c.Parameters = append(e.c.Parameters, Parameter{ID: prm.ID, Label: prm.Label, Values: prm.Values})
			}
			for _, part := range c.Parts {
				if part.Name == "statement" {
					part.collect(e.stmts)
				}
			}
			e.c.Statements = slices.SortedFunc(maps.Keys(e.stmts), compareIDs)
			idx.controls[c.ID] = e
			idx.order = append(idx.order, c.ID)
			if parent != "" {
				idx.children[parent] = append(idx.children[parent], c.ID)
			}
			visit(c.Controls, c.ID, groups)
		}
	}
	var groups func(gs []catGroup, path []Group)
	groups = func(gs []catGroup, path []Group) {
		for _, g := range gs {
			p := append(slices.Clone(path), Group{ID: g.ID, Title: g.Title})
			visit(g.Controls, "", p)
			groups(g.Groups, p)
		}
	}
	visit(body.Controls, "", nil)
	groups(body.Groups, nil)
	if len(dup) > 0 {
		slices.SortFunc(dup, compareIDs)
		return nil, blocking(CodeDuplicateCatalogID, doc.Ref.Path, dup[0], "control IDs occur more than once: %s", strings.Join(slices.Compact(dup), ", "))
	}
	r.catalogs[doc.Ref.Path] = idx
	return idx, nil
}

// descendants are every nested control of id, depth first.
func (c *catalogIndex) descendants(id string) []string {
	var out []string
	for _, k := range c.children[id] {
		out = append(out, k)
		out = append(out, c.descendants(k)...)
	}
	return out
}

// collect records a statement part and its nested statement/item parts.
func (p catPart) collect(into map[string]bool) {
	if p.ID != "" {
		into[p.ID] = true
	}
	for _, c := range p.Parts {
		if c.Name == "item" || c.Name == "statement" {
			c.collect(into)
		}
	}
}

// label is the control's core label property, preferring one without a
// class.
func label(props []prop) string {
	out := ""
	for _, p := range props {
		if p.Name != "label" || p.NS != "" {
			continue
		}
		if p.Class == "" {
			return p.Value
		}
		if out == "" {
			out = p.Value
		}
	}
	return out
}

func coreProp(props []prop, name string) string {
	for _, p := range props {
		if p.Name == name && p.NS == "" {
			return p.Value
		}
	}
	return ""
}

// model reads an entry point's root model (its first key other than
// $schema) without validating the rest; load validates it when it is used.
func (l *loader) model(p string) (string, *Limitation) {
	if d, ok := l.docs[p]; ok {
		return d.Ref.Model, nil
	}
	raw, _, err := l.raw(p)
	if err != nil {
		return "", blocking(CodeDocumentUnavailable, p, "", "%v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return "", blocking(CodeDocumentInvalid, p, "", "not a JSON object")
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return "", blocking(CodeDocumentInvalid, p, "", "%v", err)
		}
		if k, _ := t.(string); k != "$schema" {
			return k, nil
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return "", blocking(CodeDocumentInvalid, p, "", "%v", err)
		}
	}
	return "", blocking(CodeDocumentInvalid, p, "", "not a single-root OSCAL document")
}
