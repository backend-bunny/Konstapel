package provider

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Registry is an immutable set of installed providers and the default a
// selection without an explicit provider implies. Every lookup is a pure
// function of the descriptors it was built from.
type Registry struct {
	byName   map[string]Descriptor
	byKind   map[string]string // check kind -> provider name
	fallback string            // default contract
}

// New builds a registry. It rejects invalid descriptors, a provider name
// registered twice (one installed version per provider; an upgrade replaces
// it, and retained captures stay readable through Capture.Read), a check
// kind claimed by two providers, and a default that is not installed.
func New(defaultContract string, descriptors ...Descriptor) (*Registry, error) {
	r := &Registry{byName: map[string]Descriptor{}, byKind: map[string]string{}, fallback: defaultContract}
	var errs []error
	for _, d := range descriptors {
		if err := d.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		if prev, dup := r.byName[d.Name]; dup {
			errs = append(errs, fmt.Errorf("provider %s is registered twice (%s and %s)", d.Name, prev.Contract(), d.Contract()))
			continue
		}
		r.byName[d.Name] = clone(d)
		for _, k := range d.Checks {
			if owner, taken := r.byKind[k.Kind]; taken {
				errs = append(errs, fmt.Errorf("check kind %s is claimed by %s and %s", k.Kind, owner, d.Name))
				continue
			}
			r.byKind[k.Kind] = d.Name
		}
	}
	if len(descriptors) == 0 {
		errs = append(errs, errors.New("no providers"))
	}
	if d, ok := r.lookupContract(defaultContract); !ok {
		errs = append(errs, fmt.Errorf("default provider %q is not installed", defaultContract))
	} else if d.TestOnly {
		errs = append(errs, fmt.Errorf("default provider %s is test-only", defaultContract))
	}
	if len(errs) > 0 {
		return nil, joinErrors("provider registry", errs)
	}
	return r, nil
}

// Default is the contract a selection without an explicit provider uses.
func (r *Registry) Default() string { return r.fallback }

// Contracts lists the installed contracts, sorted.
func (r *Registry) Contracts() []string {
	out := make([]string, 0, len(r.byName))
	for _, d := range r.byName {
		out = append(out, d.Contract())
	}
	slices.Sort(out)
	return out
}

// Descriptors lists copies of the installed descriptors, sorted by name.
func (r *Registry) Descriptors() []Descriptor {
	out := make([]Descriptor, 0, len(r.byName))
	for _, d := range r.byName {
		out = append(out, clone(d))
	}
	slices.SortFunc(out, func(a, b Descriptor) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// Lookup resolves a contract to its installed descriptor. An empty contract
// is the default. Unknown names and other versions of an installed provider
// are distinct errors.
func (r *Registry) Lookup(contract string) (Descriptor, *SelectionError) {
	if contract == "" {
		contract = r.fallback
	}
	name, _, err := ParseContract(contract)
	if err != nil {
		return Descriptor{}, &SelectionError{Reason: ReasonInvalidSelection, Message: err.Error()}
	}
	if d, ok := r.lookupContract(contract); ok {
		return clone(d), nil
	}
	if d, ok := r.byName[name]; ok {
		return Descriptor{}, &SelectionError{Reason: ReasonIncompatibleVersion,
			Message: fmt.Sprintf("provider contract %s is not installed; this build installs %s", contract, d.Contract())}
	}
	return Descriptor{}, &SelectionError{Reason: ReasonUnknownProvider,
		Message: fmt.Sprintf("provider %s is not installed (installed: %s)", contract, strings.Join(r.Contracts(), ", "))}
}

// CheckCapture reports whether the installed provider for contract can read
// a capture payload of the given version. It never falls back to another
// provider or version.
func (r *Registry) CheckCapture(contract string, version int) error {
	d, serr := r.Lookup(contract)
	if serr != nil {
		return serr
	}
	if !slices.Contains(d.Capture.Read, version) {
		return &SelectionError{Reason: ReasonIncompatibleVersion,
			Message: fmt.Sprintf("%s reads capture versions %v, not %d", d.Contract(), d.Capture.Read, version)}
	}
	return nil
}

func (r *Registry) lookupContract(contract string) (Descriptor, bool) {
	name, version, err := ParseContract(contract)
	if err != nil {
		return Descriptor{}, false
	}
	d, ok := r.byName[name]
	return d, ok && d.Version == version
}

func clone(d Descriptor) Descriptor {
	d.Checks = slices.Clone(d.Checks)
	for i := range d.Checks {
		d.Checks[i].Modes = slices.Clone(d.Checks[i].Modes)
		d.Checks[i].Parameters.Schema = bytes.Clone(d.Checks[i].Parameters.Schema)
	}
	d.Capture.Read = slices.Clone(d.Capture.Read)
	d.Reads = slices.Clone(d.Reads)
	for i := range d.Reads {
		d.Reads[i].Verbs = slices.Clone(d.Reads[i].Verbs)
	}
	d.Requires = slices.Clone(d.Requires)
	for i := range d.Requires {
		d.Requires[i].Verbs = slices.Clone(d.Requires[i].Verbs)
	}
	return d
}

func joinErrors(what string, errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s: %w", what, errors.Join(errs...))
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
