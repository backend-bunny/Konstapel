// Package projection is the provider-neutral part of namespace projection
// (add-assessment-provider-contract 3.3): the scope a namespace package may
// disclose, the host's shared check of what an extract discloses, and the
// extractor interface a provider implements for its own payload.
//
// A namespace package discloses one namespace instance's evidence to the
// team that requested it. Two parts keep any provider's payload safe to
// disclose there:
//
//   - Provider-specific safe extraction. Only a provider can read its own
//     payload, so its Extractor rebuilds the payload for one namespace from
//     allowlisted fields. It withholds what it cannot attribute and records
//     each extract's provenance.
//   - Shared validation. Check is the host's check of the scope that the
//     provider reports for every namespace-attributable item. The provider
//     reads that scope back from the extract, never from the source. Every
//     item must belong to the authorized namespace instance, and an item of
//     unknown scope fails closed.
//
// The package imports no provider and no Kyverno package, so any provider,
// including the test-only reporting provider, can implement Extractor. The
// collector owns the capture dispatch (collector.CaptureDocument's
// ProjectNamespace and ValidateNamespace) and Kyverno's own extraction.
package projection

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Scope is the one namespace instance a namespace package may disclose. UID
// is required. Name is optional: when it is empty, an item that names a
// namespace only by name cannot be checked and fails.
type Scope struct {
	Name string
	UID  string
}

// Disclosure is one namespace-attributable item of an extract and the
// namespace it names.
type Disclosure struct {
	// Item locates the item in the extract, for example "subjects[0]". It
	// never copies the item's content.
	Item string
	// Namespace and NamespaceUID are the namespace name and instance the
	// item records. A provider sets each one the item records. An item that
	// records neither has unknown scope.
	Namespace    string
	NamespaceUID string
}

// ErrDisclosure marks a namespace extract that the shared check refuses: an
// item attributed to another namespace or of unknown scope, or an extract
// its provider cannot read back.
var ErrDisclosure = errors.New("the namespace extract discloses data outside its namespace")

// maxErrors bounds the items a refusal names.
const maxErrors = 20

// Check is the host's shared projection check. Every disclosed item must
// name the authorized namespace instance: its UID when the item records
// one, and its name when the item records one. An item that records neither
// has unknown scope and is refused, as is any scope without a UID.
//
// A refusal names only the offending items' locations and the kind of
// failure. It never repeats a namespace name or UID, because the text can
// reach operator diagnostics.
func Check(ns Scope, items []Disclosure) error {
	if ns.UID == "" {
		return fmt.Errorf("%w: the scope names no namespace instance", ErrDisclosure)
	}
	var bad []string
	total := 0
	for _, d := range items {
		var why string
		switch {
		case d.Namespace == "" && d.NamespaceUID == "":
			why = "unknown scope"
		case d.NamespaceUID != "" && d.NamespaceUID != ns.UID:
			why = "another namespace instance"
		case d.Namespace != "" && ns.Name == "":
			why = "a namespace name the scope cannot check"
		case d.Namespace != "" && d.Namespace != ns.Name:
			why = "another namespace"
		default:
			continue
		}
		total++
		if len(bad) < maxErrors {
			bad = append(bad, d.Item+": "+why)
		}
	}
	if total == 0 {
		return nil
	}
	if total > len(bad) {
		bad = append(bad, fmt.Sprintf("and %d more", total-len(bad)))
	}
	return fmt.Errorf("%w: %s", ErrDisclosure, strings.Join(bad, "; "))
}

// Extractor is one provider's safe extraction of its capture payload to one
// namespace. Both methods are pure over their arguments.
type Extractor interface {
	// Extract returns the payload restricted to what ns may disclose. It
	// rebuilds every item it keeps from allowlisted fields, records where
	// each kept piece of source evidence came from, and withholds every
	// item it cannot attribute to ns. A source object shared with other
	// namespaces contributes only its attributable part.
	Extract(payload json.RawMessage, ns Scope) (json.RawMessage, error)
	// Disclosures lists every namespace-attributable item of an extract,
	// read from the extract alone. It fails for an extract that Extract
	// could not have produced, for example one with a field outside its
	// allowlist. It never leaves out an item it cannot read.
	Disclosures(extract json.RawMessage) ([]Disclosure, error)
}
