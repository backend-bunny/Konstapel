// Package preview holds the read-only policy-change preview core
// (add-policy-change-preview). This part covers manifest inputs and the
// candidate configuration. It performs no cluster access, starts no manager
// or provider, and never mutates anything: callers supply the live desired
// state they observed.
package preview

import (
	"fmt"
	"strings"
)

// Code classifies an input problem so callers and CI can act on it without
// parsing prose. Every code makes the preview invalid; none is informational.
type Code string

const (
	CodeNoProposedInput    Code = "no-proposed-input"
	CodeStdinTwice         Code = "stdin-used-twice"
	CodeReadFailed         Code = "read-failed"
	CodeInputTooLarge      Code = "input-too-large"
	CodeSyntax             Code = "syntax"
	CodeTooDeep            Code = "too-deep"
	CodeAliasNotAllowed    Code = "alias-not-allowed"
	CodeUnsupportedTag     Code = "unsupported-tag"
	CodeNonStringKey       Code = "non-string-key"
	CodeAmbiguousScalar    Code = "ambiguous-scalar"
	CodeInvalidNumber      Code = "invalid-number"
	CodeDuplicateKey       Code = "duplicate-key"
	CodeNotAnObject        Code = "not-an-object"
	CodeMissingType        Code = "missing-type"
	CodeUnsupportedKind    Code = "unsupported-kind"
	CodeUnsupportedVersion Code = "unsupported-version"
	CodeInvalidMetadata    Code = "invalid-metadata"
	CodeInvalidName        Code = "invalid-name"
	CodeUnknownField       Code = "unknown-field"
	CodeInvalidSpec        Code = "invalid-spec"
	CodeDuplicateIdentity  Code = "duplicate-identity"
	CodeDuplicateLive      Code = "duplicate-live-object"
	CodeProfileRemoved     Code = "profile-removed-in-use"
	CodeProfileNotFound    Code = "profile-not-found"
	CodeTooManyErrors      Code = "too-many-errors"
)

// InputError is one attributable problem with the rendered input or the
// candidate built from it.
type InputError struct {
	Code Code `json:"code"`
	// Source is the input path ("-" for standard input), or empty for a
	// candidate-level problem.
	Source string `json:"source,omitempty"`
	// Document is the 1-based document index in Source; Line is 1-based.
	Document int `json:"document,omitempty"`
	Line     int `json:"line,omitempty"`
	// Identity is "Kind/name" when it could be determined.
	Identity string `json:"identity,omitempty"`
	// Field is the spec field path for field-level problems.
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

func (e InputError) Error() string {
	var b strings.Builder
	if e.Source != "" {
		b.WriteString(e.Source)
		if e.Document > 0 {
			fmt.Fprintf(&b, "#%d", e.Document)
		}
		if e.Line > 0 {
			fmt.Fprintf(&b, ":%d", e.Line)
		}
		b.WriteString(": ")
	}
	if e.Identity != "" {
		b.WriteString(e.Identity)
		b.WriteString(": ")
	}
	if e.Field != "" {
		b.WriteString(e.Field)
		b.WriteString(": ")
	}
	fmt.Fprintf(&b, "%s [%s]", e.Message, e.Code)
	return b.String()
}

// InputErrors is the error returned for an invalid input or candidate. Its
// order is deterministic: input order, then candidate checks by identity.
type InputErrors []InputError

func (e InputErrors) Error() string {
	parts := make([]string, len(e))
	for i := range e {
		parts[i] = e[i].Error()
	}
	return strings.Join(parts, "\n")
}

// Limits bounds what the preview reads. Hitting a limit is an error, never a
// silently truncated input.
type Limits struct {
	// MaxInputBytes bounds the total of every proposed and before stream.
	MaxInputBytes int64
	// MaxDepth bounds document nesting.
	MaxDepth int
	// MaxErrors bounds how many problems one parse reports.
	MaxErrors int
}

// DefaultLimits are the design limits: 16 MiB of manifest input in total.
func DefaultLimits() Limits {
	return Limits{MaxInputBytes: 16 << 20, MaxDepth: 64, MaxErrors: 100}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxInputBytes <= 0 {
		l.MaxInputBytes = d.MaxInputBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxErrors <= 0 {
		l.MaxErrors = d.MaxErrors
	}
	return l
}
