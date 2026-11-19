package preview

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
)

// StdinPath selects standard input as an input stream.
const StdinPath = "-"

// Inputs names the rendered manifest streams of one preview.
type Inputs struct {
	// Proposed are the -f/--file paths; at least one is required. An explicitly
	// supplied path whose stream holds no objects is valid and proposes the
	// removal of every identity in Before.
	Proposed []string
	// Before are the optional --before paths: the previous rendered set, which
	// declares removal scope and provenance, never the baseline.
	Before []string
}

// Load reads and validates both input sets under one shared size budget.
// Standard input ("-") may be used at most once across both roles, so two
// sets can never silently consume the same stream. It reads nothing but the
// named files and stdin, and reports every problem in input order.
func Load(in Inputs, stdin io.Reader, lim Limits) (proposed, before *Set, err error) {
	lim = lim.withDefaults()
	if len(in.Proposed) == 0 {
		return nil, nil, InputErrors{{Code: CodeNoProposedInput, Message: "at least one proposed input (-f/--file) is required; use an empty file to propose removing the previous set"}}
	}
	stdinUses := 0
	for _, p := range slices.Concat(in.Proposed, in.Before) {
		if p == StdinPath {
			stdinUses++
		}
	}
	if stdinUses > 1 {
		return nil, nil, InputErrors{{Code: CodeStdinTwice, Source: StdinPath, Message: "standard input can supply only one input stream"}}
	}
	remaining := lim.MaxInputBytes
	var errs InputErrors
	load := func(paths []string) *Set {
		var objs []*Object
		firstAt := map[Identity]*Object{}
		for _, path := range paths {
			data, rerr := readStream(path, stdin, &remaining, lim.MaxInputBytes)
			if rerr != nil {
				errs = append(errs, *rerr)
				if rerr.Code == CodeInputTooLarge {
					return nil
				}
				continue
			}
			parsed, perrs := Parse(path, data, lim)
			errs = append(errs, perrs...)
			for _, o := range parsed {
				if prev := firstAt[o.Identity]; prev != nil {
					errs = append(errs, InputError{Code: CodeDuplicateIdentity, Source: o.Source, Document: o.Document, Line: o.Line, Identity: o.Identity.String(),
						Message: fmt.Sprintf("duplicate object; first defined in %s document %d line %d", prev.Source, prev.Document, prev.Line)})
					continue
				}
				firstAt[o.Identity] = o
				objs = append(objs, o)
			}
		}
		return newSet(objs)
	}
	proposed = load(in.Proposed)
	if !hasCode(errs, CodeInputTooLarge) {
		before = load(in.Before)
	}
	if len(errs) > 0 {
		return nil, nil, errs
	}
	return proposed, before, nil
}

func hasCode(errs InputErrors, c Code) bool {
	return slices.ContainsFunc(errs, func(e InputError) bool { return e.Code == c })
}

func newSet(objs []*Object) *Set {
	slices.SortFunc(objs, func(a, b *Object) int { return compareIdentity(a.Identity, b.Identity) })
	return &Set{Objects: objs}
}

func readStream(path string, stdin io.Reader, remaining *int64, total int64) ([]byte, *InputError) {
	fail := func(code Code, format string, args ...any) ([]byte, *InputError) {
		return nil, &InputError{Code: code, Source: path, Message: fmt.Sprintf(format, args...)}
	}
	var r io.Reader
	if path == StdinPath {
		if stdin == nil {
			return fail(CodeReadFailed, "standard input is not available")
		}
		r = stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return fail(CodeReadFailed, "%v", errors.Unwrap(err))
		}
		defer f.Close()
		if st, err := f.Stat(); err != nil {
			return fail(CodeReadFailed, "%v", err)
		} else if st.IsDir() {
			return fail(CodeReadFailed, "is a directory; name the rendered manifest files explicitly")
		}
		r = f
	}
	// Read one byte past the budget so an oversize input is detected, never truncated.
	data, err := io.ReadAll(io.LimitReader(r, *remaining+1))
	if err != nil {
		return fail(CodeReadFailed, "%v", err)
	}
	if int64(len(data)) > *remaining {
		return fail(CodeInputTooLarge, "manifest input exceeds the %d byte limit across all input streams", total)
	}
	*remaining -= int64(len(data))
	return data, nil
}
