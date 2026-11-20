package preview

import (
	"crypto/sha256"
	"encoding/hex"
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
	proposed, before, _, err = LoadStreams(in, stdin, lim)
	return proposed, before, err
}

// Role is the part an input stream plays in a preview.
type Role string

const (
	RoleProposed Role = "proposed"
	RoleBefore   Role = "before"
)

// Stream is the provenance of one input stream: its role, its path ("-" for
// standard input) and, when it was read completely, the sha256 of its bytes.
// The digest identifies the bytes as read, not normalized configuration.
type Stream struct {
	Role   Role   `json:"role"`
	Path   string `json:"path"`
	Read   bool   `json:"read"`
	Digest string `json:"digest,omitempty"`
	Bytes  int64  `json:"bytes"`
}

// LoadStreams is Load that also returns the provenance of every named stream
// in argument order, the proposed streams first, including when the input is
// invalid. A stream that could not be read completely has Read false.
func LoadStreams(in Inputs, stdin io.Reader, lim Limits) (proposed, before *Set, streams []Stream, err error) {
	lim = lim.withDefaults()
	for _, p := range in.Proposed {
		streams = append(streams, Stream{Role: RoleProposed, Path: p})
	}
	for _, p := range in.Before {
		streams = append(streams, Stream{Role: RoleBefore, Path: p})
	}
	if len(in.Proposed) == 0 {
		return nil, nil, streams, InputErrors{{Code: CodeNoProposedInput, Message: "at least one proposed input (-f/--file) is required; use an empty file to propose removing the previous set"}}
	}
	stdinUses := 0
	for _, p := range slices.Concat(in.Proposed, in.Before) {
		if p == StdinPath {
			stdinUses++
		}
	}
	if stdinUses > 1 {
		return nil, nil, streams, InputErrors{{Code: CodeStdinTwice, Source: StdinPath, Message: "standard input can supply only one input stream"}}
	}
	remaining := lim.MaxInputBytes
	var errs InputErrors
	next := 0
	load := func(paths []string) *Set {
		var objs []*Object
		firstAt := map[Identity]*Object{}
		for _, path := range paths {
			st := &streams[next]
			next++
			data, rerr := readStream(path, stdin, &remaining, lim.MaxInputBytes)
			if rerr != nil {
				errs = append(errs, *rerr)
				if rerr.Code == CodeInputTooLarge {
					return nil
				}
				continue
			}
			sum := sha256.Sum256(data)
			st.Read, st.Digest, st.Bytes = true, "sha256:"+hex.EncodeToString(sum[:]), int64(len(data))
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
		next = len(in.Proposed)
		before = load(in.Before)
	}
	if len(errs) > 0 {
		return nil, nil, streams, errs
	}
	return proposed, before, streams, nil
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
