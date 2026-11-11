package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf8"
)

const maxJSONDepth = 64

// checkJSON requires raw to be exactly one valid UTF-8 JSON value with no
// object holding the same key twice and no nesting deeper than maxJSONDepth.
// Go's encoding/json keeps the last duplicate and protojson the first error,
// so a document that two parsers could read differently is refused outright.
func checkJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	type frame struct {
		object bool
		keys   map[string]bool
		expect bool // in an object: the next token is a key
	}
	var stack []*frame
	values := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		top := (*frame)(nil)
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.object && top.expect {
			key, ok := tok.(string)
			if !ok {
				if d, ok := tok.(json.Delim); ok && d == '}' {
					stack = stack[:len(stack)-1]
					continue
				}
				return errors.New("malformed object")
			}
			if top.keys[key] {
				return fmt.Errorf("duplicate key %q", key)
			}
			top.keys[key] = true
			top.expect = false
			continue
		}
		if top == nil {
			if values++; values > 1 {
				return errors.New("trailing data after the JSON value")
			}
		}
		switch d := tok.(type) {
		case json.Delim:
			switch d {
			case '{', '[':
				if len(stack) >= maxJSONDepth {
					return errors.New("nesting too deep")
				}
				if top != nil && top.object {
					top.expect = true
				}
				stack = append(stack, &frame{object: d == '{', keys: map[string]bool{}, expect: d == '{'})
			case ']':
				stack = stack[:len(stack)-1]
			}
		default:
			if top != nil && top.object {
				top.expect = true
			}
		}
	}
	if values != 1 {
		return errors.New("no JSON value")
	}
	return nil
}

// In-toto statement types. The pinned Cosign (v3.1.3) writes Statement v1 for
// `cosign sign` (new bundle format) and Statement v0.1 for `cosign attest`;
// GitHub's attestation actions write v1. Both have the same four fields.
const (
	StatementTypeV1   = "https://in-toto.io/Statement/v1"
	StatementTypeV01  = "https://in-toto.io/Statement/v0.1"
	inTotoPayloadType = "application/vnd.in-toto+json"
	maxStatementBytes = 4 << 20
	statementKeyType  = "_type"
	statementKeySubj  = "subject"
	statementKeyPredT = "predicateType"
	statementKeyPred  = "predicate"
	subjectKeyName    = "name"
	subjectKeyDigest  = "digest"
	subjectKeyAnnots  = "annotations"
	subjectDigestAlgo = "sha256"
)

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Statement is a signed in-toto statement after its signature verified under
// the publisher rule. Predicate holds the raw predicate JSON object exactly as
// signed, for later policy stages (SLSA provenance checks) to read without
// verifying again.
type Statement struct {
	Type          string
	PredicateType string
	// Subjects are the statement's subjects; verification requires exactly
	// one, for the pinned digest.
	Subjects  []Subject
	Predicate json.RawMessage
}

// Subject is one statement subject. Name is informational only: it is a
// registry location (Cosign's signature statement omits it; a mirror changes
// it) and never part of identity or policy.
type Subject struct {
	Name   string
	Digest string // sha256:<hex>
}

// parseStatement decodes a DSSE payload as an in-toto statement strictly:
// exact key names (encoding/json would otherwise match keys case-insensitively),
// no unknown or duplicate keys, a JSON object predicate, and subjects whose
// digest sets contain exactly one lowercase SHA-256 digest.
func parseStatement(payload []byte) (*Statement, error) {
	if len(payload) > maxStatementBytes {
		return nil, fail(ErrProofTooLarge, "statement exceeds %d bytes", maxStatementBytes)
	}
	if err := checkJSON(payload); err != nil {
		return nil, fail(ErrStatement, "%v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(payload, &top); err != nil {
		return nil, fail(ErrStatement, "not a JSON object")
	}
	for k := range top {
		switch k {
		case statementKeyType, statementKeySubj, statementKeyPredT, statementKeyPred:
		default:
			return nil, fail(ErrStatement, "unexpected statement field %q", k)
		}
	}
	var st Statement
	if err := decodeString(top, statementKeyType, &st.Type); err != nil {
		return nil, err
	}
	if st.Type != StatementTypeV1 && st.Type != StatementTypeV01 {
		return nil, fail(ErrStatement, "statement type %q is not %s or %s", st.Type, StatementTypeV1, StatementTypeV01)
	}
	if err := decodeString(top, statementKeyPredT, &st.PredicateType); err != nil {
		return nil, err
	}
	pred, ok := top[statementKeyPred]
	if !ok || !bytes.HasPrefix(bytes.TrimSpace(pred), []byte("{")) {
		return nil, fail(ErrStatement, "predicate must be a JSON object")
	}
	st.Predicate = append(json.RawMessage(nil), bytes.TrimSpace(pred)...)
	var subjects []map[string]json.RawMessage
	rawSubj, ok := top[statementKeySubj]
	if !ok {
		return nil, fail(ErrStatement, "statement has no subject")
	}
	if err := json.Unmarshal(rawSubj, &subjects); err != nil {
		return nil, fail(ErrStatement, "subject must be a list of objects")
	}
	for i, s := range subjects {
		var sub Subject
		for k := range s {
			switch k {
			case subjectKeyName, subjectKeyDigest, subjectKeyAnnots:
			default:
				return nil, fail(ErrStatement, "subject %d has unexpected field %q", i, k)
			}
		}
		if raw, ok := s[subjectKeyName]; ok {
			if err := json.Unmarshal(raw, &sub.Name); err != nil {
				return nil, fail(ErrStatement, "subject %d name is not a string", i)
			}
		}
		if raw, ok := s[subjectKeyAnnots]; ok && !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
			return nil, fail(ErrStatement, "subject %d annotations must be an object", i)
		}
		var digests map[string]string
		if err := json.Unmarshal(s[subjectKeyDigest], &digests); err != nil || digests == nil {
			return nil, fail(ErrStatement, "subject %d digest must be an object of strings", i)
		}
		// Exactly one sha256 digest: a second algorithm could name other
		// bytes, and only sha256 identifies an OCI manifest here.
		if len(digests) != 1 {
			return nil, fail(ErrSubject, "subject %d must carry exactly one sha256 digest, has %d", i, len(digests))
		}
		hex, ok := digests[subjectDigestAlgo]
		if !ok || !hexDigest.MatchString(hex) {
			return nil, fail(ErrSubject, "subject %d digest is not a lowercase sha256", i)
		}
		sub.Digest = "sha256:" + hex
		st.Subjects = append(st.Subjects, sub)
	}
	return &st, nil
}

func decodeString(m map[string]json.RawMessage, key string, out *string) error {
	raw, ok := m[key]
	if !ok {
		return fail(ErrStatement, "statement has no %q", key)
	}
	if err := json.Unmarshal(raw, out); err != nil || *out == "" {
		return fail(ErrStatement, "statement %q must be a non-empty string", key)
	}
	return nil
}

// checkBinding requires the statement to be about exactly the pinned digest
// and to carry the predicate type the requested proof kind needs.
func (st *Statement) checkBinding(subject, predicateType string) error {
	if len(st.Subjects) != 1 {
		return fail(ErrSubject, "statement names %d subjects; exactly one (the pinned manifest) is required", len(st.Subjects))
	}
	if st.Subjects[0].Digest != subject {
		return fail(ErrSubject, "statement is for %s, not the pinned %s", st.Subjects[0].Digest, subject)
	}
	if st.PredicateType != predicateType {
		return fail(ErrPredicateType, "signed predicate type is %q, %q is required", st.PredicateType, predicateType)
	}
	return nil
}
