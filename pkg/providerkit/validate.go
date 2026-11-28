package providerkit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
)

// Validation shared by the server, which checks requests and its handlers'
// results, and the client, which checks responses. Request violations are
// ERROR_REASON_INVALID_REQUEST; response violations are
// ERROR_REASON_INVALID_RESPONSE.

func invalidRequest(format string, args ...any) error {
	return Errorf(providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST, format, args...)
}

func invalidResponse(format string, args ...any) error {
	return Errorf(providerv1.ErrorReason_ERROR_REASON_INVALID_RESPONSE, format, args...)
}

// CheckHeader checks a request header against the description of the
// provider serving it, in order: protocol revision, provider name,
// contract version.
func CheckHeader(h *providerv1.RequestHeader, d *providerv1.DescribeResponse) error {
	switch {
	case h == nil:
		return invalidRequest("request has no header")
	case !slices.Contains(d.GetProtocolVersions(), h.GetProtocolVersion()):
		return Errorf(providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PROTOCOL_VERSION,
			"protocol revision %d of konstapel.provider.v1 is not served (serves %v)", h.GetProtocolVersion(), d.GetProtocolVersions())
	case h.GetProvider().GetName() != d.GetProvider().GetName():
		return Errorf(providerv1.ErrorReason_ERROR_REASON_PROVIDER_MISMATCH,
			"request is for provider %q, this is %q", h.GetProvider().GetName(), d.GetProvider().GetName())
	case h.GetProvider().GetVersion() != d.GetProvider().GetVersion():
		return Errorf(providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CONTRACT_VERSION,
			"request is for contract %s/v%d, this serves v%d", d.GetProvider().GetName(), h.GetProvider().GetVersion(), d.GetProvider().GetVersion())
	}
	return nil
}

func checkScope(s *providerv1.Scope) error {
	if s == nil {
		return invalidRequest("request has no scope")
	}
	if s.GetCluster() == "" || len(s.GetCluster()) > MaxTextBytes {
		return invalidRequest("scope cluster must be set and at most %d bytes", MaxTextBytes)
	}
	names, uids := map[string]bool{}, map[string]bool{}
	for _, n := range s.GetNamespaces() {
		switch {
		case !validName(n.GetName()):
			return invalidRequest("scope namespace %q is not a lowercase DNS label", n.GetName())
		case n.GetUid() == "" || len(n.GetUid()) > MaxTextBytes:
			return invalidRequest("scope namespace %q has no uid", n.GetName())
		case names[n.GetName()] || uids[n.GetUid()]:
			return invalidRequest("scope namespace %q (uid %s) is repeated", n.GetName(), n.GetUid())
		}
		names[n.GetName()], uids[n.GetUid()] = true, true
	}
	return nil
}

// jsonObject reports whether b is one JSON object.
func jsonObject(b []byte) bool {
	b = bytes.TrimSpace(b)
	return len(b) > 0 && b[0] == '{' && json.Valid(b)
}

func checkTime(name string, ts *timestamppb.Timestamp) error {
	if ts == nil {
		return invalidRequest("%s is not set", name)
	}
	if err := ts.CheckValid(); err != nil {
		return invalidRequest("%s: %v", name, err)
	}
	return nil
}

func checkID(name, id string) error {
	if id == "" || len(id) > MaxTextBytes {
		return invalidRequest("%s must be set and at most %d bytes", name, MaxTextBytes)
	}
	return nil
}

func checkWritePayload(version uint32, d *providerv1.DescribeResponse) error {
	if version != d.GetPayload().GetWrite() {
		return Errorf(providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PAYLOAD_VERSION,
			"payload version %d is not the written version %d", version, d.GetPayload().GetWrite())
	}
	return nil
}

func checkScanKey(k *providerv1.ScanKey) error {
	switch {
	case k == nil:
		return invalidRequest("start has no scan key")
	case checkID("scan key run_uid", k.GetRunUid()) != nil, checkID("scan key registration_uid", k.GetRegistrationUid()) != nil:
		return invalidRequest("scan key must name the run and registration UIDs")
	case k.GetRegistrationRevision() < 1:
		return invalidRequest("scan key registration_revision %d must be at least 1", k.GetRegistrationRevision())
	case !digestPattern.MatchString(k.GetInputDigest()):
		return invalidRequest("scan key input_digest %q must be sha256:<64 lowercase hex>", k.GetInputDigest())
	}
	return nil
}

// checkResult checks a result reference for the expected provider and
// payload version and the negotiated size bound.
func checkResult(ref *providerv1.ResultReference, provider *providerv1.ProviderContract, payloadVersion uint32, maxBytes uint64) error {
	switch {
	case ref == nil:
		return invalidResponse("no result reference")
	case ref.GetResultId() == "" || len(ref.GetResultId()) > MaxTextBytes:
		return invalidResponse("result_id must be set and at most %d bytes", MaxTextBytes)
	case !proto.Equal(ref.GetProvider(), provider):
		return invalidResponse("result %s was written by %s/v%d, not %s/v%d", ref.GetResultId(),
			ref.GetProvider().GetName(), ref.GetProvider().GetVersion(), provider.GetName(), provider.GetVersion())
	case ref.GetPayloadVersion() != payloadVersion:
		return invalidResponse("result %s has payload version %d, not %d", ref.GetResultId(), ref.GetPayloadVersion(), payloadVersion)
	case ref.GetSizeBytes() > maxBytes:
		return Errorf(providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED, "result %s is %d bytes, more than %d", ref.GetResultId(), ref.GetSizeBytes(), maxBytes)
	case !digestPattern.MatchString(ref.GetSha256()):
		return invalidResponse("result %s sha256 %q must be sha256:<64 lowercase hex>", ref.GetResultId(), ref.GetSha256())
	case ref.GetExpiresAt() == nil || ref.GetExpiresAt().CheckValid() != nil:
		return invalidResponse("result %s has no valid expires_at", ref.GetResultId())
	case len(ref.GetLimitations()) > MaxLimitations:
		return invalidResponse("result %s has more than %d limitations", ref.GetResultId(), MaxLimitations)
	}
	for _, l := range ref.GetLimitations() {
		if l == "" || len(l) > MaxTextBytes {
			return invalidResponse("result %s has an empty limitation or one longer than %d bytes", ref.GetResultId(), MaxTextBytes)
		}
	}
	return nil
}

// checkOperation checks an operation record. key, when set, is the key the
// operation must carry.
func checkOperation(op *providerv1.Operation, key *providerv1.ScanKey, provider *providerv1.ProviderContract, payloadVersion uint32, maxBytes uint64) error {
	if op == nil {
		return invalidResponse("no operation")
	}
	id := op.GetOperationId()
	switch {
	case id == "" || len(id) > MaxTextBytes:
		return invalidResponse("operation_id must be set and at most %d bytes", MaxTextBytes)
	case checkScanKey(op.GetKey()) != nil:
		return invalidResponse("operation %s has an invalid scan key", id)
	case key != nil && !proto.Equal(op.GetKey(), key):
		return invalidResponse("operation %s has another scan key than requested", id)
	case op.GetState() == providerv1.OperationState_OPERATION_STATE_UNSPECIFIED || providerv1.OperationState_name[int32(op.GetState())] == "":
		return invalidResponse("operation %s has state %d", id, op.GetState())
	case op.GetMaxAttempts() < 1 || op.GetAttempt() < 1 || op.GetAttempt() > op.GetMaxAttempts():
		return invalidResponse("operation %s attempt %d of %d is out of bounds", id, op.GetAttempt(), op.GetMaxAttempts())
	case len(op.GetMessage()) > MaxTextBytes:
		return invalidResponse("operation %s message is longer than %d bytes", id, MaxTextBytes)
	case (op.GetState() == providerv1.OperationState_OPERATION_STATE_SUCCEEDED) != (op.GetResult() != nil):
		return invalidResponse("operation %s in state %s must have a result exactly when it succeeded", id, op.GetState())
	}
	for name, ts := range map[string]*timestamppb.Timestamp{"created_at": op.GetCreatedAt(), "updated_at": op.GetUpdatedAt()} {
		if ts != nil && ts.CheckValid() != nil {
			return invalidResponse("operation %s %s is invalid", id, name)
		}
	}
	if op.GetResult() != nil {
		return checkResult(op.GetResult(), provider, payloadVersion, maxBytes)
	}
	return nil
}

// checkObservations checks an evaluation's observations: known states and
// outcomes, unique subject/check pairs, and raw outcome, normalized outcome,
// applicability and evaluation time only for attributable evidence.
func checkObservations(obs []*providerv1.Observation, max uint32) error {
	if uint64(len(obs)) > uint64(max) {
		return Errorf(providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED, "evaluation has more than %d observations", max)
	}
	seen := map[[2]string]bool{}
	for _, o := range obs {
		key := [2]string{o.GetSubject(), o.GetCheck()}
		where := fmt.Sprintf("observation %q/%q", o.GetSubject(), o.GetCheck())
		switch {
		case o.GetSubject() == "" || o.GetCheck() == "" || len(o.GetSubject()) > MaxTextBytes || len(o.GetCheck()) > MaxTextBytes:
			return invalidResponse("%s must name a subject and check of at most %d bytes", where, MaxTextBytes)
		case seen[key]:
			return invalidResponse("%s is repeated: each expected observation is evaluated once", where)
		case o.GetState() == providerv1.EvidenceState_EVIDENCE_STATE_UNSPECIFIED || providerv1.EvidenceState_name[int32(o.GetState())] == "":
			return invalidResponse("%s has evidence state %d", where, o.GetState())
		}
		seen[key] = true
		if o.GetState() != providerv1.EvidenceState_EVIDENCE_STATE_ATTRIBUTABLE {
			if o.GetRaw() != "" || o.GetOutcome() != providerv1.Outcome_OUTCOME_UNSPECIFIED || o.GetNotApplicable() || o.GetEvaluated() != nil {
				return invalidResponse("%s is %s but carries an outcome, applicability or evaluation time", where, o.GetState())
			}
			continue
		}
		switch {
		case o.GetRaw() == "" || len(o.GetRaw()) > MaxTextBytes:
			return invalidResponse("%s is attributable without a raw outcome of at most %d bytes", where, MaxTextBytes)
		case o.GetOutcome() == providerv1.Outcome_OUTCOME_UNSPECIFIED || providerv1.Outcome_name[int32(o.GetOutcome())] == "":
			return invalidResponse("%s is attributable with outcome %d", where, o.GetOutcome())
		case o.GetEvaluated() == nil || o.GetEvaluated().CheckValid() != nil:
			return invalidResponse("%s is attributable without a valid source evaluation time", where)
		}
	}
	return nil
}

// NamespaceResource is the resource of a namespace subject.
const NamespaceResource = "/v1/namespaces"

// CheckInventory checks a Collect request's inventory against its scope
// and the subject bound: at least one and at most maxSubjects subjects of
// the scope's namespaces, each UID once, with a resource, name, revision
// and unique expected checks. A namespace subject is a scope namespace:
// its own namespace, with the scope's name for that UID. More subjects
// than the bound is ERROR_REASON_LIMIT_EXCEEDED; any other violation is
// ERROR_REASON_INVALID_REQUEST. Revision 2 requires an inventory.
func CheckInventory(inv *providerv1.Inventory, scope *providerv1.Scope, maxSubjects uint32) error {
	if inv == nil {
		return invalidRequest("collect has no inventory: revision %d collects only against a host-frozen inventory", ProtocolVersion)
	}
	switch inv.GetSupplements() {
	case providerv1.Supplements_SUPPLEMENTS_NONE, providerv1.Supplements_SUPPLEMENTS_WITHIN_WORKLOADS:
	default:
		return invalidRequest("inventory supplements %d must be SUPPLEMENTS_NONE or SUPPLEMENTS_WITHIN_WORKLOADS", inv.GetSupplements())
	}
	subjects := inv.GetSubjects()
	switch {
	case len(subjects) == 0:
		return invalidRequest("inventory has no subject")
	case uint64(len(subjects)) > uint64(maxSubjects):
		return Errorf(providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED, "inventory has %d subjects, more than %d", len(subjects), maxSubjects)
	}
	namespaces := map[string]string{}
	for _, n := range scope.GetNamespaces() {
		namespaces[n.GetUid()] = n.GetName()
	}
	seen := map[string]bool{}
	for i, s := range subjects {
		where := fmt.Sprintf("inventory subject %d", i)
		ns, inScope := namespaces[s.GetNamespaceUid()]
		switch {
		case s.GetUid() == "" || len(s.GetUid()) > MaxTextBytes:
			return invalidRequest("%s must have a uid of at most %d bytes", where, MaxTextBytes)
		case seen[s.GetUid()]:
			return invalidRequest("%s repeats a uid", where)
		case !inScope:
			return invalidRequest("%s is not in a namespace of the scope", where)
		case !resourcePattern.MatchString(s.GetResource()):
			return invalidRequest("%s resource %q must be group/version/resource", where, bound(s.GetResource(), 80))
		case s.GetName() == "" || len(s.GetName()) > MaxNameBytes:
			return invalidRequest("%s must have a name of at most %d bytes", where, MaxNameBytes)
		case s.GetRevision() == "" || len(s.GetRevision()) > MaxTextBytes:
			return invalidRequest("%s must have a revision of at most %d bytes", where, MaxTextBytes)
		case s.GetResource() == NamespaceResource && (s.GetUid() != s.GetNamespaceUid() || s.GetName() != ns):
			return invalidRequest("%s is a namespace subject other than its scope namespace", where)
		case len(s.GetChecks()) == 0 || len(s.GetChecks()) > MaxSubjectChecks:
			return invalidRequest("%s must expect between 1 and %d checks", where, MaxSubjectChecks)
		}
		seen[s.GetUid()] = true
		checks := map[string]bool{}
		for _, c := range s.GetChecks() {
			if c == "" || len(c) > MaxTextBytes || checks[c] {
				return invalidRequest("%s has an empty, overlong or repeated check", where)
			}
			checks[c] = true
		}
	}
	return nil
}

// ParseCollectionResult decodes a staged result, a CollectionResult in its
// proto3 JSON mapping, and checks its structure within l (nil: the kit
// defaults): one JSON object without surrounding whitespace, no unknown
// field, at most l.max_evidence evidence items and
// limitations and l.max_subjects supplements, unique item and supplement
// identifiers, at least one unique attribution per item with a valid
// observation time, and bounded text. It does not check attribution
// against an inventory, which is the host's. More items than a bound is
// ERROR_REASON_LIMIT_EXCEEDED; any other violation is
// ERROR_REASON_INVALID_RESPONSE.
func ParseCollectionResult(data []byte, l *providerv1.Limits) (*providerv1.CollectionResult, error) {
	l = NegotiateLimits(l, nil)
	if uint64(len(data)) > l.GetMaxResultBytes() {
		return nil, Errorf(providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED, "result of %d bytes is more than %d", len(data), l.GetMaxResultBytes())
	}
	// Without surrounding whitespace, a capture keeps exactly the staged
	// bytes: a JSON reader does not keep it.
	if len(data) == 0 || data[0] != '{' || data[len(data)-1] != '}' || !jsonObject(data) {
		return nil, invalidResponse("result is not one JSON object without surrounding whitespace")
	}
	r := &providerv1.CollectionResult{}
	if err := (protojson.UnmarshalOptions{RecursionLimit: 64}).Unmarshal(data, r); err != nil {
		return nil, invalidResponse("result is not a CollectionResult: %s", bound(err.Error(), 256))
	}
	switch {
	case uint64(len(r.GetEvidence())) > uint64(l.GetMaxEvidence()):
		return nil, Errorf(providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED, "result has %d evidence items, more than %d", len(r.GetEvidence()), l.GetMaxEvidence())
	case uint64(len(r.GetLimitations())) > uint64(l.GetMaxEvidence()):
		return nil, Errorf(providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED, "result has %d limitations, more than %d", len(r.GetLimitations()), l.GetMaxEvidence())
	case uint64(len(r.GetSupplements())) > uint64(l.GetMaxSubjects()):
		return nil, Errorf(providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED, "result has %d supplements, more than %d", len(r.GetSupplements()), l.GetMaxSubjects())
	}
	text := func(s string) bool { return s != "" && len(s) <= MaxTextBytes }
	ids := map[string]bool{}
	for i, e := range r.GetEvidence() {
		switch {
		case !text(e.GetId()) || ids[e.GetId()]:
			return nil, invalidResponse("evidence %d has an empty, overlong or repeated id", i)
		case len(e.GetAttributions()) == 0 || len(e.GetAttributions()) > MaxAttributions:
			return nil, invalidResponse("evidence %d must have between 1 and %d attributions", i, MaxAttributions)
		case e.GetObserved() == nil || e.GetObserved().CheckValid() != nil:
			return nil, invalidResponse("evidence %d has no valid observation time", i)
		}
		ids[e.GetId()] = true
		pairs := map[[2]string]bool{}
		for j, a := range e.GetAttributions() {
			key := [2]string{a.GetSubject(), a.GetCheck()}
			if !text(a.GetSubject()) || !text(a.GetCheck()) || pairs[key] {
				return nil, invalidResponse("evidence %d attribution %d has an empty, overlong or repeated subject and check", i, j)
			}
			pairs[key] = true
		}
	}
	supplements := map[string]bool{}
	for i, s := range r.GetSupplements() {
		switch {
		case !text(s.GetId()) || supplements[s.GetId()]:
			return nil, invalidResponse("supplement %d has an empty, overlong or repeated id", i)
		case !text(s.GetParent()) || !text(s.GetKind()) || len(s.GetName()) > MaxTextBytes:
			return nil, invalidResponse("supplement %d must name its parent and kind, and a name of at most %d bytes", i, MaxTextBytes)
		}
		supplements[s.GetId()] = true
	}
	for i, lim := range r.GetLimitations() {
		if !text(lim.GetSubject()) || len(lim.GetCheck()) > MaxTextBytes || !text(lim.GetMessage()) {
			return nil, invalidResponse("limitation %d must name a subject and a message of at most %d bytes", i, MaxTextBytes)
		}
	}
	return r, nil
}

// bound truncates s to at most n bytes on a rune boundary.
func bound(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "..."
}
