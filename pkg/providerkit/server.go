package providerkit

import (
	"context"
	"errors"
	"io"
	"slices"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
)

// Collector serves CAPABILITY_COLLECT. Collect reads existing evidence for
// a validated request and stages it as one immutable result in the
// provider's Results. It must not mutate a source or start a scan.
type Collector interface {
	Collect(ctx context.Context, req *providerv1.CollectRequest) (*providerv1.ResultReference, error)
}

// Scanner serves CAPABILITY_SCAN. Start must durably record the request's
// key before starting work, return the original operation for a repeated
// key with the same input digest, and fail with
// ERROR_REASON_OPERATION_CONFLICT for another digest. Cancel is
// idempotent. Unknown operations are ERROR_REASON_NOT_FOUND.
type Scanner interface {
	Start(ctx context.Context, req *providerv1.StartRequest) (*providerv1.Operation, error)
	Get(ctx context.Context, operationID string) (*providerv1.Operation, error)
	Cancel(ctx context.Context, operationID string) (*providerv1.Operation, error)
}

// Results stages immutable results until the host acknowledges them.
// Result returns a result's reference and its complete bytes, which the
// server checks against the reference before sending any; an expired
// result is ERROR_REASON_RESULT_EXPIRED and an unknown one
// ERROR_REASON_NOT_FOUND. Release is called once the host acknowledged a
// result whose size and digest the server matched.
type Results interface {
	Result(ctx context.Context, resultID string) (*providerv1.ResultReference, []byte, error)
	Release(ctx context.Context, resultID string) error
}

// Evaluation is an evaluator's output.
type Evaluation struct {
	Observations []*providerv1.Observation
	// StaleScopes counts scopes whose expected checks are unknown.
	StaleScopes uint32
}

// Evaluator serves CAPABILITY_EVALUATE. Evaluate receives a validated
// start and the complete payload, whose size and digest the server
// verified. It must read nothing else: no source, clock or registry.
type Evaluator interface {
	Evaluate(ctx context.Context, start *providerv1.EvaluateStart, payload []byte) (*Evaluation, error)
}

// Handlers are a provider's implementations. Each capability the
// description declares needs its handlers: Collector and Results for
// CAPABILITY_COLLECT, Scanner and Results for CAPABILITY_SCAN, Evaluator
// for CAPABILITY_EVALUATE. Handlers of undeclared capabilities are never
// called.
type Handlers struct {
	Collector Collector
	Scanner   Scanner
	Results   Results
	Evaluator Evaluator
}

// Server is a providerv1.AssessmentProviderServer that enforces the
// protocol before calling a provider's handlers: every request's header and
// versions, capability, required fields and limits, and every handler
// result. Register it with providerv1.RegisterAssessmentProviderServer on a
// grpc.Server whose transport the deployment configures.
type Server struct {
	providerv1.UnimplementedAssessmentProviderServer
	desc   *providerv1.DescribeResponse
	limits *providerv1.Limits
	h      Handlers
}

// NewServer validates the description and that the handlers cover its
// capabilities. The server's bounds are the stricter of the kit defaults
// and the description's limits.
func NewServer(desc *providerv1.DescribeResponse, h Handlers) (*Server, error) {
	if err := ValidateDescription(desc); err != nil {
		return nil, err
	}
	// Listing another revision would accept that revision's requests,
	// which the kit cannot serve: a revision 1 host would collect without
	// an inventory and read results as opaque payloads.
	if !slices.Equal(desc.GetProtocolVersions(), []uint32{ProtocolVersion}) {
		return nil, Errorf(providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PROTOCOL_VERSION,
			"this kit serves protocol revision %d only; the description lists %v", ProtocolVersion, desc.GetProtocolVersions())
	}
	missing := func(c providerv1.Capability, ok bool) error {
		if slices.Contains(desc.GetCapabilities(), c) && !ok {
			return Errorf(providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST, "%s is declared without its handlers", c)
		}
		return nil
	}
	if err := errors.Join(
		missing(providerv1.Capability_CAPABILITY_COLLECT, h.Collector != nil && h.Results != nil),
		missing(providerv1.Capability_CAPABILITY_SCAN, h.Scanner != nil && h.Results != nil),
		missing(providerv1.Capability_CAPABILITY_EVALUATE, h.Evaluator != nil),
	); err != nil {
		return nil, err
	}
	d := proto.CloneOf(desc)
	return &Server{desc: d, limits: NegotiateLimits(nil, d.GetLimits()), h: h}, nil
}

// Limits are the server's bounds, the TransportLimits.Protocol of its
// transport.
func (s *Server) Limits() *providerv1.Limits { return proto.CloneOf(s.limits) }

func (s *Server) require(capabilities ...providerv1.Capability) error {
	for _, c := range capabilities {
		if slices.Contains(s.desc.GetCapabilities(), c) {
			return nil
		}
	}
	return Errorf(providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CAPABILITY, "provider %s does not serve %v", s.desc.GetProvider().GetName(), capabilities)
}

// Describe returns the description.
func (s *Server) Describe(_ context.Context, req *providerv1.DescribeRequest) (*providerv1.DescribeResponse, error) {
	if err := CheckHeader(req.GetHeader(), s.desc); err != nil {
		return nil, toStatus(err)
	}
	return proto.CloneOf(s.desc), nil
}

// Collect validates and serves a collection.
func (s *Server) Collect(ctx context.Context, req *providerv1.CollectRequest) (*providerv1.CollectResponse, error) {
	ref, err := s.collect(ctx, req)
	if err != nil {
		return nil, toStatus(err)
	}
	return &providerv1.CollectResponse{Result: ref}, nil
}

func (s *Server) collect(ctx context.Context, req *providerv1.CollectRequest) (*providerv1.ResultReference, error) {
	if err := CheckHeader(req.GetHeader(), s.desc); err != nil {
		return nil, err
	}
	if err := s.require(providerv1.Capability_CAPABILITY_COLLECT); err != nil {
		return nil, err
	}
	if err := checkWritePayload(req.GetPayloadVersion(), s.desc); err != nil {
		return nil, err
	}
	if err := errors.Join(checkScope(req.GetScope()), checkTime("collect deadline", req.GetDeadline())); err != nil {
		return nil, err
	}
	if err := CheckInventory(req.GetInventory(), req.GetScope(), s.limits.GetMaxSubjects()); err != nil {
		return nil, err
	}
	ref, err := s.h.Collector.Collect(ctx, req)
	if err != nil {
		return nil, err
	}
	return ref, checkResult(ref, s.desc.GetProvider(), req.GetPayloadVersion(), s.limits.GetMaxResultBytes())
}

// Start validates and serves a scan start.
func (s *Server) Start(ctx context.Context, req *providerv1.StartRequest) (*providerv1.StartResponse, error) {
	op, err := s.start(ctx, req)
	if err != nil {
		return nil, toStatus(err)
	}
	return &providerv1.StartResponse{Operation: op}, nil
}

func (s *Server) start(ctx context.Context, req *providerv1.StartRequest) (*providerv1.Operation, error) {
	if err := CheckHeader(req.GetHeader(), s.desc); err != nil {
		return nil, err
	}
	if err := s.require(providerv1.Capability_CAPABILITY_SCAN); err != nil {
		return nil, err
	}
	if err := checkWritePayload(req.GetPayloadVersion(), s.desc); err != nil {
		return nil, err
	}
	if err := errors.Join(checkScanKey(req.GetKey()), checkScope(req.GetScope()), checkTime("start deadline", req.GetDeadline())); err != nil {
		return nil, err
	}
	if !jsonObject(req.GetInput()) {
		return nil, invalidRequest("start input must be one JSON object")
	}
	if got := Digest(req.GetInput()); got != req.GetKey().GetInputDigest() {
		return nil, Errorf(providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH, "start input digest is %s, the scan key names %s", got, req.GetKey().GetInputDigest())
	}
	op, err := s.h.Scanner.Start(ctx, req)
	if err != nil {
		return nil, err
	}
	return op, s.checkOperation(op, req.GetKey())
}

func (s *Server) checkOperation(op *providerv1.Operation, key *providerv1.ScanKey) error {
	return checkOperation(op, key, s.desc.GetProvider(), s.desc.GetPayload().GetWrite(), s.limits.GetMaxResultBytes())
}

// Get validates and serves an operation read.
func (s *Server) Get(ctx context.Context, req *providerv1.GetRequest) (*providerv1.GetResponse, error) {
	op, err := s.operation(ctx, req.GetHeader(), req.GetOperationId(), func(ctx context.Context, id string) (*providerv1.Operation, error) {
		return s.h.Scanner.Get(ctx, id)
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &providerv1.GetResponse{Operation: op}, nil
}

// Cancel validates and serves a cancellation.
func (s *Server) Cancel(ctx context.Context, req *providerv1.CancelRequest) (*providerv1.CancelResponse, error) {
	op, err := s.operation(ctx, req.GetHeader(), req.GetOperationId(), func(ctx context.Context, id string) (*providerv1.Operation, error) {
		return s.h.Scanner.Cancel(ctx, id)
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &providerv1.CancelResponse{Operation: op}, nil
}

func (s *Server) operation(ctx context.Context, h *providerv1.RequestHeader, id string,
	call func(context.Context, string) (*providerv1.Operation, error)) (*providerv1.Operation, error) {
	if err := CheckHeader(h, s.desc); err != nil {
		return nil, err
	}
	if err := s.require(providerv1.Capability_CAPABILITY_SCAN); err != nil {
		return nil, err
	}
	if err := checkID("operation_id", id); err != nil {
		return nil, err
	}
	op, err := call(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.checkOperation(op, nil); err != nil {
		return nil, err
	}
	if op.GetOperationId() != id {
		return nil, invalidResponse("operation %s returned for %s", op.GetOperationId(), id)
	}
	return op, nil
}

// staged returns a staged result after checking its bytes match its
// reference.
func (s *Server) staged(ctx context.Context, h *providerv1.RequestHeader, id string) (*providerv1.ResultReference, []byte, error) {
	if err := CheckHeader(h, s.desc); err != nil {
		return nil, nil, err
	}
	if err := s.require(providerv1.Capability_CAPABILITY_COLLECT, providerv1.Capability_CAPABILITY_SCAN); err != nil {
		return nil, nil, err
	}
	if err := checkID("result_id", id); err != nil {
		return nil, nil, err
	}
	ref, data, err := s.h.Results.Result(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if err := checkResult(ref, s.desc.GetProvider(), ref.GetPayloadVersion(), s.limits.GetMaxResultBytes()); err != nil {
		return nil, nil, err
	}
	switch {
	case ref.GetResultId() != id:
		return nil, nil, invalidResponse("result %s returned for %s", ref.GetResultId(), id)
	case !slices.Contains(s.desc.GetPayload().GetRead(), ref.GetPayloadVersion()):
		return nil, nil, invalidResponse("result %s has payload version %d, which this provider does not read", id, ref.GetPayloadVersion())
	case uint64(len(data)) != ref.GetSizeBytes() || Digest(data) != ref.GetSha256():
		return nil, nil, Errorf(providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH, "staged bytes of result %s do not match its reference", id)
	}
	// No byte of a staged result that is not a well-formed
	// CollectionResult is sent.
	if _, err := ParseCollectionResult(data, s.limits); err != nil {
		return nil, nil, err
	}
	return ref, data, nil
}

// ReadResult streams a staged result from the requested offset in chunks
// of at most the negotiated chunk size.
func (s *Server) ReadResult(req *providerv1.ReadResultRequest, stream grpc.ServerStreamingServer[providerv1.ReadResultResponse]) error {
	_, data, err := s.staged(stream.Context(), req.GetHeader(), req.GetResultId())
	if err != nil {
		return toStatus(err)
	}
	if req.GetOffset() > uint64(len(data)) {
		return toStatus(invalidRequest("offset %d is beyond result %s of %d bytes", req.GetOffset(), req.GetResultId(), len(data)))
	}
	chunk := uint64(s.limits.GetMaxChunkBytes())
	for off := req.GetOffset(); off < uint64(len(data)); off += chunk {
		end := min(off+chunk, uint64(len(data)))
		if err := stream.Send(&providerv1.ReadResultResponse{Offset: off, Data: data[off:end]}); err != nil {
			return err
		}
	}
	return nil
}

// Acknowledge releases a staged result whose size and digest match.
func (s *Server) Acknowledge(ctx context.Context, req *providerv1.AcknowledgeRequest) (*providerv1.AcknowledgeResponse, error) {
	if err := CheckHeader(req.GetHeader(), s.desc); err != nil {
		return nil, toStatus(err)
	}
	if err := s.require(providerv1.Capability_CAPABILITY_COLLECT, providerv1.Capability_CAPABILITY_SCAN); err != nil {
		return nil, toStatus(err)
	}
	if !digestPattern.MatchString(req.GetSha256()) {
		return nil, toStatus(invalidRequest("acknowledged sha256 %q must be sha256:<64 lowercase hex>", req.GetSha256()))
	}
	ref, _, err := s.staged(ctx, req.GetHeader(), req.GetResultId())
	if err != nil {
		return nil, toStatus(err)
	}
	if req.GetSizeBytes() != ref.GetSizeBytes() || req.GetSha256() != ref.GetSha256() {
		return nil, toStatus(Errorf(providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH,
			"acknowledged %d bytes %s, result %s is %d bytes %s", req.GetSizeBytes(), req.GetSha256(), ref.GetResultId(), ref.GetSizeBytes(), ref.GetSha256()))
	}
	if err := s.h.Results.Release(ctx, ref.GetResultId()); err != nil {
		return nil, toStatus(err)
	}
	return &providerv1.AcknowledgeResponse{}, nil
}

// CheckEvaluateStart checks an evaluation's opening message against the
// description: header, capability, evaluator version, payload version,
// then the remaining fields and the payload size bound.
func (s *Server) CheckEvaluateStart(start *providerv1.EvaluateStart) error {
	if start == nil {
		return invalidRequest("evaluation does not open with a start")
	}
	if err := CheckHeader(start.GetHeader(), s.desc); err != nil {
		return err
	}
	if err := s.require(providerv1.Capability_CAPABILITY_EVALUATE); err != nil {
		return err
	}
	if start.GetEvaluatorVersion() != s.desc.GetEvaluatorVersion() {
		return Errorf(providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_EVALUATOR_VERSION,
			"evaluator version %d is not this provider's %d", start.GetEvaluatorVersion(), s.desc.GetEvaluatorVersion())
	}
	if !slices.Contains(s.desc.GetPayload().GetRead(), start.GetPayloadVersion()) {
		return Errorf(providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PAYLOAD_VERSION,
			"payload version %d is not one this provider reads (%v)", start.GetPayloadVersion(), s.desc.GetPayload().GetRead())
	}
	if start.GetPayloadSizeBytes() > s.limits.GetMaxResultBytes() {
		return Errorf(providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED, "payload of %d bytes is more than %d", start.GetPayloadSizeBytes(), s.limits.GetMaxResultBytes())
	}
	if !digestPattern.MatchString(start.GetPayloadSha256()) {
		return invalidRequest("payload_sha256 %q must be sha256:<64 lowercase hex>", start.GetPayloadSha256())
	}
	if err := errors.Join(checkTime("evaluation_time", start.GetEvaluationTime()), checkScope(start.GetScope())); err != nil {
		return err
	}
	kinds := map[string]bool{}
	for _, k := range s.desc.GetChecks() {
		kinds[k.GetKind()] = true
	}
	for _, c := range start.GetContent() {
		if c.GetBundle() == "" || !digestPattern.MatchString(c.GetManifestDigest()) {
			return invalidRequest("content reference %q@%q must name a bundle and its sha256 manifest digest", c.GetBundle(), c.GetManifestDigest())
		}
	}
	seen := map[[2]string]bool{}
	for _, c := range start.GetChecks() {
		key := [2]string{c.GetKind(), c.GetName()}
		switch {
		case !kinds[c.GetKind()]:
			return invalidRequest("check %q has kind %q, which this provider does not evaluate", c.GetName(), c.GetKind())
		case c.GetName() == "" || seen[key]:
			return invalidRequest("check %q of kind %q must be named and unique", c.GetName(), c.GetKind())
		case !jsonObject(c.GetDefinition()):
			return invalidRequest("check %q definition must be one JSON object", c.GetName())
		case len(c.GetParameters()) > 0 && !jsonObject(c.GetParameters()):
			return invalidRequest("check %q parameters must be one JSON object", c.GetName())
		}
		seen[key] = true
	}
	return nil
}

// Evaluate receives a start and the payload chunks, verifies them, runs
// the evaluator and streams its observations and summary.
func (s *Server) Evaluate(stream grpc.BidiStreamingServer[providerv1.EvaluateRequest, providerv1.EvaluateResponse]) error {
	ctx := stream.Context()
	start, payload, err := s.receiveEvaluation(stream)
	if err != nil {
		return toStatus(err)
	}
	ev, err := s.h.Evaluator.Evaluate(ctx, start, payload)
	if err != nil {
		return toStatus(err)
	}
	if ev == nil {
		return toStatus(invalidResponse("evaluator returned no evaluation"))
	}
	if err := checkObservations(ev.Observations, s.limits.GetMaxObservations()); err != nil {
		return toStatus(err)
	}
	if err := sendObservations(stream, ev.Observations, s.limits.GetMaxChunkBytes()); err != nil {
		return err
	}
	return stream.Send(&providerv1.EvaluateResponse{Part: &providerv1.EvaluateResponse_Summary{Summary: &providerv1.EvaluationSummary{
		Provider: proto.CloneOf(s.desc.GetProvider()), EvaluatorVersion: s.desc.GetEvaluatorVersion(),
		ObservationCount: uint32(len(ev.Observations)), StaleScopes: ev.StaleScopes,
	}}})
}

func (s *Server) receiveEvaluation(stream grpc.BidiStreamingServer[providerv1.EvaluateRequest, providerv1.EvaluateResponse]) (*providerv1.EvaluateStart, []byte, error) {
	first, err := stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil, invalidRequest("evaluation stream is empty")
		}
		return nil, nil, streamError(stream.Context(), err)
	}
	start := first.GetStart()
	if err := s.CheckEvaluateStart(start); err != nil {
		return nil, nil, err
	}
	size := start.GetPayloadSizeBytes()
	// Grow with what arrives, never by the declared size alone.
	var payload []byte
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, streamError(stream.Context(), err)
		}
		chunk, ok := msg.GetPart().(*providerv1.EvaluateRequest_PayloadChunk)
		switch {
		case !ok:
			return nil, nil, invalidRequest("only the first evaluation message is a start; later ones are payload chunks")
		case uint64(len(chunk.PayloadChunk)) > uint64(s.limits.GetMaxChunkBytes()):
			return nil, nil, Errorf(providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED, "payload chunk of %d bytes is more than %d", len(chunk.PayloadChunk), s.limits.GetMaxChunkBytes())
		case uint64(len(payload))+uint64(len(chunk.PayloadChunk)) > size:
			return nil, nil, Errorf(providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH, "payload is longer than the declared %d bytes", size)
		}
		payload = append(payload, chunk.PayloadChunk...)
	}
	if uint64(len(payload)) != size || Digest(payload) != start.GetPayloadSha256() {
		return nil, nil, Errorf(providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH, "received payload of %d bytes does not match the declared %d bytes %s", len(payload), size, start.GetPayloadSha256())
	}
	if !jsonObject(payload) {
		return nil, nil, invalidRequest("payload must be one JSON object")
	}
	return start, payload, nil
}

// streamError is a receive error: the call's own end (the host's
// deadline or cancellation) when the call ended, otherwise err.
func streamError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// sendObservations sends observations in batches whose encoding stays
// within the chunk bound.
func sendObservations(stream grpc.BidiStreamingServer[providerv1.EvaluateRequest, providerv1.EvaluateResponse], obs []*providerv1.Observation, chunk uint32) error {
	var batch []*providerv1.Observation
	size := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := stream.Send(&providerv1.EvaluateResponse{Part: &providerv1.EvaluateResponse_Observations{Observations: &providerv1.ObservationBatch{Observations: batch}}})
		batch, size = nil, 0
		return err
	}
	for _, o := range obs {
		n := proto.Size(o) + 8
		if size+n > int(chunk) {
			if err := flush(); err != nil {
				return err
			}
		}
		batch = append(batch, o)
		size += n
	}
	return flush()
}
