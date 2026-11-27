package providerkit

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
)

// Client is a host's view of one provider endpoint. It describes the
// endpoint once, checks the description against the registration's
// Compatibility, and then sends only requests the description and the
// registration both allow, with the expected header. It checks every
// response against the protocol and verifies transferred bytes against
// their size and digest. The connection's transport and peer
// authentication are the caller's.
type Client struct {
	rpc  providerv1.AssessmentProviderClient
	want Compatibility
	host *providerv1.Limits

	mu     sync.Mutex
	desc   *providerv1.DescribeResponse
	limits *providerv1.Limits
}

// NewClient returns a client for conn. host are the host's bounds; zero
// fields use the kit defaults.
func NewClient(conn grpc.ClientConnInterface, want Compatibility, host *providerv1.Limits) (*Client, error) {
	if err := want.Validate(); err != nil {
		return nil, err
	}
	want.Capabilities = slices.Clone(want.Capabilities)
	return &Client{rpc: providerv1.NewAssessmentProviderClient(conn), want: want, host: proto.CloneOf(host)}, nil
}

// Describe describes the endpoint and checks the description against the
// expected compatibility. A compatible description is kept for later
// calls; an incompatible one is returned as the dimension's *Error and
// blocks every other call.
func (c *Client) Describe(ctx context.Context) (*providerv1.DescribeResponse, error) {
	d, err := c.rpc.Describe(ctx, &providerv1.DescribeRequest{Header: c.want.Header()})
	if err != nil {
		return nil, fromStatus(ctx, err)
	}
	if err := CheckCompatibility(c.want, d); err != nil {
		c.mu.Lock()
		c.desc, c.limits = nil, nil
		c.mu.Unlock()
		return nil, err
	}
	c.mu.Lock()
	c.desc, c.limits = d, NegotiateLimits(c.host, d.GetLimits())
	c.mu.Unlock()
	return proto.CloneOf(d), nil
}

// Limits are the negotiated bounds, after a compatible Describe.
func (c *Client) Limits() *providerv1.Limits {
	c.mu.Lock()
	defer c.mu.Unlock()
	return proto.CloneOf(c.limits)
}

// described returns the description, describing first if needed, after
// checking that the registration allows and the endpoint serves one of the
// capabilities.
func (c *Client) described(ctx context.Context, capabilities ...providerv1.Capability) (*providerv1.DescribeResponse, *providerv1.Limits, error) {
	c.mu.Lock()
	d, l := c.desc, c.limits
	c.mu.Unlock()
	if d == nil {
		if _, err := c.Describe(ctx); err != nil {
			return nil, nil, err
		}
		c.mu.Lock()
		d, l = c.desc, c.limits
		c.mu.Unlock()
	}
	for _, capability := range capabilities {
		if c.want.allows(capability) && slices.Contains(d.GetCapabilities(), capability) {
			return d, l, nil
		}
	}
	return nil, nil, Errorf(providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CAPABILITY,
		"the registration of %s does not allow %v, or the endpoint does not serve it", c.want.Provider, capabilities)
}

func (c *Client) contract() *providerv1.ProviderContract { return c.want.Header().GetProvider() }

// Collect asks the provider to collect existing evidence for scope against
// the host-frozen inventory and returns the checked reference of the staged
// result. An inventory with more subjects than the negotiated bound is
// ERROR_REASON_LIMIT_EXCEEDED and is never sent, or truncated.
func (c *Client) Collect(ctx context.Context, scope *providerv1.Scope, inventory *providerv1.Inventory, deadline time.Time) (*providerv1.ResultReference, error) {
	_, l, err := c.described(ctx, providerv1.Capability_CAPABILITY_COLLECT)
	if err != nil {
		return nil, err
	}
	if err := checkScope(scope); err != nil {
		return nil, err
	}
	if deadline.IsZero() {
		return nil, invalidRequest("collect needs a deadline")
	}
	if err := CheckInventory(inventory, scope, l.GetMaxSubjects()); err != nil {
		return nil, err
	}
	resp, err := c.rpc.Collect(ctx, &providerv1.CollectRequest{Header: c.want.Header(), Scope: scope, Inventory: inventory,
		PayloadVersion: c.want.PayloadVersion, Deadline: timestamppb.New(deadline)})
	if err != nil {
		return nil, fromStatus(ctx, err)
	}
	ref := resp.GetResult()
	return ref, checkResult(ref, c.contract(), c.want.PayloadVersion, l.GetMaxResultBytes())
}

// Start starts, or resumes, the scan identified by key. The key's
// input_digest must be Digest(input); a mismatch is refused before any
// request.
func (c *Client) Start(ctx context.Context, key *providerv1.ScanKey, scope *providerv1.Scope, input []byte, deadline time.Time) (*providerv1.Operation, error) {
	_, l, err := c.described(ctx, providerv1.Capability_CAPABILITY_SCAN)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(checkScanKey(key), checkScope(scope)); err != nil {
		return nil, err
	}
	if !jsonObject(input) {
		return nil, invalidRequest("start input must be one JSON object")
	}
	if deadline.IsZero() {
		return nil, invalidRequest("start needs a deadline")
	}
	if Digest(input) != key.GetInputDigest() {
		return nil, Errorf(providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH, "start input digest is %s, the scan key names %s", Digest(input), key.GetInputDigest())
	}
	resp, err := c.rpc.Start(ctx, &providerv1.StartRequest{Header: c.want.Header(), Key: key, Scope: scope, Input: input,
		PayloadVersion: c.want.PayloadVersion, Deadline: timestamppb.New(deadline)})
	if err != nil {
		return nil, fromStatus(ctx, err)
	}
	op := resp.GetOperation()
	return op, checkOperation(op, key, c.contract(), c.want.PayloadVersion, l.GetMaxResultBytes())
}

// Get returns a scan operation's checked state.
func (c *Client) Get(ctx context.Context, operationID string) (*providerv1.Operation, error) {
	return c.operation(ctx, operationID, func(h *providerv1.RequestHeader) (*providerv1.Operation, error) {
		resp, err := c.rpc.Get(ctx, &providerv1.GetRequest{Header: h, OperationId: operationID})
		return resp.GetOperation(), err
	})
}

// Cancel requests a scan operation's cancellation and returns its checked
// state.
func (c *Client) Cancel(ctx context.Context, operationID string) (*providerv1.Operation, error) {
	return c.operation(ctx, operationID, func(h *providerv1.RequestHeader) (*providerv1.Operation, error) {
		resp, err := c.rpc.Cancel(ctx, &providerv1.CancelRequest{Header: h, OperationId: operationID})
		return resp.GetOperation(), err
	})
}

func (c *Client) operation(ctx context.Context, id string, call func(*providerv1.RequestHeader) (*providerv1.Operation, error)) (*providerv1.Operation, error) {
	_, l, err := c.described(ctx, providerv1.Capability_CAPABILITY_SCAN)
	if err != nil {
		return nil, err
	}
	if err := checkID("operation_id", id); err != nil {
		return nil, err
	}
	op, err := call(c.want.Header())
	if err != nil {
		return nil, fromStatus(ctx, err)
	}
	if err := checkOperation(op, nil, c.contract(), c.want.PayloadVersion, l.GetMaxResultBytes()); err != nil {
		return nil, err
	}
	if op.GetOperationId() != id {
		return nil, invalidResponse("operation %s returned for %s", op.GetOperationId(), id)
	}
	return op, nil
}

// ReadResult transfers a result from the start.
func (c *Client) ReadResult(ctx context.Context, ref *providerv1.ResultReference) ([]byte, error) {
	return c.ResumeResult(ctx, ref, nil)
}

// ReadCollection transfers a result from the start and returns its bytes
// with the decoded CollectionResult, checked as ParseCollectionResult
// checks it within the negotiated bounds.
func (c *Client) ReadCollection(ctx context.Context, ref *providerv1.ResultReference) ([]byte, *providerv1.CollectionResult, error) {
	data, err := c.resume(ctx, ref, nil)
	if err != nil {
		return nil, nil, err
	}
	res, err := ParseCollectionResult(data, c.Limits())
	if err != nil {
		return nil, nil, err
	}
	return data, res, nil
}

// ResumeResult continues a transfer after the bytes already received. It
// returns the complete result once its size and digest match ref and it is
// a well-formed CollectionResult (ParseCollectionResult). On an
// interrupted stream it returns the bytes received so far with the error,
// so the caller can resume again; on any protocol violation it returns no
// bytes. The reference must be one a checked response returned for the
// registration's payload version.
func (c *Client) ResumeResult(ctx context.Context, ref *providerv1.ResultReference, have []byte) ([]byte, error) {
	data, err := c.resume(ctx, ref, have)
	if err != nil {
		return data, err
	}
	if _, err := ParseCollectionResult(data, c.Limits()); err != nil {
		return nil, err
	}
	return data, nil
}

func (c *Client) resume(ctx context.Context, ref *providerv1.ResultReference, have []byte) ([]byte, error) {
	_, l, err := c.described(ctx, providerv1.Capability_CAPABILITY_COLLECT, providerv1.Capability_CAPABILITY_SCAN)
	if err != nil {
		return nil, err
	}
	if err := checkResult(ref, c.contract(), c.want.PayloadVersion, l.GetMaxResultBytes()); err != nil {
		return nil, err
	}
	size := ref.GetSizeBytes()
	if uint64(len(have)) > size {
		return nil, invalidRequest("already have %d bytes of result %s of %d bytes", len(have), ref.GetResultId(), size)
	}
	data := slices.Clone(have)
	if uint64(len(data)) < size {
		// A violation returns early: end the stream with it.
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stream, err := c.rpc.ReadResult(ctx, &providerv1.ReadResultRequest{Header: c.want.Header(), ResultId: ref.GetResultId(), Offset: uint64(len(data))})
		if err != nil {
			return data, fromStatus(ctx, err)
		}
		for {
			msg, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return data, fromStatus(ctx, err)
			}
			switch {
			case msg.GetOffset() != uint64(len(data)):
				return nil, invalidResponse("result %s chunk at offset %d, expected %d", ref.GetResultId(), msg.GetOffset(), len(data))
			case len(msg.GetData()) == 0 || uint64(len(msg.GetData())) > uint64(l.GetMaxChunkBytes()):
				return nil, Errorf(providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED, "result %s chunk of %d bytes is empty or more than %d", ref.GetResultId(), len(msg.GetData()), l.GetMaxChunkBytes())
			case uint64(len(data))+uint64(len(msg.GetData())) > size:
				return nil, Errorf(providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH, "result %s is longer than its %d bytes", ref.GetResultId(), size)
			}
			data = append(data, msg.GetData()...)
		}
	}
	if uint64(len(data)) != size {
		return data, Errorf(providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH, "result %s ended after %d of %d bytes", ref.GetResultId(), len(data), size)
	}
	if Digest(data) != ref.GetSha256() {
		return nil, Errorf(providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH, "result %s bytes have digest %s, not %s", ref.GetResultId(), Digest(data), ref.GetSha256())
	}
	if !jsonObject(data) {
		return nil, invalidResponse("result %s is not one JSON object", ref.GetResultId())
	}
	return data, nil
}

// Acknowledge confirms durable capture of a result's bytes. Call it only
// after the host's capture is durable; the provider may then release it.
func (c *Client) Acknowledge(ctx context.Context, ref *providerv1.ResultReference) error {
	if _, _, err := c.described(ctx, providerv1.Capability_CAPABILITY_COLLECT, providerv1.Capability_CAPABILITY_SCAN); err != nil {
		return err
	}
	if err := checkID("result_id", ref.GetResultId()); err != nil {
		return err
	}
	if !digestPattern.MatchString(ref.GetSha256()) {
		return invalidRequest("result %s sha256 %q must be sha256:<64 lowercase hex>", ref.GetResultId(), ref.GetSha256())
	}
	_, err := c.rpc.Acknowledge(ctx, &providerv1.AcknowledgeRequest{Header: c.want.Header(), ResultId: ref.GetResultId(),
		SizeBytes: ref.GetSizeBytes(), Sha256: ref.GetSha256()})
	return fromStatus(ctx, err)
}

// EvaluateInput is one evaluation's frozen input. PayloadVersion and
// EvaluatorVersion are those the capture records; a capture of an
// evaluator version the endpoint does not serve, or a payload version it
// does not read, is refused before any request.
type EvaluateInput struct {
	PayloadVersion   uint32
	EvaluatorVersion uint32
	Payload          []byte
	At               time.Time
	Scope            *providerv1.Scope
	Content          []*providerv1.ContentReference
	Checks           []*providerv1.CheckDefinition
}

// Evaluate evaluates a frozen payload and returns the checked evaluation.
func (c *Client) Evaluate(ctx context.Context, in EvaluateInput) (*Evaluation, error) {
	d, l, err := c.described(ctx, providerv1.Capability_CAPABILITY_EVALUATE)
	if err != nil {
		return nil, err
	}
	switch {
	case in.EvaluatorVersion != d.GetEvaluatorVersion():
		return nil, Errorf(providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_EVALUATOR_VERSION,
			"capture was evaluated with evaluator version %d; the endpoint serves %d", in.EvaluatorVersion, d.GetEvaluatorVersion())
	case !slices.Contains(d.GetPayload().GetRead(), in.PayloadVersion):
		return nil, Errorf(providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PAYLOAD_VERSION,
			"capture payload version %d is not one the endpoint reads (%v)", in.PayloadVersion, d.GetPayload().GetRead())
	case uint64(len(in.Payload)) > l.GetMaxResultBytes():
		return nil, Errorf(providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED, "payload of %d bytes is more than %d", len(in.Payload), l.GetMaxResultBytes())
	case !jsonObject(in.Payload):
		return nil, invalidRequest("payload must be one JSON object")
	case in.At.IsZero():
		return nil, invalidRequest("evaluation needs an explicit evaluation time")
	}
	if err := checkScope(in.Scope); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := c.rpc.Evaluate(ctx)
	if err != nil {
		return nil, fromStatus(ctx, err)
	}
	start := &providerv1.EvaluateStart{Header: c.want.Header(), EvaluatorVersion: in.EvaluatorVersion, PayloadVersion: in.PayloadVersion,
		PayloadSizeBytes: uint64(len(in.Payload)), PayloadSha256: Digest(in.Payload), EvaluationTime: timestamppb.New(in.At),
		Scope: in.Scope, Content: in.Content, Checks: in.Checks}
	// A provider that rejects the evaluation ends the stream: Send then
	// reports io.EOF, and Recv returns the provider's status.
	if err := c.sendEvaluation(stream, start, in.Payload, int(l.GetMaxChunkBytes())); err != nil && !errors.Is(err, io.EOF) {
		return nil, fromStatus(ctx, err)
	}
	return c.receiveEvaluation(ctx, stream, d, l)
}

func (c *Client) sendEvaluation(stream grpc.BidiStreamingClient[providerv1.EvaluateRequest, providerv1.EvaluateResponse],
	start *providerv1.EvaluateStart, payload []byte, chunk int) error {
	if err := stream.Send(&providerv1.EvaluateRequest{Part: &providerv1.EvaluateRequest_Start{Start: start}}); err != nil {
		return err
	}
	for off := 0; off < len(payload); off += chunk {
		part := payload[off:min(off+chunk, len(payload))]
		if err := stream.Send(&providerv1.EvaluateRequest{Part: &providerv1.EvaluateRequest_PayloadChunk{PayloadChunk: part}}); err != nil {
			return err
		}
	}
	return stream.CloseSend()
}

func (c *Client) receiveEvaluation(ctx context.Context, stream grpc.BidiStreamingClient[providerv1.EvaluateRequest, providerv1.EvaluateResponse],
	d *providerv1.DescribeResponse, l *providerv1.Limits) (*Evaluation, error) {
	var obs []*providerv1.Observation
	var summary *providerv1.EvaluationSummary
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fromStatus(ctx, err)
		}
		if summary != nil {
			return nil, invalidResponse("evaluation sent a message after its summary")
		}
		switch part := msg.GetPart().(type) {
		case *providerv1.EvaluateResponse_Observations:
			obs = append(obs, part.Observations.GetObservations()...)
			if uint64(len(obs)) > uint64(l.GetMaxObservations()) {
				return nil, Errorf(providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED, "evaluation has more than %d observations", l.GetMaxObservations())
			}
		case *providerv1.EvaluateResponse_Summary:
			summary = part.Summary
		default:
			return nil, invalidResponse("evaluation sent an empty message")
		}
	}
	switch {
	case summary == nil:
		return nil, invalidResponse("evaluation ended without a summary")
	case !proto.Equal(summary.GetProvider(), d.GetProvider()) || summary.GetEvaluatorVersion() != d.GetEvaluatorVersion():
		return nil, invalidResponse("evaluation summary names %s/v%d evaluator %d, not the described %s/v%d evaluator %d",
			summary.GetProvider().GetName(), summary.GetProvider().GetVersion(), summary.GetEvaluatorVersion(),
			d.GetProvider().GetName(), d.GetProvider().GetVersion(), d.GetEvaluatorVersion())
	case uint64(summary.GetObservationCount()) != uint64(len(obs)):
		return nil, invalidResponse("evaluation summary counts %d observations, %d were sent", summary.GetObservationCount(), len(obs))
	}
	if err := checkObservations(obs, l.GetMaxObservations()); err != nil {
		return nil, err
	}
	return &Evaluation{Observations: obs, StaleScopes: summary.GetStaleScopes()}, nil
}
