package providerkit

import (
	"context"
	"errors"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
)

// These tests run the kit over an in-memory gRPC connection without
// transport security; transport_test.go runs it over mutual TLS.

var (
	testScope = &providerv1.Scope{Cluster: "cluster-uid", Namespaces: []*providerv1.Namespace{{Name: "team-a", Uid: "ns-a-uid"}}}
	testAt    = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	testWant  = Compatibility{Provider: "example-reporting", ContractVersion: 2, PayloadVersion: 3, EvaluatorVersion: 5,
		Capabilities: []providerv1.Capability{providerv1.Capability_CAPABILITY_COLLECT, providerv1.Capability_CAPABILITY_EVALUATE}}
)

func testDescription(caps ...providerv1.Capability) *providerv1.DescribeResponse {
	if len(caps) == 0 {
		caps = testWant.Capabilities
	}
	return &providerv1.DescribeResponse{
		Provider:         &providerv1.ProviderContract{Name: "example-reporting", Version: 2},
		ProtocolVersions: []uint32{1}, EvaluatorVersion: 5,
		Payload:      &providerv1.PayloadCompatibility{Write: 3, Read: []uint32{2, 3}},
		Capabilities: caps,
		Checks:       []*providerv1.CheckKind{{Kind: "reporting.example.io/v1/Posture"}},
		Limits:       &providerv1.Limits{MaxChunkBytes: 4},
	}
}

// calls records the methods a client invoked.
type calls struct {
	mu      sync.Mutex
	methods []string
}

func (c *calls) record(method string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.methods = append(c.methods, method[strings.LastIndex(method, "/")+1:])
}

func (c *calls) get() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.methods...)
}

func connect(t *testing.T, srv providerv1.AssessmentProviderServer) (*grpc.ClientConn, *calls) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	s := grpc.NewServer()
	providerv1.RegisterAssessmentProviderServer(s, srv)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	rec := &calls{}
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			rec.record(method)
			return invoker(ctx, method, req, reply, cc, opts...)
		}),
		grpc.WithStreamInterceptor(func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			rec.record(method)
			return streamer(ctx, desc, cc, method, opts...)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, rec
}

func wantReason(t *testing.T, err error, reason providerv1.ErrorReason) {
	t.Helper()
	if got := ReasonOf(err); got != reason {
		t.Fatalf("got %v (reason %s), want reason %s", err, got, reason)
	}
}

// fakeProvider is a minimal in-memory reporting provider.
type fakeProvider struct {
	referenceHandlers
	observations []*providerv1.Observation
	evaluated    []byte
	collectErr   error
	badRef       func(*providerv1.ResultReference)
}

func newFake(d *providerv1.DescribeResponse, payload string) *fakeProvider {
	return &fakeProvider{referenceHandlers: referenceHandlers{desc: d, staged: map[string][]byte{"result-1": []byte(payload)}}}
}

func (f *fakeProvider) Collect(ctx context.Context, req *providerv1.CollectRequest) (*providerv1.ResultReference, error) {
	if f.collectErr != nil {
		return nil, f.collectErr
	}
	ref, _ := f.referenceHandlers.Collect(ctx, req)
	if f.badRef != nil {
		f.badRef(ref)
	}
	return ref, nil
}

func (f *fakeProvider) Evaluate(_ context.Context, _ *providerv1.EvaluateStart, payload []byte) (*Evaluation, error) {
	f.evaluated = payload
	return &Evaluation{Observations: f.observations, StaleScopes: 1}, nil
}

func kitServer(t *testing.T, f *fakeProvider) *Server {
	t.Helper()
	h := Handlers{Collector: f, Results: f, Evaluator: f}
	if containsCapability(f.desc, providerv1.Capability_CAPABILITY_SCAN) {
		h.Scanner = f
	}
	s, err := NewServer(f.desc, h)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func containsCapability(d *providerv1.DescribeResponse, c providerv1.Capability) bool {
	for _, x := range d.GetCapabilities() {
		if x == c {
			return true
		}
	}
	return false
}

func attributable(subject string) *providerv1.Observation {
	return &providerv1.Observation{Subject: subject, Check: "posture", State: providerv1.EvidenceState_EVIDENCE_STATE_ATTRIBUTABLE,
		Raw: "PASSED", Outcome: providerv1.Outcome_OUTCOME_PASS, Evaluated: timestamppb.New(testAt.Add(-time.Minute))}
}

func TestReportingRoundTrip(t *testing.T) {
	const payload = `{"reports":[{"image":"sha256:abc","verdict":"PASSED"}]}`
	f := newFake(testDescription(), payload)
	f.observations = []*providerv1.Observation{attributable("w1"), attributable("w2"),
		{Subject: "w3", Check: "posture", State: providerv1.EvidenceState_EVIDENCE_STATE_MISSING}}
	conn, rec := connect(t, kitServer(t, f))
	c, err := NewClient(conn, testWant, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.Describe(ctx); err != nil {
		t.Fatal(err)
	}
	if got := c.Limits(); got.GetMaxChunkBytes() != 4 || got.GetMaxResultBytes() != DefaultMaxResultBytes || got.GetMaxObservations() != DefaultMaxObservations {
		t.Fatalf("negotiated limits %v", got)
	}
	ref, err := c.Collect(ctx, testScope, []byte(`{"subjects":[]}`), testAt)
	if err != nil {
		t.Fatal(err)
	}
	data, err := c.ReadResult(ctx, ref)
	if err != nil || string(data) != payload {
		t.Fatalf("read %q, %v", data, err)
	}
	// A resumed transfer continues after the bytes already held.
	resumed, err := c.ResumeResult(ctx, ref, data[:9])
	if err != nil || string(resumed) != payload {
		t.Fatalf("resumed %q, %v", resumed, err)
	}
	if err := c.Acknowledge(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if len(f.release) != 1 || f.release[0] != "result-1" {
		t.Fatalf("released %v", f.release)
	}
	ev, err := c.Evaluate(ctx, EvaluateInput{PayloadVersion: 2, EvaluatorVersion: 5, Payload: []byte(payload), At: testAt, Scope: testScope,
		Checks: []*providerv1.CheckDefinition{{Kind: "reporting.example.io/v1/Posture", Name: "posture", Definition: []byte(`{}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	if string(f.evaluated) != payload || len(ev.Observations) != 3 || ev.StaleScopes != 1 {
		t.Fatalf("evaluated %q into %v", f.evaluated, ev)
	}
	if got := strings.Join(rec.get(), ","); got != "Describe,Collect,ReadResult,ReadResult,Acknowledge,Evaluate" {
		t.Fatalf("calls %s", got)
	}
}

func TestClientRefusesBeforeSending(t *testing.T) {
	f := newFake(testDescription(), `{}`)
	conn, rec := connect(t, kitServer(t, f))
	c, err := NewClient(conn, testWant, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	in := []byte(`{"checks":["posture"]}`)
	key := &providerv1.ScanKey{RunUid: "run", RegistrationUid: "registration", RegistrationRevision: 1, InputDigest: Digest(in)}
	_, err = c.Start(ctx, key, testScope, in, testAt)
	wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CAPABILITY)
	_, err = c.Get(ctx, "operation-1")
	wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CAPABILITY)

	eval := EvaluateInput{PayloadVersion: 3, EvaluatorVersion: 4, Payload: []byte(`{}`), At: testAt, Scope: testScope}
	_, err = c.Evaluate(ctx, eval)
	wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_EVALUATOR_VERSION)
	eval.EvaluatorVersion, eval.PayloadVersion = 5, 5
	_, err = c.Evaluate(ctx, eval)
	wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PAYLOAD_VERSION)
	eval.PayloadVersion, eval.At = 3, time.Time{}
	_, err = c.Evaluate(ctx, eval)
	wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST)

	if got := strings.Join(rec.get(), ","); got != "Describe" {
		t.Fatalf("calls %s: a refused request must not be sent", got)
	}
}

func TestScanClientChecksInputDigestBeforeSending(t *testing.T) {
	d := testDescription(providerv1.Capability_CAPABILITY_COLLECT, providerv1.Capability_CAPABILITY_SCAN, providerv1.Capability_CAPABILITY_EVALUATE)
	f := newFake(d, `{}`)
	conn, rec := connect(t, kitServer(t, f))
	want := testWant
	want.Capabilities = d.GetCapabilities()
	c, err := NewClient(conn, want, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	in := []byte(`{"checks":["posture"]}`)
	key := &providerv1.ScanKey{RunUid: "run", RegistrationUid: "registration", RegistrationRevision: 1, InputDigest: Digest([]byte(`{}`))}
	_, err = c.Start(ctx, key, testScope, in, testAt)
	wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH)
	key.InputDigest = Digest(in)
	op, err := c.Start(ctx, key, testScope, in, testAt)
	if err != nil || !proto.Equal(op.GetKey(), key) {
		t.Fatalf("start %v, %v", op, err)
	}
	if got := strings.Join(rec.get(), ","); got != "Describe,Start" {
		t.Fatalf("calls %s", got)
	}
}

func TestIncompatibleDescriptionBlocksEveryCall(t *testing.T) {
	d := testDescription()
	d.EvaluatorVersion = 6
	conn, rec := connect(t, kitServer(t, newFake(d, `{}`)))
	c, err := NewClient(conn, testWant, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, err = c.Describe(ctx)
	wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_EVALUATOR_VERSION)
	_, err = c.Collect(ctx, testScope, nil, testAt)
	wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_EVALUATOR_VERSION)
	if got := strings.Join(rec.get(), ","); got != "Describe,Describe" {
		t.Fatalf("calls %s: no payload request may follow an incompatible description", got)
	}
}

func TestServerRejectsEvaluationStreams(t *testing.T) {
	f := newFake(testDescription(), `{}`)
	conn, _ := connect(t, kitServer(t, f))
	raw := providerv1.NewAssessmentProviderClient(conn)
	payload := []byte(`{"reports":[]}`)
	start := func() *providerv1.EvaluateStart {
		return &providerv1.EvaluateStart{Header: testWant.Header(), EvaluatorVersion: 5, PayloadVersion: 3,
			PayloadSizeBytes: uint64(len(payload)), PayloadSha256: Digest(payload), EvaluationTime: timestamppb.New(testAt), Scope: testScope}
	}
	run := func(msgs ...*providerv1.EvaluateRequest) error {
		ctx := context.Background()
		s, err := raw.Evaluate(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range msgs {
			_ = s.Send(m)
		}
		_ = s.CloseSend()
		for {
			if _, err := s.Recv(); err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return fromStatus(ctx, err)
			}
		}
	}
	startMsg := func(st *providerv1.EvaluateStart) *providerv1.EvaluateRequest {
		return &providerv1.EvaluateRequest{Part: &providerv1.EvaluateRequest_Start{Start: st}}
	}
	chunk := func(b []byte) *providerv1.EvaluateRequest {
		return &providerv1.EvaluateRequest{Part: &providerv1.EvaluateRequest_PayloadChunk{PayloadChunk: b}}
	}
	chunks := func(b []byte) []*providerv1.EvaluateRequest {
		var out []*providerv1.EvaluateRequest
		for i := 0; i < len(b); i += 4 {
			out = append(out, chunk(b[i:min(i+4, len(b))]))
		}
		return out
	}
	if err := run(append([]*providerv1.EvaluateRequest{startMsg(start())}, chunks(payload)...)...); err != nil {
		t.Fatalf("valid evaluation: %v", err)
	}
	old := start()
	old.EvaluatorVersion = 4
	wantReason(t, run(startMsg(old)), providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_EVALUATOR_VERSION)
	wantReason(t, run(chunk(payload)), providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST)
	wantReason(t, run(startMsg(start()), chunk(payload)), providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED)
	wantReason(t, run(append([]*providerv1.EvaluateRequest{startMsg(start())}, chunks(payload[:8])...)...), providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH)
	tampered := append([]byte(nil), payload...)
	tampered[3] = 'X'
	wantReason(t, run(append([]*providerv1.EvaluateRequest{startMsg(start())}, chunks(tampered)...)...), providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH)
	twice := append([]*providerv1.EvaluateRequest{startMsg(start())}, chunks(payload)...)
	wantReason(t, run(append(twice, startMsg(start()))...), providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST)
	if f.evaluated == nil {
		t.Fatal("the valid evaluation did not reach the evaluator")
	}
}

func TestServerChecksHandlerOutputs(t *testing.T) {
	ctx := context.Background()
	collect := &providerv1.CollectRequest{Header: testWant.Header(), Scope: testScope, PayloadVersion: 3, Deadline: timestamppb.New(testAt)}
	for name, mutate := range map[string]func(*providerv1.ResultReference){
		"other payload version": func(r *providerv1.ResultReference) { r.PayloadVersion = 2 },
		"other provider": func(r *providerv1.ResultReference) {
			r.Provider = &providerv1.ProviderContract{Name: "example-reporting", Version: 1}
		},
		"no expiry":        func(r *providerv1.ResultReference) { r.ExpiresAt = nil },
		"malformed digest": func(r *providerv1.ResultReference) { r.Sha256 = "abc" },
	} {
		f := newFake(testDescription(), `{}`)
		f.badRef = mutate
		_, err := kitServer(t, f).Collect(ctx, collect)
		if got := outcome(err); got != providerv1.ErrorReason_ERROR_REASON_INVALID_RESPONSE.String() {
			t.Errorf("%s: %s", name, got)
		}
	}

	f := newFake(testDescription(), `{}`)
	f.collectErr = errors.New("source unavailable")
	_, err := kitServer(t, f).Collect(ctx, collect)
	if got := outcome(err); got != providerv1.ErrorReason_ERROR_REASON_UNAVAILABLE.String() {
		t.Errorf("plain handler error: %s", got)
	}

	// Staged bytes that do not match their reference are never sent.
	f = newFake(testDescription(), `{}`)
	s, err := NewServer(f.desc, Handlers{Collector: f, Results: mismatched{f}, Evaluator: f})
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := connect(t, s)
	c, err := NewClient(conn, testWant, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ReadResult(ctx, f.ref("result-1", []byte(`{}`)))
	wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH)

	for name, obs := range map[string][]*providerv1.Observation{
		"repeated pair":           {attributable("w1"), attributable("w1")},
		"missing with an outcome": {{Subject: "w1", Check: "posture", State: providerv1.EvidenceState_EVIDENCE_STATE_MISSING, Outcome: providerv1.Outcome_OUTCOME_PASS}},
		"attributable untimed":    {{Subject: "w1", Check: "posture", State: providerv1.EvidenceState_EVIDENCE_STATE_ATTRIBUTABLE, Raw: "PASSED", Outcome: providerv1.Outcome_OUTCOME_PASS}},
		"unknown state":           {{Subject: "w1", Check: "posture", State: 9}},
	} {
		f := newFake(testDescription(), `{}`)
		f.observations = obs
		conn, _ := connect(t, kitServer(t, f))
		c, err := NewClient(conn, testWant, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Evaluate(ctx, EvaluateInput{PayloadVersion: 3, EvaluatorVersion: 5, Payload: []byte(`{}`), At: testAt, Scope: testScope})
		if ReasonOf(err) != providerv1.ErrorReason_ERROR_REASON_INVALID_RESPONSE {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// mismatched stages bytes that do not match their reference.
type mismatched struct{ f *fakeProvider }

func (m mismatched) Result(_ context.Context, id string) (*providerv1.ResultReference, []byte, error) {
	return m.f.ref(id, []byte(`{}`)), []byte(`{"x":1}`), nil
}

func (m mismatched) Release(context.Context, string) error { return nil }

// rogue is a provider that does not use the kit, to check that the client
// refuses responses that violate the protocol.
type rogue struct {
	providerv1.UnimplementedAssessmentProviderServer
	ref     *providerv1.ResultReference
	chunks  []*providerv1.ReadResultResponse
	summary *providerv1.EvaluationSummary
	plain   bool
}

func (r *rogue) Describe(context.Context, *providerv1.DescribeRequest) (*providerv1.DescribeResponse, error) {
	return testDescription(), nil
}

func (r *rogue) Collect(context.Context, *providerv1.CollectRequest) (*providerv1.CollectResponse, error) {
	if r.plain {
		return nil, status.Error(codes.FailedPrecondition, "no detail")
	}
	return &providerv1.CollectResponse{Result: r.ref}, nil
}

func (r *rogue) ReadResult(_ *providerv1.ReadResultRequest, s grpc.ServerStreamingServer[providerv1.ReadResultResponse]) error {
	for _, c := range r.chunks {
		if err := s.Send(c); err != nil {
			return err
		}
	}
	return nil
}

func (r *rogue) Evaluate(s grpc.BidiStreamingServer[providerv1.EvaluateRequest, providerv1.EvaluateResponse]) error {
	for {
		if _, err := s.Recv(); err != nil {
			break
		}
	}
	if err := s.Send(&providerv1.EvaluateResponse{Part: &providerv1.EvaluateResponse_Observations{Observations: &providerv1.ObservationBatch{
		Observations: []*providerv1.Observation{attributable("w1")}}}}); err != nil {
		return err
	}
	if r.summary == nil {
		return nil
	}
	return s.Send(&providerv1.EvaluateResponse{Part: &providerv1.EvaluateResponse_Summary{Summary: r.summary}})
}

func TestClientRefusesProtocolViolations(t *testing.T) {
	ctx := context.Background()
	payload := []byte(`{"reports":[]}`)
	good := func() *providerv1.ResultReference {
		return (&referenceHandlers{desc: testDescription()}).ref("result-1", payload)
	}
	client := func(r *rogue) *Client {
		conn, _ := connect(t, r)
		c, err := NewClient(conn, testWant, nil)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	other := good()
	other.PayloadVersion = 2
	_, err := client(&rogue{ref: other}).Collect(ctx, testScope, nil, testAt)
	wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_INVALID_RESPONSE)

	_, err = client(&rogue{plain: true}).Collect(ctx, testScope, nil, testAt)
	wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_UNSPECIFIED)
	if err == nil || !strings.Contains(err.Error(), "FailedPrecondition") {
		t.Fatalf("a status without a detail keeps its code: %v", err)
	}

	chunk := func(off int, b []byte) *providerv1.ReadResultResponse {
		return &providerv1.ReadResultResponse{Offset: uint64(off), Data: b}
	}
	for name, tc := range map[string]struct {
		chunks []*providerv1.ReadResultResponse
		reason providerv1.ErrorReason
	}{
		"gap":       {[]*providerv1.ReadResultResponse{chunk(0, payload[:4]), chunk(8, payload[8:])}, providerv1.ErrorReason_ERROR_REASON_INVALID_RESPONSE},
		"oversized": {[]*providerv1.ReadResultResponse{chunk(0, payload[:5])}, providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED},
		"too long":  {[]*providerv1.ReadResultResponse{chunk(0, payload[:4]), chunk(4, payload[4:8]), chunk(8, payload[8:12]), chunk(12, payload[12:]), chunk(14, []byte("{}"))}, providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH},
		"truncated": {[]*providerv1.ReadResultResponse{chunk(0, payload[:4])}, providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH},
		"altered":   {[]*providerv1.ReadResultResponse{chunk(0, []byte(`{"re`)), chunk(4, []byte(`port`)), chunk(8, []byte(`s":[`)), chunk(12, []byte(`0}`))}, providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH},
	} {
		got, err := client(&rogue{chunks: tc.chunks}).ReadResult(ctx, good())
		if ReasonOf(err) != tc.reason {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}

	eval := EvaluateInput{PayloadVersion: 3, EvaluatorVersion: 5, Payload: payload, At: testAt, Scope: testScope}
	contract := &providerv1.ProviderContract{Name: "example-reporting", Version: 2}
	for name, summary := range map[string]*providerv1.EvaluationSummary{
		"no summary":      nil,
		"miscounted":      {Provider: contract, EvaluatorVersion: 5, ObservationCount: 2},
		"other evaluator": {Provider: contract, EvaluatorVersion: 4, ObservationCount: 1},
	} {
		_, err := client(&rogue{summary: summary}).Evaluate(ctx, eval)
		if ReasonOf(err) != providerv1.ErrorReason_ERROR_REASON_INVALID_RESPONSE {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := client(&rogue{summary: &providerv1.EvaluationSummary{Provider: contract, EvaluatorVersion: 5, ObservationCount: 1}}).Evaluate(ctx, eval); err != nil {
		t.Fatalf("conforming rogue evaluation: %v", err)
	}
}

func TestNewServerRequiresDeclaredHandlers(t *testing.T) {
	d := testDescription(providerv1.Capability_CAPABILITY_COLLECT, providerv1.Capability_CAPABILITY_SCAN)
	f := newFake(d, `{}`)
	if _, err := NewServer(d, Handlers{Collector: f, Results: f}); err == nil {
		t.Fatal("a scan capability without a Scanner was accepted")
	}
	d.ProtocolVersions = []uint32{2}
	if _, err := NewServer(d, Handlers{Collector: f, Results: f, Scanner: f}); ReasonOf(err) != providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PROTOCOL_VERSION {
		t.Fatalf("a description without revision 1: %v", err)
	}
}

func TestNegotiateLimitsNeverRaisesAHostBound(t *testing.T) {
	host := &providerv1.Limits{MaxResultBytes: 1 << 20, MaxChunkBytes: 1 << 16, MaxObservations: 10}
	got := NegotiateLimits(host, &providerv1.Limits{MaxResultBytes: 1 << 30, MaxChunkBytes: 1 << 10, MaxObservations: 0})
	want := &providerv1.Limits{MaxResultBytes: 1 << 20, MaxChunkBytes: 1 << 10, MaxObservations: 10}
	if !proto.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	got = NegotiateLimits(nil, &providerv1.Limits{MaxResultBytes: DefaultMaxResultBytes * 2})
	if got.GetMaxResultBytes() != DefaultMaxResultBytes || got.GetMaxChunkBytes() != DefaultMaxChunkBytes {
		t.Fatalf("defaults raised: %v", got)
	}
}

// TestPublicPackagesImportNoInternalCode keeps the authoring kit buildable
// outside this module's internal packages and API types.
func TestPublicPackagesImportNoInternalCode(t *testing.T) {
	out, err := exec.Command("go", "list", "-mod=readonly", "-deps", "-f", "{{.ImportPath}}", "../...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.HasPrefix(dep, "github.com/backend-bunny/Konstapel/") && !strings.HasPrefix(dep, "github.com/backend-bunny/Konstapel/pkg/") {
			t.Errorf("pkg/ depends on %s", dep)
		}
	}
}
