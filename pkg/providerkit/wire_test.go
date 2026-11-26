package providerkit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/timestamppb"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
)

// The wire fixtures are the language-neutral conformance cases of the
// protocol (proto/konstapel/provider/v1/testdata/wire). Each case is one
// message, as protojson and as its binary wire encoding, and the outcome a
// conforming implementation must reach: "OK" or the ErrorReason it fails
// with. Request cases are served by a reference description; description
// cases are checked against the host expectation.
//
// -update-wire fills a case's missing (absent) wire encoding from its value. It never
// rewrites an existing encoding: those pin field numbers and types.
var updateWire = flag.Bool("update-wire", false, "fill missing wire encodings of the protocol fixtures")

const wireDir = "../../proto/konstapel/provider/v1/testdata/wire"

type wireReference struct {
	Description string                     `json:"description"`
	Providers   map[string]json.RawMessage `json:"providers"`
	Host        struct {
		Provider         string   `json:"provider"`
		ContractVersion  uint32   `json:"contractVersion"`
		PayloadVersion   uint32   `json:"payloadVersion"`
		EvaluatorVersion uint32   `json:"evaluatorVersion"`
		Capabilities     []string `json:"capabilities"`
	} `json:"host"`
	Staged struct {
		ResultID string `json:"resultId"`
		Payload  []byte `json:"payload"`
	} `json:"staged"`
}

type wireCase struct {
	Description string          `json:"description"`
	Provider    string          `json:"provider,omitempty"`
	Message     string          `json:"message"`
	Value       json.RawMessage `json:"value"`
	Expect      string          `json:"expect"`
	// Wire is the base64 binary encoding; absent until -update-wire fills
	// it. An empty message encodes to "".
	Wire *string `json:"wire,omitempty"`
}

func decodeStrict(t *testing.T, raw []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatal(err)
	}
}

func loadReference(t *testing.T) (wireReference, map[string]*providerv1.DescribeResponse, Compatibility) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(wireDir, "reference.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ref wireReference
	decodeStrict(t, raw, &ref)
	descs := map[string]*providerv1.DescribeResponse{}
	for name, v := range ref.Providers {
		d := &providerv1.DescribeResponse{}
		if err := protojson.Unmarshal(v, d); err != nil {
			t.Fatalf("reference provider %s: %v", name, err)
		}
		descs[name] = d
	}
	want := Compatibility{Provider: ref.Host.Provider, ContractVersion: ref.Host.ContractVersion,
		PayloadVersion: ref.Host.PayloadVersion, EvaluatorVersion: ref.Host.EvaluatorVersion}
	for _, c := range ref.Host.Capabilities {
		v, ok := providerv1.Capability_value[c]
		if !ok {
			t.Fatalf("host capability %q is unknown", c)
		}
		want.Capabilities = append(want.Capabilities, providerv1.Capability(v))
	}
	return ref, descs, want
}

// referenceHandlers accept every validated request. Their results are
// well-formed for the reference providers, so a case's outcome is decided
// by the protocol checks alone.
type referenceHandlers struct {
	desc    *providerv1.DescribeResponse
	staged  map[string][]byte
	release []string
}

func (h *referenceHandlers) ref(id string, data []byte) *providerv1.ResultReference {
	return &providerv1.ResultReference{ResultId: id, Provider: h.desc.GetProvider(), PayloadVersion: h.desc.GetPayload().GetWrite(),
		SizeBytes: uint64(len(data)), Sha256: Digest(data), ExpiresAt: timestamppb.New(time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC))}
}

func (h *referenceHandlers) Collect(context.Context, *providerv1.CollectRequest) (*providerv1.ResultReference, error) {
	return h.ref("result-1", h.staged["result-1"]), nil
}

func (h *referenceHandlers) Result(_ context.Context, id string) (*providerv1.ResultReference, []byte, error) {
	data, ok := h.staged[id]
	if !ok {
		return nil, nil, Errorf(providerv1.ErrorReason_ERROR_REASON_NOT_FOUND, "no result %s", id)
	}
	return h.ref(id, data), data, nil
}

func (h *referenceHandlers) Release(_ context.Context, id string) error {
	h.release = append(h.release, id)
	return nil
}

func (h *referenceHandlers) operation(key *providerv1.ScanKey, id string) *providerv1.Operation {
	return &providerv1.Operation{OperationId: id, Key: key, State: providerv1.OperationState_OPERATION_STATE_PENDING, Attempt: 1, MaxAttempts: 1}
}

func (h *referenceHandlers) Start(_ context.Context, req *providerv1.StartRequest) (*providerv1.Operation, error) {
	return h.operation(req.GetKey(), "operation-1"), nil
}

var referenceKey = &providerv1.ScanKey{RunUid: "run", RegistrationUid: "registration", RegistrationRevision: 1, InputDigest: Digest([]byte("{}"))}

func (h *referenceHandlers) Get(_ context.Context, id string) (*providerv1.Operation, error) {
	return h.operation(referenceKey, id), nil
}

func (h *referenceHandlers) Cancel(_ context.Context, id string) (*providerv1.Operation, error) {
	return h.operation(referenceKey, id), nil
}

func (h *referenceHandlers) Evaluate(context.Context, *providerv1.EvaluateStart, []byte) (*Evaluation, error) {
	return &Evaluation{}, nil
}

func referenceServer(t *testing.T, d *providerv1.DescribeResponse, staged map[string][]byte) (*Server, *referenceHandlers) {
	t.Helper()
	h := &referenceHandlers{desc: d, staged: staged}
	all := Handlers{Collector: h, Results: h, Evaluator: h}
	if slices.Contains(d.GetCapabilities(), providerv1.Capability_CAPABILITY_SCAN) {
		all.Scanner = h
	}
	s, err := NewServer(d, all)
	if err != nil {
		t.Fatal(err)
	}
	return s, h
}

// serve runs one request case through the reference server and returns
// the reason it failed with, or "OK".
func serve(s *Server, m proto.Message) string {
	ctx := context.Background()
	var err error
	switch req := m.(type) {
	case *providerv1.DescribeRequest:
		_, err = s.Describe(ctx, req)
	case *providerv1.CollectRequest:
		_, err = s.Collect(ctx, req)
	case *providerv1.StartRequest:
		_, err = s.Start(ctx, req)
	case *providerv1.GetRequest:
		_, err = s.Get(ctx, req)
	case *providerv1.CancelRequest:
		_, err = s.Cancel(ctx, req)
	case *providerv1.AcknowledgeRequest:
		_, err = s.Acknowledge(ctx, req)
	case *providerv1.EvaluateStart:
		// The opening message of the Evaluate stream.
		return outcome(toStatus(s.CheckEvaluateStart(req)))
	default:
		return "unsupported fixture message " + string(m.ProtoReflect().Descriptor().FullName())
	}
	return outcome(err)
}

func outcome(err error) string {
	if err == nil {
		return "OK"
	}
	return ReasonOf(fromStatus(context.Background(), err)).String()
}

func TestWireFixtures(t *testing.T) {
	ref, descs, want := loadReference(t)
	files, err := filepath.Glob(filepath.Join(wireDir, "cases", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no wire cases: %v", err)
	}
	seen := map[string]bool{}
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".json")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var c wireCase
			decodeStrict(t, raw, &c)
			if c.Description == "" {
				t.Fatal("case has no description")
			}
			m := newMessage(t, c.Message)
			if err := protojson.Unmarshal(c.Value, m); err != nil {
				t.Fatalf("value: %v", err)
			}
			checkWire(t, file, &c, m)
			seen[c.Expect] = true

			var got string
			if c.Provider == "" {
				d, ok := m.(*providerv1.DescribeResponse)
				if !ok {
					t.Fatalf("a case without a provider is a description case, not %s", c.Message)
				}
				got = "OK"
				if err := CheckCompatibility(want, d); err != nil {
					got = ReasonOf(err).String()
				}
			} else {
				d, ok := descs[c.Provider]
				if !ok {
					t.Fatalf("unknown reference provider %q", c.Provider)
				}
				s, _ := referenceServer(t, d, map[string][]byte{ref.Staged.ResultID: ref.Staged.Payload})
				got = serve(s, m)
			}
			if got != c.Expect {
				t.Fatalf("%s: got %s, want %s", c.Description, got, c.Expect)
			}
		})
	}
	// Each version dimension has its own rejection among the cases.
	for _, r := range []providerv1.ErrorReason{
		providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PROTOCOL_VERSION,
		providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CONTRACT_VERSION,
		providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PAYLOAD_VERSION,
		providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_EVALUATOR_VERSION,
		providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CAPABILITY,
	} {
		if !seen[r.String()] {
			t.Errorf("no wire case is rejected with %s", r)
		}
	}
}

func newMessage(t *testing.T, name string) proto.Message {
	t.Helper()
	mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(name))
	if err != nil || mt.Descriptor().ParentFile().Package() != "konstapel.provider.v1" {
		t.Fatalf("message %q is not a konstapel.provider.v1 message: %v", name, err)
	}
	return mt.New().Interface()
}

// checkWire requires the case's binary encoding to decode, with no unknown
// field, to exactly its protojson value. That pins every field number and
// type the case uses.
func checkWire(t *testing.T, file string, c *wireCase, m proto.Message) {
	t.Helper()
	if c.Wire == nil {
		if !*updateWire {
			t.Fatal("case has no wire encoding; run go test ./pkg/providerkit -run TestWireFixtures -update-wire")
		}
		b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		w := base64.StdEncoding.EncodeToString(b)
		c.Wire = &w
		writeCase(t, file, c)
		return
	}
	b, err := base64.StdEncoding.DecodeString(*c.Wire)
	if err != nil {
		t.Fatalf("wire: %v", err)
	}
	decoded := m.ProtoReflect().New().Interface()
	if err := proto.Unmarshal(b, decoded); err != nil {
		t.Fatalf("wire: %v", err)
	}
	if unknown := unknownFields(decoded.ProtoReflect()); unknown {
		t.Fatal("wire encoding has fields this definition does not know")
	}
	if !proto.Equal(decoded, m) {
		t.Fatalf("wire encoding decodes to %v, the value is %v", decoded, m)
	}
}

func unknownFields(m protoreflect.Message) bool {
	if len(m.GetUnknown()) > 0 {
		return true
	}
	found := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList() && fd.Message() != nil:
			for i := range v.List().Len() {
				found = found || unknownFields(v.List().Get(i).Message())
			}
		case fd.Message() != nil && !fd.IsMap():
			found = found || unknownFields(v.Message())
		}
		return !found
	})
	return found
}

func writeCase(t *testing.T, file string, c *wireCase) {
	t.Helper()
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(c); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(buf.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
