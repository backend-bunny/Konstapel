package providerkit

import (
	"context"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
)

// Revision 2 is negotiated, not additive (design Decision 9). These tests
// keep the evidence for that choice: a revision 1 reader silently ignores
// revision 2's fields, so only the revision check makes them mandatory, and
// it rejects the other revision in both directions.
//
// The revision 1 reader is the generated code of revision 1 itself: its
// file descriptor as published before revision 2 (pkg/providerapi/v1 at
// 0ddcaa5), saved in testdata/revision1 and read here as dynamic messages,
// so it never collides with the registered revision 2 types.

func revision1(t *testing.T) protoreflect.FileDescriptor {
	t.Helper()
	raw, err := os.ReadFile("../../proto/konstapel/provider/v1/testdata/revision1/provider.descriptor.json")
	if err != nil {
		t.Fatal(err)
	}
	fdp := &descriptorpb.FileDescriptorProto{}
	if err := protojson.Unmarshal(raw, fdp); err != nil {
		t.Fatal(err)
	}
	deps := new(protoregistry.Files)
	if err := deps.RegisterFile(timestamppb.File_google_protobuf_timestamp_proto); err != nil {
		t.Fatal(err)
	}
	fd, err := protodesc.NewFile(fdp, deps)
	if err != nil {
		t.Fatal(err)
	}
	if fd.Messages().ByName("Inventory") != nil || fd.Messages().ByName("CollectRequest").Fields().ByName("inventory").Kind() != protoreflect.BytesKind {
		t.Fatal("testdata/revision1 is not revision 1: it must have the opaque inventory bytes and no Inventory message")
	}
	return fd
}

// decodeAs decodes b as a revision 1 message of the given name.
func decodeAs(t *testing.T, fd protoreflect.FileDescriptor, name protoreflect.Name, b []byte) *dynamicpb.Message {
	t.Helper()
	m := dynamicpb.NewMessage(fd.Messages().ByName(name))
	if err := proto.Unmarshal(b, m); err != nil {
		t.Fatalf("a revision 1 %s rejects the revision 2 encoding: %v", name, err)
	}
	return m
}

func TestRevision1ReadersSilentlyIgnoreRevision2Fields(t *testing.T) {
	fd := revision1(t)
	// A revision 2 Collect, inventory included, as a revision 1 provider
	// decodes it: no error, and the inventory is only unknown bytes, which
	// its handlers never see. Had revision 2 stayed revision 1, such a
	// provider would collect without the host's denominator.
	req := &providerv1.CollectRequest{Header: testWant.Header(), Scope: testScope, Inventory: testInventory, PayloadVersion: 3,
		Deadline: timestamppb.New(testAt)}
	b, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	old := decodeAs(t, fd, "CollectRequest", b)
	if len(old.GetUnknown()) == 0 {
		t.Fatal("the inventory should be unknown to revision 1")
	}
	if got := old.Get(old.Descriptor().Fields().ByName("inventory")).Bytes(); len(got) != 0 {
		t.Fatalf("revision 1 reads an inventory of %q", got)
	}

	// A revision 2 description's subject and evidence bounds, as a revision
	// 1 host decodes them: dropped without error.
	limits, err := proto.Marshal(&providerv1.Limits{MaxChunkBytes: 4, MaxSubjects: 10, MaxEvidence: 10})
	if err != nil {
		t.Fatal(err)
	}
	oldLimits := decodeAs(t, fd, "Limits", limits)
	if len(oldLimits.GetUnknown()) == 0 || oldLimits.Descriptor().Fields().ByName("max_subjects") != nil {
		t.Fatal("revision 1 should not know the subject bound")
	}

	// A staged CollectionResult is, to a revision 1 host, just a JSON
	// object payload: it would store the attribution envelope opaquely.
	if !jsonObject([]byte(testResult)) {
		t.Fatal("a CollectionResult is one JSON object")
	}
}

func TestOtherRevisionsAreRejectedInBothDirections(t *testing.T) {
	ctx := context.Background()
	// The revision check every kit server ran at revision 1 (CheckHeader
	// against a description serving revision 1) refuses revision 2.
	rev1 := testDescription()
	rev1.ProtocolVersions = []uint32{1}
	wantReason(t, CheckHeader(testWant.Header(), rev1), providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PROTOCOL_VERSION)

	// A revision 2 host refuses a provider serving revision 1 only, and
	// accepts one that also serves a later revision.
	wantReason(t, CheckCompatibility(testWant, rev1), providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PROTOCOL_VERSION)
	both := testDescription()
	both.ProtocolVersions = []uint32{ProtocolVersion, ProtocolVersion + 1}
	if err := CheckCompatibility(testWant, both); err != nil {
		t.Fatalf("a provider also serving a later revision: %v", err)
	}

	// A revision 2 kit server refuses a revision 1 request before any
	// handler runs, and Collect requires an inventory.
	f := newFake(testDescription(), testResult)
	called := false
	f.badRef = func(*providerv1.ResultReference) { called = true }
	s := kitServer(t, f)
	h := testWant.Header()
	h.ProtocolVersion = 1
	_, err := s.Collect(ctx, &providerv1.CollectRequest{Header: h, Scope: testScope, Inventory: testInventory, PayloadVersion: 3, Deadline: timestamppb.New(testAt)})
	wantReason(t, fromStatus(ctx, err), providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PROTOCOL_VERSION)
	_, err = s.Collect(ctx, &providerv1.CollectRequest{Header: testWant.Header(), Scope: testScope, PayloadVersion: 3, Deadline: timestamppb.New(testAt)})
	wantReason(t, fromStatus(ctx, err), providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST)
	if called {
		t.Fatal("a refused Collect reached the handler")
	}
	_, err = s.Collect(ctx, &providerv1.CollectRequest{Header: testWant.Header(), Scope: testScope, Inventory: testInventory, PayloadVersion: 3,
		Deadline: timestamppb.New(testAt.Add(time.Minute))})
	if err != nil || !called {
		t.Fatalf("a revision 2 Collect with an inventory: %v (handler called %t)", err, called)
	}
}
