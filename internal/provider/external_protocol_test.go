package provider_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

// The external provider protocol (pkg/providerapi/v1) maps onto the
// installed-provider contract rather than defining parallel versions: a
// description's provider contract is a Descriptor's Name and Version, its
// evaluator version is EvaluatorVersion, and its payload compatibility is
// Capture. A result's payload is what a capture envelope records under the
// same three dimensions. Registration and selection of external providers
// are later tasks; these tests pin the mapping they will use.

// describedDescriptor is the Descriptor a compatible description stands
// for. External check kinds deliver nothing, so they accept only Audit, and
// the provider declares no host reads: it reads its own sources.
func describedDescriptor(d *providerv1.DescribeResponse) provider.Descriptor {
	out := provider.Descriptor{Name: d.GetProvider().GetName(), Version: int(d.GetProvider().GetVersion()),
		EvaluatorVersion: int(d.GetEvaluatorVersion()),
		Capture:          provider.CaptureCompatibility{Write: int(d.GetPayload().GetWrite())}}
	for _, v := range d.GetPayload().GetRead() {
		out.Capture.Read = append(out.Capture.Read, int(v))
	}
	for _, k := range d.GetChecks() {
		params := provider.ParameterContract{Source: provider.ParametersNone}
		if len(k.GetParameterSchema()) > 0 {
			params = provider.ParameterContract{Source: provider.ParametersFromDescriptor, Schema: k.GetParameterSchema()}
		}
		out.Checks = append(out.Checks, provider.CheckKind{Kind: k.GetKind(), Delivery: false,
			Modes: []v1alpha1.EnforcementMode{v1alpha1.ModeAudit}, Parameters: params})
	}
	return out
}

func referenceDescription(t *testing.T, name string) *providerv1.DescribeResponse {
	t.Helper()
	raw, err := os.ReadFile("../../proto/konstapel/provider/v1/testdata/wire/reference.json")
	if err != nil {
		t.Fatal(err)
	}
	var ref struct {
		Providers map[string]json.RawMessage `json:"providers"`
	}
	if err := json.Unmarshal(raw, &ref); err != nil {
		t.Fatal(err)
	}
	d := &providerv1.DescribeResponse{}
	if err := protojson.Unmarshal(ref.Providers[name], d); err != nil {
		t.Fatal(err)
	}
	if err := providerkit.ValidateDescription(d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestProtocolDescriptionIsAnInstalledDescriptor(t *testing.T) {
	d := referenceDescription(t, "reporting")
	desc := describedDescriptor(d)
	if err := desc.Validate(); err != nil {
		t.Fatalf("a valid protocol description maps to an invalid descriptor: %v", err)
	}
	if got, want := desc.Contract(), fmt.Sprintf("%s/v%d", d.GetProvider().GetName(), d.GetProvider().GetVersion()); got != want {
		t.Fatalf("contract %s, want %s", got, want)
	}
	r, err := provider.New(desc.Contract(), desc)
	if err != nil {
		t.Fatal(err)
	}
	// The payload and evaluator versions stay separate dimensions of the
	// registry's capture checks, exactly as the protocol keeps them.
	for _, v := range d.GetPayload().GetRead() {
		if err := r.CheckCapture(desc.Contract(), int(v)); err != nil {
			t.Errorf("payload %d: %v", v, err)
		}
	}
	if err := r.CheckCapture(desc.Contract(), int(d.GetEvaluatorVersion())); err == nil {
		t.Error("the evaluator version was accepted as a payload version")
	}
	if err := r.CheckEvaluator(desc.Contract(), int(d.GetEvaluatorVersion())); err != nil {
		t.Error(err)
	}
	if err := r.CheckEvaluator(desc.Contract(), int(d.GetPayload().GetWrite())); err == nil {
		t.Error("the payload version was accepted as an evaluator version")
	}

	// A result written by the provider is captured in an envelope under its
	// contract, payload version and evaluator version.
	envelope, err := json.Marshal(collector.CaptureEnvelope{Version: collector.CaptureEnvelopeVersion, Provider: desc.Contract(),
		PayloadVersion: int(d.GetPayload().GetWrite()), EvaluatorVersion: int(d.GetEvaluatorVersion()), Payload: json.RawMessage(`{"reports":[]}`)})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := collector.ReadCapture(envelope, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.CheckEvaluator(r); err != nil {
		t.Fatal(err)
	}
	other := collector.CaptureEnvelope{Version: collector.CaptureEnvelopeVersion, Provider: desc.Contract(),
		PayloadVersion: int(d.GetEvaluatorVersion()), EvaluatorVersion: int(d.GetEvaluatorVersion()), Payload: json.RawMessage(`{}`)}
	raw, _ := json.Marshal(other)
	if _, err := collector.ReadCapture(raw, r); !errors.Is(err, collector.ErrUnsupportedCapture) {
		t.Fatalf("an unread payload version was captured: %v", err)
	}
}

// TestProtocolDefaultsShareTheCollectionLimits keeps the protocol's
// default bounds equal to the host's collection defaults: the protocol
// never silently allows more than an in-tree collection.
func TestProtocolDefaultsShareTheCollectionLimits(t *testing.T) {
	if providerkit.DefaultMaxResultBytes != uint64(provider.DefaultMaxBytes) {
		t.Errorf("DefaultMaxResultBytes %d, collection MaxBytes %d", providerkit.DefaultMaxResultBytes, provider.DefaultMaxBytes)
	}
	if providerkit.DefaultMaxObservations != uint32(provider.DefaultMaxObjects) {
		t.Errorf("DefaultMaxObservations %d, collection MaxObjects %d", providerkit.DefaultMaxObservations, provider.DefaultMaxObjects)
	}
}
