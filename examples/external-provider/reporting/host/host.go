// Package host is the quickstart's stand-in for the Konstapel controller: it
// dials a provider over mutual TLS and drives one reporting assessment
// through the public kit's Client, Describe, Collect, ReadResult,
// Acknowledge and Evaluate, the way the host does. Like the host, it
// collects at the source endpoint and evaluates at the evaluator endpoint;
// the quickstart's single process is both.
package host

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"google.golang.org/grpc"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

// Expect is what the quickstart's "registration" expects of the source
// endpoint, and EvaluatorExpect of the evaluator endpoint. Each field is
// checked separately against that endpoint's Describe, and each client
// sends nothing outside its capability: evaluation never goes to the
// source endpoint.
var (
	Expect = providerkit.Compatibility{
		Provider:         "example-reporting",
		ContractVersion:  1,
		PayloadVersion:   1,
		EvaluatorVersion: 1,
		Capabilities:     []providerv1.Capability{providerv1.Capability_CAPABILITY_COLLECT},
	}
	EvaluatorExpect = providerkit.Compatibility{
		Provider:         "example-reporting",
		ContractVersion:  1,
		PayloadVersion:   1,
		EvaluatorVersion: 1,
		Capabilities:     []providerv1.Capability{providerv1.Capability_CAPABILITY_EVALUATE},
	}
)

// Scope is the frozen scope the quickstart assesses. team-c is not in the
// provider's synthetic source, so its evidence is missing.
func Scope() *providerv1.Scope {
	return &providerv1.Scope{Cluster: "quickstart", Namespaces: []*providerv1.Namespace{
		{Name: "team-a", Uid: "6f1c7a52-0000-4000-8000-00000000000a"},
		{Name: "team-b", Uid: "6f1c7a52-0000-4000-8000-00000000000b"},
		{Name: "team-c", Uid: "6f1c7a52-0000-4000-8000-00000000000c"},
	}}
}

// Check is the name of the quickstart's one check, expected for every
// namespace of the scope.
const Check = "namespace-owner"

// Inventory is the host-frozen inventory the quickstart collects for: each
// scope namespace as a subject expecting Check. A real host derives it
// from targeting and the listed workloads.
func Inventory() *providerv1.Inventory {
	inv := &providerv1.Inventory{Supplements: providerv1.Supplements_SUPPLEMENTS_NONE}
	for _, ns := range Scope().GetNamespaces() {
		inv.Subjects = append(inv.Subjects, &providerv1.InventorySubject{Uid: ns.GetUid(), NamespaceUid: ns.GetUid(),
			Resource: providerkit.NamespaceResource, Name: ns.GetName(), Revision: "quickstart", Checks: []string{Check}})
	}
	return inv
}

// Dial connects to a provider at addr whose certificate must name
// serverName, presenting the host certificate in files.
func Dial(addr string, files providerkit.TLSFiles, serverName string) (*grpc.ClientConn, error) {
	mtls, err := providerkit.NewClientTLS(files, serverName)
	if err != nil {
		return nil, err
	}
	opts, err := providerkit.DialOptions(mtls, providerkit.TransportLimits{})
	if err != nil {
		return nil, err
	}
	return grpc.NewClient(addr, opts...)
}

// Report is the outcome of one quickstart assessment.
type Report struct {
	Description  *providerv1.DescribeResponse
	Limits       *providerv1.Limits
	Result       *providerv1.ResultReference
	Payload      []byte
	Collection   *providerv1.CollectionResult
	Observations []*providerv1.Observation
}

// Timeout is each call's deadline. Every protocol call must carry one.
const Timeout = 10 * time.Second

// Run drives one assessment, collecting over source and evaluating over
// evaluator (the same connection for the quickstart's single process), and
// prints each step to out.
func Run(ctx context.Context, source, evaluator grpc.ClientConnInterface, out io.Writer) (*Report, error) {
	client, err := providerkit.NewClient(source, Expect, nil)
	if err != nil {
		return nil, err
	}
	evaluatorClient, err := providerkit.NewClient(evaluator, EvaluatorExpect, nil)
	if err != nil {
		return nil, err
	}
	call := func() (context.Context, context.CancelFunc) { return context.WithTimeout(ctx, Timeout) }
	r := &Report{}

	cctx, cancel := call()
	r.Description, err = client.Describe(cctx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("describe: %w", err)
	}
	r.Limits = client.Limits()
	d := r.Description
	fmt.Fprintf(out, "describe: %s/v%d protocol=%v evaluator=%d payload=write %d read %v capabilities=%v\n",
		d.GetProvider().GetName(), d.GetProvider().GetVersion(), d.GetProtocolVersions(), d.GetEvaluatorVersion(),
		d.GetPayload().GetWrite(), d.GetPayload().GetRead(), d.GetCapabilities())
	fmt.Fprintf(out, "negotiated limits: max_result_bytes=%d max_chunk_bytes=%d max_observations=%d\n",
		r.Limits.GetMaxResultBytes(), r.Limits.GetMaxChunkBytes(), r.Limits.GetMaxObservations())

	cctx, cancel = call()
	deadline, _ := cctx.Deadline()
	r.Result, err = client.Collect(cctx, Scope(), Inventory(), deadline)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("collect: %w", err)
	}
	fmt.Fprintf(out, "collect: result %s, %d bytes, %s\n", r.Result.GetResultId(), r.Result.GetSizeBytes(), r.Result.GetSha256())

	// The kit verifies offset continuity, chunk bounds, size and digest, and
	// that the bytes are a well-formed CollectionResult. On an interrupted
	// stream, ResumeResult(ref, received) continues from the bytes already
	// received. A real host then attributes the result against its
	// inventory before using any evidence.
	cctx, cancel = call()
	r.Payload, r.Collection, err = client.ReadCollection(cctx, r.Result)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("read result: %w", err)
	}
	fmt.Fprintf(out, "read result: %d bytes verified in chunks of at most %d: %d evidence items, %d limitations\n",
		len(r.Payload), r.Limits.GetMaxChunkBytes(), len(r.Collection.GetEvidence()), len(r.Collection.GetLimitations()))
	for _, l := range r.Collection.GetLimitations() {
		fmt.Fprintf(out, "  limitation: %s\n", l.GetMessage())
	}

	// A real host acknowledges only once its capture is durable; the
	// provider may then release its staging.
	cctx, cancel = call()
	err = client.Acknowledge(cctx, r.Result)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("acknowledge: %w", err)
	}
	fmt.Fprintf(out, "acknowledge: provider may release %s\n", r.Result.GetResultId())

	def, _ := json.Marshal(map[string]string{"label": "owner"})
	cctx, cancel = call()
	ev, err := evaluatorClient.Evaluate(cctx, providerkit.EvaluateInput{
		PayloadVersion:   Expect.PayloadVersion,
		EvaluatorVersion: Expect.EvaluatorVersion,
		Payload:          r.Payload,
		At:               time.Now().UTC(),
		Scope:            Scope(),
		Content:          []*providerv1.ContentReference{{Bundle: "quickstart", ManifestDigest: providerkit.Digest([]byte("quickstart"))}},
		Checks:           []*providerv1.CheckDefinition{{Kind: "reporting.example.test/v1/RequiredLabel", Name: Check, Definition: def}},
	})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("evaluate: %w", err)
	}
	r.Observations = ev.Observations
	fmt.Fprintf(out, "evaluate: %d observations, %d stale scopes\n", len(ev.Observations), ev.StaleScopes)
	for _, o := range ev.Observations {
		outcome := "-"
		if o.GetState() == providerv1.EvidenceState_EVIDENCE_STATE_ATTRIBUTABLE {
			outcome = fmt.Sprintf("%s (raw %q)", o.GetOutcome(), o.GetRaw())
		}
		fmt.Fprintf(out, "  %s %s: %s %s\n", o.GetSubject(), o.GetCheck(), o.GetState(), outcome)
	}
	return r, nil
}
