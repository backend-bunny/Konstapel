// Package host is the quickstart's stand-in for the Konstapel controller: it
// dials a provider over mutual TLS and drives one reporting assessment
// through the public kit's Client, Describe, Collect, ReadResult,
// Acknowledge and Evaluate, the way the host does.
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

// Expect is what the quickstart's "registration" expects of the endpoint.
// Each field is checked separately against Describe.
var Expect = providerkit.Compatibility{
	Provider:         "example-reporting",
	ContractVersion:  1,
	PayloadVersion:   1,
	EvaluatorVersion: 1,
	Capabilities:     []providerv1.Capability{providerv1.Capability_CAPABILITY_COLLECT, providerv1.Capability_CAPABILITY_EVALUATE},
}

// Scope is the frozen scope the quickstart assesses. team-c is not in the
// provider's synthetic source, so its evidence is missing.
func Scope() *providerv1.Scope {
	return &providerv1.Scope{Cluster: "quickstart", Namespaces: []*providerv1.Namespace{
		{Name: "team-a", Uid: "6f1c7a52-0000-4000-8000-00000000000a"},
		{Name: "team-b", Uid: "6f1c7a52-0000-4000-8000-00000000000b"},
		{Name: "team-c", Uid: "6f1c7a52-0000-4000-8000-00000000000c"},
	}}
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
	Observations []*providerv1.Observation
}

// Timeout is each call's deadline. Every protocol call must carry one.
const Timeout = 10 * time.Second

// Run drives one assessment over conn and prints each step to out.
func Run(ctx context.Context, conn grpc.ClientConnInterface, out io.Writer) (*Report, error) {
	client, err := providerkit.NewClient(conn, Expect, nil)
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
	r.Result, err = client.Collect(cctx, Scope(), nil, deadline)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("collect: %w", err)
	}
	fmt.Fprintf(out, "collect: result %s, %d bytes, %s\n", r.Result.GetResultId(), r.Result.GetSizeBytes(), r.Result.GetSha256())
	for _, l := range r.Result.GetLimitations() {
		fmt.Fprintf(out, "  limitation: %s\n", l)
	}

	// The kit verifies offset continuity, chunk bounds, size and digest. On
	// an interrupted stream, ResumeResult(ref, received) continues from
	// the bytes already received.
	cctx, cancel = call()
	r.Payload, err = client.ReadResult(cctx, r.Result)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("read result: %w", err)
	}
	fmt.Fprintf(out, "read result: %d bytes verified in chunks of at most %d\n", len(r.Payload), r.Limits.GetMaxChunkBytes())

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
	ev, err := client.Evaluate(cctx, providerkit.EvaluateInput{
		PayloadVersion:   Expect.PayloadVersion,
		EvaluatorVersion: Expect.EvaluatorVersion,
		Payload:          r.Payload,
		At:               time.Now().UTC(),
		Scope:            Scope(),
		Content:          []*providerv1.ContentReference{{Bundle: "quickstart", ManifestDigest: providerkit.Digest([]byte("quickstart"))}},
		Checks:           []*providerv1.CheckDefinition{{Kind: "reporting.example.test/v1/RequiredLabel", Name: "namespace-owner", Definition: def}},
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
