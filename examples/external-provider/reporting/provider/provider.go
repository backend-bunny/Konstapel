// Package provider is a tiny synthetic reporting provider built only on the
// public Konstapel provider kit. It collects existing "evidence" (namespace
// labels) from a source for the namespace subjects of the host's frozen
// inventory, stages each result as a CollectionResult until the host
// acknowledges it, and evaluates one check kind, RequiredLabel, over a
// frozen payload.
//
// The quickstart runs it as one process over a fixed in-memory source. The
// reference chart (chart/, see docs/integration/external-provider-chart.md)
// runs the same code as two deployments with separate identities, each its
// own registered endpoint: a source worker that reads Namespaces from the
// Kubernetes API and only collects, and a credential-free evaluator that
// only evaluates (Roles).
//
// It is a demonstration of the protocol, not a supported provider: staging
// lives in memory, so a restart loses unacknowledged results. A real
// provider persists staged results until acknowledgement or the end of the
// handoff window.
package provider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

// Identity and versions of the example provider. Each version is its own
// compatibility dimension.
const (
	Name             = "example-reporting"
	ContractVersion  = 1
	PayloadVersion   = 1
	EvaluatorVersion = 1
	// CheckKind is the only check kind the provider evaluates. Its
	// definition is {"label": "<name>"}: the namespace must carry that label.
	CheckKind = "reporting.example.test/v1/RequiredLabel"
	// Handoff is how long a staged result waits for acknowledgement.
	Handoff = 10 * time.Minute
	// QuickstartImplementation is the implementation the quickstart's
	// combined process reports. A deployed provider reports its release
	// digest instead, the one its registration expects.
	QuickstartImplementation = "example-reporting quickstart (unversioned local build)"
)

// Namespace is one namespace of the synthetic source.
type Namespace struct {
	UID    string
	Labels map[string]string
}

// NamespaceSource is where Collect reads namespaces: the quickstart's
// Synthetic map or the Kubernetes API (Kubernetes). Namespace reports
// found=false for a namespace the source does not have; any other failure
// is an error, never an absent namespace. String names the source in
// limitations.
type NamespaceSource interface {
	Namespace(ctx context.Context, name string) (ns Namespace, found bool, err error)
	String() string
}

// Synthetic is a fixed in-memory source.
type Synthetic map[string]Namespace

// Namespace looks name up in the map.
func (s Synthetic) Namespace(_ context.Context, name string) (Namespace, bool, error) {
	ns, ok := s[name]
	return ns, ok, nil
}

func (Synthetic) String() string { return "the synthetic source" }

// Source is the synthetic evidence source the quickstart reads: two
// namespaces, one labeled with an owner and one without.
func Source() Synthetic {
	return Synthetic{
		"team-a": {UID: "6f1c7a52-0000-4000-8000-00000000000a", Labels: map[string]string{"owner": "alice"}},
		"team-b": {UID: "6f1c7a52-0000-4000-8000-00000000000b", Labels: map[string]string{}},
	}
}

// Description is the Describe response of the quickstart's combined
// process.
func Description() *providerv1.DescribeResponse {
	return Describe(RoleCombined, QuickstartImplementation)
}

// Describe is the Describe response of a process serving role, reporting
// implementation. The worker and the evaluator describe the same provider,
// contract, versions, limits and release; only their capabilities differ.
func Describe(role Role, implementation string) *providerv1.DescribeResponse {
	capabilities := []providerv1.Capability{providerv1.Capability_CAPABILITY_COLLECT, providerv1.Capability_CAPABILITY_EVALUATE}
	switch role {
	case RoleWorker:
		capabilities = []providerv1.Capability{providerv1.Capability_CAPABILITY_COLLECT}
	case RoleEvaluator:
		capabilities = []providerv1.Capability{providerv1.Capability_CAPABILITY_EVALUATE}
	}
	return &providerv1.DescribeResponse{
		Provider:         &providerv1.ProviderContract{Name: Name, Version: ContractVersion},
		ProtocolVersions: []uint32{providerkit.ProtocolVersion},
		EvaluatorVersion: EvaluatorVersion,
		Payload:          &providerv1.PayloadCompatibility{Write: PayloadVersion, Read: []uint32{PayloadVersion}},
		Capabilities:     capabilities,
		Checks:           []*providerv1.CheckKind{{Kind: CheckKind}},
		// Stricter than the kit defaults, so even this small payload
		// travels in several chunks. The host applies the stricter of its
		// own bounds and these.
		Limits:         &providerv1.Limits{MaxResultBytes: 1 << 20, MaxChunkBytes: 256, MaxObservations: 1000},
		Implementation: implementation,
	}
}

// details is version 1 of the provider's evidence details: one namespace's
// name and labels. It is the only part of a staged CollectionResult in the
// provider's own format.
type details struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

type staged struct {
	ref  *providerv1.ResultReference
	data []byte
}

// Provider implements the kit's Collector and Results over a source, and,
// in the quickstart's combined process, Evaluator.
type Provider struct {
	source NamespaceSource
	now    func() time.Time

	mu     sync.Mutex
	staged map[string]staged
}

// New returns a provider reading source.
func New(source NamespaceSource) *Provider {
	return &Provider{source: source, now: time.Now, staged: map[string]staged{}}
}

// Handlers are the combined process's kit handlers: collection and
// evaluation in one process.
func (p *Provider) Handlers() providerkit.Handlers {
	return providerkit.Handlers{Collector: p, Results: p, Evaluator: Evaluator{}}
}

// Collect reads the source for the namespace subjects of the frozen
// inventory. A namespace whose name and UID both match its subject is one
// evidence item, attributed to that subject and every check the inventory
// expects for it. Every other subject is a limitation, never an empty pass:
// a namespace the source lacks or knows under another UID, and every
// workload subject, which this provider does not assess. A source that
// cannot be read fails the collection: nothing is staged.
func (p *Provider) Collect(ctx context.Context, req *providerv1.CollectRequest) (*providerv1.ResultReference, error) {
	now := p.now().UTC().Truncate(time.Second)
	out := &providerv1.CollectionResult{}
	limit := func(subject, message string) {
		out.Limitations = append(out.Limitations, &providerv1.SubjectLimitation{Subject: subject, Message: message})
	}
	for _, s := range req.GetInventory().GetSubjects() {
		if s.GetResource() != providerkit.NamespaceResource {
			limit(s.GetUid(), s.GetResource()+" "+s.GetName()+" is not assessed: this provider reads namespaces only")
			continue
		}
		src, ok, err := p.source.Namespace(ctx, s.GetName())
		switch {
		case err != nil:
			return nil, providerkit.Errorf(providerv1.ErrorReason_ERROR_REASON_UNAVAILABLE, "read namespace %s: %v", s.GetName(), err)
		case !ok:
			limit(s.GetUid(), "namespace "+s.GetName()+" is not in "+p.source.String())
			continue
		case src.UID != s.GetUid():
			limit(s.GetUid(), "namespace "+s.GetName()+" has another uid in "+p.source.String())
			continue
		}
		e, err := namespaceEvidence(s, src, now)
		if err != nil {
			return nil, err
		}
		out.Evidence = append(out.Evidence, e)
	}
	data, err := protojson.Marshal(out)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	ref := &providerv1.ResultReference{
		ResultId:       "result-" + hex.EncodeToString(id),
		Provider:       &providerv1.ProviderContract{Name: Name, Version: ContractVersion},
		PayloadVersion: PayloadVersion,
		SizeBytes:      uint64(len(data)),
		Sha256:         providerkit.Digest(data),
		ExpiresAt:      timestamppb.New(now.Add(Handoff)),
	}
	p.mu.Lock()
	p.staged[ref.GetResultId()] = staged{ref: ref, data: data}
	p.mu.Unlock()
	return ref, nil
}

// namespaceEvidence is one namespace's evidence item.
func namespaceEvidence(s *providerv1.InventorySubject, ns Namespace, observed time.Time) (*providerv1.Evidence, error) {
	raw, err := json.Marshal(details{Name: s.GetName(), Labels: ns.Labels})
	if err != nil {
		return nil, err
	}
	d := &structpb.Struct{}
	if err := protojson.Unmarshal(raw, d); err != nil {
		return nil, err
	}
	e := &providerv1.Evidence{Id: "namespace/" + s.GetName(), Observed: timestamppb.New(observed), Details: d}
	for _, c := range s.GetChecks() {
		e.Attributions = append(e.Attributions, &providerv1.Attribution{Subject: s.GetUid(), Check: c})
	}
	return e, nil
}

// Result returns a staged result's reference and bytes.
func (p *Provider) Result(_ context.Context, id string) (*providerv1.ResultReference, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.staged[id]
	if !ok {
		return nil, nil, providerkit.Errorf(providerv1.ErrorReason_ERROR_REASON_NOT_FOUND, "result %s is unknown", id)
	}
	if !p.now().Before(s.ref.GetExpiresAt().AsTime()) {
		delete(p.staged, id)
		return nil, nil, providerkit.Errorf(providerv1.ErrorReason_ERROR_REASON_RESULT_EXPIRED, "result %s expired unacknowledged", id)
	}
	return s.ref, s.data, nil
}

// Release drops a staged result the host acknowledged.
func (p *Provider) Release(_ context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.staged, id)
	return nil
}

// Staged reports how many results wait for acknowledgement.
func (p *Provider) Staged() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.staged)
}

// Evaluator is the provider's evaluation: a pure function of the start
// message and the payload. It holds no source, so the evaluator process
// has nothing to read but its input.
type Evaluator struct{}

// Evaluate evaluates every RequiredLabel check for every scope namespace,
// reading only the start and the payload: the CollectionResult the host
// captured.
func (Evaluator) Evaluate(_ context.Context, start *providerv1.EvaluateStart, data []byte) (*providerkit.Evaluation, error) {
	res, err := providerkit.ParseCollectionResult(data, nil)
	if err != nil {
		return nil, providerkit.Errorf(providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST, "payload is not a CollectionResult: %v", err)
	}
	type found struct {
		labels   map[string]string
		observed time.Time
	}
	// byPair is each (namespace uid, check) the payload attributes evidence
	// to.
	byPair := map[[2]string]found{}
	for _, e := range res.GetEvidence() {
		raw, err := protojson.Marshal(e.GetDetails())
		var d details
		if err == nil {
			err = json.Unmarshal(raw, &d)
		}
		if err != nil {
			return nil, providerkit.Errorf(providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST, "evidence %s details are not version %d: %v", e.GetId(), PayloadVersion, err)
		}
		for _, a := range e.GetAttributions() {
			byPair[[2]string{a.GetSubject(), a.GetCheck()}] = found{labels: d.Labels, observed: e.GetObserved().AsTime()}
		}
	}
	at := start.GetEvaluationTime().AsTime()
	var obs []*providerv1.Observation
	for _, check := range start.GetChecks() {
		var def struct {
			Label string `json:"label"`
		}
		if err := json.Unmarshal(check.GetDefinition(), &def); err != nil || def.Label == "" {
			return nil, providerkit.Errorf(providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST, "check %s definition needs a label", check.GetName())
		}
		for _, ns := range start.GetScope().GetNamespaces() {
			o := &providerv1.Observation{Subject: ns.GetName(), Check: check.GetName()}
			got, ok := byPair[[2]string{ns.GetUid(), check.GetName()}]
			switch {
			case !ok:
				o.State = providerv1.EvidenceState_EVIDENCE_STATE_MISSING
			case got.observed.After(at):
				o.State = providerv1.EvidenceState_EVIDENCE_STATE_REJECTED
			default:
				o.State = providerv1.EvidenceState_EVIDENCE_STATE_ATTRIBUTABLE
				o.Evaluated = timestamppb.New(got.observed)
				if _, has := got.labels[def.Label]; has {
					o.Raw, o.Outcome = "present", providerv1.Outcome_OUTCOME_PASS
				} else {
					o.Raw, o.Outcome = "absent", providerv1.Outcome_OUTCOME_FAIL
				}
			}
			obs = append(obs, o)
		}
	}
	return &providerkit.Evaluation{Observations: obs}, nil
}
