// Package reporttest is a synthetic, test-only reporting provider. It
// exists to keep the shared provider contract honest: its subjects are
// container images of workloads, its evidence is one posture report per
// image digest shared by every workload running that image, and its checks
// are named verdicts. It has no engine policy, validation index or policy
// report, so any Kyverno assumption in the shared harness or selection
// fails against it.
//
// It is not a model of Trivy or any real producer, establishes no producer
// support, and its fixtures are not producer-compatibility evidence. It is
// never part of the production registry (internal/provider/installed), no
// shipped binary links it (checked by go list in installed_test.go), and
// linking it into a non-test binary panics at startup.
package reporttest

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
)

func init() {
	if !testing.Testing() {
		panic("internal/provider/reporttest is test-only and must not be linked into a binary")
	}
}

const (
	// Name, Version and Contract identify the synthetic provider.
	Name     = "konstapel-reporttest"
	Version  = 1
	Contract = "konstapel-reporttest/v1"
	// CheckKind is its reporting-only check kind.
	CheckKind = "reporttest.konstapel.io/v1/ImagePosture"
	// PayloadVersion is the only input payload version it reads.
	PayloadVersion = 1
)

// ParameterSchema is the descriptor-owned parameter contract of its checks.
var ParameterSchema = json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"maxEvidenceAge":{"type":"string","pattern":"^[0-9]+(s|m|h)$"}}}`)

// Descriptor is the synthetic provider's capability contract: reporting
// only (Audit, no delivery), read-only list/get of its own report type.
func Descriptor() provider.Descriptor {
	return provider.Descriptor{
		Name: Name, Version: Version, EvaluatorVersion: 1,
		Checks: []provider.CheckKind{{Kind: CheckKind, Delivery: false,
			Modes:      []v1alpha1.EnforcementMode{v1alpha1.ModeAudit},
			Parameters: provider.ParameterContract{Source: provider.ParametersFromDescriptor, Schema: ParameterSchema}}},
		Capture:  provider.CaptureCompatibility{Write: PayloadVersion, Read: []int{PayloadVersion}},
		Reads:    []provider.Read{Postures()},
		TestOnly: true,
	}
}

// Input is the synthetic payload: a frozen subject inventory and checks,
// and the posture reports observed for it.
type Input struct {
	PayloadVersion int `json:"payloadVersion"`
	// MaxEvidenceAge bounds report age at the evaluation time.
	MaxEvidenceAge string    `json:"maxEvidenceAge"`
	Subjects       []Subject `json:"subjects"`
	Checks         []string  `json:"checks"`
	Reports        []Report  `json:"reports"`
}

// Subject is one container of one workload instance and the image it runs.
type Subject struct {
	NamespaceUID string `json:"namespaceUID"`
	WorkloadUID  string `json:"workloadUID"`
	Container    string `json:"container"`
	// Image is the reference the workload runs; only a digest reference
	// (…@sha256:<hex>) identifies what a report evaluated.
	Image string `json:"image"`
}

// Report is one posture report for one image digest. EvaluatedAt is when
// the producer evaluated the image; UpdatedAt is when the report object was
// last written and never counts as freshness.
type Report struct {
	ID          string            `json:"id"`
	Digest      string            `json:"digest"`
	EvaluatedAt *time.Time        `json:"evaluatedAt,omitempty"`
	UpdatedAt   *time.Time        `json:"updatedAt,omitempty"`
	Verdicts    map[string]string `json:"verdicts"`
}

// Adapter implements conformance.Adapter for the synthetic provider.
type Adapter struct{}

var _ conformance.Adapter = Adapter{}

// Contract implements conformance.Adapter.
func (Adapter) Contract() string { return Contract }

func decode(raw json.RawMessage) (Input, time.Duration, error) {
	var in Input
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return in, 0, err
	}
	if in.PayloadVersion != PayloadVersion {
		return in, 0, fmt.Errorf("payload version %d is not supported (reads %d)", in.PayloadVersion, PayloadVersion)
	}
	age, err := time.ParseDuration(in.MaxEvidenceAge)
	if err != nil || age <= 0 {
		return in, 0, fmt.Errorf("maxEvidenceAge %q must be a positive duration", in.MaxEvidenceAge)
	}
	return in, age, nil
}

func (s Subject) key() string { return s.NamespaceUID + "/" + s.WorkloadUID + "/" + s.Container }

// digest is the image digest a subject runs, or "" when its reference does
// not pin one.
func (s Subject) digest() string {
	_, d, ok := strings.Cut(s.Image, "@")
	if !ok || !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
		return ""
	}
	return d
}

// Inventory implements conformance.Adapter: every subject times every
// check, from the frozen scope only.
func (Adapter) Inventory(raw json.RawMessage) ([]conformance.Expectation, error) {
	in, _, err := decode(raw)
	if err != nil {
		return nil, err
	}
	var out []conformance.Expectation
	for _, s := range in.Subjects {
		if s.NamespaceUID == "" || s.WorkloadUID == "" || s.Container == "" {
			return nil, fmt.Errorf("subject %+v lacks identity", s)
		}
		for _, c := range in.Checks {
			out = append(out, conformance.Expectation{Subject: s.key(), Check: c})
		}
	}
	return out, nil
}

// normalized maps the synthetic verdict vocabulary. Anything unrecognized
// is unknown, never a pass.
func normalized(raw string) (conformance.Outcome, bool) {
	switch raw {
	case "Passed":
		return conformance.Pass, false
	case "Violated":
		return conformance.Fail, false
	case "Errored":
		return conformance.Error, false
	case "NotApplicable":
		return conformance.Unknown, true
	}
	return conformance.Unknown, false
}

type candidate struct {
	verdict string
	at      time.Time
}

// Evaluate implements conformance.Adapter. Per subject and check, a report
// for the subject's exact digest is usable when it has an evaluation time
// not after at and within maxEvidenceAge. The newest usable verdict counts;
// equally new conflicting verdicts are unresolved; a subject without a
// digest is unresolved for every check.
func (Adapter) Evaluate(raw json.RawMessage, at time.Time) (conformance.Evaluation, error) {
	in, age, err := decode(raw)
	if err != nil {
		return conformance.Evaluation{}, err
	}
	ev := conformance.Evaluation{Observations: []conformance.Observation{}}
	for _, s := range in.Subjects {
		d := s.digest()
		for _, c := range in.Checks {
			o := conformance.Observation{Subject: s.key(), Check: c}
			if d == "" {
				o.State = conformance.Unresolved
				ev.Observations = append(ev.Observations, o)
				continue
			}
			var usable []candidate
			seen := false
			for _, r := range in.Reports {
				v, ok := r.Verdicts[c]
				if r.Digest != d || !ok {
					continue
				}
				seen = true
				if r.EvaluatedAt == nil || r.EvaluatedAt.After(at) || at.Sub(*r.EvaluatedAt) > age || v == "" {
					continue
				}
				usable = append(usable, candidate{verdict: v, at: r.EvaluatedAt.UTC()})
			}
			slices.SortFunc(usable, func(a, b candidate) int { return cmp.Or(b.at.Compare(a.at), cmp.Compare(a.verdict, b.verdict)) })
			switch {
			case len(usable) == 0 && !seen:
				o.State = conformance.Missing
			case len(usable) == 0:
				o.State = conformance.Rejected
			case len(usable) > 1 && usable[0].at.Equal(usable[1].at) && usable[0].verdict != usable[1].verdict:
				o.State = conformance.Unresolved
			default:
				t := usable[0].at
				o.State, o.Raw, o.Evaluated = conformance.Attributable, usable[0].verdict, &t
				o.Outcome, o.NotApplicable = normalized(usable[0].verdict)
			}
			ev.Observations = append(ev.Observations, o)
		}
	}
	return ev, nil
}

// WithoutEvidence implements conformance.Adapter.
func (Adapter) WithoutEvidence(raw json.RawMessage) (json.RawMessage, error) {
	in, _, err := decode(raw)
	if err != nil {
		return nil, err
	}
	in.Reports = []Report{}
	return json.Marshal(in)
}
