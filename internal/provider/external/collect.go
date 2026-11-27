package external

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

// Collection seam (add-external-assessment-providers 3.1.3, design
// Decision 12). Collect is the host's whole read-only collection from one
// registered provider: tested, but called by no assessment run yet. Task
// 3.1 wires it; until then no evidence of an external provider reaches a
// capture, report or export.

// RegistrationReader returns the AssessmentProvider of the given name as
// the controller now sees it, or nil when it does not exist. Collect calls
// it once, right before dispatch, for Frozen.Continue.
type RegistrationReader func(ctx context.Context, name string) (*v1alpha1.AssessmentProvider, error)

// Inventory is a collection's host-frozen inventory (design Decision 9):
// the scope's namespace instances and the namespace and workload subjects
// in them, each with the checks expected for it. The host derives it before
// dispatch; the provider never defines it, and a result can neither add to
// its expectations, narrow them nor replace them.
type Inventory struct {
	Scope    provider.Scope `json:"scope"`
	Subjects []Subject      `json:"subjects"`
	// Supplements allows the provider to report parts of inventory
	// workloads (containers, images) as supplements of them. They never
	// change the expectations.
	Supplements bool `json:"supplements"`
}

// Subject is one inventory subject. It projects identities, a revision and
// expectations only, never object data.
type Subject struct {
	// UID is the object's metadata.uid.
	UID string `json:"uid"`
	// NamespaceUID is its scope namespace's UID, its own for a namespace.
	NamespaceUID string `json:"namespaceUID"`
	// Resource is "group/version/resource", "" for the core group
	// (providerkit.NamespaceResource for a namespace).
	Resource string `json:"resource"`
	Name     string `json:"name"`
	// Revision is the host's revision of the state checks can read (for a
	// workload collector.WorkloadState, never its resourceVersion).
	Revision string `json:"revision"`
	// Checks are the names of the checks expected for the subject.
	Checks []string `json:"checks"`
}

// Expectation is one expected observation: a check of an inventory subject,
// or, for a supplement, of the supplement standing for a part of its
// parent.
type Expectation struct {
	Subject string `json:"subject"`
	Check   string `json:"check"`
}

func (inv Inventory) proto() (*providerv1.Inventory, *providerv1.Scope) {
	scope := &providerv1.Scope{Cluster: inv.Scope.Cluster}
	for _, n := range inv.Scope.Namespaces {
		scope.Namespaces = append(scope.Namespaces, &providerv1.Namespace{Name: n.Name, Uid: n.UID})
	}
	out := &providerv1.Inventory{Supplements: providerv1.Supplements_SUPPLEMENTS_NONE}
	if inv.Supplements {
		out.Supplements = providerv1.Supplements_SUPPLEMENTS_WITHIN_WORKLOADS
	}
	for _, s := range inv.Subjects {
		out.Subjects = append(out.Subjects, &providerv1.InventorySubject{Uid: s.UID, NamespaceUid: s.NamespaceUID, Resource: s.Resource,
			Name: s.Name, Revision: s.Revision, Checks: slices.Clone(s.Checks)})
	}
	return out, scope
}

func (inv Inventory) clone() Inventory {
	out := Inventory{Scope: provider.Scope{Cluster: inv.Scope.Cluster, Namespaces: slices.Clone(inv.Scope.Namespaces)}, Supplements: inv.Supplements}
	for _, s := range inv.Subjects {
		s.Checks = slices.Clone(s.Checks)
		out.Subjects = append(out.Subjects, s)
	}
	return out
}

// StopReason classifies why a collection is incomplete. Every reason means
// the same thing for the run: no evidence of the collection is used.
type StopReason string

const (
	// StopRegistration: the registration the work is frozen to is gone,
	// replaced or changed, or could not be read (Frozen.Continue).
	StopRegistration StopReason = "registration"
	// StopUnavailable: the endpoint could not be reached or authenticated,
	// failed for a reason of its own, or went away mid-transfer.
	StopUnavailable StopReason = "unavailable"
	// StopIncompatible: the endpoint no longer serves the frozen identity
	// or compatibility.
	StopIncompatible StopReason = "incompatible"
	// StopDeadline: the collection did not finish within its deadline.
	StopDeadline StopReason = "deadline"
	// StopLimit: the inventory or the result is beyond the host's or the
	// provider's bounds. An inventory beyond them is never dispatched.
	StopLimit StopReason = "limit"
	// StopMalformed: the response or the staged result violates the
	// protocol.
	StopMalformed StopReason = "malformed"
	// StopDigestMismatch: the transferred bytes are not the staged result.
	StopDigestMismatch StopReason = "digest-mismatch"
	// StopResultLost: the result expired or the provider no longer holds
	// it. The evidence is lost; it is never an empty result.
	StopResultLost StopReason = "result-lost"
	// StopRefused: the provider refused the request as invalid.
	StopRefused StopReason = "refused"
)

// Stop is why a collection is incomplete.
type Stop struct {
	Reason StopReason
	// Message is bounded and carries no credentials or staged data.
	Message string
}

// Limitation is the single limitation the run records for a collection of
// contract this stop ended. Its consequence comes first, as
// provider.LimitError.Limitation puts it.
func (s *Stop) Limitation(contract string) string {
	return fmt.Sprintf("%s evidence is not used: collection incomplete (%s): %s", contract, s.Reason, s.Message)
}

// Collection is one external collection's outcome and the single result
// seam task 3.2 extends: durable capture of Capture, then Acknowledge of
// Result, and resumption. Collect never acknowledges, so the provider keeps
// the result until 3.2 does or until Result.expires_at.
//
// An incomplete collection (Stop set) carries no payload, capture or
// evidence: its expectations are all missing, and Stop.Limitation is its
// one limitation.
type Collection struct {
	Frozen    Frozen
	Inventory Inventory
	Stop      *Stop
	// Result is the staged result's checked reference, and Payload its
	// verified bytes: a CollectionResult.
	Result  *providerv1.ResultReference
	Payload []byte
	// Capture is the version 3 capture document of Payload, recording the
	// frozen registration (collector.EncodeEnvelope), read back through
	// Frozen.CaptureReaders.
	Capture []byte
	// Limitations are the provider's own limitations of the result.
	Limitations []string
	Attribution
}

// Incomplete reports whether no evidence of the collection may be used.
func (c *Collection) Incomplete() bool { return c.Stop != nil }

// Collect collects existing evidence from f's endpoint for the frozen
// inventory, within the stricter of the host's limits and the provider's
// advertised ones and by the earlier of deadline and limits.Timeout:
//
//  1. Frozen.Continue with the registration d.Registration reads now;
//  2. the inventory against the host's bounds: one beyond them is not
//     dispatched;
//  3. one authenticated connection: Describe, checked against f, Collect,
//     then ReadResult of the staged result;
//  4. attribution of the result against the inventory;
//  5. the capture document, read back through f.CaptureReaders.
//
// When ctx ends (leadership loss, shutdown) Collect returns ctx's error and
// nothing may be recorded. A misconfigured host (invalid limits, no
// registration reader) is an error too. Every other failure is a
// Collection with Stop set and no evidence: nothing partial, malformed or
// unverified is ever evidence.
func Collect(ctx context.Context, d *Dialer, f Frozen, inv Inventory, limits provider.Limits, deadline time.Time) (*Collection, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if d == nil || d.Registration == nil {
		return nil, errors.New("external collection: no registration reader is configured")
	}
	c := &Collection{Frozen: f, Inventory: inv.clone()}
	end := time.Now().Add(limits.Timeout)
	if !deadline.IsZero() && deadline.Before(end) {
		end = deadline
	}
	cctx, cancel := context.WithDeadline(ctx, end)
	defer cancel()
	stop := func(reason StopReason, format string, a ...any) (*Collection, error) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("external %s collection: %w", f.Contract(), ctx.Err())
		}
		if cctx.Err() != nil || reason == StopDeadline {
			reason, format, a = StopDeadline, "the collection did not finish within its deadline %s (%s)", []any{end.UTC().Format(time.RFC3339), fmt.Sprintf(format, a...)}
		}
		*c = Collection{Frozen: f, Inventory: c.Inventory, Stop: &Stop{Reason: reason, Message: bound(fmt.Sprintf(format, a...), 512)}}
		return c, nil
	}

	current, err := d.Registration(cctx, f.Registration)
	if err != nil {
		return stop(StopRegistration, "registration %s could not be read: %s", f.Registration, bound(err.Error(), 256))
	}
	if err := f.Continue(current, v1alpha1.ProviderCapabilityCollect); err != nil {
		return stop(StopRegistration, "%s", err.Error())
	}

	host := providerkit.NegotiateLimits(d.Limits.Protocol, collectionLimits(limits))
	pinv, scope := c.Inventory.proto()
	if err := providerkit.CheckInventory(pinv, scope, host.GetMaxSubjects()); err != nil {
		return stopFor(stop, "the inventory is not dispatched", err)
	}
	dd := *d
	dd.Limits.Protocol = host
	conn, err := dd.Connect(cctx, f)
	if err != nil {
		var p *Problem
		if errors.As(err, &p) && p.Condition == v1alpha1.ProviderConditionCompatible {
			return stop(StopIncompatible, "%s", p.Error())
		}
		return stop(StopUnavailable, "%s", bound(err.Error(), 512))
	}
	defer func() { _ = conn.Close() }()

	ref, err := conn.Client.Collect(cctx, scope, pinv, end)
	if err != nil {
		return stopFor(stop, "Collect", err)
	}
	data, res, err := conn.Client.ReadCollection(cctx, ref)
	if err != nil {
		return stopFor(stop, "ReadResult", err)
	}
	capture, err := collector.EncodeEnvelope(f.captureHeader(), data)
	if err == nil {
		_, err = collector.ReadCapture(capture, f.CaptureReaders())
	}
	if err != nil {
		return stop(StopMalformed, "the result does not read back as a capture: %s", bound(err.Error(), 256))
	}
	c.Result, c.Payload, c.Capture = ref, data, capture
	c.Limitations = slices.Clone(ref.GetLimitations())
	c.Attribution = Attribute(c.Inventory, res)
	return c, nil
}

// stopFor classifies a failed call by its protocol reason.
func stopFor(stop func(StopReason, string, ...any) (*Collection, error), at string, err error) (*Collection, error) {
	reason := StopUnavailable
	if errors.Is(err, context.DeadlineExceeded) {
		// The provider ended the call on the propagated deadline, a moment
		// before the host's own context ended.
		return stop(StopDeadline, "%s: %s", at, bound(err.Error(), 512))
	}
	switch providerkit.ReasonOf(err) {
	case providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED:
		reason = StopLimit
	case providerv1.ErrorReason_ERROR_REASON_INVALID_RESPONSE:
		reason = StopMalformed
	case providerv1.ErrorReason_ERROR_REASON_DIGEST_MISMATCH:
		reason = StopDigestMismatch
	case providerv1.ErrorReason_ERROR_REASON_RESULT_EXPIRED, providerv1.ErrorReason_ERROR_REASON_NOT_FOUND:
		reason = StopResultLost
	case providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST:
		reason = StopRefused
	case providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PROTOCOL_VERSION, providerv1.ErrorReason_ERROR_REASON_PROVIDER_MISMATCH,
		providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CONTRACT_VERSION, providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PAYLOAD_VERSION,
		providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_EVALUATOR_VERSION, providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CAPABILITY:
		reason = StopIncompatible
	}
	return stop(reason, "%s: %s", at, bound(err.Error(), 512))
}

// collectionLimits are a collection's host bounds in protocol terms: its
// byte budget bounds the result, and its object budget the inventory's
// subjects, the result's evidence items and supplements.
func collectionLimits(l provider.Limits) *providerv1.Limits {
	objects := uint32(min(l.MaxObjects, math.MaxUint32))
	return &providerv1.Limits{MaxResultBytes: uint64(l.MaxBytes), MaxSubjects: objects, MaxEvidence: objects, MaxObservations: objects}
}

// CaptureRegistration is the registration identity f's captures record.
func (f Frozen) CaptureRegistration() collector.CaptureRegistration {
	return collector.CaptureRegistration{Name: f.Registration, UID: f.UID, Revision: f.Revision, ReleaseDigest: f.ReleaseDigest,
		Protocol: string(f.Protocol), ProtocolRevision: int(f.ProtocolRevision)}
}

func (f Frozen) captureHeader() collector.CaptureHeader {
	reg := f.CaptureRegistration()
	return collector.CaptureHeader{Version: collector.CaptureEnvelopeVersion, Provider: f.Contract(), PayloadVersion: int(f.PayloadVersion),
		EvaluatorVersion: int(f.EvaluatorVersion), Registration: &reg}
}

// CaptureReaders read exactly the captures of work frozen to f: its
// contract, payload and evaluator versions, and its registration. Every
// other capture, a built-in provider's included, is refused.
func (f Frozen) CaptureReaders() collector.CaptureReaders { return frozenReaders{f} }

type frozenReaders struct{ f Frozen }

func (r frozenReaders) CheckCapture(contract string, payloadVersion int) error {
	if contract != r.f.Contract() || payloadVersion != int(r.f.PayloadVersion) {
		return fmt.Errorf("work frozen to registration %s reads %s payload %d only", r.f.Registration, r.f.Contract(), r.f.PayloadVersion)
	}
	return nil
}

func (r frozenReaders) CheckEvaluator(contract string, evaluatorVersion int) error {
	if contract != r.f.Contract() || evaluatorVersion != int(r.f.EvaluatorVersion) {
		return fmt.Errorf("work frozen to registration %s evaluates %s with evaluator %d only", r.f.Registration, r.f.Contract(), r.f.EvaluatorVersion)
	}
	return nil
}

func (r frozenReaders) CheckRegistration(contract string, reg *collector.CaptureRegistration) error {
	switch {
	case reg == nil:
		return fmt.Errorf("a capture of registered provider %s records its registration", contract)
	case *reg != r.f.CaptureRegistration():
		return fmt.Errorf("the capture is frozen to registration %s uid %s revision %d release %s, not to the work's registration %s uid %s revision %d release %s",
			reg.Name, reg.UID, reg.Revision, reg.ReleaseDigest, r.f.Registration, r.f.UID, r.f.Revision, r.f.ReleaseDigest)
	}
	return nil
}

// sortExpectations orders expectations by subject, then check.
func sortExpectations(e []Missing) {
	slices.SortFunc(e, func(a, b Missing) int {
		return cmp.Or(cmp.Compare(a.Subject, b.Subject), cmp.Compare(a.Check, b.Check))
	})
}
