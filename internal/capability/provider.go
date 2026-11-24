package capability

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
)

// Provider availability (add-assessment-provider-contract 2.2).
//
// An installed provider's prerequisites are the ones its descriptor
// declares, and ForProvider turns them into capability requirements, so
// there is no second list to keep in step. The Kyverno provider's are the
// Assessment capability (Requirements[Assessment]), which keeps its name,
// messages and metrics. Any other provider is checked as ProviderName(its
// contract).
//
// Every provider is checked separately through the same bounded, cached
// Monitor. A missing API, denied access or unreachable dependency of one
// provider never makes another unavailable. Recovery needs no restart,
// because a result is reused for at most the Monitor's TTL.
//
// Enforcement is a separate dimension. A provider that delivers engine
// resources enforces through the delivery owner's capability (Delivery). A
// reporting-only provider never enforces. Its enforcement is NotApplicable,
// which is not Available, so nothing can count it as ready enforcement, and
// checking it never consults the delivery capability.

// NotApplicable: the capability does not apply, such as enforcement by a
// reporting-only provider. It is never Available and is not a failure of
// any dependency.
const NotApplicable Reason = "NotApplicable"

// ForProvider derives a provider's capability requirements from its
// descriptor. Each declared read must be served in its declared shape and
// with its verbs, and the service account must be allowed those verbs (in
// every namespace for a namespaced read). Each declared prerequisite must be
// served in its shape and with its verbs; no access is reviewed for it.
// Reads come first, in declaration order, then prerequisites, so discovery
// reports the first unmet requirement in a stable order.
func ForProvider(d provider.Descriptor) []Resource {
	out := make([]Resource, 0, len(d.Reads)+len(d.Requires))
	for _, r := range d.Reads {
		out = append(out, Resource{Group: r.Group, Version: r.Version, Resource: r.Resource, Kind: r.Kind, Namespaced: r.Namespaced,
			Verbs: slices.Clone(r.Verbs), Access: slices.Clone(r.Verbs)})
	}
	for _, p := range d.Requires {
		out = append(out, Resource{Group: p.Group, Version: p.Version, Resource: p.Resource, Kind: p.Kind, Namespaced: p.Namespaced,
			Verbs: slices.Clone(p.Verbs)})
	}
	return out
}

// ProviderName is the evidence capability of an installed provider other
// than Kyverno, such as "Assessment(konstapel-reporttest/v1)". Its results
// and messages name the provider, so a diagnostic is attributable.
func ProviderName(contract string) Name { return Name(string(Assessment) + "(" + contract + ")") }

// Providers checks each installed provider's availability through one
// Monitor. It is immutable after NewProviders.
type Providers struct {
	monitor   *Monitor
	byName    map[string]providerCapability
	contracts []string
}

type providerCapability struct {
	evidence     Name
	requirements []Resource
	// reporting: no check kind of the provider delivers engine resources.
	reporting bool
}

// NewProviders derives the capabilities of the given installed providers.
// It rejects an invalid descriptor, a contract given twice, a Kyverno
// descriptor whose prerequisites differ from the Assessment capability,
// and a provider other than Kyverno that delivers engine resources: only
// the Kyverno engine has a delivery capability.
func NewProviders(m *Monitor, descriptors ...provider.Descriptor) (*Providers, error) {
	if m == nil {
		return nil, errors.New("provider capabilities: no monitor")
	}
	p := &Providers{monitor: m, byName: map[string]providerCapability{}}
	var errs []error
	for _, d := range descriptors {
		if err := d.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		c := d.Contract()
		if _, dup := p.byName[c]; dup {
			errs = append(errs, fmt.Errorf("provider %s is given twice", c))
			continue
		}
		e := providerCapability{evidence: ProviderName(c), requirements: ForProvider(d),
			reporting: !slices.ContainsFunc(d.Checks, func(k provider.CheckKind) bool { return k.Delivery })}
		switch {
		case c == kyverno.Contract && !reflect.DeepEqual(e.requirements, Requirements[Assessment]):
			errs = append(errs, fmt.Errorf("provider %s declares prerequisites that differ from the %s capability", c, Assessment))
			continue
		case c == kyverno.Contract:
			e.evidence = Assessment
		case !e.reporting:
			errs = append(errs, fmt.Errorf("provider %s delivers engine resources, but only %s has a delivery capability", c, kyverno.Contract))
			continue
		}
		p.byName[c] = e
		p.contracts = append(p.contracts, c)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("provider capabilities: %w", errors.Join(errs...))
	}
	slices.Sort(p.contracts)
	return p, nil
}

// Contracts lists the providers' contracts, sorted.
func (p *Providers) Contracts() []string { return slices.Clone(p.contracts) }

// Name is the evidence capability of the provider, or "" when it is not
// one of these providers.
func (p *Providers) Name(contract string) Name { return p.byName[contract].evidence }

// Evidence returns whether the provider's evidence source can be used: its
// declared reads and prerequisites. An unknown provider is Unavailable.
func (p *Providers) Evidence(ctx context.Context, contract string) Result {
	e, ok := p.byName[contract]
	if !ok {
		return notInstalled(contract)
	}
	return p.monitor.checkResources(ctx, e.evidence, e.requirements)
}

// Enforcement returns whether the provider can enforce: the delivery
// capability for a provider that delivers engine resources, and
// NotApplicable for a reporting-only one, whose readiness never claims
// enforcement. An unknown provider is Unavailable.
func (p *Providers) Enforcement(ctx context.Context, contract string) Result {
	e, ok := p.byName[contract]
	switch {
	case !ok:
		return notInstalled(contract)
	case e.reporting:
		return Result{Name: e.evidence, Reason: NotApplicable,
			Message: fmt.Sprintf("%s: enforcement is not applicable: %s is reporting-only and delivers no engine resources", e.evidence, contract)}
	}
	return p.monitor.Check(ctx, Delivery)
}

// EvidenceCheck adapts Evidence to an (available, error) check, like
// Monitor.Engine.
func (p *Providers) EvidenceCheck(contract string) func(context.Context) (bool, error) {
	return asCheck(func(ctx context.Context) Result { return p.Evidence(ctx, contract) })
}

// EnforcementCheck adapts Enforcement to an (available, error) check. For a
// reporting-only provider it always returns false and an *Error whose
// reason is NotApplicable.
func (p *Providers) EnforcementCheck(contract string) func(context.Context) (bool, error) {
	return asCheck(func(ctx context.Context) Result { return p.Enforcement(ctx, contract) })
}

func notInstalled(contract string) Result {
	n := ProviderName(contract)
	return Result{Name: n, Reason: Unavailable, Message: fmt.Sprintf("%s: provider %s is not installed", n, contract)}
}
