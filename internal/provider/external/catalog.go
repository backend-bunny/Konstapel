package external

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/provider"
)

// DefaultMaxStatusAge bounds how old a registration's last compatible
// observation may be for new work to select it. The controller re-probes
// every registration well within it, so only a status nobody refreshes,
// for example while no controller leads, goes stale.
const DefaultMaxStatusAge = 5 * time.Minute

// CatalogOptions configure a Catalog.
type CatalogOptions struct {
	// BuiltIn is the compiled-in registry (installed.Registry()). Required.
	BuiltIn *provider.Registry
	// External enables registered external providers. When false,
	// Registrations are ignored and every contract that is not built in is
	// UnknownProvider, exactly as without registration support.
	External bool
	// Registrations are the AssessmentProviders, in any order.
	Registrations []v1alpha1.AssessmentProvider
	// Now is the selection time; MaxStatusAge (default DefaultMaxStatusAge)
	// bounds the age of the observation a selection relies on.
	Now          time.Time
	MaxStatusAge time.Duration
}

// Catalog resolves provider contracts for new work: built-in providers
// first, then registered external providers. It is an immutable, pure
// function of its options; it reads no cluster and contacts no endpoint.
type Catalog struct {
	builtIn  *provider.Registry
	external bool
	regs     []v1alpha1.AssessmentProvider
	now      time.Time
	maxAge   time.Duration
}

// NewCatalog builds a catalog.
func NewCatalog(o CatalogOptions) (*Catalog, error) {
	if o.BuiltIn == nil {
		return nil, errors.New("provider catalog: no built-in registry")
	}
	c := &Catalog{builtIn: o.BuiltIn, external: o.External, now: o.Now, maxAge: o.MaxStatusAge}
	if c.maxAge <= 0 {
		c.maxAge = DefaultMaxStatusAge
	}
	if o.External {
		c.regs = make([]v1alpha1.AssessmentProvider, 0, len(o.Registrations))
		for i := range o.Registrations {
			c.regs = append(c.regs, *o.Registrations[i].DeepCopy())
		}
		slices.SortFunc(c.regs, func(a, b v1alpha1.AssessmentProvider) int { return cmp.Compare(a.Name, b.Name) })
	}
	return c, nil
}

// Selected is a resolved contract: a built-in provider's descriptor, or the
// frozen identity of the one selected registration.
type Selected struct {
	Contract string
	BuiltIn  *provider.Descriptor
	External *Frozen
}

// BuiltIn reports whether a provider name is built into Konstapel, at any
// contract version. Such a name is never resolved to a registration.
func (c *Catalog) BuiltIn(name string) bool {
	return slices.ContainsFunc(c.builtIn.Descriptors(), func(d provider.Descriptor) bool { return d.Name == name })
}

// Resolve selects the provider of contract for new work that needs the
// given capabilities. Rules, in order:
//
//   - An empty contract is the built-in default; a malformed one is
//     InvalidSelection.
//   - A built-in provider name resolves only to the built-in provider
//     (IncompatibleVersion for another version); registrations are not
//     consulted, so a built-in provider is never shadowed.
//   - Without external providers enabled, or without a registration of
//     the name, the contract is UnknownProvider. Registrations of the name
//     at other contract versions only are IncompatibleVersion.
//   - Of the registrations of the contract, those with newRequests
//     Disabled are never selected: none Enabled is ProviderDisabled, more
//     than one Enabled is AmbiguousProvider. Selection never picks among
//     registrations, so it does not depend on order, age or health.
//   - The one Enabled registration must allow every needed capability
//     (UnsupportedCapability), and its status must show it Ready, with a
//     compatible identity, for its current revision, observed within the
//     maximum status age (ProviderUnavailable otherwise).
//
// The result freezes the selected registration's current revision.
func (c *Catalog) Resolve(contract string, need ...v1alpha1.AssessmentProviderCapability) (Selected, *provider.SelectionError) {
	if contract == "" {
		contract = c.builtIn.Default()
	}
	name, version, err := provider.ParseContract(contract)
	if err != nil {
		return Selected{}, &provider.SelectionError{Reason: provider.ReasonInvalidSelection, Message: err.Error()}
	}
	if c.BuiltIn(name) {
		d, serr := c.builtIn.Lookup(contract)
		if serr != nil {
			return Selected{}, serr
		}
		return Selected{Contract: d.Contract(), BuiltIn: &d}, nil
	}
	fail := func(reason provider.SelectionReason, format string, a ...any) (Selected, *provider.SelectionError) {
		return Selected{}, &provider.SelectionError{Reason: reason, Message: fmt.Sprintf(format, a...)}
	}
	if !c.external {
		return fail(provider.ReasonUnknownProvider, "provider %s is not installed (installed: %s); registered external providers are not enabled on this controller",
			contract, strings.Join(c.builtIn.Contracts(), ", "))
	}
	var named, matching, enabled []v1alpha1.AssessmentProvider
	for _, ap := range c.regs {
		if ap.Spec.Provider.Name != name {
			continue
		}
		named = append(named, ap)
		if int(ap.Spec.Compatibility.ContractVersion) != version {
			continue
		}
		matching = append(matching, ap)
		if enabledForNew(&ap) {
			enabled = append(enabled, ap)
		}
	}
	switch {
	case len(named) == 0:
		return fail(provider.ReasonUnknownProvider, "provider %s is neither installed (installed: %s) nor registered", contract, strings.Join(c.builtIn.Contracts(), ", "))
	case len(matching) == 0:
		var versions []string
		for _, ap := range named {
			versions = append(versions, Expected(&ap).Contract())
		}
		slices.Sort(versions)
		return fail(provider.ReasonIncompatibleVersion, "provider contract %s is not registered; registrations name %s", contract, list(slices.Compact(versions)))
	case len(enabled) == 0:
		return fail(provider.ReasonProviderDisabled, "every registration of %s (%s) has newRequests Disabled or is being deleted", contract, names(matching))
	case len(enabled) > 1:
		return fail(provider.ReasonAmbiguousProvider, "registrations %s all name %s with newRequests Enabled; disable all but one", names(enabled), contract)
	}
	ap := &enabled[0]
	f := Expected(ap)
	for _, n := range need {
		if !f.Allows(n) {
			return fail(provider.ReasonUnsupportedCapability, "registration %s of %s does not allow %s (allows %v)", ap.Name, contract, n, f.Capabilities)
		}
	}
	if msg := c.unready(ap, need); msg != "" {
		return fail(provider.ReasonProviderUnavailable, "registration %s of %s: %s", ap.Name, contract, msg)
	}
	return Selected{Contract: f.Contract(), External: &f}, nil
}

// unready explains why the registration's status does not show it Ready
// for its current revision, or is "".
func (c *Catalog) unready(ap *v1alpha1.AssessmentProvider, need []v1alpha1.AssessmentProviderCapability) string {
	st := ap.Status
	gen := ap.Generation
	if st.ObservedGeneration != gen {
		return fmt.Sprintf("its status describes revision %d, not the current revision %d", st.ObservedGeneration, gen)
	}
	ready := meta.FindStatusCondition(st.Conditions, v1alpha1.ProviderConditionReady)
	switch {
	case ready == nil || ready.ObservedGeneration != gen:
		return fmt.Sprintf("revision %d is not probed yet", gen)
	case ready.Status != metav1.ConditionTrue:
		return fmt.Sprintf("not Ready (%s): %s", ready.Reason, bound(ready.Message, 256))
	}
	id := st.Identity
	f := Expected(ap)
	switch {
	case id == nil:
		return "no compatible identity is observed"
	case id.Name != f.Provider || id.ReleaseDigest != f.ReleaseDigest || id.Protocol != f.Protocol || id.ContractVersion != f.ContractVersion ||
		id.EvaluatorVersion != f.EvaluatorVersion || id.PayloadVersion != f.PayloadVersion:
		return "the observed identity differs from the registration"
	case c.now.Sub(id.ObservedAt.Time) > c.maxAge:
		return fmt.Sprintf("it was last observed compatible at %s, more than %s ago", id.ObservedAt.UTC().Format(time.RFC3339), c.maxAge)
	}
	for _, n := range need {
		if !slices.Contains(id.Capabilities, n) {
			return fmt.Sprintf("the endpoint was not observed serving %s", n)
		}
	}
	return ""
}

// Conflicts are the other registrations that make ap's contract
// ambiguous: every other registration of the same provider name and
// contract version with newRequests Enabled, sorted. It is empty while ap
// itself is Disabled.
func (c *Catalog) Conflicts(ap *v1alpha1.AssessmentProvider) []string {
	if !enabledForNew(ap) {
		return nil
	}
	var out []string
	for _, o := range c.regs {
		if o.Name != ap.Name && o.Spec.Provider.Name == ap.Spec.Provider.Name &&
			o.Spec.Compatibility.ContractVersion == ap.Spec.Compatibility.ContractVersion && enabledForNew(&o) {
			out = append(out, o.Name)
		}
	}
	return out
}

// Registration returns the registration of the given name, or nil.
func (c *Catalog) Registration(name string) *v1alpha1.AssessmentProvider {
	i := slices.IndexFunc(c.regs, func(ap v1alpha1.AssessmentProvider) bool { return ap.Name == name })
	if i < 0 {
		return nil
	}
	return c.regs[i].DeepCopy()
}

// enabledForNew: newRequests is Enabled (the default) and the registration
// is not being deleted.
func enabledForNew(ap *v1alpha1.AssessmentProvider) bool {
	return ap.Spec.NewRequests != v1alpha1.ProviderNewRequestsDisabled && ap.DeletionTimestamp == nil
}

func names(aps []v1alpha1.AssessmentProvider) string {
	out := make([]string, 0, len(aps))
	for _, ap := range aps {
		out = append(out, ap.Name)
	}
	return list(out)
}

// list joins at most eight names, then counts the rest.
func list(s []string) string {
	const shown = 8
	if len(s) <= shown {
		return strings.Join(s, ", ")
	}
	return strings.Join(s[:shown], ", ") + " and " + strconv.Itoa(len(s)-shown) + " more"
}
