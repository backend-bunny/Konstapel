package controller

import (
	"slices"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
)

// Provider evidence watches (add-assessment-provider-contract 2.2).
//
// The host owns watch setup. Each evidence source that an installed
// provider declares watchable (a read with the watch verb) gets one
// cluster-wide deferred watch. The watch is registered once that
// provider's own evidence capability is available
// (capability.Providers.EvidenceCheck), and never because another provider
// is available. A source event re-reconciles the assessment of every
// binding. A provider that declares no watch gets no informer: collection
// reads its source each time a snapshot is taken, and capability changes
// still re-reconcile through the capability trigger.

// providerWatch is one deferred evidence-source watch.
type providerWatch struct {
	name string
	gvk  schema.GroupVersionKind
	// available is the owning provider's evidence capability.
	available EngineAvailable
}

// providerWatches derives the evidence-source watches of the installed
// providers, in descriptor order. evidence returns a provider's evidence
// capability check.
func providerWatches(descriptors []provider.Descriptor, evidence func(contract string) EngineAvailable) []providerWatch {
	var out []providerWatch
	for _, d := range descriptors {
		for _, r := range d.Reads {
			if !slices.Contains(r.Verbs, "watch") {
				continue
			}
			out = append(out, providerWatch{name: watchName(d, r), gvk: schema.GroupVersionKind{Group: r.Group, Version: r.Version, Kind: r.Kind},
				available: evidence(d.Contract())})
		}
	}
	return out
}

// watchName names a watch's runnable and logger. The Kyverno report watch
// keeps its historic name.
func watchName(d provider.Descriptor, r provider.Read) string {
	if d.Contract() == kyverno.Contract && r.ID() == kyverno.Reports().ID() {
		return "assessment-policy-reports"
	}
	return "assessment-" + d.Name + "-" + r.Resource
}
