// Package installed assembles the production provider registry: the
// providers compiled into Konstapel's shipped binaries. It is a closed list.
// Nothing at runtime, and nothing in bundle content, adds to it; a
// test-only provider is never part of it (see installed_test.go, which
// also checks that no shipped binary links one).
package installed

import (
	"fmt"

	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
)

// Default is the contract a selection without an explicit provider implies:
// every existing binding and profile resolves to the Kyverno provider.
const Default = kyverno.Contract

// Registry returns the production registry. It panics only if the
// compiled-in descriptors are inconsistent, which the package tests rule out.
func Registry() *provider.Registry {
	descriptors := []provider.Descriptor{kyverno.Descriptor()}
	for _, d := range descriptors {
		if d.TestOnly {
			panic(fmt.Sprintf("installed provider registry: %s is test-only", d.Contract()))
		}
	}
	r, err := provider.New(Default, descriptors...)
	if err != nil {
		panic(err)
	}
	return r
}
