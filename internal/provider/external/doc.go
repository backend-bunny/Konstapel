// Package external is the host side of registered external assessment
// providers (add-external-assessment-providers 2.2): how the controller
// selects an administrator's AssessmentProvider registration for new work,
// freezes the selected registration's identity for that work, reaches the
// endpoint over the public kit's mutual TLS and reports the endpoint's
// availability and compatibility as registration status.
//
// Selection (Catalog) extends the compiled-in registry and never replaces
// it. A provider name built into Konstapel always resolves to the built-in
// provider; a registration naming one is never contacted or selected. A
// registered contract resolves to exactly one registration: the single
// registration of that provider name and contract version whose
// newRequests is Enabled, and only while its status shows it Ready for its
// current revision. Every other case is an explicit, bounded
// provider.SelectionError; nothing falls back to another registration,
// release, version or provider, and nothing is downloaded or executed.
//
// The frozen identity (Frozen) is the registration UID, its configuration
// revision (metadata.generation), the implementation the endpoint reported
// (the release digest) and that revision's endpoint configuration. Work
// frozen to it keeps using exactly that configuration: a later revision,
// including newRequests Disabled, is used only by new work. Deleting or
// replacing the registration ends the frozen work explicitly, as does an
// endpoint that no longer reports the frozen implementation.
//
// Each registration is probed on its own with a bounded deadline. One
// unavailable or incompatible endpoint never affects the selection,
// probing or availability of another registration or of a built-in
// provider.
package external
