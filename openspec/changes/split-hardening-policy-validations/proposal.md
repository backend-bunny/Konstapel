# Proposal

## Why

Issue [#362](https://github.com/backend-bunny/Konstapel/issues/362) correlates 292
missing observations to unreported siblings in multi-validation hardening policies.
Kyverno's saved fixtures already demonstrate this behavior. Splitting the checks
lets the producer report each outcome without weakening collector safeguards.

## What Changes

- Split capabilities into drop-ALL and allowed-additions policies, and seccomp into
  Pod-profile and effective-container-profile policies, each with one validation.
- Preserve the original expressions, variables, matching, Linux applicability,
  exception inputs and security requirements in policies.kyverno.io/v1 resources.
- Update authored OSCAL/check mappings, descriptors, local-variant provenance,
  tests and independently versioned bundle release inputs.
- Owner decision 2026-11-27 (option a): keep the vendored bundle stable. Its
  content and digest stay on the original five-policy revision; the split checks
  ship only through the separately versioned OCI bundle
  `konstapel-linux-hardening` 0.2.0. Users get independent outcomes only by
  explicitly selecting that OCI revision.
- **BREAKING for selectors adopting the new bundle revision:** old logical policy
  IDs become explicit replacement pairs. Document migration and safe staged
  replacement; never reinterpret an old pinned digest or exception acceptance.
- Prove all four result combinations for each pair in live admission/background
  assessment and export. Preserve missing/stale/unresolved behavior elsewhere.

## Capabilities

### New Capabilities

- `hardening-policy-migration`: Independently reported hardening revisions,
  identity/mapping compatibility and safe operator migration between bundle pins.

### Modified Capabilities

None in main specs. The active linux-workload-hardening plan describes the original
four policy families and its initial bundle. This follow-up owns their versioned
split and migration; implementation must reconcile that owner's remaining tasks
without rewriting historical acceptance or claiming blocked exception support.

## Impact

Touches content/linux-hardening variants, provenance and component definitions,
the OCI bundle definition (next version) and build inputs, hardening fixtures,
targeting migration tests, and installation/migration documentation. Preserve
original upstream files, the vendored content and its digest, and old published
artifacts. New signed bundle publication needs separate release
authorization; this plan prepares and verifies release inputs, not production
tags. No inferred sibling passes, reduced check inventory or unrelated policy
tightening is included.
