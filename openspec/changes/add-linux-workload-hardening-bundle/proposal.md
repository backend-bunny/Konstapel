# Proposal

## Why

The researched Kyverno samples provide concrete additional evidence for Linux
workload hardening. Konstapel needs a tested, versioned bundle with authored
Moderate mappings and explicit exception behavior, building on the proven
single-policy assessment loop.

## What Changes

- Add four `policies.kyverno.io/v1` policies: `disallow-privilege-escalation`,
  `disallow-capabilities-strict`, `require-run-as-nonroot`, and
  `restrict-seccomp-strict`.
- Vendor identified upstream sources and relevant fixtures with license,
  checksums, and separately tracked local variants.
- Scope the bundle to Linux. Treat explicit Windows workloads as outside this
  bundle's assessment scope, with no passing Linux coverage inferred from skips.
- Remove the non-root policy's automatic `hostUsers: false` bypass. A Linux
  workload that cannot meet the non-root requirement needs an explicit permitted
  exception with recorded risk acceptance.
- Ship bounded mappings to verified Moderate statements and exercise multiple
  checks contributing evidence to shared controls without inflating coverage.
- Validate rendered policies, real admission/background behavior, exception
  handling, and C2P/OSCAL evidence using the preceding integration contracts.

## Capabilities

### New Capabilities

- `linux-workload-hardening`: Ship and assess a defined set of Linux workload
  configuration checks, including explicit coverage and exception semantics.

### Modified Capabilities

None. The existing privileged-container check remains owned by the assessment
loop and is a complementary prerequisite for the expanded demonstration.

## Impact

Adds policy content, local transformations, mapping artifacts, rendered-policy
tests, runtime acceptance fixtures, and bundle documentation. The evidence base
is `docs/research/next-policy-bundle.md`; its test results are research input,
not acceptance results for the changed policies.

Content and CLI fixture work can proceed independently in separate policy
directories. Use the assessment loop's content format once available. Scope/mode
integration depends on `add-compliance-targeting-api`; accepted-risk integration
depends on `add-self-service-policy-exceptions`. Full acceptance requires those
merged implementations. Registry restrictions, Windows policy coverage, and a
complete NIST Moderate or Kubernetes Restricted implementation are outside scope.
