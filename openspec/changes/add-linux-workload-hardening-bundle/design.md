# Design

## Context

See [proposal.md](proposal.md),
[linux-workload-hardening](specs/linux-workload-hardening/spec.md), and the
[merged research](../../../docs/research/next-policy-bundle.md). Research verified
upstream CLI expectations and NIST references; it did not test these local
variants, live admission, background reporting, or accepted-risk export.

The first assessment loop owns the privileged-container check and establishes
content packaging, rendering, C2P-Go v2, and the disposable cluster environment.
Targeting supplies scope/mode and versioned policy instances. Exceptions supplies
the only supported self-service waiver path.

## Goals / Non-Goals

**Goals:** Ship reproducible Linux configuration checks with independently
identifiable evidence and bounded Moderate mappings. Make every local semantic
change visible in provenance and test it against the deployed renderings.

**Non-Goals:** Windows hardening, image registry policy, a complete Kubernetes
Restricted profile, full NIST control satisfaction, runtime attestation, or a
second copy of the privileged-container check.

## Decisions

### 1. Vendor four sources and maintain explicit local variants

Use the four directories under `pod-security-vpol/restricted/` at
`kyverno/policies` revision `fac1ccda72ab53594921ca1c040ac90b80afadcd`:

- `disallow-privilege-escalation`
- `disallow-capabilities-strict`
- `require-run-as-nonroot`
- `restrict-seccomp-strict`

Preserve original YAML, relevant hidden CLI/Chainsaw fixtures, Apache-2.0 license,
and applicable notices. Record source URLs, checksums, and local transformations
separately. The content manifest records source, variant, and rendered digests.
Use the first loop's packaging contract once merged; do not design a competing
bundle format or follow moving upstream URLs during reconciliation.

Keep one stable logical check per named policy, with sub-validation identifiers
where available. The capabilities policy's drop/add validations remain traceable
parts of that check. Binding instance names and runtime revisions are separate
identities. Compose the expanded demonstration with the existing privileged
check by reference through the content format, without copying its source.

Copying the full upstream library would expand scope and maintenance cost.
Editing upstream files in place would make local intent harder to audit.

### 2. Make Linux scope and the non-root deviation explicit

Add a consistent OS applicability guard to the local variants: explicit
`spec.os.name: windows` is outside scope; missing OS uses the documented Linux-rule
convention. Apply the same convention to extracted Pod templates, including
CronJob job templates. Record scope in the expected assessment inventory rather
than inferring it solely from a policy skip or a passing short-circuit expression.
The API declaration is not evidence of the node's observed operating system.

Remove the non-root expression's unconditional `hostUsers: false` bypass. Preserve
its other semantics: every container sets or inherits `runAsNonRoot: true`,
explicit container false fails, and explicit Pod-level false fails even if all
containers set true. Add Windows exclusion to this policy, which upstream lacks.
Retain source fixtures as provenance and add local expected results for every
intentional difference; do not rewrite history to claim the upstream suite proved
the variant.

Implicit user-namespace acceptance would bypass the user's risk-acceptance
workflow. A valid self-service exception can waive the non-root check when
centrally allowed, with the usual recorded scope and lifetime.

### 3. Preserve exact checks and avoid hidden relaxations

Require `allowPrivilegeEscalation: false` on every applicable regular, init, and
ephemeral container. There is no Pod-level inheritance for that setting.
Require `capabilities.drop` to include exact `ALL`; only exact `NET_BIND_SERVICE`
may be added by default. Keep both validations in the shipped combined policy.
The upstream added-capabilities helper is a fixture aid, not another shipped check.

Seccomp accepts `RuntimeDefault` or `Localhost`, with allowed container values or
Pod inheritance. Missing both fails, and an invalid Pod-level type fails. These
checks do not inspect actual capability sets, UID, privilege transitions, or
Localhost profile contents. Document those limits alongside the mappings.

Rendering adds the targeting contract's selector/mode and provenance while
retaining background evaluation and the source's supported workload/operation
set. No default namespace exclusions or sample exceptions are added. Central
profiles default each policy to Forbidden; an operator explicitly opts individual
checks into SelfService with a maximum lifetime.

Do not expose upstream `images`/`allowedValues` waivers as an independent product
API. The first exception capability grants a recorded whole-policy exemption;
for capabilities that can waive both drop and add validations. Document this
scope clearly. Fine-grained waivers preserving selected sub-validations require
separate later design.

### 4. Author bounded mappings against the pinned Moderate content

Use NIST revision `f0de6d8d8c059d374f15e0ae07508d82e370fc1d` as the authoritative
catalog/profile input and verify each statement and Moderate inclusion again:

| Logical check | Mapped statements | Evidence boundary |
| --- | --- | --- |
| Privilege escalation | `ac-6_smt`, `cm-6_smt.b` | One declared privilege/configuration restriction |
| Capabilities | `ac-6_smt`, `cm-7_smt.b`, `cm-6_smt.b` | Declared capability lists, not effective privileges |
| Non-root | `ac-6_smt`, `cm-6_smt.b` | Requested non-root execution, not observed UID |
| Seccomp | `cm-7_smt.b`, `cm-6_smt.b` | Selected profile type, not profile content or observed filtering |

Keep each check's rationale and exclusions in the Component Definition and
assessment context. Multiple checks sharing AC-6 contribute separate observations
to the same control; multiple bindings do not multiply satisfied controls. No
single or combined pass establishes full-control or baseline compliance.

Preserve official OSCAL 1.2.3 source documents. Use the C2P pin's supported OSCAL
1.1.3 for authored/generated inputs and outputs, validating each at its declared
version. Do not round-trip the newer catalog through older Go model types.

### 5. Separate content validation from runtime acceptance

Initially use Kyverno runtime/CLI 1.19.2, matching the first loop; record exact
Kubernetes/chart/image pins when its environment lands. The exception change has
an explicit expiry compatibility gate and may require a corrected engine pin.
Full bundle acceptance uses that verified runtime and reruns the initial check
and all four variants after any pin change.

Run the retained upstream CLI suite to establish the source baseline, then test
the actual variants and binding renderings. Add the full capability add/drop
matrix against the combined policy, non-root inheritance/override/user-namespace
cases, OS scope, seccomp inheritance, and all applicable container forms.

Use a pinned disposable Linux cluster for real admission and background cases.
Seed violating workloads before Deny policy installation, capture readiness and
policy-specific denial reasons, and distinguish rejected creations from persisted
background subjects. Exercise controller templates and ephemeral-container
updates where supported. Runtime prerequisites for `hostUsers: false` must be
recorded: CLI rejection is useful but cannot replace a required live case or
prove runtime isolation. Record any container-execution evidence separately
from policy configuration evidence.

Capture expected scope independently of reports. Windows is out of scope, accepted
exceptions are risk acceptance, missing reports are incomplete, and ordinary
passes require complete unexcepted evaluation. Preserve source timestamps,
resource UIDs, cluster identity, policy revisions, and acceptance snapshots through
C2P to the final OSCAL package.

### 6. Keep agent work isolated until integration dependencies land

This change owns the four new source/variant directories, their fixtures, new
mapping entries, and bundle documentation. Vendoring and CLI cases can proceed
in parallel with the controller work. Content packaging and Go adapter use wait
for the merged first-loop contracts. Binding integration waits for targeting;
accepted-risk integration waits for exceptions and its compatible runtime.

Do not rewrite the initial privileged policy, bootstrap another Go module, or
modify profile/exception CRDs from this change. Rebase before editing shared
content manifests or the combined acceptance entry point. Artifact completion
does not imply any of those external implementations are already available.

## Risks / Trade-offs

- **Local variants diverge from upstream expectations:** preserve originals and
  test each intentional delta, including removal of the user-namespace bypass.
- **Upstream test counts overstate shipped coverage:** execute the rendered
  combined policies and publish per-case results with rendered digests.
- **Runtime support varies by node and Kubernetes version:** pin and record the
  tested Linux environment; do not mark unsupported live cases as passed.
- **Windows short-circuits look like success in raw reports:** retain raw values
  and independently mark OS applicability as outside Linux coverage.
- **Related checks inflate NIST coverage:** keep stable check/control identities
  and regression-test partial coverage, including repeated binding results.

## Migration Plan

Introduce new immutable bundle content and Audit bindings in a disposable test
namespace. Verify scope, reports, and mappings, then add Deny bindings and explicit
exceptions for selected eligible checks. Roll out to other namespaces only through
central bindings; do not change existing profile content silently.

Rollback by restoring the prior pinned profile/binding revision and observing
policy replacement, or remove only test-owned bindings. New revisions require
renewed risk acceptance; rollback does not automatically revive an old acceptance.
Preserve raw reports and output packages for comparison across bundle revisions.
