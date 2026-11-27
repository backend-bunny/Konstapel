# Spec Delta

## Purpose

Allow independently deployed assessment providers to supply bounded evidence and
optional scan execution through an authenticated, versioned contract.

## ADDED Requirements

### Requirement: Administrators register external providers

Konstapel SHALL select external providers only through administrator-owned
AssessmentProvider registrations. Registration SHALL bind its source and
evaluator endpoints, expected provider identity, compatible contracts, and
permitted capabilities. Bundles
SHALL NOT install providers, grant permissions, or choose arbitrary endpoints.
Built-in identities SHALL NOT be silently shadowed.

#### Scenario: Content names an unregistered provider

- **WHEN** a bundle requires an unknown external provider
- **THEN** resolution fails explicitly without downloading or executing code

#### Scenario: A namespace team edits provider registration

- **WHEN** a caller with only namespace assessment rights creates or changes registration
- **THEN** authorization denies the request

### Requirement: Provider communication authenticates both parties

Requests and responses SHALL use authenticated encrypted transport with explicit
peer identity checks. Invalid identity, unavailable trust, incompatible protocol,
or capability mismatch SHALL prevent execution. Provider availability SHALL be
reported separately from findings; failure SHALL NOT block unrelated providers.

#### Scenario: An endpoint impersonates the registered provider

- **WHEN** a service presents an untrusted certificate or wrong provider identity
- **THEN** Konstapel sends no assessment payload and records the availability failure

### Requirement: Providers are independently installed OCI workloads

External providers SHALL run in separate pods installed and upgraded by platform
operators. Reference distributions SHALL include Helm charts and signed,
digest-pinned OCI images with SBOMs and provenance. Installation instructions
SHALL verify artifact identity and publisher before use. Konstapel SHALL NOT
install workloads or extract executable plugins from OCI bundles.

#### Scenario: Upgrade a provider independently

- **WHEN** an operator upgrades a provider to an approved compatible image
- **THEN** new work can use it without rebuilding Konstapel
- **AND** incompatible existing work is not silently reinterpreted

### Requirement: Source authority stays with the provider

Providers SHALL use dedicated identities and explicitly approved targets.
Assessment input SHALL NOT choose arbitrary credentials, service accounts,
commands, or execution images. Konstapel SHALL authorize scope before dispatch
and validate returned attribution. Provider authority SHALL NOT grant namespace
users access to cloud-wide or sibling evidence.

#### Scenario: A result exceeds the authorized scope

- **WHEN** returned evidence includes subjects outside the request's scope
- **THEN** those subjects are rejected or safely projected before any disclosure
- **AND** unknown scope cannot establish a pass or expose raw findings

### Requirement: Collection is attributed against a host-frozen inventory

Konstapel SHALL send each collection a host-derived inventory, frozen before
dispatch: the scope's namespace identities and its workload instances, each
with a stable UID, the host revision of the state checks read, and the checks
expected for it. It SHALL project only those fields to the provider. The
expected subject-check pairs SHALL be the collection's denominator. Cloud
accounts and other non-Kubernetes targets SHALL require a separate target
contract.

#### Scenario: Evidence names a subject outside the inventory

- **WHEN** a result attributes evidence to a subject or check the frozen inventory does not expect
- **THEN** that item is withheld with a diagnostic, even when it also names in-scope subjects
- **AND** it never counts as evidence for any subject

#### Scenario: An expected subject has no evidence

- **WHEN** a result omits an expected subject or check
- **THEN** the expectation is recorded as missing and is never a pass

#### Scenario: The inventory exceeds the negotiated bounds

- **WHEN** the frozen inventory is larger than the host's or the provider's bounds
- **THEN** nothing is dispatched and the collection is explicitly incomplete, never truncated

### Requirement: Reports never define their own denominator

Returned evidence SHALL NOT define, narrow or replace the frozen expectations.
Provider-discovered subjects SHALL supplement an inventory workload only when
the inventory allows it and only under that workload, and SHALL NOT make a
frozen expectation complete or passing.

#### Scenario: A provider discovers parts of a workload

- **WHEN** a result reports containers of an inventory workload as supplements
- **THEN** they are accepted only if the inventory allows supplements, and only under that workload
- **AND** the workload's frozen expectations still need evidence attributed to the workload itself

#### Scenario: A supplement names no inventory workload

- **WHEN** a supplement's parent is not a frozen workload subject, or the inventory allows no supplements
- **THEN** the supplement and the evidence attributed to it are diagnostics, not evidence

### Requirement: Results carry a host-readable attribution envelope

A collection result SHALL be a protocol-defined document that attributes each
evidence item to inventory subjects and checks, with its source time. Only
source-specific details SHALL be opaque. Konstapel SHALL validate the document
and its attribution before it uses any evidence. A malformed, oversized,
digest-mismatched, expired or interrupted result, or one not read before the
deadline, SHALL become an explicit incomplete collection with a bounded
limitation and no evidence.

#### Scenario: The result is malformed

- **WHEN** the staged document has an unknown field, an invalid time or a duplicate item, or exceeds its bounds
- **THEN** no evidence is used and the collection records one bounded limitation

#### Scenario: The deadline passes during transfer

- **WHEN** the collection deadline ends before the result is read and verified
- **THEN** the collection is explicitly incomplete and partial bytes are never evidence

### Requirement: Protocol additions are negotiated, never silently ignored

A wire contract change that older peers would ignore SHALL be a new protocol
revision that both peers must speak. Konstapel and the authoring kit SHALL
reject a peer of another revision explicitly, in both directions, before any
assessment payload is sent.

#### Scenario: A revision 1 provider is registered

- **WHEN** the endpoint serves only protocol revision 1
- **THEN** Konstapel reports the registration incompatible and sends no collection

#### Scenario: A revision 1 host calls a revision 2 provider

- **WHEN** a request carries protocol revision 1
- **THEN** the provider rejects it as an unsupported protocol version before any handler runs

### Requirement: Captures record the frozen registration identity

A capture of a registered provider SHALL record the registration name, UID and
configuration revision, the release digest, the protocol and its revision, and
the provider contract, payload and evaluator versions. A reader without
registered-provider support SHALL reject such a capture, and a registered
provider's capture without that identity SHALL be rejected.

#### Scenario: A built-in reader reads a registered capture

- **WHEN** a reader that knows only built-in providers reads a capture carrying a registration identity
- **THEN** it rejects the capture explicitly instead of reading it as a built-in capture

#### Scenario: The capture names another registration

- **WHEN** a capture frozen to one registration UID, revision or release is read for another
- **THEN** it is rejected explicitly

### Requirement: Evaluation uses a separately authenticated evaluator endpoint

A registration that allows evaluation SHALL name an evaluator endpoint with its
own Service, server name and trust, distinct from the source endpoint.
Konstapel SHALL send evaluation only to that endpoint, and collection, scans
and result transfer only to the source endpoint, authenticating each
separately. The reference evaluator SHALL hold no source credentials and have
no source network access.

#### Scenario: Register evaluation without an evaluator endpoint

- **WHEN** a registration allows Evaluate without an evaluator endpoint, or reuses the source endpoint's Service or server name
- **THEN** the API rejects it

#### Scenario: The evaluator endpoint is unavailable

- **WHEN** the source endpoint is healthy but the evaluator endpoint fails authentication
- **THEN** the registration is not Ready, and no evaluation is sent to the source endpoint

### Requirement: Fresh evidence requests are optional and explicit

Scan initiation SHALL require a declared provider capability and administrator
authorization. Read-only collection and evaluation SHALL NOT initiate scans.
Providers SHALL own scanner execution; Konstapel SHALL own assessment scheduling,
scope, deadlines and evidence lifecycle. Unsupported scan requests SHALL fail
explicitly without changing enforcement.

#### Scenario: Collect reports from a reporting provider

- **WHEN** a run uses an existing-evidence provider without scan capability
- **THEN** collection reads existing evidence without creating a scanner Job

#### Scenario: Request fresh evidence

- **WHEN** an authorized run requests a scan-capable provider
- **THEN** the provider executes only the approved target and frozen check configuration

### Requirement: Scan requests survive retries without duplicate logical work

Scan operations SHALL bind a durable idempotency identity to immutable request
inputs. Retries and leader changes SHALL resume that operation; conflicting
inputs SHALL be rejected. Attempts SHALL remain attributable and bounded.
Cancellation SHALL be idempotent, and uncertainty about running work SHALL
remain explicit rather than trigger an untracked replacement.

#### Scenario: The start response is lost

- **WHEN** the provider accepted a scan but Konstapel retries after a timeout
- **THEN** the same identity returns the original operation instead of a second logical scan

### Requirement: Scan completion does not imply complete evidence

Results SHALL preserve expected scope, check coverage, source times, scanner
identity, failures and truncation. Findings SHALL remain distinct from execution
errors. Deadlines SHALL bound collection without extending closed runs. Missing
permissions, regions, checks, or results SHALL NOT become passes.

#### Scenario: A scan exits successfully with denied API calls

- **WHEN** some expected resources could not be assessed
- **THEN** evidence records that limitation and the assessment remains incomplete

### Requirement: Capture acknowledgement precedes disposable result cleanup

Providers SHALL keep completed results available until Konstapel acknowledges
durable capture or a documented bounded handoff deadline expires. Checksums,
operation identity and attribution SHALL be verified before acknowledgement.
Late or lost results SHALL NOT replace a closed capture. Provider staging SHALL
NOT become a second authoritative publication or retention system.

#### Scenario: The controller fails while receiving results

- **WHEN** transfer stops before durable acknowledgement
- **THEN** retry can retrieve the same immutable result within the handoff window
- **AND** expiration is reported as evidence loss, not successful empty collection

### Requirement: Evaluation and replay preserve frozen semantics

External evaluation SHALL use only frozen evidence, configuration, exact verified
content and an explicit evaluation time. Replay SHALL require a compatible,
operator-installed evaluator and SHALL NOT access live sources or initiate scans.
Provider, implementation digest, protocol, evaluator and payload identities SHALL
be recorded. Unavailable compatibility SHALL produce an explicit diagnostic.

#### Scenario: Replay after source removal and provider upgrade

- **WHEN** a retained capture is replayed after its source disappears
- **THEN** a compatible evaluator produces equivalent normalized results
- **AND** an incompatible evaluator is rejected without fetching executable code

### Requirement: C2P export consumes the same evaluated evidence

The Konstapel adapter and C2P conversion SHALL preserve shared evaluator semantics,
raw outcomes, mappings, completeness and attribution. C2P SHALL receive projected
frozen inputs without source credentials. External execution SHALL NOT weaken
existing publication, signing, retention or download authorization.

#### Scenario: Compare current assessment with retained export

- **WHEN** both evaluate the same frozen inputs at the same boundary
- **THEN** normalized results agree and OSCAL preserves richer source outcomes

### Requirement: Provider authors have an executable integration guide

The authoring guide SHALL define protocol, registration, permissions, OCI
packaging, installation, upgrades, error handling, capture compatibility and C2P
integration. It SHALL include runnable reporting and synthetic scan examples.
A reusable conformance suite SHALL test independent implementations and negative
cases; example success SHALL NOT claim production scanner compatibility.

#### Scenario: Implement a provider outside the controller repository

- **WHEN** an author follows the published guide using the reference kit
- **THEN** the provider builds, installs and passes documented conformance commands
- **AND** it needs no imports from Konstapel's internal Go packages

### Requirement: Installed integration is exercised in CI

Required CI SHALL exercise authenticated external providers against the
Helm-installed controller, including registration, isolation, retries, failover,
capture, replay and export. Reference scan tests SHALL use disposable workloads.
Real Prowler or Trivy support SHALL require separate producer compatibility and
target authorization evidence.

#### Scenario: A provider violates the wire contract

- **WHEN** CI tests malformed results, incompatible versions or unauthorized calls
- **THEN** the gate fails on acceptance or disclosure of those inputs
