# Spec Delta

## Purpose

Allow independently deployed assessment providers to supply bounded evidence and
optional scan execution through an authenticated, versioned contract.

## ADDED Requirements

### Requirement: Administrators register external providers

Konstapel SHALL select external providers only through administrator-owned
AssessmentProvider registrations. Registration SHALL bind an endpoint, expected
provider identity, compatible contracts, and permitted capabilities. Bundles
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
