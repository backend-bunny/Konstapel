# Spec Delta

## Purpose

Keep Konstapel's controller and enabled services available across replica changes
while preserving enforcement ownership, authorization, and assessment history.

## ADDED Requirements

### Requirement: Two-replica default with explicit development mode

The supported controller installation SHALL default to two replicas and support
an explicit single-replica development configuration. Replicas SHALL belong to
one coordinated cluster-wide installation. Single-replica mode SHALL retain
authorization and coordination safeguards and SHALL NOT claim redundant service.

#### Scenario: Select deployment size

- **WHEN** an operator uses default values or sets the replica count to one
- **THEN** the installation requests two replicas or one replica respectively
- **AND** the development configuration preserves the same protected operations

### Requirement: Preferred separation across nodes

Default scheduling SHALL prefer placing replicas of the installation on
different nodes without requiring that separation. Documentation SHALL state
that co-located replicas do not protect against loss of their shared node.

#### Scenario: Only one suitable node is available

- **WHEN** one node has enough capacity and satisfies the other scheduling constraints
- **THEN** both replicas can be scheduled there despite the separation preference
- **AND** node redundancy is not reported as guaranteed

### Requirement: Disruption protection matches the replica configuration

The default multi-replica installation SHALL protect at least one available
replica through a PodDisruptionBudget. The single-replica development default
SHALL omit that budget. Protection SHALL apply to voluntary eviction and SHALL
NOT be presented as protection against involuntary failures or direct deletion.

#### Scenario: Evict replicas for maintenance

- **WHEN** voluntary eviction would leave no available matching replica under the default multi-replica budget
- **THEN** Kubernetes rejects that eviction until availability permits it
- **AND** single-replica development does not acquire an implicit drain-blocking budget

### Requirement: Rolling upgrades retain ready serving capacity

Default rolling updates SHALL use zero unavailable replicas and one surge
replica. A replacement SHALL satisfy serving readiness before normal rollout
retires an available old replica. Insufficient surge capacity SHALL leave the
rollout pending rather than weakening its availability settings automatically.

#### Scenario: Upgrade a healthy two-replica installation

- **WHEN** an operator upgrades the controller with the default strategy
- **THEN** a third replica can be introduced before an old replica is retired
- **AND** the deployment follows Kubernetes rolling-update semantics, including separately terminating pods

### Requirement: Coordinated background reconciliation

Only the elected, synchronized replica SHALL start background policy, exception,
assessment, and retention reconciliation. Replicas SHALL share a stable election
identity across restarts and supported upgrades. Failure to acquire leadership
SHALL NOT start an uncoordinated worker or itself disable healthy serving endpoints.

#### Scenario: Start two replicas together

- **WHEN** both replicas start against the same installation state
- **THEN** one coordinated set of background workers becomes active
- **AND** both replicas can independently become ready to serve enabled endpoints

### Requirement: Leadership loss preserves mutation safeguards

A replica that loses leadership SHALL stop starting background work and cancel
its owned attempts within documented bounds. Retries and delayed in-flight
operations SHALL preserve current resource ownership, accepted revisions, and
immutable run/publication identities. Election SHALL NOT be the sole safeguard
against conflicting mutations.

#### Scenario: A delayed former leader resumes

- **WHEN** an old attempt completes after another replica has acquired leadership
- **THEN** stale writes cannot overwrite newer protected state or publish different evidence for the same run
- **AND** an already committed operation is recovered through its original identity

### Requirement: Serving readiness is independent of leadership

Every replica SHALL serve implemented admission and download endpoints when its
required local handlers, state, and TLS are usable. Readiness SHALL distinguish
serving health from leadership, engine readiness, and assessment completeness.
Missing external capabilities SHALL fail affected operations explicitly without
forcing unrelated healthy services unavailable.

#### Scenario: Use the follower while the leader changes

- **WHEN** a synchronized follower has valid TLS and the prerequisites for a request
- **THEN** it can handle that request without forwarding it to the elected pod
- **AND** losing the leader does not inherently remove that follower's service endpoint

#### Scenario: TLS is not usable

- **WHEN** a replica lacks valid serving credentials or required handler initialization
- **THEN** it is not advertised as a ready serving endpoint
- **AND** process health alone does not admit it to service traffic

### Requirement: All replicas preserve admission authorization

Admission handled by any replica SHALL preserve the owning feature's current
authorization, scope, revision, attribution, and dry-run rules. A replica unable
to establish required authoritative state SHALL reject the affected operation
instead of using stale permissions or granting broader exceptions.

#### Scenario: Restrict eligibility during failover

- **WHEN** a central restriction or acceptance renewal races with requests reaching different replicas
- **THEN** each accepted operation remains bound to a valid protected acceptance under the owning contract
- **AND** leadership changes do not renew, broaden, or revive a native grant

### Requirement: Downloads do not depend on the elected pod

Each serving replica SHALL resolve published evidence from durable identities
and the configured backend, authenticate and authorize each new download, and
verify the returned package under the existing download contract. A leader's
local files or sticky routing SHALL NOT be required to retrieve published evidence.

#### Scenario: Download after the publishing pod is removed

- **WHEN** an authorized client retries the original published-artifact request through another ready replica
- **THEN** it receives the same verified package if still authorized and available
- **AND** changed authorization, expiry, or backend failure produces the defined rejection

### Requirement: Recovery preserves frozen assessment history

A new leader SHALL recover durable runs, staging, publications, and retention
ownership using their original identities. Lost capture bytes SHALL produce the
existing explicit loss outcome. New observations SHALL NOT replace a lost frozen
capture under its old identity or alter a committed package's bytes or expiry.

#### Scenario: Fail before and after durable staging

- **WHEN** the producing pod is lost during an assessment
- **THEN** a recoverable staged package continues with its recorded identity
- **AND** an unrecoverable capture is recorded as CaptureLost, with any later assessment using a new identity

#### Scenario: Lose the publication response

- **WHEN** storage commits a package before the leader loses its response or Kubernetes status write
- **THEN** the successor recovers that commit and its original retention dates
- **AND** it does not publish another snapshot for that trigger

### Requirement: Replica-local state is reconstructible or explicitly unavailable

Caches and working directories SHALL be bounded per replica. Loss of local state
SHALL NOT erase durable grants, publications, or cleanup obligations. A replica
SHALL re-establish required content trust and observation continuity before
claiming current resolution or evidence; cache presence alone is insufficient.

#### Scenario: Fail over without a usable content cache

- **WHEN** the successor cannot retrieve or verify the pinned content
- **THEN** affected reconciliation reports unavailability and preserves existing owned policies
- **AND** it does not select another digest or claim current evidence from remembered status

### Requirement: Shutdown is bounded and observable

Terminating replicas SHALL leave ready service endpoints, stop accepting new
background work, and bound request, worker, and provider shutdown. Interrupted
operations SHALL retain recoverable identity or explicit loss/failure status.
Clients SHALL be able to retry against another ready replica without bypassing
authorization or changing committed evidence.

#### Scenario: Terminate during a download and collection

- **WHEN** the pod receives a graceful termination signal
- **THEN** in-flight work completes within the shutdown budget or is canceled for recovery
- **AND** an interrupted download is retryable through the same authorized route rather than promised an uninterrupted connection

### Requirement: Controller outages preserve engine responsibilities

Loss of Konstapel leadership or replicas SHALL NOT intentionally remove applied
engine policies or disable protected admission rules. Kyverno SHALL remain the
workload enforcement authority. Assessment freshness and prerequisite failures
SHALL remain explicit; Konstapel availability SHALL NOT substitute for the
exception engine's independently tested expiry guarantees.

#### Scenario: Konstapel cannot reach the Kubernetes API

- **WHEN** API access is unavailable to the controller replicas
- **THEN** coordination and authorization-dependent operations stop or fail closed
- **AND** existing engine resources remain in place while assessment state cannot be advertised as newly current

### Requirement: Supported availability has integrated evidence

Supported releases SHALL verify replica failure, graceful replacement, voluntary
eviction, leadership recovery, and enabled service behavior against real feature
implementations. Evidence SHALL record versions, placement, transitions, and
recovery times. Documentation SHALL distinguish service redundancy from evidence
continuity and state the dependency and capacity limits of the tested setup.

#### Scenario: Release the default multi-replica deployment

- **WHEN** a controller chart release is prepared
- **THEN** its real packaged runtime passes the availability cases for every advertised enabled feature
- **AND** fixture-only success, two Running pods, or leader election alone cannot satisfy that release gate
