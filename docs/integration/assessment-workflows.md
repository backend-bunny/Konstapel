# Assessment workflows

How platform operators and application teams run assessments, read results,
and hand off namespace evidence. The contract and its rules are in the
[assessment contract](assessment-contract.md). Storage, retention and the
download service are in [S3 evidence](s3-evidence.md).

Every YAML example on this page is a file in
`testdata/assessments/examples/valid/`. `TestWorkflowExamplesArePublishedFiles`
keeps them identical, and `TestAssessmentExamplesAreAccepted` validates them
against the CRDs. `scripts/check-assessment-access.sh` applies them as the
identities named here on a disposable cluster.

## Who does what

| Step | Identity | Role |
| --- | --- | --- |
| Configure schedule and retention | platform administrator | writes `ComplianceBinding` (central, cluster-scoped) |
| Request a full-binding run, read and download any run | platform operator | `konstapel-assessment-operator` (ClusterRoleBinding) |
| Request an assessment of one's own namespace, read and download it | application team | `konstapel-assessment-requester` (RoleBinding in that namespace only) |
| Create scheduled and team runs, write all status | controller | `konstapel-controller-assessments` |

Teams never see `AssessmentRun` objects, other namespaces' requests, or
full-binding packages.

## Scheduled assessments

The binding's `spec.assessment` sets the cadence
(`testdata/assessments/examples/valid/binding-assessment.yaml`):

```yaml
# A binding with hourly snapshots and 30-day retention. enforcementEpoch is
# omitted: the konstapel-binding-enforcement-epoch policy maintains it.
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: baseline-audit
spec:
  profileRef: {name: baseline}
  namespaceSelector: {}
  mode: Audit
  assessment:
    interval: 1h
    maxEvidenceAge: 2h
    collectionTimeout: 10m
    retention: 720h
```

Every `interval` the controller freezes the binding's scope, collects
evidence until it is complete or `collectionTimeout` passes, exports the
package, and publishes it with the binding's current `retention`. Only one run
per binding is active at a time. Missed due times coalesce into one run, and
the skipped times are recorded as `gaps`, never claimed as assessed. Check
progress with:

```sh
kubectl get compliancebinding baseline-audit -o jsonpath='{.status.assessment.schedule}'
kubectl get compliancebinding baseline-audit -o jsonpath='{.status.assessment.current}'
```

`current` is the live evidence view: completeness, outcome counts, next
expiry. It is not a published snapshot. Scheduling is explicitly disabled (a
limitation on `current`) when no evidence backend is configured or ready.

## On-demand runs

A platform operator requests a full-binding snapshot
(`testdata/assessments/examples/valid/run-platform-binding.yaml`):

```yaml
# A platform operator requests a full-binding run. The trigger defaults to Manual.
apiVersion: compliance.erenius.io/v1alpha1
kind: AssessmentRun
metadata:
  generateName: baseline-audit-manual-
spec:
  bindingRef: {name: baseline-audit}
  scope: Binding
```

An application team requests its own namespace
(`testdata/assessments/examples/valid/request-team-a.yaml`):

```yaml
# An application team asks for an assessment of its own namespace.
apiVersion: compliance.erenius.io/v1alpha1
kind: AssessmentRequest
metadata:
  name: nightly-check
  namespace: team-a
spec:
  bindingRef: {name: baseline-audit}
```

The requester is set from the authenticated user at admission. A value
written by the client is overwritten. The request is queued behind the
binding's active run, then resolved to a `Namespace`-scope run that the
controller creates. The run's scope is frozen to that namespace's UID. Follow
it with:

```sh
kubectl -n team-a get assessmentrequest nightly-check -o jsonpath='{.status.phase} {.status.artifactRef}{"\n"}'
```

`Completed` with an `artifactRef` means the package is published. `Rejected`
(binding missing or the namespace not selected) and `Failed` give the reason
in the status conditions.

## Reading results

A run's `status.summary` and the request's `status.summary` report what the
package means:

| `summary.export` | `summary.evidence.completeness` | Meaning |
| --- | --- | --- |
| `Assessment` | `Complete` | Every expected check was attributable. Outcomes cover the frozen technical-check scope; completeness does not establish a pass or whole-control compliance. |
| `Assessment` | `Incomplete` | A valid, published assessment that records what it could not establish: missing, rejected or stale evidence, and limitations. It is never upgraded later. |
| `Assessment` | `NoTargets` | Nothing was in scope. Not a pass. |
| `Diagnostic` | any | Valid OSCAL could not be produced, for example because the engine policy did not match pinned content. The package holds `diagnostic.json` with the reason and evidence counts, and no OSCAL. |
| `CaptureLost` | any | The frozen bytes were lost before durable storage. Nothing is published under that run's identity, and a new run is needed. |

The engine's readiness (`EngineReady` on the binding) is never a compliance
result. Mapped checks provide bounded technical evidence, not whole-control or
baseline compliance.

## Namespace download handoff

1. **The platform grants the team access, once per namespace:**

   ```sh
   kubectl -n team-a create rolebinding assessment-requester \
     --clusterrole=konstapel-assessment-requester --group=team-a-developers
   ```

2. **The team requests an assessment** with the example above and waits for
   `Completed`.

3. **The team downloads its package** from the download service with a token
   issued for the `konstapel-download` audience:

   ```sh
   REQUEST_UID=$(kubectl -n team-a get assessmentrequest nightly-check -o jsonpath='{.metadata.uid}')
   DOWNLOAD_TOKEN=$(kubectl -n team-a create token ci-reader --audience konstapel-download)
   curl --cacert ca.crt -H "Authorization: Bearer $DOWNLOAD_TOKEN" -D headers.txt -o package.tar.gz \
     "https://<download-service>/v1/namespaces/team-a/assessmentrequests/nightly-check/download?uid=$REQUEST_UID"
   ```

   Here `ci-reader` is any service account in `team-a` whose subject the
   RoleBinding covers. People use a token from their identity provider with
   that audience.

4. **The team checks the bytes.** `headers.txt` carries
   `Repr-Digest: sha-256=:…:`, which equals the request's published package
   digest, plus `X-Konstapel-Published-At` and `X-Konstapel-Expires-At`. The
   archive unpacks to `descriptor.json` (scope `Namespace`, the namespace UID,
   completeness and outcomes) and the OSCAL documents and evidence it
   inventories.

The same token cannot fetch another namespace's request, the full-binding run,
or a run by UID. Platform operators download any run with
`GET /v1/assessmentruns/<run uid>/download`. Removing the RoleBinding stops new
downloads. A package is served until its `expiresAt`. After that the run keeps
a cleanup record until storage is deleted (see
[Retention](s3-evidence.md#retention)).
