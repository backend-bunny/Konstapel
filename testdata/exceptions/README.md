# Exception lifecycle fixtures

`lifecycle-matrix.yaml` is the fixture matrix for
`add-self-service-policy-exceptions` (task 1.1). Every case states, for each
step, an explicit expected outcome for acceptance, renewal, revocation, native
governance, or report handling. The matrix does not depend on the
ComplianceException API, the controller, or a cluster, so you can review and
extend it on its own.

Run it:

```sh
devbox run -- go test ./internal/exception/ -run LifecycleMatrix
```

`task check` runs it as part of `task test`.

## What the tests check

- Every `#### Scenario:` in the `policy-exceptions` spec is cited by at least one
  case. Every cited scenario exists, either in the open change or in
  `openspec/specs` after archive.
- The matrix spans the categories `acceptance`, `renewal`, `revocation`,
  `report` and `native`. It also spans the boundaries `namespace`, `revision`,
  `eligibility`, `attribution`, `lifetime`, `expired-context`,
  `missing-context`, `native-governance` and `engine`.
- The YAML decodes strictly, step times never go backwards, and every step has
  a non-empty `expect`.
- Expectation keys come from a closed list, so a typo fails rather than being
  ignored. Enumerable values (`admission`, `grant`, `disposition`, …) come
  from closed vocabularies.
- Caller operations name the authenticated `actor` and an `admission` outcome.
  Every rejection names a `reason`. Every report states a `disposition`.

## Format

```yaml
cases:
  - id: unique-case-name
    category: acceptance | renewal | revocation | report | native
    boundaries: [namespace, revision, ...]
    scenarios: ["<policy-exceptions scenario name>", ...]
    setup:
      namespaces: [{name, uid}]                 # uid models namespace identity
      contributions: [{binding, policy, revision, eligibility, maxLifetime, generation}]
      engineReady: true                         # engine expiry/governance gates passed
      existingWorkloads: [...]                  # optional
      acceptances: [{exception, revision, validFrom, validUntil, snapshot}]  # report cases
    steps:
      - at: RFC3339 time
        action: create | renew | revoke | expire | change-contribution | report | ...
        actor: {username, uid, groups}          # authenticated principal (AdmissionReview.userInfo)
        expect: {admission, reason, grant, snapshot, disposition, ...}
```

The contribution `revision` is the targeting `Contribution.Revision`, which
acceptance compares. `generation` is binding provenance only. A case that
changes `generation` with the same `revision` models an assessment-only edit,
and the grant must survive it.

The admission `reason` values (`Forbidden`, `LifetimeExceeded`,
`RenewalRequired`, …) are the vocabulary that the group 2–4 conditions and
admission messages will use. Report cases describe what the evidence
integration in group 5 must produce: the raw engine result plus a separate
risk disposition.

Groups 2–6 execute these cases against the API, the controller and the
evidence pipeline as they land. Change a case only when the spec changes.
