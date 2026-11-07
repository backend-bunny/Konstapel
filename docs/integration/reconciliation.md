# Reconciled assessment implementation

Historical integration and validation record for the standalone assessment-loop
prototype. See the [documentation index](../README.md) for current controller
workflows and implementation status.

Two independent implementations of `prove-kyverno-v1-assessment-loop` completed
in parallel. PR #29 supplied the implementation already on main. This merge
keeps its `internal/assessment` package, Go runner/provider, version-1 capture
format, source layout, Go schema validation, CI and upstream Chainsaw workflow.
There is one maintained implementation; the alternative runner and duplicate
vendored trees are not installed alongside it.

The independent implementation contributes full captured-spec verification
against the shipped source and selected overlay, source/rendered digest artifacts,
all-missing export semantics, unique disposable-cluster names, UID-checked
teardown, independent admitted-resource identity rechecks, retained failure
snapshots and complete live failure probes. Namespace validation and duplicate
inventory checks also fail closed. Regression tests cover drift even when a
capture's self-reported digest is recomputed, changed package bytes, replaced
resource UIDs, and refusal to delete a replacement cluster.

The completed OpenSpec change is archived and the nine requirements and fifteen
scenarios are synced into `openspec/specs/kyverno-assessment-loop/spec.md`.
At reconciliation time, the original independent implementation was preserved
locally on branch `backup/prove-kyverno-independent` for recovery and comparison;
that local branch is not a distributed repository artifact. Its capture format
is different; its original artifacts remain separate from version-1 captures.

## Validation

- Go tests and go vet passed.
- Vendored source/schema checksums and strict OpenSpec validation passed.
- All 44 upstream Kyverno CLI cases passed.
- The first clean reconciled acceptance passed admission, current background
  pass/fail evidence, OSCAL schemas/references, upstream Chainsaw, offline replay
  and owned-cluster cleanup.

Both clean reconciled acceptance runs passed, including upstream Chainsaw and
offline replay, and removed their own clusters. Each captured four expected
subjects: passing Pod/Deployment and failing pre-existing/Audit-admitted Pods.
Original violating resource identities remained present until owned cleanup.

| Run | Cluster identity | Evaluation boundary | Collected |
| --- | --- | --- | --- |
| `acceptance-reconciled-1` | `kube-system:7da4246f-0506-4222-8734-80686c84b706` | 2026-11-05T09:42:37.203740104Z | 2026-11-05T09:43:03.49183857Z |
| `acceptance-reconciled-2` | `kube-system:e9597aef-83b2-4f9c-b456-6a19c8a85de1` | 2026-11-05T09:46:42.072977188Z | 2026-11-05T09:47:08.213895409Z |

Original Assessment Results SHA-256 values:

```text
c7b8138d12c153e768bdd2913f0f83fbe8dd289f7cc568f7abe34e1d5656effa  acceptance-reconciled-1/package/assessment-results.json
91e6ea38a10a9051c99167ab7b6e2a23611e318596af14f938170cb9381987bd  acceptance-reconciled-2/package/assessment-results.json
```

`scripts/test-failures.sh artifacts/failure-probes-reconciled` passed both live
failure probes. Missing evidence returned exit code 1, retained the raw capture
and incomplete reconciliation, and identified `required-missing-resource`.
The admission probe returned exit code 1 after the expected Audit behavior was
contradicted by this policy's Deny response. Both retained final policy, report,
workload and admission snapshots and removed their own clusters. No kind clusters
remained after the probes.

These combined runs supersede the independent acceptance runs for the maintained
runner. Historical evidence in validation-results.md remains unchanged and is
not presented as evidence for the newly added safeguards.
