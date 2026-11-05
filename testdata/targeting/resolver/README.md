# Resolver fixtures

Each `*.yaml` file is one resolver case: `input` holds the bundle metadata,
profiles, bindings and namespaces; `expected` holds a projection of
`targeting.Result`. The projection compares by object name and leaves out
digests and revisions, so cases stay readable. Revision behaviour is covered by
the contract tests in `internal/targeting`.

`scenarios` lists the `compliance-targeting` spec scenarios a case exercises.
`internal/targeting` tests check that every scenario exists, that inputs decode
strictly into the API types and pass CRD validation, and, once the resolver
lands, that resolving `input` yields `expected` for every permutation of the
input order.

A case may add `steps`. Each step replaces namespaces or deletes bindings and
then states the full expected result. The top-level `expected` always describes
`input` before any step.

Expected lists are sorted: bindings by name, targets by name, contributions by
policy, eligibility by namespace then policy, and contributors by binding name.
