# Agent task routing

The model map lives in `.claude/task-routing.json` and serves both Claude Code
and Codex. It is repository-owned configuration, not a native setting read by
either client. `scripts/agents/select-task.py` reads it and task metadata; an
external loop harness must call the selector and start the chosen model.
There is no scheduled loop harness in this repository.

## Task metadata

Keep the normal OpenSpec checkbox and dotted task number. Put one HTML comment
on the immediately following line:

```markdown
- [ ] 4.2 Verify recovery after commit but before the Kubernetes receipt.
  <!-- agent: tier=deep risk=high reason="Distributed recovery and immutable publication" -->

- [ ] 4.3 Document supported recovery behavior.
  <!-- agent: tier=standard risk=low -->
```

`tier` and `risk` are required when a comment is present; `reason` is optional
and should explain non-obvious assignments. Risk is `low`, `medium`, or `high`;
high-risk work requires `deep`. Comments must stay attached when tasks move or
are marked complete. Do not edit requirements or acceptance criteria to fit a
model budget. Archived changes do not need retroactive metadata.

| Tier | Suitable work | Claude default | Codex default |
| --- | --- | --- | --- |
| `light` | Explicitly mechanical, low-risk edits with unambiguous checks | `sonnet` | `gpt-6-luna` |
| `standard` | Bounded implementation, ordinary tests, documentation | `sonnet` | `gpt-6.1-sol` |
| `deep` | Concurrency, distributed recovery, authorization, cryptographic trust, release integrity, ambiguous cross-component design | `opus` | `gpt-6-astra` |

Codex also has `gpt-6-sol` and `gpt-5.6-terra` configured as standard alternatives.
These assignments are editable project preferences, not benchmark claims or a
guarantee that the provider serves a model. The harness must use its installed
client/account to check availability. Do not silently substitute another model
when startup fails. Claude aliases follow the client's current model versions;
use exact supported IDs in the map when version pinning is needed.

Missing metadata defaults to `standard`, with `risk: null` and `defaulted: true`
in the output. This is backward compatibility, not evidence that the task is
low risk. Triage an unannotated task before execution and add a deep assignment
when it crosses one of the boundaries above. Every unfinished task in the active
changes has an initial assignment; completed and archived tasks are left alone.
Add metadata to new tasks. CI checks unfinished-task coverage so new repository
tasks do not accidentally rely on the compatibility default. Reassess the tier
when a task's scope changes; these are starting assignments, not permanent model
rankings. None of the current unfinished tasks is purely mechanical enough for
the light tier.

## Calling the selector

Run from the repository in its pinned Devbox environment:

```sh
devbox run -- python3 scripts/agents/select-task.py add-controller-high-availability 5.3
devbox run -- python3 scripts/agents/select-task.py add-controller-high-availability 5.3 --provider codex
devbox run -- python3 scripts/agents/select-task.py --check
```

The number is the printed `5.3` in `tasks.md`, **not** the ordinal `id` emitted
by `openspec instructions apply --json`. The output is JSON with change, task,
description, source line, provider, model, declared/effective tier, risk, reason,
and default/escalation flags. `--format model` emits just the model identifier.
`--model gpt-6-sol` (with `--provider codex`) selects an explicit configured
alternative; it must meet or exceed the task's tier. `--escalate` chooses deep.
Completed/missing tasks, duplicate numbers, malformed metadata, invalid model
maps, and downgrades exit nonzero instead of falling back silently.

The selector reads files and prints a decision. It does not choose the next
ready task, execute a client, change checkboxes, or grant permission to publish.
Keep dependency selection and existing approval boundaries in the harness.

## Harness contract

1. Select one unfinished, dependency-ready task. Read its surrounding OpenSpec
   artifacts and triage missing metadata. Re-read after rebasing or another
   agent's edits; line numbers are diagnostic, not stable task identities.
2. Call the selector with the intended provider. Stop on nonzero exit; never
   continue with an empty model value or evaluate output as shell code.
3. Start a fresh Claude Code or Codex invocation with the selected model using
   that installed client's supported model option. Pass the change, dotted task
   number, and instructions to follow `AGENTS.md`. Metadata cannot switch an
   already-running invocation's model.
4. Keep a harness-owned run record outside tracked source: source SHA, change,
   task number, routing JSON, actual model reported by the client, attempt,
   validation results, and PR. Do not record credentials or raw sensitive prompts.
5. After two substantive failed attempts, escalate to deep with the failure
   evidence. Network outages, registry failures, and unavailable models do not
   count as implementation failures. If deep still fails repeatedly, report the
   blocker rather than retrying indefinitely or weakening tests.
6. Require the same repository checks and PR workflow for every model. For
   high-risk changes, use a separate deep review before merge. Model selection
   never changes acceptance criteria or authorizes a release.

The selector's tests run through the existing `task test` / `task check` Python
suite. No new Taskfile task or client installation is needed. OpenSpec's task
reader still sees the same checkbox descriptions and completion counts; the
comments supply routing only.
