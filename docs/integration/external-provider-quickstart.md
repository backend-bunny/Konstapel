# External provider quickstart: a reporting provider

This walkthrough builds and runs a tiny synthetic *reporting* provider from
an independent Go module. It uses only the public protocol types
(`pkg/providerapi/v1`) and authoring kit (`pkg/providerkit`), and talks to a
stand-in host over mutual TLS. The wire contract is described in the
[protocol reference](external-provider-protocol.md).

**Scope.** This is a local demonstration of the protocol. The controller
cannot select an external provider yet, so this quickstart does not install
anything in a cluster, register a provider or run a real assessment. Using a
registration, Helm installation, and the full authoring
guide with conformance, packaging and replay are later tasks of
[`add-external-assessment-providers`](../../openspec/changes/add-external-assessment-providers/tasks.md).
The example provider is not supported and reads no real evidence source.

`task test` runs every command on this page
(`scripts/examples/external-provider.sh`). The script fails if this page
stops quoting one of the commands it runs.

## The example module

[`examples/external-provider/reporting`](../../examples/external-provider/reporting)
is its own Go module (`example.com/konstapel-reporting`), with its own
`go.mod` and `go.sum`:

| Path | What it is |
| --- | --- |
| `provider/` | The provider. `Description()` is its `Describe` response: `example-reporting/v1`, protocol revision 1, evaluator 1, payload 1, capabilities Collect and Evaluate, check kind `reporting.example.test/v1/RequiredLabel`, and a 256-byte chunk limit, so even a small payload travels in several chunks. `Provider` implements the kit's `Collector`, `Results` and `Evaluator` over a fixed in-memory source. `Serve` runs the protocol port over mutual TLS, with probes on a separate port. |
| `host/` | A stand-in for the Konstapel host. Through `providerkit.Client` it runs Describe, then Collect, then ReadResult, then Acknowledge, then Evaluate, giving each call its own deadline. |
| `certs/` | Throwaway CA, server and host certificates generated at run time. |
| `cmd/quickstart-certs`, `cmd/reporting-provider`, `cmd/reporting-host` | The three commands used below. |
| `imports_test.go` | Fails if the module depends, directly or transitively, on any Konstapel package other than `pkg/providerapi/v1` and `pkg/providerkit`, in particular anything under `internal/` or `api/`. |
| `host/host_test.go` | Runs the same assessment in process, and checks that a wrong server name, an unauthorized host identity, a call without a deadline and an incompatible evaluator version are refused. |

Its `go.mod` has
`replace github.com/backend-bunny/Konstapel => ../../..`, so it builds from
this checkout without fetching Konstapel. An author outside the repository
drops the `replace` and requires a published Konstapel module version
instead.

The synthetic source holds namespaces `team-a` (labeled `owner=alice`) and
`team-b` (unlabeled). The host's frozen scope is `team-a`, `team-b` and
`team-c`. Its one check, `namespace-owner`, requires an `owner` label.

## Run it

Run these commands from the repository root, inside the Devbox environment
(`devbox shell`, or direnv). Without direnv, prefix each `go` command with
`devbox run --` from the root.

1. Build the three commands into a scratch directory:

   ```sh
   cd examples/external-provider/reporting
   work=$(mktemp -d)
   go build -mod=readonly -o "$work/" ./cmd/...
   ```

2. Generate throwaway mutual TLS material. It is one private CA plus a
   provider certificate for `reporting.provider.example.test` and a host
   certificate for `host.konstapel.example.test`, each with exactly one DNS
   SAN. Each side's directory has `tls.crt`, `tls.key` and `ca.crt`, the
   layout of a `kubernetes.io/tls` Secret. The keys are only written to the
   scratch directory. Never commit them:

   ```sh
   "$work/quickstart-certs" -out "$work/tls"
   ```

   ```text
   wrote /tmp/tmp.XXXX/tls/server (reporting.provider.example.test) and /tmp/tmp.XXXX/tls/host (host.konstapel.example.test), valid 24h
   ```

3. Start the provider. It serves the protocol on `127.0.0.1:18443` and
   authorizes only the host identity `host.konstapel.example.test` (change it
   with `-authorized-hosts`). Probes run on `127.0.0.1:18444`: the protocol
   port admits only authenticated calls with a deadline, which probes are
   not. The provider re-reads its certificate files every 10 seconds, so
   rotated files are used without a restart:

   ```sh
   "$work/reporting-provider" -tls-dir "$work/tls/server" &
   curl -fsS --retry 30 --retry-delay 1 --retry-all-errors http://127.0.0.1:18444/readyz
   ```

   ```text
   reporting-provider: … health probes on http://127.0.0.1:18444
   reporting-provider: … serving example-reporting/v1 on 127.0.0.1:18443 for [host.konstapel.example.test]
   ready
   ```

4. Run the host. It requires the provider's certificate to name
   `reporting.provider.example.test`, whatever address it dials:

   ```sh
   "$work/reporting-host" -tls-dir "$work/tls/host"
   ```

   ```text
   describe: example-reporting/v1 protocol=[1] evaluator=1 payload=write 1 read [1] capabilities=[CAPABILITY_COLLECT CAPABILITY_EVALUATE]
   negotiated limits: max_result_bytes=1048576 max_chunk_bytes=256 max_observations=1000
   collect: result result-…, 272 bytes, sha256:…
     limitation: namespace team-c is not in the synthetic source
   read result: 272 bytes verified in chunks of at most 256
   acknowledge: provider may release result-…
   evaluate: 3 observations, 0 stale scopes
     team-a namespace-owner: EVIDENCE_STATE_ATTRIBUTABLE OUTCOME_PASS (raw "present")
     team-b namespace-owner: EVIDENCE_STATE_ATTRIBUTABLE OUTCOME_FAIL (raw "absent")
     team-c namespace-owner: EVIDENCE_STATE_MISSING -
   ```

   The negotiated chunk bound is the provider's stricter 256 bytes, not the
   kit's 1 MiB default. `team-c` is missing from the source, so it comes back
   as a limitation and as missing evidence, never as a pass.

5. Expect a different server identity. The handshake fails and the host
   sends no request:

   ```sh
   "$work/reporting-host" -tls-dir "$work/tls/host" -server-name other.provider.example.test
   ```

   ```text
   reporting-host: describe: ERROR_REASON_UNSPECIFIED: Unavailable: connection error: desc = "transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate is valid for reporting.provider.example.test, not other.provider.example.test" (reason ERROR_REASON_UNSPECIFIED)
   ```

6. Stop the provider and delete the scratch directory, including the keys:

   ```sh
   kill %1
   rm -rf "$work"
   ```

To run the module's tests, including the import check, run
`go test ./...` in `examples/external-provider/reporting`.

## What to change for your own provider

- Pick your own provider name, contract version, payload version and
  evaluator version. Each one is a separate compatibility dimension
  ([versions](external-provider-protocol.md#request-header-and-versions)).
- Replace the in-memory source with your read-only evidence source, and
  persist staged results until they are acknowledged or `expires_at` passes.
  The example keeps them in memory, so a restart loses unacknowledged
  results.
- Keep `Evaluate` pure. It may read only the start message and the payload.
- Return `providerkit.Errorf(reason, …)` to choose an
  [error reason](external-provider-protocol.md#errors). Any other error is
  served as `ERROR_REASON_UNAVAILABLE`.
- Use platform-issued certificates (for example cert-manager) mounted from a
  Secret, the host identities your deployment authorizes, and a separate
  probe port.
