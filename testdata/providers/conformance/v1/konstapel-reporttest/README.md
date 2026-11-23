# Synthetic reporting-provider conformance cases

These cases exercise the shared provider contract with the test-only
`konstapel-reporttest/v1` provider (`internal/provider/reporttest`). Their
subjects, reports and verdicts are invented to differ from Kyverno's shape.
They are not Trivy or any other producer's output and are not evidence that
any real producer is supported. Regenerate `expected.json` with
`go test ./internal/provider/reporttest -run TestReportingConformance -update`
and review the diff.
