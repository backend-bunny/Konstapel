package host_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.com/konstapel-reporting/certs"
	"example.com/konstapel-reporting/host"
	"example.com/konstapel-reporting/provider"
	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

// serve starts the example provider over mutual TLS with material generated
// into a temporary directory, and returns its address and the directory.
func serve(t *testing.T) (string, string, *provider.Provider) {
	return serveWith(t, certs.Options{})
}

func serveWith(t *testing.T, o certs.Options) (string, string, *provider.Provider) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "tls")
	if err := certs.Generate(dir, o); err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := provider.New(provider.Source())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- provider.Serve(ctx, provider.CombinedService(p), provider.Config{Listener: lis, TLS: providerkit.SecretFiles(filepath.Join(dir, "server")),
			AuthorizedHosts: []string{certs.HostName}, Log: t.Logf})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return lis.Addr().String(), dir, p
}

func TestQuickstartAssessment(t *testing.T) {
	addr, dir, p := serve(t)
	conn, err := host.Dial(addr, providerkit.SecretFiles(filepath.Join(dir, "host")), certs.ServerName)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var out bytes.Buffer
	r, err := host.Run(context.Background(), conn, conn, &out)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	t.Log("\n" + out.String())

	if got := r.Limits.GetMaxChunkBytes(); got != 256 {
		t.Errorf("negotiated chunk bound %d, want the provider's stricter 256", got)
	}
	if r.Result.GetSizeBytes() <= 256 {
		t.Errorf("result of %d bytes does not exercise chunked transfer", r.Result.GetSizeBytes())
	}
	if got := r.Collection.GetLimitations(); len(got) != 1 || got[0].GetSubject() != host.Scope().GetNamespaces()[2].GetUid() || !strings.Contains(got[0].GetMessage(), "team-c") {
		t.Errorf("limitations %v, want team-c missing from the source", got)
	}
	if got := r.Collection.GetEvidence(); len(got) != 2 || got[0].GetAttributions()[0].GetCheck() != host.Check {
		t.Errorf("evidence %v, want team-a and team-b attributed to %s", got, host.Check)
	}
	if n := p.Staged(); n != 0 {
		t.Errorf("%d results still staged after acknowledgement", n)
	}
	want := map[string]string{
		"team-a": "EVIDENCE_STATE_ATTRIBUTABLE OUTCOME_PASS",
		"team-b": "EVIDENCE_STATE_ATTRIBUTABLE OUTCOME_FAIL",
		"team-c": "EVIDENCE_STATE_MISSING OUTCOME_UNSPECIFIED",
	}
	if len(r.Observations) != len(want) {
		t.Fatalf("%d observations, want %d", len(r.Observations), len(want))
	}
	for _, o := range r.Observations {
		if got := o.GetState().String() + " " + o.GetOutcome().String(); got != want[o.GetSubject()] {
			t.Errorf("%s: %s, want %s", o.GetSubject(), got, want[o.GetSubject()])
		}
	}
}

// A provider certificate that does not name the expected server is refused
// before any request is sent.
func TestWrongServerNameIsRefused(t *testing.T) {
	addr, dir, _ := serve(t)
	conn, err := host.Dial(addr, providerkit.SecretFiles(filepath.Join(dir, "host")), "other.provider.example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = host.Run(context.Background(), conn, conn, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "authentication handshake failed") {
		t.Fatalf("run with the wrong server name: %v, want a handshake failure", err)
	}
}

// A host whose certificate names an identity the provider does not
// authorize reaches no handler.
func TestUnauthorizedHostIsRefused(t *testing.T) {
	addr, dir, p := serveWith(t, certs.Options{HostName: "intruder.example.test"})
	conn, err := host.Dial(addr, providerkit.SecretFiles(filepath.Join(dir, "host")), certs.ServerName)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r, err := host.Run(context.Background(), conn, conn, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("unauthorized host completed a run: %+v", r)
	}
	t.Log(err)
	if n := p.Staged(); n != 0 {
		t.Errorf("unauthorized host staged %d results", n)
	}
}

// A call without a deadline fails before it is sent.
func TestCallWithoutDeadlineIsRefused(t *testing.T) {
	addr, dir, _ := serve(t)
	conn, err := host.Dial(addr, providerkit.SecretFiles(filepath.Join(dir, "host")), certs.ServerName)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = providerv1.NewAssessmentProviderClient(conn).Describe(context.Background(), &providerv1.DescribeRequest{Header: host.Expect.Header()})
	if got := providerkit.ReasonOf(err); got != providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST {
		t.Fatalf("describe without a deadline: %v (reason %s), want ERROR_REASON_INVALID_REQUEST", err, got)
	}
}

// An expectation the endpoint does not meet fails at Describe with that
// dimension's reason, and no other call is made.
func TestIncompatibleEvaluatorVersionIsRefused(t *testing.T) {
	addr, dir, _ := serve(t)
	conn, err := host.Dial(addr, providerkit.SecretFiles(filepath.Join(dir, "host")), certs.ServerName)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	want := host.Expect
	want.EvaluatorVersion = 2
	client, err := providerkit.NewClient(conn, want, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = client.Describe(ctx)
	if !errors.Is(err, &providerkit.Error{Reason: providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_EVALUATOR_VERSION}) {
		t.Fatalf("describe: %v, want ERROR_REASON_UNSUPPORTED_EVALUATOR_VERSION", err)
	}
}
