package provider_test

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"example.com/konstapel-reporting/certs"
	"example.com/konstapel-reporting/host"
	"example.com/konstapel-reporting/provider"
	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

const (
	release      = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	otherRelease = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	// The worker's client identity towards the evaluator, and the
	// evaluator's serving identity.
	workerClient  = "worker.reporting.example.test"
	evaluatorName = "evaluator.reporting.example.test"
)

func collectRequest(pairs ...string) *providerv1.CollectRequest {
	scope := &providerv1.Scope{Cluster: "test"}
	for i := 0; i < len(pairs); i += 2 {
		scope.Namespaces = append(scope.Namespaces, &providerv1.Namespace{Name: pairs[i], Uid: pairs[i+1]})
	}
	return &providerv1.CollectRequest{Scope: scope}
}

// start serves s with the server material in dir, authorizing client, and
// returns its address.
func start(t *testing.T, s provider.Service, dir, client string) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- provider.Serve(ctx, s, provider.Config{Listener: lis, TLS: providerkit.SecretFiles(dir), AuthorizedHosts: []string{client}, Log: t.Logf})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return lis.Addr().String()
}

// split runs the reference deployment in process: an evaluator of
// evaluatorRelease, and a worker of release over the synthetic source that
// forwards to evaluatorAddr (the evaluator's own address when empty). It
// returns the worker's address, the host's material and the worker.
func split(t *testing.T, evaluatorRelease, evaluatorAddr string) (string, string, *provider.Provider) {
	t.Helper()
	dir := t.TempDir()
	if err := certs.Generate(filepath.Join(dir, "host"), certs.Options{}); err != nil {
		t.Fatal(err)
	}
	if err := certs.Generate(filepath.Join(dir, "evaluator"), certs.Options{ServerName: evaluatorName, HostName: workerClient}); err != nil {
		t.Fatal(err)
	}
	addr := start(t, provider.EvaluatorService(evaluatorRelease), filepath.Join(dir, "evaluator", "server"), workerClient)
	if evaluatorAddr != "" {
		addr = evaluatorAddr
	}
	mtls, err := providerkit.NewClientTLS(providerkit.SecretFiles(filepath.Join(dir, "evaluator", "host")), evaluatorName)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := providerkit.DialOptions(mtls, providerkit.TransportLimits{})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client, err := providerkit.NewClient(conn, provider.EvaluatorExpectation(), nil)
	if err != nil {
		t.Fatal(err)
	}
	p := provider.New(provider.Source())
	worker := start(t, provider.WorkerService(release, p, &provider.Forward{Client: client, Implementation: release}),
		filepath.Join(dir, "host", "server"), certs.HostName)
	return worker, filepath.Join(dir, "host", "host"), p
}

func dial(t *testing.T, addr, hostDir, serverName string) *grpc.ClientConn {
	t.Helper()
	conn, err := host.Dial(addr, providerkit.SecretFiles(hostDir), serverName)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// The host runs the quickstart's assessment against the worker alone: the
// worker collects, and the evaluator, reached only by the worker, evaluates
// with the same results as the combined process.
func TestSplitAssessment(t *testing.T) {
	worker, hostDir, p := split(t, release, "")
	var out bytes.Buffer
	r, err := host.Run(context.Background(), dial(t, worker, hostDir, certs.ServerName), &out)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	t.Log("\n" + out.String())
	if got := r.Description.GetImplementation(); got != release {
		t.Errorf("the worker reports implementation %q", got)
	}
	want := map[string]string{
		"team-a": "EVIDENCE_STATE_ATTRIBUTABLE OUTCOME_PASS",
		"team-b": "EVIDENCE_STATE_ATTRIBUTABLE OUTCOME_FAIL",
		"team-c": "EVIDENCE_STATE_MISSING OUTCOME_UNSPECIFIED",
	}
	if len(r.Observations) != len(want) {
		t.Fatalf("%d observations", len(r.Observations))
	}
	for _, o := range r.Observations {
		if got := o.GetState().String() + " " + o.GetOutcome().String(); got != want[o.GetSubject()] {
			t.Errorf("%s: %s, want %s", o.GetSubject(), got, want[o.GetSubject()])
		}
	}
	if p.Staged() != 0 {
		t.Errorf("%d results staged after acknowledgement", p.Staged())
	}
}

// The evaluator serves Evaluate only: it describes no collection, holds no
// handler that could read a source, and refuses a collection.
func TestEvaluatorServesEvaluateOnly(t *testing.T) {
	s := provider.EvaluatorService(release)
	if s.Handlers.Collector != nil || s.Handlers.Results != nil || s.Handlers.Scanner != nil {
		t.Fatalf("the evaluator has non-evaluation handlers: %+v", s.Handlers)
	}
	if got := s.Description.GetCapabilities(); len(got) != 1 || got[0] != providerv1.Capability_CAPABILITY_EVALUATE {
		t.Fatalf("evaluator capabilities %v", got)
	}
	w := provider.Describe(provider.RoleWorker, release)
	s.Description.Capabilities, w.Capabilities = nil, nil
	if s.Description.String() != w.String() {
		t.Errorf("worker and evaluator describe different providers:\n%v\n%v", w, s.Description)
	}

	dir := filepath.Join(t.TempDir(), "tls")
	if err := certs.Generate(dir, certs.Options{}); err != nil {
		t.Fatal(err)
	}
	addr := start(t, provider.EvaluatorService(release), filepath.Join(dir, "server"), certs.HostName)
	expect := host.Expect
	client, err := providerkit.NewClient(dial(t, addr, filepath.Join(dir, "host"), certs.ServerName), expect, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := client.Describe(ctx); providerkit.ReasonOf(err) != providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CAPABILITY {
		t.Fatalf("a Collect and Evaluate expectation of the evaluator: %v, want ERROR_REASON_UNSUPPORTED_CAPABILITY", err)
	}
	raw := providerv1.NewAssessmentProviderClient(dial(t, addr, filepath.Join(dir, "host"), certs.ServerName))
	_, err = raw.Collect(ctx, &providerv1.CollectRequest{Header: expect.Header(), PayloadVersion: provider.PayloadVersion,
		Scope: collectRequest("team-a", "x").GetScope()})
	// The kit serves an unsupported capability as Unimplemented.
	if status.Code(err) != codes.Unimplemented || !strings.Contains(err.Error(), "does not serve [CAPABILITY_COLLECT]") {
		t.Fatalf("collect from the evaluator: %v, want the capability refused", err)
	}
}

// A worker forwards only to an evaluator of its own release, and an
// unreachable evaluator is an explicit unavailable evaluation; collection
// is unaffected in both cases.
func TestWorkerRefusesAnotherOrMissingEvaluator(t *testing.T) {
	for name, tc := range map[string]struct {
		evaluatorRelease, addr, want string
	}{
		"another release": {otherRelease, "", "not this worker's release"},
		"unreachable":     {release, unreachable(t), "describe the evaluator"},
	} {
		t.Run(name, func(t *testing.T) {
			worker, hostDir, _ := split(t, tc.evaluatorRelease, tc.addr)
			_, err := host.Run(context.Background(), dial(t, worker, hostDir, certs.ServerName), &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), "evaluate:") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run: %v, want an evaluation failure mentioning %q", err, tc.want)
			}
			if got := providerkit.ReasonOf(err); got != providerv1.ErrorReason_ERROR_REASON_UNAVAILABLE {
				t.Errorf("reason %s, want ERROR_REASON_UNAVAILABLE", got)
			}
		})
	}
}

// unreachable is an address nothing listens on.
func unreachable(t *testing.T) string {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	_ = lis.Close()
	return addr
}

func TestParseRoleAndRelease(t *testing.T) {
	for _, r := range []string{"combined", "worker", "evaluator"} {
		if _, err := provider.ParseRole(r); err != nil {
			t.Errorf("%s: %v", r, err)
		}
	}
	if _, err := provider.ParseRole("scanner"); err == nil {
		t.Error("an unknown role parsed")
	}
	for _, s := range []string{"", "latest", "sha256:abc", "sha256:" + strings.Repeat("A", 64), "sha512:" + strings.Repeat("a", 64)} {
		if provider.ValidRelease(s) {
			t.Errorf("%q is accepted as a release digest", s)
		}
	}
	if !provider.ValidRelease(release) {
		t.Error("a sha256 digest is refused")
	}
}
