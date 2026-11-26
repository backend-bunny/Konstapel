// Command reporting-provider serves the synthetic example-reporting
// provider over mutual TLS until interrupted.
//
// By default it is the quickstart's single process over the in-memory
// source. The reference chart runs it twice, with separate identities:
// -role worker reads Namespaces from the Kubernetes API (-source
// kubernetes) and forwards every evaluation to -role evaluator, which only
// evaluates. Both report the release digest the chart passes as
// -implementation.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"google.golang.org/grpc"

	"example.com/konstapel-reporting/certs"
	"example.com/konstapel-reporting/provider"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18443", "protocol (mutual TLS) address")
	health := flag.String("health-listen", "127.0.0.1:18444", "plain-HTTP probe address; empty disables probes")
	tlsDir := flag.String("tls-dir", "", "directory holding tls.crt, tls.key and ca.crt")
	hosts := flag.String("authorized-hosts", certs.HostName, "comma-separated client identities (exact DNS SANs) allowed to call")
	roleName := flag.String("role", string(provider.RoleCombined), "combined (the quickstart), worker or evaluator")
	sourceName := flag.String("source", "synthetic", "combined and worker: synthetic (in memory) or kubernetes (Namespaces, with the Pod's ServiceAccount)")
	implementation := flag.String("implementation", "", "worker and evaluator: the release digest (sha256:...) to report, the one the registration expects")
	evaluatorAddr := flag.String("evaluator-addr", "", "worker: the evaluator's protocol address")
	evaluatorName := flag.String("evaluator-server-name", "", "worker: the DNS SAN the evaluator's certificate must carry")
	evaluatorTLS := flag.String("evaluator-tls-dir", "", "worker: directory holding the worker's client tls.crt, tls.key and the evaluator's ca.crt")
	flag.Parse()
	logger := log.New(os.Stderr, "reporting-provider: ", log.LstdFlags)
	usage := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "reporting-provider: "+format+"\n", args...)
		os.Exit(2)
	}
	if *tlsDir == "" {
		usage("-tls-dir is required")
	}
	role, err := provider.ParseRole(*roleName)
	if err != nil {
		usage("%v", err)
	}
	if role != provider.RoleCombined && !provider.ValidRelease(*implementation) {
		usage("-role %s needs -implementation sha256:<64 lowercase hex>, the release digest", role)
	}
	if role == provider.RoleCombined && *implementation != "" {
		usage("-implementation is for -role worker and evaluator")
	}
	if role == provider.RoleEvaluator && *sourceName != "synthetic" {
		usage("the evaluator reads no source; -source is for -role combined and worker")
	}
	forwarding := *evaluatorAddr != "" || *evaluatorName != "" || *evaluatorTLS != ""
	if forwarding != (role == provider.RoleWorker) || role == provider.RoleWorker && (*evaluatorAddr == "" || *evaluatorName == "" || *evaluatorTLS == "") {
		usage("-role worker needs -evaluator-addr, -evaluator-server-name and -evaluator-tls-dir; other roles take none of them")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg := provider.Config{TLS: providerkit.SecretFiles(*tlsDir), AuthorizedHosts: strings.Split(*hosts, ","), Log: logger.Printf}

	var service provider.Service
	switch role {
	case provider.RoleEvaluator:
		service = provider.EvaluatorService(*implementation)
	default:
		var source provider.NamespaceSource
		switch *sourceName {
		case "synthetic":
			source = provider.Source()
		case "kubernetes":
			if source, err = provider.InCluster(); err != nil {
				logger.Fatal(err)
			}
		default:
			usage("-source %q is not synthetic or kubernetes", *sourceName)
		}
		p := provider.New(source)
		if role == provider.RoleCombined {
			service = provider.CombinedService(p)
			break
		}
		forward, ready, closeConn, err := dialEvaluator(ctx, *evaluatorAddr, *evaluatorName, *evaluatorTLS, *implementation, logger)
		if err != nil {
			logger.Fatal(err)
		}
		defer closeConn()
		cfg.Ready = ready
		service = provider.WorkerService(*implementation, p, forward)
	}

	if cfg.Listener, err = net.Listen("tcp", *listen); err != nil {
		logger.Fatal(err)
	}
	if *health != "" {
		if cfg.Health, err = net.Listen("tcp", *health); err != nil {
			logger.Fatal(err)
		}
	}
	if err := provider.Serve(ctx, service, cfg); err != nil {
		logger.Fatal(err)
	}
}

// dialEvaluator prepares the worker's mutual TLS client to the evaluator.
// The client material is re-read like the serving material, so a rotated
// client certificate or evaluator trust is used without a restart.
func dialEvaluator(ctx context.Context, addr, serverName, tlsDir, implementation string, logger *log.Logger) (*provider.Forward, func() error, func(), error) {
	mtls, err := providerkit.NewClientTLS(providerkit.SecretFiles(tlsDir), serverName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("evaluator client TLS: %w", err)
	}
	go mtls.Watch(ctx, 0, func(err error) { logger.Printf("evaluator client tls reload rejected: %v", err) })
	opts, err := providerkit.DialOptions(mtls, providerkit.TransportLimits{})
	if err != nil {
		return nil, nil, nil, err
	}
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, nil, nil, err
	}
	client, err := providerkit.NewClient(conn, provider.EvaluatorExpectation(), nil)
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	ready := func() error {
		if err := mtls.Ready(); err != nil {
			return errors.New("evaluator client material: " + err.Error())
		}
		return nil
	}
	logger.Printf("forwarding evaluations to %s (%s)", addr, serverName)
	return &provider.Forward{Client: client, Implementation: implementation}, ready, func() { _ = conn.Close() }, nil
}
