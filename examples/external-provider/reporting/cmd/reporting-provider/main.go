// Command reporting-provider serves the synthetic example-reporting
// provider over mutual TLS until interrupted.
//
// By default it is the quickstart's single process over the in-memory
// source. The reference chart runs it twice, with separate identities:
// -role worker reads Namespaces from the Kubernetes API (-source
// kubernetes) and only collects, and -role evaluator only evaluates. The
// host calls each at its own registered endpoint. Both report the release
// digest the chart passes as -implementation.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

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
		service = provider.WorkerService(*implementation, p)
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
