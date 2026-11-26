// Command reporting-provider serves the synthetic example-reporting
// provider over mutual TLS until interrupted.
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
	hosts := flag.String("authorized-hosts", certs.HostName, "comma-separated host identities (exact DNS SANs) allowed to call")
	flag.Parse()
	if *tlsDir == "" {
		fmt.Fprintln(os.Stderr, "reporting-provider: -tls-dir is required")
		os.Exit(2)
	}
	logger := log.New(os.Stderr, "reporting-provider: ", log.LstdFlags)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Fatal(err)
	}
	cfg := provider.Config{Listener: lis, TLS: providerkit.SecretFiles(*tlsDir),
		AuthorizedHosts: strings.Split(*hosts, ","), Log: logger.Printf}
	if *health != "" {
		if cfg.Health, err = net.Listen("tcp", *health); err != nil {
			logger.Fatal(err)
		}
	}
	if err := provider.Serve(ctx, provider.New(provider.Source()), cfg); err != nil {
		logger.Fatal(err)
	}
}
