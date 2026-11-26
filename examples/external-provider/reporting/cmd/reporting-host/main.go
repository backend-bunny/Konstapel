// Command reporting-host plays the Konstapel host against a provider: it
// describes it, collects, reads and acknowledges the result, and evaluates
// it, printing each step.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"example.com/konstapel-reporting/certs"
	"example.com/konstapel-reporting/host"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18443", "provider address")
	tlsDir := flag.String("tls-dir", "", "directory holding the host's tls.crt, tls.key and ca.crt")
	server := flag.String("server-name", certs.ServerName, "DNS SAN the provider certificate must carry")
	flag.Parse()
	if *tlsDir == "" {
		fmt.Fprintln(os.Stderr, "reporting-host: -tls-dir is required")
		os.Exit(2)
	}
	conn, err := host.Dial(*addr, providerkit.SecretFiles(*tlsDir), *server)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reporting-host:", err)
		os.Exit(1)
	}
	defer conn.Close()
	if _, err := host.Run(context.Background(), conn, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "reporting-host: %v (reason %s)\n", err, providerkit.ReasonOf(err))
		os.Exit(1)
	}
}
