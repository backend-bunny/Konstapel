// Command quickstart-certs writes throwaway mutual TLS material for the
// quickstart into a fresh directory: server/ for the provider and host/ for
// the host, each with tls.crt, tls.key and ca.crt. Never commit the output.
package main

import (
	"flag"
	"fmt"
	"os"

	"example.com/konstapel-reporting/certs"
)

func main() {
	out := flag.String("out", "", "fresh directory to write server/ and host/ into")
	server := flag.String("server-name", certs.ServerName, "DNS SAN of the provider certificate")
	host := flag.String("host-name", certs.HostName, "DNS SAN of the host certificate")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "quickstart-certs: -out is required")
		os.Exit(2)
	}
	if err := certs.Generate(*out, certs.Options{ServerName: *server, HostName: *host}); err != nil {
		fmt.Fprintln(os.Stderr, "quickstart-certs:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s/server (%s) and %s/host (%s), valid 24h\n", *out, *server, *out, *host)
}
