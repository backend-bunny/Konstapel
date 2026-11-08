// Command s3fault runs the test-owned S3 fault proxy (package s3fault) for
// live acceptance. It is built statically by the test and runs in a
// disposable container on the kind network; it is never shipped.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/backend-bunny/Konstapel/internal/s3fault"
)

func main() {
	backend := flag.String("backend", "", "S3 backend host:port (plain HTTP)")
	listen := flag.String("listen", ":9000", "S3 data address")
	control := flag.String("control", ":9100", "control address")
	flag.Parse()
	if *backend == "" {
		log.Fatal("-backend is required")
	}
	p := &s3fault.Proxy{Backend: *backend, Logf: log.Printf}
	go func() {
		srv := &http.Server{Addr: *control, Handler: p.Control(), ReadHeaderTimeout: 10 * time.Second}
		log.Fatal(srv.ListenAndServe())
	}()
	srv := &http.Server{Addr: *listen, Handler: p, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
