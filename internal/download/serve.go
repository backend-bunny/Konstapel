package download

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// DefaultDrain bounds how long accepted requests may finish after shutdown
// begins; remaining connections are then closed.
const DefaultDrain = 20 * time.Second

// Probe paths answer without authorization and reveal nothing but health:
// HealthRoute while the process serves, ReadyRoute only while its serving
// certificate is valid.
const (
	HealthRoute = "/healthz"
	ReadyRoute  = "/readyz"
)

// Serve serves h over TLS on l until ctx ends, presenting the current
// certificate from certs on every handshake. Plain HTTP is never served:
// bearer tokens and evidence must not cross the network unencrypted.
func Serve(ctx context.Context, l net.Listener, certs *Certificates, h http.Handler, drain time.Duration) error {
	if drain <= 0 {
		return fmt.Errorf("shutdown drain %s must be positive", drain)
	}
	if certs == nil {
		return errors.New("a TLS certificate and key are required")
	}
	if _, err := certs.GetCertificate(nil); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/", h)
	mux.HandleFunc(HealthRoute, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc(ReadyRoute, func(w http.ResponseWriter, _ *http.Request) {
		if ctx.Err() != nil {
			http.Error(w, "shutting down", http.StatusServiceUnavailable)
			return
		}
		if err := certs.Ready(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok")
	})
	srv := &http.Server{
		Handler:           mux,
		TLSConfig:         &tls.Config{GetCertificate: certs.GetCertificate, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Minute,
	}
	done := make(chan error, 1)
	go func() { done <- srv.ServeTLS(l, "", "") }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), drain)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			// The drain expired: a long download cannot hold termination
			// open. Its client retries the full download with fresh
			// authorization.
			_ = srv.Close()
		}
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
