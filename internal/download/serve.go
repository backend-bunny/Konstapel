package download

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Serve serves h over TLS on l until ctx ends. Plain HTTP is never served:
// bearer tokens and evidence must not cross the network unencrypted.
// DefaultDrain bounds how long accepted requests may finish after shutdown
// begins; remaining connections are then closed.
const DefaultDrain = 20 * time.Second

func Serve(ctx context.Context, l net.Listener, certFile, keyFile string, h http.Handler, drain time.Duration) error {
	if drain <= 0 {
		return fmt.Errorf("shutdown drain %s must be positive", drain)
	}
	if certFile == "" || keyFile == "" {
		return errors.New("a TLS certificate and key are required")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("TLS certificate: %w", err)
	}
	srv := &http.Server{
		Handler:           h,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
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
