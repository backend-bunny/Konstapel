package provider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"google.golang.org/grpc"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

// Config is one provider process.
type Config struct {
	// Listener serves the protocol over mutual TLS.
	Listener net.Listener
	// Health, when set, serves plain-HTTP /healthz and /readyz probes. They
	// run on their own port: the protocol port admits only authenticated
	// calls that carry a deadline, which kubelet probes do not.
	Health net.Listener
	// TLS are the mounted tls.crt, tls.key and ca.crt files.
	TLS providerkit.TLSFiles
	// AuthorizedHosts are the host identities (exact DNS SANs) allowed to
	// call.
	AuthorizedHosts []string
	// Reload is how often the TLS files are re-read (the kit default when
	// zero).
	Reload time.Duration
	// Log receives one line per event.
	Log func(format string, args ...any)
	// Ready, when set, is checked by /readyz after the serving material:
	// the worker reports its evaluator client's TLS material there.
	Ready func() error
}

// Serve runs s until ctx ends.
func Serve(ctx context.Context, s Service, c Config) error {
	if c.Log == nil {
		c.Log = func(string, ...any) {}
	}
	mtls, err := providerkit.NewServerTLS(c.TLS, c.AuthorizedHosts)
	if err != nil {
		return err
	}
	srv, err := providerkit.NewServer(s.Description, s.Handlers)
	if err != nil {
		return err
	}
	opts, err := providerkit.ServerOptions(mtls, providerkit.TransportLimits{Protocol: srv.Limits()})
	if err != nil {
		return err
	}
	g := grpc.NewServer(opts...)
	providerv1.RegisterAssessmentProviderServer(g, srv)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Rotated certificate files are picked up without a restart; a rejected
	// reload keeps the last valid material and fails readiness.
	go mtls.Watch(ctx, c.Reload, func(err error) { c.Log("tls reload rejected: %v", err) })

	errs := make(chan error, 2)
	if c.Health != nil {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
		mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
			err := mtls.Ready()
			if err == nil && c.Ready != nil {
				err = c.Ready()
			}
			if err != nil {
				http.Error(w, "not ready: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
			fmt.Fprintln(w, "ready")
		})
		h := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() { errs <- h.Serve(c.Health) }()
		defer h.Close()
		c.Log("health probes on http://%s", c.Health.Addr())
	}
	go func() { errs <- g.Serve(c.Listener) }()
	c.Log("serving %s/v%d on %s for %v", Name, ContractVersion, c.Listener.Addr(), c.AuthorizedHosts)
	if s.Description.GetImplementation() != QuickstartImplementation {
		c.Log("capabilities %v, implementation %s", s.Description.GetCapabilities(), s.Description.GetImplementation())
	}

	select {
	case <-ctx.Done():
		g.GracefulStop()
		c.Log("stopped")
		return nil
	case err := <-errs:
		g.Stop()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
