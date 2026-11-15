package controller

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"path/filepath"

	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/backend-bunny/Konstapel/internal/download"
)

// MetricsTLS configures the controller's authenticated metrics endpoint.
// The endpoint serves only HTTPS with this verified certificate: there is
// no plaintext mode and no self-signed fallback.
type MetricsTLS struct {
	// CertDir holds tls.crt, tls.key and ca.crt (a kubernetes.io/tls
	// Secret volume). The certificate must chain to ca.crt, be valid now and
	// cover ServerName.
	CertDir string
	// ServerName is the Service name clients verify, such as
	// konstapel-controller-metrics.konstapel-system.svc.
	ServerName string
}

// metricsOptions builds the metrics server options. Disabled ("0" or
// empty) serves nothing. Any other address requires MetricsTLS: requests
// are authenticated with TokenReview and authorized with
// SubjectAccessReview (get on the non-resource URL /metrics) by
// controller-runtime's filter, and the certificate is verified at start
// and reloaded, keeping the last good one when a rotation is invalid.
func metricsOptions(addr string, mtls *MetricsTLS) (metricsserver.Options, *download.Certificates, error) {
	if addr == "" || addr == "0" {
		return metricsserver.Options{BindAddress: "0"}, nil, nil
	}
	if mtls == nil || mtls.CertDir == "" || mtls.ServerName == "" {
		return metricsserver.Options{}, nil, errors.New("metrics: serving requires a TLS certificate directory and server name; plaintext metrics are not supported")
	}
	certs, err := download.LoadCertificates(filepath.Join(mtls.CertDir, "tls.crt"), filepath.Join(mtls.CertDir, "tls.key"),
		filepath.Join(mtls.CertDir, "ca.crt"), []string{mtls.ServerName})
	if err != nil {
		return metricsserver.Options{}, nil, fmt.Errorf("metrics TLS: %w", err)
	}
	return metricsserver.Options{
		BindAddress:    addr,
		SecureServing:  true,
		FilterProvider: filters.WithAuthenticationAndAuthorization,
		TLSOpts: []func(*tls.Config){func(c *tls.Config) {
			c.MinVersion = tls.VersionTLS12
			c.GetCertificate = certs.GetCertificate
		}},
	}, certs, nil
}

// certificateReloader re-reads the metrics certificate on every replica.
type certificateReloader struct{ certs *download.Certificates }

func (certificateReloader) NeedLeaderElection() bool { return false }

func (r certificateReloader) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("metrics-tls")
	r.certs.Watch(ctx, download.DefaultReloadInterval, func(err error) {
		logger.Info("metrics certificate rotation rejected; serving the last valid certificate", "error", err.Error())
	})
	return nil
}
