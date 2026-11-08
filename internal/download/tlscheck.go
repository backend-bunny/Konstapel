package download

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"
)

// VerifyServingCertificate checks a serving certificate before it is used:
// the key pair loads and matches, the leaf is currently valid, it chains to
// the CA bundle in caFile (when set), and its names cover every service name
// clients use. A failure is explicit at startup instead of a half-working
// endpoint. It never prints key material.
func VerifyServingCertificate(certFile, keyFile, caFile string, names []string, now time.Time) error {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("TLS key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("TLS certificate: %w", err)
	}
	switch {
	case now.Before(leaf.NotBefore):
		return fmt.Errorf("TLS certificate is not valid until %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	case now.After(leaf.NotAfter):
		return fmt.Errorf("TLS certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	for _, n := range names {
		if err := leaf.VerifyHostname(n); err != nil {
			return fmt.Errorf("TLS certificate does not cover service name %s (it names %v)", n, leaf.DNSNames)
		}
	}
	if caFile == "" {
		return nil
	}
	raw, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("TLS CA bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return errors.New("TLS CA bundle has no certificates")
	}
	inter := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("TLS certificate is not trusted by the CA bundle clients use: %w", err)
	}
	return nil
}
