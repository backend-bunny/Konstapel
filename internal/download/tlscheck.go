package download

import (
	"bytes"
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
	m, err := readMaterial(certFile, keyFile, caFile)
	if err != nil {
		return err
	}
	_, err = m.verify(names, now)
	return err
}

// material is one read of the serving certificate, key and CA bundle.
type material struct {
	cert, key, ca []byte
	caSet         bool
}

func readMaterial(certFile, keyFile, caFile string) (material, error) {
	var m material
	var err error
	if m.cert, err = os.ReadFile(certFile); err != nil {
		return m, fmt.Errorf("TLS key pair: %w", err)
	}
	if m.key, err = os.ReadFile(keyFile); err != nil {
		return m, fmt.Errorf("TLS key pair: %w", err)
	}
	if caFile != "" {
		m.caSet = true
		if m.ca, err = os.ReadFile(caFile); err != nil {
			return m, fmt.Errorf("TLS CA bundle: %w", err)
		}
	}
	return m, nil
}

func (m material) equal(o material) bool {
	return m.caSet == o.caSet && bytes.Equal(m.cert, o.cert) && bytes.Equal(m.key, o.key) && bytes.Equal(m.ca, o.ca)
}

// verify returns the key pair once every check passes.
func (m material) verify(names []string, now time.Time) (*tls.Certificate, error) {
	pair, err := tls.X509KeyPair(m.cert, m.key)
	if err != nil {
		return nil, fmt.Errorf("TLS key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("TLS certificate: %w", err)
	}
	pair.Leaf = leaf
	if err := validAt(leaf, now); err != nil {
		return nil, err
	}
	for _, n := range names {
		if err := leaf.VerifyHostname(n); err != nil {
			return nil, fmt.Errorf("TLS certificate does not cover service name %s (it names %v)", n, leaf.DNSNames)
		}
	}
	if !m.caSet {
		return &pair, nil
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(m.ca) {
		return nil, errors.New("TLS CA bundle has no certificates")
	}
	inter := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		if c, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, fmt.Errorf("TLS certificate is not trusted by the CA bundle clients use: %w", err)
	}
	return &pair, nil
}

func validAt(leaf *x509.Certificate, now time.Time) error {
	switch {
	case now.Before(leaf.NotBefore):
		return fmt.Errorf("TLS certificate is not valid until %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	case now.After(leaf.NotAfter):
		return fmt.Errorf("TLS certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}
