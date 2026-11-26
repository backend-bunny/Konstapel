// Package certs writes throwaway mutual TLS material for the quickstart: one
// private CA, a provider server certificate and a host client certificate,
// each as a kubernetes.io/tls-style directory (tls.crt, tls.key, ca.crt).
//
// The material is for a local demonstration only. Keys are generated at run
// time, written with owner-only permissions and never committed. In a
// cluster, certificates are the platform's (for example cert-manager).
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Default peer names of the quickstart. Each is an exact DNS subject
// alternative name; the kit never matches wildcards or common names.
const (
	ServerName = "reporting.provider.example.test"
	HostName   = "host.konstapel.example.test"
)

// Options name the peers and the validity of the generated material.
type Options struct {
	ServerName string
	HostName   string
	// NotBefore and Validity bound every certificate; NotBefore defaults to
	// a minute ago and Validity to 24 hours.
	NotBefore time.Time
	Validity  time.Duration
}

// Generate writes dir/server and dir/host, each holding tls.crt, tls.key and
// ca.crt. dir must not exist yet, so existing material is never overwritten.
func Generate(dir string, o Options) error {
	if o.ServerName == "" {
		o.ServerName = ServerName
	}
	if o.HostName == "" {
		o.HostName = HostName
	}
	if o.NotBefore.IsZero() {
		o.NotBefore = time.Now().Add(-time.Minute)
	}
	if o.Validity == 0 {
		o.Validity = 24 * time.Hour
	}
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("%s already exists; choose a fresh directory", dir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	notAfter := o.NotBefore.Add(o.Validity)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "konstapel quickstart CA"},
		NotBefore:             o.NotBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leaves := []struct {
		sub   string
		name  string
		usage x509.ExtKeyUsage
	}{
		{"server", o.ServerName, x509.ExtKeyUsageServerAuth},
		{"host", o.HostName, x509.ExtKeyUsageClientAuth},
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, l := range leaves {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: serial(),
			Subject:      pkix.Name{CommonName: l.name},
			DNSNames:     []string{l.name},
			NotBefore:    o.NotBefore,
			NotAfter:     notAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{l.usage},
		}, ca, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		out := filepath.Join(dir, l.sub)
		if err := os.Mkdir(out, 0o700); err != nil {
			return err
		}
		files := []struct {
			name string
			data []byte
			mode os.FileMode
		}{
			{"tls.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644},
			{"tls.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600},
			// One CA signs both sides, so each side's ca.crt is also the
			// trust for its peer.
			{"ca.crt", caPEM, 0o644},
		}
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(out, f.name), f.data, f.mode); err != nil {
				return err
			}
		}
	}
	return nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}
