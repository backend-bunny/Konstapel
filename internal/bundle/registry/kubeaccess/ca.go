package kubeaccess

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

// Limits on a custom CA bundle.
const (
	MaxCABytes = 1 << 20
	MaxCACerts = 512
)

// ErrMalformedCA: a referenced CA bundle is not an acceptable PEM
// certificate bundle. It wraps registry.ErrTrustConfig.
var ErrMalformedCA = fmt.Errorf("%w: malformed CA bundle", registry.ErrTrustConfig)

func badCA(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrMalformedCA}, a...)...)
}

// ParseCABundle parses PEM certificates strictly: only CERTIFICATE blocks
// without headers, nothing but whitespace around them, at least one and at
// most MaxCACerts certificates within MaxCABytes. A private key or any other
// block type is rejected. The certificates are trust anchors; they need not
// be CA certificates (a self-signed server certificate works).
func ParseCABundle(data []byte) ([]*x509.Certificate, error) {
	switch {
	case len(data) > MaxCABytes:
		return nil, badCA("exceeds %d bytes", MaxCABytes)
	case len(bytes.TrimSpace(data)) == 0:
		return nil, badCA("contains no certificates")
	}
	// pem.Decode silently skips text and malformed blocks; count the block
	// starts so that nothing can be skipped.
	begins := bytes.Count(data, []byte("-----BEGIN"))
	var certs []*x509.Certificate
	rest := data
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return nil, badCA("contains data outside PEM blocks")
		}
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, badCA("contains a malformed PEM block")
		}
		switch {
		case strings.Contains(block.Type, "PRIVATE KEY"):
			return nil, badCA("contains a private key; only certificates are accepted")
		case block.Type != "CERTIFICATE":
			return nil, badCA("contains a %q block; only CERTIFICATE blocks are accepted", block.Type)
		case len(block.Headers) > 0:
			return nil, badCA("a CERTIFICATE block has PEM headers")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, badCA("certificate %d does not parse", len(certs)+1)
		}
		if certs = append(certs, cert); len(certs) > MaxCACerts {
			return nil, badCA("more than %d certificates", MaxCACerts)
		}
	}
	if len(certs) == 0 {
		return nil, badCA("contains no certificates")
	}
	if len(certs) != begins {
		return nil, badCA("contains a malformed PEM block")
	}
	return certs, nil
}

// newTransport returns a transport that trusts roots plus extra (when roots
// is nil, the system roots only), requires TLS 1.2 or later and never skips
// verification. Proxying follows http.ProxyFromEnvironment, as
// http.DefaultTransport does; TLS to the registry is end to end through a
// CONNECT proxy.
func newTransport(roots *x509.CertPool, extra []*x509.Certificate) *http.Transport {
	if len(extra) > 0 {
		for _, c := range extra {
			roots.AddCert(c)
		}
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = http.ProxyFromEnvironment
	t.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	return t
}
