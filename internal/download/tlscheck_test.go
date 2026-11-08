package download

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T) testCA {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return testCA{c, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf writes a CA-signed serving certificate and key; it returns their paths.
func (ca testCA) leaf(t *testing.T, names []string, notBefore, notAfter time.Time) (string, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "download"}, DNSNames: names,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	c, k := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	_ = os.WriteFile(c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(k, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return c, k
}

func writeFile(t *testing.T, b []byte) string {
	f := filepath.Join(t.TempDir(), "ca.crt")
	_ = os.WriteFile(f, b, 0o600)
	return f
}

func TestVerifyServingCertificate(t *testing.T) {
	now := time.Now()
	ca, other := newCA(t), newCA(t)
	svc := []string{"konstapel-download.konstapel-system.svc"}
	good, goodKey := ca.leaf(t, svc, now.Add(-time.Hour), now.Add(time.Hour))
	caFile := writeFile(t, ca.pem)
	if err := VerifyServingCertificate(good, goodKey, caFile, svc, now); err != nil {
		t.Fatalf("valid certificate rejected: %v", err)
	}
	wrongName, wrongNameKey := ca.leaf(t, []string{"elsewhere.svc"}, now.Add(-time.Hour), now.Add(time.Hour))
	expired, expiredKey := ca.leaf(t, svc, now.Add(-2*time.Hour), now.Add(-time.Hour))
	future, futureKey := ca.leaf(t, svc, now.Add(time.Hour), now.Add(2*time.Hour))
	for name, c := range map[string]struct {
		cert, key, ca string
		want          string
	}{
		"absent key":         {good, filepath.Join(t.TempDir(), "missing.key"), caFile, "TLS key pair"},
		"mismatched key":     {good, expiredKey, caFile, "TLS key pair"},
		"wrong service name": {wrongName, wrongNameKey, caFile, "does not cover service name konstapel-download.konstapel-system.svc"},
		"expired":            {expired, expiredKey, caFile, "expired"},
		"not yet valid":      {future, futureKey, caFile, "not valid until"},
		"untrusted":          {good, goodKey, writeFile(t, other.pem), "not trusted by the CA bundle"},
		"empty CA bundle":    {good, goodKey, writeFile(t, []byte("not a certificate")), "no certificates"},
	} {
		err := VerifyServingCertificate(c.cert, c.key, c.ca, svc, now)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Errorf("%s: error exposes key material", name)
		}
	}
}
