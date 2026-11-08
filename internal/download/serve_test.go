package download

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func selfSigned(t *testing.T) (string, string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "download"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	cert, keyf := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	_ = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return cert, keyf
}

func TestServeIsTLSOnly(t *testing.T) {
	e := newEnv(t)
	cert, key := selfSigned(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l, mustLoad(t, cert, key), e.h, DefaultDrain) }()
	base := "://" + l.Addr().String() + teamPath
	tlsClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // test-only self-signed cert
	var resp *http.Response
	for range 50 {
		if resp, err = tlsClient.Get("https" + base); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("TLS route without a token: %v %v", resp, err)
	}
	_ = resp.Body.Close()
	if r, err := http.Get("http" + base); err == nil && r.StatusCode < 400 {
		t.Fatal("plain HTTP served")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := Serve(context.Background(), l, nil, e.h, DefaultDrain); err == nil {
		t.Fatal("served without a certificate")
	}
}

// A request that never finishes cannot hold shutdown open past the drain:
// the server closes it and Serve returns.
func TestServeDrainIsBounded(t *testing.T) {
	cert, key := selfSigned(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	hang := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		<-release // a download that would never finish
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l, mustLoad(t, cert, key), hang, 300*time.Millisecond) }()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // test-only self-signed cert
	go func() {
		for range 50 {
			if resp, err := client.Get("https://" + l.Addr().String() + "/"); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	<-started
	begin := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a hanging request held shutdown open")
	}
	if waited := time.Since(begin); waited < 300*time.Millisecond || waited > 2*time.Second {
		t.Fatalf("shutdown took %s for a 300ms drain", waited)
	}
	if err := Serve(context.Background(), l, mustLoad(t, cert, key), hang, 0); err == nil {
		t.Fatal("non-positive drain accepted")
	}
}

func mustLoad(t *testing.T, cert, key string) *Certificates {
	t.Helper()
	c, err := LoadCertificates(cert, key, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
