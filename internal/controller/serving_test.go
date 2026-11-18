package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// Serving runs on every replica (add-controller-high-availability 3.1):
// the webhook server, the certificate reloaders and the informer gate are
// not leader-elected, so a follower serves admission and reports ready.
func TestServingRunnablesNeedNoLeadership(t *testing.T) {
	for name, r := range map[string]manager.LeaderElectionRunnable{
		"admission webhook server": webhook.NewServer(webhook.Options{}).(manager.LeaderElectionRunnable),
		"webhook certificate":      certificateReloader{server: "webhook"},
		"metrics certificate":      certificateReloader{},
		"informer readiness gate":  &informerSync{},
	} {
		if r.NeedLeaderElection() {
			t.Errorf("%s runs only on the leader", name)
		}
	}
}

// A replica is not ready before its informer caches synced, and a sync
// that never completes (shutdown first) never reports ready.
func TestInformerSyncGatesReadiness(t *testing.T) {
	release := make(chan struct{})
	s := &informerSync{wait: func(ctx context.Context) bool {
		select {
		case <-release:
			return true
		case <-ctx.Done():
			return false
		}
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Start(ctx) }()
	time.Sleep(50 * time.Millisecond)
	if err := s.check(nil); err == nil || !strings.Contains(err.Error(), "not synced") {
		t.Fatalf("ready before the caches synced: %v", err)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for s.check(nil) != nil {
		if time.Now().After(deadline) {
			t.Fatal("not ready after the caches synced")
		}
		time.Sleep(10 * time.Millisecond)
	}

	never := &informerSync{wait: func(ctx context.Context) bool { <-ctx.Done(); return false }}
	nctx, ncancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = never.Start(nctx); close(done) }()
	ncancel()
	<-done
	if never.check(nil) == nil {
		t.Fatal("ready although the caches never synced")
	}
}

// writeLeaf writes tls.crt and tls.key, issued by ca and valid in
// [notBefore, notAfter] for 127.0.0.1 and ips, into dir.
func writeLeaf(t *testing.T, dir string, ca testIssuer, serial int64, notBefore, notAfter time.Time, ips ...string) {
	t.Helper()
	addrs := []net.IP{net.ParseIP("127.0.0.1")}
	for _, ip := range ips {
		addrs = append(addrs, net.ParseIP(ip))
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "konstapel-webhook.konstapel-system.svc"},
		DNSNames: []string{"konstapel-webhook.konstapel-system.svc"}, IPAddresses: addrs,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
		NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	for name, b := range map[string][]byte{
		"tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"tls.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// The webhook readiness check follows the served certificate and the
// server: not ready before the server answers TLS, ready with a verified
// certificate, not ready after a rejected rotation (the last good
// certificate keeps serving), ready again once a valid one is mounted.
func TestWebhookReadinessFollowsTLS(t *testing.T) {
	ca := newIssuer(t)
	dir := t.TempDir()
	now := time.Now()
	writeLeaf(t, dir, ca, 2, now.Add(-time.Hour), now.Add(time.Hour))
	certs, err := webhookTLS(dir)
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	srv := webhook.NewServer(webhook.Options{Host: "127.0.0.1", Port: port, TLSOpts: webhookTLSOptions(certs)})
	ready := webhookReady(certs, srv.StartedChecker())
	req, _ := http.NewRequest(http.MethodGet, "/readyz", nil)
	if err := ready(req); err == nil {
		t.Fatal("ready before the webhook server started")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := ready(req)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not ready with a valid certificate: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	served := func() *x509.Certificate {
		conn, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // inspects the served certificate only
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0]
	}
	if s := served().SerialNumber.Int64(); s != 2 {
		t.Fatalf("served serial %d", s)
	}

	// An expired rotation is rejected: the replica keeps serving the last
	// good certificate but leaves its Service.
	writeLeaf(t, dir, ca, 3, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err := certs.Reload(); err == nil {
		t.Fatal("expired rotation accepted")
	}
	if err := ready(req); err == nil || !strings.Contains(err.Error(), "webhook TLS") {
		t.Fatalf("ready with a rejected rotation: %v", err)
	}
	if s := served().SerialNumber.Int64(); s != 2 {
		t.Fatalf("served serial %d after a rejected rotation", s)
	}
	// A valid rotation is served and the replica is ready again.
	writeLeaf(t, dir, ca, 4, now.Add(-time.Hour), now.Add(time.Hour))
	if err := certs.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := ready(req); err != nil {
		t.Fatalf("not ready after a valid rotation: %v", err)
	}
	if s := served().SerialNumber.Int64(); s != 4 {
		t.Fatalf("served serial %d after a valid rotation", s)
	}
}

// Invalid webhook TLS fails startup instead of serving an unusable
// endpoint; the manager is never built.
func TestWebhookTLSValidatedAtStartup(t *testing.T) {
	ca := newIssuer(t)
	expired := t.TempDir()
	writeLeaf(t, expired, ca, 2, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	for name, dir := range map[string]string{"missing files": t.TempDir(), "expired": expired} {
		_, err := NewManager(&rest.Config{Host: "https://127.0.0.1:1"}, Options{WebhookCertDir: dir})
		if err == nil || !strings.Contains(err.Error(), "webhook TLS") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
