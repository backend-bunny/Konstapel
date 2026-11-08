package download

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mounted mimics a Secret volume as the kubelet writes it: each file is a
// symlink through ..data, and an update atomically swaps ..data to a new
// directory, so readers never see a mix of old and new files.
type mounted struct{ dir string }

func (m mounted) path(n string) string { return filepath.Join(m.dir, n) }

func (m mounted) set(t *testing.T, ca testCA, cert, key string) {
	t.Helper()
	files := map[string][]byte{"ca.crt": ca.pem}
	for n, src := range map[string]string{"tls.crt": cert, "tls.key": key} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		files[n] = b
	}
	m.write(t, files)
}

func (m mounted) write(t *testing.T, files map[string][]byte) {
	t.Helper()
	gen, err := os.MkdirTemp(m.dir, "..gen")
	if err != nil {
		t.Fatal(err)
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(gen, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
		link := m.path(n)
		if _, err := os.Lstat(link); os.IsNotExist(err) {
			if err := os.Symlink(filepath.Join("..data", n), link); err != nil {
				t.Fatal(err)
			}
		}
	}
	tmp := m.path("..data_tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(filepath.Base(gen), tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, m.path("..data")); err != nil {
		t.Fatal(err)
	}
}

// read returns the current files, for a rotation that changes one of them.
func (m mounted) read(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, n := range []string{"tls.crt", "tls.key", "ca.crt"} {
		if b, err := os.ReadFile(m.path(n)); err == nil {
			out[n] = b
		}
	}
	return out
}

func servedSerial(t *testing.T, addr string, roots *x509.CertPool) (string, error) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots, ServerName: "konstapel-download.konstapel-system.svc"})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.String(), nil
}

func probe(t *testing.T, addr, route string) int {
	t.Helper()
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // kubelet probes skip verification too
	resp, err := hc.Get("https://" + addr + route)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestCertificatesReloadRotation(t *testing.T) {
	names := []string{"konstapel-download.konstapel-system.svc"}
	now := time.Now()
	m := mounted{t.TempDir()}
	oldCA := newCA(t)
	c1, k1 := oldCA.leaf(t, names, now.Add(-time.Hour), now.Add(time.Hour))
	m.set(t, oldCA, c1, k1)
	certs, err := LoadCertificates(m.path("tls.crt"), m.path("tls.key"), m.path("ca.crt"), names)
	if err != nil {
		t.Fatal(err)
	}
	clock := now
	certs.Now = func() time.Time { return clock }

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l, certs, http.NotFoundHandler(), DefaultDrain) }()
	addr := l.Addr().String()
	oldRoots := x509.NewCertPool()
	oldRoots.AppendCertsFromPEM(oldCA.pem)
	for range 50 {
		if _, err = servedSerial(t, addr, oldRoots); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	if code := probe(t, addr, ReadyRoute); code != http.StatusOK {
		t.Fatalf("valid certificate not ready: %d", code)
	}

	// Leaf rotation under the same CA is served without a restart.
	c2, k2 := oldCA.leaf(t, names, now.Add(-time.Minute), now.Add(2*time.Hour))
	m.set(t, oldCA, c2, k2)
	if err := certs.Reload(); err != nil {
		t.Fatal(err)
	}
	served, _ := certs.GetCertificate(nil)
	if served.Leaf.NotAfter.Sub(now) < 90*time.Minute {
		t.Fatal("rotated leaf not served")
	}
	if _, err := servedSerial(t, addr, oldRoots); err != nil {
		t.Fatalf("handshake after leaf rotation: %v", err)
	}

	// CA rotation: a new CA and leaf are served; clients trusting only the
	// new CA connect, and the old trust no longer validates it.
	newCA := newCA(t)
	c3, k3 := newCA.leaf(t, names, now.Add(-time.Minute), now.Add(time.Hour))
	m.set(t, newCA, c3, k3)
	if err := certs.Reload(); err != nil {
		t.Fatal(err)
	}
	newRoots := x509.NewCertPool()
	newRoots.AppendCertsFromPEM(newCA.pem)
	if _, err := servedSerial(t, addr, newRoots); err != nil {
		t.Fatalf("handshake trusting the rotated CA: %v", err)
	}
	if _, err := servedSerial(t, addr, oldRoots); err == nil {
		t.Fatal("old CA still validates the rotated certificate")
	}

	// Invalid rotations keep the last good certificate but report not ready.
	wrongName, wrongKey := newCA.leaf(t, []string{"elsewhere.example"}, now.Add(-time.Minute), now.Add(time.Hour))
	cases := map[string]func(){
		"wrong service name": func() { m.set(t, newCA, wrongName, wrongKey) },
		"mismatched key":     func() { m.set(t, newCA, c3, k1) },
		"untrusted by CA":    func() { m.set(t, oldCA, c3, k3) },
		"missing key": func() {
			f := m.read(t)
			delete(f, "tls.key")
			m.write(t, f)
		},
	}
	for name, apply := range cases {
		apply()
		if err := certs.Reload(); err == nil {
			t.Fatalf("%s: reload accepted", name)
		}
		if code := probe(t, addr, ReadyRoute); code != http.StatusServiceUnavailable {
			t.Fatalf("%s: readiness %d", name, code)
		}
		if code := probe(t, addr, HealthRoute); code != http.StatusOK {
			t.Fatalf("%s: liveness %d", name, code)
		}
		if _, err := servedSerial(t, addr, newRoots); err != nil {
			t.Fatalf("%s: last good certificate not served: %v", name, err)
		}
		m.set(t, newCA, c3, k3)
		if err := certs.Reload(); err != nil || probe(t, addr, ReadyRoute) != http.StatusOK {
			t.Fatalf("%s: not ready after repair: %v", name, err)
		}
	}

	// Expiry of the served certificate is not ready even without a rotation.
	clock = now.Add(2 * time.Hour)
	if err := certs.Ready(); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired certificate ready: %v", err)
	}
	if code := probe(t, addr, ReadyRoute); code != http.StatusServiceUnavailable {
		t.Fatalf("expired certificate readiness %d", code)
	}
	clock = now
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestCertificatesWatchReloads(t *testing.T) {
	names := []string{"konstapel-download.konstapel-system.svc"}
	now := time.Now()
	m := mounted{t.TempDir()}
	ca := newCA(t)
	c1, k1 := ca.leaf(t, names, now.Add(-time.Hour), now.Add(time.Hour))
	m.set(t, ca, c1, k1)
	certs, err := LoadCertificates(m.path("tls.crt"), m.path("tls.key"), m.path("ca.crt"), names)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 10)
	go certs.Watch(ctx, 10*time.Millisecond, func(err error) { errs <- err })
	c2, k2 := ca.leaf(t, names, now.Add(-time.Hour), now.Add(3*time.Hour))
	m.set(t, ca, c2, k2)
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, _ := certs.GetCertificate(nil)
		if got.Leaf.NotAfter.Sub(now) > 2*time.Hour {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("watch did not reload the rotated certificate")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case err := <-errs:
		t.Fatalf("valid rotation reported %v", err)
	default:
	}
}

func TestLoadCertificatesRefusesInvalid(t *testing.T) {
	ca := newCA(t)
	now := time.Now()
	c, k := ca.leaf(t, []string{"other.example"}, now.Add(-time.Hour), now.Add(time.Hour))
	if _, err := LoadCertificates(c, k, "", []string{"konstapel-download.konstapel-system.svc"}); err == nil {
		t.Fatal("loaded a certificate for the wrong name")
	}
	if _, err := LoadCertificates("", "", "", nil); err == nil {
		t.Fatal("loaded without files")
	}
}
