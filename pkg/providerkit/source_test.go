package providerkit

import (
	"bytes"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
)

// memorySource is a host's material held in memory: the client certificate
// and key it would read from a mounted Secret and a trust bundle it read
// elsewhere, such as a provider registration's ConfigMap.
type memorySource struct {
	mu    sync.Mutex
	mat   TLSMaterial
	err   error
	loads int
}

func (s *memorySource) LoadTLS() (TLSMaterial, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads++
	return s.mat, s.err
}

func (s *memorySource) set(mat TLSMaterial, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mat, s.err = mat, err
}

func newMemorySource(i issued, trust []byte) *memorySource {
	return &memorySource{mat: TLSMaterial{Certificate: i.cert, Key: i.key, Trust: trust}}
}

// A host whose trust is not a file authenticates the provider exactly as
// one with mounted files: the trust it supplies is the only trust, and a
// provider it does not trust receives no call.
func TestClientTLSFromSourceAuthenticatesTheServer(t *testing.T) {
	f := newFixture(t, TransportLimits{})
	src := newMemorySource(f.ca.issue(t, clientLeaf()), f.ca.pem)
	m, err := NewClientTLSFrom(src, testServerName)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Ready(); err != nil {
		t.Fatal(err)
	}
	leaf, err := describePeer(timeout(t, 5*time.Second), dialTLS(t, m, f.srv.addr, TransportLimits{}))
	if err != nil {
		t.Fatal(err)
	}
	if leaf.DNSNames[0] != testServerName {
		t.Fatalf("authenticated %v", leaf.DNSNames)
	}

	calls := f.srv.calls.Load()
	other := newCA(t)
	untrusting, err := NewClientTLSFrom(newMemorySource(f.ca.issue(t, clientLeaf()), other.pem), testServerName)
	if err != nil {
		t.Fatal(err)
	}
	_, err = describePeer(timeout(t, 5*time.Second), dialTLS(t, untrusting, f.srv.addr, TransportLimits{}))
	wantCode(t, err, codes.Unavailable)
	if f.srv.calls.Load() != calls {
		t.Fatal("a call reached a provider the source's trust does not authorize")
	}
	wrongName, err := NewClientTLSFrom(newMemorySource(f.ca.issue(t, clientLeaf()), f.ca.pem), "other-provider.providers.svc")
	if err != nil {
		t.Fatal(err)
	}
	_, err = describePeer(timeout(t, 5*time.Second), dialTLS(t, wrongName, f.srv.addr, TransportLimits{}))
	wantCode(t, err, codes.Unavailable)
	if f.srv.calls.Load() != calls {
		t.Fatal("a call reached a provider whose certificate names another server")
	}
}

// Material from a source passes every check mounted files pass, and a
// rejected load names what is wrong without any key material.
func TestClientTLSFromSourceAppliesTheFileChecks(t *testing.T) {
	ca := newCA(t)
	good := ca.issue(t, clientLeaf())
	other := ca.issue(t, clientLeaf())
	expired := ca.issue(t, clientLeaf().valid(time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)))
	serverOnly := ca.issue(t, serverLeaf())
	oversized := bytes.Repeat(ca.pem, maxTLSFileBytes/len(ca.pem)+1)
	for _, tc := range []struct {
		name string
		mat  TLSMaterial
		err  error
		want string
	}{
		{name: "trust with a private key", mat: TLSMaterial{Certificate: good.cert, Key: good.key, Trust: append(slicesClone(ca.pem), good.key...)}, want: "private key"},
		{name: "trust that is not PEM", mat: TLSMaterial{Certificate: good.cert, Key: good.key, Trust: []byte("not a certificate")}, want: "outside PEM blocks"},
		{name: "empty trust", mat: TLSMaterial{Certificate: good.cert, Key: good.key}, want: "trust bundle contains no certificate"},
		{name: "oversized trust", mat: TLSMaterial{Certificate: good.cert, Key: good.key, Trust: oversized}, want: "trust bundle is larger than"},
		{name: "mismatched key", mat: TLSMaterial{Certificate: good.cert, Key: other.key, Trust: ca.pem}, want: "certificate and key"},
		{name: "expired certificate", mat: TLSMaterial{Certificate: expired.cert, Key: expired.key, Trust: ca.pem}, want: "expired"},
		{name: "server-only certificate", mat: TLSMaterial{Certificate: serverOnly.cert, Key: serverOnly.key, Trust: ca.pem}, want: "does not allow client authentication"},
		{name: "source failure", err: errors.New("trust ConfigMap provider-ca is missing"), want: "trust ConfigMap provider-ca is missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := &memorySource{mat: tc.mat, err: tc.err}
			m, err := NewClientTLSFrom(src, testServerName)
			if err == nil || !strings.Contains(err.Error(), tc.want) || m != nil {
				t.Fatalf("NewClientTLSFrom: %v, want %q", err, tc.want)
			}
			for _, key := range [][]byte{good.key, other.key, expired.key, serverOnly.key} {
				if strings.Contains(err.Error(), string(key)) || strings.Contains(err.Error(), strings.TrimSpace(string(key[28:60]))) {
					t.Fatalf("the error carries key material: %v", err)
				}
			}
		})
	}
	if _, err := NewClientTLSFrom(nil, testServerName); err == nil {
		t.Fatal("a nil source was accepted")
	}
	if _, err := NewClientTLSFrom(newMemorySource(good, ca.pem), "*.providers.svc"); err == nil {
		t.Fatal("a wildcard server name was accepted")
	}
}

// A rotated trust bundle from the source is used on Reload without a
// restart; a rejected reload keeps the last valid material, Ready reports
// it, and nothing insecure stands in. The verified material is a copy, so
// the source changing its buffers changes nothing.
func TestClientTLSFromSourceRotatesTrust(t *testing.T) {
	f := newFixture(t, TransportLimits{})
	client := f.ca.issue(t, clientLeaf())
	src := newMemorySource(client, slicesClone(f.ca.pem))
	m, err := NewClientTLSFrom(src, testServerName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := describePeer(timeout(t, 5*time.Second), dialTLS(t, m, f.srv.addr, TransportLimits{})); err != nil {
		t.Fatal(err)
	}

	// The source's buffer is overwritten in place: the loaded trust stays.
	src.mu.Lock()
	for i := range src.mat.Trust {
		src.mat.Trust[i] = 'x'
	}
	src.mu.Unlock()
	if _, err := describePeer(timeout(t, 5*time.Second), dialTLS(t, m, f.srv.addr, TransportLimits{})); err != nil {
		t.Fatalf("a changed source buffer changed verified material: %v", err)
	}
	if err := m.Reload(); err == nil || m.Ready() == nil {
		t.Fatalf("an invalid reload was accepted: reload %v, ready %v", err, m.Ready())
	}
	if _, err := describePeer(timeout(t, 5*time.Second), dialTLS(t, m, f.srv.addr, TransportLimits{})); err != nil {
		t.Fatalf("the last valid material was dropped after a rejected reload: %v", err)
	}

	// The provider rotates to a new CA. Until the source supplies it, the
	// host does not authenticate the provider; afterwards it does.
	ca2 := newCA(t)
	rotateLeaf(t, f.serverDir, ca2.issue(t, serverLeaf()), nil)
	if err := f.serverTLS.Reload(); err != nil {
		t.Fatal(err)
	}
	calls := f.srv.calls.Load()
	src.set(TLSMaterial{Certificate: client.cert, Key: client.key, Trust: f.ca.pem}, nil)
	if err := m.Reload(); err != nil {
		t.Fatal(err)
	}
	_, err = describePeer(timeout(t, 5*time.Second), dialTLS(t, m, f.srv.addr, TransportLimits{}))
	wantCode(t, err, codes.Unavailable)
	if f.srv.calls.Load() != calls {
		t.Fatal("a call reached the provider under the old trust")
	}
	src.set(TLSMaterial{Certificate: client.cert, Key: client.key, Trust: ca2.pem}, nil)
	if err := m.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := m.Ready(); err != nil {
		t.Fatal(err)
	}
	leaf, err := describePeer(timeout(t, 5*time.Second), dialTLS(t, m, f.srv.addr, TransportLimits{}))
	if err != nil {
		t.Fatalf("the rotated trust was not used: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: poolOf(ca2), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("authenticated a certificate outside the rotated trust: %v", err)
	}
}

func poolOf(ca *testCA) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}
