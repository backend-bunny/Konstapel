package providerkit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
)

// These tests run the kit over real mutual TLS on loopback. Every key and
// certificate is generated in memory per test; key files exist only in the
// test's temporary directory, as a mounted Secret would.

const (
	testServerName = "example-reporting.providers.svc"
	testClientName = "konstapel-controller.konstapel-system.svc"
	canary         = "payload-canary-7f3a9c"
)

var testSerial atomic.Int64

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func pemBlock(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

// newCA returns a CA valid for the hour around now, or within the given
// bounds.
func newCA(t *testing.T, bounds ...time.Time) *testCA {
	t.Helper()
	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	if len(bounds) == 2 {
		notBefore, notAfter = bounds[0], bounds[1]
	}
	key := newKey(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(testSerial.Add(1)), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pemBlock("CERTIFICATE", der)}
}

type leafSpec struct {
	names               []string
	usage               []x509.ExtKeyUsage
	notBefore, notAfter time.Time
}

func serverLeaf(names ...string) leafSpec {
	if len(names) == 0 {
		names = []string{testServerName}
	}
	return leafSpec{names: names, usage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
}

func clientLeaf(names ...string) leafSpec {
	if len(names) == 0 {
		names = []string{testClientName}
	}
	return leafSpec{names: names, usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
}

func (l leafSpec) valid(notBefore, notAfter time.Time) leafSpec {
	l.notBefore, l.notAfter = notBefore, notAfter
	return l
}

// issued is a leaf certificate and its key, in PEM and parsed.
type issued struct {
	cert, key []byte
	leaf      *x509.Certificate
}

func (ca *testCA) issue(t *testing.T, l leafSpec) issued {
	t.Helper()
	if l.notBefore.IsZero() {
		l.notBefore, l.notAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	}
	key := newKey(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(testSerial.Add(1)), Subject: pkix.Name{CommonName: strings.Join(l.names, ",")},
		DNSNames: l.names, NotBefore: l.notBefore, NotAfter: l.notAfter, ExtKeyUsage: l.usage, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return issued{cert: pemBlock("CERTIFICATE", der), key: pemBlock("PRIVATE KEY", pkcs8), leaf: leaf}
}

func (i issued) tlsCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	c, err := tls.X509KeyPair(i.cert, i.key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// tlsDir is one side's mounted material.
type tlsDir struct {
	t     *testing.T
	files TLSFiles
}

func newTLSDir(t *testing.T, i issued, trust []byte) *tlsDir {
	d := &tlsDir{t: t, files: SecretFiles(t.TempDir())}
	d.write(i, trust)
	return d
}

// write replaces each file atomically; a nil trust keeps the trust file.
func (d *tlsDir) write(i issued, trust []byte) {
	d.t.Helper()
	d.writeFile(d.files.Certificate, i.cert)
	d.writeFile(d.files.Key, i.key)
	if trust != nil {
		d.writeFile(d.files.Trust, trust)
	}
}

func (d *tlsDir) writeFile(path string, data []byte) {
	d.t.Helper()
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		d.t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		d.t.Fatal(err)
	}
}

// tlsHandlers count the calls that reach a provider's handlers.
type tlsHandlers struct {
	ref         *referenceHandlers
	collects    atomic.Int64
	evaluations atomic.Int64
	mu          sync.Mutex
	inventory   []byte
	// block makes Collect wait for its context and report it on blocked.
	block   bool
	started chan struct{}
	blocked chan context.Context
}

func newTLSHandlers(desc *providerv1.DescribeResponse) *tlsHandlers {
	return &tlsHandlers{ref: &referenceHandlers{desc: desc, staged: map[string][]byte{"result-1": []byte(`{"evidence":"staged"}`)}},
		started: make(chan struct{}, 4), blocked: make(chan context.Context, 4)}
}

func (h *tlsHandlers) Collect(ctx context.Context, req *providerv1.CollectRequest) (*providerv1.ResultReference, error) {
	h.collects.Add(1)
	h.mu.Lock()
	h.inventory = slicesClone(req.GetInventory())
	h.mu.Unlock()
	if h.block {
		h.started <- struct{}{}
		<-ctx.Done()
		h.blocked <- ctx
		return nil, ctx.Err()
	}
	return h.ref.Collect(ctx, req)
}

func (h *tlsHandlers) lastInventory() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.inventory
}

func slicesClone(b []byte) []byte { return append([]byte(nil), b...) }

func (h *tlsHandlers) Result(ctx context.Context, id string) (*providerv1.ResultReference, []byte, error) {
	return h.ref.Result(ctx, id)
}

func (h *tlsHandlers) Release(context.Context, string) error { return nil }

func (h *tlsHandlers) Evaluate(context.Context, *providerv1.EvaluateStart, []byte) (*Evaluation, error) {
	h.evaluations.Add(1)
	return &Evaluation{Observations: []*providerv1.Observation{attributable("subject-a")}}, nil
}

func tlsDescription() *providerv1.DescribeResponse {
	d := testDescription()
	d.Limits = &providerv1.Limits{MaxChunkBytes: 1024}
	return d
}

// tlsServer is a provider's grpc.Server on loopback. calls counts the
// calls that passed the transport's checks; ended receives each stream
// handler's result.
type tlsServer struct {
	addr  string
	srv   *grpc.Server
	calls atomic.Int64
	ended chan error
	mu    sync.Mutex
	peers [][]string
}

func serveTLS(t *testing.T, m *MutualTLS, limits TransportLimits, impl providerv1.AssessmentProviderServer) *tlsServer {
	t.Helper()
	opts, err := ServerOptions(m, limits)
	if err != nil {
		t.Fatal(err)
	}
	s := &tlsServer{ended: make(chan error, 16)}
	record := func(ctx context.Context) {
		s.calls.Add(1)
		if p, ok := peer.FromContext(ctx); ok {
			if info, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(info.State.PeerCertificates) > 0 {
				s.mu.Lock()
				s.peers = append(s.peers, info.State.PeerCertificates[0].DNSNames)
				s.mu.Unlock()
			}
		}
	}
	opts = append(opts,
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			record(ctx)
			return handler(ctx, req)
		}),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			record(ss.Context())
			err := handler(srv, ss)
			s.ended <- err
			return err
		}))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.addr = lis.Addr().String()
	s.srv = grpc.NewServer(opts...)
	providerv1.RegisterAssessmentProviderServer(s.srv, impl)
	go func() { _ = s.srv.Serve(lis) }()
	t.Cleanup(s.srv.Stop)
	return s
}

func dialTLS(t *testing.T, m *MutualTLS, addr string, limits TransportLimits, extra ...grpc.DialOption) *grpc.ClientConn {
	t.Helper()
	opts, err := DialOptions(m, limits)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient("passthrough:///"+addr, append(opts, extra...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func timeout(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// fixture is a provider and a host with valid material from one CA.
type fixture struct {
	t                    *testing.T
	ca                   *testCA
	serverDir, clientDir *tlsDir
	serverTLS, clientTLS *MutualTLS
	h                    *tlsHandlers
	kit                  *Server
	srv                  *tlsServer
}

func newFixture(t *testing.T, limits TransportLimits, setup ...func(*fixture)) *fixture {
	t.Helper()
	f := &fixture{t: t, ca: newCA(t)}
	f.serverDir = newTLSDir(t, f.ca.issue(t, serverLeaf()), f.ca.pem)
	f.clientDir = newTLSDir(t, f.ca.issue(t, clientLeaf()), f.ca.pem)
	var err error
	if f.serverTLS, err = NewServerTLS(f.serverDir.files, []string{testClientName}); err != nil {
		t.Fatal(err)
	}
	if f.clientTLS, err = NewClientTLS(f.clientDir.files, testServerName); err != nil {
		t.Fatal(err)
	}
	f.h = newTLSHandlers(tlsDescription())
	for _, s := range setup {
		s(f)
	}
	if f.kit, err = NewServer(tlsDescription(), Handlers{Collector: f.h, Results: f.h, Evaluator: f.h}); err != nil {
		t.Fatal(err)
	}
	if limits.Protocol == nil {
		limits.Protocol = f.kit.Limits()
	}
	f.srv = serveTLS(t, f.serverTLS, limits, f.kit)
	return f
}

func (f *fixture) dial(limits TransportLimits, extra ...grpc.DialOption) *grpc.ClientConn {
	return dialTLS(f.t, f.clientTLS, f.srv.addr, limits, extra...)
}

func (f *fixture) client(conn *grpc.ClientConn) *Client {
	c, err := NewClient(conn, testWant, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

// describePeer describes the endpoint and returns the server leaf the
// connection authenticated.
func describePeer(ctx context.Context, conn *grpc.ClientConn) (*x509.Certificate, error) {
	var p peer.Peer
	if _, err := providerv1.NewAssessmentProviderClient(conn).Describe(ctx, &providerv1.DescribeRequest{Header: testWant.Header()}, grpc.Peer(&p)); err != nil {
		return nil, err
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return nil, errors.New("no TLS peer")
	}
	if info.State.Version != tls.VersionTLS13 {
		return nil, errors.New("not TLS 1.3")
	}
	return info.State.PeerCertificates[0], nil
}

// eventually retries fn until it succeeds, resetting the connection
// backoff between attempts.
func eventually(t *testing.T, conn *grpc.ClientConn, within time.Duration, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		err := fn()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("still failing after %s: %v", within, err)
		}
		if conn != nil {
			conn.ResetConnectBackoff()
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func wantCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("got %v (code %s), want code %s", err, status.Code(err), code)
	}
}

func canaryCollect() *providerv1.CollectRequest {
	return &providerv1.CollectRequest{Header: testWant.Header(), Scope: testScope, Inventory: []byte(`{"marker":"` + canary + `"}`),
		PayloadVersion: testWant.PayloadVersion, Deadline: timestamppb.New(testAt.Add(time.Minute))}
}

func TestMutualTLSServesAuthorizedPeers(t *testing.T) {
	f := newFixture(t, TransportLimits{})
	conn := f.dial(TransportLimits{})
	leaf, err := describePeer(timeout(t, 5*time.Second), conn)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.DNSNames[0] != testServerName {
		t.Fatalf("server presented %v", leaf.DNSNames)
	}
	c := f.client(conn)
	ctx := timeout(t, 5*time.Second)
	ref, err := c.Collect(ctx, testScope, []byte(`{"marker":"`+canary+`"}`), testAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(f.h.lastInventory(), []byte(canary)) {
		t.Fatal("the authorized provider did not receive the request")
	}
	data, err := c.ReadResult(ctx, ref)
	if err != nil || string(data) != `{"evidence":"staged"}` {
		t.Fatalf("read %q: %v", data, err)
	}
	ev, err := c.Evaluate(ctx, EvaluateInput{PayloadVersion: 3, EvaluatorVersion: 5, Payload: data, At: testAt, Scope: testScope})
	if err != nil || len(ev.Observations) != 1 {
		t.Fatalf("evaluate: %v, %v", ev, err)
	}
	f.srv.mu.Lock()
	defer f.srv.mu.Unlock()
	for _, names := range f.srv.peers {
		if len(names) != 1 || names[0] != testClientName {
			t.Fatalf("provider served client %v", names)
		}
	}
}

// impostor is a TLS endpoint that records what a client sends it: the raw
// bytes, any client certificate and any application data. Without a
// certificate it is a plaintext endpoint that answers with HTTP.
type impostor struct {
	lis         net.Listener
	wg          sync.WaitGroup
	once        sync.Once
	clientCerts atomic.Int64
	handshakes  atomic.Int64
	appBytes    atomic.Int64
	mu          sync.Mutex
	received    bytes.Buffer
}

type recordingConn struct {
	net.Conn
	imp *impostor
}

func (c recordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.imp.mu.Lock()
	c.imp.received.Write(b[:n])
	c.imp.mu.Unlock()
	return n, err
}

func startImpostor(t *testing.T, cert *tls.Certificate, maxVersion uint16) *impostor {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	imp := &impostor{lis: lis}
	var cfg *tls.Config
	if cert != nil {
		cfg = &tls.Config{Certificates: []tls.Certificate{*cert}, ClientAuth: tls.RequestClientCert, NextProtos: []string{"h2"},
			MinVersion: tls.VersionTLS12, MaxVersion: maxVersion,
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) > 0 {
					imp.clientCerts.Add(1)
				}
				return nil
			}}
	}
	imp.wg.Add(1)
	go func() {
		defer imp.wg.Done()
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			imp.wg.Add(1)
			go func() {
				defer imp.wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				rec := recordingConn{Conn: c, imp: imp}
				if cfg == nil {
					buf := make([]byte, 4096)
					_, _ = rec.Read(buf)
					_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
					return
				}
				tc := tls.Server(rec, cfg)
				if tc.Handshake() == nil {
					imp.handshakes.Add(1)
					n, _ := io.Copy(io.Discard, tc)
					imp.appBytes.Add(n)
				}
			}()
		}
	}()
	t.Cleanup(imp.stop)
	return imp
}

func (imp *impostor) stop() {
	imp.once.Do(func() { _ = imp.lis.Close() })
	imp.wg.Wait()
}

func (imp *impostor) bytes() []byte {
	imp.mu.Lock()
	defer imp.mu.Unlock()
	return bytes.Clone(imp.received.Bytes())
}

func TestClientSendsNothingToUnauthorizedServers(t *testing.T) {
	ca := newCA(t)
	client := ca.issue(t, clientLeaf())
	now := time.Now()
	expiredCA := newCA(t, now.Add(-2*time.Hour), now.Add(-time.Minute))
	cases := []struct {
		name   string
		trust  *testCA
		issuer *testCA
		leaf   leafSpec
	}{
		{"wrong name", ca, ca, serverLeaf("other-provider.providers.svc")},
		{"wildcard name", ca, ca, serverLeaf("*.providers.svc")},
		{"additional names only", ca, ca, serverLeaf("example-reporting", "example-reporting.providers")},
		{"untrusted CA", ca, newCA(t), serverLeaf()},
		{"expired leaf", ca, ca, serverLeaf().valid(now.Add(-2*time.Hour), now.Add(-time.Minute))},
		{"not yet valid leaf", ca, ca, serverLeaf().valid(now.Add(time.Hour), now.Add(2*time.Hour))},
		{"client usage only", ca, ca, clientLeaf(testServerName)},
		{"expired trust anchor", expiredCA, expiredCA, serverLeaf()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientTLS, err := NewClientTLS(newTLSDir(t, client, tc.trust.pem).files, testServerName)
			if err != nil {
				t.Fatal(err)
			}
			server := tc.issuer.issue(t, tc.leaf).tlsCertificate(t)
			imp := startImpostor(t, &server, tls.VersionTLS13)
			conn := dialTLS(t, clientTLS, imp.lis.Addr().String(), TransportLimits{})
			_, err = providerv1.NewAssessmentProviderClient(conn).Collect(timeout(t, 5*time.Second), canaryCollect())
			wantCode(t, err, codes.Unavailable)
			_ = conn.Close()
			imp.stop()
			assertNothingSent(t, imp, client.leaf)
		})
	}
}

func assertNothingSent(t *testing.T, imp *impostor, client *x509.Certificate) {
	t.Helper()
	raw := imp.bytes()
	switch {
	case len(raw) == 0:
		t.Fatal("the client never connected")
	case imp.handshakes.Load() != 0 || imp.clientCerts.Load() != 0 || imp.appBytes.Load() != 0:
		t.Fatalf("impostor completed %d handshakes, received %d client certificates and %d application bytes",
			imp.handshakes.Load(), imp.clientCerts.Load(), imp.appBytes.Load())
	case bytes.Contains(raw, []byte(canary)), bytes.Contains(raw, client.Raw), bytes.Contains(raw, []byte("konstapel.provider.v1")):
		t.Fatal("the client sent its payload, certificate or call to an unauthorized server")
	case raw[0] != 0x16 || raw[1] != 0x03:
		t.Fatalf("the client's first bytes %x are not a TLS handshake record", raw[:2])
	}
}

func TestClientSendsNothingToPlaintextOrLegacyServers(t *testing.T) {
	ca := newCA(t)
	client := ca.issue(t, clientLeaf())
	clientTLS, err := NewClientTLS(newTLSDir(t, client, ca.pem).files, testServerName)
	if err != nil {
		t.Fatal(err)
	}
	server := ca.issue(t, serverLeaf()).tlsCertificate(t)
	for name, imp := range map[string]*impostor{
		"plaintext": startImpostor(t, nil, 0),
		"TLS 1.2":   startImpostor(t, &server, tls.VersionTLS12),
	} {
		t.Run(name, func(t *testing.T) {
			conn := dialTLS(t, clientTLS, imp.lis.Addr().String(), TransportLimits{})
			_, err := providerv1.NewAssessmentProviderClient(conn).Collect(timeout(t, 5*time.Second), canaryCollect())
			wantCode(t, err, codes.Unavailable)
			_ = conn.Close()
			imp.stop()
			assertNothingSent(t, imp, client.leaf)
		})
	}
}

// rawClient dials with plain TLS, presenting any certificate: a caller
// that does not use the kit.
func rawClient(t *testing.T, addr string, roots *x509.CertPool, certs ...tls.Certificate) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: testServerName, RootCAs: roots, Certificates: certs})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestProviderServesNoUnauthorizedClient(t *testing.T) {
	now := time.Now()
	expiredCA := newCA(t, now.Add(-2*time.Hour), now.Add(-time.Minute))
	cases := []struct {
		name   string
		issuer func(*fixture) *testCA
		leaf   *leafSpec
	}{
		{"wrong name", nil, &leafSpec{names: []string{"intruder.konstapel-system.svc"}, usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}},
		{"wildcard name", nil, &leafSpec{names: []string{"*.konstapel-system.svc"}, usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}},
		{"untrusted CA", func(*fixture) *testCA { return newCA(t) }, nil},
		{"expired leaf", nil, ptr(clientLeaf().valid(now.Add(-2*time.Hour), now.Add(-time.Minute)))},
		{"not yet valid leaf", nil, ptr(clientLeaf().valid(now.Add(time.Hour), now.Add(2*time.Hour)))},
		{"server usage only", nil, ptr(serverLeaf(testClientName))},
		{"no certificate", nil, &leafSpec{}},
		{"expired trust anchor", func(f *fixture) *testCA {
			f.serverDir.writeFile(f.serverDir.files.Trust, expiredCA.pem)
			if err := f.serverTLS.Reload(); err != nil {
				t.Fatal(err)
			}
			return expiredCA
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, TransportLimits{})
			issuer := f.ca
			if tc.issuer != nil {
				issuer = tc.issuer(f)
			}
			spec := clientLeaf()
			if tc.leaf != nil {
				spec = *tc.leaf
			}
			var certs []tls.Certificate
			var leaf *x509.Certificate
			if len(spec.names) > 0 {
				i := issuer.issue(t, spec)
				certs, leaf = []tls.Certificate{i.tlsCertificate(t)}, i.leaf
			}
			roots := x509.NewCertPool()
			roots.AddCert(f.ca.cert)
			wire := startRecordingProxy(t, f.srv.addr)
			conn := rawClient(t, wire.addr, roots, certs...)
			_, err := providerv1.NewAssessmentProviderClient(conn).Collect(timeout(t, 5*time.Second), canaryCollect())
			wantCode(t, err, codes.Unavailable)
			if n := f.srv.calls.Load(); n != 0 || f.h.collects.Load() != 0 {
				t.Fatalf("%d calls reached the provider", n)
			}
			_ = conn.Close()
			wire.assertOpaque(t, leaf)
		})
	}
}

func ptr[T any](v T) *T { return &v }

// recordingProxy forwards loopback connections and records what the client
// sends on the wire.
type recordingProxy struct {
	addr string
	lis  net.Listener
	wg   sync.WaitGroup
	mu   sync.Mutex
	sent bytes.Buffer
}

func startRecordingProxy(t *testing.T, target string) *recordingProxy {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &recordingProxy{addr: lis.Addr().String(), lis: lis}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			s, err := net.Dial("tcp", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			p.wg.Add(2)
			go func() {
				defer p.wg.Done()
				_, _ = io.Copy(io.MultiWriter(s, p), c)
				_ = s.Close()
			}()
			go func() {
				defer p.wg.Done()
				_, _ = io.Copy(c, s)
				_ = c.Close()
			}()
		}
	}()
	t.Cleanup(p.stop)
	return p
}

func (p *recordingProxy) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sent.Write(b)
}

func (p *recordingProxy) stop() {
	_ = p.lis.Close()
	p.wg.Wait()
}

// assertOpaque checks that no request payload, call, identity name or
// certificate appeared in plaintext on the wire.
func (p *recordingProxy) assertOpaque(t *testing.T, certs ...*x509.Certificate) {
	t.Helper()
	p.stop()
	p.mu.Lock()
	sent := bytes.Clone(p.sent.Bytes())
	p.mu.Unlock()
	if len(sent) == 0 {
		t.Fatal("nothing crossed the wire")
	}
	for _, plain := range [][]byte{[]byte(canary), []byte("konstapel.provider.v1"), []byte(testClientName)} {
		if bytes.Contains(sent, plain) {
			t.Fatalf("%q crossed the wire in plaintext", plain)
		}
	}
	for _, c := range certs {
		if c != nil && bytes.Contains(sent, c.Raw) {
			t.Fatal("a certificate crossed the wire in plaintext")
		}
	}
}

func TestAuthorizedTrafficIsOpaqueOnTheWire(t *testing.T) {
	f := newFixture(t, TransportLimits{})
	wire := startRecordingProxy(t, f.srv.addr)
	conn := dialTLS(t, f.clientTLS, wire.addr, TransportLimits{})
	if _, err := providerv1.NewAssessmentProviderClient(conn).Collect(timeout(t, 5*time.Second), canaryCollect()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(f.h.lastInventory(), []byte(canary)) {
		t.Fatal("the provider did not receive the request")
	}
	_ = conn.Close()
	wire.assertOpaque(t, f.clientTLS.current().cert.Leaf)
}

func TestProviderRequiresTLS13(t *testing.T) {
	f := newFixture(t, TransportLimits{})
	client := f.ca.issue(t, clientLeaf()).tlsCertificate(t)
	roots := x509.NewCertPool()
	roots.AddCert(f.ca.cert)
	conn, err := tls.Dial("tcp", f.srv.addr, &tls.Config{ServerName: testServerName, RootCAs: roots, Certificates: []tls.Certificate{client},
		MaxVersion: tls.VersionTLS12, NextProtos: []string{"h2"}})
	if err == nil {
		_ = conn.Close()
		t.Fatal("a TLS 1.2 handshake succeeded")
	}
	if f.srv.calls.Load() != 0 {
		t.Fatal("a call reached the provider")
	}
}

func rotateLeaf(t *testing.T, d *tlsDir, i issued, trust []byte) {
	t.Helper()
	d.write(i, trust)
}

func TestRotatedCertificateIsServedWithoutRestart(t *testing.T) {
	f := newFixture(t, TransportLimits{})
	old := f.dial(TransportLimits{})
	first, err := describePeer(timeout(t, 5*time.Second), old)
	if err != nil {
		t.Fatal(err)
	}
	next := f.ca.issue(t, serverLeaf())
	rotateLeaf(t, f.serverDir, next, nil)
	if err := f.serverTLS.Reload(); err != nil {
		t.Fatal(err)
	}
	// The established connection stays: its certificate is still valid.
	same, err := describePeer(timeout(t, 5*time.Second), old)
	if err != nil || same.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatalf("established connection: %v, %v", same, err)
	}
	// A new connection gets the rotated certificate from the same server.
	rotated, err := describePeer(timeout(t, 5*time.Second), f.dial(TransportLimits{}))
	if err != nil || rotated.SerialNumber.Cmp(next.leaf.SerialNumber) != 0 {
		t.Fatalf("new connection: %v, %v", rotated, err)
	}
}

func TestWatchPicksUpRotation(t *testing.T) {
	f := newFixture(t, TransportLimits{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.serverTLS.Watch(ctx, 20*time.Millisecond, nil); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	next := f.ca.issue(t, serverLeaf())
	rotateLeaf(t, f.serverDir, next, nil)
	eventually(t, nil, 5*time.Second, func() error {
		conn := f.dial(TransportLimits{})
		defer conn.Close()
		leaf, err := describePeer(timeout(t, 5*time.Second), conn)
		if err == nil && leaf.SerialNumber.Cmp(next.leaf.SerialNumber) != 0 {
			err = errors.New("old certificate")
		}
		return err
	})
}

func TestRotatedOutServerTrustClosesConnections(t *testing.T) {
	f := newFixture(t, TransportLimits{})
	conn := f.dial(TransportLimits{})
	if _, err := describePeer(timeout(t, 5*time.Second), conn); err != nil {
		t.Fatal(err)
	}
	calls := f.srv.calls.Load()
	// The host now trusts only a new CA; the provider still presents the
	// old CA's certificate.
	ca2 := newCA(t)
	f.clientDir.writeFile(f.clientDir.files.Trust, ca2.pem)
	if err := f.clientTLS.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := describePeer(timeout(t, 5*time.Second), conn); status.Code(err) != codes.Unavailable {
		t.Fatalf("call after the trust rotation: %v", err)
	}
	if f.srv.calls.Load() != calls {
		t.Fatal("a call reached the provider under the rotated-out trust")
	}
	// Once the provider rotates to the new CA, the same connection
	// recovers without a restart.
	rotateLeaf(t, f.serverDir, ca2.issue(t, serverLeaf()), nil)
	if err := f.serverTLS.Reload(); err != nil {
		t.Fatal(err)
	}
	f.serverDir.writeFile(f.serverDir.files.Trust, f.ca.pem)
	eventually(t, conn, 10*time.Second, func() error {
		_, err := describePeer(timeout(t, 5*time.Second), conn)
		return err
	})
}

func TestRotatedOutClientTrustClosesConnectionsAndCallsInFlight(t *testing.T) {
	f := newFixture(t, TransportLimits{}, func(f *fixture) { f.h.block = true })
	conn := f.dial(TransportLimits{})
	inflight := make(chan error, 1)
	go func() {
		_, err := providerv1.NewAssessmentProviderClient(conn).Collect(timeout(t, 30*time.Second), canaryCollect())
		inflight <- err
	}()
	<-f.h.started
	calls := f.srv.calls.Load()
	// The provider now trusts only a new CA; the host still presents the
	// old CA's certificate.
	ca2 := newCA(t)
	f.serverDir.writeFile(f.serverDir.files.Trust, ca2.pem)
	if err := f.serverTLS.Reload(); err != nil {
		t.Fatal(err)
	}
	select {
	case ctx := <-f.h.blocked:
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("in-flight handler context: %v", ctx.Err())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the in-flight call of the rotated-out client kept running")
	}
	wantCode(t, <-inflight, codes.Unavailable)
	if _, err := describePeer(timeout(t, 5*time.Second), conn); status.Code(err) != codes.Unavailable {
		t.Fatalf("call after the trust rotation: %v", err)
	}
	if f.srv.calls.Load() != calls {
		t.Fatal("a call of the rotated-out client reached the provider")
	}
	rotateLeaf(t, f.clientDir, ca2.issue(t, clientLeaf()), nil)
	if err := f.clientTLS.Reload(); err != nil {
		t.Fatal(err)
	}
	eventually(t, conn, 10*time.Second, func() error {
		_, err := describePeer(timeout(t, 5*time.Second), conn)
		return err
	})
}

func TestRejectedRotationKeepsTheLastValidMaterial(t *testing.T) {
	f := newFixture(t, TransportLimits{})
	first, err := describePeer(timeout(t, 5*time.Second), f.dial(TransportLimits{}))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	other := newCA(t)
	valid := f.ca.issue(t, serverLeaf())
	rotations := map[string]func(){
		"malformed certificate": func() { f.serverDir.writeFile(f.serverDir.files.Certificate, []byte("not a certificate")) },
		"expired certificate": func() {
			rotateLeaf(t, f.serverDir, f.ca.issue(t, serverLeaf().valid(now.Add(-2*time.Hour), now.Add(-time.Minute))), nil)
		},
		"mismatched key": func() { f.serverDir.writeFile(f.serverDir.files.Key, f.ca.issue(t, serverLeaf()).key) },
		"key in trust": func() {
			rotateLeaf(t, f.serverDir, valid, append(bytes.Clone(other.pem), valid.key...))
		},
		"missing trust": func() {
			if err := os.Remove(f.serverDir.files.Trust); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, rotate := range rotations {
		t.Run(name, func(t *testing.T) {
			rotate()
			err := f.serverTLS.Reload()
			if err == nil || f.serverTLS.Ready() == nil {
				t.Fatalf("rotation accepted: %v", err)
			}
			if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), string(valid.key[40:80])) {
				t.Fatal("the error shows key material")
			}
			leaf, err := describePeer(timeout(t, 5*time.Second), f.dial(TransportLimits{}))
			if err != nil || leaf.SerialNumber.Cmp(first.SerialNumber) != 0 {
				t.Fatalf("after a rejected rotation the server presents %v: %v", leaf, err)
			}
			rotateLeaf(t, f.serverDir, issued{cert: pemOf(t, first), key: f.serverTLS.currentKey(t)}, f.ca.pem)
		})
	}
	rotateLeaf(t, f.serverDir, valid, f.ca.pem)
	if err := f.serverTLS.Reload(); err != nil || f.serverTLS.Ready() != nil {
		t.Fatalf("valid rotation: %v, ready %v", err, f.serverTLS.Ready())
	}
}

func pemOf(t *testing.T, c *x509.Certificate) []byte {
	t.Helper()
	return pemBlock("CERTIFICATE", c.Raw)
}

// currentKey returns the PEM key of the current material, to restore it.
func (m *MutualTLS) currentKey(t *testing.T) []byte {
	t.Helper()
	return bytes.Clone(m.current().raw[1])
}

func TestExpiringPeersAreDisconnected(t *testing.T) {
	expiring := func() leafSpec {
		end := time.Now().Truncate(time.Second).Add(3 * time.Second)
		return leafSpec{notBefore: time.Now().Add(-time.Hour), notAfter: end}
	}
	t.Run("client", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, TransportLimits{}, func(f *fixture) {
			l := clientLeaf().valid(expiring().notBefore, expiring().notAfter)
			rotateLeaf(t, f.clientDir, f.ca.issue(t, l), nil)
			if err := f.clientTLS.Reload(); err != nil {
				t.Fatal(err)
			}
		})
		conn := f.dial(TransportLimits{})
		if _, err := describePeer(timeout(t, 5*time.Second), conn); err != nil {
			t.Fatal(err)
		}
		calls := f.srv.calls.Load()
		time.Sleep(time.Until(f.clientTLS.current().cert.Leaf.NotAfter) + 500*time.Millisecond)
		if _, err := describePeer(timeout(t, 5*time.Second), conn); status.Code(err) != codes.Unavailable {
			t.Fatalf("call with an expired client certificate: %v", err)
		}
		if f.srv.calls.Load() != calls {
			t.Fatal("a call with an expired client certificate reached the provider")
		}
	})
	t.Run("server", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, TransportLimits{}, func(f *fixture) {
			l := serverLeaf().valid(expiring().notBefore, expiring().notAfter)
			rotateLeaf(t, f.serverDir, f.ca.issue(t, l), nil)
			if err := f.serverTLS.Reload(); err != nil {
				t.Fatal(err)
			}
		})
		conn := f.dial(TransportLimits{})
		if _, err := describePeer(timeout(t, 5*time.Second), conn); err != nil {
			t.Fatal(err)
		}
		calls := f.srv.calls.Load()
		time.Sleep(time.Until(f.serverTLS.current().cert.Leaf.NotAfter) + 500*time.Millisecond)
		if f.serverTLS.Ready() == nil {
			t.Fatal("an expired certificate is ready")
		}
		if _, err := describePeer(timeout(t, 5*time.Second), conn); status.Code(err) != codes.Unavailable {
			t.Fatalf("call to a server with an expired certificate: %v", err)
		}
		if f.srv.calls.Load() != calls {
			t.Fatal("a call reached a server whose certificate expired")
		}
	})
}

// bigProvider answers with messages and streams beyond the client's
// bounds.
type bigProvider struct {
	providerv1.UnimplementedAssessmentProviderServer
	describeBytes int
	chunks        int
	streamErr     chan error
}

func (b *bigProvider) Describe(context.Context, *providerv1.DescribeRequest) (*providerv1.DescribeResponse, error) {
	d := tlsDescription()
	d.Checks[0].ParameterSchema = bytes.Repeat([]byte(" "), b.describeBytes)
	return d, nil
}

func (b *bigProvider) ReadResult(_ *providerv1.ReadResultRequest, s grpc.ServerStreamingServer[providerv1.ReadResultResponse]) error {
	var err error
	for i := 0; i < b.chunks && err == nil; i++ {
		err = s.Send(&providerv1.ReadResultResponse{Offset: uint64(i * 1024), Data: bytes.Repeat([]byte("x"), 1024)})
	}
	if err == nil {
		<-s.Context().Done()
		err = s.Context().Err()
	}
	b.streamErr <- err
	return err
}

func TestTransportBoundsMessages(t *testing.T) {
	chunks := &providerv1.Limits{MaxChunkBytes: 1024}
	small := TransportLimits{MaxMessageBytes: 64 << 10, Protocol: chunks}
	large := TransportLimits{MaxMessageBytes: 2 << 20}
	big := []byte(`{"pad":"` + strings.Repeat("x", 100<<10) + `"}`)
	t.Run("oversized request reaches no handler", func(t *testing.T) {
		f := newFixture(t, small)
		conn := f.dial(large)
		req := canaryCollect()
		req.Inventory = big
		_, err := providerv1.NewAssessmentProviderClient(conn).Collect(timeout(t, 5*time.Second), req)
		wantCode(t, err, codes.ResourceExhausted)
		if f.srv.calls.Load() != 0 || f.h.collects.Load() != 0 {
			t.Fatal("an oversized request reached the provider")
		}
	})
	t.Run("client refuses to send an oversized request", func(t *testing.T) {
		f := newFixture(t, TransportLimits{})
		req := canaryCollect()
		req.Inventory = big
		_, err := providerv1.NewAssessmentProviderClient(f.dial(small)).Collect(timeout(t, 5*time.Second), req)
		wantCode(t, err, codes.ResourceExhausted)
		if f.srv.calls.Load() != 0 {
			t.Fatal("the client sent an oversized request")
		}
	})
	t.Run("oversized response", func(t *testing.T) {
		ca := newCA(t)
		serverTLS, _ := NewServerTLS(newTLSDir(t, ca.issue(t, serverLeaf()), ca.pem).files, []string{testClientName})
		clientTLS, _ := NewClientTLS(newTLSDir(t, ca.issue(t, clientLeaf()), ca.pem).files, testServerName)
		srv := serveTLS(t, serverTLS, large, &bigProvider{describeBytes: 100 << 10})
		_, err := describePeer(timeout(t, 5*time.Second), dialTLS(t, clientTLS, srv.addr, small))
		wantCode(t, err, codes.ResourceExhausted)
	})
}

func TestTransportBoundsStreamTotals(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		ca := newCA(t)
		serverTLS, err := NewServerTLS(newTLSDir(t, ca.issue(t, serverLeaf()), ca.pem).files, []string{testClientName})
		if err != nil {
			t.Fatal(err)
		}
		clientTLS, err := NewClientTLS(newTLSDir(t, ca.issue(t, clientLeaf()), ca.pem).files, testServerName)
		if err != nil {
			t.Fatal(err)
		}
		b := &bigProvider{chunks: 64, streamErr: make(chan error, 1)}
		srv := serveTLS(t, serverTLS, TransportLimits{}, b)
		conn := dialTLS(t, clientTLS, srv.addr, TransportLimits{MaxStreamBytes: 16 << 10})
		stream, err := providerv1.NewAssessmentProviderClient(conn).ReadResult(timeout(t, 10*time.Second),
			&providerv1.ReadResultRequest{Header: testWant.Header(), ResultId: "result-1"})
		if err != nil {
			t.Fatal(err)
		}
		received := 0
		for {
			msg, err := stream.Recv()
			if err != nil {
				wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED)
				break
			}
			received += len(msg.GetData())
		}
		if received > 16<<10 {
			t.Fatalf("received %d bytes beyond the 16 KiB stream bound", received)
		}
		// Exceeding the bound cancels the call at the provider.
		select {
		case err := <-b.streamErr:
			if status.Code(err) != codes.Canceled && !errors.Is(err, context.Canceled) {
				t.Fatalf("provider stream ended with %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the provider kept streaming after the client's bound")
		}
	})
	t.Run("server", func(t *testing.T) {
		f := newFixture(t, TransportLimits{MaxStreamBytes: 16 << 10})
		payload := []byte(`{"pad":"` + strings.Repeat("x", 64<<10) + `"}`)
		_, err := f.client(f.dial(TransportLimits{})).Evaluate(timeout(t, 10*time.Second),
			EvaluateInput{PayloadVersion: 3, EvaluatorVersion: 5, Payload: payload, At: testAt, Scope: testScope})
		wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED)
		if f.h.evaluations.Load() != 0 {
			t.Fatal("an over-bound payload was evaluated")
		}
	})
}

func TestCallsNeedDeadlines(t *testing.T) {
	f := newFixture(t, TransportLimits{})
	t.Run("client", func(t *testing.T) {
		// A server that would serve calls without a deadline sees none.
		var calls atomic.Int64
		count := func(context.Context, any, *grpc.UnaryServerInfo, grpc.UnaryHandler) (any, error) {
			calls.Add(1)
			return nil, status.Error(codes.Internal, "served")
		}
		countStream := func(any, grpc.ServerStream, *grpc.StreamServerInfo, grpc.StreamHandler) error {
			calls.Add(1)
			return status.Error(codes.Internal, "served")
		}
		srv := grpc.NewServer(grpc.Creds(transportCredentials{m: f.serverTLS}), grpc.UnaryInterceptor(count), grpc.StreamInterceptor(countStream))
		providerv1.RegisterAssessmentProviderServer(srv, f.kit)
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.Serve(lis) }()
		defer srv.Stop()
		conn := dialTLS(t, f.clientTLS, lis.Addr().String(), TransportLimits{})
		_, err = f.client(conn).Describe(context.Background())
		wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST)
		_, err = providerv1.NewAssessmentProviderClient(conn).Evaluate(context.Background())
		wantReason(t, err, providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST)
		if calls.Load() != 0 {
			t.Fatal("a call without a deadline was sent")
		}
	})
	t.Run("server", func(t *testing.T) {
		// A caller without the kit's client options sends no deadline.
		conn, err := grpc.NewClient("passthrough:///"+f.srv.addr, grpc.WithTransportCredentials(transportCredentials{m: f.clientTLS}))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, err = providerv1.NewAssessmentProviderClient(conn).Describe(context.Background(), &providerv1.DescribeRequest{Header: testWant.Header()})
		wantReason(t, fromStatus(context.Background(), err), providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST)
		if f.srv.calls.Load() != 0 {
			t.Fatal("a call without a deadline reached the provider")
		}
	})
}

func TestHandshakeTimeoutClosesStalledConnections(t *testing.T) {
	f := newFixture(t, TransportLimits{HandshakeTimeout: 300 * time.Millisecond})
	hello := clientHello(t)
	for name, send := range map[string]func(net.Conn){
		"silent": func(net.Conn) {},
		"trickle": func(c net.Conn) {
			go func() {
				for _, b := range hello {
					if _, err := c.Write([]byte{b}); err != nil {
						return
					}
					time.Sleep(50 * time.Millisecond)
				}
			}()
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := net.Dial("tcp", f.srv.addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			start := time.Now()
			send(c)
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err = io.Copy(io.Discard, c)
			if elapsed := time.Since(start); err != nil || elapsed > 2*time.Second {
				t.Fatalf("connection closed after %s (%v); want the 300ms handshake bound", elapsed, err)
			}
		})
	}
	if f.srv.calls.Load() != 0 {
		t.Fatal("a stalled connection reached the provider")
	}
	t.Run("client", func(t *testing.T) {
		// A server that accepts and never answers holds the host for
		// one handshake bound, not the call's deadline.
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer lis.Close()
		go func() {
			for {
				c, err := lis.Accept()
				if err != nil {
					return
				}
				go func() { _, _ = io.Copy(io.Discard, c) }()
			}
		}()
		conn := dialTLS(t, f.clientTLS, lis.Addr().String(), TransportLimits{HandshakeTimeout: 300 * time.Millisecond})
		start := time.Now()
		_, err = providerv1.NewAssessmentProviderClient(conn).Describe(timeout(t, 30*time.Second), &providerv1.DescribeRequest{Header: testWant.Header()})
		wantCode(t, err, codes.Unavailable)
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("the call waited %s for a silent server", elapsed)
		}
	})
}

// clientHello captures a TLS 1.3 ClientHello's bytes.
func clientHello(t *testing.T) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		_ = tls.Client(b, &tls.Config{ServerName: testServerName, MinVersion: tls.VersionTLS13}).Handshake()
	}()
	buf := make([]byte, 4096)
	_ = a.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := a.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	return buf[:n]
}

func TestStalledStreamEndsAtTheDeadline(t *testing.T) {
	f := newFixture(t, TransportLimits{})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	stream, err := providerv1.NewAssessmentProviderClient(f.dial(TransportLimits{})).Evaluate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"a":1}`)
	if err := stream.Send(&providerv1.EvaluateRequest{Part: &providerv1.EvaluateRequest_Start{Start: &providerv1.EvaluateStart{
		Header: testWant.Header(), EvaluatorVersion: 5, PayloadVersion: 3, PayloadSizeBytes: uint64(len(payload)), PayloadSha256: Digest(payload),
		EvaluationTime: timestamppb.New(testAt), Scope: testScope}}}); err != nil {
		t.Fatal(err)
	}
	// Send nothing more: the provider waits for the payload until the
	// host's deadline ends the call on both sides.
	_, err = stream.Recv()
	wantCode(t, err, codes.DeadlineExceeded)
	select {
	case err := <-f.srv.ended:
		if c := status.Code(err); c != codes.DeadlineExceeded && c != codes.Canceled {
			t.Fatalf("provider stream ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled stream kept the provider's handler running")
	}
	if f.h.evaluations.Load() != 0 {
		t.Fatal("a stalled evaluation was evaluated")
	}
}

func TestCancellationAndDeadlineReachTheHandler(t *testing.T) {
	f := newFixture(t, TransportLimits{}, func(f *fixture) { f.h.block = true })
	c := f.client(f.dial(TransportLimits{}))
	deadline := time.Now().Add(20 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := c.Collect(ctx, testScope, nil, testAt)
		done <- err
	}()
	<-f.h.started
	cancel()
	select {
	case hctx := <-f.h.blocked:
		if !errors.Is(hctx.Err(), context.Canceled) {
			t.Fatalf("handler context ended with %v", hctx.Err())
		}
		got, ok := hctx.Deadline()
		if !ok || got.Sub(deadline).Abs() > time.Second {
			t.Fatalf("handler deadline %s (set %v), host deadline %s", got, ok, deadline)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the host's cancellation did not reach the handler")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("client got %v", err)
	}
}

func TestMutualTLSValidatesMaterial(t *testing.T) {
	ca := newCA(t)
	server := ca.issue(t, serverLeaf())
	client := ca.issue(t, clientLeaf())
	now := time.Now()
	write := func(t *testing.T, cert, key, trust []byte) TLSFiles {
		d := &tlsDir{t: t, files: SecretFiles(t.TempDir())}
		for path, data := range map[string][]byte{d.files.Certificate: cert, d.files.Key: key, d.files.Trust: trust} {
			if data != nil {
				d.writeFile(path, data)
			}
		}
		return d.files
	}
	cases := map[string]struct {
		files  TLSFiles
		server bool
		names  []string
		want   string
	}{
		"missing trust":        {files: write(t, server.cert, server.key, nil), server: true, want: "ca.crt"},
		"key in trust":         {files: write(t, server.cert, server.key, append(bytes.Clone(ca.pem), server.key...)), server: true, want: "private key"},
		"text in trust":        {files: write(t, server.cert, server.key, append([]byte("hello\n"), ca.pem...)), server: true, want: "outside PEM"},
		"other block in trust": {files: write(t, server.cert, server.key, pemBlock("PUBLIC KEY", []byte{1})), server: true, want: `"PUBLIC KEY"`},
		"key in certificate":   {files: write(t, append(bytes.Clone(server.cert), server.key...), server.key, ca.pem), server: true, want: "private key"},
		"mismatched key":       {files: write(t, server.cert, client.key, ca.pem), server: true, want: "key"},
		"oversized trust":      {files: write(t, server.cert, server.key, bytes.Repeat(ca.pem, maxTLSFileBytes/len(ca.pem)+1)), server: true, want: "larger than"},
		"server without usage": {files: write(t, client.cert, client.key, ca.pem), server: true, want: "server authentication"},
		"client without usage": {files: write(t, server.cert, server.key, ca.pem), want: "client authentication"},
		"no authorized client": {files: write(t, server.cert, server.key, ca.pem), server: true, names: []string{}, want: "at least one"},
		"wildcard client":      {files: write(t, server.cert, server.key, ca.pem), server: true, names: []string{"*.svc"}, want: "wildcard"},
		"uppercase client":     {files: write(t, server.cert, server.key, ca.pem), server: true, names: []string{"Konstapel.svc"}, want: "lowercase"},
		"trailing dot client":  {files: write(t, server.cert, server.key, ca.pem), server: true, names: []string{"konstapel.svc."}, want: "lowercase"},
		"repeated client":      {files: write(t, server.cert, server.key, ca.pem), server: true, names: []string{"a.svc", "a.svc"}, want: "unique"},
		"empty server name":    {files: write(t, client.cert, client.key, ca.pem), names: []string{""}, want: "DNS name"},
		"no files":             {files: TLSFiles{}, server: true, want: "trust bundle"},
	}
	expired := ca.issue(t, serverLeaf().valid(now.Add(-2*time.Hour), now.Add(-time.Minute)))
	cases["expired"] = struct {
		files  TLSFiles
		server bool
		names  []string
		want   string
	}{files: write(t, expired.cert, expired.key, ca.pem), server: true, want: "expired"}
	notYet := ca.issue(t, clientLeaf().valid(now.Add(time.Hour), now.Add(2*time.Hour)))
	cases["not yet valid"] = struct {
		files  TLSFiles
		server bool
		names  []string
		want   string
	}{files: write(t, notYet.cert, notYet.key, ca.pem), want: "not valid until"}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var err error
			if tc.server {
				names := tc.names
				if names == nil {
					names = []string{testClientName}
				}
				_, err = NewServerTLS(tc.files, names)
			} else {
				serverName := testServerName
				if tc.names != nil {
					serverName = tc.names[0]
				}
				_, err = NewClientTLS(tc.files, serverName)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "-----") || strings.Contains(err.Error(), string(server.key[40:80])) {
				t.Fatal("the error shows file contents")
			}
		})
	}
	t.Run("roles", func(t *testing.T) {
		s, err := NewServerTLS(write(t, server.cert, server.key, ca.pem), []string{testClientName})
		if err != nil || s.Ready() != nil {
			t.Fatalf("server: %v, ready %v", err, s.Ready())
		}
		c, err := NewClientTLS(write(t, client.cert, client.key, ca.pem), testServerName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ServerOptions(c, TransportLimits{}); err == nil {
			t.Fatal("client mutual TLS served")
		}
		if _, err := DialOptions(s, TransportLimits{}); err == nil {
			t.Fatal("server mutual TLS dialed")
		}
		if _, err := ServerOptions(s, TransportLimits{MaxMessageBytes: 1 << 10}); err == nil {
			t.Fatal("a message bound below 64 KiB was accepted")
		}
		if _, err := ServerOptions(s, TransportLimits{MaxMessageBytes: 64 << 10, Protocol: &providerv1.Limits{MaxChunkBytes: 1 << 20}}); err == nil {
			t.Fatal("a message bound below the chunk bound was accepted")
		}
		if _, err := DialOptions(c, TransportLimits{HandshakeTimeout: -time.Second}); err == nil {
			t.Fatal("a negative handshake timeout was accepted")
		}
	})
}

func TestDefaultStreamBoundCarriesTheProtocolBounds(t *testing.T) {
	for _, p := range []*providerv1.Limits{nil, {MaxChunkBytes: 4}, {MaxResultBytes: 1 << 20, MaxObservations: 100_000}} {
		l, err := TransportLimits{Protocol: p}.resolve()
		if err != nil {
			t.Fatal(err)
		}
		n := NegotiateLimits(p, nil)
		chunks := (n.GetMaxResultBytes() + uint64(n.GetMaxChunkBytes()) - 1) / uint64(n.GetMaxChunkBytes())
		if l.MaxStreamBytes < n.GetMaxResultBytes()+chunks*(chunkEnvelopeBytes+messageFrameBytes) ||
			l.MaxStreamBytes < uint64(n.GetMaxObservations())*observationBytes {
			t.Fatalf("stream bound %d cannot carry %v", l.MaxStreamBytes, n)
		}
	}
	// The observation size bound covers the largest valid observation.
	o := &providerv1.Observation{Subject: strings.Repeat("s", MaxTextBytes), Check: strings.Repeat("c", MaxTextBytes),
		Raw: strings.Repeat("r", MaxTextBytes), State: providerv1.EvidenceState_EVIDENCE_STATE_ATTRIBUTABLE,
		Outcome: providerv1.Outcome_OUTCOME_UNKNOWN, NotApplicable: true, Evaluated: timestamppb.New(testAt)}
	batch := &providerv1.EvaluateResponse{Part: &providerv1.EvaluateResponse_Observations{Observations: &providerv1.ObservationBatch{
		Observations: []*providerv1.Observation{o}}}}
	if proto.Size(batch) > observationBytes || proto.Size(batch) > minMessageBytes {
		t.Fatalf("one observation encodes to %d bytes", proto.Size(batch))
	}
}

func TestEveryCallIsAdmittedAgainstTheCurrentMaterial(t *testing.T) {
	f := newFixture(t, TransportLimits{})
	client := f.ca.issue(t, clientLeaf())
	intruder := f.ca.issue(t, clientLeaf("intruder.konstapel-system.svc"))
	call := func(i issued, withDeadline bool) error {
		ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{i.leaf}}}})
		if withDeadline {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Minute)
			defer cancel()
		}
		_, err := f.serverTLS.admit(ctx, nil)
		return err
	}
	if err := call(client, true); err != nil {
		t.Fatalf("authorized call: %v", err)
	}
	wantCode(t, call(intruder, true), codes.Unauthenticated)
	wantReason(t, fromStatus(context.Background(), call(client, false)), providerv1.ErrorReason_ERROR_REASON_INVALID_REQUEST)
	// An unauthorized caller learns nothing about its request.
	wantCode(t, call(intruder, false), codes.Unauthenticated)
	if _, err := f.serverTLS.admit(context.Background(), nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("call without a peer: %v", err)
	}
	// After a trust rotation the same certificate is no longer admitted,
	// even on a connection established before it.
	f.serverDir.writeFile(f.serverDir.files.Trust, newCA(t).pem)
	if err := f.serverTLS.Reload(); err != nil {
		t.Fatal(err)
	}
	wantCode(t, call(client, true), codes.Unauthenticated)
}

func TestProviderOffersNoSessionResumption(t *testing.T) {
	f := newFixture(t, TransportLimits{})
	client := f.ca.issue(t, clientLeaf()).tlsCertificate(t)
	roots := x509.NewCertPool()
	roots.AddCert(f.ca.cert)
	cfg := &tls.Config{ServerName: testServerName, RootCAs: roots, Certificates: []tls.Certificate{client}, MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"}, ClientSessionCache: tls.NewLRUClientSessionCache(4)}
	for i := range 2 {
		conn, err := tls.Dial("tcp", f.srv.addr, cfg)
		if err != nil {
			t.Fatal(err)
		}
		// Session tickets arrive after the handshake; read until the
		// server's HTTP/2 preface so any ticket is processed.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(make([]byte, 64))
		if conn.ConnectionState().DidResume {
			t.Fatalf("connection %d resumed a session", i+1)
		}
		if _, ok := cfg.ClientSessionCache.Get(testServerName); ok {
			t.Fatal("the provider issued a session ticket")
		}
		_ = conn.Close()
	}
}

// A handshake that completes after a rotation is authorized against the
// rotated material too, so it cannot escape the rotation's sweep.
func TestHandshakeRacingARotationUsesTheNewMaterial(t *testing.T) {
	ca := newCA(t)
	dir := newTLSDir(t, ca.issue(t, clientLeaf()), ca.pem)
	m, err := NewClientTLS(dir.files, testServerName)
	if err != nil {
		t.Fatal(err)
	}
	untrusting := newCA(t).pem
	server := ca.issue(t, serverLeaf()).tlsCertificate(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	rotated := make(chan error, 1)
	go func() {
		c, err := lis.Accept()
		if err != nil {
			rotated <- err
			return
		}
		defer c.Close()
		srv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{server}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"},
			ClientAuth: tls.RequestClientCert, SessionTicketsDisabled: true,
			// The client has taken its material; rotate it mid-handshake.
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				err := os.WriteFile(dir.files.Trust, untrusting, 0o600)
				if err == nil {
					err = m.Reload()
				}
				rotated <- err
				return nil, nil
			}})
		_ = srv.SetDeadline(time.Now().Add(5 * time.Second))
		_ = srv.Handshake()
		_, _ = io.Copy(io.Discard, srv)
	}()
	raw, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := transportCredentials{m: m}.ClientHandshake(timeout(t, 5*time.Second), "", raw)
	if rerr := <-rotated; rerr != nil {
		t.Fatal(rerr)
	}
	if err == nil {
		_ = conn.Close()
		t.Fatal("a connection authorized only by rotated-out trust was kept")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.conns) != 0 {
		t.Fatalf("%d connections are tracked", len(m.conns))
	}
}

func TestRotationUnderConcurrentCalls(t *testing.T) {
	f := newFixture(t, TransportLimits{})
	shared := f.dial(TransportLimits{})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				conn := shared
				if i%2 == 0 {
					conn = f.dial(TransportLimits{})
				}
				if _, err := describePeer(timeout(t, 5*time.Second), conn); err != nil {
					t.Errorf("call during rotation: %v", err)
					return
				}
				if conn != shared {
					_ = conn.Close()
				}
			}
		}()
	}
	for range 20 {
		rotateLeaf(t, f.serverDir, f.ca.issue(t, serverLeaf()), nil)
		rotateLeaf(t, f.clientDir, f.ca.issue(t, clientLeaf()), nil)
		if err := errors.Join(f.serverTLS.Reload(), f.clientTLS.Reload()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
}
