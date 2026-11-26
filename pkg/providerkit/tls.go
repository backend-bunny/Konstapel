package providerkit

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"
)

// DefaultReloadInterval is how often Watch re-reads the mounted TLS files.
// The kubelet updates Secret volumes within about a minute of a rotation, so
// renewed material is used without a restart.
const DefaultReloadInterval = 10 * time.Second

// Bounds of one mounted TLS file.
const (
	maxTLSFileBytes        = 1 << 20
	maxTLSFileCertificates = 512
)

// TLSFiles are the PEM files of one side's mutual TLS material.
type TLSFiles struct {
	// Certificate is this side's certificate chain, leaf first, and
	// nothing else.
	Certificate string
	// Key is the leaf certificate's private key.
	Key string
	// Trust is the CA bundle the peer's certificate must chain to. It holds
	// certificates only.
	Trust string
}

// TLSMaterial is one side's PEM material as one load returns it: the
// certificate chain, leaf first, its private key, and the trust bundle the
// peer's certificate must chain to. Each part is at most 1 MiB.
type TLSMaterial struct {
	Certificate []byte
	Key         []byte
	Trust       []byte
}

// TLSSource supplies one side's material each time a MutualTLS loads it: on
// construction and on every Reload, including Watch's. TLSFiles is the
// mounted-files source. A side whose material does not all come from
// mounted files, such as a host that reads a provider's trust bundle
// through the Kubernetes API, implements its own source.
//
// Material from any source passes exactly the checks of TLSFiles, and a
// rejected or failed load keeps the last valid material in use. An error
// is reported by Reload and Ready and must not contain key material.
type TLSSource interface {
	LoadTLS() (TLSMaterial, error)
}

// LoadTLS reads the three files, each at most 1 MiB.
func (f TLSFiles) LoadTLS() (TLSMaterial, error) {
	var raw [3][]byte
	for i, path := range []string{f.Certificate, f.Key, f.Trust} {
		data, err := readBounded(path)
		if err != nil {
			return TLSMaterial{}, err
		}
		raw[i] = data
	}
	return TLSMaterial{Certificate: raw[0], Key: raw[1], Trust: raw[2]}, nil
}

// SecretFiles are tls.crt, tls.key and ca.crt in dir: a mounted
// kubernetes.io/tls Secret such as cert-manager writes. Its ca.crt is the
// trust for the peer only when one issuer signs both sides; otherwise name
// the peer's CA bundle in TLSFiles.Trust.
func SecretFiles(dir string) TLSFiles {
	return TLSFiles{Certificate: filepath.Join(dir, "tls.crt"), Key: filepath.Join(dir, "tls.key"), Trust: filepath.Join(dir, "ca.crt")}
}

type role int

const (
	roleServer role = iota + 1
	roleClient
)

// peerUsage is the extended key usage the peer of a side must hold, and
// ownUsage the one its own certificate needs.
func (r role) peerUsage() x509.ExtKeyUsage {
	if r == roleServer {
		return x509.ExtKeyUsageClientAuth
	}
	return x509.ExtKeyUsageServerAuth
}

func (r role) ownUsage() x509.ExtKeyUsage {
	if r == roleServer {
		return x509.ExtKeyUsageServerAuth
	}
	return x509.ExtKeyUsageClientAuth
}

// MutualTLS is one side's mutual TLS: its certificate and key, the trust
// bundle its peer must chain to, and the peer names it authorizes. Use a
// server's with ServerOptions and a client's with DialOptions.
//
// A peer is authorized when its certificate chains to the trust bundle, is
// valid now, carries the extended key usage of its role (client or server
// authentication, or none) and names an authorized peer as a DNS subject
// alternative name, compared exactly apart from letter case. Wildcards,
// common names, URIs and IP addresses never match. A client authorizes
// exactly one name, the server name of the provider registration, whatever
// address it connects to; a server authorizes the host identities its
// deployment configures.
//
// The material is reloaded from its files, or its TLSSource, by Reload or
// Watch without a restart. Changed material is used only after it passes
// the checks of the initial load; until then the last valid material stays in use and Ready
// reports the problem, with no insecure fallback. New connections use the
// current material. An established connection whose peer the current
// material no longer authorizes, after a trust rotation or once a
// certificate of its chain expires, is closed at once; its calls fail and
// the client reconnects with the current material.
type MutualTLS struct {
	role   role
	source TLSSource
	peers  []string

	reload sync.Mutex // serializes Reload
	mu     sync.Mutex
	cur    *material
	err    error
	conns  map[*peerConn]struct{}
}

// NewServerTLS loads a provider's material, authorizing clients that name
// one of authorizedClients. It fails when the files are invalid, so a
// server never starts with them.
func NewServerTLS(files TLSFiles, authorizedClients []string) (*MutualTLS, error) {
	if len(authorizedClients) == 0 {
		return nil, errors.New("providerkit: a server authorizes at least one client name")
	}
	return newMutualTLS(roleServer, files, authorizedClients)
}

// NewClientTLS loads a host's material for the provider named serverName.
// It fails when the files are invalid.
func NewClientTLS(files TLSFiles, serverName string) (*MutualTLS, error) {
	return newMutualTLS(roleClient, files, []string{serverName})
}

// NewClientTLSFrom is NewClientTLS with the material loaded from src, for
// a host whose trust bundle is not a mounted file. It fails when the
// material is invalid; every load is checked as NewClientTLS checks files.
func NewClientTLSFrom(src TLSSource, serverName string) (*MutualTLS, error) {
	if src == nil {
		return nil, errors.New("providerkit: mutual TLS needs a material source")
	}
	return newMutualTLS(roleClient, src, []string{serverName})
}

var dnsNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$`)

func newMutualTLS(r role, src TLSSource, peers []string) (*MutualTLS, error) {
	for i, name := range peers {
		if len(name) > 253 || !dnsNamePattern.MatchString(name) || slices.Contains(peers[:i], name) {
			return nil, fmt.Errorf("providerkit: peer name %q must be a unique lowercase DNS name without a wildcard", name)
		}
	}
	if f, ok := src.(TLSFiles); ok && (f.Certificate == "" || f.Key == "" || f.Trust == "") {
		return nil, errors.New("providerkit: mutual TLS needs a certificate, its key and a trust bundle")
	}
	m := &MutualTLS{role: r, source: src, peers: slices.Clone(peers), conns: map[*peerConn]struct{}{}}
	if err := m.Reload(); err != nil {
		return nil, err
	}
	return m, nil
}

// material is one verified load of the files or source.
type material struct {
	raw   [3][]byte
	cert  tls.Certificate
	trust *x509.CertPool
}

func (m *MutualTLS) current() *material {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur
}

// Reload re-reads the files or source. Changed material replaces the current
// material only when it is valid, and then closes every connection whose
// peer it no longer authorizes; otherwise the error is kept for Ready and
// returned.
func (m *MutualTLS) Reload() error {
	m.reload.Lock()
	defer m.reload.Unlock()
	cur := m.current()
	var (
		next *material
		err  error
	)
	// The files are read one at a time, so a Secret update landing between
	// reads can pair an old certificate with a new key: read once more
	// before reporting a failure. A source is given the same second read.
	for range 2 {
		var raw [3][]byte
		if raw, err = m.read(); err != nil {
			continue
		}
		if cur != nil && bytes.Equal(raw[0], cur.raw[0]) && bytes.Equal(raw[1], cur.raw[1]) && bytes.Equal(raw[2], cur.raw[2]) {
			m.mu.Lock()
			m.err = nil
			m.mu.Unlock()
			return nil
		}
		if next, err = m.verify(raw, time.Now()); err == nil {
			break
		}
	}
	if err != nil {
		err = fmt.Errorf("providerkit: mutual TLS material: %w", err)
		m.mu.Lock()
		m.err = err
		m.mu.Unlock()
		return err
	}
	m.mu.Lock()
	m.cur, m.err = next, nil
	conns := make([]*peerConn, 0, len(m.conns))
	for c := range m.conns {
		conns = append(conns, c)
	}
	m.mu.Unlock()
	for _, c := range conns {
		c.recheck()
	}
	return nil
}

// Watch reloads every interval (DefaultReloadInterval when not positive)
// until ctx ends, reporting each rejected reload to onError.
func (m *MutualTLS) Watch(ctx context.Context, interval time.Duration, onError func(error)) {
	if interval <= 0 {
		interval = DefaultReloadInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Reload(); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

// Ready reports whether the material is usable now: the last reload
// succeeded and the current certificate is valid.
func (m *MutualTLS) Ready() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	return validNow(m.cur.cert.Leaf, time.Now(), "certificate")
}

// read loads the material and bounds each part. The parts are copied, so a
// source that reuses its buffers cannot change verified material.
func (m *MutualTLS) read() ([3][]byte, error) {
	mat, err := m.source.LoadTLS()
	if err != nil {
		return [3][]byte{}, err
	}
	raw := [3][]byte{mat.Certificate, mat.Key, mat.Trust}
	for i, what := range []string{"certificate", "key", "trust bundle"} {
		if len(raw[i]) > maxTLSFileBytes {
			return [3][]byte{}, fmt.Errorf("%s is larger than %d bytes", what, maxTLSFileBytes)
		}
		raw[i] = bytes.Clone(raw[i])
	}
	return raw, nil
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxTLSFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxTLSFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxTLSFileBytes)
	}
	return data, nil
}

// verify checks a read of the files or source: a certificate chain and its matching
// key, a leaf valid now with the usage of this side's role, and a trust
// bundle of certificates only. Errors never include file contents.
func (m *MutualTLS) verify(raw [3][]byte, now time.Time) (*material, error) {
	chain, err := parseCertificates(raw[0], "certificate file")
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(raw[0], raw[1])
	if err != nil {
		return nil, fmt.Errorf("certificate and key: %w", err)
	}
	pair.Leaf = chain[0]
	if err := validNow(pair.Leaf, now, "certificate"); err != nil {
		return nil, err
	}
	if !allowsUsage(pair.Leaf, m.role.ownUsage()) {
		return nil, fmt.Errorf("certificate does not allow %s", usageName(m.role.ownUsage()))
	}
	anchors, err := parseCertificates(raw[2], "trust bundle")
	if err != nil {
		return nil, err
	}
	trust := x509.NewCertPool()
	for _, c := range anchors {
		trust.AddCert(c)
	}
	return &material{raw: raw, cert: pair, trust: trust}, nil
}

// parseCertificates parses PEM certificates strictly: only CERTIFICATE
// blocks without headers and nothing but whitespace around them, at least
// one and at most maxTLSFileCertificates. A private key or any other block is
// rejected.
func parseCertificates(data []byte, what string) ([]*x509.Certificate, error) {
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
			return nil, fmt.Errorf("%s contains data outside PEM blocks", what)
		}
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			return nil, fmt.Errorf("%s contains a malformed PEM block", what)
		}
		switch {
		case strings.Contains(block.Type, "PRIVATE KEY"):
			return nil, fmt.Errorf("%s contains a private key; only certificates are accepted", what)
		case block.Type != "CERTIFICATE":
			return nil, fmt.Errorf("%s contains a %q block; only certificates are accepted", what, block.Type)
		case len(block.Headers) > 0:
			return nil, fmt.Errorf("%s has a certificate with PEM headers", what)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s certificate %d does not parse", what, len(certs)+1)
		}
		if certs = append(certs, cert); len(certs) > maxTLSFileCertificates {
			return nil, fmt.Errorf("%s has more than %d certificates", what, maxTLSFileCertificates)
		}
	}
	switch {
	case len(certs) == 0:
		return nil, fmt.Errorf("%s contains no certificate", what)
	case len(certs) != begins:
		return nil, fmt.Errorf("%s contains a malformed PEM block", what)
	}
	return certs, nil
}

func validNow(c *x509.Certificate, now time.Time, what string) error {
	switch {
	case now.Before(c.NotBefore):
		return fmt.Errorf("%s is not valid until %s", what, c.NotBefore.UTC().Format(time.RFC3339))
	case now.After(c.NotAfter):
		return fmt.Errorf("%s expired at %s", what, c.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// allowsUsage follows crypto/x509: a certificate without extended key
// usages allows any.
func allowsUsage(c *x509.Certificate, u x509.ExtKeyUsage) bool {
	if len(c.ExtKeyUsage) == 0 && len(c.UnknownExtKeyUsage) == 0 {
		return true
	}
	return slices.Contains(c.ExtKeyUsage, u) || slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageAny)
}

func usageName(u x509.ExtKeyUsage) string {
	if u == x509.ExtKeyUsageServerAuth {
		return "server authentication"
	}
	return "client authentication"
}

// authorize checks a peer's certificates, leaf first, against mat at now.
// It returns when the authorization ends: when every chain that verified
// has a certificate past its validity.
func (m *MutualTLS) authorize(mat *material, certs []*x509.Certificate, now time.Time) (time.Time, error) {
	if len(certs) == 0 {
		return time.Time{}, errors.New("peer presented no certificate")
	}
	leaf := certs[0]
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: mat.trust, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{m.role.peerUsage()}})
	if err != nil {
		return time.Time{}, fmt.Errorf("peer certificate is not trusted: %w", err)
	}
	if !slices.ContainsFunc(leaf.DNSNames, func(n string) bool {
		return slices.ContainsFunc(m.peers, func(p string) bool { return strings.EqualFold(n, p) })
	}) {
		return time.Time{}, fmt.Errorf("peer certificate names %s, not an authorized peer (%s)", listNames(leaf.DNSNames), strings.Join(m.peers, ", "))
	}
	var ends time.Time
	for _, chain := range chains {
		end := chain[0].NotAfter
		for _, c := range chain[1:] {
			if c.NotAfter.Before(end) {
				end = c.NotAfter
			}
		}
		if end.After(ends) {
			ends = end
		}
	}
	return ends, nil
}

// listNames lists at most four names, each at most 253 bytes.
func listNames(names []string) string {
	if len(names) == 0 {
		return "no DNS name"
	}
	shown := make([]string, 0, 4)
	for _, n := range names[:min(len(names), 4)] {
		shown = append(shown, fmt.Sprintf("%q", n[:min(len(n), 253)]))
	}
	if len(names) > 4 {
		shown = append(shown, fmt.Sprintf("and %d more", len(names)-4))
	}
	return strings.Join(shown, ", ")
}

// handshake performs this side's TLS 1.3 handshake on raw and tracks the
// authenticated connection.
func (m *MutualTLS) handshake(ctx context.Context, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	mat := m.current()
	verify := func(cs tls.ConnectionState) error {
		_, err := m.authorize(mat, cs.PeerCertificates, time.Now())
		return err
	}
	var (
		conn net.Conn
		info credentials.AuthInfo
		err  error
	)
	if m.role == roleServer {
		// Standard verification against the trust bundle, then the same
		// authorization every call repeats. Session tickets are off: a
		// resumed session would skip the trust bundle.
		conn, info, err = credentials.NewTLS(&tls.Config{
			MinVersion:             tls.VersionTLS13,
			Certificates:           []tls.Certificate{mat.cert},
			ClientAuth:             tls.RequireAndVerifyClientCert,
			ClientCAs:              mat.trust,
			SessionTicketsDisabled: true,
			VerifyConnection:       verify,
		}).ServerHandshake(raw)
	} else {
		// The server is verified before the client certificate is sent.
		// The configured name, not the dialed address, is the server name.
		name := m.peers[0]
		conn, info, err = credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: name,
			RootCAs:    mat.trust,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return &mat.cert, nil
			},
			VerifyConnection: verify,
		}).ClientHandshake(ctx, name, raw)
	}
	if err != nil {
		return nil, nil, err
	}
	tlsInfo, ok := info.(credentials.TLSInfo)
	if !ok || tlsInfo.State.Version != tls.VersionTLS13 {
		_ = conn.Close()
		return nil, nil, errors.New("providerkit: connection is not TLS 1.3")
	}
	pc := &peerConn{Conn: conn, m: m, certs: tlsInfo.State.PeerCertificates}
	m.mu.Lock()
	m.conns[pc] = struct{}{}
	m.mu.Unlock()
	// From here on every rotation checks the connection. A rotation during
	// the handshake has already swept: check against the current material
	// now, and schedule the connection's end.
	if !pc.recheck() {
		return nil, nil, errors.New("providerkit: peer is no longer authorized")
	}
	return pc, tlsInfo, nil
}

// peerConn is an authenticated connection. It closes itself once the
// current material no longer authorizes its peer. Locks are taken in the
// order peerConn.mu, then MutualTLS.mu.
type peerConn struct {
	net.Conn
	m     *MutualTLS
	certs []*x509.Certificate

	mu     sync.Mutex
	closed bool
	timer  *time.Timer
}

// recheck authorizes the peer against the current material and schedules
// the next check for when that authorization ends, or closes the
// connection. Checks are serialized, so the last one reflects the latest
// material. It reports whether the connection stays open.
func (c *peerConn) recheck() bool {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return false
	}
	ends, err := c.m.authorize(c.m.current(), c.certs, time.Now())
	if err == nil {
		if c.timer != nil {
			c.timer.Stop()
		}
		c.timer = time.AfterFunc(time.Until(ends)+time.Millisecond, func() { c.recheck() })
		c.mu.Unlock()
		return true
	}
	c.closeLocked()
	c.mu.Unlock()
	_ = c.Conn.Close()
	return false
}

func (c *peerConn) closeLocked() {
	if c.closed {
		return
	}
	c.closed = true
	if c.timer != nil {
		c.timer.Stop()
	}
	c.m.mu.Lock()
	delete(c.m.conns, c)
	c.m.mu.Unlock()
}

func (c *peerConn) Close() error {
	c.mu.Lock()
	c.closeLocked()
	c.mu.Unlock()
	return c.Conn.Close()
}

// transportCredentials adapts a MutualTLS to gRPC for its role only. A
// client bounds its handshake by timeout; a server's is bounded by
// grpc.ConnectionTimeout.
type transportCredentials struct {
	m       *MutualTLS
	timeout time.Duration
}

func (t transportCredentials) ClientHandshake(ctx context.Context, _ string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if t.m.role != roleClient {
		return nil, nil, errors.New("providerkit: server mutual TLS cannot dial")
	}
	if t.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.timeout)
		defer cancel()
	}
	return t.m.handshake(ctx, raw)
}

func (t transportCredentials) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if t.m.role != roleServer {
		return nil, nil, errors.New("providerkit: client mutual TLS cannot serve")
	}
	return t.m.handshake(context.Background(), raw)
}

func (transportCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls", SecurityVersion: "1.3"}
}

func (t transportCredentials) Clone() credentials.TransportCredentials { return t }

func (transportCredentials) OverrideServerName(string) error {
	return errors.New("providerkit: the server name is the configured peer name")
}
