// Package externaltest runs real external provider endpoints for tests of
// the host's registered-provider support: a providerkit Server over mutual
// TLS 1.3 on loopback, with every key and certificate generated in memory
// per test. Key files exist only in the test's temporary directories, as a
// mounted Secret would. It is a test helper; no shipped binary imports it.
package externaltest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

// Names and identities of the default fixture.
const (
	Provider   = "example-reporting"
	ServerName = "example-reporting.providers.svc"
	// EvaluatorServerName and EvaluatorServiceName are the default
	// registration's separate evaluator endpoint.
	EvaluatorServerName  = "example-reporting-evaluator.providers.svc"
	EvaluatorServiceName = "example-reporting-evaluator"
	ClientName           = "konstapel-controller.konstapel-system.svc"
	Release              = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	OtherRelease         = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	TrustConfig          = "example-reporting-ca"
	ProviderNS           = "providers"
	ServiceName          = "example-reporting"
	ServicePort          = 8443
	CheckKindName        = "reporting.example.io/v1/Posture"
)

var serial atomic.Int64

// CA is an in-memory certificate authority.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	// PEM is the CA certificate, a trust bundle.
	PEM []byte
}

// NewCA returns a CA valid for the hour around now.
func NewCA(t testing.TB) *CA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: "externaltest CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{cert: cert, key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// Leaf is an issued certificate and its key in PEM.
type Leaf struct{ Cert, Key []byte }

// Issue issues a leaf for names with the usage, valid for the hour around now.
func (ca *CA) Issue(t testing.TB, usage x509.ExtKeyUsage, names ...string) Leaf {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: strings.Join(names, ",")},
		DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return Leaf{Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})}
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// WriteFile replaces path atomically.
func WriteFile(t testing.TB, path string, data []byte) {
	t.Helper()
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// ClientDir writes the controller's client certificate for ClientName,
// issued by ca, as a mounted kubernetes.io/tls Secret, and returns the
// directory.
func ClientDir(t testing.TB, ca *CA) string {
	t.Helper()
	dir := t.TempDir()
	WriteClient(t, dir, ca.Issue(t, x509.ExtKeyUsageClientAuth, ClientName))
	return dir
}

// WriteClient replaces the client certificate and key in dir.
func WriteClient(t testing.TB, dir string, l Leaf) {
	t.Helper()
	WriteFile(t, filepath.Join(dir, "tls.crt"), l.Cert)
	WriteFile(t, filepath.Join(dir, "tls.key"), l.Key)
}

// Description is the default fixture's description: Collect and Evaluate
// of contract example-reporting/v1, evaluator 1, payload 1, release Release.
func Description() *providerv1.DescribeResponse {
	return &providerv1.DescribeResponse{
		Provider:         &providerv1.ProviderContract{Name: Provider, Version: 1},
		ProtocolVersions: []uint32{providerkit.ProtocolVersion}, EvaluatorVersion: 1,
		Payload:        &providerv1.PayloadCompatibility{Write: 1, Read: []uint32{1}},
		Capabilities:   []providerv1.Capability{providerv1.Capability_CAPABILITY_COLLECT, providerv1.Capability_CAPABILITY_EVALUATE},
		Checks:         []*providerv1.CheckKind{{Kind: CheckKindName}},
		Implementation: Release,
	}
}

// Server is a running provider endpoint.
type Server struct {
	t testing.TB
	// Addr is the loopback address it listens on.
	Addr string
	// Calls counts the calls that reached the provider's handlers after
	// the transport authenticated the host.
	Calls atomic.Int64
	// Describes counts Describe calls that reached the provider.
	Describes atomic.Int64

	dir string
	tls *providerkit.MutualTLS
	srv *grpc.Server
}

// ServerOptions configure Serve.
type ServerOptions struct {
	// Description defaults to Description().
	Description *providerv1.DescribeResponse
	// CA issues the serving certificate and is the client trust, unless
	// ClientTrust is set.
	CA *CA
	// ServerNames default to ServerName and EvaluatorServerName: one
	// process serving both of the default registration's endpoints.
	ServerNames []string
	// ClientTrust is the CA bundle the provider trusts for clients.
	ClientTrust []byte
	// AuthorizedClients default to ClientName.
	AuthorizedClients []string
	// Handlers serve the description's capabilities. Nil serves Describe
	// only: every other call fails, as probing and selection never make
	// one.
	Handlers *providerkit.Handlers
}

// Serve starts a provider endpoint on loopback.
func Serve(t testing.TB, o ServerOptions) *Server {
	t.Helper()
	if o.Description == nil {
		o.Description = Description()
	}
	if len(o.ServerNames) == 0 {
		o.ServerNames = []string{ServerName, EvaluatorServerName}
	}
	if o.ClientTrust == nil {
		o.ClientTrust = o.CA.PEM
	}
	if len(o.AuthorizedClients) == 0 {
		o.AuthorizedClients = []string{ClientName}
	}
	s := &Server{t: t, dir: t.TempDir()}
	files := providerkit.SecretFiles(s.dir)
	l := o.CA.Issue(t, x509.ExtKeyUsageServerAuth, o.ServerNames...)
	WriteFile(t, files.Certificate, l.Cert)
	WriteFile(t, files.Key, l.Key)
	WriteFile(t, files.Trust, o.ClientTrust)
	var err error
	if s.tls, err = providerkit.NewServerTLS(files, o.AuthorizedClients); err != nil {
		t.Fatal(err)
	}
	h := providerkit.Handlers{Collector: refuse{}, Results: refuse{}, Scanner: refuse{}, Evaluator: refuse{}}
	if o.Handlers != nil {
		h = *o.Handlers
	}
	kit, err := providerkit.NewServer(o.Description, h)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := providerkit.ServerOptions(s.tls, providerkit.TransportLimits{Protocol: kit.Limits()})
	if err != nil {
		t.Fatal(err)
	}
	opts = append(opts, grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		s.Calls.Add(1)
		if strings.HasSuffix(info.FullMethod, "/Describe") {
			s.Describes.Add(1)
		}
		return h(ctx, req)
	}), grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
		s.Calls.Add(1)
		return h(srv, ss)
	}))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.Addr = lis.Addr().String()
	s.srv = grpc.NewServer(opts...)
	providerv1.RegisterAssessmentProviderServer(s.srv, kit)
	go func() { _ = s.srv.Serve(lis) }()
	t.Cleanup(s.srv.Stop)
	return s
}

// Rotate replaces the serving certificate with one issued by ca for
// ServerName and EvaluatorServerName and reloads it.
func (s *Server) Rotate(ca *CA) {
	s.t.Helper()
	files := providerkit.SecretFiles(s.dir)
	l := ca.Issue(s.t, x509.ExtKeyUsageServerAuth, ServerName, EvaluatorServerName)
	WriteFile(s.t, files.Certificate, l.Cert)
	WriteFile(s.t, files.Key, l.Key)
	if err := s.tls.Reload(); err != nil {
		s.t.Fatal(err)
	}
}

// Stop stops the endpoint.
func (s *Server) Stop() { s.srv.Stop() }

// Hang listens on loopback, accepts connections and never answers them:
// an endpoint that hangs. It returns the address.
func Hang(t testing.TB) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = lis.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return lis.Addr().String()
}

// Closed returns a loopback address nothing listens on.
func Closed(t testing.TB) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	_ = lis.Close()
	return addr
}

// refuse is a handler set that is never expected to run: probing and
// selection only describe.
type refuse struct{}

var errRefused = errors.New("externaltest: only Describe is served")

func (refuse) Collect(context.Context, *providerv1.CollectRequest) (*providerv1.ResultReference, error) {
	return nil, errRefused
}
func (refuse) Result(context.Context, string) (*providerv1.ResultReference, []byte, error) {
	return nil, nil, errRefused
}
func (refuse) Release(context.Context, string) error { return errRefused }
func (refuse) Start(context.Context, *providerv1.StartRequest) (*providerv1.Operation, error) {
	return nil, errRefused
}
func (refuse) Get(context.Context, string) (*providerv1.Operation, error)    { return nil, errRefused }
func (refuse) Cancel(context.Context, string) (*providerv1.Operation, error) { return nil, errRefused }
func (refuse) Evaluate(context.Context, *providerv1.EvaluateStart, []byte) (*providerkit.Evaluation, error) {
	return nil, errRefused
}

// Registration is an AssessmentProvider for the default fixture, as the API
// server would hold it after creation: generation 1, defaults applied.
func Registration(name string, mutate ...func(*v1alpha1.AssessmentProvider)) *v1alpha1.AssessmentProvider {
	ap := &v1alpha1.AssessmentProvider{
		TypeMeta:   metav1.TypeMeta{APIVersion: v1alpha1.GroupVersion.String(), Kind: "AssessmentProvider"},
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID("uid-" + name), Generation: 1},
		Spec: v1alpha1.AssessmentProviderSpec{
			Provider: v1alpha1.ExpectedProvider{Name: Provider, ReleaseDigest: Release},
			Endpoint: &v1alpha1.ProviderEndpoint{
				Service:     v1alpha1.ProviderServiceReference{Namespace: ProviderNS, Name: ServiceName, Port: ServicePort},
				ServerName:  ServerName,
				ServerTrust: v1alpha1.CATrust{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: TrustConfig}, Key: "ca.crt"},
			},
			EvaluatorEndpoint: &v1alpha1.ProviderEndpoint{
				Service:     v1alpha1.ProviderServiceReference{Namespace: ProviderNS, Name: EvaluatorServiceName, Port: ServicePort},
				ServerName:  EvaluatorServerName,
				ServerTrust: v1alpha1.CATrust{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: TrustConfig}, Key: "ca.crt"},
			},
			Compatibility: v1alpha1.ProviderCompatibility{Protocol: v1alpha1.ProviderProtocolV1, ContractVersion: 1, EvaluatorVersion: 1, PayloadVersion: 1},
			Capabilities:  []v1alpha1.AssessmentProviderCapability{v1alpha1.ProviderCapabilityCollect, v1alpha1.ProviderCapabilityEvaluate},
			NewRequests:   v1alpha1.ProviderNewRequestsEnabled,
		},
	}
	for _, m := range mutate {
		m(ap)
	}
	return ap
}
