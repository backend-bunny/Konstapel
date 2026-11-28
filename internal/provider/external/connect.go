package external

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

// maxCredentialBytes bounds each credential file, as the kit bounds its own.
const maxCredentialBytes = 1 << 20

// Credentials are the controller's own client certificate and key for
// external providers: deployment configuration, never part of a
// registration. They are read at each connection, so a rotated mounted
// Secret is used without a restart.
type Credentials struct {
	Certificate string
	Key         string
}

// CredentialsDir is tls.crt and tls.key in dir, a mounted
// kubernetes.io/tls Secret.
func CredentialsDir(dir string) Credentials {
	return Credentials{Certificate: filepath.Join(dir, "tls.crt"), Key: filepath.Join(dir, "tls.key")}
}

// Check loads the credentials with every check the kit applies to a
// host's certificate and key: a certificate chain matching its key, valid
// now and allowing client authentication.
func (c Credentials) Check() error {
	cert, key, err := c.read()
	if err != nil {
		return err
	}
	// The kit verifies a certificate and key only together with a trust
	// bundle. The trust is irrelevant to the controller's own credentials,
	// so the certificate's own chain stands in for it.
	if _, err := providerkit.NewClientTLSFrom(material{cert: cert, key: key, trust: cert}, "credentials.check.invalid"); err != nil {
		return fmt.Errorf("external provider client credentials: %w", err)
	}
	return nil
}

func (c Credentials) read() (cert, key []byte, err error) {
	if c.Certificate == "" || c.Key == "" {
		return nil, nil, errors.New("no client certificate and key are configured")
	}
	if cert, err = readBounded(c.Certificate); err != nil {
		return nil, nil, err
	}
	if key, err = readBounded(c.Key); err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("client credentials: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxCredentialBytes+1))
	if err != nil {
		return nil, fmt.Errorf("client credentials: %w", err)
	}
	if len(b) > maxCredentialBytes {
		return nil, fmt.Errorf("client credentials: %s is larger than %d bytes", path, maxCredentialBytes)
	}
	return b, nil
}

// material is one connection's TLS material: the controller's
// credentials and a registration's trust.
type material struct{ cert, key, trust []byte }

func (m material) LoadTLS() (providerkit.TLSMaterial, error) {
	return providerkit.TLSMaterial{Certificate: m.cert, Key: m.key, Trust: m.trust}, nil
}

// TrustReader returns the PEM roots of a serverTrust ConfigMap key in the
// controller namespace. Errors must not contain the ConfigMap's data.
type TrustReader func(ctx context.Context, configMap, key string) ([]byte, error)

// Problem is a bounded reason a registration's endpoint cannot be used:
// the condition it falsifies (Available or Compatible), a
// v1alpha1.ProviderReason* reason and a message without credentials.
type Problem struct {
	Condition string
	Reason    string
	Message   string
	// cause is the underlying error, such as a *FrozenError for an
	// endpoint that no longer reports the frozen implementation.
	cause error
}

func (p *Problem) Error() string { return p.Reason + ": " + p.Message }

// Unwrap returns the underlying error, if any.
func (p *Problem) Unwrap() error { return p.cause }

func unavailable(reason, format string, a ...any) *Problem {
	return &Problem{Condition: v1alpha1.ProviderConditionAvailable, Reason: reason, Message: fmt.Sprintf(format, a...)}
}

func incompatible(reason, format string, a ...any) *Problem {
	return &Problem{Condition: v1alpha1.ProviderConditionCompatible, Reason: reason, Message: fmt.Sprintf(format, a...)}
}

// Dialer connects the host to registered providers over the kit's mutual
// TLS.
type Dialer struct {
	Credentials Credentials
	Trust       TrustReader
	// Address is the address dialed for an endpoint; nil is
	// Endpoint.Address, the Service's cluster DNS name. The authenticated
	// server name never depends on it.
	Address func(Endpoint) string
	// Limits are the transport bounds; zero fields take the kit defaults.
	// Limits.Protocol are also the host's protocol bounds, of which the
	// client applies the stricter and the provider's.
	Limits providerkit.TransportLimits
	// Registration reads a registration as it is now, for work frozen to
	// it to continue (Collect). Probing does not need it.
	Registration RegistrationReader
}

// Connection is an authenticated provider endpoint whose description
// matched the identity it was connected for.
type Connection struct {
	Client      *providerkit.Client
	Description *providerv1.DescribeResponse
	conn        *grpc.ClientConn
}

// Close closes the connection.
func (c *Connection) Close() error { return c.conn.Close() }

// Connect reaches f's endpoint: it reads the current roots of f's trust
// ConfigMap and the controller's current credentials, authenticates the
// server as f's server name over mutual TLS 1.3, describes it within ctx's
// deadline, and checks the description against f, its implementation
// included. Nothing is sent before the server is authenticated. Every
// failure is a *Problem; no fallback weakens a check.
func (d *Dialer) Connect(ctx context.Context, f Frozen) (*Connection, error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, unavailable(v1alpha1.ProviderReasonEndpointUnavailable, "connecting needs a deadline")
	}
	if d.Trust == nil {
		return nil, unavailable(v1alpha1.ProviderReasonTrustUnavailable, "no trust reader is configured")
	}
	trust, err := d.Trust(ctx, f.Endpoint.TrustConfigMap, f.Endpoint.TrustKey)
	if err != nil {
		return nil, unavailable(v1alpha1.ProviderReasonTrustUnavailable, "%s", bound(err.Error(), 512))
	}
	cert, key, err := d.Credentials.read()
	if err != nil {
		return nil, unavailable(v1alpha1.ProviderReasonClientCredentialsUnavailable, "%s", bound(err.Error(), 512))
	}
	m, err := providerkit.NewClientTLSFrom(material{cert: cert, key: key, trust: trust}, f.Endpoint.ServerName)
	if err != nil {
		// The kit names the trust bundle in every trust problem; any other
		// material problem is the controller's own certificate or key.
		reason := v1alpha1.ProviderReasonClientCredentialsUnavailable
		if strings.Contains(err.Error(), "trust bundle") {
			reason = v1alpha1.ProviderReasonTrustUnavailable
		}
		return nil, unavailable(reason, "%s", bound(err.Error(), 512))
	}
	opts, err := providerkit.DialOptions(m, d.Limits)
	if err != nil {
		return nil, unavailable(v1alpha1.ProviderReasonEndpointUnavailable, "%s", bound(err.Error(), 512))
	}
	addr := f.Endpoint.Address()
	if d.Address != nil {
		addr = d.Address(f.Endpoint)
	}
	var seen dialed
	opts = append(opts, grpc.WithContextDialer(seen.dial), grpc.WithChainUnaryInterceptor(seen.intercept))
	conn, err := grpc.NewClient("passthrough:///"+addr, opts...)
	if err != nil {
		return nil, unavailable(v1alpha1.ProviderReasonEndpointUnavailable, "%s", bound(err.Error(), 512))
	}
	client, err := providerkit.NewClient(conn, f.Compatibility(), d.Limits.Protocol)
	if err != nil {
		// The API validates registrations; this is the host's own check.
		_ = conn.Close()
		return nil, incompatible(v1alpha1.ProviderReasonInvalidDescription, "the registration's expectation is invalid: %s", bound(err.Error(), 512))
	}
	desc, err := client.Describe(ctx)
	if err == nil && desc.GetImplementation() != f.ReleaseDigest {
		err = &FrozenError{Reason: FrozenImplementationChanged, Message: fmt.Sprintf("endpoint reports implementation %q, not the registered release %s",
			bound(desc.GetImplementation(), 80), f.ReleaseDigest)}
	}
	if err != nil {
		_ = conn.Close()
		return nil, classify(ctx, err, f, &seen)
	}
	return &Connection{Client: client, Description: desc, conn: conn}, nil
}

// classify turns a Describe failure into a Problem.
func classify(ctx context.Context, err error, f Frozen, seen *dialed) *Problem {
	var fe *FrozenError
	if errors.As(err, &fe) {
		p := incompatible(v1alpha1.ProviderReasonReleaseMismatch, "%s", fe.Message)
		p.cause = fe
		return p
	}
	msg := bound(err.Error(), 512)
	switch providerkit.ReasonOf(err) {
	case providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PROTOCOL_VERSION:
		return incompatible(v1alpha1.ProviderReasonUnsupportedProtocolVersion, "%s", msg)
	case providerv1.ErrorReason_ERROR_REASON_PROVIDER_MISMATCH:
		return incompatible(v1alpha1.ProviderReasonProviderMismatch, "%s", msg)
	case providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CONTRACT_VERSION:
		return incompatible(v1alpha1.ProviderReasonUnsupportedContractVersion, "%s", msg)
	case providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_EVALUATOR_VERSION:
		return incompatible(v1alpha1.ProviderReasonUnsupportedEvaluatorVersion, "%s", msg)
	case providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_PAYLOAD_VERSION:
		return incompatible(v1alpha1.ProviderReasonUnsupportedPayloadVersion, "%s", msg)
	case providerv1.ErrorReason_ERROR_REASON_UNSUPPORTED_CAPABILITY:
		return incompatible(v1alpha1.ProviderReasonUnsupportedCapability, "%s", msg)
	case providerv1.ErrorReason_ERROR_REASON_INVALID_RESPONSE:
		return incompatible(v1alpha1.ProviderReasonInvalidDescription, "%s", msg)
	case providerv1.ErrorReason_ERROR_REASON_UNSPECIFIED:
		// A transport failure: no protocol answer at all.
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return unavailable(v1alpha1.ProviderReasonEndpointUnavailable, "%s did not answer within the deadline", f.Endpoint.Address())
		}
		if code := seen.code(); code == codes.Unauthenticated || (code == codes.Unavailable && seen.answered()) {
			// The endpoint answered, but no mutually authenticated TLS 1.3
			// connection for the server name was established.
			return unavailable(v1alpha1.ProviderReasonAuthenticationFailed, "%s", msg)
		}
	}
	return unavailable(v1alpha1.ProviderReasonEndpointUnavailable, "%s", msg)
}

// dialed records whether the endpoint accepted a connection and sent
// anything back, and the last call's gRPC code, to tell an unreachable
// endpoint from one that failed mutual authentication.
type dialed struct {
	connected atomic.Bool
	received  atomic.Bool
	last      atomic.Uint32
}

func (d *dialed) intercept(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	err := invoker(ctx, method, req, reply, cc, opts...)
	d.last.Store(uint32(status.Code(err)))
	return err
}

func (d *dialed) code() codes.Code { return codes.Code(d.last.Load()) }

func (d *dialed) dial(ctx context.Context, addr string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	d.connected.Store(true)
	return &trackedConn{Conn: c, d: d}, nil
}

func (d *dialed) answered() bool { return d.connected.Load() && d.received.Load() }

type trackedConn struct {
	net.Conn
	d *dialed
}

func (c *trackedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.d.received.Store(true)
	}
	return n, err
}
