package providerkit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/tap"
	"google.golang.org/protobuf/proto"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
)

// Default transport bounds.
const (
	// DefaultMaxMessageBytes bounds one gRPC message in either direction:
	// gRPC's own default receive bound, made explicit and applied to sends.
	DefaultMaxMessageBytes = 4 << 20
	// DefaultMaxConcurrentStreams bounds the concurrent calls of one
	// connection to a server.
	DefaultMaxConcurrentStreams uint32 = 100
	// DefaultHandshakeTimeout bounds each connection's TLS handshake, and
	// on a server also its HTTP/2 preface.
	DefaultHandshakeTimeout = 10 * time.Second
)

const (
	// minMessageBytes is the smallest message bound: it carries the largest
	// observation and request header the protocol allows.
	minMessageBytes = 64 << 10
	// chunkEnvelopeBytes bounds the encoding around one chunk's data.
	chunkEnvelopeBytes = 32
	// observationBytes bounds one encoded observation of bounded text.
	observationBytes = 4 << 10
	// messageFrameBytes is gRPC's length prefix of each message.
	messageFrameBytes = 5
	// maxHeaderListBytes bounds the metadata of one call.
	maxHeaderListBytes = 16 << 10
)

// TransportLimits bound a connection. Zero fields take their defaults.
type TransportLimits struct {
	// Protocol are the protocol bounds the transport carries: a provider's
	// own (Server.Limits) or the host's. Nil means the kit defaults.
	Protocol *providerv1.Limits
	// MaxMessageBytes bounds one message sent or received (default
	// DefaultMaxMessageBytes). It must carry one chunk of
	// Protocol.max_chunk_bytes and is at least 64 KiB.
	MaxMessageBytes int
	// MaxStreamBytes bounds the wire bytes of all messages one call
	// receives. The default is the largest transfer the protocol bounds
	// allow (a result or payload in chunks, or an evaluation's
	// observations) plus one message.
	MaxStreamBytes uint64
	// MaxConcurrentStreams bounds a server connection's concurrent calls
	// (default DefaultMaxConcurrentStreams). Clients ignore it.
	MaxConcurrentStreams uint32
	// HandshakeTimeout bounds each connection's TLS handshake, and on a
	// server also its HTTP/2 preface (default DefaultHandshakeTimeout).
	HandshakeTimeout time.Duration
}

func (t TransportLimits) resolve() (TransportLimits, error) {
	p := NegotiateLimits(t.Protocol, nil)
	if t.MaxMessageBytes == 0 {
		t.MaxMessageBytes = DefaultMaxMessageBytes
	}
	if t.MaxConcurrentStreams == 0 {
		t.MaxConcurrentStreams = DefaultMaxConcurrentStreams
	}
	if t.HandshakeTimeout == 0 {
		t.HandshakeTimeout = DefaultHandshakeTimeout
	}
	switch {
	case t.MaxMessageBytes < minMessageBytes:
		return t, fmt.Errorf("providerkit: MaxMessageBytes %d is less than %d", t.MaxMessageBytes, minMessageBytes)
	case uint64(t.MaxMessageBytes) < uint64(p.GetMaxChunkBytes())+chunkEnvelopeBytes:
		return t, fmt.Errorf("providerkit: MaxMessageBytes %d cannot carry a chunk of %d bytes", t.MaxMessageBytes, p.GetMaxChunkBytes())
	case t.HandshakeTimeout < 0:
		return t, fmt.Errorf("providerkit: HandshakeTimeout %s is negative", t.HandshakeTimeout)
	}
	if t.MaxStreamBytes == 0 {
		chunks := (p.GetMaxResultBytes() + uint64(p.GetMaxChunkBytes()) - 1) / uint64(p.GetMaxChunkBytes())
		transfer := p.GetMaxResultBytes() + chunks*(chunkEnvelopeBytes+messageFrameBytes)
		observations := uint64(p.GetMaxObservations()) * (observationBytes + messageFrameBytes)
		t.MaxStreamBytes = max(transfer, observations) + uint64(t.MaxMessageBytes)
	}
	t.Protocol = p
	return t, nil
}

// ServerOptions configure a provider's grpc.Server with m, a server's
// mutual TLS, and the limits. Before any call reaches a handler the
// server has
//
//   - completed a TLS 1.3 handshake whose client m authorizes, within
//     HandshakeTimeout together with the HTTP/2 preface;
//   - authorized the client again against m's current material, so a
//     rotation applies to established connections at once;
//   - required a deadline: a call without one fails with
//     ERROR_REASON_INVALID_REQUEST. The host's deadline is authoritative
//     and reaches the handler's context, as does its cancellation.
//
// Messages are bounded by MaxMessageBytes and a call's received messages
// by MaxStreamBytes (ERROR_REASON_LIMIT_EXCEEDED). The options install the
// server's tap handle; add interceptors with grpc.ChainUnaryInterceptor
// and grpc.ChainStreamInterceptor, which run after these checks.
func ServerOptions(m *MutualTLS, limits TransportLimits) ([]grpc.ServerOption, error) {
	if m == nil || m.role != roleServer {
		return nil, errors.New("providerkit: ServerOptions needs a server's mutual TLS (NewServerTLS)")
	}
	l, err := limits.resolve()
	if err != nil {
		return nil, err
	}
	return []grpc.ServerOption{
		grpc.Creds(transportCredentials{m: m}),
		grpc.ConnectionTimeout(l.HandshakeTimeout),
		grpc.MaxRecvMsgSize(l.MaxMessageBytes),
		grpc.MaxSendMsgSize(l.MaxMessageBytes),
		grpc.MaxConcurrentStreams(l.MaxConcurrentStreams),
		grpc.MaxHeaderListSize(maxHeaderListBytes),
		grpc.InTapHandle(m.admit),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			return handler(srv, &boundedServerStream{ServerStream: ss, budget: budget{max: l.MaxStreamBytes}})
		}),
	}, nil
}

// admit authorizes a call's peer against the current material and
// requires a deadline, before the call's messages are read.
func (m *MutualTLS) admit(ctx context.Context, _ *tap.Info) (context.Context, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "call has no mutual TLS peer")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "call has no mutual TLS peer")
	}
	if _, err := m.authorize(m.current(), info.State.PeerCertificates, time.Now()); err != nil {
		// The caller learns no authorized name or trust detail.
		return nil, status.Error(codes.Unauthenticated, "peer is not authorized")
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, toStatus(invalidRequest("call has no deadline"))
	}
	return ctx, nil
}

// DialOptions configure a host's grpc.ClientConn with m, a client's mutual
// TLS, and the limits. The connection sends no call, and no client
// certificate, before the server's TLS 1.3 handshake shows m's
// authorized server name and trust, within HandshakeTimeout; the dialed
// address does not change the expected name. A call without a deadline
// fails with ERROR_REASON_INVALID_REQUEST before anything is sent.
// Messages are bounded by MaxMessageBytes and a call's received messages
// by MaxStreamBytes (ERROR_REASON_LIMIT_EXCEEDED), which also cancels the
// call. Service configuration from name resolution is ignored.
func DialOptions(m *MutualTLS, limits TransportLimits) ([]grpc.DialOption, error) {
	if m == nil || m.role != roleClient {
		return nil, errors.New("providerkit: DialOptions needs a client's mutual TLS (NewClientTLS)")
	}
	l, err := limits.resolve()
	if err != nil {
		return nil, err
	}
	return []grpc.DialOption{
		grpc.WithTransportCredentials(transportCredentials{m: m, timeout: l.HandshakeTimeout}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(l.MaxMessageBytes), grpc.MaxCallSendMsgSize(l.MaxMessageBytes)),
		grpc.WithMaxHeaderListSize(maxHeaderListBytes),
		grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.DefaultConfig, MinConnectTimeout: l.HandshakeTimeout}),
		grpc.WithDisableServiceConfig(),
		grpc.WithChainUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			if _, ok := ctx.Deadline(); !ok {
				return invalidRequest("call has no deadline")
			}
			return invoker(ctx, method, req, reply, cc, opts...)
		}),
		grpc.WithChainStreamInterceptor(func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			if _, ok := ctx.Deadline(); !ok {
				return nil, invalidRequest("call has no deadline")
			}
			ctx, cancel := context.WithCancel(ctx)
			cs, err := streamer(ctx, desc, cc, method, opts...)
			if err != nil {
				cancel()
				return nil, err
			}
			return &boundedClientStream{ClientStream: cs, budget: budget{max: l.MaxStreamBytes}, cancel: cancel}, nil
		}),
	}, nil
}

// budget counts the wire bytes a call received.
type budget struct {
	max, used uint64
}

func (b *budget) charge(m any) error {
	msg, ok := m.(proto.Message)
	if !ok {
		return invalidRequest("message %T is not a protocol buffer", m)
	}
	if b.used += uint64(proto.Size(msg)) + messageFrameBytes; b.used > b.max {
		return Errorf(providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED, "call received more than %d bytes", b.max)
	}
	return nil
}

type boundedServerStream struct {
	grpc.ServerStream
	budget budget
}

func (s *boundedServerStream) RecvMsg(m any) error {
	if s.budget.used > s.budget.max {
		return Errorf(providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED, "call received more than %d bytes", s.budget.max)
	}
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	return s.budget.charge(m)
}

type boundedClientStream struct {
	grpc.ClientStream
	budget budget
	cancel context.CancelFunc
}

// RecvMsg cancels the call when it ends or exceeds its budget, so an
// abandoned stream holds nothing.
func (s *boundedClientStream) RecvMsg(m any) error {
	if s.budget.used > s.budget.max {
		return Errorf(providerv1.ErrorReason_ERROR_REASON_LIMIT_EXCEEDED, "call received more than %d bytes", s.budget.max)
	}
	if err := s.ClientStream.RecvMsg(m); err != nil {
		s.cancel()
		return err
	}
	if err := s.budget.charge(m); err != nil {
		s.cancel()
		return err
	}
	return nil
}
