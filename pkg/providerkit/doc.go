// Package providerkit is the Go authoring kit for external Konstapel
// assessment providers: a Server that enforces the konstapel.provider.v1
// protocol around a provider's handlers, and a Client a host uses to reach a
// provider endpoint (add-external-assessment-providers).
//
// The wire contract is proto/konstapel/provider/v1/provider.proto, whose Go
// types are github.com/backend-bunny/Konstapel/pkg/providerapi/v1. Providers
// in other languages generate their own code from that file and follow the
// same rules; the wire fixtures in proto/konstapel/provider/v1/testdata pin
// them.
//
// Four versions are compatibility dimensions of their own, checked
// separately and in a fixed order, each failing with its own
// providerv1.ErrorReason:
//
//   - the protocol revision of major version 1 (ProtocolVersion);
//   - the provider contract version, the provider's capability contract
//     ("<name>/v<version>");
//   - the payload version the provider writes and reads;
//   - the evaluator version, the provider's evaluation semantics.
//
// Nothing is negotiated downward or adapted: an unsupported version is an
// error, never a default.
//
// Transport is mutual TLS 1.3 with explicit peer names and configured
// trust. NewServerTLS and NewClientTLS load one side's certificate, key and
// trust bundle from mounted files, and NewClientTLSFrom from a TLSSource,
// for a host whose trust bundle is not a file; every load passes the same
// checks. ServerOptions and DialOptions configure
// a grpc.Server or grpc.ClientConn with them and with TransportLimits. A
// peer is authorized only when its certificate chains to the trust bundle,
// is valid and names an expected peer exactly as a DNS subject alternative
// name: the host authorizes the server name of its registration, the
// provider the host identities it allows. The host sends no call, and no
// client certificate, before the server is authorized, and no call reaches
// a provider's handlers before the host is. Rotated material is picked up
// without a restart, and established connections the rotated material no
// longer authorizes are closed. Every call needs a deadline; messages,
// received stream totals, concurrent calls and connection setup are
// bounded. Certificate issuance is the platform's.
//
// This package imports nothing from Konstapel's internal packages, and its
// API is the only Go surface external providers build on.
package providerkit
