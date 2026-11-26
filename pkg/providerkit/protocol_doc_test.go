package providerkit

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
)

// The protocol reference (docs/integration/external-provider-protocol.md)
// carries tables generated from the protocol descriptor, the comments of
// provider.proto and this package's constants, between
// "<!-- BEGIN GENERATED: name -->" and "<!-- END GENERATED: name -->"
// markers. TestProtocolReference fails when a table differs from what the
// protocol says; -update-protocol-doc rewrites them.
var updateProtocolDoc = flag.Bool("update-protocol-doc", false, "rewrite the generated tables of the protocol reference")

const (
	protocolDoc   = "../../docs/integration/external-provider-protocol.md"
	protocolProto = "../../proto/konstapel/provider/v1/provider.proto"
)

// rpcCapabilities are the capabilities each RPC needs, as Server.require
// enforces them. A new RPC must be added here, so the table cannot omit it.
var rpcCapabilities = map[string][]providerv1.Capability{
	"Describe":    nil,
	"Collect":     {providerv1.Capability_CAPABILITY_COLLECT},
	"Start":       {providerv1.Capability_CAPABILITY_SCAN},
	"Get":         {providerv1.Capability_CAPABILITY_SCAN},
	"Cancel":      {providerv1.Capability_CAPABILITY_SCAN},
	"ReadResult":  {providerv1.Capability_CAPABILITY_COLLECT, providerv1.Capability_CAPABILITY_SCAN},
	"Acknowledge": {providerv1.Capability_CAPABILITY_COLLECT, providerv1.Capability_CAPABILITY_SCAN},
	"Evaluate":    {providerv1.Capability_CAPABILITY_EVALUATE},
}

func TestProtocolReference(t *testing.T) {
	comments, err := enumComments(protocolProto)
	if err != nil {
		t.Fatal(err)
	}
	tables := map[string]string{
		"rpcs":             rpcTable(t),
		"capabilities":     enumTable(t, providerv1.Capability(0).Descriptor(), comments, false),
		"error-reasons":    enumTable(t, providerv1.ErrorReason(0).Descriptor(), comments, true),
		"operation-states": enumTable(t, providerv1.OperationState(0).Descriptor(), comments, false),
		"evidence-states":  enumTable(t, providerv1.EvidenceState(0).Descriptor(), comments, false),
		"limits":           limitsTable(),
	}
	raw, err := os.ReadFile(protocolDoc)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for name, table := range tables {
		begin, end := "<!-- BEGIN GENERATED: "+name+" -->\n", "<!-- END GENERATED: "+name+" -->"
		i, j := strings.Index(doc, begin), strings.Index(doc, end)
		if i < 0 || j < i {
			t.Errorf("%s has no generated %q table", protocolDoc, name)
			continue
		}
		got := doc[i+len(begin) : j]
		if got == table {
			continue
		}
		if *updateProtocolDoc {
			doc = doc[:i+len(begin)] + table + doc[j:]
			continue
		}
		t.Errorf("generated %q table is stale; run go test ./pkg/providerkit -run TestProtocolReference -update-protocol-doc\ngot:\n%s\nwant:\n%s", name, got, table)
	}
	if *updateProtocolDoc && doc != string(raw) {
		if err := os.WriteFile(protocolDoc, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func rpcTable(t *testing.T) string {
	svc := providerv1.File_konstapel_provider_v1_provider_proto.Services().ByName("AssessmentProvider")
	var b strings.Builder
	b.WriteString("| RPC | Shape | Capability | Request | Response |\n| --- | --- | --- | --- | --- |\n")
	methods := svc.Methods()
	if methods.Len() != len(rpcCapabilities) {
		t.Errorf("service has %d RPCs, the reference table knows %d", methods.Len(), len(rpcCapabilities))
	}
	for i := range methods.Len() {
		m := methods.Get(i)
		caps, ok := rpcCapabilities[string(m.Name())]
		if !ok {
			t.Errorf("RPC %s has no capability in rpcCapabilities", m.Name())
		}
		shape := "unary"
		switch {
		case m.IsStreamingClient() && m.IsStreamingServer():
			shape = "bidirectional stream"
		case m.IsStreamingServer():
			shape = "server stream"
		case m.IsStreamingClient():
			shape = "client stream"
		}
		capability := "none (always served)"
		if len(caps) > 0 {
			names := make([]string, len(caps))
			for i, c := range caps {
				names[i] = "`" + c.String() + "`"
			}
			capability = strings.Join(names, " or ")
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | `%s` | `%s` |\n", m.Name(), shape, capability, m.Input().Name(), m.Output().Name())
	}
	return b.String()
}

// enumTable lists an enum's values after the zero value, with the comment
// provider.proto gives each. Error reasons also get their gRPC code.
func enumTable(t *testing.T, e protoreflect.EnumDescriptor, comments map[string]string, codes bool) string {
	var b strings.Builder
	if codes {
		b.WriteString("| Reason | Number | gRPC code | Meaning |\n| --- | --- | --- | --- |\n")
	} else {
		b.WriteString("| Value | Number | Meaning |\n| --- | --- | --- |\n")
	}
	values := e.Values()
	for i := range values.Len() {
		v := values.Get(i)
		if v.Number() == 0 {
			continue
		}
		comment, ok := comments[string(v.Name())]
		if !ok || comment == "" {
			t.Errorf("%s has no comment in provider.proto", v.Name())
		}
		if codes {
			fmt.Fprintf(&b, "| `%s` | %d | `%s` | %s |\n", v.Name(), v.Number(), Code(providerv1.ErrorReason(v.Number())), comment)
		} else {
			fmt.Fprintf(&b, "| `%s` | %d | %s |\n", v.Name(), v.Number(), comment)
		}
	}
	return b.String()
}

var enumValueLine = regexp.MustCompile(`^\s*([A-Z][A-Z0-9_]*)\s*=\s*\d+;`)

// enumComments maps each enum value of a .proto file to its leading
// comment, joined into one line.
func enumComments(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	var comment []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		switch {
		case strings.HasPrefix(line, "//"):
			comment = append(comment, strings.TrimSpace(strings.TrimPrefix(line, "//")))
			continue
		case enumValueLine.MatchString(line):
			out[enumValueLine.FindStringSubmatch(line)[1]] = strings.ReplaceAll(strings.Join(comment, " "), "|", `\|`)
		}
		comment = nil
	}
	return out, s.Err()
}

func limitsTable() string {
	rows := [][3]string{
		{"`Limits.max_result_bytes`", mib(DefaultMaxResultBytes), "`DefaultMaxResultBytes`: one staged result, and one evaluated payload"},
		{"`Limits.max_chunk_bytes`", mib(uint64(DefaultMaxChunkBytes)), "`DefaultMaxChunkBytes`: the data of one `ReadResultResponse` or `EvaluateRequest.payload_chunk`, and the encoded observations of one `ObservationBatch`"},
		{"`Limits.max_observations`", fmt.Sprint(DefaultMaxObservations), "`DefaultMaxObservations`: the observations of one evaluation"},
		{"gRPC message, either direction", mib(DefaultMaxMessageBytes), fmt.Sprintf("`TransportLimits.MaxMessageBytes` (`DefaultMaxMessageBytes`); at least %s and one chunk plus its envelope", kib(minMessageBytes))},
		{"Received bytes of one call", "largest bounded transfer plus one message", "`TransportLimits.MaxStreamBytes`: a full result or payload in chunks, or a full evaluation's observations"},
		{"Concurrent calls per connection", fmt.Sprint(DefaultMaxConcurrentStreams), "`TransportLimits.MaxConcurrentStreams` (`DefaultMaxConcurrentStreams`), server side"},
		{"TLS handshake and HTTP/2 preface", DefaultHandshakeTimeout.String(), "`TransportLimits.HandshakeTimeout` (`DefaultHandshakeTimeout`)"},
		{"Call metadata", kib(maxHeaderListBytes), "Fixed header-list bound, both sides"},
		{"Limitations per result", fmt.Sprint(MaxLimitations), "`MaxLimitations`"},
		{"Identifier, limitation, operation message or raw outcome", fmt.Sprintf("%d bytes", MaxTextBytes), "`MaxTextBytes`"},
		{"One mounted TLS file", mib(maxTLSFileBytes), fmt.Sprintf("Fixed; at most %d certificates", maxTLSFileCertificates)},
		{"TLS file reload interval", DefaultReloadInterval.String(), "`DefaultReloadInterval` (`MutualTLS.Watch`)"},
	}
	var b strings.Builder
	b.WriteString("| Bound | Default | Configured by / applies to |\n| --- | --- | --- |\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", r[0], r[1], r[2])
	}
	return b.String()
}

func mib(n uint64) string { return fmt.Sprintf("%d MiB", n>>20) }

func kib(n uint64) string { return fmt.Sprintf("%d KiB", n>>10) }
