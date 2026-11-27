package collector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// CaptureEnvelopeVersion is the provider-discriminated capture document,
// CaptureEnvelope. A capture document's top-level "version" selects its
// format:
//
//   - 1: the prototype's single-policy assessment.Capture
//   - 2: the controller's CaptureV2
//   - 3: the envelope, which names its provider, payload and evaluator
//
// Versions 1 and 2 predate provider discrimination. Their provider, payload
// and evaluator are implied by the version (LegacyProvider,
// LegacyEvaluatorVersion) and are never read from the document. This build
// reads the envelope but writes none: readers ship before writers. Every
// reader that predates the envelope rejects version 3 explicitly
// (CaptureVersion, CaptureV2.Validate and assessment.Reconcile check the
// version), so an envelope is never read as an empty Kyverno capture.
const CaptureEnvelopeVersion = 3

const (
	// LegacyProvider is the provider contract of every version 1 and 2
	// capture: the Kyverno provider (kyverno.Contract).
	LegacyProvider = "konstapel-kyverno/v1"
	// LegacyEvaluatorVersion is the evaluator version every version 1 and
	// 2 capture implies: the 0.3.0 Kyverno semantics, which are
	// assessment.Reconcile for payload 1 and CaptureV2.Evaluate for
	// payload 2.
	LegacyEvaluatorVersion = 1
)

// ErrUnsupportedCapture marks every capture the boundary does not accept:
// an unknown or malformed document, provider, payload or evaluator. Such a
// capture is never read as an empty or partial one.
var ErrUnsupportedCapture = errors.New("unsupported capture")

// CaptureHeader is a capture document's compatibility identity: its format
// version and the three dimensions a reader must support separately.
type CaptureHeader struct {
	// Version is the document format version.
	Version int `json:"version"`
	// Provider is the provider contract ("name/vN") whose payload the
	// document holds.
	Provider string `json:"provider"`
	// PayloadVersion is the provider's payload version, one of its
	// descriptor's capture.read versions.
	PayloadVersion int `json:"payloadVersion"`
	// EvaluatorVersion is the provider evaluation semantics the capture
	// was evaluated with.
	EvaluatorVersion int `json:"evaluatorVersion"`
	// Registration is the frozen registration of a registered external
	// provider's envelope, nil for a built-in provider's capture.
	Registration *CaptureRegistration `json:"registration,omitempty"`
}

// Legacy reports whether the header is implied by a version 1 or 2
// document rather than recorded in an envelope.
func (h CaptureHeader) Legacy() bool { return h.Version != CaptureEnvelopeVersion }

func (h CaptureHeader) String() string {
	s := fmt.Sprintf("capture version %d (%s payload %d, evaluator %d", h.Version, h.Provider, h.PayloadVersion, h.EvaluatorVersion)
	if r := h.Registration; r != nil {
		s += fmt.Sprintf(", registration %s uid %s revision %d", r.Name, r.UID, r.Revision)
	}
	return s + ")"
}

// CaptureEnvelope is the version 3 capture document: a provider-discriminated
// header and that provider's payload. Every field but Registration is
// required, and Registration is required exactly for a registered external
// provider. A reader rejects any other field, so a field added later is
// never silently ignored: once a release writes envelopes, it needs a new
// version.
//
// Registration was added within version 3 (add-external-assessment-providers
// design Decision 10) because no release reads version 3 (0.3.0 and earlier
// refuse it), nothing writes it, and every reader that predates the field
// decodes the envelope strictly and refuses it as an unknown field.
type CaptureEnvelope struct {
	Version          int                  `json:"version"`
	Provider         string               `json:"provider"`
	PayloadVersion   int                  `json:"payloadVersion"`
	EvaluatorVersion int                  `json:"evaluatorVersion"`
	Registration     *CaptureRegistration `json:"registration,omitempty"`
	Payload          json.RawMessage      `json:"payload"`
}

// CaptureRegistration is what interpreting a registered external
// provider's capture needs beyond the envelope's provider contract, payload
// version and evaluator version: the frozen registration (its name, UID and
// configuration revision), the release the endpoint reported as its
// implementation, and the protocol and its revision. Every field is
// required. It holds identities only, never endpoint configuration or
// credentials.
type CaptureRegistration struct {
	Name             string `json:"name"`
	UID              string `json:"uid"`
	Revision         int64  `json:"revision"`
	ReleaseDigest    string `json:"releaseDigest"`
	Protocol         string `json:"protocol"`
	ProtocolRevision int    `json:"protocolRevision"`
}

var (
	registrationName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	releaseDigest    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	protocolName     = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*\.v[1-9][0-9]*$`)
)

// Validate requires every field: a registration name, a UID of at most 128
// bytes, a revision and protocol revision of at least 1, a sha256 release
// digest and a protocol package name such as konstapel.provider.v1.
func (r CaptureRegistration) Validate() error {
	switch {
	case !registrationName.MatchString(r.Name):
		return errors.New("the registration name must be a DNS subdomain name")
	case r.UID == "" || len(r.UID) > 128:
		return errors.New("the registration uid must be set and at most 128 bytes")
	case r.Revision < 1 || r.ProtocolRevision < 1:
		return errors.New("the registration revision and protocol revision start at 1")
	case !releaseDigest.MatchString(r.ReleaseDigest):
		return errors.New("the release digest must be sha256:<64 lowercase hex>")
	case !protocolName.MatchString(r.Protocol):
		return errors.New("the protocol must be a protocol package name such as konstapel.provider.v1")
	}
	return nil
}

// RegistrationReaders is what CaptureReaders also implement to read the
// captures of registered external providers. Readers without it, such as
// the built-in provider registry, refuse every capture that records a
// registration. A reader with it is asked about every capture it reads,
// with the recorded registration or nil, and refuses a registered
// provider's capture without one.
type RegistrationReaders interface {
	CheckRegistration(contract string, registration *CaptureRegistration) error
}

// EncodeEnvelope writes a version 3 capture document of h and payload,
// keeping the payload's bytes exactly as given: encoding/json would compact
// and escape a raw payload, so a payload's digest would no longer be the
// digest of what its provider staged. payload must be one JSON object
// without surrounding whitespace, which a reader would not keep.
// h.Version is ignored. The result reads back through ReadCapture only
// when its readers support h.
func EncodeEnvelope(h CaptureHeader, payload json.RawMessage) ([]byte, error) {
	if len(payload) == 0 || payload[0] != '{' || payload[len(payload)-1] != '}' || !json.Valid(payload) {
		return nil, errors.New("capture envelope: the payload is not one JSON object without surrounding whitespace")
	}
	if h.Registration != nil {
		if err := h.Registration.Validate(); err != nil {
			return nil, fmt.Errorf("capture envelope: %w", err)
		}
	}
	head, err := json.Marshal(struct {
		Version          int                  `json:"version"`
		Provider         string               `json:"provider"`
		PayloadVersion   int                  `json:"payloadVersion"`
		EvaluatorVersion int                  `json:"evaluatorVersion"`
		Registration     *CaptureRegistration `json:"registration,omitempty"`
	}{CaptureEnvelopeVersion, h.Provider, h.PayloadVersion, h.EvaluatorVersion, h.Registration})
	if err != nil {
		return nil, err
	}
	out := append(head[:len(head)-1:len(head)-1], `,"payload":`...)
	out = append(out, payload...)
	return append(out, '}'), nil
}

// CaptureReaders is the installed compatibility a capture is read against,
// the provider registry (*provider.Registry). Neither check may fall back to
// another provider or version.
type CaptureReaders interface {
	// CheckCapture fails unless the installed provider for contract reads
	// payloads of the given version.
	CheckCapture(contract string, payloadVersion int) error
	// CheckEvaluator fails unless the installed provider for contract
	// evaluates with the given evaluator version.
	CheckEvaluator(contract string, evaluatorVersion int) error
}

// CaptureDocument is a capture document read through ReadCapture.
type CaptureDocument struct {
	Header CaptureHeader
	// Payload is the provider payload as read: the whole document for a
	// legacy version, the envelope's payload otherwise. Nothing is
	// re-encoded.
	Payload json.RawMessage
	// v2 is a decoded and validated envelope payload 2 of the Kyverno
	// provider; a legacy CaptureV2 is decoded by V2 when asked for.
	v2 *CaptureV2
}

// ReadCapture is the capture compatibility boundary. It identifies the
// document's provider, payload and evaluator and accepts it only when an
// installed provider reads that payload version. Every rejection wraps
// ErrUnsupportedCapture and names what is unsupported:
//
//   - a document without a version, or with a version other than 1, 2 or 3
//   - a version 1 or 2 document carrying an envelope field (provider,
//     payloadVersion, evaluatorVersion or payload): older readers would
//     ignore it and read the document as Kyverno's
//   - an envelope with an unknown or missing field, no provider (never the
//     registry default), a version below 1, or a payload that is not a
//     JSON object
//   - a provider that is not installed, or a payload version it does not
//     read
//   - an envelope recording a registration that is incomplete, read by
//     readers without RegistrationReaders (a built-in provider's reader),
//     or refused by their CheckRegistration (another registration, or a
//     registered provider's capture without one)
//   - a Kyverno envelope payload that is not exactly a valid CaptureV2 of
//     the header's payload version
//
// A legacy document is not decoded here: V2 decodes it exactly as readers
// before the envelope did, so retained captures keep their bytes and their
// interpretation. Another provider's payload is returned as read, for that
// provider to decode and validate.
//
// ReadCapture does not check the evaluator, a separate dimension: a reader
// that evaluates or replays a retained capture, or vouches that it can (the
// storage backend's package validation), calls CheckEvaluator as well.
func ReadCapture(raw []byte, readers CaptureReaders) (CaptureDocument, error) {
	if readers == nil {
		return CaptureDocument{}, fmt.Errorf("%w: no installed providers to read it with", ErrUnsupportedCapture)
	}
	h, payload, err := readHeader(raw)
	if err != nil {
		return CaptureDocument{}, err
	}
	if err := readers.CheckCapture(h.Provider, h.PayloadVersion); err != nil {
		return CaptureDocument{}, fmt.Errorf("%w: %s: %w", ErrUnsupportedCapture, h, err)
	}
	if rr, ok := readers.(RegistrationReaders); ok {
		if err := rr.CheckRegistration(h.Provider, h.Registration); err != nil {
			return CaptureDocument{}, fmt.Errorf("%w: %s: %w", ErrUnsupportedCapture, h, err)
		}
	} else if h.Registration != nil {
		return CaptureDocument{}, fmt.Errorf("%w: %s: a registered external provider's capture is read only by a reader of registered providers, not by built-in providers' readers",
			ErrUnsupportedCapture, h)
	}
	d := CaptureDocument{Header: h, Payload: payload}
	if err := d.decodeEnvelope(); err != nil {
		return CaptureDocument{}, err
	}
	return d, nil
}

// CheckEvaluator fails unless the capture's installed provider evaluates
// with the evaluator version the capture records. A capture recorded under
// other semantics is never evaluated with this build's.
func (d CaptureDocument) CheckEvaluator(readers CaptureReaders) error {
	if readers == nil {
		return fmt.Errorf("%w: no installed providers to evaluate it with", ErrUnsupportedCapture)
	}
	if err := readers.CheckEvaluator(d.Header.Provider, d.Header.EvaluatorVersion); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrUnsupportedCapture, d.Header, err)
	}
	return nil
}

// V2 returns the capture's Kyverno payload 2, from either a legacy version
// 2 document or an envelope. Any other capture is an error, never an empty
// CaptureV2.
func (d CaptureDocument) V2() (CaptureV2, error) {
	if d.Header.Provider != LegacyProvider || d.Header.PayloadVersion != CaptureV2Version {
		return CaptureV2{}, fmt.Errorf("%w: %s is not a %s payload %d (CaptureV2)", ErrUnsupportedCapture, d.Header, LegacyProvider, CaptureV2Version)
	}
	if d.v2 != nil {
		return *d.v2, nil
	}
	if !d.Header.Legacy() {
		return CaptureV2{}, fmt.Errorf("%w: %s was not read through ReadCapture", ErrUnsupportedCapture, d.Header)
	}
	// Exactly the decoding of every reader before the envelope.
	var c CaptureV2
	if err := json.Unmarshal(d.Payload, &c); err != nil {
		return CaptureV2{}, fmt.Errorf("%w: %s: %v", ErrUnsupportedCapture, d.Header, err)
	}
	return c, nil
}

// readCaptureV2 reads a Kyverno payload 2 document, legacy or envelope,
// for the collector's own package verification. It checks no installed
// provider: the collector owns this payload.
func readCaptureV2(raw []byte) (CaptureV2, error) {
	h, payload, err := readHeader(raw)
	if err != nil {
		return CaptureV2{}, err
	}
	d := CaptureDocument{Header: h, Payload: payload}
	if err := d.decodeEnvelope(); err != nil {
		return CaptureV2{}, err
	}
	return d.V2()
}

// readHeader identifies a capture document. It returns the provider payload:
// the whole legacy document, or the envelope's payload.
func readHeader(raw []byte) (CaptureHeader, json.RawMessage, error) {
	var probe struct {
		Version          *int            `json:"version"`
		Provider         json.RawMessage `json:"provider"`
		PayloadVersion   json.RawMessage `json:"payloadVersion"`
		EvaluatorVersion json.RawMessage `json:"evaluatorVersion"`
		Payload          json.RawMessage `json:"payload"`
		Registration     json.RawMessage `json:"registration"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return CaptureHeader{}, nil, fmt.Errorf("%w: %v", ErrUnsupportedCapture, err)
	}
	if probe.Version == nil {
		return CaptureHeader{}, nil, fmt.Errorf("%w: the document has no version", ErrUnsupportedCapture)
	}
	switch v := *probe.Version; v {
	case 1, CaptureV2Version:
		if probe.Provider != nil || probe.PayloadVersion != nil || probe.EvaluatorVersion != nil || probe.Payload != nil || probe.Registration != nil {
			return CaptureHeader{}, nil, fmt.Errorf("%w: a version %d capture has no provider, payload, evaluator or registration fields; a provider-discriminated capture is version %d",
				ErrUnsupportedCapture, v, CaptureEnvelopeVersion)
		}
		return CaptureHeader{Version: v, Provider: LegacyProvider, PayloadVersion: v, EvaluatorVersion: LegacyEvaluatorVersion}, raw, nil
	case CaptureEnvelopeVersion:
		return readEnvelope(raw)
	default:
		return CaptureHeader{}, nil, fmt.Errorf("%w: capture version %d is not supported (this build reads 1, 2 and %d)", ErrUnsupportedCapture, v, CaptureEnvelopeVersion)
	}
}

func readEnvelope(raw []byte) (CaptureHeader, json.RawMessage, error) {
	var e CaptureEnvelope
	if err := decodeStrict(raw, &e); err != nil {
		return CaptureHeader{}, nil, fmt.Errorf("%w: capture envelope: %v", ErrUnsupportedCapture, err)
	}
	h := CaptureHeader{Version: e.Version, Provider: e.Provider, PayloadVersion: e.PayloadVersion, EvaluatorVersion: e.EvaluatorVersion, Registration: e.Registration}
	if e.Registration != nil {
		if err := e.Registration.Validate(); err != nil {
			return h, nil, fmt.Errorf("%w: %s: %w", ErrUnsupportedCapture, h, err)
		}
	}
	switch {
	case e.Provider == "":
		return h, nil, fmt.Errorf("%w: the capture envelope names no provider", ErrUnsupportedCapture)
	case e.PayloadVersion < 1 || e.EvaluatorVersion < 1:
		return h, nil, fmt.Errorf("%w: %s: payload and evaluator versions start at 1", ErrUnsupportedCapture, h)
	case len(e.Payload) == 0 || e.Payload[0] != '{':
		return h, nil, fmt.Errorf("%w: %s: the payload is not a JSON object", ErrUnsupportedCapture, h)
	}
	return h, e.Payload, nil
}

// decodeEnvelope decodes and validates a Kyverno envelope payload. The
// envelope is new, so unlike a legacy document its payload is decoded
// strictly: it must be exactly a valid CaptureV2 of the header's payload
// version. Kyverno payload 1 exists only as a legacy version 1 document.
// Other providers' payloads are theirs to decode.
func (d *CaptureDocument) decodeEnvelope() error {
	h := d.Header
	if h.Legacy() || h.Provider != LegacyProvider {
		return nil
	}
	if h.PayloadVersion != CaptureV2Version {
		return fmt.Errorf("%w: %s: %s payload %d is read only as a legacy version %d document", ErrUnsupportedCapture, h, LegacyProvider, h.PayloadVersion, h.PayloadVersion)
	}
	var c CaptureV2
	if err := decodeStrict(d.Payload, &c); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrUnsupportedCapture, h, err)
	}
	// Validate also requires the payload's own version to be 2.
	if err := c.Validate(); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrUnsupportedCapture, h, err)
	}
	d.v2 = &c
	return nil
}

// decodeStrict decodes a JSON value with no unknown fields. Its callers pass
// one complete value: readHeader has already rejected trailing data.
func decodeStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
