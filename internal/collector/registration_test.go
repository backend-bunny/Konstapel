package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/assessment"
)

// testRegistration is a complete registration identity of the registered
// provider "example-reporting/v1".
var testRegistration = CaptureRegistration{Name: "example-reporting", UID: "uid-example-reporting", Revision: 3,
	ReleaseDigest: "sha256:" + strings.Repeat("1", 64), Protocol: "konstapel.provider.v1", ProtocolRevision: 2}

const registered = "example-reporting/v1"

// registeredReaders read the captures of one frozen registration of
// registered, besides the built-in readers.
type registeredReaders struct {
	readers
	want CaptureRegistration
}

func (r registeredReaders) CheckRegistration(contract string, reg *CaptureRegistration) error {
	switch {
	case contract != registered && reg == nil:
		return nil
	case contract != registered:
		return fmt.Errorf("%s is built in; its captures record no registration", contract)
	case reg == nil:
		return errors.New("a registered provider's capture records its registration")
	case *reg != r.want:
		return fmt.Errorf("the capture is frozen to registration %s uid %s revision %d, not this one", reg.Name, reg.UID, reg.Revision)
	}
	return nil
}

func withRegistration(reg any) func(map[string]any) {
	return func(m map[string]any) { m["registration"] = reg }
}

func registrationJSON(t *testing.T, mutate func(map[string]any)) map[string]any {
	t.Helper()
	b, _ := json.Marshal(testRegistration)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(m)
	}
	return m
}

func TestRegisteredCaptureIdentity(t *testing.T) {
	both := registeredReaders{readers: readers{LegacyProvider: {[]int{1, 2}, 1}, registered: {[]int{1}, 1}}, want: testRegistration}
	payload := []byte(`{"evidence":[]}`)
	reg := testRegistration
	raw, err := json.Marshal(CaptureEnvelope{Version: CaptureEnvelopeVersion, Provider: registered, PayloadVersion: 1, EvaluatorVersion: 1,
		Registration: &reg, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ReadCapture(raw, both)
	if err != nil || doc.Header.Registration == nil || *doc.Header.Registration != testRegistration || string(doc.Payload) != string(payload) {
		t.Fatalf("read %+v %s: %v", doc.Header, doc.Payload, err)
	}
	if !strings.Contains(doc.Header.String(), "registration example-reporting uid uid-example-reporting revision 3") {
		t.Errorf("the header does not name its registration: %s", doc.Header)
	}

	reject := func(name string, raw []byte, r CaptureReaders, why string) {
		t.Helper()
		_, err := ReadCapture(raw, r)
		if !errors.Is(err, ErrUnsupportedCapture) || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: %v, want an unsupported capture naming %q", name, err, why)
		}
	}
	// Built-in providers' readers know no registration: they refuse every
	// capture that records one, never reading it as a built-in capture.
	kyverno := edit(t, envelope(t, LegacyProvider, 2, 1, fixture(t, v2Fixture)), withRegistration(registrationJSON(t, nil)))
	reject("built-in readers, registered capture", raw, readers{LegacyProvider: {[]int{1, 2}, 1}, registered: {[]int{1}, 1}}, "read only by a reader of registered providers")
	reject("built-in readers, Kyverno capture with a registration", kyverno, installedReaders, "read only by a reader of registered providers")
	reject("registered readers, Kyverno capture with a registration", kyverno, both, "is built in")
	// A registered provider's capture names its registration, and only that
	// one.
	reject("no registration", edit(t, raw, func(m map[string]any) { delete(m, "registration") }), both, "records its registration")
	for name, mutate := range map[string]func(map[string]any){
		"another uid":      func(m map[string]any) { m["uid"] = "uid-replaced" },
		"another revision": func(m map[string]any) { m["revision"] = 4 },
		"another release":  func(m map[string]any) { m["releaseDigest"] = "sha256:" + strings.Repeat("2", 64) },
	} {
		reject(name, edit(t, raw, withRegistration(registrationJSON(t, mutate))), both, "frozen to registration")
	}
	// Every field of the registration is required, and no other is read.
	for _, field := range []string{"name", "uid", "revision", "releaseDigest", "protocol", "protocolRevision"} {
		reject("without "+field, edit(t, raw, withRegistration(registrationJSON(t, func(m map[string]any) { delete(m, field) }))), both, "registration")
	}
	reject("tag instead of digest", edit(t, raw, withRegistration(registrationJSON(t, func(m map[string]any) { m["releaseDigest"] = "v1.2.3" }))), both, "release digest")
	reject("unknown registration field", edit(t, raw, withRegistration(registrationJSON(t, func(m map[string]any) { m["endpoint"] = "x" }))), both, "unknown field")
	reject("registration not an object", edit(t, raw, withRegistration("example-reporting")), both, "capture envelope")
	// A legacy document never carries one: an earlier reader would ignore it.
	reject("legacy version 2 with a registration", edit(t, fixture(t, v2Fixture), withRegistration(registrationJSON(t, nil))), both, "registration fields")
}

// The readers of the releases before the registration identity refuse a
// capture that records one (design Decision 10): 0.3.0 and earlier read
// versions 1 and 2 only, through readers unchanged in this build, and this
// build's own envelope reader decodes strictly, so the unreleased builds
// before the field refuse it as an unknown field.
func TestEarlierReadersRefuseRegisteredCaptures(t *testing.T) {
	reg := testRegistration
	raw, err := json.Marshal(CaptureEnvelope{Version: CaptureEnvelopeVersion, Provider: registered, PayloadVersion: 1, EvaluatorVersion: 1,
		Registration: &reg, Payload: []byte(`{"evidence":[]}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureVersion(raw); err == nil {
		t.Error("the earlier releases' version dispatch accepts it")
	}
	var asV2 CaptureV2
	if err := json.Unmarshal(raw, &asV2); err != nil {
		t.Fatal(err)
	}
	if err := asV2.Validate(); err == nil {
		t.Error("the earlier releases' CaptureV2 validation accepts it")
	}
	var asV1 assessment.Capture
	_ = json.Unmarshal(raw, &asV1)
	if _, _, err := assessment.Reconcile(asV1); err == nil {
		t.Error("the prototype's reconciliation accepts it")
	}
	// The envelope as the builds before the field declared it.
	type preRegistrationEnvelope struct {
		Version          int             `json:"version"`
		Provider         string          `json:"provider"`
		PayloadVersion   int             `json:"payloadVersion"`
		EvaluatorVersion int             `json:"evaluatorVersion"`
		Payload          json.RawMessage `json:"payload"`
	}
	var pre preRegistrationEnvelope
	if err := decodeStrict(raw, &pre); err == nil || !strings.Contains(err.Error(), `unknown field "registration"`) {
		t.Errorf("the strict envelope decoding before the field: %v", err)
	}
}
