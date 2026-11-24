package s3store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

// A capture of an installed provider that has no package verification is
// refused, not archived unverified: the boundary reads it, the backend does
// not accept it. The production registry does not install the provider.
func TestPackageCaptureRefusesProvidersWithoutVerification(t *testing.T) {
	var c struct {
		Input json.RawMessage `json:"input"`
	}
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata/providers/conformance/v1/konstapel-reporttest/shared-image-evidence/case.json"))
	if err != nil || json.Unmarshal(raw, &c) != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(collector.CaptureEnvelope{Version: collector.CaptureEnvelopeVersion, Provider: reporttest.Contract, PayloadVersion: reporttest.PayloadVersion, EvaluatorVersion: 1, Payload: c.Input})
	if err != nil {
		t.Fatal(err)
	}
	both, err := provider.New(kyverno.Contract, kyverno.Descriptor(), reporttest.Descriptor())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.ReadCapture(env, both); err != nil {
		t.Fatalf("the boundary does not read an installed provider's capture: %v", err)
	}
	if _, err := packageCapture(env, both); !errors.Is(err, collector.ErrUnsupportedCapture) || !strings.Contains(err.Error(), "cannot verify") {
		t.Fatalf("a capture without package verification accepted: %v", err)
	}
	var serr *provider.SelectionError
	if _, err := packageCapture(env, installed.Registry()); !errors.As(err, &serr) || serr.Reason != provider.ReasonUnknownProvider {
		t.Fatalf("the production registry reads the test-only provider: %v", err)
	}
}
