package collector_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

func envelope(t *testing.T, contract string, payloadVersion, evaluatorVersion int, payload []byte) []byte {
	t.Helper()
	b, err := json.Marshal(collector.CaptureEnvelope{Version: collector.CaptureEnvelopeVersion, Provider: contract,
		PayloadVersion: payloadVersion, EvaluatorVersion: evaluatorVersion, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The storage backend's pre-archive validation reads a package's capture
// through the boundary, against the production registry. A legacy package
// validates as before and keeps its bytes. A Kyverno envelope package
// validates with the same meaning, so this build can archive what a later
// writer staged. Unknown providers, payloads and evaluators are refused.
func TestStorageValidationOfCapturePackages(t *testing.T) {
	for name, build := range map[string]func(*testing.T) (string, publication.Descriptor){
		"binding":   collector.ExportedPackage,
		"namespace": collector.NamespacePackage,
	} {
		t.Run(name, func(t *testing.T) {
			dir, d := build(t)
			path := filepath.Join(dir, "capture.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := s3store.ValidatePackage(dir)
			if err != nil {
				t.Fatalf("a legacy package no longer validates: %v", err)
			}
			if got.Digest() != d.Digest() {
				t.Fatal("validation changed the descriptor")
			}
			if after, _ := os.ReadFile(path); !bytes.Equal(after, raw) {
				t.Fatal("validation rewrote the capture")
			}
			write := func(b []byte) {
				t.Helper()
				if err := os.WriteFile(path, b, 0o644); err != nil {
					t.Fatal(err)
				}
				collector.Rehash(t, dir, d)
			}
			write(envelope(t, collector.LegacyProvider, 2, collector.LegacyEvaluatorVersion, raw))
			env, err := s3store.ValidatePackage(dir)
			if err != nil {
				t.Fatalf("a Kyverno envelope package does not validate: %v", err)
			}
			if env.PackageKind != d.PackageKind || !reflect.DeepEqual(env.Scope, d.Scope) || env.Evidence != d.Evidence || env.Outcomes != d.Outcomes {
				t.Fatalf("the envelope package means something else: %+v", env)
			}
			for name, tc := range map[string]struct {
				raw    []byte
				reason provider.SelectionReason
			}{
				"unknown provider":         {envelope(t, "example-scanner/v1", 1, 1, raw), provider.ReasonUnknownProvider},
				"test-only provider":       {envelope(t, "konstapel-reporttest/v1", 1, 1, []byte(`{"payloadVersion":1}`)), provider.ReasonUnknownProvider},
				"no provider":              {envelope(t, "", 2, 1, raw), ""},
				"unknown payload":          {envelope(t, collector.LegacyProvider, 4, 1, raw), provider.ReasonIncompatibleVersion},
				"payload 3 of a CaptureV2": {envelope(t, collector.LegacyProvider, 3, 1, raw), ""},
				"unknown evaluator":        {envelope(t, collector.LegacyProvider, 2, 2, raw), provider.ReasonIncompatibleVersion},
				"unknown version":          {[]byte(`{"version": 4}`), ""},
				"appended to legacy":       {append(bytes.TrimSuffix(bytes.TrimSpace(raw), []byte("}")), []byte(`,"evaluatorVersion":2}`)...), ""},
				"another Kyverno form":     {envelope(t, collector.LegacyProvider, 1, 1, raw), ""},
			} {
				write(tc.raw)
				_, err := s3store.ValidatePackage(dir)
				var serr *provider.SelectionError
				switch {
				case !errors.Is(err, collector.ErrUnsupportedCapture):
					t.Errorf("%s: validated (%v)", name, err)
				case tc.reason != "" && (!errors.As(err, &serr) || serr.Reason != tc.reason):
					t.Errorf("%s: %v, want reason %s", name, err, tc.reason)
				}
			}
		})
	}
}

// A package that records its evaluation inputs (Kyverno payload 3)
// validates, binding and namespace scope alike, only when the recorded
// inputs re-evaluate to its stored evaluation. Validation never rewrites
// it.
func TestStorageValidationOfFrozenInputPackages(t *testing.T) {
	for name, namespace := range map[string]bool{"binding": false, "namespace": true} {
		t.Run(name, func(t *testing.T) {
			dir, d, p := collector.FrozenPackage(t, namespace)
			path := filepath.Join(dir, collector.CaptureFile)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := s3store.ValidatePackage(dir)
			if err != nil {
				t.Fatalf("a payload 3 package does not validate: %v", err)
			}
			if got.Digest() != d.Digest() {
				t.Fatal("validation changed the descriptor")
			}
			if after, _ := os.ReadFile(path); !bytes.Equal(after, raw) {
				t.Fatal("validation rewrote the capture")
			}
			// Another recorded limit is a valid payload 3, but not the one
			// the stored evaluation was made with.
			p.EvaluationInputs.MaxEvidenceAge = "10m0s"
			other, err := collector.EncodeCaptureV3(p, collector.LegacyEvaluatorVersion)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, other, 0o644); err != nil {
				t.Fatal(err)
			}
			collector.Rehash(t, dir, d)
			if _, err := s3store.ValidatePackage(dir); err == nil || !strings.Contains(err.Error(), "not the re-evaluation") {
				t.Fatalf("a package whose inputs do not reproduce its evaluation validated: %v", err)
			}
		})
	}
}
