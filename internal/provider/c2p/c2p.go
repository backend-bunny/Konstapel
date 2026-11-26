// Package c2p is the C2P provider the konstapel-provider plugin serves
// (add-assessment-provider-contract 4.2): the pinned C2P-Go v2
// Configure/Generate/GetResults contract, dispatched on the capture it is
// configured with. The capture is read through the capture boundary
// against the installed providers, and only a capture this build both
// reads and evaluates with its recorded evaluator is converted:
//
//   - no capture (generate, deliver, acceptance) or a version 1 prototype
//     capture: the prototype provider, assessment.Provider, unchanged. It
//     renders the vendored content locally and reconciles the capture.
//   - a Kyverno payload 2 capture, legacy or envelope, with its package's
//     evaluation file beside it: collector.SnapshotProvider, the conversion
//     continuous export dispatches to in process.
//   - anything else, including another installed provider: an explicit
//     error. No OSCAL is guessed for it and it is never read as Kyverno's.
//
// Every path reads only local files. None of them reaches a cluster, a
// registry, the content cache or a scanner.
package c2p

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
)

// prototypePayload is the payload version of the prototype's capture
// (assessment.Capture, document version 1).
const prototypePayload = 1

// Provider is the dispatching C2P provider.
type Provider struct {
	// Readers is the installed compatibility captures are read against;
	// nil is the production registry.
	Readers collector.CaptureReaders
	impl    policy.Provider
}

var _ policy.Provider = (*Provider)(nil)

// Configure selects and configures the provider for the configured
// capture. A failure leaves the provider unconfigured.
func (p *Provider) Configure(ctx context.Context, m map[string]string) error {
	p.impl = nil
	impl, err := p.dispatch(m["capture"])
	if err != nil {
		return err
	}
	if err := impl.Configure(ctx, m); err != nil {
		return err
	}
	p.impl = impl
	return nil
}

func (p *Provider) dispatch(path string) (policy.Provider, error) {
	if path == "" {
		// Policy generation renders the prototype's local content; it
		// reads no capture.
		return &assessment.Provider{}, nil
	}
	readers := p.Readers
	if readers == nil {
		readers = installed.Registry()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	doc, err := collector.ReadCapture(raw, readers)
	if err != nil {
		return nil, err
	}
	if err := doc.CheckEvaluator(readers); err != nil {
		return nil, err
	}
	h := doc.Header
	switch {
	case h.Provider == collector.LegacyProvider && h.PayloadVersion == prototypePayload:
		return &assessment.Provider{}, nil
	case h.Provider == collector.LegacyProvider && h.PayloadVersion == collector.CaptureV2Version:
		ev, err := os.ReadFile(filepath.Join(filepath.Dir(path), collector.EvaluationFile))
		if err != nil {
			return nil, fmt.Errorf("a %s capture is converted with its package's %s: %w", h, collector.EvaluationFile, err)
		}
		s, err := collector.ReadSnapshot(doc, readers, ev)
		if err != nil {
			return nil, err
		}
		return &collector.SnapshotProvider{Snapshot: s}, nil
	default:
		return nil, fmt.Errorf("%w: %s has no C2P conversion in this build; no OSCAL is produced from it", collector.ErrUnsupportedCapture, h)
	}
}

// Generate generates with the configured provider: the prototype renders
// local policy artifacts, and a frozen snapshot refuses.
func (p *Provider) Generate(ctx context.Context, pl policy.Policy) error {
	if p.impl == nil {
		return errors.New("provider not configured")
	}
	return p.impl.Generate(ctx, pl)
}

// GetResults converts with the configured provider.
func (p *Provider) GetResults(ctx context.Context, pl policy.Policy) (policy.PVPResult, error) {
	if p.impl == nil {
		return policy.PVPResult{}, errors.New("provider not configured")
	}
	return p.impl.GetResults(ctx, pl)
}
