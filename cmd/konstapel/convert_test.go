package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"

	"github.com/backend-bunny/Konstapel/internal/assessment"
)

// convert re-exports prototype captures only. A continuous package's
// capture is refused before any conversion or output, never reconciled
// and packaged as a prototype capture.
func TestConvertRefusesAContinuousCapture(t *testing.T) {
	saved := startProvider
	t.Cleanup(func() { startProvider = saved })
	converted := false
	startProvider = func(string, map[string]string) (policy.Provider, error) {
		return &convertProbe{converted: &converted}, nil
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "package")
	err = run([]string{"convert", "--root", root, "--output", out,
		"--capture", filepath.Join(root, "testdata/assessments/kyverno-1.19.2-background/capture.json")})
	if err == nil || !strings.Contains(err.Error(), "prototype (version 1) captures only") {
		t.Fatalf("a continuous capture was converted: %v", err)
	}
	if converted {
		t.Fatal("the C2P provider converted a continuous capture for the prototype package")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("convert wrote %s: %v", out, err)
	}
}

// convertProbe records whether results were requested.
type convertProbe struct {
	assessment.Provider
	converted *bool
}

func (p *convertProbe) GetResults(context.Context, policy.Policy) (policy.PVPResult, error) {
	*p.converted = true
	return policy.PVPResult{}, nil
}
