package reporttest_test

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

// A test registry with the real Kyverno descriptor and the synthetic
// reporting one. Only tests can build it.
func registry(t *testing.T) *provider.Registry {
	t.Helper()
	r, err := provider.New(kyverno.Contract, kyverno.Descriptor(), reporttest.Descriptor())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReportingDescriptorIsTestOnlyAndReadOnly(t *testing.T) {
	d := reporttest.Descriptor()
	if !d.TestOnly || d.Contract() != reporttest.Contract {
		t.Fatalf("descriptor %+v", d)
	}
	for _, k := range d.Checks {
		if k.Delivery || len(k.Modes) != 1 || k.Modes[0] != v1alpha1.ModeAudit {
			t.Errorf("check kind %s is not reporting-only: %+v", k.Kind, k)
		}
	}
	if _, err := provider.New(reporttest.Contract, d); err == nil {
		t.Error("a test-only provider was accepted as the default")
	}
}

// Spec: a reporting binding and a Kyverno Deny binding over the same
// namespace resolve independently; the reporting one claims no delivery,
// cannot Deny, and cannot be mixed into a Kyverno binding.
func TestReportingOverlapsKyvernoIndependently(t *testing.T) {
	r := registry(t)
	deny, errs := r.Select(provider.Selection{Mode: v1alpha1.ModeDeny, Checks: []provider.CheckSelection{{Name: "disallow-privileged-containers", Kind: kyverno.CheckKind}}})
	if len(errs) > 0 || deny.Provider != kyverno.Contract || !deny.Delivery {
		t.Fatalf("Kyverno Deny: %+v %v", deny, errs)
	}
	audit, errs := r.Select(provider.Selection{Provider: reporttest.Contract, Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{
		{Name: "no-critical", Kind: reporttest.CheckKind, Parameters: &apiextensionsv1.JSON{Raw: []byte(`{"maxEvidenceAge":"1h"}`)}}}})
	if len(errs) > 0 || audit.Provider != reporttest.Contract || audit.Delivery || audit.CaptureVersion != reporttest.PayloadVersion {
		t.Fatalf("reporting Audit: %+v %v", audit, errs)
	}
	for name, sel := range map[string]provider.Selection{
		"reporting Deny":                 {Provider: reporttest.Contract, Mode: v1alpha1.ModeDeny, Checks: []provider.CheckSelection{{Name: "no-critical", Kind: reporttest.CheckKind}}},
		"mixed":                          {Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{{Name: "a", Kind: kyverno.CheckKind}, {Name: "no-critical", Kind: reporttest.CheckKind}}},
		"reporting checks under Kyverno": {Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{{Name: "no-critical", Kind: reporttest.CheckKind}}},
		"bad parameters": {Provider: reporttest.Contract, Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{
			{Name: "no-critical", Kind: reporttest.CheckKind, Parameters: &apiextensionsv1.JSON{Raw: []byte(`{"maxEvidenceAge":"forever"}`)}}}},
	} {
		if plan, errs := r.Select(sel); plan != nil || len(errs) == 0 {
			t.Errorf("%s accepted: %+v", name, plan)
		}
	}
	again, _ := r.Select(provider.Selection{Mode: v1alpha1.ModeDeny, Checks: []provider.CheckSelection{{Name: "disallow-privileged-containers", Kind: kyverno.CheckKind}}})
	a, _ := json.Marshal(deny)
	b, _ := json.Marshal(again)
	if string(a) != string(b) {
		t.Fatalf("Kyverno selection changed after rejected reporting selections: %s / %s", a, b)
	}
}

// Linking the synthetic provider into any non-test binary fails at startup.
func TestLinkingIntoABinaryPanics(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	cmd := exec.Command("go", "run", "-mod=readonly", "./internal/provider/reporttest/testdata/linked")
	cmd.Dir = "../../.."
	out, err := cmd.CombinedOutput()
	if err == nil || strings.Contains(string(out), "started with") || !strings.Contains(string(out), "test-only and must not be linked") {
		t.Fatalf("binary linking reporttest ran: %v\n%s", err, out)
	}
}
