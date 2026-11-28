package reporttest_test

import (
	"slices"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/bundletest"
	"github.com/backend-bunny/Konstapel/internal/bundle/content"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

// reportingBundle is a verified-shape bundle of reporting-only check
// definitions for the test-only provider (add-assessment-provider-contract
// 6.2): its descriptor and the definitions as content presents them.
func reportingBundle(t *testing.T, checks ...bundletest.ReportingCheck) (*bundle.Descriptor, map[string]*bundle.CheckDefinition) {
	t.Helper()
	api, kind, _ := cutKind(reporttest.CheckKind)
	a, err := bundletest.Reporting("../../..", bundletest.ReportingOptions{Contract: reporttest.Contract, APIVersion: api, Kind: kind, Checks: checks})
	if err != nil {
		t.Fatal(err)
	}
	d, files, err := bundle.Unpack(a.Layer)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.VerifyPayload(files); err != nil {
		t.Fatal(err)
	}
	if err := bundle.ValidateContent(d, files); err != nil {
		t.Fatal(err)
	}
	defs := map[string]*bundle.CheckDefinition{}
	for _, p := range d.Policies {
		def, err := bundle.ParseCheckDefinition(files[p.Path].Data)
		if err != nil {
			t.Fatal(err)
		}
		defs[p.Name] = def
	}
	return d, defs
}

// cutKind splits "<group>/<version>/<Kind>" into apiVersion and kind.
func cutKind(k string) (string, string, bool) {
	i := strings.LastIndex(k, "/")
	return k[:i], k[i+1:], i > 0
}

// The test-only provider's bundle is compatible only where its contract
// is selectable: in a test registry, never under the production one.
func TestReportingContentCompatibility(t *testing.T) {
	d, _ := reportingBundle(t)
	if v := (content.Compatibility{Controller: "0.3.0"}).Check(d); v.Compatible || !strings.Contains(strings.Join(v.Reasons, ";"), reporttest.Contract) {
		t.Fatalf("production compatibility accepts the test-only contract: %+v", v)
	}
	if v := (content.Compatibility{Controller: "0.3.0", Providers: installed.Registry().Contracts()}).Check(d); v.Compatible {
		t.Fatalf("the installed contracts accept the test-only contract: %+v", v)
	}
	if v := (content.Compatibility{Controller: "0.3.0", Providers: testRegistry().Contracts()}).Check(d); !v.Compatible {
		t.Fatalf("the test registry's contracts reject the test-only content: %v", v.Reasons)
	}
	if _, err := installed.Registry().Lookup(reporttest.Contract); err == nil {
		t.Fatal("the production registry selects the test-only provider")
	}
}

// selection builds a selection from verified definitions, exactly as
// content presents them: each check's kind is its definition's.
func contentSelection(d *bundle.Descriptor, defs map[string]*bundle.CheckDefinition, mode v1alpha1.EnforcementMode, params map[string]string) provider.Selection {
	sel := provider.Selection{Provider: d.Compatibility.Provider, Mode: mode}
	for _, p := range d.Policies {
		c := provider.CheckSelection{Name: p.Name, Kind: defs[p.Name].CheckKind()}
		if raw, ok := params[p.Name]; ok {
			c.Parameters = &apiextensionsv1.JSON{Raw: []byte(raw)}
		}
		sel.Checks = append(sel.Checks, c)
	}
	return sel
}

// The descriptor decides kinds, modes and parameters of content-defined
// checks: a declared kind in Audit is a reporting-only plan, and an
// undeclared kind, Deny, or parameters outside the kind's descriptor
// schema reject the whole selection.
func TestReportingContentSelection(t *testing.T) {
	r := testRegistry()
	d, defs := reportingBundle(t)
	plan, errs := r.Select(contentSelection(d, defs, v1alpha1.ModeAudit, map[string]string{"image-posture-current": `{"maxEvidenceAge":"24h"}`}))
	if len(errs) > 0 || plan.Provider != reporttest.Contract || plan.Delivery || len(plan.Checks) != 1 || plan.Checks[0].Kind != reporttest.CheckKind {
		t.Fatalf("plan %+v, errors %v", plan, errs)
	}

	reason := func(sel provider.Selection) []provider.SelectionReason {
		plan, errs := r.Select(sel)
		if plan != nil {
			t.Fatalf("a rejected selection has a plan: %+v", plan)
		}
		var out []provider.SelectionReason
		for _, e := range errs {
			out = append(out, e.Reason)
		}
		return out
	}
	if got := reason(contentSelection(d, defs, v1alpha1.ModeDeny, nil)); !slices.Equal(got, []provider.SelectionReason{provider.ReasonUnsupportedMode}) {
		t.Errorf("Deny: %v", got)
	}
	for _, bad := range []string{`{"maxEvidenceAge":"soon"}`, `{"severity":"HIGH"}`, `[]`} {
		if got := reason(contentSelection(d, defs, v1alpha1.ModeAudit, map[string]string{"image-posture-current": bad})); !slices.Equal(got, []provider.SelectionReason{provider.ReasonInvalidParameters}) {
			t.Errorf("parameters %s: %v", bad, got)
		}
	}

	// A well-formed definition of a kind no provider declares validates as
	// content and is rejected by selection.
	undeclared, udefs := reportingBundle(t, bundletest.ReportingCheck{Name: "image-posture-current",
		Definition: bundletest.ReportingDefinition("reporttest.konstapel.io/v1", "ImageSignature", "image-posture-current")})
	if got := reason(contentSelection(undeclared, udefs, v1alpha1.ModeAudit, nil)); !slices.Equal(got, []provider.SelectionReason{provider.ReasonUnsupportedCheck}) {
		t.Errorf("undeclared kind: %v", got)
	}
	// A Kyverno kind under the reporting contract is another provider's.
	sel := contentSelection(d, defs, v1alpha1.ModeAudit, nil)
	sel.Checks = append(sel.Checks, provider.CheckSelection{Name: "privileged", Kind: kyverno.CheckKind})
	if got := reason(sel); !slices.Contains(got, provider.ReasonMixedProviders) {
		t.Errorf("mixed kinds: %v", got)
	}
}
