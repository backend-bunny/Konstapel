package provider_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/provider"
)

const (
	enforceKind = "policies.example.io/v1/EnginePolicy"
	reportKind  = "reports.example.io/v1/ImagePosture"
)

var reportSchema = json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"maxHigh":{"type":"integer","minimum":0}}}`)

func enforcing() provider.Descriptor {
	return provider.Descriptor{Name: "engine", Version: 1, EvaluatorVersion: 1,
		Checks: []provider.CheckKind{{Kind: enforceKind, Delivery: true,
			Modes: []v1alpha1.EnforcementMode{v1alpha1.ModeAudit, v1alpha1.ModeDeny}, Parameters: provider.ParameterContract{Source: provider.ParametersFromContent}}},
		Capture: provider.CaptureCompatibility{Write: 2, Read: []int{1, 2}},
		Reads:   []provider.Read{{Group: "reports.example.io", Version: "v1", Resource: "enginereports", Kind: "EngineReport", Namespaced: true, Verbs: []string{"get", "list", "watch"}}}}
}

func reporting() provider.Descriptor {
	return provider.Descriptor{Name: "posture", Version: 3, EvaluatorVersion: 1,
		Checks: []provider.CheckKind{{Kind: reportKind, Modes: []v1alpha1.EnforcementMode{v1alpha1.ModeAudit},
			Parameters: provider.ParameterContract{Source: provider.ParametersFromDescriptor, Schema: reportSchema}}},
		Capture: provider.CaptureCompatibility{Write: 1, Read: []int{1}},
		Reads:   []provider.Read{{Group: "reports.example.io", Version: "v1", Resource: "posturereports", Kind: "PostureReport", Verbs: []string{"list"}}}}
}

func registry(t *testing.T) *provider.Registry {
	t.Helper()
	r, err := provider.New("engine/v1", enforcing(), reporting())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func params(s string) *apiextensionsv1.JSON { return &apiextensionsv1.JSON{Raw: []byte(s)} }

func TestNewRejectsInconsistentRegistries(t *testing.T) {
	for name, tc := range map[string]struct {
		def   string
		descs func() []provider.Descriptor
		want  string
	}{
		"duplicate name": {"engine/v1", func() []provider.Descriptor {
			d := enforcing()
			d.Version = 2
			return []provider.Descriptor{enforcing(), d}
		}, "registered twice"},
		"duplicate identity": {"engine/v1", func() []provider.Descriptor { return []provider.Descriptor{enforcing(), enforcing()} }, "registered twice"},
		"kind claimed twice": {"engine/v1", func() []provider.Descriptor {
			d := reporting()
			d.Checks[0].Kind = enforceKind
			return []provider.Descriptor{enforcing(), d}
		}, "claimed by engine and posture"},
		"kind declared twice": {"engine/v1", func() []provider.Descriptor {
			d := enforcing()
			d.Checks = append(d.Checks, d.Checks[0])
			return []provider.Descriptor{d}
		}, "declared twice"},
		"no providers":      {"engine/v1", func() []provider.Descriptor { return nil }, "no providers"},
		"default missing":   {"other/v1", func() []provider.Descriptor { return []provider.Descriptor{enforcing()} }, `default provider "other/v1" is not installed`},
		"default wrong ver": {"engine/v2", func() []provider.Descriptor { return []provider.Descriptor{enforcing()} }, "not installed"},
		"default test-only": {"engine/v1", func() []provider.Descriptor {
			d := enforcing()
			d.TestOnly = true
			return []provider.Descriptor{d}
		}, "test-only"},
		"bad name":           {"engine/v1", mutate(func(d *provider.Descriptor) { d.Name = "Engine_1" }), "lowercase DNS label"},
		"version zero":       {"engine/v1", mutate(func(d *provider.Descriptor) { d.Version = 0 }), "version 0"},
		"no evaluator":       {"engine/v1", mutate(func(d *provider.Descriptor) { d.EvaluatorVersion = 0 }), "evaluatorVersion"},
		"no checks":          {"engine/v1", mutate(func(d *provider.Descriptor) { d.Checks = nil }), "no check kinds"},
		"bad kind":           {"engine/v1", mutate(func(d *provider.Descriptor) { d.Checks[0].Kind = "EnginePolicy" }), "group/version/Kind"},
		"no modes":           {"engine/v1", mutate(func(d *provider.Descriptor) { d.Checks[0].Modes = nil }), "no modes"},
		"unknown mode":       {"engine/v1", mutate(func(d *provider.Descriptor) { d.Checks[0].Modes = []v1alpha1.EnforcementMode{"Warn"} }), "not Audit or Deny"},
		"repeated mode":      {"engine/v1", mutate(func(d *provider.Descriptor) { d.Checks[0].Modes = append(d.Checks[0].Modes, v1alpha1.ModeDeny) }), "declared twice"},
		"reporting deny":     {"engine/v1", mutate(func(d *provider.Descriptor) { d.Checks[0].Delivery = false }), "reporting-only"},
		"unknown params":     {"engine/v1", mutate(func(d *provider.Descriptor) { d.Checks[0].Parameters.Source = "Bundle" }), "parameters.source"},
		"schema not used":    {"engine/v1", mutate(func(d *provider.Descriptor) { d.Checks[0].Parameters.Schema = reportSchema }), "only for source Descriptor"},
		"capture unreadable": {"engine/v1", mutate(func(d *provider.Descriptor) { d.Capture.Read = []int{1} }), "readers ship before writers"},
		"capture zero":       {"engine/v1", mutate(func(d *provider.Descriptor) { d.Capture = provider.CaptureCompatibility{} }), "capture.write 0"},
		"write verb":         {"engine/v1", mutate(func(d *provider.Descriptor) { d.Reads[0].Verbs = []string{"list", "create"} }), "not read-only"},
		"read without verbs": {"engine/v1", mutate(func(d *provider.Descriptor) { d.Reads[0].Verbs = nil }), "verbs"},
		"read without kind":  {"engine/v1", mutate(func(d *provider.Descriptor) { d.Reads[0].Kind = "" }), "its kind"},
		"read bad kind":      {"engine/v1", mutate(func(d *provider.Descriptor) { d.Reads[0].Kind = "engineReport" }), "its kind"},
		"read twice":         {"engine/v1", mutate(func(d *provider.Descriptor) { d.Reads = append(d.Reads, d.Reads[0]) }), "declared twice"},
		"prerequisite write verb": {"engine/v1", mutate(func(d *provider.Descriptor) {
			d.Requires = []provider.Prerequisite{{Group: "reports.example.io", Version: "v1", Resource: "clusterreports", Kind: "ClusterReport", Verbs: []string{"get", "create"}}}
		}), "not read-only"},
		"prerequisite without kind": {"engine/v1", mutate(func(d *provider.Descriptor) {
			d.Requires = []provider.Prerequisite{{Group: "reports.example.io", Version: "v1", Resource: "clusterreports", Verbs: []string{"get"}}}
		}), "its kind"},
		"prerequisite also a read": {"engine/v1", mutate(func(d *provider.Descriptor) {
			r := d.Reads[0]
			d.Requires = []provider.Prerequisite{{Group: r.Group, Version: r.Version, Resource: r.Resource, Kind: r.Kind, Namespaced: r.Namespaced, Verbs: r.Verbs}}
		}), "is also a read"},
		"schema not object":   {"engine/v1", reportingWith(`{"type":"string"}`), "must describe an object"},
		"schema remote ref":   {"engine/v1", reportingWith(`{"type":"object","properties":{"a":{"$ref":"https://example.com/s.json"}}}`), "not allowed"},
		"schema invalid json": {"engine/v1", reportingWith(`{"type":`), "parameters.schema"},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := provider.New(tc.def, tc.descs()...)
			if err == nil || r != nil {
				t.Fatalf("registry accepted: %v", r)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func mutate(f func(*provider.Descriptor)) func() []provider.Descriptor {
	return func() []provider.Descriptor {
		d := enforcing()
		f(&d)
		return []provider.Descriptor{d}
	}
}

func reportingWith(schema string) func() []provider.Descriptor {
	return func() []provider.Descriptor {
		d := reporting()
		d.Checks[0].Parameters.Schema = json.RawMessage(schema)
		return []provider.Descriptor{enforcing(), d}
	}
}

func TestRegistryIsImmutable(t *testing.T) {
	d := enforcing()
	d.Requires = []provider.Prerequisite{{Group: "reports.example.io", Version: "v1", Resource: "clusterreports", Kind: "ClusterReport", Verbs: []string{"get"}}}
	r, err := provider.New("engine/v1", d)
	if err != nil {
		t.Fatal(err)
	}
	d.Checks[0].Modes[1] = v1alpha1.ModeAudit
	d.Requires[0].Verbs[0] = "list"
	got := r.Descriptors()
	got[0].Checks[0].Modes[0] = "Changed"
	got[0].Reads[0].Verbs[0] = "delete"
	got[0].Requires[0].Verbs[0] = "delete"
	if l, _ := r.Lookup("engine/v1"); !slices.Equal(l.Checks[0].Modes, []v1alpha1.EnforcementMode{v1alpha1.ModeAudit, v1alpha1.ModeDeny}) || l.Reads[0].Verbs[0] != "get" ||
		l.Requires[0].Verbs[0] != "get" {
		t.Fatalf("registry changed through a caller's copy: %+v", l)
	}
}

func TestLookupDistinguishesUnknownAndIncompatible(t *testing.T) {
	r := registry(t)
	if got := r.Contracts(); !slices.Equal(got, []string{"engine/v1", "posture/v3"}) {
		t.Fatalf("contracts %v", got)
	}
	if d, err := r.Lookup(""); err != nil || d.Contract() != "engine/v1" {
		t.Fatalf("default lookup %v %v", d.Contract(), err)
	}
	for contract, want := range map[string]provider.SelectionReason{
		"scanner/v1":    provider.ReasonUnknownProvider,
		"engine/v2":     provider.ReasonIncompatibleVersion,
		"posture/v1":    provider.ReasonIncompatibleVersion,
		"engine":        provider.ReasonInvalidSelection,
		"/usr/bin/sh":   provider.ReasonInvalidSelection,
		"engine/v1/../": provider.ReasonInvalidSelection,
	} {
		if _, err := r.Lookup(contract); err == nil || err.Reason != want {
			t.Errorf("%s: %v, want %s", contract, err, want)
		}
	}
}

func TestCheckCapture(t *testing.T) {
	r := registry(t)
	for _, ok := range []struct {
		contract string
		version  int
	}{{"engine/v1", 1}, {"engine/v1", 2}, {"", 2}, {"posture/v3", 1}} {
		if err := r.CheckCapture(ok.contract, ok.version); err != nil {
			t.Errorf("%s capture %d: %v", ok.contract, ok.version, err)
		}
	}
	for _, bad := range []struct {
		contract string
		version  int
	}{{"engine/v1", 3}, {"posture/v3", 2}, {"engine/v2", 2}, {"unknown/v1", 1}} {
		if err := r.CheckCapture(bad.contract, bad.version); err == nil {
			t.Errorf("%s capture %d accepted", bad.contract, bad.version)
		}
	}
}

func TestCheckEvaluator(t *testing.T) {
	r := registry(t)
	if err := r.CheckEvaluator("engine/v1", 1); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		contract string
		version  int
		reason   provider.SelectionReason
	}{
		{"engine/v1", 2, provider.ReasonIncompatibleVersion},
		{"engine/v1", 0, provider.ReasonIncompatibleVersion},
		{"engine/v2", 1, provider.ReasonIncompatibleVersion},
		{"unknown/v1", 1, provider.ReasonUnknownProvider},
		{"./engine", 1, provider.ReasonInvalidSelection},
	} {
		err := r.CheckEvaluator(bad.contract, bad.version)
		var serr *provider.SelectionError
		if !errors.As(err, &serr) || serr.Reason != bad.reason {
			t.Errorf("%s evaluator %d: %v, want %s", bad.contract, bad.version, err, bad.reason)
		}
	}
}

// ReportingOnly decides a capture's content role (collector.ContentUse): a
// provider whose kinds all deliver nothing uses the run's frozen
// selection. One delivering kind makes it a provider with applied content.
// It never falls back to the default provider.
func TestReportingOnly(t *testing.T) {
	mixed := enforcing()
	mixed.Name = "mixed"
	report := reporting().Checks[0]
	mixed.Checks[0].Kind, report.Kind = "policies.mixed.io/v1/EnginePolicy", "reports.mixed.io/v1/ImagePosture"
	mixed.Checks = append(mixed.Checks, report)
	r, err := provider.New("engine/v1", enforcing(), reporting(), mixed)
	if err != nil {
		t.Fatal(err)
	}
	for contract, want := range map[string]bool{"engine/v1": false, "posture/v3": true, "mixed/v1": false} {
		if got, err := r.ReportingOnly(contract); err != nil || got != want {
			t.Errorf("%s: %v %v, want %v", contract, got, err, want)
		}
	}
	for contract, reason := range map[string]provider.SelectionReason{
		"":           provider.ReasonInvalidSelection,
		"posture/v1": provider.ReasonIncompatibleVersion,
		"unknown/v1": provider.ReasonUnknownProvider,
	} {
		got, err := r.ReportingOnly(contract)
		var serr *provider.SelectionError
		if got || !errors.As(err, &serr) || serr.Reason != reason {
			t.Errorf("%q: %v %v, want %s", contract, got, err, reason)
		}
	}
}

func TestSelect(t *testing.T) {
	r := registry(t)
	engineCheck := func(name string) provider.CheckSelection {
		return provider.CheckSelection{Name: name, Kind: enforceKind}
	}
	reportCheck := func(name string) provider.CheckSelection {
		return provider.CheckSelection{Name: name, Kind: reportKind}
	}
	type want struct {
		reason provider.SelectionReason
		check  string
	}
	for name, tc := range map[string]struct {
		sel  provider.Selection
		want []want
		plan *provider.Plan
	}{
		"implied default": {
			sel:  provider.Selection{Mode: v1alpha1.ModeDeny, Checks: []provider.CheckSelection{engineCheck("b"), engineCheck("a")}},
			plan: &provider.Plan{Provider: "engine/v1", EvaluatorVersion: 1, CaptureVersion: 2, Mode: v1alpha1.ModeDeny, Delivery: true, Checks: []provider.PlannedCheck{{Name: "a", Kind: enforceKind}, {Name: "b", Kind: enforceKind}}},
		},
		"reporting audit": {
			sel:  provider.Selection{Provider: "posture/v3", Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{reportCheck("x")}},
			plan: &provider.Plan{Provider: "posture/v3", EvaluatorVersion: 1, CaptureVersion: 1, Mode: v1alpha1.ModeAudit, Delivery: false, Checks: []provider.PlannedCheck{{Name: "x", Kind: reportKind}}},
		},
		"reporting deny": {
			sel:  provider.Selection{Provider: "posture/v3", Mode: v1alpha1.ModeDeny, Checks: []provider.CheckSelection{reportCheck("x")}},
			want: []want{{provider.ReasonUnsupportedMode, "x"}},
		},
		"unknown provider": {
			sel:  provider.Selection{Provider: "scanner/v1", Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{engineCheck("a")}},
			want: []want{{provider.ReasonUnknownProvider, ""}},
		},
		"incompatible version": {
			sel:  provider.Selection{Provider: "engine/v2", Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{engineCheck("a")}},
			want: []want{{provider.ReasonIncompatibleVersion, ""}},
		},
		"executable path": {
			sel:  provider.Selection{Provider: "./konstapel-provider", Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{engineCheck("a")}},
			want: []want{{provider.ReasonInvalidSelection, ""}},
		},
		"mixed providers": {
			sel:  provider.Selection{Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{engineCheck("a"), reportCheck("x")}},
			want: []want{{provider.ReasonMixedProviders, ""}},
		},
		"checks of another provider": {
			sel:  provider.Selection{Provider: "engine/v1", Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{reportCheck("x")}},
			want: []want{{provider.ReasonMixedProviders, "x"}},
		},
		"unsupported kind": {
			sel:  provider.Selection{Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{engineCheck("a"), {Name: "c", Kind: "kyverno.io/v1/ClusterPolicy"}}},
			want: []want{{provider.ReasonUnsupportedCheck, "c"}},
		},
		"invalid mode": {
			sel:  provider.Selection{Mode: "Enforce", Checks: []provider.CheckSelection{engineCheck("a")}},
			want: []want{{provider.ReasonInvalidSelection, ""}},
		},
		"no checks": {
			sel:  provider.Selection{Mode: v1alpha1.ModeAudit},
			want: []want{{provider.ReasonInvalidSelection, ""}},
		},
		"repeated check": {
			sel:  provider.Selection{Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{engineCheck("a"), engineCheck("a")}},
			want: []want{{provider.ReasonInvalidSelection, "a"}},
		},
		"content parameters not rendered": {
			sel:  provider.Selection{Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{{Name: "a", Kind: enforceKind, Parameters: params(`{"x":1}`)}, engineCheck("b")}},
			want: []want{{provider.ReasonInvalidParameters, "a"}},
		},
		"content parameters violate schema": {
			sel: provider.Selection{Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{{Name: "a", Kind: enforceKind, Parameters: params(`{"x":"one"}`),
				Content: provider.ContentParameters{Declared: true, Schema: []byte(`{"type":"object","properties":{"x":{"type":"integer"}}}`), Rendered: true}}}},
			want: []want{{provider.ReasonInvalidParameters, "a"}},
		},
		"content parameters rendered": {
			sel: provider.Selection{Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{{Name: "a", Kind: enforceKind, Parameters: params(`{"x":1}`),
				Content: provider.ContentParameters{Declared: true, Schema: []byte(`{"type":"object","properties":{"x":{"type":"integer"}}}`), Rendered: true}}}},
			plan: &provider.Plan{Provider: "engine/v1", EvaluatorVersion: 1, CaptureVersion: 2, Mode: v1alpha1.ModeAudit, Delivery: true, Checks: []provider.PlannedCheck{{Name: "a", Kind: enforceKind}}},
		},
		"empty parameters are none": {
			sel: provider.Selection{Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{{Name: "a", Kind: enforceKind, Parameters: params(`{}`)},
				{Name: "b", Kind: enforceKind, Parameters: params(` null `)}}},
			plan: &provider.Plan{Provider: "engine/v1", EvaluatorVersion: 1, CaptureVersion: 2, Mode: v1alpha1.ModeAudit, Delivery: true, Checks: []provider.PlannedCheck{{Name: "a", Kind: enforceKind}, {Name: "b", Kind: enforceKind}}},
		},
		"descriptor parameters valid": {
			sel:  provider.Selection{Provider: "posture/v3", Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{{Name: "x", Kind: reportKind, Parameters: params(`{"maxHigh":5}`)}}},
			plan: &provider.Plan{Provider: "posture/v3", EvaluatorVersion: 1, CaptureVersion: 1, Mode: v1alpha1.ModeAudit, Checks: []provider.PlannedCheck{{Name: "x", Kind: reportKind}}},
		},
		"descriptor parameters invalid": {
			sel:  provider.Selection{Provider: "posture/v3", Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{{Name: "x", Kind: reportKind, Parameters: params(`{"maxHigh":-1}`)}, {Name: "y", Kind: reportKind, Parameters: params(`{"other":1}`)}}},
			want: []want{{provider.ReasonInvalidParameters, "x"}, {provider.ReasonInvalidParameters, "y"}},
		},
		"descriptor parameters not an object": {
			sel:  provider.Selection{Provider: "posture/v3", Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{{Name: "x", Kind: reportKind, Parameters: params(`[1]`)}}},
			want: []want{{provider.ReasonInvalidParameters, "x"}},
		},
		"descriptor parameters duplicate keys": {
			sel:  provider.Selection{Provider: "posture/v3", Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{{Name: "x", Kind: reportKind, Parameters: params(`{"maxHigh":1,"maxHigh":9}`)}}},
			want: []want{{provider.ReasonInvalidParameters, "x"}},
		},
		"every reason at once": {
			sel: provider.Selection{Provider: "posture/v3", Mode: v1alpha1.ModeDeny, Checks: []provider.CheckSelection{
				{Name: "x", Kind: reportKind, Parameters: params(`{"maxHigh":-1}`)}, {Name: "z", Kind: "unknown.io/v1/Thing"}}},
			want: []want{{provider.ReasonInvalidParameters, "x"}, {provider.ReasonUnsupportedMode, "x"}, {provider.ReasonUnsupportedCheck, "z"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			plan, errs := r.Select(tc.sel)
			var got []want
			for _, e := range errs {
				got = append(got, want{e.Reason, e.Check})
				if e.Message == "" || e.Error() == "" {
					t.Errorf("error without message: %+v", e)
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("errors %v, want %v (%v)", got, tc.want, errs)
			}
			if len(errs) > 0 && plan != nil {
				t.Fatalf("rejected selection returned a partial plan %+v", plan)
			}
			if tc.plan != nil {
				a, _ := json.Marshal(plan)
				b, _ := json.Marshal(tc.plan)
				if string(a) != string(b) {
					t.Fatalf("plan %s, want %s", a, b)
				}
			}
		})
	}
}

// Descriptor-defined parameters use exactly the bundle parameter semantics.
func TestDescriptorParametersMatchBundleSemantics(t *testing.T) {
	r := registry(t)
	for _, raw := range []string{`{}`, `null`, `{"maxHigh":0}`, `{"maxHigh":2.5}`, `{"maxHigh":"1"}`, `{"x":1}`, `"s"`, `[]`, `{"maxHigh":1,"maxHigh":1}`} {
		_, errs := r.Select(provider.Selection{Provider: "posture/v3", Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{{Name: "x", Kind: reportKind, Parameters: params(raw)}}})
		bundleErr := bundle.ValidatePolicyParameters("x", reportSchema, []byte(raw))
		if (len(errs) == 0) != (bundleErr == nil) {
			t.Errorf("%s: selection errors %v, bundle validation %v", raw, errs, bundleErr)
		}
	}
}

// Selection is independent per binding: a rejected selection does not
// change how another one resolves.
func TestSelectionsAreIndependent(t *testing.T) {
	r := registry(t)
	good := provider.Selection{Mode: v1alpha1.ModeDeny, Checks: []provider.CheckSelection{{Name: "a", Kind: enforceKind}}}
	before, _ := r.Select(good)
	if _, errs := r.Select(provider.Selection{Mode: v1alpha1.ModeAudit, Checks: []provider.CheckSelection{{Name: "a", Kind: enforceKind}, {Name: "x", Kind: reportKind}}}); len(errs) == 0 {
		t.Fatal("mixed selection accepted")
	}
	after, errs := r.Select(good)
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(after)
	if len(errs) > 0 || string(a) != string(b) {
		t.Fatalf("valid selection changed after a rejected one: %s / %s %v", a, b, errs)
	}
}

func TestBindingReasonsAreExistingConditionReasons(t *testing.T) {
	for reason, want := range map[provider.SelectionReason]string{
		provider.ReasonUnknownProvider:     v1alpha1.ReasonContentUnavailable,
		provider.ReasonIncompatibleVersion: v1alpha1.ReasonContentUnavailable,
		provider.ReasonUnsupportedCheck:    v1alpha1.ReasonUnsupportedScope,
		provider.ReasonMixedProviders:      v1alpha1.ReasonInvalidConfiguration,
		provider.ReasonUnsupportedMode:     v1alpha1.ReasonInvalidConfiguration,
		provider.ReasonInvalidParameters:   v1alpha1.ReasonInvalidConfiguration,
		provider.ReasonInvalidSelection:    v1alpha1.ReasonInvalidConfiguration,
	} {
		if got := reason.BindingReason(); got != want {
			t.Errorf("%s maps to %s, want %s", reason, got, want)
		}
	}
}

func TestKindOf(t *testing.T) {
	for _, tc := range [][3]string{
		{"policies.kyverno.io/v1", "ValidatingPolicy", "policies.kyverno.io/v1/ValidatingPolicy"},
		{"v1", "Pod", ""}, {"", "X", ""}, {"a.io/v1", "", ""},
	} {
		if got := provider.KindOf(tc[0], tc[1]); got != tc[2] {
			t.Errorf("KindOf(%q, %q) = %q, want %q", tc[0], tc[1], got, tc[2])
		}
	}
}
