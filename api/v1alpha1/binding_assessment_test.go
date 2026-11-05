package v1alpha1_test

import (
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/crdtest"
)

const assessedBinding = `
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata: {name: b}
spec:
  profileRef: {name: baseline}
  namespaceSelector: {matchLabels: {env: prod}}
  mode: Audit
`

func TestAssessmentSettingsDefault(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	for name, patch := range map[string]string{
		"omitted":      `{}`,
		"empty object": `{"spec": {"assessment": {}}}`,
		"partial":      `{"spec": {"assessment": {"interval": "1h"}}}`,
		// null is pruned and defaulted, never stored (see BindingAssessment).
		"null settings": `{"spec": {"assessment": {"interval": null, "retention": null}}}`,
		"null object":   `{"spec": {"assessment": null}}`,
	} {
		t.Run(name, func(t *testing.T) {
			o := obj(t, assessedBinding)
			mergePatch(t, o, patch)
			if errs := crds["ComplianceBinding"].Validate(o); len(errs) > 0 {
				t.Fatal(errs.ToAggregate())
			}
			a := o["spec"].(map[string]any)["assessment"].(map[string]any)
			want := map[string]string{"interval": "24h", "maxEvidenceAge": "2h", "collectionTimeout": "5m", "retention": "2160h"}
			if name == "partial" {
				want["interval"] = "1h"
			}
			for k, v := range want {
				if a[k] != v {
					t.Errorf("%s = %v, want %s", k, a[k], v)
				}
			}
		})
	}
}

func TestAssessmentSettingsRejectInvalidDurations(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	for value, expect := range map[string]string{
		`"0s"`:                  "must be a positive duration",
		`"0h0m"`:                "must be a positive duration",
		`"-1h"`:                 "must be a duration such as",
		`"90d"`:                 "must be a duration such as",
		`"0 * * * *"`:           "must be a duration such as",
		`"@daily"`:              "must be a duration such as",
		`"1 h"`:                 "must be a duration such as",
		`"9999999999999999h"`:   "spec.assessment.interval",
		`""`:                    "spec.assessment.interval",
		`24`:                    "spec.assessment.interval",
		`"100000000000000000h"`: "spec.assessment.interval",
	} {
		t.Run(value, func(t *testing.T) {
			o := obj(t, assessedBinding)
			mergePatch(t, o, `{"spec": {"assessment": {"interval": `+value+`}}}`)
			errs := crds["ComplianceBinding"].Validate(o)
			if len(errs) == 0 {
				t.Fatalf("accepted interval %s", value)
			}
			if got := errs.ToAggregate().Error(); !strings.Contains(got, expect) {
				t.Fatalf("want %q, got %q", expect, got)
			}
		})
	}
	o := obj(t, assessedBinding)
	mergePatch(t, o, `{"spec": {"assessment": {"interval": "90m", "maxEvidenceAge": "1h30m", "collectionTimeout": "45s", "retention": "8760h"}}}`)
	if errs := crds["ComplianceBinding"].Validate(o); len(errs) > 0 {
		t.Fatal(errs.ToAggregate())
	}
}

func TestEnforcementEpochTransitions(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	v := crds["ComplianceBinding"]
	with := func(epoch string, patch string) map[string]any {
		o := obj(t, assessedBinding)
		if epoch != "" {
			mergePatch(t, o, `{"spec": {"enforcementEpoch": `+epoch+`}}`)
		}
		mergePatch(t, o, patch)
		return o
	}
	cases := []struct {
		name     string
		old, new map[string]any
		ok       bool
	}{
		{"reporting-only keeps epoch", with("2", ``), with("2", `{"spec": {"assessment": {"interval": "1h"}}}`), true},
		{"reporting-only bump rejected", with("2", ``), with("3", `{"spec": {"assessment": {"interval": "1h"}}}`), false},
		{"mode change increments", with("2", ``), with("3", `{"spec": {"mode": "Deny"}}`), true},
		{"selector change increments", with("2", ``), with("3", `{"spec": {"namespaceSelector": {"matchLabels": {"env": "dev"}}}}`), true},
		{"profile change increments", with("2", ``), with("3", `{"spec": {"profileRef": {"name": "strict"}}}`), true},
		{"enforcement change without increment", with("2", ``), with("2", `{"spec": {"mode": "Deny"}}`), false},
		{"forged jump", with("2", ``), with("7", `{"spec": {"mode": "Deny"}}`), false},
		{"reset", with("5", ``), with("1", `{"spec": {"mode": "Deny"}}`), false},
		{"removed", with("2", ``), with("", ``), false},
		{"migration: epoch-less binding gains one", with("", ``), with("4", `{"spec": {"assessment": {"interval": "1h"}}}`), true},
		{"migration: epoch-less stays epoch-less", with("", ``), with("", `{"spec": {"assessment": {"interval": "1h"}}}`), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if errs := v.Validate(copyObj(c.old)); len(errs) > 0 {
				t.Fatal("old object invalid:", errs.ToAggregate())
			}
			errs := v.ValidateUpdate(copyObj(c.new), copyObj(c.old))
			if c.ok && len(errs) > 0 {
				t.Fatalf("rejected: %v", errs.ToAggregate())
			}
			if !c.ok && (len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), "enforcementEpoch")) {
				t.Fatalf("accepted or wrong error: %v", errs.ToAggregate())
			}
		})
	}
	o := with("0", ``)
	if errs := v.Validate(o); len(errs) == 0 {
		t.Fatal("epoch 0 accepted")
	}
}
