package v1alpha1_test

import (
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/crdtest"
)

const fp1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
const fp2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

func runWithIntent(t *testing.T, intent map[string]any) map[string]any {
	t.Helper()
	o := obj(t, `apiVersion: compliance.erenius.io/v1alpha1
kind: AssessmentRun
metadata: {name: baseline-audit-manual-1}
spec:
  bindingRef: {name: baseline-audit}
  scope: Binding
`)
	if intent != nil {
		o["status"] = map[string]any{"signingIntent": intent}
	}
	return o
}

func intent(mode, secret string, key map[string]any) map[string]any {
	in := map[string]any{"mode": mode, "destinationUID": "dest-uid", "destinationGeneration": 3,
		"archiveSha256": strings.Repeat("ab", 32), "preparedAt": "2026-11-13T12:00:00Z"}
	if secret != "" {
		in["secretName"] = secret
	}
	if key != nil {
		in["key"] = key
	}
	return in
}

func key(fp string) map[string]any {
	return map[string]any{"fingerprint": fp, "algorithm": "ecdsa-sha2-256-nistp256", "publicKey": "-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----\n",
		"pinnedAt": "2026-11-13T12:00:01Z"}
}

// A run's signing intent is written once: it cannot be removed, its policy,
// destination, Secret and archive never change, and its key is set once.
func TestSigningIntentIsImmutable(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["AssessmentRun"]
	for name, o := range map[string]map[string]any{
		"disabled":                runWithIntent(t, intent("Disabled", "", nil)),
		"required without key":    runWithIntent(t, intent("Required", "signing-a", nil)),
		"required with key":       runWithIntent(t, intent("Required", "signing-a", key(fp1))),
		"no intent (pre-upgrade)": runWithIntent(t, nil),
	} {
		if errs := v.Validate(o); len(errs) > 0 {
			t.Errorf("%s rejected: %v", name, errs.ToAggregate())
		}
	}
	for name, o := range map[string]map[string]any{
		"required without secret": runWithIntent(t, intent("Required", "", nil)),
		"disabled with secret":    runWithIntent(t, intent("Disabled", "s", nil)),
		"disabled with key":       runWithIntent(t, intent("Disabled", "", key(fp1))),
		"bad fingerprint":         runWithIntent(t, intent("Required", "s", key("sha256:xyz"))),
	} {
		if errs := v.Validate(o); len(errs) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	for name, c := range map[string]struct {
		next, prev map[string]any
		want       string
	}{
		"removed":         {runWithIntent(t, nil), runWithIntent(t, intent("Required", "signing-a", key(fp1))), "never removed"},
		"downgraded":      {runWithIntent(t, intent("Disabled", "", nil)), runWithIntent(t, intent("Required", "signing-a", nil)), "immutable"},
		"upgraded":        {runWithIntent(t, intent("Required", "signing-a", nil)), runWithIntent(t, intent("Disabled", "", nil)), "immutable"},
		"secret switched": {runWithIntent(t, intent("Required", "signing-b", nil)), runWithIntent(t, intent("Required", "signing-a", nil)), "key Secret is immutable"},
		"key replaced":    {runWithIntent(t, intent("Required", "signing-a", key(fp2))), runWithIntent(t, intent("Required", "signing-a", key(fp1))), "set once"},
		"key removed":     {runWithIntent(t, intent("Required", "signing-a", nil)), runWithIntent(t, intent("Required", "signing-a", key(fp1))), "set once"},
		"archive switched": {func() map[string]any {
			i := intent("Required", "signing-a", nil)
			i["archiveSha256"] = strings.Repeat("cd", 32)
			return runWithIntent(t, i)
		}(), runWithIntent(t, intent("Required", "signing-a", nil)), "immutable"},
	} {
		errs := v.ValidateUpdate(c.next, c.prev)
		if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), c.want) {
			t.Errorf("%s: want %q, got %v", name, c.want, errs.ToAggregate())
		}
	}
	// The one allowed transition: pinning the key of a keyless Required intent.
	if errs := v.ValidateUpdate(runWithIntent(t, intent("Required", "signing-a", key(fp1))), runWithIntent(t, intent("Required", "signing-a", nil))); len(errs) > 0 {
		t.Fatalf("pinning the key rejected: %v", errs.ToAggregate())
	}
	if errs := v.ValidateUpdate(runWithIntent(t, intent("Required", "signing-a", nil)), runWithIntent(t, nil)); len(errs) > 0 {
		t.Fatalf("recording an intent rejected: %v", errs.ToAggregate())
	}
}
