package v1alpha1_test

import (
	"encoding/json"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/crdtest"
)

// add-evidence-signing-recovery 1.1: the generated EvidenceSigningRequest CRD
// rejects malformed run references, empty or whitespace reasons, malformed
// fingerprints, spec edits, reasons outside a phase's vocabulary, and any
// rewrite of a terminal status; the additive AssessmentRun
// status.signingRecovery keeps its recovered record write-once, and runs
// without recovery keep their exact status bytes. Admission (requester
// attribution, controller-only status) is checked against a real API server
// by TestLiveEvidenceSigningRequestAPI.

const (
	runUID  = "0b1c2d3e-4f50-4617-8899-aabbccddeeff"
	runUID2 = "11111111-2222-4333-8444-555555555555"
	reqUID  = "9f8e7d6c-5b4a-4392-8170-fedcba987654"
	sha     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func signingRequest(t *testing.T) map[string]any {
	t.Helper()
	return obj(t, `apiVersion: compliance.erenius.io/v1alpha1
kind: EvidenceSigningRequest
metadata: {name: recover-baseline-audit-1}
spec:
  run: {name: baseline-audit-manual-1, uid: `+runUID+`}
  reason: Signing key Secret restored after the 2026-11-20 rotation incident (CHG-1234).
`)
}

// attributed is a stored request: admission recorded the requester.
func attributed(t *testing.T) map[string]any {
	t.Helper()
	o := signingRequest(t)
	mergePatch(t, o, `{"spec":{"requestedBy":{"username":"platform-admin","uid":"u-1"}}}`)
	return o
}

func withStatus(t *testing.T, o map[string]any, status string) map[string]any {
	t.Helper()
	o = copyObj(o)
	o["status"] = obj(t, status)
	return o
}

// Status fixtures, in the order the controller writes them.
const (
	statusAccepted = `{"phase":"Pending","reason":"Accepted","requestedBy":{"username":"platform-admin","uid":"u-1"},
		"run":{"name":"baseline-audit-manual-1","uid":"` + runUID + `"},"acceptedAt":"2026-11-24T10:00:00Z",
		"conditions":[{"type":"Complete","status":"False","reason":"Accepted","message":"","lastTransitionTime":"2026-11-24T10:00:00Z"}]}`
	statusRunning = `{"phase":"Running","reason":"Signing","requestedBy":{"username":"platform-admin","uid":"u-1"},
		"run":{"name":"baseline-audit-manual-1","uid":"` + runUID + `"},"keyFingerprint":"` + fp1 + `",
		"acceptedAt":"2026-11-24T10:00:00Z","startedAt":"2026-11-24T10:00:01Z",
		"conditions":[{"type":"Complete","status":"False","reason":"Signing","message":"","lastTransitionTime":"2026-11-24T10:00:01Z"}]}`
	statusSucceeded = `{"phase":"Succeeded","reason":"Recovered","message":"run baseline-audit-manual-1 signature recovery committed",
		"requestedBy":{"username":"platform-admin","uid":"u-1"},"run":{"name":"baseline-audit-manual-1","uid":"` + runUID + `"},
		"keyFingerprint":"` + fp1 + `","publication":{"publicationID":"pub-1","packageSha256":"` + sha + `","signatureSha256":"` + sha + `",
		"publishedAt":"2026-11-24T10:00:05Z","expiresAt":"2027-02-20T00:00:00Z"},
		"acceptedAt":"2026-11-24T10:00:00Z","startedAt":"2026-11-24T10:00:01Z","completedAt":"2026-11-24T10:00:06Z",
		"conditions":[{"type":"Complete","status":"True","reason":"Recovered","message":"","lastTransitionTime":"2026-11-24T10:00:06Z"}]}`
	statusFailed = `{"phase":"Failed","reason":"KeyMismatch","message":"the key Secret holds another fingerprint",
		"requestedBy":{"username":"platform-admin","uid":"u-1"},"run":{"name":"baseline-audit-manual-1","uid":"` + runUID + `"},
		"keyFingerprint":"` + fp1 + `","acceptedAt":"2026-11-24T10:00:00Z","completedAt":"2026-11-24T10:00:02Z",
		"conditions":[{"type":"Complete","status":"True","reason":"KeyMismatch","message":"","lastTransitionTime":"2026-11-24T10:00:02Z"}]}`
)

func TestEvidenceSigningRequestCreateValidation(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["EvidenceSigningRequest"]
	for name, patch := range map[string]string{
		"minimal":              `{}`,
		"confirmed key":        `{"spec":{"expectedKeyFingerprint":"` + fp1 + `"}}`,
		"attributed":           `{"spec":{"requestedBy":{"username":"platform-admin"}}}`,
		"one-character reason": `{"spec":{"reason":"x"}}`,
		"longest reason":       `{"spec":{"reason":"` + strings.Repeat("r", 1024) + `"}}`,
		"dotted run name":      `{"spec":{"run":{"name":"team-a.nightly-1","uid":"` + runUID + `"}}}`,
	} {
		o := signingRequest(t)
		if strings.Contains(patch, `"run":{`) {
			delete(o["spec"].(map[string]any), "run")
		}
		mergePatch(t, o, patch)
		if errs := v.Validate(o); len(errs) > 0 {
			t.Errorf("%s rejected: %v", name, errs.ToAggregate())
		}
	}
	cases := []struct{ name, patch, expect string }{
		{"no run", `{"spec":{"run":null}}`, "spec.run: Required"},
		{"run without name", `{"spec":{"run":{"uid":"` + runUID + `"}}}`, "spec.run.name: Required"},
		{"run without uid", `{"spec":{"run":{"name":"r"}}}`, "spec.run.uid: Required"},
		{"empty run name", `{"spec":{"run":{"name":"","uid":"` + runUID + `"}}}`, "spec.run.name"},
		{"uppercase run name", `{"spec":{"run":{"name":"Baseline","uid":"` + runUID + `"}}}`, "spec.run.name"},
		{"run name with slash", `{"spec":{"run":{"name":"team-a/run","uid":"` + runUID + `"}}}`, "spec.run.name"},
		{"overlong run name", `{"spec":{"run":{"name":"` + strings.Repeat("a", 254) + `","uid":"` + runUID + `"}}}`, "spec.run.name"},
		{"uid not a UUID", `{"spec":{"run":{"name":"r","uid":"run-uid"}}}`, "spec.run.uid"},
		{"uppercase uid", `{"spec":{"run":{"name":"r","uid":"` + strings.ToUpper(runUID) + `"}}}`, "spec.run.uid"},
		{"no reason", `{"spec":{"reason":null}}`, "spec.reason: Required"},
		{"empty reason", `{"spec":{"reason":""}}`, "spec.reason"},
		{"blank reason", `{"spec":{"reason":"   "}}`, "reason must not be blank"},
		{"whitespace reason", `{"spec":{"reason":"\t\n \r"}}`, "reason must not be blank"},
		{"overlong reason", `{"spec":{"reason":"` + strings.Repeat("r", 1025) + `"}}`, "spec.reason"},
		{"fingerprint without algorithm", `{"spec":{"expectedKeyFingerprint":"` + strings.Repeat("1", 64) + `"}}`, "spec.expectedKeyFingerprint"},
		{"uppercase fingerprint", `{"spec":{"expectedKeyFingerprint":"sha256:` + strings.Repeat("A", 64) + `"}}`, "spec.expectedKeyFingerprint"},
		{"short fingerprint", `{"spec":{"expectedKeyFingerprint":"sha256:1111"}}`, "spec.expectedKeyFingerprint"},
		{"blank requester", `{"spec":{"requestedBy":{"username":""}}}`, "spec.requestedBy.username"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := signingRequest(t)
			if strings.Contains(c.patch, `"run":{`) {
				delete(o["spec"].(map[string]any), "run") // replace, not merge
			}
			mergePatch(t, o, c.patch)
			errs := v.Validate(o)
			if len(errs) == 0 {
				t.Fatal("accepted, want rejection")
			}
			if got := errs.ToAggregate().Error(); !strings.Contains(got, c.expect) {
				t.Fatalf("want %q, got %q", c.expect, got)
			}
		})
	}
	// No Secret name, key material or alternative signing policy can be
	// carried: unsupported fields are pruned.
	o := signingRequest(t)
	mergePatch(t, o, `{"spec":{"secretName":"other-key","privateKey":"LS0t","signing":{"mode":"Disabled"}}}`)
	if errs := v.Validate(o); len(errs) > 0 {
		t.Fatal(errs.ToAggregate())
	}
	for _, k := range []string{"secretName", "privateKey", "signing"} {
		if _, ok := o["spec"].(map[string]any)[k]; ok {
			t.Errorf("spec.%s survived pruning", k)
		}
	}
	// The Go type decodes the stored object strictly.
	raw, _ := yaml.Marshal(attributed(t))
	r := &v1alpha1.EvidenceSigningRequest{}
	if err := yaml.UnmarshalStrict(raw, r); err != nil || r.Spec.RequestedBy == nil || r.Spec.Run.UID != runUID {
		t.Fatalf("does not decode into the Go type: %v %+v", err, r.Spec)
	}
}

func TestEvidenceSigningRequestSpecIsImmutable(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["EvidenceSigningRequest"]
	for name, patch := range map[string]string{
		"run renamed":           `{"spec":{"run":{"name":"other-run","uid":"` + runUID + `"}}}`,
		"run uid changed":       `{"spec":{"run":{"name":"baseline-audit-manual-1","uid":"` + runUID2 + `"}}}`,
		"reason changed":        `{"spec":{"reason":"a different justification"}}`,
		"fingerprint added":     `{"spec":{"expectedKeyFingerprint":"` + fp2 + `"}}`,
		"requester changed":     `{"spec":{"requestedBy":{"username":"someone-else"}}}`,
		"requester uid changed": `{"spec":{"requestedBy":{"username":"platform-admin","uid":"u-2"}}}`,
		"requester removed":     `{"spec":{"requestedBy":null}}`,
	} {
		t.Run(name, func(t *testing.T) {
			old := attributed(t)
			updated := copyObj(old)
			mergePatch(t, updated, patch)
			errs := v.ValidateUpdate(updated, copyObj(old))
			if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), "spec is immutable") {
				t.Fatalf("spec change accepted: %v", errs.ToAggregate())
			}
		})
	}
	// A confirmed fingerprint cannot be removed or swapped either.
	old := attributed(t)
	mergePatch(t, old, `{"spec":{"expectedKeyFingerprint":"`+fp1+`"}}`)
	for name, patch := range map[string]string{"removed": `{"spec":{"expectedKeyFingerprint":null}}`, "swapped": `{"spec":{"expectedKeyFingerprint":"` + fp2 + `"}}`} {
		updated := copyObj(old)
		mergePatch(t, updated, patch)
		if errs := v.ValidateUpdate(updated, copyObj(old)); len(errs) == 0 {
			t.Errorf("fingerprint %s in place", name)
		}
	}
	// Descriptive metadata stays writable.
	updated := copyObj(old)
	mergePatch(t, updated, `{"metadata":{"labels":{"change":"CHG-1234"}}}`)
	if errs := v.ValidateUpdate(updated, copyObj(old)); len(errs) > 0 {
		t.Fatal(errs.ToAggregate())
	}
}

// Every phase accepts exactly the reasons SigningRecoveryReasons lists, so
// the controller, metrics and CRD share one vocabulary.
func TestEvidenceSigningRequestReasonVocabulary(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["EvidenceSigningRequest"]
	var all []v1alpha1.SigningRecoveryReason
	for _, rs := range v1alpha1.SigningRecoveryReasons {
		all = append(all, rs...)
	}
	if len(all) != 16 {
		t.Fatalf("vocabulary has %d reasons, the design defines 16", len(all))
	}
	for _, phase := range []v1alpha1.SigningRequestPhase{v1alpha1.SigningRequestPending, v1alpha1.SigningRequestRunning, v1alpha1.SigningRequestSucceeded, v1alpha1.SigningRequestFailed} {
		allowed := map[v1alpha1.SigningRecoveryReason]bool{}
		for _, r := range v1alpha1.SigningRecoveryReasons[phase] {
			allowed[r] = true
		}
		for _, reason := range all {
			st := map[string]any{"phase": string(phase), "reason": string(reason)}
			if phase.Terminal() {
				st["completedAt"] = "2026-11-24T10:00:06Z"
				st["conditions"] = []any{map[string]any{"type": v1alpha1.ConditionSigningRequestComplete, "status": "True", "reason": string(reason), "message": "", "lastTransitionTime": "2026-11-24T10:00:06Z"}}
			}
			if phase == v1alpha1.SigningRequestSucceeded {
				st["keyFingerprint"] = fp1
				st["publication"] = map[string]any{"publicationID": "pub-1", "packageSha256": sha, "signatureSha256": sha, "publishedAt": "2026-11-24T10:00:05Z", "expiresAt": "2027-02-20T00:00:00Z"}
			}
			o := attributed(t)
			o["status"] = st
			errs := v.Validate(o)
			if allowed[reason] && len(errs) > 0 {
				t.Errorf("%s/%s rejected: %v", phase, reason, errs.ToAggregate())
			}
			if !allowed[reason] && (len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), "reason is not in the phase's vocabulary")) {
				t.Errorf("%s/%s accepted: %v", phase, reason, errs.ToAggregate())
			}
		}
	}
}

func TestEvidenceSigningRequestStatusValidation(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["EvidenceSigningRequest"]
	base := attributed(t)
	for name, s := range map[string]string{"accepted": statusAccepted, "running": statusRunning, "succeeded": statusSucceeded, "failed": statusFailed} {
		if errs := v.Validate(withStatus(t, base, s)); len(errs) > 0 {
			t.Errorf("%s rejected: %v", name, errs.ToAggregate())
		}
	}
	// An authenticator without user UIDs: admission may record an empty
	// uid, which the controller's copy omits.
	noUID := withStatus(t, base, statusAccepted)
	mergePatch(t, noUID, `{"spec":{"requestedBy":{"uid":""}},"status":{"requestedBy":{"uid":null}}}`)
	if errs := v.Validate(noUID); len(errs) > 0 {
		t.Errorf("empty requester uid rejected: %v", errs.ToAggregate())
	}
	for name, c := range map[string]struct{ status, patch, expect string }{
		"unknown phase":               {statusAccepted, `{"status":{"phase":"Done"}}`, "status.phase"},
		"free-text reason":            {statusAccepted, `{"status":{"reason":"looks fine"}}`, "status.reason"},
		"phase without reason":        {statusAccepted, `{"status":{"reason":null}}`, "phase and reason are set together"},
		"reason without phase":        {statusAccepted, `{"status":{"phase":null}}`, "phase and reason are set together"},
		"terminal without completion": {statusFailed, `{"status":{"completedAt":null}}`, "a terminal phase records completedAt"},
		"success without publication": {statusSucceeded, `{"status":{"publication":null}}`, "records its publication and key fingerprint"},
		"success without key":         {statusSucceeded, `{"status":{"keyFingerprint":null}}`, "records its publication and key fingerprint"},
		"terminal without Complete": {statusFailed, `{"status":{"conditions":[{"type":"Complete","status":"False","reason":"KeyMismatch","message":"","lastTransitionTime":"2026-11-24T10:00:02Z"}]}}`,
			"the Complete condition is True exactly on a terminal phase"},
		"Complete while running": {statusRunning, `{"status":{"conditions":[{"type":"Complete","status":"True","reason":"Signing","message":"","lastTransitionTime":"2026-11-24T10:00:02Z"}]}}`,
			"the Complete condition is True exactly on a terminal phase"},
		"key name, not fingerprint":     {statusRunning, `{"status":{"keyFingerprint":"signing-key"}}`, "status.keyFingerprint"},
		"prefixed package digest":       {statusSucceeded, `{"status":{"publication":{"packageSha256":"sha256:` + sha + `"}}}`, "status.publication.packageSha256"},
		"another run":                   {statusAccepted, `{"status":{"run":{"name":"baseline-audit-manual-1","uid":"` + runUID2 + `"}}}`, "status.run must be spec.run"},
		"requester uid dropped":         {statusAccepted, `{"status":{"requestedBy":{"uid":null}}}`, "status.requestedBy must be spec.requestedBy"},
		"another requester uid":         {statusAccepted, `{"status":{"requestedBy":{"uid":"u-2"}}}`, "status.requestedBy must be spec.requestedBy"},
		"another requester":             {statusAccepted, `{"status":{"requestedBy":{"username":"someone-else"}}}`, "status.requestedBy must be spec.requestedBy"},
		"requester without admission":   {statusAccepted, `{"spec":{"requestedBy":null}}`, "status.requestedBy must be spec.requestedBy"},
		"overlong message":              {statusAccepted, `{"status":{"message":"` + strings.Repeat("m", 1025) + `"}}`, "status.message"},
		"too many conditions (bounded)": {statusAccepted, `{"status":{"conditions":[` + conditions(9) + `]}}`, "status.conditions"},
	} {
		t.Run(name, func(t *testing.T) {
			o := withStatus(t, base, c.status)
			mergePatch(t, o, c.patch)
			errs := v.Validate(o)
			if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), c.expect) {
				t.Fatalf("want %q, got %v", c.expect, errs.ToAggregate())
			}
		})
	}
}

func conditions(n int) string {
	var out []string
	for i := range n {
		out = append(out, `{"type":"C`+string(rune('a'+i))+`","status":"False","reason":"R","message":"","lastTransitionTime":"2026-11-24T10:00:00Z"}`)
	}
	return strings.Join(out, ",")
}

// The controller advances a request until it is terminal; then nothing
// changes. The recorded requester and run are set once.
func TestEvidenceSigningRequestStatusTransitions(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["EvidenceSigningRequest"]
	base := attributed(t)
	for name, c := range map[string]struct{ from, to string }{
		"accept":         {"", statusAccepted},
		"start":          {statusAccepted, statusRunning},
		"succeed":        {statusRunning, statusSucceeded},
		"fail":           {statusAccepted, statusFailed},
		"wait":           {statusAccepted, strings.Replace(statusAccepted, `"reason":"Accepted"`, `"reason":"Waiting"`, 1)},
		"terminal no-op": {statusSucceeded, statusSucceeded},
	} {
		prev := copyObj(base)
		if c.from != "" {
			prev = withStatus(t, base, c.from)
		}
		if errs := v.ValidateUpdate(withStatus(t, base, c.to), prev); len(errs) > 0 {
			t.Errorf("%s rejected: %v", name, errs.ToAggregate())
		}
	}
	for name, c := range map[string]struct {
		from, patch, expect string
	}{
		"success rewritten as failure": {statusSucceeded, `{"status":{"phase":"Failed","reason":"Conflict","publication":null,"conditions":[{"type":"Complete","status":"True","reason":"Conflict","message":"","lastTransitionTime":"2026-11-24T10:00:06Z"}]}}`, "a terminal outcome is never rewritten"},
		"failure reopened":             {statusFailed, `{"status":{"phase":"Running","reason":"Signing","completedAt":null,"conditions":[{"type":"Complete","status":"False","reason":"Signing","message":"","lastTransitionTime":"2026-11-24T10:00:06Z"}]}}`, "a terminal outcome is never rewritten"},
		"terminal message edited":      {statusFailed, `{"status":{"message":"nothing happened"}}`, "a terminal outcome is never rewritten"},
		"terminal publication edited":  {statusSucceeded, `{"status":{"publication":{"expiresAt":"2030-01-01T00:00:00Z"}}}`, "a terminal outcome is never rewritten"},
		"terminal status cleared":      {statusSucceeded, `{"status":null}`, "a recorded request status is never removed"},
		"terminal status emptied":      {statusFailed, `{"status":{"phase":null,"reason":null,"message":null,"requestedBy":null,"run":null,"keyFingerprint":null,"acceptedAt":null,"completedAt":null,"conditions":null}}`, "a terminal outcome is never rewritten"},
		"requester rewritten":          {statusAccepted, `{"status":{"requestedBy":{"username":"someone-else"}}}`, "the recorded requester is set once"},
		"requester dropped":            {statusAccepted, `{"status":{"requestedBy":null}}`, "the recorded requester is set once"},
		"run dropped":                  {statusRunning, `{"status":{"run":null}}`, "the recorded run is set once"},
		"attributed status cleared":    {statusRunning, `{"status":null}`, "a recorded request status is never removed"},
	} {
		t.Run(name, func(t *testing.T) {
			prev := withStatus(t, base, c.from)
			next := copyObj(prev)
			mergePatch(t, next, c.patch)
			errs := v.ValidateUpdate(next, copyObj(prev))
			if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), c.expect) {
				t.Fatalf("want %q, got %v", c.expect, errs.ToAggregate())
			}
		})
	}
}

func runWithRecovery(t *testing.T, recovery string) map[string]any {
	t.Helper()
	o := runWithIntent(t, intent("Required", "signing-a", key(fp1)))
	if recovery != "" {
		o["status"].(map[string]any)["signingRecovery"] = obj(t, recovery)
	}
	return o
}

const (
	recoveryClaim     = `{"active":{"name":"recover-1","uid":"` + reqUID + `","claimedAt":"2026-11-24T10:00:00Z","deadline":"2026-11-24T10:10:00Z"}}`
	recoveryRecovered = `{"recovered":{"name":"recover-1","uid":"` + reqUID + `","requestedBy":{"username":"platform-admin","uid":"u-1"},"at":"2026-11-24T10:00:06Z"}}`
)

// add-evidence-signing-recovery 1.1: the run's recovery claim comes and goes,
// but the recovered record is written once and never changes or disappears.
func TestAssessmentRunSigningRecoveryIsWriteOnce(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["AssessmentRun"]
	for name, c := range map[string]struct{ from, to string }{
		"claim":                 {"", recoveryClaim},
		"release after failure": {recoveryClaim, `{}`},
		"recover":               {recoveryClaim, recoveryRecovered},
		"recover unclaimed":     {"", recoveryRecovered},
		"recovered unchanged":   {recoveryRecovered, recoveryRecovered},
	} {
		if errs := v.ValidateUpdate(runWithRecovery(t, c.to), runWithRecovery(t, c.from)); len(errs) > 0 {
			t.Errorf("%s rejected: %v", name, errs.ToAggregate())
		}
	}
	for name, c := range map[string]struct {
		next   map[string]any
		expect string
	}{
		"recovered rewritten": {runWithRecovery(t, strings.Replace(recoveryRecovered, "recover-1", "recover-2", 1)), "set once and never changes"},
		"requester rewritten": {runWithRecovery(t, strings.Replace(recoveryRecovered, "platform-admin", "someone-else", 1)), "set once and never changes"},
		"recovered dropped":   {runWithRecovery(t, `{}`), "set once and never changes"},
		"recovery dropped":    {runWithRecovery(t, ""), "status.signingRecovery.recovered is never removed"},
		"status dropped":      {runWithIntent(t, nil), "never removed"},
		"claimed after recovery": {runWithRecovery(t, `{"active":{"name":"recover-2","uid":"`+reqUID+`","claimedAt":"2026-11-24T11:00:00Z","deadline":"2026-11-24T11:10:00Z"},`+
			strings.TrimPrefix(recoveryRecovered, "{")), "a recovered run holds no recovery claim"},
	} {
		errs := v.ValidateUpdate(c.next, runWithRecovery(t, recoveryRecovered))
		if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), c.expect) {
			t.Errorf("%s: want %q, got %v", name, c.expect, errs.ToAggregate())
		}
	}
	for name, recovery := range map[string]string{
		"deadline before claim": `{"active":{"name":"recover-1","uid":"` + reqUID + `","claimedAt":"2026-11-24T10:10:00Z","deadline":"2026-11-24T10:00:00Z"}}`,
		"anonymous claim":       `{"active":{"name":"","uid":"` + reqUID + `","claimedAt":"2026-11-24T10:00:00Z","deadline":"2026-11-24T10:10:00Z"}}`,
		"unattributed recovery": `{"recovered":{"name":"recover-1","uid":"` + reqUID + `","at":"2026-11-24T10:00:06Z"}}`,
	} {
		if errs := v.Validate(runWithRecovery(t, recovery)); len(errs) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
}

// A retained SigningFailed run's status, as stored before signing recovery
// existed, decodes and encodes byte for byte and still passes the CRD.
func TestAssessmentRunWithoutRecoveryIsByteCompatible(t *testing.T) {
	const retained = `{"phase":"Failed","binding":{"name":"baseline-audit","uid":"b-uid"},"bindingConfiguration":"3","retention":"2160h",` +
		`"descriptorSha256":"` + sha + `","publication":{"phase":"Failed","publicationID":"pub-1","packageSha256":"` + sha + `","packageSize":4096,` +
		`"expiresAt":"2027-02-20T00:00:00Z","availability":"Unavailable","cleanup":{"state":"NotDue"},` +
		`"failure":{"reason":"SigningFailed","message":"signing key unavailable","retryable":false,"at":"2026-11-22T00:10:00Z"}},` +
		`"signingIntent":{"mode":"Required","destinationUID":"dest-uid","destinationGeneration":3,"secretName":"signing-a","archiveSha256":"` + sha + `","preparedAt":"2026-11-22T00:00:00Z"},` +
		`"conditions":[{"type":"Published","status":"False","lastTransitionTime":"2026-11-22T00:10:00Z","reason":"SigningFailed","message":"signing key unavailable"}]}`
	var s v1alpha1.AssessmentRunStatus
	if err := json.Unmarshal([]byte(retained), &s); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != retained {
		t.Fatalf("re-encoded differently:\n%s\n%s", out, retained)
	}
	if s.SigningRecovery != nil {
		t.Fatal("a run without recovery decoded a signingRecovery")
	}
	o := runWithIntent(t, nil)
	o["status"] = obj(t, retained)
	if errs := crdtest.Load(t, "../../config/crd/bases")["AssessmentRun"].ValidateUpdate(copyObj(o), copyObj(o)); len(errs) > 0 {
		t.Fatal(errs.ToAggregate())
	}
}
