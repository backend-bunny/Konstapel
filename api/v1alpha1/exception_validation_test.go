package v1alpha1_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/crdtest"
)

const exception = `
apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceException
metadata: {name: priv-debug, namespace: team-a}
spec:
  policy: disallow-privileged-containers
  workloadSelector: {matchLabels: {app: debug}}
  reason: incident 42 debugging
  expiresAt: "2026-01-08T00:00:00Z"
  acceptanceRevision: 1
`

func exceptionSpec(o map[string]any) map[string]any { return o["spec"].(map[string]any) }

func TestComplianceExceptionCreateValidation(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	v := crds["ComplianceException"]
	if v == nil {
		t.Fatal("ComplianceException CRD not loaded")
	}
	cases := []struct {
		name   string
		mutate func(spec map[string]any)
		want   string // "" means accepted
	}{
		{"valid", func(map[string]any) {}, ""},
		{"explicit empty selector selects the namespace", func(s map[string]any) { s["workloadSelector"] = map[string]any{} }, ""},
		{"expression selector", func(s map[string]any) {
			s["workloadSelector"] = map[string]any{"matchExpressions": []any{map[string]any{"key": "app", "operator": "In", "values": []any{"a", "b"}}}}
		}, ""},
		{"missing selector", func(s map[string]any) { delete(s, "workloadSelector") }, "workloadSelector"},
		{"null selector", func(s map[string]any) { s["workloadSelector"] = nil }, "workloadSelector"},
		{"missing policy", func(s map[string]any) { delete(s, "policy") }, "policy"},
		{"invalid policy name", func(s map[string]any) { s["policy"] = "Not_A_Policy" }, "policy"},
		{"empty reason", func(s map[string]any) { s["reason"] = "" }, "reason"},
		{"blank reason", func(s map[string]any) { s["reason"] = " \t\n " }, "reason must not be blank"},
		{"missing reason", func(s map[string]any) { delete(s, "reason") }, "reason"},
		{"missing expiry", func(s map[string]any) { delete(s, "expiresAt") }, "expiresAt"},
		{"null expiry", func(s map[string]any) { s["expiresAt"] = nil }, "expiresAt"},
		{"malformed expiry", func(s map[string]any) { s["expiresAt"] = "next week" }, "expiresAt"},
		{"missing revision", func(s map[string]any) { delete(s, "acceptanceRevision") }, "acceptanceRevision"},
		{"creation at a later revision", func(s map[string]any) { s["acceptanceRevision"] = int64(2) }, "starts at acceptanceRevision 1"},
		{"zero revision", func(s map[string]any) { s["acceptanceRevision"] = int64(0) }, "acceptanceRevision"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := obj(t, exception)
			c.mutate(exceptionSpec(o))
			errs := v.Validate(o)
			if c.want == "" {
				if len(errs) > 0 {
					t.Fatalf("rejected: %v", errs.ToAggregate())
				}
				return
			}
			if len(errs) == 0 {
				t.Fatalf("accepted, want error mentioning %q", c.want)
			}
			if !strings.Contains(errs.ToAggregate().Error(), c.want) {
				t.Fatalf("got %v, want error mentioning %q", errs.ToAggregate(), c.want)
			}
		})
	}
}

func TestComplianceExceptionUpdateValidation(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	v := crds["ComplianceException"]
	cases := []struct {
		name   string
		mutate func(o map[string]any)
		want   string // "" means accepted
	}{
		{"metadata-only edit keeps the acceptance", func(o map[string]any) {
			o["metadata"].(map[string]any)["labels"] = map[string]any{"team": "a"}
		}, ""},
		{"explicit renewal", func(o map[string]any) {
			s := exceptionSpec(o)
			s["acceptanceRevision"] = int64(2)
			s["reason"] = "still needed"
			s["expiresAt"] = "2026-01-14T00:00:00Z"
		}, ""},
		{"policy change", func(o map[string]any) { exceptionSpec(o)["policy"] = "disallow-host-path" }, "policy is immutable"},
		{"selector widened to the namespace", func(o map[string]any) { exceptionSpec(o)["workloadSelector"] = map[string]any{} }, "workloadSelector is immutable"},
		{"selector removed", func(o map[string]any) { delete(exceptionSpec(o), "workloadSelector") }, "workloadSelector"},
		{"expiry extended without renewal", func(o map[string]any) { exceptionSpec(o)["expiresAt"] = "2026-01-14T00:00:00Z" }, "explicit renewal"},
		{"reason changed without renewal", func(o map[string]any) { exceptionSpec(o)["reason"] = "different" }, "explicit renewal"},
		{"revision skipped", func(o map[string]any) { exceptionSpec(o)["acceptanceRevision"] = int64(3) }, "exactly one"},
		{"renewal with a scope change", func(o map[string]any) {
			s := exceptionSpec(o)
			s["acceptanceRevision"] = int64(2)
			s["workloadSelector"] = map[string]any{}
		}, "workloadSelector is immutable"},
		{"renewal with a blank reason", func(o map[string]any) {
			s := exceptionSpec(o)
			s["acceptanceRevision"] = int64(2)
			s["reason"] = "   "
		}, "reason must not be blank"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			old := obj(t, exception)
			updated := copyObj(old)
			c.mutate(updated)
			errs := v.ValidateUpdate(updated, copyObj(old))
			if c.want == "" {
				if len(errs) > 0 {
					t.Fatalf("rejected: %v", errs.ToAggregate())
				}
				return
			}
			if len(errs) == 0 {
				t.Fatalf("accepted, want error mentioning %q", c.want)
			}
			if !strings.Contains(errs.ToAggregate().Error(), c.want) {
				t.Fatalf("got %v, want error mentioning %q", errs.ToAggregate(), c.want)
			}
		})
	}

	// A revision never goes backwards.
	old := obj(t, exception)
	exceptionSpec(old)["acceptanceRevision"] = int64(2)
	updated := copyObj(old)
	exceptionSpec(updated)["acceptanceRevision"] = int64(1)
	if errs := v.ValidateUpdate(updated, copyObj(old)); len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), "exactly one") {
		t.Fatalf("decrement: got %v", errs.ToAggregate())
	}
}

// spec.revoked (add-self-service-policy-exceptions task 2.6): the API server
// defaults it to false and allows it to change only as the transition table
// in the design says. Admission adds the authenticated record and the
// renewal-of-a-revoked-revision gate on top (internal/exception).
func TestComplianceExceptionRevocationValidation(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	v := crds["ComplianceException"]

	// Creation: omitted defaults to false; a new acceptance starts unrevoked.
	o := obj(t, exception)
	if errs := v.Validate(o); len(errs) > 0 || exceptionSpec(o)["revoked"] != false {
		t.Fatalf("omitted revoked: errs %v, defaulted to %v", errs.ToAggregate(), exceptionSpec(o)["revoked"])
	}
	o = obj(t, exception)
	exceptionSpec(o)["revoked"] = false
	if errs := v.Validate(o); len(errs) > 0 {
		t.Fatalf("explicit revoked false rejected: %v", errs.ToAggregate())
	}
	o = obj(t, exception)
	exceptionSpec(o)["revoked"] = true
	if errs := v.Validate(o); len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), "InvalidRevocationTransition") {
		t.Fatalf("create revoked: got %v", errs.ToAggregate())
	}

	renew := func(s map[string]any) {
		s["acceptanceRevision"] = int64(2)
		s["reason"] = "fresh acceptance"
		s["expiresAt"] = "2026-01-14T00:00:00Z"
	}
	cases := []struct {
		name       string
		oldRevoked any // nil: stored before the field existed
		mutate     func(spec map[string]any)
		want       string // "" means accepted
	}{
		{"revoke", false, func(s map[string]any) { s["revoked"] = true }, ""},
		{"revoke a resource stored before the field existed", nil, func(s map[string]any) { s["revoked"] = true }, ""},
		{"metadata-only edit of a resource stored before the field existed", nil, func(map[string]any) {}, ""},
		{"repeat revoke", true, func(s map[string]any) { s["revoked"] = true }, ""},
		{"same-revision reactivation", true, func(s map[string]any) { s["revoked"] = false }, "RenewalRequired"},
		{"same-revision re-apply omitting revoked", true, func(s map[string]any) { delete(s, "revoked") }, "RenewalRequired"},
		{"revoke while extending the expiry", false, func(s map[string]any) {
			s["revoked"] = true
			s["expiresAt"] = "2026-01-14T00:00:00Z"
		}, "explicit renewal"},
		{"revoke while replacing the reason", false, func(s map[string]any) {
			s["revoked"] = true
			s["reason"] = "revoked: incident closed"
		}, "explicit renewal"},
		{"renew and revoke together", false, func(s map[string]any) { renew(s); s["revoked"] = true }, "InvalidRevocationTransition"},
		{"renew a revoked revision into revoked", true, func(s map[string]any) { renew(s); s["revoked"] = true }, "InvalidRevocationTransition"},
		// The API allows the renewal of a revoked revision; admission holds
		// it until the revocation is persisted independently (task 3.6).
		{"renew a revoked revision", true, func(s map[string]any) { renew(s); s["revoked"] = false }, ""},
		{"renew a revoked revision omitting revoked", true, func(s map[string]any) { renew(s); delete(s, "revoked") }, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			old := obj(t, exception)
			if c.oldRevoked != nil {
				exceptionSpec(old)["revoked"] = c.oldRevoked
			}
			updated := copyObj(old)
			c.mutate(exceptionSpec(updated))
			errs := v.ValidateUpdate(updated, copyObj(old))
			if c.want == "" {
				if len(errs) > 0 {
					t.Fatalf("rejected: %v", errs.ToAggregate())
				}
				return
			}
			if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), c.want) {
				t.Fatalf("got %v, want error mentioning %q", errs.ToAggregate(), c.want)
			}
		})
	}
}

// The documented example (docs/examples/policy-exceptions) is a valid
// creation; TestLiveExceptionRevocation applies it and its patches to a real
// API server.
func TestComplianceExceptionDocsExample(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["ComplianceException"]
	raw, err := os.ReadFile("../../docs/examples/policy-exceptions/exception.yaml")
	if err != nil {
		t.Fatal(err)
	}
	o := obj(t, string(raw))
	if errs := v.Validate(o); len(errs) > 0 {
		t.Fatalf("example rejected: %v", errs.ToAggregate())
	}
	if exceptionSpec(o)["acceptanceRevision"] != int64(1) || exceptionSpec(o)["revoked"] != false {
		t.Errorf("the example must create revision 1, unrevoked: %v", exceptionSpec(o))
	}
	// Both patches test the UID, resourceVersion and revision they were
	// written for before they change anything.
	for _, f := range []string{"revoke.json", "renew.json", "renew-revoked.json"} {
		raw, err := os.ReadFile("../../docs/examples/policy-exceptions/" + f)
		if err != nil {
			t.Fatal(err)
		}
		var ops []struct {
			Op, Path string
		}
		if err := json.Unmarshal(raw, &ops); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		var tested []string
		changed := false
		for _, op := range ops {
			switch {
			case op.Op != "test":
				changed = true
			case changed:
				t.Errorf("%s: test %s after a change", f, op.Path)
			default:
				tested = append(tested, op.Path)
			}
		}
		if len(tested) < 3 || tested[0] != "/metadata/uid" || tested[1] != "/metadata/resourceVersion" || tested[2] != "/spec/acceptanceRevision" {
			t.Errorf("%s tests %v, want the UID, resourceVersion and acceptanceRevision first", f, tested)
		}
	}
}
