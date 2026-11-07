package v1alpha1_test

import (
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/crdtest"
)

const destination = `apiVersion: compliance.erenius.io/v1alpha1
kind: EvidenceDestination
metadata: {name: primary}
spec:
  s3:
    endpoint: https://s3.example.internal
    bucket: konstapel-evidence
    region: eu-north-1
    prefix: clusters/prod
    credentialSecret: {name: konstapel-s3}
`

func destinationWith(t *testing.T, edit func(map[string]any)) map[string]any {
	t.Helper()
	o := obj(t, destination)
	edit(o["spec"].(map[string]any)["s3"].(map[string]any))
	return o
}

func TestEvidenceDestinationCreateValidation(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	v := crds["EvidenceDestination"]
	if errs := v.Validate(obj(t, destination)); len(errs) > 0 {
		t.Fatalf("valid destination rejected: %v", errs.ToAggregate())
	}
	for name, c := range map[string]struct {
		edit func(map[string]any)
		want string
	}{
		"both credential sources": {func(s map[string]any) { s["workloadIdentity"] = true }, "exactly one credential source"},
		"no credential source":    {func(s map[string]any) { delete(s, "credentialSecret") }, "exactly one credential source"},
		"cross-namespace secret": {func(s map[string]any) {
			s["credentialSecret"] = map[string]any{"name": "konstapel-s3", "namespace": "team-a"}
		}, "controller namespace only"},
		"cross-namespace trust": {func(s map[string]any) { s["caTrust"] = map[string]any{"name": "ca", "namespace": "team-a"} }, "controller namespace only"},
		"plain http":            {func(s map[string]any) { s["endpoint"] = "http://s3.example.internal" }, "must be https"},
		"bad bucket":            {func(s map[string]any) { s["bucket"] = "Bad_Bucket" }, "bucket"},
		"traversal prefix":      {func(s map[string]any) { s["prefix"] = "a/../b" }, "prefix"},
		"absolute prefix":       {func(s map[string]any) { s["prefix"] = "/abs" }, "prefix"},
		"endpoint with path":    {func(s map[string]any) { s["endpoint"] = "https://s3.example.internal/bucket" }, "endpoint"},
	} {
		errs := v.Validate(destinationWith(t, c.edit))
		if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), c.want) {
			t.Errorf("%s: want rejection mentioning %q, got %v", name, c.want, errs.ToAggregate())
		}
	}
	// An isolated development fixture may use plain http.
	if errs := v.Validate(destinationWith(t, func(s map[string]any) {
		s["endpoint"], s["developmentFixture"] = "http://127.0.0.1:9000", true
	})); len(errs) > 0 {
		t.Fatalf("development fixture rejected: %v", errs.ToAggregate())
	}
	// Defaults: Retire, path addressing, standard Secret keys.
	o := obj(t, destination)
	if errs := v.Validate(o); len(errs) > 0 { // Validate defaults in place
		t.Fatal(errs.ToAggregate())
	}
	spec := o["spec"].(map[string]any)
	s3 := spec["s3"].(map[string]any)
	if spec["deletionPolicy"] != "Retire" || s3["addressing"] != "path" || s3["credentialSecret"].(map[string]any)["accessKeyIDKey"] != "accessKeyID" {
		t.Fatalf("defaults not applied: %v", spec)
	}
}

// The location never changes; credentials and CA trust rotate, including
// while the destination is being deleted (retiring).
func TestEvidenceDestinationLocationImmutableAccessRotates(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["EvidenceDestination"]
	old := obj(t, destination)
	for field, value := range map[string]any{"endpoint": "https://other.example.internal", "bucket": "other-bucket", "region": "eu-west-1", "prefix": "clusters/other"} {
		errs := v.ValidateUpdate(destinationWith(t, func(s map[string]any) { s[field] = value }), old)
		if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), "immutable") {
			t.Errorf("%s change accepted: %v", field, errs.ToAggregate())
		}
	}
	if errs := v.ValidateUpdate(destinationWith(t, func(s map[string]any) { delete(s, "prefix") }), old); len(errs) == 0 {
		t.Error("prefix removal accepted")
	}
	for _, deleting := range []bool{false, true} {
		rotated := destinationWith(t, func(s map[string]any) {
			s["credentialSecret"] = map[string]any{"name": "konstapel-s3-rotated", "accessKeyIDKey": "id", "secretAccessKeyKey": "secret"}
			s["caTrust"] = map[string]any{"name": "s3-ca-2026", "key": "bundle.pem"}
		})
		prev := obj(t, destination)
		if deleting {
			for _, o := range []map[string]any{rotated, prev} {
				o["metadata"].(map[string]any)["deletionTimestamp"] = "2026-11-06T12:00:00Z"
				o["metadata"].(map[string]any)["finalizers"] = []any{"compliance.erenius.io/destination"}
			}
		}
		if errs := v.ValidateUpdate(rotated, prev); len(errs) > 0 {
			t.Fatalf("rotation rejected (retiring=%v): %v", deleting, errs.ToAggregate())
		}
	}
	// Switching to workload identity is a credential change, not a move.
	wi := destinationWith(t, func(s map[string]any) { delete(s, "credentialSecret"); s["workloadIdentity"] = true })
	if errs := v.ValidateUpdate(wi, old); len(errs) > 0 {
		t.Fatalf("credential source switch rejected: %v", errs.ToAggregate())
	}
}

func TestEvidenceDestinationOrphanRequestValidation(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["EvidenceDestination"]
	with := func(policy string, orphan map[string]any) map[string]any {
		o := obj(t, destination)
		spec := o["spec"].(map[string]any)
		spec["deletionPolicy"] = policy
		if orphan != nil {
			spec["orphan"] = orphan
		}
		return o
	}
	if errs := v.Validate(with("Orphan", map[string]any{"reason": "handed to the archive team"})); len(errs) > 0 {
		t.Fatalf("valid orphan request rejected: %v", errs.ToAggregate())
	}
	for name, c := range map[string]struct {
		o    map[string]any
		want string
	}{
		"orphan without reason":    {with("Orphan", nil), "requires orphan.reason"},
		"blank reason":             {with("Orphan", map[string]any{"reason": "   "}), "must not be blank"},
		"orphan block with Retire": {with("Retire", map[string]any{"reason": "x"}), "only with deletionPolicy Orphan"},
	} {
		if errs := v.Validate(c.o); len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), c.want) {
			t.Errorf("%s: want %q, got %v", name, c.want, errs.ToAggregate())
		}
	}
}

// spec.legacy declares a legacy destination only when the destination is
// created; it cannot be added, changed, or removed later.
func TestEvidenceDestinationLegacyIsCreationOnly(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["EvidenceDestination"]
	legacy := func(id string) map[string]any {
		o := obj(t, destination)
		o["spec"].(map[string]any)["legacy"] = map[string]any{"destinationID": id, "configuration": map[string]any{"name": "legacy-destination"}}
		return o
	}
	created := legacy("prod-legacy")
	if errs := v.Validate(created); len(errs) > 0 {
		t.Fatalf("legacy declaration rejected: %v", errs.ToAggregate())
	}
	if key := created["spec"].(map[string]any)["legacy"].(map[string]any)["configuration"].(map[string]any)["key"]; key != "destination.yaml" {
		t.Fatalf("configuration key default: %v", key)
	}
	for name, c := range map[string]struct{ next, prev map[string]any }{
		"added later": {legacy("prod-legacy"), obj(t, destination)},
		"changed":     {legacy("other-legacy"), legacy("prod-legacy")},
		"removed":     {obj(t, destination), legacy("prod-legacy")},
		"config moved": {func() map[string]any {
			o := legacy("prod-legacy")
			o["spec"].(map[string]any)["legacy"].(map[string]any)["configuration"] = map[string]any{"name": "elsewhere"}
			return o
		}(), legacy("prod-legacy")},
	} {
		if errs := v.ValidateUpdate(c.next, c.prev); len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), "immutable") {
			t.Errorf("%s: accepted: %v", name, errs.ToAggregate())
		}
	}
	if errs := v.ValidateUpdate(legacy("prod-legacy"), legacy("prod-legacy")); len(errs) > 0 {
		t.Fatalf("unchanged legacy rejected: %v", errs.ToAggregate())
	}
	if errs := v.Validate(legacy("Not_A_Label")); len(errs) == 0 {
		t.Error("invalid legacy destination ID accepted")
	}
}
