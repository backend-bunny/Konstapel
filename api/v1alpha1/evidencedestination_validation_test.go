package v1alpha1_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

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

func withSigning(t *testing.T, signing any) map[string]any {
	t.Helper()
	o := obj(t, destination)
	if signing != nil {
		o["spec"].(map[string]any)["signing"] = signing
	}
	return o
}

// spec.signing: absent means Disabled and adds nothing to existing objects;
// Required needs a controller-namespace Secret reference; deferred signer
// kinds and invalid combinations are rejected with field-specific messages.
func TestEvidenceDestinationSigningValidation(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["EvidenceDestination"]
	plain := obj(t, destination)
	if errs := v.Validate(plain); len(errs) > 0 {
		t.Fatal(errs.ToAggregate())
	}
	if _, ok := plain["spec"].(map[string]any)["signing"]; ok {
		t.Fatalf("defaulting added spec.signing to a destination without it: %v", plain["spec"])
	}
	empty := withSigning(t, map[string]any{})
	if errs := v.Validate(empty); len(errs) > 0 {
		t.Fatalf("empty signing rejected: %v", errs.ToAggregate())
	}
	if m := empty["spec"].(map[string]any)["signing"].(map[string]any)["mode"]; m != "Disabled" {
		t.Fatalf("signing.mode default: %v", m)
	}
	for name, s := range map[string]map[string]any{
		"disabled": {"mode": "Disabled"},
		"required": {"mode": "Required", "secretRef": map[string]any{"name": "konstapel-evidence-signing-2026-11"}},
	} {
		if errs := v.Validate(withSigning(t, s)); len(errs) > 0 {
			t.Errorf("%s rejected: %v", name, errs.ToAggregate())
		}
	}
	for name, c := range map[string]struct {
		signing map[string]any
		want    string
	}{
		"required without secretRef": {map[string]any{"mode": "Required"}, "Required needs secretRef"},
		"disabled with secretRef":    {map[string]any{"mode": "Disabled", "secretRef": map[string]any{"name": "k"}}, "secretRef is set only with signing mode Required"},
		"default with secretRef":     {map[string]any{"secretRef": map[string]any{"name": "k"}}, "secretRef is set only with signing mode Required"},
		"cross-namespace secretRef":  {map[string]any{"mode": "Required", "secretRef": map[string]any{"name": "k", "namespace": "team-a"}}, "controller namespace only"},
		"unknown mode":               {map[string]any{"mode": "Optional"}, "Unsupported value"},
		"bad secret name":            {map[string]any{"mode": "Required", "secretRef": map[string]any{"name": "Bad_Name"}}, "secretRef.name"},
		"kms":                        {map[string]any{"mode": "Required", "kms": map[string]any{"keyID": "arn:aws:kms:eu-north-1:1:key/x"}}, "KMS signing keys are not supported"},
		"keyless":                    {map[string]any{"mode": "Required", "keyless": map[string]any{"issuer": "https://kubernetes.default.svc"}}, "keyless signing is not supported"},
	} {
		errs := v.Validate(withSigning(t, c.signing))
		if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), c.want) {
			t.Errorf("%s: want rejection mentioning %q, got %v", name, c.want, errs.ToAggregate())
		}
		if len(errs) > 0 && !strings.Contains(errs.ToAggregate().Error(), "spec.signing") {
			t.Errorf("%s: rejection does not name spec.signing: %v", name, errs.ToAggregate())
		}
	}
	// The policy can change in either direction and the key can rotate,
	// including while the destination retires.
	required := func(secret string) map[string]any {
		return withSigning(t, map[string]any{"mode": "Required", "secretRef": map[string]any{"name": secret}})
	}
	for name, c := range map[string]struct{ next, prev map[string]any }{
		"enable":            {required("key-a"), obj(t, destination)},
		"rotate":            {required("key-b"), required("key-a")},
		"required→disabled": {withSigning(t, map[string]any{"mode": "Disabled"}), required("key-a")},
		"remove":            {obj(t, destination), required("key-a")},
	} {
		for _, deleting := range []bool{false, true} {
			next, prev := c.next, c.prev
			if deleting {
				next, prev = deepCopy(t, next), deepCopy(t, prev)
				for _, o := range []map[string]any{next, prev} {
					o["metadata"].(map[string]any)["deletionTimestamp"] = "2026-11-13T12:00:00Z"
					o["metadata"].(map[string]any)["finalizers"] = []any{"compliance.erenius.io/destination"}
				}
			}
			if errs := v.ValidateUpdate(deepCopy(t, next), deepCopy(t, prev)); len(errs) > 0 {
				t.Errorf("%s (retiring=%v) rejected: %v", name, deleting, errs.ToAggregate())
			}
		}
	}
}

func deepCopy(t *testing.T, o map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Signing policy is central: no binding, request, run, or profile spec field
// can select or disable signing, so the API prunes such fields and no other
// CRD's spec schema has a signing property.
func TestSigningIsOnlyConfiguredOnDestinations(t *testing.T) {
	files, err := filepath.Glob("../../config/crd/bases/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatal(err)
	}
	var walk func(path string, schema map[string]any) []string
	walk = func(path string, schema map[string]any) []string {
		var found []string
		props, _ := schema["properties"].(map[string]any)
		for name, sub := range props {
			if strings.Contains(strings.ToLower(name), "sign") {
				found = append(found, path+"."+name)
			}
			if m, ok := sub.(map[string]any); ok {
				found = append(found, walk(path+"."+name, m)...)
			}
		}
		if items, ok := schema["items"].(map[string]any); ok {
			found = append(found, walk(path+"[]", items)...)
		}
		return found
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_evidencedestinations.yaml") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var crd struct {
			Spec struct {
				Versions []struct {
					Schema struct {
						OpenAPIV3Schema map[string]any `json:"openAPIV3Schema"`
					} `json:"schema"`
				} `json:"versions"`
			} `json:"spec"`
		}
		if err := yaml.Unmarshal(raw, &crd); err != nil {
			t.Fatal(err)
		}
		for _, v := range crd.Spec.Versions {
			spec, _ := v.Schema.OpenAPIV3Schema["properties"].(map[string]any)["spec"].(map[string]any)
			if found := walk("spec", spec); len(found) > 0 {
				t.Errorf("%s has signing fields %v; only EvidenceDestination configures signing", filepath.Base(f), found)
			}
		}
	}
	crds := crdtest.Load(t, "../../config/crd/bases")
	request := obj(t, `apiVersion: compliance.erenius.io/v1alpha1
kind: AssessmentRequest
metadata: {name: nightly, namespace: team-a}
spec:
  bindingRef: {name: baseline-audit}
  signing: {mode: Disabled}
`)
	_ = crds["AssessmentRequest"].Validate(request)
	if _, ok := request["spec"].(map[string]any)["signing"]; ok {
		t.Fatal("an AssessmentRequest kept a signing override")
	}
}

// The documented signing destination example is valid as published and names
// the Secret the documented key-generation command creates.
func TestEvidenceSigningExampleIsValid(t *testing.T) {
	v := crdtest.Load(t, "../../config/crd/bases")["EvidenceDestination"]
	raw, err := os.ReadFile("../../docs/examples/evidence-signing/destination.yaml")
	if err != nil {
		t.Fatal(err)
	}
	o := obj(t, string(raw))
	if errs := v.Validate(o); len(errs) > 0 {
		t.Fatalf("example rejected: %v", errs.ToAggregate())
	}
	signing := o["spec"].(map[string]any)["signing"].(map[string]any)
	name := signing["secretRef"].(map[string]any)["name"].(string)
	doc, err := os.ReadFile("../../docs/integration/evidence-signing.md")
	if err != nil {
		t.Fatal(err)
	}
	if signing["mode"] != "Required" || !strings.Contains(string(doc), "cosign generate-key-pair k8s://konstapel-system/"+name+"\n") ||
		!strings.Contains(string(doc), "docs/examples/evidence-signing/destination.yaml") {
		t.Fatalf("example and guide disagree on the signing Secret %q", name)
	}
}
