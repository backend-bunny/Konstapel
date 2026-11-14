package v1alpha1_test

import (
	"os"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/crdtest"
)

// add-supporting-evidence-attachments 1.1: the generated EvidenceAttachment
// CRD accepts the published example, rejects malformed dates, digests and
// structure, prunes unsupported fields, and keeps every evidence-defining
// field immutable.

const attachmentExample = "../../docs/examples/supporting-evidence/attachment-datacenter.yaml"

func attachment(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(attachmentExample)
	if err != nil {
		t.Fatal(err)
	}
	return obj(t, string(raw))
}

func TestEvidenceAttachmentExampleIsValid(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	o := attachment(t)
	if errs := crds["EvidenceAttachment"].Validate(o); len(errs) > 0 {
		t.Fatal(errs.ToAggregate())
	}
	raw, _ := yaml.Marshal(o)
	a := &v1alpha1.EvidenceAttachment{}
	if err := yaml.UnmarshalStrict(raw, a); err != nil {
		t.Fatalf("does not decode into Go type: %v", err)
	}
	if a.Spec.RegisteredBy != nil {
		t.Fatal("the example must not supply protected attribution")
	}
	if len(a.Spec.Associations) != 2 || a.Spec.Associations[0].Binding.UID == a.Spec.Associations[1].Binding.UID {
		t.Fatal("the example must associate two distinct bindings")
	}
}

func TestEvidenceAttachmentCreateValidation(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	cases := []struct{ name, patch, expect string }{
		{"malformed validFrom", `{"spec":{"validity":{"validFrom":"2026-13-01T00:00:00Z"}}}`, "spec.validity.validFrom"},
		{"date without time", `{"spec":{"validity":{"validUntil":"2027-01-01"}}}`, "spec.validity.validUntil"},
		{"missing validUntil", `{"spec":{"validity":{"validUntil":null}}}`, "spec.validity.validUntil: Required"},
		{"empty period", `{"spec":{"validity":{"validFrom":"2027-01-01T00:00:00Z"}}}`, "validFrom must be before validUntil"},
		{"reversed period", `{"spec":{"validity":{"validFrom":"2027-06-01T00:00:00Z"}}}`, "validFrom must be before validUntil"},
		{"digest without algorithm", `{"spec":{"document":{"sha256":"9f2b5c1d0e8a7f6b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a10"}}}`, "spec.document.sha256"},
		{"uppercase digest", `{"spec":{"document":{"sha256":"sha256:9F2B5C1D0E8A7F6B4C3D2E1F0A9B8C7D6E5F4A3B2C1D0E9F8A7B6C5D4E3F2A10"}}}`, "spec.document.sha256"},
		{"short digest", `{"spec":{"document":{"sha256":"sha256:9f2b5c1d"}}}`, "spec.document.sha256"},
		{"zero size", `{"spec":{"document":{"size":0}}}`, "spec.document.size"},
		{"oversized", `{"spec":{"document":{"size":1073741825}}}`, "spec.document.size"},
		{"media type with parameters", `{"spec":{"document":{"mediaType":"text/html; charset=utf-8"}}}`, "spec.document.mediaType"},
		{"blank title", `{"spec":{"document":{"title":"   "}}}`, "title must not be blank"},
		{"blank issuer", `{"spec":{"source":{"issuer":" "}}}`, "issuer must not be blank"},
		{"non-http source url", `{"spec":{"source":{"url":"file:///etc/passwd"}}}`, "spec.source.url"},
		{"blank scope", `{"spec":{"scope":{"description":"\t"}}}`, "description must not be blank"},
		{"no associations", `{"spec":{"associations":[]}}`, "spec.associations"},
		{"binding without uid", `{"spec":{"associations":[{"binding":{"name":"b"},"catalogDigest":"sha256:64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb","controls":[{"id":"pe-3"}]}]}}`, "uid: Required"},
		{"bad catalog digest", `{"spec":{"associations":[{"binding":{"name":"b","uid":"u"},"catalogDigest":"sha256:xyz","controls":[{"id":"pe-3"}]}]}}`, "catalogDigest"},
		{"no controls", `{"spec":{"associations":[{"binding":{"name":"b","uid":"u"},"catalogDigest":"sha256:64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb","controls":[]}]}}`, "controls"},
		{"duplicate control", `{"spec":{"associations":[{"binding":{"name":"b","uid":"u"},"catalogDigest":"sha256:64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb","controls":[{"id":"pe-3"},{"id":"pe-3"}]}]}}`, "Duplicate value"},
		{"duplicate statement", `{"spec":{"associations":[{"binding":{"name":"b","uid":"u"},"catalogDigest":"sha256:64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb","controls":[{"id":"pe-3","statements":["pe-3_smt.a","pe-3_smt.a"]}]}]}}`, "Duplicate value"},
		{"malformed control id", `{"spec":{"associations":[{"binding":{"name":"b","uid":"u"},"catalogDigest":"sha256:64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb","controls":[{"id":"pe 3"}]}]}}`, "controls[0].id"},
		{"same binding twice", `{"spec":{"associations":[{"binding":{"name":"b","uid":"u"},"catalogDigest":"sha256:64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb","controls":[{"id":"pe-3"}]},{"binding":{"name":"b","uid":"u"},"catalogDigest":"sha256:64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb","controls":[{"id":"pe-6"}]}]}}`, "each binding UID may be associated only once"},
		{"blank registered user", `{"spec":{"registeredBy":{"username":""}}}`, "spec.registeredBy.username"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := attachment(t)
			mergePatch(t, o, c.patch)
			errs := crds["EvidenceAttachment"].Validate(o)
			if len(errs) == 0 {
				t.Fatal("accepted, want rejection")
			}
			if got := errs.ToAggregate().Error(); !strings.Contains(got, c.expect) {
				t.Fatalf("want %q, got %q", c.expect, got)
			}
		})
	}
}

// Unsupported fields never reach storage: the structural schema prunes them
// (and strict field validation rejects them; see TestLiveEvidenceAttachmentAPI).
// No bulk document, credential, or storage location field exists in spec.
func TestEvidenceAttachmentPrunesUnsupportedFields(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	o := attachment(t)
	mergePatch(t, o, `{"spec":{"content":"JVBERi0=","bucket":"evidence","document":{"data":"JVBERi0=","verdict":"Satisfied"}}}`)
	if errs := crds["EvidenceAttachment"].Validate(o); len(errs) > 0 {
		t.Fatal(errs.ToAggregate())
	}
	spec := o["spec"].(map[string]any)
	for _, k := range []string{"content", "bucket"} {
		if _, ok := spec[k]; ok {
			t.Errorf("spec.%s survived pruning", k)
		}
	}
	doc := spec["document"].(map[string]any)
	for _, k := range []string{"data", "verdict"} {
		if _, ok := doc[k]; ok {
			t.Errorf("spec.document.%s survived pruning", k)
		}
	}
}

func TestEvidenceAttachmentSpecIsImmutable(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	for name, patch := range map[string]string{
		"document bytes":     `{"spec":{"document":{"sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}}`,
		"size":               `{"spec":{"document":{"size":1}}}`,
		"title":              `{"spec":{"document":{"title":"Renamed"}}}`,
		"validity extended":  `{"spec":{"validity":{"validUntil":"2030-01-01T00:00:00Z"}}}`,
		"source":             `{"spec":{"source":{"issuer":"Someone else"}}}`,
		"scope":              `{"spec":{"scope":{"description":"Every datacenter"}}}`,
		"association added":  `{"spec":{"associations":[{"binding":{"name":"other","uid":"x"},"catalogDigest":"sha256:64ca6b4161de51ab6af098a7d101d326f14c95e1abf721396cd8a049e8115eeb","controls":[{"id":"pe-3"}]}]}}`,
		"registrant changed": `{"spec":{"registeredBy":{"username":"someone-else"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			old := attachment(t)
			mergePatch(t, old, `{"spec":{"registeredBy":{"username":"platform-operator"}}}`)
			if errs := crds["EvidenceAttachment"].Validate(copyObj(old)); len(errs) > 0 {
				t.Fatal(errs.ToAggregate())
			}
			updated := copyObj(old)
			mergePatch(t, updated, patch)
			errs := crds["EvidenceAttachment"].ValidateUpdate(updated, copyObj(old))
			if len(errs) == 0 || !strings.Contains(errs.ToAggregate().Error(), "spec is immutable") {
				t.Fatalf("spec change accepted: %v", errs.ToAggregate())
			}
		})
	}
	// Descriptive metadata and the retention finalizer remain writable.
	old := attachment(t)
	updated := copyObj(old)
	mergePatch(t, updated, `{"metadata":{"labels":{"team":"platform"},"finalizers":["`+v1alpha1.EvidenceAttachmentFinalizer+`"]}}`)
	if errs := crds["EvidenceAttachment"].ValidateUpdate(updated, copyObj(old)); len(errs) > 0 {
		t.Fatal(errs.ToAggregate())
	}
}
