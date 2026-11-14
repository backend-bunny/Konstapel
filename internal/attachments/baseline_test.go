package attachments

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func vendored(t *testing.T) *Baseline {
	t.Helper()
	b, err := ReadBaseline(os.DirFS("../.."))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVendoredBaselineSelectsPhysicalControls(t *testing.T) {
	b := vendored(t)
	raw, err := os.ReadFile("../../" + CatalogPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if want := "sha256:" + hex.EncodeToString(sum[:]); b.CatalogDigest != want {
		t.Fatalf("catalog digest %s, want %s", b.CatalogDigest, want)
	}
	// Moderate selects PE-3 (no technical mapping) and its statements, not
	// PE-3(1) or AC-2(6).
	if !b.Controls["pe-3"]["pe-3_smt.a"] || !b.Controls["pe-3"]["pe-3_smt"] {
		t.Fatalf("pe-3 statements missing: %v", b.Controls["pe-3"])
	}
	if b.Controls["pe-3"]["pe-3_gdn"] || b.Controls["pe-3"]["pe-3_obj.a"] {
		t.Fatal("guidance or assessment-objective parts counted as statements")
	}
	if !b.Controls["ac-2"]["ac-2_smt.d.1"] {
		t.Fatal("nested statement items missing")
	}
	for _, id := range []string{"pe-3.1", "ac-2.6"} {
		if _, ok := b.Controls[id]; ok {
			t.Fatalf("%s is not in the Moderate baseline", id)
		}
	}
}

func assoc(digest string, controls ...v1alpha1.AttachmentControl) v1alpha1.AttachmentAssociation {
	return v1alpha1.AttachmentAssociation{Binding: v1alpha1.ExactBindingReference{Name: "b", UID: "u"}, CatalogDigest: digest, Controls: controls}
}

func TestCheckAssociations(t *testing.T) {
	b := vendored(t)
	other := "sha256:" + strings.Repeat("0", 64)
	cases := []struct {
		name   string
		a      v1alpha1.AttachmentAssociation
		reason string
	}{
		{"physical control with statements", assoc(b.CatalogDigest, v1alpha1.AttachmentControl{ID: "pe-3", Statements: []string{"pe-3_smt.a", "pe-3_smt.b"}}, v1alpha1.AttachmentControl{ID: "pe-6"}), ""},
		{"enhancement in baseline", assoc(b.CatalogDigest, v1alpha1.AttachmentControl{ID: "pe-6.1"}), ""},
		{"wrong catalog", assoc(other, v1alpha1.AttachmentControl{ID: "pe-3"}), v1alpha1.ReasonCatalogMismatch},
		{"control outside baseline", assoc(b.CatalogDigest, v1alpha1.AttachmentControl{ID: "pe-3.1"}), v1alpha1.ReasonControlNotInBaseline},
		{"unknown control", assoc(b.CatalogDigest, v1alpha1.AttachmentControl{ID: "zz-1"}), v1alpha1.ReasonControlNotInBaseline},
		{"statement of another control", assoc(b.CatalogDigest, v1alpha1.AttachmentControl{ID: "pe-3", Statements: []string{"pe-2_smt.a"}}), v1alpha1.ReasonStatementNotInControl},
		{"guidance is not a statement", assoc(b.CatalogDigest, v1alpha1.AttachmentControl{ID: "pe-3", Statements: []string{"pe-3_gdn"}}), v1alpha1.ReasonStatementNotInControl},
		{"enhancement statement under base control", assoc(b.CatalogDigest, v1alpha1.AttachmentControl{ID: "ac-2", Statements: []string{"ac-2.1_smt"}}), v1alpha1.ReasonStatementNotInControl},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := b.Check(c.a)
			switch {
			case c.reason == "" && m != nil:
				t.Fatalf("rejected: %v", m)
			case c.reason != "" && (m == nil || m.Reason != c.reason):
				t.Fatalf("got %v, want %s", m, c.reason)
			}
		})
	}
}

func TestMismatchMessagesAreBounded(t *testing.T) {
	b := vendored(t)
	var cs []v1alpha1.AttachmentControl
	for i := range 64 {
		cs = append(cs, v1alpha1.AttachmentControl{ID: "zz-" + strings.Repeat("x", 100) + string(rune('a'+i%26)) + strings.Repeat("y", i)})
	}
	m := b.Check(assoc(b.CatalogDigest, cs...))
	if m == nil || !strings.Contains(m.Message, "and 56 more") {
		t.Fatalf("got %v", m)
	}
}

func TestUnsupportedBaselinesFailClosed(t *testing.T) {
	catalog := `{"catalog":{"groups":[{"controls":[{"id":"pe-3","parts":[{"id":"pe-3_smt","name":"statement"}]}]}]}}`
	for name, profile := range map[string]string{
		"include-all":     `{"profile":{"imports":[{"href":"#c","include-all":{}}]}}`,
		"matching":        `{"profile":{"imports":[{"href":"#c","include-controls":[{"matching":[{"pattern":"pe-*"}]}]}]}}`,
		"two imports":     `{"profile":{"imports":[{"href":"#c","include-controls":[{"with-ids":["pe-3"]}]},{"href":"#d","include-controls":[{"with-ids":["pe-3"]}]}]}}`,
		"unknown control": `{"profile":{"imports":[{"href":"#c","include-controls":[{"with-ids":["pe-9"]}]}]}}`,
		"all excluded":    `{"profile":{"imports":[{"href":"#c","include-controls":[{"with-ids":["pe-3"]}],"exclude-controls":[{"with-ids":["pe-3"]}]}]}}`,
		"not json":        `{`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ReadBaseline(fstest.MapFS{CatalogPath: {Data: []byte(catalog)}, BaselinePath: {Data: []byte(profile)}})
			if !errors.Is(err, ErrBaseline) {
				t.Fatalf("got %v, want ErrBaseline", err)
			}
		})
	}
	if _, err := ReadBaseline(fstest.MapFS{}); !errors.Is(err, ErrBaseline) {
		t.Fatalf("missing content: %v", err)
	}
}
