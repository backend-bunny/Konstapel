package attachments

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/coverage"
)

func vendored(t *testing.T) *Baseline {
	t.Helper()
	b, err := ReadVendoredBaseline(os.DirFS("../.."))
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

// The coverage owner's reader resolves the baseline; whatever it cannot
// resolve is a resolution failure (pending), never a mismatch, and never a
// guessed inventory. The digest of other content is never substituted.
func TestUnresolvedBaselinesFailClosed(t *testing.T) {
	src := os.DirFS("../..")
	tree := func(edit func(m fstest.MapFS)) fstest.MapFS {
		m := fstest.MapFS{}
		for _, p := range []string{"content/SHA256SUMS", CatalogPath, BaselinePath} {
			b, err := fs.ReadFile(src, p)
			if err != nil {
				t.Fatal(err)
			}
			m[p] = &fstest.MapFile{Data: b}
		}
		for _, v := range coverage.SupportedOSCAL {
			b, err := fs.ReadFile(src, "content/schemas/oscal-"+v+".json")
			if err != nil {
				t.Fatal(err)
			}
			m["content/schemas/oscal-"+v+".json"] = &fstest.MapFile{Data: b}
		}
		edit(m)
		return m
	}
	if _, err := ReadVendoredBaseline(tree(func(fstest.MapFS) {})); err != nil {
		t.Fatalf("intact copy: %v", err)
	}
	for name, edit := range map[string]func(fstest.MapFS){
		"profile changed after its checksum": func(m fstest.MapFS) { m[BaselinePath].Data = append([]byte(" "), m[BaselinePath].Data...) },
		"catalog missing":                    func(m fstest.MapFS) { delete(m, CatalogPath) },
		"profile not json":                   func(m fstest.MapFS) { m[BaselinePath].Data = []byte("{") },
		"no checksums":                       func(m fstest.MapFS) { delete(m, "content/SHA256SUMS") },
		"no trusted schema":                  func(m fstest.MapFS) { delete(m, "content/schemas/oscal-1.2.3.json") },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ReadVendoredBaseline(tree(edit))
			if !errors.Is(err, ErrBaseline) {
				t.Fatalf("got %v, want ErrBaseline", err)
			}
		})
	}
	// An unresolved coverage inventory is both ErrBaseline and
	// coverage.ErrUnresolved: callers treat it as resolution, not mismatch.
	_, err := ReadVendoredBaseline(tree(func(m fstest.MapFS) { delete(m, CatalogPath) }))
	if !errors.Is(err, coverage.ErrUnresolved) {
		t.Fatalf("got %v, want coverage.ErrUnresolved", err)
	}
	if _, err := ReadBaseline(coverage.Content{}, coverage.Options{}); !errors.Is(err, ErrBaseline) {
		t.Fatalf("zero handle: %v", err)
	}
}
