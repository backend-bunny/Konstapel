package coverage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// packaged is a bind-a platform descriptor whose context is the shared
// current fixture, limited to bind-a, with its document included.
func packaged(t *testing.T) (*SupportingEvidenceContext, publication.Descriptor) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(supportingDir, "current.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseSupportingContext(raw)
	if err != nil {
		t.Fatal(err)
	}
	c.Entries = c.Entries[:1]
	e := &c.Entries[0]
	e.Access = AccessIncluded
	e.Document.Copy = SupportingCopyPath(e.Source)
	run := publication.RunRef{ClusterID: "kube-system:c", BindingUID: "bind-a", RunUID: "run-1"}
	scope := publication.Scope{Kind: publication.ScopeBinding, ClusterID: run.ClusterID, BindingUID: run.BindingUID, NamespaceUIDs: []string{"ns-a"}, Revision: "r"}
	d := publication.Descriptor{Run: run, Scope: scope, Window: publication.Window{Started: e.ObservedAt.Add(-time.Minute), Closed: e.ObservedAt.Add(time.Minute)},
		Files: []publication.File{
			{Path: publication.SupportingContextFile, Role: publication.RoleSupportingContext, SHA256: strings.Repeat("1", 64), Size: 1},
			{Path: e.Document.Copy, Role: publication.RoleSupportingDocument, SHA256: e.Document.SHA256, Size: e.Document.Size}}}
	d.Protection = publication.ProtectionFor(d.Files)
	return c, d
}

func encode(t *testing.T, c *SupportingEvidenceContext) []byte {
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPackagedSupportingContextVerifies(t *testing.T) {
	c, d := packaged(t)
	if err := VerifySupportingContext(encode(t, c), d); err != nil {
		t.Fatal(err)
	}
	// Another binding's entry (as in the unfiltered fixture) is never in
	// this package, even without a copy.
	other := c.Entries[0]
	other.BindingUID, other.Access = "bind-b", AccessNotIncluded
	doc := *other.Document
	doc.Copy = ""
	other.Document = &doc
	c.Entries = append(c.Entries, other)
	if err := VerifySupportingContext(encode(t, c), d); err == nil || !strings.Contains(err.Error(), "another binding") {
		t.Fatalf("a context with another binding's entry: %v", err)
	}
}

func TestPackagedSupportingContextRejects(t *testing.T) {
	doc := func(d *publication.Descriptor) *publication.File { return &d.Files[1] }
	cases := map[string]func(*SupportingEvidenceContext, *publication.Descriptor){
		"namespace package": func(_ *SupportingEvidenceContext, d *publication.Descriptor) {
			d.Scope.Kind = publication.ScopeNamespace
		},
		"copy digest differs": func(_ *SupportingEvidenceContext, d *publication.Descriptor) { doc(d).SHA256 = strings.Repeat("9", 64) },
		"copy size differs":   func(_ *SupportingEvidenceContext, d *publication.Descriptor) { doc(d).Size++ },
		"copy missing": func(_ *SupportingEvidenceContext, d *publication.Descriptor) {
			d.Files = d.Files[:1]
		},
		"dangling copy path": func(c *SupportingEvidenceContext, _ *publication.Descriptor) {
			c.Entries[0].Document.Copy = publication.SupportingDocumentDir + "other"
		},
		"uncited document": func(c *SupportingEvidenceContext, _ *publication.Descriptor) {
			c.Entries[0].Access, c.Entries[0].Document.Copy = AccessNotIncluded, ""
		},
		"restricted entry": func(c *SupportingEvidenceContext, d *publication.Descriptor) {
			c.Entries[0].Access, c.Entries[0].Document, c.Entries[0].Revision = AccessRestricted, nil, ""
			d.Files = d.Files[:1]
		},
		"observed after closure": func(c *SupportingEvidenceContext, d *publication.Descriptor) {
			d.Window.Closed = c.Entries[0].ObservedAt.Add(-time.Second)
		},
		"unavailable context": func(c *SupportingEvidenceContext, d *publication.Descriptor) {
			c.Integration, c.Reason, c.Entries = IntegrationUnavailable, "RecordsUnavailable", nil
			d.Files = d.Files[:1]
		},
		"empty context": func(c *SupportingEvidenceContext, d *publication.Descriptor) {
			c.Entries = []SupportingEntry{}
			d.Files = d.Files[:1]
		},
		"context role missing": func(_ *SupportingEvidenceContext, d *publication.Descriptor) {
			d.Files[0].Role = publication.RoleProvenance
		},
	}
	for name, mutate := range cases {
		c, d := packaged(t)
		mutate(c, &d)
		if VerifySupportingContext(encode(t, c), d) == nil {
			t.Errorf("%s: verified", name)
		}
	}
	c, d := packaged(t)
	if VerifySupportingContext(append(encode(t, c)[:10], '}'), d) == nil {
		t.Error("a malformed context verified")
	}
	if VerifySupportingContext([]byte(strings.Replace(string(encode(t, c)), `"entries"`, `"verdict":"satisfied","entries"`, 1)), d) == nil {
		t.Error("a context with a verdict field verified")
	}
}
