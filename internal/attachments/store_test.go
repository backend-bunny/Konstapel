package attachments

import (
	"os"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func TestExpiresAtKeepsValidityAvailable(t *testing.T) {
	committed := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	year := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	past := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	// A year-long document stays for its declared period plus the tail,
	// independent of a 90-day assessment-package retention.
	if got := ExpiresAt(committed, year, DefaultRetention); !got.Equal(year.Add(2160 * time.Hour)) {
		t.Fatalf("future validity: %s", got)
	}
	// An already expired document still gets the tail after commitment.
	if got := ExpiresAt(committed, past, DefaultRetention); !got.Equal(committed.Add(2160 * time.Hour)) {
		t.Fatalf("past validity: %s", got)
	}
	if got := ExpiresAt(committed, committed, time.Hour); !got.Equal(committed.Add(time.Hour)) {
		t.Fatalf("equal: %s", got)
	}
}

func TestValidateRetention(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Hour, 1500 * time.Millisecond} {
		if ValidateRetention(d) == nil {
			t.Errorf("%s accepted", d)
		}
	}
	if err := ValidateRetention(DefaultRetention); err != nil {
		t.Fatal(err)
	}
}

func TestSpecDigestCoversEvidenceDefiningFields(t *testing.T) {
	base := v1alpha1.EvidenceAttachmentSpec{
		Document:     v1alpha1.AttachmentDocument{Title: "t", MediaType: "application/pdf", Size: 1, SHA256: "sha256:" + strings.Repeat("a", 64)},
		Source:       v1alpha1.AttachmentSource{Issuer: "i"},
		Validity:     v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(time.Unix(0, 0)), ValidUntil: metav1.NewTime(time.Unix(100, 0))},
		Associations: []v1alpha1.AttachmentAssociation{{Binding: v1alpha1.ExactBindingReference{Name: "b", UID: "u"}, CatalogDigest: "sha256:" + strings.Repeat("c", 64), Controls: []v1alpha1.AttachmentControl{{ID: "pe-3"}}}},
		Scope:        v1alpha1.AttachmentScope{Description: "d"},
		RegisteredBy: &v1alpha1.Requester{Username: "r"},
	}
	d := SpecDigest(base)
	if d != SpecDigest(*base.DeepCopy()) {
		t.Fatal("digest is not deterministic")
	}
	edits := map[string]func(*v1alpha1.EvidenceAttachmentSpec){
		"validity":     func(s *v1alpha1.EvidenceAttachmentSpec) { s.Validity.ValidUntil = metav1.NewTime(time.Unix(200, 0)) },
		"association":  func(s *v1alpha1.EvidenceAttachmentSpec) { s.Associations[0].Binding.UID = "u2" },
		"registrant":   func(s *v1alpha1.EvidenceAttachmentSpec) { s.RegisteredBy.Username = "x" },
		"document":     func(s *v1alpha1.EvidenceAttachmentSpec) { s.Document.Size = 2 },
		"source claim": func(s *v1alpha1.EvidenceAttachmentSpec) { s.Source.Issuer = "j" },
	}
	for name, edit := range edits {
		s := base.DeepCopy()
		edit(s)
		if SpecDigest(*s) == d {
			t.Errorf("%s does not change the spec digest", name)
		}
	}
}

// The worked example in docs/supporting-evidence.md ("Retention"): source
// and package copies expire independently.
func TestDocumentedRetentionExample(t *testing.T) {
	raw, err := os.ReadFile("../../docs/supporting-evidence.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	day := func(s string) time.Time { d, _ := time.Parse("2006-01-02", s); return d }
	pkg := 90 * 24 * time.Hour
	source := ExpiresAt(day("2026-03-01"), day("2027-01-01"), DefaultRetention)
	expired := ExpiresAt(day("2026-03-01"), day("2025-12-31"), DefaultRetention)
	for _, c := range []struct {
		got  time.Time
		want string
	}{
		{source, "2027-04-01"},
		{day("2026-06-01").Add(pkg), "2026-08-30"},
		{day("2027-03-01").Add(pkg), "2027-05-30"},
		{expired, "2026-05-30"},
	} {
		if got := c.got.Format("2006-01-02"); got != c.want || !strings.Contains(doc, c.want) {
			t.Errorf("computed %s, documented %s (present: %v)", got, c.want, strings.Contains(doc, c.want))
		}
	}
	if !day("2027-03-01").Add(pkg).After(source) || !source.After(day("2026-06-01").Add(pkg)) {
		t.Error("the example must show a package outliving the source and the source outliving a package")
	}
}
