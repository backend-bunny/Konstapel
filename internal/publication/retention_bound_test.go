package publication_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/crdtest"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// recovered is a signed receipt committed by signing recovery late in its
// retention: the commit (day 80) keeps the expiry recorded at the signing
// failure (day 90 from closure), not publishedAt + retention.
func recovered() publication.Receipt {
	r := receipt()
	closure := r.PublishedAt.Add(-80 * 24 * time.Hour)
	notAfter := closure.Add(2160 * time.Hour)
	r.Retention.NotAfter = &notAfter
	r.ExpiresAt = notAfter
	r.Signature = &publication.Signature{Key: "konstapel/pub-1/package.sigstore.json", SHA256: strings.Repeat("3", 64), Size: 900,
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json", Algorithm: "ecdsa-sha2-256-nistp256", KeyFingerprint: "sha256:" + strings.Repeat("4", 64)}
	return r
}

// add-evidence-signing-recovery 2.1: with retention.notAfter the expiry is
// notAfter and may never be after publishedAt + duration; without it the
// existing equality holds.
func TestRetentionNotAfterBoundsExpiry(t *testing.T) {
	r := recovered()
	if err := r.Validate(); err != nil {
		t.Fatalf("recovered receipt: %v", err)
	}
	if !r.ExpiresAt.Before(r.PublishedAt.Add(2160 * time.Hour)) {
		t.Fatal("fixture does not exercise a bound earlier than publishedAt + retention")
	}
	// The bound may equal publishedAt + duration.
	eq := recovered()
	full := eq.PublishedAt.Add(2160 * time.Hour)
	eq.Retention.NotAfter, eq.ExpiresAt = &full, full
	if err := eq.Validate(); err != nil {
		t.Fatalf("notAfter = publishedAt + retention: %v", err)
	}
	// A commit landing at or after the bound is a valid, already expired record.
	for _, at := range []time.Duration{0, time.Second} {
		late := recovered()
		late.PublishedAt = late.Retention.NotAfter.Add(at)
		if err := late.Validate(); err != nil || late.PublishedAt.Before(late.ExpiresAt) {
			t.Fatalf("late commit (+%s): %v", at, err)
		}
	}
	for name, edit := range map[string]func(*publication.Receipt){
		"expiry from duration despite notAfter": func(r *publication.Receipt) { r.ExpiresAt = r.PublishedAt.Add(2160 * time.Hour) },
		"expiry other than notAfter":            func(r *publication.Receipt) { r.ExpiresAt = r.ExpiresAt.Add(-time.Second) },
		"notAfter extends retention": func(r *publication.Receipt) {
			ext := r.PublishedAt.Add(2160*time.Hour + time.Second)
			r.Retention.NotAfter, r.ExpiresAt = &ext, ext
		},
		"zero notAfter": func(r *publication.Receipt) {
			z := time.Time{}
			r.Retention.NotAfter, r.ExpiresAt = &z, z
		},
		"unsigned with notAfter": func(r *publication.Receipt) { r.Signature = nil },
		"no publication time":    func(r *publication.Receipt) { r.PublishedAt = time.Time{} },
	} {
		bad := recovered()
		edit(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if err := publication.Committed(bad).Validate(); err == nil {
			t.Errorf("%s: committed status accepted", name)
		}
	}
	// Without the bound, the equality is unchanged.
	plain := receipt()
	plain.ExpiresAt = plain.ExpiresAt.Add(-time.Second)
	if err := plain.Validate(); err == nil {
		t.Fatal("an unbounded receipt with an earlier expiry was accepted")
	}
	if got, err := receipt().Retention.Expiry(receipt().PublishedAt); err != nil || !got.Equal(receipt().ExpiresAt) {
		t.Fatalf("unbounded expiry %s %v", got, err)
	}
}

// The field is additive: a retention without it serializes exactly as
// before, and the bound round-trips through the AssessmentRun API and its
// CRD schema.
func TestRetentionNotAfterIsAdditive(t *testing.T) {
	b, _ := json.Marshal(receipt().Retention)
	if want := `{"duration":"2160h","bindingConfiguration":"binding-config-3","selectedAt":"2026-11-05T10:04:59Z"}`; string(b) != want {
		t.Fatalf("unbounded retention changed:\n%s\n%s", b, want)
	}
	crds := crdtest.Load(t, "../../config/crd/bases")
	for _, s := range []publication.Status{publication.Committed(recovered()), publication.Committed(receipt())} {
		pub := publication.ToAPI(s)
		if (pub.Retention.NotAfter == nil) != (s.Retention.NotAfter == nil) {
			t.Fatalf("notAfter lost in conversion: %+v", pub.Retention)
		}
		back := publication.FromAPI(pub)
		x, _ := json.Marshal(s)
		y, _ := json.Marshal(back)
		if string(x) != string(y) || back.Validate() != nil {
			t.Fatalf("conversion is lossy:\n%s\n%s", x, y)
		}
		run := v1alpha1.AssessmentRun{Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: "b"}, Scope: v1alpha1.RunScopeBinding}}
		run.APIVersion, run.Kind, run.Name = v1alpha1.GroupVersion.String(), "AssessmentRun", "run"
		run.Status.Publication = &pub
		raw, _ := json.Marshal(run)
		var o map[string]any
		_ = json.Unmarshal(raw, &o)
		if errs := crds["AssessmentRun"].Validate(o); len(errs) > 0 {
			t.Fatalf("status rejected by CRD schema: %v", errs.ToAggregate())
		}
	}
}
