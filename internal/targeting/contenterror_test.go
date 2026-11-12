package targeting

import (
	"errors"
	"fmt"
	"testing"
)

func TestContentErrorIsContentUnavailable(t *testing.T) {
	sentinel := errors.New("producer sentinel")
	err := fmt.Errorf("profile p: %w", &ContentError{Class: ContentErrorUntrusted, Detail: "b@sha256:x: untrusted", Err: sentinel})
	if !errors.Is(err, ErrContentUnavailable) || !errors.Is(err, sentinel) {
		t.Fatalf("%v", err)
	}
	if ContentErrorClassOf(err) != ContentErrorUntrusted {
		t.Fatal(ContentErrorClassOf(err))
	}
	if got, want := err.Error(), "profile p: content unavailable: Untrusted: b@sha256:x: untrusted"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	if ContentErrorClassOf(fmt.Errorf("%w: plain", ErrContentUnavailable)) != "" {
		t.Fatal("an unclassified error has a class")
	}
}

// ScopeUnsupported is rejected like Cluster scope.
func TestUnsupportedScopeIsRejected(t *testing.T) {
	m := map[string]any{"apiVersion": "kyverno.io/v1", "kind": "ClusterPolicy"}
	if _, err := PolicyScopeOf(m, StandardWorkloadScopes); err == nil {
		t.Fatal("PolicyScopeOf accepted a ClusterPolicy")
	}
	if _, err := Render(Contribution{Policy: "x", Mode: "Audit"}, PolicySource{Manifest: m}); err == nil {
		t.Fatal("rendered an unsupported policy")
	}
}
