package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/rest"
)

// The production runtime publishes only through EvidenceDestinations: no
// legacy file publisher and no backend contacted at startup.
func TestEvidenceRuntime(t *testing.T) {
	cfg := &rest.Config{Host: "https://127.0.0.1:1"}
	staging := filepath.Join(t.TempDir(), "staging")
	content := filepath.Join(t.TempDir(), "content")
	rt, err := EvidenceRuntime(context.Background(), cfg, EvidenceConfig{StagingDir: staging, ContentDir: content, Namespace: "konstapel-system"})
	if err != nil {
		t.Fatal(err)
	}
	if ok, why := rt.ready(); !ok || rt.Publisher != nil || rt.Destinations == nil || rt.ContentRoot != filepath.Dir(content) || rt.ControllerNamespace != "konstapel-system" {
		t.Fatalf("runtime not configured: %v %s %+v", ok, why, rt)
	}
	if st, err := os.Stat(staging); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("staging dir: %v %v", st, err)
	}
}

func TestEvidenceRuntimeRejectsBadConfiguration(t *testing.T) {
	cfg := &rest.Config{Host: "https://127.0.0.1:1"}
	content := filepath.Join(t.TempDir(), "content")
	for name, c := range map[string]struct {
		ec   EvidenceConfig
		want string
	}{
		"content root":   {EvidenceConfig{StagingDir: t.TempDir(), ContentDir: t.TempDir(), Namespace: "ns"}, "named content"},
		"no staging dir": {EvidenceConfig{ContentDir: content, Namespace: "ns"}, "staging"},
	} {
		if _, err := EvidenceRuntime(context.Background(), cfg, c.ec); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
