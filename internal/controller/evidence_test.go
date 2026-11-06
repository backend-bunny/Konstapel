package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/rest"
)

func writeDestination(t *testing.T, body string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "destination.yaml")
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

const testDestination = `id: test
endpoint: http://127.0.0.1:9
bucket: evidence
region: us-east-1
addressing: path
developmentFixture: true
credentialSecret:
  name: s3
`

func TestEvidenceRuntime(t *testing.T) {
	cfg := &rest.Config{Host: "https://127.0.0.1:1"}
	staging := filepath.Join(t.TempDir(), "staging")
	content := filepath.Join(t.TempDir(), "content")
	rt, err := EvidenceRuntime(context.Background(), cfg, EvidenceConfig{
		Destination: writeDestination(t, testDestination), StagingDir: staging, ContentDir: content, Namespace: "konstapel-system"})
	if err != nil {
		t.Fatal(err)
	}
	if ok, why := rt.ready(); !ok || rt.Ready == nil || rt.ContentRoot != filepath.Dir(content) {
		t.Fatalf("runtime not configured: %v %s %+v", ok, why, rt)
	}
	if st, err := os.Stat(staging); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("staging dir: %v %v", st, err)
	}
	// The backend is unreachable and the Secret unreadable: not ready, never a fallback.
	if err := rt.Ready(context.Background()); err == nil {
		t.Fatal("unreachable backend reported ready")
	}
}

func TestEvidenceRuntimeRejectsBadConfiguration(t *testing.T) {
	cfg := &rest.Config{Host: "https://127.0.0.1:1"}
	content := filepath.Join(t.TempDir(), "content")
	for name, c := range map[string]struct {
		ec   EvidenceConfig
		want string
	}{
		"unknown field":  {EvidenceConfig{Destination: writeDestination(t, testDestination+"bogus: 1\n"), StagingDir: t.TempDir(), ContentDir: content, Namespace: "ns"}, "bogus"},
		"no namespace":   {EvidenceConfig{Destination: writeDestination(t, testDestination), StagingDir: t.TempDir(), ContentDir: content}, "POD_NAMESPACE"},
		"content root":   {EvidenceConfig{Destination: writeDestination(t, testDestination), StagingDir: t.TempDir(), ContentDir: t.TempDir(), Namespace: "ns"}, "named content"},
		"no staging dir": {EvidenceConfig{Destination: writeDestination(t, testDestination), ContentDir: content, Namespace: "ns"}, "staging"},
	} {
		if _, err := EvidenceRuntime(context.Background(), cfg, c.ec); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
