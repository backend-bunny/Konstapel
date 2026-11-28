package provider_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"example.com/konstapel-reporting/certs"
	"example.com/konstapel-reporting/provider"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

// fakeAPI serves Namespace gets the way the API server does, and records
// the bearer token of every request.
type fakeAPI struct {
	mu     sync.Mutex
	tokens []string
	paths  []string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.tokens = append(f.tokens, r.Header.Get("Authorization"))
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	switch r.URL.Path {
	case "/api/v1/namespaces/team-a":
		_ = json.NewEncoder(w).Encode(map[string]any{"kind": "Namespace", "apiVersion": "v1",
			"metadata": map[string]any{"name": "team-a", "uid": "uid-a", "labels": map[string]string{"owner": "alice"}}})
	case "/api/v1/namespaces/team-b":
		_ = json.NewEncoder(w).Encode(map[string]any{"kind": "Namespace", "apiVersion": "v1", "metadata": map[string]any{"name": "team-b", "uid": "uid-b"}})
	case "/api/v1/namespaces/wrong":
		_ = json.NewEncoder(w).Encode(map[string]any{"kind": "Secret", "metadata": map[string]any{"name": "wrong", "uid": "uid-w"}})
	case "/api/v1/namespaces/forbidden":
		http.Error(w, `{"kind":"Status","reason":"Forbidden"}`, http.StatusForbidden)
	default:
		http.Error(w, `{"kind":"Status","reason":"NotFound"}`, http.StatusNotFound)
	}
}

func kubernetesSource(t *testing.T) (*provider.Kubernetes, *fakeAPI, string) {
	t.Helper()
	api := &fakeAPI{}
	srv := httptest.NewTLSServer(api)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte("first-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := provider.NewKubernetes(srv.URL, token, ca)
	if err != nil {
		t.Fatal(err)
	}
	return k, api, token
}

// The source gets one Namespace per call with the current token, reports
// 404 as absent and every other failure as an error, never as absent.
func TestKubernetesSource(t *testing.T) {
	k, api, token := kubernetesSource(t)
	ctx := context.Background()
	ns, ok, err := k.Namespace(ctx, "team-a")
	if err != nil || !ok || ns.UID != "uid-a" || ns.Labels["owner"] != "alice" {
		t.Fatalf("team-a: %+v %v %v", ns, ok, err)
	}
	if ns, ok, err := k.Namespace(ctx, "team-b"); err != nil || !ok || ns.Labels == nil || len(ns.Labels) != 0 {
		t.Fatalf("unlabeled team-b: %+v %v %v", ns, ok, err)
	}
	if _, ok, err := k.Namespace(ctx, "team-c"); err != nil || ok {
		t.Fatalf("missing team-c: %v %v, want absent", ok, err)
	}
	if _, ok, err := k.Namespace(ctx, "forbidden"); err == nil || ok || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("denied namespace: %v %v, want an error", ok, err)
	}
	if _, ok, err := k.Namespace(ctx, "wrong"); err == nil || ok {
		t.Fatalf("a response that is not the Namespace: %v %v, want an error", ok, err)
	}
	// A rotated projected token is used from the next request.
	if err := os.WriteFile(token, []byte("rotated-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.Namespace(ctx, "team-a"); err != nil {
		t.Fatal(err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if got := api.tokens[len(api.tokens)-1]; got != "Bearer rotated-token" {
		t.Errorf("after rotation the source sent %q", got)
	}
	if got := api.tokens[0]; got != "Bearer first-token" {
		t.Errorf("first request sent %q", got)
	}
	for _, p := range api.paths {
		if !strings.HasPrefix(p, "GET /api/v1/namespaces/") {
			t.Errorf("the source made request %s; it only gets Namespaces", p)
		}
	}
}

// The source only talks HTTPS to a CA it was given.
func TestKubernetesSourceRefusesUnverifiableServers(t *testing.T) {
	dir := t.TempDir()
	if _, err := provider.NewKubernetes("http://127.0.0.1:1", filepath.Join(dir, "token"), filepath.Join(dir, "ca.crt")); err == nil {
		t.Error("an http API server was accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.NewKubernetes("https://127.0.0.1:1", filepath.Join(dir, "token"), filepath.Join(dir, "ca.crt")); err == nil {
		t.Error("a CA file without a certificate was accepted")
	}
	// A CA other than the server's: the quickstart's throwaway one.
	srv := httptest.NewTLSServer(&fakeAPI{})
	defer srv.Close()
	other := filepath.Join(dir, "other")
	if err := certs.Generate(other, certs.Options{}); err != nil {
		t.Fatal(err)
	}
	k, err := provider.NewKubernetes(srv.URL, filepath.Join(dir, "token"), filepath.Join(other, "server", "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.Namespace(context.Background(), "team-a"); err == nil {
		t.Error("a server the CA does not verify answered")
	}
}

// A collection whose source fails stages nothing and fails explicitly.
func TestCollectFailsWhenTheSourceFails(t *testing.T) {
	k, _, _ := kubernetesSource(t)
	p := provider.New(k)
	_, err := p.Collect(context.Background(), collectRequest("team-a", "uid-a", "forbidden", "uid-f"))
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("collect over a denied namespace: %v", err)
	}
	if p.Staged() != 0 {
		t.Errorf("a failed collection staged %d results", p.Staged())
	}
	ref, err := p.Collect(context.Background(), collectRequest("team-a", "uid-a", "team-c", "uid-c"))
	if err != nil {
		t.Fatal(err)
	}
	_, data, err := p.Result(context.Background(), ref.GetResultId())
	if err != nil {
		t.Fatal(err)
	}
	res, err := providerkit.ParseCollectionResult(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.GetLimitations(); len(got) != 1 || got[0].GetSubject() != "uid-c" || got[0].GetMessage() != "namespace team-c is not in the Kubernetes API" {
		t.Errorf("limitations %v", got)
	}
	if got := res.GetEvidence(); len(got) != 1 || got[0].GetAttributions()[0].GetSubject() != "uid-a" {
		t.Errorf("evidence %v", got)
	}
}
