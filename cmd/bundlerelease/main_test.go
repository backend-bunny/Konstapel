package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/publish"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

// Only verify-release may report a release complete.
func TestPublishNeverReportsComplete(t *testing.T) {
	for _, c := range []struct {
		res *publish.Result
		err error
	}{
		{&publish.Result{Complete: true}, nil},
		{&publish.Result{Missing: []registry.ProofKind{registry.ProofProvenance}}, nil},
		{&publish.Result{Complete: true}, errors.New("x")},
	} {
		if s := publishStatus(c.res, c.err); s == "complete" || strings.HasPrefix(s, "complete") {
			t.Errorf("publish reported %q", s)
		}
	}
}

func TestTrustObjectsFromFiles(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "cosign.pub")
	_ = os.WriteFile(key, []byte("pem"), 0o600)
	keyRule := bundle.BundleSource{Publisher: bundle.Publisher{Type: bundle.SignerPublicKey, PublicKey: &bundle.ObjectRef{Kind: bundle.KindSecret, Name: "k"}}}
	keyless := bundle.BundleSource{Publisher: bundle.Publisher{Type: bundle.SignerKeyless}}
	r, err := trustObjects(keyRule, key, "")
	if err != nil {
		t.Fatal(err)
	}
	if o, err := r.Get(context.Background(), bundle.KindSecret, "k"); err != nil {
		t.Fatal(err)
	} else if v, ok := o.Value(bundle.DefaultPublicKey); !ok || string(v) != "pem" {
		t.Fatal("key not under its default data key")
	}
	if _, err := trustObjects(keyRule, "", ""); err == nil {
		t.Error("a referenced key without -public-key-file was accepted")
	}
	if _, err := trustObjects(keyless, key, ""); err == nil {
		t.Error("a key for a rule that references none was accepted")
	}
	if _, err := trustObjects(keyless, "", key); err == nil {
		t.Error("a trust root for a rule that references none was accepted: the official rule uses the embedded root")
	}
	if _, err := trustObjects(keyless, "", ""); err != nil {
		t.Error(err)
	}
}

func TestWorkflowRunSource(t *testing.T) {
	o := options{wf: publish.Workflow{Repository: "https://x.example/r", Path: "ci.yml", Commit: strings.Repeat("a", 40)}}
	t.Setenv("GITHUB_ACTIONS", "true")
	if _, err := workflowRun(o); err == nil {
		t.Error("-workflow-* flags accepted inside GitHub Actions")
	}
	t.Setenv("GITHUB_ACTIONS", "")
	if r, err := workflowRun(o); err != nil || r.Workflow != o.wf || r.Identity != "" {
		t.Errorf("%+v %v", r, err)
	}
	if _, err := workflowRun(options{}); err == nil {
		t.Error("no workflow revision accepted outside GitHub Actions")
	}
}

func TestVerifyReleaseArguments(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{
		{"verify-release"},
		{"verify-release", "-name", "konstapel-privileged-containers"},
		{"verify-release", "-name", "not-configured", "-digest", "sha256:" + strings.Repeat("a", 64), "-repo", "../.."},
	} {
		if err := run(context.Background(), args, &out); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
	if strings.Contains(out.String(), "status=complete") {
		t.Fatal("reported complete")
	}
}

// release-notes needs a package and a verification record, and never reaches
// GitHub without them.
func TestReleaseNotesArguments(t *testing.T) {
	for name, args := range map[string][]string{
		"no arguments":            {"release-notes"},
		"no package":              {"release-notes", "-name", "demo", "-verification", "v.json"},
		"no verification":         {"release-notes", "-name", "demo", "-package", "p"},
		"package that is missing": {"release-notes", "-name", "demo", "-package", filepath.Join(t.TempDir(), "absent"), "-verification", filepath.Join(t.TempDir(), "absent.json"), "-announce"},
	} {
		var out bytes.Buffer
		if err := run(context.Background(), args, &out); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if strings.Contains(out.String(), "release=") {
			t.Errorf("%s: reported a release: %q", name, out.String())
		}
	}
}
