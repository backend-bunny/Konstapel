package release

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/publish"
)

const repoRoot = "../../.."

func githubEnv(over map[string]string) func(string) string {
	env := map[string]string{
		"GITHUB_SERVER_URL":   "https://github.com",
		"GITHUB_REPOSITORY":   "backend-bunny/Konstapel",
		"GITHUB_WORKFLOW_REF": "backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main",
		"GITHUB_REF":          "refs/heads/main",
		"GITHUB_SHA":          "834c259212c1f11d41faf42b81f361a7f7107e53",
		"GITHUB_RUN_ID":       "123456",
		"GITHUB_RUN_ATTEMPT":  "2",
	}
	for k, v := range over {
		env[k] = v
	}
	return func(k string) string { return env[k] }
}

func TestRunFromGitHub(t *testing.T) {
	r, err := RunFromGitHub(githubEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := publish.Workflow{Repository: OfficialRepositoryURL, Path: OfficialWorkflowPath, Ref: OfficialWorkflowRef, Commit: "834c259212c1f11d41faf42b81f361a7f7107e53"}
	if r.Workflow != want || r.Identity != OfficialIdentity() ||
		r.InvocationID != "https://github.com/backend-bunny/Konstapel/actions/runs/123456/attempts/2" {
		t.Fatalf("%+v", r)
	}
	if r, _ := RunFromGitHub(githubEnv(map[string]string{"GITHUB_RUN_ID": "x"})); r.InvocationID != "" {
		t.Fatalf("invocation from a non-numeric run id: %q", r.InvocationID)
	}
	for name, over := range map[string]map[string]string{
		"ref differs from the workflow ref":  {"GITHUB_REF": "refs/heads/dev"},
		"workflow ref of another repository": {"GITHUB_WORKFLOW_REF": "evil/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main"},
		"workflow ref without a ref":         {"GITHUB_WORKFLOW_REF": "backend-bunny/Konstapel/.github/workflows/bundle-release.yml"},
		"short sha":                          {"GITHUB_SHA": "834c259"},
		"no sha":                             {"GITHUB_SHA": ""},
		"plain http server":                  {"GITHUB_SERVER_URL": "http://github.com"},
		"server with a path":                 {"GITHUB_SERVER_URL": "https://github.com/x"},
		"repository is not owner/name":       {"GITHUB_REPOSITORY": "Konstapel"},
	} {
		if _, err := RunFromGitHub(githubEnv(over)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func loadOfficial(t *testing.T) bundle.Sources {
	t.Helper()
	s, err := LoadSources(filepath.Join(repoRoot, OfficialSourcesFile))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The checked-in official rule, the release workflow and the tool agree:
// every bundle in bundles/ has a keyless rule whose identity and builder
// are exactly the release workflow on main, on the official registry, with
// the embedded public-good root and anonymous access.
func TestOfficialRuleMatchesTheReleaseWorkflow(t *testing.T) {
	if OfficialIdentity() != "https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main" {
		t.Fatalf("official identity %s", OfficialIdentity())
	}
	off := loadOfficial(t)
	if len(off.Sources) == 0 {
		t.Fatal("no official sources")
	}
	byName := map[string]bundle.BundleSource{}
	for _, s := range off.Sources {
		p := s.Publisher
		switch {
		case p.Type != bundle.SignerKeyless || p.Issuer != GitHubIssuer:
			t.Errorf("%s: publisher %s/%s, want keyless by %s", s.Name, p.Type, p.Issuer, GitHubIssuer)
		case p.Identity != OfficialIdentity():
			t.Errorf("%s: identity %s, want %s", s.Name, p.Identity, OfficialIdentity())
		case p.Provenance.Builder != p.Identity:
			t.Errorf("%s: builder %s differs from the signing identity %s", s.Name, p.Provenance.Builder, p.Identity)
		case p.Provenance.SourceRepository != OfficialRepositoryURL:
			t.Errorf("%s: source %s", s.Name, p.Provenance.SourceRepository)
		case p.TrustRoot != nil || s.CredentialSecret != nil || s.CA != nil:
			t.Errorf("%s: official sources use the embedded root and anonymous public access", s.Name)
		case s.Repository != OfficialRegistry+"/"+s.Name:
			t.Errorf("%s: repository %s, want %s/%s", s.Name, s.Repository, OfficialRegistry, s.Name)
		}
		byName[s.Name] = s
	}
	defs, err := filepath.Glob(filepath.Join(repoRoot, "bundles", "*", "definition.json"))
	if err != nil || len(defs) == 0 {
		t.Fatalf("bundle definitions: %v", err)
	}
	for _, d := range defs {
		name := filepath.Base(filepath.Dir(d))
		raw, err := os.ReadFile(d)
		if err != nil {
			t.Fatal(err)
		}
		def, err := bundle.LoadDefinition(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := byName[name]; !ok {
			t.Errorf("bundles/%s has no rule in %s; it could be published but never verified", name, OfficialSourcesFile)
		}
		if def.Source.Repository != OfficialRepositoryURL {
			t.Errorf("bundles/%s declares source %s", name, def.Source.Repository)
		}
	}
	// The workflow that signs is the one the identity names, and it only
	// runs from that ref.
	w, raw := loadWorkflow(t, filepath.Base(OfficialWorkflowPath))
	if filepath.Join(".github", "workflows", filepath.Base(OfficialWorkflowPath)) != OfficialWorkflowPath {
		t.Fatalf("workflow path %s", OfficialWorkflowPath)
	}
	for name, job := range w.Jobs {
		if job.If != "github.ref == '"+OfficialWorkflowRef+"'" {
			t.Errorf("job %s runs outside %s", name, OfficialWorkflowRef)
		}
	}
	if !strings.Contains(raw, "-signing keyless") {
		t.Error("the release workflow does not sign keylessly")
	}
	// A run of that workflow on main passes the pre-signing rule check for
	// every official bundle.
	run, err := RunFromGitHub(githubEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range off.Sources {
		if err := CheckSigningRule(s, true, run, officialRecord(s.Name)); err != nil {
			t.Errorf("%s: %v", s.Name, err)
		}
	}
}

func officialRecord(name string) publish.Record {
	var r publish.Record
	r.Name = name
	r.Source.Repository = OfficialRepositoryURL
	return r
}

func TestCheckSigningRuleRefusesMismatches(t *testing.T) {
	off := loadOfficial(t)
	src := off.Sources[0]
	run, _ := RunFromGitHub(githubEnv(nil))
	keyRule := src
	keyRule.Publisher = bundle.Publisher{
		Type: bundle.SignerPublicKey, PublicKey: &bundle.ObjectRef{Kind: bundle.KindSecret, Name: "k"},
		KeyFingerprint: "sha256:" + strings.Repeat("a", 64), Provenance: src.Publisher.Provenance,
	}
	edit := func(fn func(*bundle.BundleSource)) bundle.BundleSource {
		s := src
		fn(&s)
		return s
	}
	runFrom := func(over map[string]string) Run {
		r, err := RunFromGitHub(githubEnv(over))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, c := range []struct {
		name    string
		src     bundle.BundleSource
		keyless bool
		run     Run
		rec     publish.Record
	}{
		{"another workflow file", src, true, runFrom(map[string]string{"GITHUB_WORKFLOW_REF": "backend-bunny/Konstapel/.github/workflows/publish.yml@refs/heads/main"}), officialRecord(src.Name)},
		{"another branch", src, true, runFrom(map[string]string{"GITHUB_WORKFLOW_REF": "backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/dev", "GITHUB_REF": "refs/heads/dev"}), officialRecord(src.Name)},
		{"outside GitHub Actions", src, true, Run{Workflow: run.Workflow}, officialRecord(src.Name)},
		{"builder differs from identity", edit(func(s *bundle.BundleSource) {
			s.Publisher.Provenance.Builder = "https://github.com/backend-bunny/Konstapel/.github/workflows/other.yml@refs/heads/main"
		}), true, run, officialRecord(src.Name)},
		{"another issuer", edit(func(s *bundle.BundleSource) { s.Publisher.Issuer = "https://accounts.example.com" }), true, run, officialRecord(src.Name)},
		{"keyless run, public-key rule", keyRule, true, run, officialRecord(src.Name)},
		{"key run, keyless rule", src, false, run, officialRecord(src.Name)},
		{"source repository is not the rule's", src, true, run, func() publish.Record {
			r := officialRecord(src.Name)
			r.Source.Repository = "https://github.com/example-fork/Konstapel"
			return r
		}()},
		{"rule of another bundle", src, true, run, officialRecord("other-bundle")},
	} {
		if err := CheckSigningRule(c.src, c.keyless, c.run, c.rec); !errors.Is(err, ErrSigningRule) {
			t.Errorf("%s: got %v, want ErrSigningRule", c.name, err)
		}
	}
	if err := CheckSigningRule(keyRule, false, Run{Workflow: run.Workflow}, officialRecord(src.Name)); err != nil {
		t.Errorf("key signing under a public-key rule: %v", err)
	}
}
