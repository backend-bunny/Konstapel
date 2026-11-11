package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fixture is a working clone and its bare "origin", both real Git
// repositories in a temporary directory. Neither contains an application
// VERSION file, Helm charts or release-please state, so every passing case
// below also shows that a bundle release needs none of them.
type fixture struct {
	t      *testing.T
	work   string
	origin string
	git    ExecGit
}

func gitEnv(t *testing.T) {
	t.Helper()
	// Isolate from the developer's Git configuration (signing, hooks, aliases).
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	for k, v := range map[string]string{
		"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
		"GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.invalid",
		"GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
	} {
		t.Setenv(k, v)
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	gitEnv(t)
	dir := t.TempDir()
	f := &fixture{t: t, work: filepath.Join(dir, "work"), origin: filepath.Join(dir, "origin.git")}
	f.git = ExecGit{Dir: f.work}
	f.run(dir, "init", "--quiet", "--bare", "--initial-branch=main", f.origin)
	f.run(dir, "init", "--quiet", "--initial-branch=main", f.work)
	f.run(f.work, "remote", "add", "origin", f.origin)
	return f
}

// run executes git in dir and returns trimmed stdout, failing the test on error.
func (f *fixture) run(dir string, args ...string) string {
	f.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		f.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, stderr)
	}
	return strings.TrimSpace(string(out))
}

// commit writes files (path -> content; "" deletes) and commits them.
func (f *fixture) commit(files map[string]string) string {
	f.t.Helper()
	for p, content := range files {
		full := filepath.Join(f.work, p)
		if content == "" {
			if err := os.RemoveAll(full); err != nil {
				f.t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			f.t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
	f.run(f.work, "add", "--all")
	f.run(f.work, "commit", "--quiet", "--allow-empty", "-m", "change")
	return f.run(f.work, "rev-parse", "HEAD")
}

// publishMain pushes main and refreshes refs/remotes/origin/main, as a
// full-history checkout of main would see it.
func (f *fixture) publishMain() {
	f.t.Helper()
	f.run(f.work, "push", "--quiet", "origin", "main")
	f.run(f.work, "fetch", "--quiet", "origin")
}

func def(name, version string) string {
	return `{"name":"` + name + `","version":"` + version + `"}`
}

func defPath(dir string) string { return "bundles/" + dir + "/definition.json" }

func (f *fixture) remoteTag(tag string) string {
	f.t.Helper()
	out, err := exec.Command("git", "-C", f.origin, "rev-parse", "--verify", "--quiet", "refs/tags/"+tag+"^{commit}").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

const mainRef = "refs/remotes/origin/main"

func TestValidate(t *testing.T) {
	f := newFixture(t)
	first := f.commit(map[string]string{
		defPath("alpha"):        def("alpha", "0.1.0"),
		defPath("mismatch"):     def("other", "1.0.0"),
		"bundles/empty/README":  "no definition",
		defPath("vprefixed"):    def("vprefixed", "v1.0.0"),
		defPath("short"):        def("short", "1.0"),
		defPath("leadingzero"):  def("leadingzero", "01.0.0"),
		defPath("build"):        def("build", "1.0.0+build.1"),
		defPath("emptypre"):     def("emptypre", "1.0.0-"),
		defPath("zeropre"):      def("zeropre", "1.0.0-01"),
		defPath("noversion"):    def("noversion", ""),
		defPath("prerelease"):   def("prerelease", "1.0.0-rc.1"),
		defPath("tagged"):       def("tagged", "1.0.0"),
		defPath("unknownfield"): `{"name":"unknownfield","version":"1.0.0","extra":true}`,
		defPath("longversion"):  def("longversion", "1.0.0-"+strings.Repeat("a", 64)),
	})
	// A later main commit bumps alpha: releasing the first commit must still
	// read 0.1.0 from that commit, not the newer tree.
	second := f.commit(map[string]string{defPath("alpha"): def("alpha", "0.2.0")})
	f.publishMain()
	// An unreviewed side branch, never merged to main.
	f.run(f.work, "switch", "--quiet", "-c", "side")
	side := f.commit(map[string]string{defPath("alpha"): def("alpha", "9.9.9")})
	f.run(f.work, "switch", "--quiet", "main")
	// A local (fetched) tag marking a version at a different commit.
	f.run(f.work, "tag", "bundle/tagged/v1.0.0", second)

	cases := []struct {
		name    string
		req     Request
		version string // want on success
		err     string // substring of the expected error
	}{
		{name: "main tip", req: Request{Name: "alpha", Commit: second}, version: "0.2.0"},
		{name: "older main ancestor reads its own version", req: Request{Name: "alpha", Commit: first}, version: "0.1.0"},
		{name: "pre-release allowed", req: Request{Name: "prerelease", Commit: first}, version: "1.0.0-rc.1"},
		{name: "fetched tag at another commit", req: Request{Name: "tagged", Commit: first}, err: "already marks " + second},
		{name: "packaged version matches", req: Request{Name: "alpha", Commit: first, Version: "0.1.0"}, version: "0.1.0"},
		{name: "packaged version differs", req: Request{Name: "alpha", Commit: first, Version: "0.2.0"}, err: "but 0.2.0 was packaged"},

		{name: "empty name", req: Request{Name: "", Commit: first}, err: "DNS label"},
		{name: "traversal", req: Request{Name: "../alpha", Commit: first}, err: "DNS label"},
		{name: "nested path", req: Request{Name: "alpha/x", Commit: first}, err: "DNS label"},
		{name: "uppercase", req: Request{Name: "Alpha", Commit: first}, err: "DNS label"},
		{name: "leading hyphen", req: Request{Name: "-alpha", Commit: first}, err: "DNS label"},
		{name: "too long", req: Request{Name: strings.Repeat("a", 64), Commit: first}, err: "DNS label"},
		{name: "option-like", req: Request{Name: "--all", Commit: first}, err: "DNS label"},
		{name: "nonexistent bundle", req: Request{Name: "missing", Commit: first}, err: "no bundle directory"},
		{name: "directory without definition", req: Request{Name: "empty", Commit: first}, err: "no bundles/empty/definition.json"},
		{name: "directory and name differ", req: Request{Name: "mismatch", Commit: first}, err: `names "other"`},
		{name: "unknown definition field", req: Request{Name: "unknownfield", Commit: first}, err: "unknown field"},

		{name: "leading v", req: Request{Name: "vprefixed", Commit: first}, err: "must not start with"},
		{name: "not SemVer", req: Request{Name: "short", Commit: first}, err: "not SemVer"},
		{name: "leading zero", req: Request{Name: "leadingzero", Commit: first}, err: "not SemVer"},
		{name: "build metadata", req: Request{Name: "build", Commit: first}, err: "build metadata"},
		{name: "empty pre-release", req: Request{Name: "emptypre", Commit: first}, err: "not SemVer"},
		{name: "numeric pre-release leading zero", req: Request{Name: "zeropre", Commit: first}, err: "not SemVer"},
		{name: "missing version", req: Request{Name: "noversion", Commit: first}, err: "not SemVer"},
		{name: "overlong version", req: Request{Name: "longversion", Commit: first}, err: "longer than"},

		{name: "short commit", req: Request{Name: "alpha", Commit: first[:12]}, err: "full 40-character"},
		{name: "uppercase commit", req: Request{Name: "alpha", Commit: strings.ToUpper(first)}, err: "full 40-character"},
		{name: "non-hex commit", req: Request{Name: "alpha", Commit: strings.Repeat("z", 40)}, err: "full 40-character"},
		{name: "branch name", req: Request{Name: "alpha", Commit: "main"}, err: "full 40-character"},
		{name: "empty commit", req: Request{Name: "alpha", Commit: ""}, err: "full 40-character"},
		{name: "unknown commit", req: Request{Name: "alpha", Commit: strings.Repeat("0123456789", 4)}, err: "not a commit in this repository"},
		{name: "tree object, not commit", req: Request{Name: "alpha", Commit: f.run(f.work, "rev-parse", first+"^{tree}")}, err: "not a commit in this repository"},
		{name: "side-branch commit", req: Request{Name: "alpha", Commit: side}, err: "not on reviewed main history"},
		{name: "unqualified main ref", req: Request{Name: "alpha", Commit: first, MainRef: "main"}, err: "fully qualified"},
		{name: "missing main ref", req: Request{Name: "alpha", Commit: first, MainRef: "refs/remotes/upstream/main"}, err: "does not exist"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.req.MainRef == "" {
				tc.req.MainRef = mainRef
			}
			rel, err := Validate(context.Background(), f.git, tc.req)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want containing %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// The definition digest is checked against the blob in
			// TestRequireTagAndDefinitionDigest.
			if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(rel.DefinitionSHA256) {
				t.Fatalf("definition digest %q", rel.DefinitionSHA256)
			}
			rel.DefinitionSHA256 = ""
			want := Release{Name: tc.req.Name, Version: tc.version, Commit: tc.req.Commit, Tag: "bundle/" + tc.req.Name + "/v" + tc.version}
			if rel != want {
				t.Fatalf("release = %+v, want %+v", rel, want)
			}
		})
	}
}

func TestEnsureTag(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	c1 := f.commit(map[string]string{defPath("alpha"): def("alpha", "1.0.0"), defPath("beta"): def("beta", "1.0.0")})
	// The next main commit forgot to bump alpha's version.
	c2 := f.commit(map[string]string{"bundles/alpha/notes": "unbumped change"})
	c3 := f.commit(map[string]string{defPath("alpha"): def("alpha", "1.1.0"), defPath("gamma"): def("gamma", "1.0.0"), defPath("delta"): def("delta", "2.0.0")})
	f.publishMain()
	// An application release tag of the same version at another commit.
	f.run(f.work, "tag", "v1.0.0", c3)
	f.run(f.work, "push", "--quiet", "origin", "v1.0.0")

	ensure := func(name, commit string) (Release, TagState, error) {
		return EnsureTag(ctx, f.git, Request{Name: name, Commit: commit, MainRef: mainRef}, "origin")
	}

	t.Run("creates an absent tag", func(t *testing.T) {
		rel, state, err := ensure("alpha", c1)
		if err != nil || state != TagCreated || rel.Tag != "bundle/alpha/v1.0.0" {
			t.Fatalf("got %+v %q %v", rel, state, err)
		}
		if got := f.remoteTag("bundle/alpha/v1.0.0"); got != c1 {
			t.Fatalf("remote tag marks %q, want %s", got, c1)
		}
		if got := f.remoteTag("v1.0.0"); got != c3 {
			t.Fatalf("application tag v1.0.0 moved to %q", got)
		}
	})
	t.Run("existing tag at the source commit is idempotent", func(t *testing.T) {
		_, state, err := ensure("alpha", c1)
		if err != nil || state != TagExisting {
			t.Fatalf("got %q %v", state, err)
		}
	})
	t.Run("unbumped version conflicts with its existing tag", func(t *testing.T) {
		_, _, err := ensure("alpha", c2)
		if err == nil || !strings.Contains(err.Error(), "never moved") {
			t.Fatalf("err = %v", err)
		}
		if got := f.remoteTag("bundle/alpha/v1.0.0"); got != c1 {
			t.Fatalf("tag moved to %s", got)
		}
	})
	t.Run("remote-only tag at another commit conflicts", func(t *testing.T) {
		// Created on the remote by someone else; this clone has not fetched it.
		f.run(f.origin, "tag", "bundle/beta/v1.0.0", c2)
		_, _, err := ensure("beta", c1)
		if err == nil || !strings.Contains(err.Error(), "remote tag bundle/beta/v1.0.0 already marks "+c2) {
			t.Fatalf("err = %v", err)
		}
		if got := f.remoteTag("bundle/beta/v1.0.0"); got != c2 {
			t.Fatalf("tag moved to %s", got)
		}
	})
	t.Run("annotated tag at the source commit is accepted", func(t *testing.T) {
		f.run(f.origin, "tag", "-a", "-m", "release", "bundle/alpha/v1.1.0", c3)
		_, state, err := ensure("alpha", c3)
		if err != nil || state != TagExisting {
			t.Fatalf("got %q %v", state, err)
		}
	})
	t.Run("annotated tag at another commit conflicts", func(t *testing.T) {
		f.run(f.origin, "tag", "-a", "-m", "release", "bundle/delta/v2.0.0", c1)
		_, _, err := ensure("delta", c3)
		if err == nil || !strings.Contains(err.Error(), "already marks "+c1) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a ref occupying the bundle namespace blocks creation", func(t *testing.T) {
		f.run(f.origin, "tag", "bundle/gamma", c1)
		_, _, err := ensure("gamma", c3)
		if err == nil || !strings.Contains(err.Error(), "occupies the bundle tag namespace") {
			t.Fatalf("err = %v", err)
		}
		if got := f.remoteTag("bundle/gamma/v1.0.0"); got != "" {
			t.Fatalf("tag created at %s", got)
		}
	})
	t.Run("validation failures never touch the remote", func(t *testing.T) {
		before := f.run(f.origin, "for-each-ref", "refs/tags")
		for _, req := range []Request{
			{Name: "Alpha", Commit: c1, MainRef: mainRef},
			{Name: "alpha", Commit: c1[:8], MainRef: mainRef},
			{Name: "alpha", Commit: c1, MainRef: mainRef, Version: "9.9.9"},
		} {
			if _, _, err := EnsureTag(ctx, f.git, req, "origin"); err == nil {
				t.Fatalf("%+v: no error", req)
			}
		}
		if _, _, err := EnsureTag(ctx, f.git, Request{Name: "alpha", Commit: c1, MainRef: mainRef}, "--upload-pack=x"); err == nil {
			t.Fatal("option-like remote accepted")
		}
		if after := f.run(f.origin, "for-each-ref", "refs/tags"); after != before {
			t.Fatalf("remote tags changed:\n%s\n->\n%s", before, after)
		}
	})
}

// The fixture repository never contains application release inputs; the
// release succeeded above without them. Assert that explicitly.
func TestReleaseNeedsNoApplicationOrChartRelease(t *testing.T) {
	f := newFixture(t)
	c := f.commit(map[string]string{defPath("alpha"): def("alpha", "0.1.0")})
	f.publishMain()
	files := f.run(f.work, "ls-tree", "-r", "--name-only", c)
	if files != defPath("alpha") {
		t.Fatalf("fixture tree = %q", files)
	}
	if tags := f.run(f.work, "tag", "--list"); tags != "" {
		t.Fatalf("fixture has tags %q", tags)
	}
	if _, state, err := EnsureTag(context.Background(), f.git, Request{Name: "alpha", Commit: c, MainRef: mainRef}, "origin"); err != nil || state != TagCreated {
		t.Fatalf("got %q %v", state, err)
	}
}

// Bundle tags live under bundle/ and can never be read as an application
// release tag, whatever the name and version.
func TestTagNamespaceIsSeparateFromApplicationTags(t *testing.T) {
	// The application tag patterns used by publish.yml and release-please
	// (include-v-in-tag, no component).
	appTag := regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	gitEnv(t)
	for _, tc := range []struct{ name, version, want string }{
		{"alpha", "1.0.0", "bundle/alpha/v1.0.0"},
		{"v1", "1.0.0", "bundle/v1/v1.0.0"},
		{"bundle", "0.1.0-rc.1", "bundle/bundle/v0.1.0-rc.1"},
		{"konstapel", "0.1.0", "bundle/konstapel/v0.1.0"},
	} {
		if err := ValidateName(tc.name); err != nil {
			t.Fatal(err)
		}
		if err := ValidateVersion(tc.version); err != nil {
			t.Fatal(err)
		}
		tag := TagName(tc.name, tc.version)
		if tag != tc.want {
			t.Fatalf("TagName(%q, %q) = %q, want %q", tc.name, tc.version, tag, tc.want)
		}
		if appTag.MatchString(tag) || strings.HasPrefix(tag, "v") || !strings.HasPrefix(tag, TagPrefix) {
			t.Fatalf("%s overlaps the application tag namespace", tag)
		}
		if out, err := exec.Command("git", "check-ref-format", "refs/tags/"+tag).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", tag, err, out)
		}
	}
	// A version that would itself look like an application tag is rejected
	// rather than producing bundle/<name>/vv1.0.0.
	if err := ValidateVersion("v1.0.0"); err == nil {
		t.Fatal("v-prefixed version accepted")
	}
}

// Publication requires the release tag at the source commit, and the
// release records the definition's digest exactly as stored at that commit.
func TestRequireTagAndDefinitionDigest(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	c1 := f.commit(map[string]string{defPath("alpha"): def("alpha", "1.0.0")})
	c2 := f.commit(map[string]string{"bundles/alpha/notes": "later"})
	f.publishMain()
	rel, err := Validate(ctx, f.git, Request{Name: "alpha", Commit: c1, MainRef: mainRef})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(def("alpha", "1.0.0")))
	if rel.DefinitionSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("definition digest %s", rel.DefinitionSHA256)
	}
	if err := RequireTag(ctx, f.git, rel); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("absent tag: %v", err)
	}
	f.run(f.work, "tag", rel.Tag, c2)
	if err := RequireTag(ctx, f.git, rel); err == nil || !strings.Contains(err.Error(), "marks") {
		t.Fatalf("tag at another commit: %v", err)
	}
	f.run(f.work, "tag", "-f", rel.Tag, c1)
	if err := RequireTag(ctx, f.git, rel); err != nil {
		t.Fatal(err)
	}
}
