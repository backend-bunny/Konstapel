package release

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// fakeReleases records what EnsureRelease asks of GitHub.
type fakeReleases struct {
	have  *GitHubRelease
	calls []string
	tags  []string
	last  GitHubRelease
}

func (f *fakeReleases) Get(_ context.Context, tag string) (*GitHubRelease, error) {
	f.calls, f.tags = append(f.calls, "get"), append(f.tags, tag)
	return f.have, nil
}

func (f *fakeReleases) Create(_ context.Context, tag string, r GitHubRelease) error {
	f.calls, f.tags, f.last = append(f.calls, "create"), append(f.tags, tag), r
	return nil
}

func (f *fakeReleases) Edit(_ context.Context, tag string, r GitHubRelease) error {
	f.calls, f.tags, f.last = append(f.calls, "edit"), append(f.tags, tag), r
	return nil
}

func TestEnsureRelease(t *testing.T) {
	const notes = "# notes\n\nbody\n"
	same := GitHubRelease{Title: "demo 1.2.3", Body: notes}
	for _, tc := range []struct {
		name    string
		version string
		have    *GitHubRelease
		want    EnsureOutcome
		calls   string
		pre     bool
	}{
		{"absent", "1.2.3", nil, ReleaseCreated, "get create", false},
		{"identical", "1.2.3", &same, ReleaseUnchanged, "get", false},
		{"identical up to trailing whitespace", "1.2.3", &GitHubRelease{Title: "demo 1.2.3", Body: notes + "\n\n"}, ReleaseUnchanged, "get", false},
		{"notes differ", "1.2.3", &GitHubRelease{Title: "demo 1.2.3", Body: "old"}, ReleaseUpdated, "get edit", false},
		{"title differs", "1.2.3", &GitHubRelease{Title: "renamed", Body: notes}, ReleaseUpdated, "get edit", false},
		{"pre-release flag differs", "1.2.3", &GitHubRelease{Title: "demo 1.2.3", Body: notes, Prerelease: true}, ReleaseUpdated, "get edit", false},
		{"pre-release version", "1.2.3-rc.1", nil, ReleaseCreated, "get create", true},
		{"pre-release version already announced", "1.2.3-rc.1", &GitHubRelease{Title: "demo 1.2.3-rc.1", Body: notes, Prerelease: true}, ReleaseUnchanged, "get", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeReleases{have: tc.have}
			got, err := EnsureRelease(context.Background(), f, "demo", tc.version, notes)
			if err != nil || got != tc.want || strings.Join(f.calls, " ") != tc.calls {
				t.Fatalf("got %q %v after %v, want %q after %q", got, err, f.calls, tc.want, tc.calls)
			}
			for _, tag := range f.tags {
				if tag != "bundle/demo/v"+tc.version {
					t.Errorf("acted on tag %q, want the bundle release tag", tag)
				}
			}
			if tc.want != ReleaseUnchanged && f.last.Prerelease != tc.pre {
				t.Errorf("prerelease = %v, want %v", f.last.Prerelease, tc.pre)
			}
		})
	}
}

func TestEnsureReleaseRefusals(t *testing.T) {
	f := &fakeReleases{have: &GitHubRelease{Title: "demo 1.2.3", Body: "x", Draft: true}}
	if _, err := EnsureRelease(context.Background(), f, "demo", "1.2.3", "n"); !errors.Is(err, ErrReleaseDraft) || strings.Contains(strings.Join(f.calls, " "), "edit") {
		t.Fatalf("a draft must be refused and never edited: %v %v", err, f.calls)
	}
	for name, args := range map[string][3]string{
		"bad name":      {"../x", "1.2.3", "n"},
		"bad version":   {"demo", "v1.2", "n"},
		"empty notes":   {"demo", "1.2.3", "  \n"},
		"tag-like name": {"demo/v1.0.0", "1.2.3", "n"},
	} {
		f := &fakeReleases{}
		if _, err := EnsureRelease(context.Background(), f, args[0], args[1], args[2]); err == nil || len(f.calls) != 0 {
			t.Errorf("%s: accepted or reached GitHub (%v, %v)", name, err, f.calls)
		}
	}
}

// testToken is a realistic fake token: redaction replaces every occurrence of
// the token, so a one-character value would garble unrelated text.
const testToken = "ghs_exampletokenvalue0123456789"

// ghCall is one recorded gh invocation.
type ghCall struct {
	args  []string
	env   []string
	notes string // contents of the --notes-file at call time
	mode  os.FileMode
}

func fakeRunner(calls *[]ghCall, reply func(args []string) ([]byte, int, error)) Runner {
	return func(_ context.Context, _ string, args []string, env []string) ([]byte, int, error) {
		c := ghCall{args: append([]string(nil), args...), env: append([]string(nil), env...)}
		for i, a := range args {
			if a == "--notes-file" && i+1 < len(args) {
				if b, err := os.ReadFile(args[i+1]); err == nil {
					c.notes = string(b)
				}
				if st, err := os.Stat(args[i+1]); err == nil {
					c.mode = st.Mode().Perm()
				}
			}
		}
		*calls = append(*calls, c)
		return reply(args)
	}
}

func flagValue(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func TestGHCreateAndEditArguments(t *testing.T) {
	const token = "ghs_SECRETSECRETSECRET"
	const body = "# notes with `backticks` and $(not run) and 'quotes'\n"
	var calls []ghCall
	g := &GH{Repo: "backend-bunny/Konstapel", Token: token, Run: fakeRunner(&calls, func([]string) ([]byte, int, error) { return nil, 0, nil })}
	ctx := context.Background()
	tag := "bundle/demo/v1.2.3"

	if err := g.Create(ctx, tag, GitHubRelease{Title: "demo 1.2.3", Body: body}); err != nil {
		t.Fatal(err)
	}
	if err := g.Edit(ctx, tag, GitHubRelease{Title: "demo 1.2.3", Body: body, Prerelease: true}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %d", len(calls))
	}
	create, edit := calls[0], calls[1]

	has := func(c ghCall, want ...string) {
		t.Helper()
		for _, w := range want {
			found := false
			for _, a := range c.args {
				found = found || a == w
			}
			if !found {
				t.Errorf("%v lacks %q", c.args, w)
			}
		}
	}
	// Create never makes the tag and never takes over the "latest" release.
	has(create, "release", "create", tag, "--verify-tag", "--latest=false", "--repo", "backend-bunny/Konstapel")
	has(edit, "release", "edit", tag, "--latest=false", "--prerelease=true")
	if flagValue(create.args, "--title") != "demo 1.2.3" {
		t.Errorf("title = %q", flagValue(create.args, "--title"))
	}
	for _, c := range calls {
		// The notes travel in a private file, never in an argument.
		if c.notes != body || c.mode != 0o600 {
			t.Errorf("notes file = %q mode %v", c.notes, c.mode)
		}
		for _, a := range c.args {
			if strings.Contains(a, "backticks") || strings.Contains(a, token) || strings.Contains(a, "notes with") {
				t.Errorf("secret or notes in argv: %q", a)
			}
		}
		// The token only through the environment; nothing else leaks in.
		gotToken := false
		for _, e := range c.env {
			k, _, _ := strings.Cut(e, "=")
			switch k {
			case "GH_TOKEN":
				gotToken = e == "GH_TOKEN="+token
			case "PATH", "HOME", "GH_PROMPT_DISABLED", "NO_COLOR", "GH_NO_UPDATE_NOTIFIER":
			default:
				t.Errorf("unexpected environment variable %q", k)
			}
		}
		if !gotToken {
			t.Error("the token is not in GH_TOKEN")
		}
		if _, err := os.Stat(flagValue(c.args, "--notes-file")); err == nil {
			t.Error("the private notes file was not removed")
		}
	}
	has(create, "--notes-file")
	// A pre-release is announced as one on create, too.
	calls = nil
	if err := g.Create(ctx, tag, GitHubRelease{Title: "t", Body: "b", Prerelease: true}); err != nil {
		t.Fatal(err)
	}
	has(calls[0], "--prerelease")
}

func TestGHGet(t *testing.T) {
	var calls []ghCall
	reply := func([]byte, int, error) func([]string) ([]byte, int, error) { return nil }
	_ = reply
	notFound := &GH{Repo: "o/r", Token: testToken, Run: fakeRunner(&calls, func([]string) ([]byte, int, error) {
		return nil, 1, errors.New("gh exited 1: release not found")
	})}
	if r, err := notFound.Get(context.Background(), "bundle/demo/v1.0.0"); r != nil || err != nil {
		t.Fatalf("a missing release is nil, nil: %v %v", r, err)
	}
	found := &GH{Repo: "o/r", Token: testToken, Run: fakeRunner(&calls, func([]string) ([]byte, int, error) {
		return []byte(`{"name":"demo 1.0.0","body":"b","isPrerelease":false,"isDraft":true}`), 0, nil
	})}
	r, err := found.Get(context.Background(), "bundle/demo/v1.0.0")
	if err != nil || r == nil || r.Title != "demo 1.0.0" || !r.Draft {
		t.Fatalf("parsed release %+v %v", r, err)
	}
	if got := flagValue(calls[len(calls)-1].args, "--json"); got != "name,body,isPrerelease,isDraft" {
		t.Errorf("--json = %q", got)
	}
	for name, run := range map[string]func([]string) ([]byte, int, error){
		"other failure": func([]string) ([]byte, int, error) { return nil, 1, errors.New("gh exited 1: HTTP 403") },
		"bad json":      func([]string) ([]byte, int, error) { return []byte("nope"), 0, nil },
	} {
		g := &GH{Repo: "o/r", Token: testToken, Run: fakeRunner(&calls, run)}
		if r, err := g.Get(context.Background(), "bundle/demo/v1.0.0"); err == nil || r != nil {
			t.Errorf("%s: want an error, got %v %v", name, r, err)
		}
	}
}

func TestGHRefusals(t *testing.T) {
	var calls []ghCall
	ok := fakeRunner(&calls, func([]string) ([]byte, int, error) { return nil, 0, nil })
	cases := map[string]struct {
		g   *GH
		tag string
	}{
		"no token":           {&GH{Repo: "o/r", Run: ok}, "bundle/demo/v1.0.0"},
		"bad repository":     {&GH{Repo: "o/r; rm", Token: testToken, Run: ok}, "bundle/demo/v1.0.0"},
		"application tag":    {&GH{Repo: "o/r", Token: testToken, Run: ok}, "v1.0.0"},
		"tag with a quote":   {&GH{Repo: "o/r", Token: testToken, Run: ok}, "bundle/demo/v1.0.0'"},
		"tag with traversal": {&GH{Repo: "o/r", Token: testToken, Run: ok}, "bundle/../v1.0.0"},
	}
	for name, c := range cases {
		if err := c.g.Create(context.Background(), c.tag, GitHubRelease{Title: "t", Body: "b"}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(calls) != 0 {
		t.Fatalf("a refused request still ran gh: %v", calls)
	}
}

func TestGHErrorsNeverCarryTheToken(t *testing.T) {
	const token = "ghs_SECRETSECRETSECRET"
	g := &GH{Repo: "o/r", Token: token, Run: func(context.Context, string, []string, []string) ([]byte, int, error) {
		return nil, 1, errors.New("gh exited 1: bad credentials " + token)
	}}
	err := g.Create(context.Background(), "bundle/demo/v1.0.0", GitHubRelease{Title: "t", Body: "b"})
	if err == nil || strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("error = %v", err)
	}
}
