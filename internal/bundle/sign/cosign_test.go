package sign

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

// fakeCosign records each invocation's argv, environment, Docker config (and
// its mode) and predicate next to itself, and behaves as its mode file says.
const fakeCosign = `#!/bin/sh
d=$(dirname "$0")
i=$(cat "$d/count" 2>/dev/null || echo 0); i=$((i+1)); echo $i > "$d/count"
printf '%s\n' "$@" > "$d/argv.$i"
env | sort > "$d/env.$i"
if [ -n "$DOCKER_CONFIG" ]; then
  cp "$DOCKER_CONFIG/config.json" "$d/docker.$i"
  stat -c %a "$DOCKER_CONFIG/config.json" > "$d/dockermode.$i"
  echo "$DOCKER_CONFIG" > "$d/dockerdir.$i"
fi
for a in "$@"; do case "$a" in */predicate.json) cp "$a" "$d/predicate.$i"; echo "$a" > "$d/predicatepath.$i";; esac; done
if [ "$1" = version ]; then echo '{"gitVersion":"v3.1.3","gitCommit":"x"}'; exit 0; fi
case "$(cat "$d/mode" 2>/dev/null)" in
fail)
  echo "error: denied; token=$ACTIONS_ID_TOKEN_REQUEST_TOKEN password=$COSIGN_PASSWORD key=$TEST_KEY_PEM" >&2
  echo "fetched eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvIn0.c2lnbmF0dXJl and Bearer abcdefghijklmnop" >&2
  exit 1;;
hang) sleep 30;;
esac
echo "tlog entry created" >&2
`

const (
	testRef      = "ghcr.io/backend-bunny/bundles/konstapel-privileged-containers@sha256:2d574a6fd3c1553cd29b82faaa35b413fadf296e8af55d8ecb1d691f32cdc5bd"
	oidcToken    = "oidc-request-token-value-0123456789"
	keyPassword  = "key-password-value-9876"
	registryPass = "ghs_registryTokenValue123456"
	keyPEM       = "-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----secretkeymaterial"
)

type fake struct {
	dir string
	bin string
}

func newFake(t *testing.T, mode string) fake {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "cosign")
	if err := os.WriteFile(bin, []byte(fakeCosign), 0o755); err != nil {
		t.Fatal(err)
	}
	if mode != "" {
		if err := os.WriteFile(filepath.Join(dir, "mode"), []byte(mode), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return fake{dir: dir, bin: bin}
}

func (f fake) read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return string(b)
}

func (f fake) calls() int {
	b, err := os.ReadFile(filepath.Join(f.dir, "count"))
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range strings.TrimSpace(string(b)) {
		n = n*10 + int(c-'0')
	}
	return n
}

func (f fake) argv(t *testing.T, i int) []string {
	return strings.Split(strings.TrimSuffix(f.read(t, "argv."+string(rune('0'+i))), "\n"), "\n")
}

// environ is a hostile environment: secrets for every mode, a repository
// redirect and unrelated tokens that Cosign must never see.
func environ(path string) []string {
	return []string{
		"PATH=" + path, "HOME=/tmp/home", "SSL_CERT_FILE=/etc/ssl/ca.pem",
		"ACTIONS_ID_TOKEN_REQUEST_URL=https://token.actions.example/req", "ACTIONS_ID_TOKEN_REQUEST_TOKEN=" + oidcToken,
		"COSIGN_PASSWORD=" + keyPassword, "TEST_KEY_PEM=" + keyPEM,
		"COSIGN_REPOSITORY=evil.example/elsewhere", "COSIGN_EXPERIMENTAL=1", "GITHUB_TOKEN=ghp_unrelated",
		"BUNDLE_REGISTRY_PASSWORD=" + registryPass, "DOCKER_CONFIG=/home/user/.docker", "SIGSTORE_ROOT_FILE=/tmp/evil-root.json",
	}
}

func TestArgvIsExactDigestOnlyAndSecretFree(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "cosign.key")
	if err := os.WriteFile(keyFile, []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	pred := []byte(`{"buildDefinition":{}}`)
	cases := []struct {
		name       string
		c          Cosign
		attest     bool
		want       []string
		wantEnv    []string
		notEnv     []string
		dockerAuth bool
	}{
		{
			name: "keyless sign", c: Cosign{Mode: Keyless},
			want:    []string{"sign", "--yes", testRef},
			wantEnv: []string{"ACTIONS_ID_TOKEN_REQUEST_TOKEN=" + oidcToken, "ACTIONS_ID_TOKEN_REQUEST_URL=", "SSL_CERT_FILE=", "DOCKER_CONFIG=/home/user/.docker"},
			notEnv:  []string{"COSIGN_PASSWORD", "TEST_KEY_PEM"},
		},
		{
			name: "keyless attest", c: Cosign{Mode: Keyless}, attest: true,
			want:    []string{"attest", "--yes", "--type", "slsaprovenance1", "--predicate", "<predicate>", testRef},
			wantEnv: []string{"ACTIONS_ID_TOKEN_REQUEST_TOKEN="},
			notEnv:  []string{"COSIGN_PASSWORD"},
		},
		{
			name: "keyless with a registry credential", c: Cosign{Mode: Keyless, RegistryHost: "ghcr.io", Credential: registry.Credential{Username: "actor", Password: registryPass}},
			want:    []string{"sign", "--yes", testRef},
			wantEnv: []string{"DOCKER_CONFIG=" + os.TempDir()}, notEnv: []string{"/home/user/.docker"}, dockerAuth: true,
		},
		{
			name: "key file, offline", c: Cosign{Mode: Key, Key: keyFile},
			want:    []string{"sign", "--yes", "--key", keyFile, "--tlog-upload=false", "--use-signing-config=false", testRef},
			wantEnv: []string{"COSIGN_PASSWORD=" + keyPassword},
			notEnv:  []string{"ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "TEST_KEY_PEM"},
		},
		{
			name: "env key with tlog upload and registry CA", c: Cosign{Mode: Key, Key: "env://TEST_KEY_PEM", TlogUpload: true, RegistryCA: "/etc/ca.pem"}, attest: true,
			want:    []string{"attest", "--yes", "--type", "slsaprovenance1", "--predicate", "<predicate>", "--key", "env://TEST_KEY_PEM", "--registry-cacert", "/etc/ca.pem", testRef},
			wantEnv: []string{"TEST_KEY_PEM=" + keyPEM, "COSIGN_PASSWORD="},
			notEnv:  []string{"ACTIONS_ID_TOKEN_REQUEST_TOKEN"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t, "")
			c := tc.c
			c.Path, c.Environ = f.bin, environ(os.Getenv("PATH"))
			var err error
			if tc.attest {
				err = c.Attest(context.Background(), testRef, pred)
			} else {
				err = c.Sign(context.Background(), testRef)
			}
			if err != nil {
				t.Fatal(err)
			}
			argv := f.argv(t, 1)
			want := append([]string(nil), tc.want...)
			for i, a := range want {
				if a == "<predicate>" {
					want[i] = strings.TrimSpace(f.read(t, "predicatepath.1"))
					if f.read(t, "predicate.1") != string(pred) || !strings.HasSuffix(want[i], "/predicate.json") {
						t.Fatalf("predicate %q at %s", f.read(t, "predicate.1"), want[i])
					}
					if _, err := os.Stat(want[i]); !os.IsNotExist(err) {
						t.Fatalf("predicate file left behind: %v", err)
					}
				}
			}
			if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
				t.Fatalf("argv %q\nwant %q", argv, want)
			}
			// The reference is a digest, and no secret is ever an argument.
			joined := strings.Join(argv, " ")
			for _, s := range []string{oidcToken, keyPassword, registryPass, keyPEM, ":0.1.0", "ghp_"} {
				if strings.Contains(joined, s) {
					t.Fatalf("argv carries %q: %q", s, argv)
				}
			}
			env := f.read(t, "env.1")
			for _, w := range tc.wantEnv {
				if !strings.Contains(env, w) {
					t.Errorf("env lacks %q:\n%s", w, env)
				}
			}
			for _, banned := range append(tc.notEnv, "COSIGN_REPOSITORY", "COSIGN_EXPERIMENTAL", "GITHUB_TOKEN", "BUNDLE_REGISTRY_PASSWORD", "SIGSTORE_ROOT_FILE", registryPass) {
				if strings.Contains(env, banned) {
					t.Errorf("env carries %q:\n%s", banned, env)
				}
			}
			if tc.dockerAuth {
				doc := f.read(t, "docker.1")
				auth := base64.StdEncoding.EncodeToString([]byte("actor:" + registryPass))
				if !strings.Contains(doc, `"ghcr.io":{"auth":"`+auth+`"}`) || strings.TrimSpace(f.read(t, "dockermode.1")) != "600" {
					t.Fatalf("docker config %s mode %s", doc, f.read(t, "dockermode.1"))
				}
				if _, err := os.Stat(strings.TrimSpace(f.read(t, "dockerdir.1"))); !os.IsNotExist(err) {
					t.Fatalf("temporary docker config not removed: %v", err)
				}
			}
		})
	}
}

func TestRefusesBeforeRunning(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "cosign.key")
	_ = os.WriteFile(keyFile, []byte("pem"), 0o600)
	digest := "@sha256:" + strings.Repeat("a", 64)
	repo := "ghcr.io/backend-bunny/bundles/x"
	for name, c := range map[string]struct {
		c   Cosign
		ref string
		env []string
	}{
		"tag reference":              {Cosign{Mode: Keyless}, repo + ":0.1.0", nil},
		"tag and digest":             {Cosign{Mode: Keyless}, repo + ":0.1.0" + digest, nil},
		"no digest":                  {Cosign{Mode: Keyless}, repo, nil},
		"uppercase digest":           {Cosign{Mode: Keyless}, repo + "@sha256:" + strings.Repeat("A", 64), nil},
		"sha512 digest":              {Cosign{Mode: Keyless}, repo + "@sha512:" + strings.Repeat("a", 128), nil},
		"option-looking reference":   {Cosign{Mode: Keyless}, "--key=x" + digest, nil},
		"no mode":                    {Cosign{}, repo + digest, nil},
		"keyless with a key":         {Cosign{Mode: Keyless, Key: keyFile}, repo + digest, nil},
		"keyless without OIDC token": {Cosign{Mode: Keyless}, repo + digest, []string{"PATH=/usr/bin", "COSIGN_PASSWORD=x"}},
		"key mode without key":       {Cosign{Mode: Key}, repo + digest, nil},
		"relative key path":          {Cosign{Mode: Key, Key: "cosign.key"}, repo + digest, nil},
		"KMS key reference":          {Cosign{Mode: Key, Key: "awskms://alias/x"}, repo + digest, nil},
		"bad env key name":           {Cosign{Mode: Key, Key: "env://bad-name"}, repo + digest, nil},
		"unset env key":              {Cosign{Mode: Key, Key: "env://UNSET_KEY"}, repo + digest, nil},
		"missing key file":           {Cosign{Mode: Key, Key: keyFile + ".missing"}, repo + digest, nil},
		"relative registry CA":       {Cosign{Mode: Key, Key: keyFile, RegistryCA: "ca.pem"}, repo + digest, nil},
		"credential without host":    {Cosign{Mode: Key, Key: keyFile, Credential: registry.Credential{Username: "u", Password: "p"}}, repo + digest, nil},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, "")
			cc := c.c
			cc.Path, cc.Environ = f.bin, c.env
			if cc.Environ == nil {
				cc.Environ = environ(os.Getenv("PATH"))
			}
			err := cc.Sign(context.Background(), c.ref)
			if err == nil || f.calls() != 0 {
				t.Fatalf("ran cosign %d times, err %v", f.calls(), err)
			}
		})
	}
	if err := (&Cosign{Mode: Keyless}).Attest(context.Background(), repo+digest, []byte("not json")); err == nil {
		t.Fatal("a non-JSON predicate was accepted")
	}
}

func TestFailuresAreRedactedAndBounded(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "cosign.key")
	_ = os.WriteFile(keyFile, []byte("pem"), 0o600)
	for _, c := range []Cosign{
		{Mode: Keyless, RegistryHost: "ghcr.io", Credential: registry.Credential{Username: "actor", Password: registryPass}},
		{Mode: Key, Key: "env://TEST_KEY_PEM"},
	} {
		f := newFake(t, "fail")
		var log strings.Builder
		c.Path, c.Environ, c.Log = f.bin, environ(os.Getenv("PATH")), &log
		err := c.Sign(context.Background(), testRef)
		if err == nil || !strings.Contains(err.Error(), "cosign sign failed") || !strings.Contains(err.Error(), "denied") {
			t.Fatalf("got %v", err)
		}
		for _, s := range []string{oidcToken, keyPassword, keyPEM, "eyJhbGciOiJSUzI1NiJ9", "abcdefghijklmnop"} {
			if strings.Contains(err.Error(), s) || strings.Contains(log.String(), s) {
				t.Fatalf("%s mode leaked %q: %v\nlog: %s", c.Mode, s, err, log.String())
			}
		}
	}

	f := newFake(t, "hang")
	start := time.Now()
	c := Cosign{Mode: Keyless, Path: f.bin, Environ: environ(os.Getenv("PATH")), Timeout: 300 * time.Millisecond}
	err := c.Sign(context.Background(), testRef)
	if err == nil || !strings.Contains(err.Error(), "timed out") || time.Since(start) > 10*time.Second {
		t.Fatalf("hung cosign: %v after %s", err, time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (&Cosign{Mode: Keyless, Path: newFake(t, "").bin, Environ: environ(os.Getenv("PATH"))}).Sign(ctx, testRef); err == nil {
		t.Fatal("a cancelled context still signed")
	}
}

func TestToolVersion(t *testing.T) {
	f := newFake(t, "")
	tool, err := (&Cosign{Mode: Keyless, Path: f.bin, Environ: []string{"PATH=" + os.Getenv("PATH")}}).Tool(context.Background())
	if err != nil || tool.Name != "cosign" || tool.Version != "v3.1.3" {
		t.Fatalf("%+v %v", tool, err)
	}
	if got := f.argv(t, 1); strings.Join(got, " ") != "version --json" {
		t.Fatalf("argv %q", got)
	}
}
