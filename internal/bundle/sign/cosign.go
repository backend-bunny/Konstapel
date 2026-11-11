// Package sign runs the pinned Cosign CLI (devbox.json) to sign and attest
// a published policy bundle by digest. It is a build tool for
// cmd/bundlerelease, the only place in the repository that executes Cosign;
// it is not linked into the controller or the provider.
//
// The wrapper is deliberately small. Arguments are passed as an argv vector,
// never through a shell, and are built only from a validated
// <repository>@sha256:<hex> reference (never a tag), fixed flags, a
// predicate file this package writes and a private-key reference (a path or
// env://NAME, never key material). Secrets never appear on a command line:
// the ambient OIDC token (keyless), the key password and an env:// key reach
// Cosign only through the environment variables Cosign documents (cosign env),
// and a registry credential only through a private, temporary DOCKER_CONFIG
// that is removed after each call. Cosign inherits nothing else from the
// environment: everything outside a fixed allowlist (for example
// COSIGN_REPOSITORY, which would redirect proofs, or GITHUB_TOKEN) is dropped.
// Output is bounded and redacted before it is logged or returned.
package sign

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/publish"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

// Mode selects how Cosign signs.
type Mode string

const (
	// Keyless signs with an OIDC identity through Fulcio and records the
	// signature in Rekor (the official release: GitHub Actions' ambient
	// token, which needs id-token: write).
	Keyless Mode = "keyless"
	// Key signs with a Cosign private key (organizations, tests). Without
	// TlogUpload no public service is contacted.
	Key Mode = "key"
)

// DefaultTimeout bounds one Cosign invocation.
const DefaultTimeout = 5 * time.Minute

// maxOutput bounds the Cosign output kept for logs and errors.
const maxOutput = 8 << 10

// Environment variables Cosign may inherit. Everything else is dropped.
var (
	baseEnv = []string{
		"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL",
		"SSL_CERT_FILE", "SSL_CERT_DIR",
		"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
		"TUF_ROOT", "TUF_MIRROR",
	}
	// Documented by `cosign env`: GitHub Actions' ambient OIDC credentials,
	// or an explicit identity token.
	keylessEnv = []string{"ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "SIGSTORE_ID_TOKEN"}
	// Documented by `cosign env`: the private key's password.
	keyEnv = []string{"COSIGN_PASSWORD"}
	// Values that are always secret when present.
	secretEnv = []string{"ACTIONS_ID_TOKEN_REQUEST_TOKEN", "SIGSTORE_ID_TOKEN", "COSIGN_PASSWORD"}
)

var (
	digestRef = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	envName   = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	// jwtLike and bearer catch tokens Cosign might echo that are not in the
	// environment (a token fetched from ACTIONS_ID_TOKEN_REQUEST_URL).
	jwtLike = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`)
	bearer  = regexp.MustCompile(`(?i)(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
)

// Cosign signs and attests with the Cosign CLI. It implements
// publish.ProofSigner. The zero value is not usable: set Mode (and Key for
// key mode).
type Cosign struct {
	// Path is the cosign executable; empty looks "cosign" up on PATH.
	Path string
	Mode Mode
	// Key (key mode) is a private key file or env://NAME, where NAME holds
	// the PEM key; the reference, never the key, is on the command line.
	Key string
	// TlogUpload (key mode) uploads to the transparency log of Cosign's
	// signing configuration. By default key mode contacts no public service.
	TlogUpload bool
	// RegistryCA is an optional PEM file of extra registry roots
	// (--registry-cacert); TLS verification is never disabled.
	RegistryCA string
	// RegistryHost and Credential, when Credential is set, are written to a
	// private temporary DOCKER_CONFIG for the duration of each call.
	RegistryHost string
	Credential   registry.Credential
	// Timeout bounds each invocation (DefaultTimeout when zero).
	Timeout time.Duration
	// Environ is the environment the allowlist is applied to; nil uses
	// os.Environ().
	Environ []string
	// Log receives Cosign's bounded, redacted output after each call.
	Log io.Writer
}

var _ publish.ProofSigner = (*Cosign)(nil)

// Sign implements publish.ProofSigner.
func (c *Cosign) Sign(ctx context.Context, ref string) error {
	args, err := c.signArgs(ref)
	if err != nil {
		return err
	}
	_, err = c.run(ctx, "sign", args, nil)
	return err
}

// Attest implements publish.ProofSigner: a SLSA provenance v1 attestation
// (cosign attest --type slsaprovenance1) of predicate.
func (c *Cosign) Attest(ctx context.Context, ref string, predicate []byte) error {
	if len(predicate) == 0 || !json.Valid(predicate) {
		return errors.New("cosign attest: the predicate is not JSON")
	}
	// The predicate path is only known inside run's private directory.
	args, err := c.attestArgs(ref, predicateFile)
	if err != nil {
		return err
	}
	_, err = c.run(ctx, "attest", args, predicate)
	return err
}

// Tool implements publish.ProofSigner: the CLI's version (cosign version --json).
func (c *Cosign) Tool(ctx context.Context) (publish.Tool, error) {
	out, err := c.run(ctx, "version", []string{"version", "--json"}, nil)
	if err != nil {
		return publish.Tool{}, err
	}
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &v); err != nil || !regexp.MustCompile(`^v?[0-9][0-9A-Za-z.+-]{0,62}$`).MatchString(v.GitVersion) {
		return publish.Tool{}, fmt.Errorf("cosign version: unrecognized output")
	}
	return publish.Tool{Name: "cosign", Version: v.GitVersion}, nil
}

// predicateFile stands for the predicate path in attestArgs; run replaces
// it with the file it writes.
const predicateFile = "\x00predicate"

// CheckRef accepts only <repository>@sha256:<64 hex>: a digest, never a tag.
func CheckRef(ref string) error {
	repo, d, ok := strings.Cut(ref, "@")
	if !ok || !digestRef.MatchString(d) {
		return fmt.Errorf("signing reference %q must be <repository>@sha256:<64 hex>, never a tag", ref)
	}
	if err := bundle.ValidateRepository(repo); err != nil {
		return fmt.Errorf("signing reference %q: %w", ref, err)
	}
	return nil
}

func (c *Cosign) common() ([]string, error) {
	var args []string
	switch c.Mode {
	case Keyless:
		if c.Key != "" || c.TlogUpload {
			return nil, errors.New("keyless signing takes no key and always uses the transparency log")
		}
	case Key:
		if err := checkKey(c.Key); err != nil {
			return nil, err
		}
		args = append(args, "--key", c.Key)
		if !c.TlogUpload {
			args = append(args, "--tlog-upload=false", "--use-signing-config=false")
		}
	default:
		return nil, fmt.Errorf("signing mode %q: want %q or %q", c.Mode, Keyless, Key)
	}
	if c.RegistryCA != "" {
		if !filepath.IsAbs(c.RegistryCA) {
			return nil, fmt.Errorf("registry CA %q must be an absolute path", c.RegistryCA)
		}
		args = append(args, "--registry-cacert", c.RegistryCA)
	}
	return args, nil
}

func (c *Cosign) signArgs(ref string) ([]string, error) {
	if err := CheckRef(ref); err != nil {
		return nil, err
	}
	common, err := c.common()
	if err != nil {
		return nil, err
	}
	return append(append([]string{"sign", "--yes"}, common...), ref), nil
}

func (c *Cosign) attestArgs(ref, predicate string) ([]string, error) {
	if err := CheckRef(ref); err != nil {
		return nil, err
	}
	common, err := c.common()
	if err != nil {
		return nil, err
	}
	args := append([]string{"attest", "--yes", "--type", "slsaprovenance1", "--predicate", predicate}, common...)
	return append(args, ref), nil
}

// checkKey accepts an absolute path to a regular file or env://NAME.
func checkKey(key string) error {
	if name, ok := strings.CutPrefix(key, "env://"); ok {
		if !envName.MatchString(name) {
			return fmt.Errorf("key reference env://%s: NAME must be an environment variable name", name)
		}
		return nil
	}
	if key == "" || !filepath.IsAbs(key) || strings.Contains(key, "://") {
		return errors.New("key mode needs -key: an absolute path to a Cosign private key file, or env://NAME")
	}
	if fi, err := os.Stat(key); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("key file %s is not a readable regular file", key)
	}
	return nil
}

// env returns the environment Cosign runs with and the secret values in it.
func (c *Cosign) env(dockerConfig string) ([]string, []string, error) {
	src := c.Environ
	if src == nil {
		src = os.Environ()
	}
	have := map[string]string{}
	for _, kv := range src {
		if k, v, ok := strings.Cut(kv, "="); ok {
			have[k] = v
		}
	}
	allow := append([]string(nil), baseEnv...)
	switch c.Mode {
	case Keyless:
		allow = append(allow, keylessEnv...)
	case Key:
		allow = append(allow, keyEnv...)
		if name, ok := strings.CutPrefix(c.Key, "env://"); ok {
			allow = append(allow, name)
			if have[name] == "" {
				return nil, nil, fmt.Errorf("key reference env://%s: %s is not set", name, name)
			}
		}
	}
	if dockerConfig == "" {
		allow = append(allow, "DOCKER_CONFIG")
	}
	var env, secrets []string
	for _, k := range allow {
		if v, ok := have[k]; ok {
			env = append(env, k+"="+v)
		}
	}
	if dockerConfig != "" {
		env = append(env, "DOCKER_CONFIG="+dockerConfig)
	}
	for _, k := range secretEnv {
		secrets = append(secrets, have[k])
	}
	if name, ok := strings.CutPrefix(c.Key, "env://"); ok && c.Mode == Key {
		secrets = append(secrets, have[name])
	}
	if c.Credential.Password != "" {
		secrets = append(secrets, c.Credential.Password,
			base64.StdEncoding.EncodeToString([]byte(c.Credential.Username+":"+c.Credential.Password)))
	}
	return env, secrets, nil
}

// HasAmbientOIDC reports whether keyless signing has a token source in the
// environment Cosign will get.
func HasAmbientOIDC(environ []string) bool {
	have := map[string]bool{}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && v != "" {
			have[k] = true
		}
	}
	return (have["ACTIONS_ID_TOKEN_REQUEST_URL"] && have["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]) || have["SIGSTORE_ID_TOKEN"]
}

// run executes one Cosign command in a private temporary directory that
// holds the predicate (if any) and the registry credential (if any), and
// removes it afterwards.
func (c *Cosign) run(ctx context.Context, what string, args []string, predicate []byte) ([]byte, error) {
	bin := c.Path
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("cosign"); err != nil {
			return nil, fmt.Errorf("cosign %s: %w", what, err)
		}
	}
	dir, err := os.MkdirTemp("", "bundle-sign-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	args = append([]string(nil), args...)
	for i, a := range args {
		if a == predicateFile {
			p := filepath.Join(dir, "predicate.json")
			if err := os.WriteFile(p, predicate, 0o600); err != nil {
				return nil, err
			}
			args[i] = p
		}
	}
	dockerConfig := ""
	if c.Credential.Username != "" || c.Credential.Password != "" {
		if c.RegistryHost == "" || c.Credential.Username == "" || c.Credential.Password == "" {
			return nil, errors.New("a registry credential needs a host, a username and a password")
		}
		dockerConfig = filepath.Join(dir, "docker")
		auth := base64.StdEncoding.EncodeToString([]byte(c.Credential.Username + ":" + c.Credential.Password))
		doc, _ := json.Marshal(map[string]any{"auths": map[string]any{c.RegistryHost: map[string]string{"auth": auth}}})
		if err := os.Mkdir(dockerConfig, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dockerConfig, "config.json"), doc, 0o600); err != nil {
			return nil, err
		}
	}
	env, secrets, err := c.env(dockerConfig)
	if err != nil {
		return nil, err
	}
	if c.Mode == Keyless && what != "version" && !HasAmbientOIDC(env) {
		return nil, errors.New("keyless signing needs an ambient OIDC token (GitHub Actions with id-token: write, or SIGSTORE_ID_TOKEN); refusing to start an interactive login")
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	cmd.Dir = dir
	cmd.Stdin = nil
	cmd.WaitDelay = 5 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limited{buf: &stdout, max: 1 << 20}
	cmd.Stderr = &limited{buf: &stderr, max: 1 << 20}
	err = cmd.Run()
	logged := redact(tail(stderr.String()), secrets)
	if c.Log != nil && logged != "" {
		fmt.Fprintf(c.Log, "cosign %s:\n%s\n", what, logged)
	}
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("cosign %s timed out after %s: %s", what, timeout, logged)
		}
		return nil, fmt.Errorf("cosign %s failed (%s): %s", what, redact(err.Error(), secrets), logged)
	}
	return stdout.Bytes(), nil
}

// limited keeps at most max bytes, then discards.
type limited struct {
	buf *bytes.Buffer
	max int
}

func (l *limited) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		l.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxOutput {
		s = "..." + s[len(s)-maxOutput:]
	}
	return s
}

// redact removes secret values and anything shaped like a token.
func redact(s string, secrets []string) string {
	for _, v := range secrets {
		if len(v) >= 3 {
			s = strings.ReplaceAll(s, v, "[REDACTED]")
		}
	}
	s = jwtLike.ReplaceAllString(s, "[REDACTED]")
	return bearer.ReplaceAllString(s, "$1 [REDACTED]")
}
