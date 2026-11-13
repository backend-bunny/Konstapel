package evidencesign

// Interoperability with the pinned Cosign CLI (devbox.json): Cosign-made keys
// load in Go, Go-made bundles verify with the documented `cosign verify-blob`
// command offline, and tampering, wrong trust, malformed bundles, double
// hashing and unsupported algorithms fail. Cosign runs with a minimal
// environment (no ambient OIDC variables), an empty HOME and TUF cache, and
// every proxy variable pointing at a local listener that counts connections;
// the test requires zero. Where unprivileged user namespaces are available,
// Cosign additionally runs in a new network namespace with no interfaces.
// Keys are generated per test in t.TempDir() and never committed.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal(err)
	}
	return root
}

func pinnedCosign(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "devbox.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`"cosign@([0-9][0-9A-Za-z.+-]*)"`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("devbox.json does not pin cosign")
	}
	return string(m[1])
}

func goModVersion(t *testing.T, module string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(module) + `\s+(v\S+)`).FindSubmatch(raw)
	if m == nil {
		t.Fatalf("go.mod does not require %s", module)
	}
	return string(m[1])
}

// offlineCosign runs the pinned Cosign with no network path.
type offlineCosign struct {
	t        *testing.T
	env      []string
	wrap     []string
	connects *atomic.Int64
}

func newOfflineCosign(t *testing.T) *offlineCosign {
	t.Helper()
	bin, err := exec.LookPath("cosign")
	if err != nil {
		t.Fatal("cosign is not on PATH; run the tests in the pinned Devbox environment (devbox run -- task test)")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	connects := &atomic.Int64{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			connects.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	tmp := t.TempDir()
	proxy := "http://" + ln.Addr().String()
	c := &offlineCosign{t: t, connects: connects, env: []string{
		"PATH=" + filepath.Dir(bin) + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + filepath.Join(tmp, "home"),
		"TUF_ROOT=" + filepath.Join(tmp, "tuf"),
		"TMPDIR=" + tmp,
		"HTTPS_PROXY=" + proxy, "HTTP_PROXY=" + proxy, "https_proxy=" + proxy, "http_proxy=" + proxy,
		"NO_PROXY=", "no_proxy=",
	}}
	if err := os.MkdirAll(filepath.Join(tmp, "home"), 0o700); err != nil {
		t.Fatal(err)
	}
	if exec.Command("unshare", "-rn", "true").Run() == nil {
		c.wrap = []string{"unshare", "-rn"}
		t.Log("cosign runs in an empty network namespace and behind a counting proxy")
	} else {
		t.Log("unprivileged network namespaces are unavailable; cosign runs behind a counting proxy only")
	}
	out, err := c.run(tmp, nil, "cosign", "version", "--json")
	if err != nil {
		t.Fatalf("cosign version: %v\n%s", err, out)
	}
	var v struct{ GitVersion string }
	if err := json.Unmarshal(out, &v); err != nil || v.GitVersion != "v"+pinnedCosign(t) {
		t.Fatalf("cosign on PATH is %q, devbox.json pins v%s", v.GitVersion, pinnedCosign(t))
	}
	return c
}

func (c *offlineCosign) run(dir string, extra []string, argv ...string) ([]byte, error) {
	argv = append(append([]string(nil), c.wrap...), argv...)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = append(append([]string(nil), c.env...), extra...)
	cmd.Stdin = nil
	return cmd.CombinedOutput()
}

func (c *offlineCosign) sh(dir, line string) ([]byte, error) {
	return c.run(dir, nil, "sh", "-c", line)
}

// generateKeyPair runs `cosign generate-key-pair` and returns the Secret
// data `cosign generate-key-pair k8s://...` would store.
func (c *offlineCosign) generateKeyPair(password string) map[string][]byte {
	c.t.Helper()
	dir := c.t.TempDir()
	if out, err := c.run(dir, []string{"COSIGN_PASSWORD=" + password}, "cosign", "generate-key-pair"); err != nil {
		c.t.Fatalf("cosign generate-key-pair: %v\n%s", err, out)
	}
	return c.secretFrom(dir, password)
}

func (c *offlineCosign) secretFrom(dir, password string) map[string][]byte {
	c.t.Helper()
	key, err := os.ReadFile(filepath.Join(dir, "cosign.key"))
	if err != nil {
		c.t.Fatal(err)
	}
	pub, err := os.ReadFile(filepath.Join(dir, "cosign.pub"))
	if err != nil {
		c.t.Fatal(err)
	}
	return map[string][]byte{SecretPrivateKey: key, SecretPublicKey: pub, SecretPassword: []byte(password)}
}

// documentedVerify returns the offline verification commands from
// docs/integration/evidence-signing.md.
func documentedVerify(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "docs/integration/evidence-signing.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(raw), "Verify a downloaded package offline:")
	_, rest, ok2 := strings.Cut(section, "```sh\n")
	block, _, ok3 := strings.Cut(rest, "```")
	if !ok || !ok2 || !ok3 {
		t.Fatal("verification commands not found in docs/integration/evidence-signing.md")
	}
	var lines []string
	for _, l := range strings.Split(block, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 || !strings.Contains(strings.Join(lines, "\n"), "--key trusted.pub") {
		t.Fatalf("documented verification does not use a separately trusted key: %q", lines)
	}
	return lines
}

// verifyCase lays out the files the documented commands name and runs them.
func (c *offlineCosign) verifyDocumented(cmds []string, archive, bundle, trusted []byte) ([]byte, error) {
	c.t.Helper()
	dir := c.t.TempDir()
	for name, b := range map[string][]byte{"package.tar.gz": archive, BundleFileName: bundle, "trusted.pub": trusted} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			c.t.Fatal(err)
		}
	}
	var all []byte
	for _, line := range cmds {
		out, err := c.sh(dir, line)
		all = append(all, out...)
		if err != nil {
			return all, err
		}
	}
	return all, nil
}

func TestCosignInteroperability(t *testing.T) {
	ctx := context.Background()
	c := newOfflineCosign(t)
	cmds := documentedVerify(t)

	keyA := c.generateKeyPair("pw-a-" + t.Name())
	keyB := c.generateKeyPair("")
	sA, err := NewSecretSigner(keyA)
	if err != nil {
		t.Fatalf("a Cosign-generated key does not load: %v", err)
	}
	sB, err := NewSecretSigner(keyB)
	if err != nil {
		t.Fatalf("a Cosign-generated key with an empty password does not load: %v", err)
	}
	if _, err := NewSecretSigner(with(keyA, SecretPassword, []byte("wrong"))); !errors.Is(err, ErrKeyPassword) {
		t.Fatalf("wrong password for a Cosign key: %v", err)
	}

	archive := bytes.Repeat([]byte("konstapel evidence archive "), 4096)
	d := DigestArchive(archive)
	sig, err := sA.Sign(ctx, d)
	if err != nil {
		t.Fatal(err)
	}

	out, err := c.verifyDocumented(cmds, archive, sig.Bundle, keyA[SecretPublicKey])
	if err != nil || !bytes.Contains(out, []byte("Verified OK")) {
		t.Fatalf("documented verification of a Go-signed archive failed: %v\n%s", err, out)
	}

	changed := bytes.Clone(archive)
	changed[len(changed)/2] ^= 1
	truncated := sig.Bundle[:len(sig.Bundle)-10]
	flipped := mustWire(t, sig.Bundle)
	flipped.MessageSignature.Signature[len(flipped.MessageSignature.Signature)-1] ^= 1
	sha384 := editMap(t, sig.Bundle, func(m map[string]any) {
		m["messageSignature"].(map[string]any)["messageDigest"].(map[string]any)["algorithm"] = "SHA2_384"
	})
	// A signer that hashed the hex digest text instead of using the digest.
	hexText, err := sA.Sign(ctx, DigestArchive([]byte(d.String())))
	if err != nil {
		t.Fatal(err)
	}
	// An attacker's replacement package signed with the attacker's key, which
	// the attacker ships beside it.
	replacement := append(bytes.Clone(archive), "attacker"...)
	attackerSig, err := sB.Sign(ctx, DigestArchive(replacement))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name                     string
		archive, bundle, trusted []byte
	}{
		{"changed archive byte", changed, sig.Bundle, keyA[SecretPublicKey]},
		{"wrong trusted key", archive, sig.Bundle, keyB[SecretPublicKey]},
		{"truncated bundle", archive, truncated, keyA[SecretPublicKey]},
		{"flipped signature byte", archive, mustJSON(t, flipped), keyA[SecretPublicKey]},
		{"unsupported digest algorithm", archive, sha384, keyA[SecretPublicKey]},
		{"hex digest hashed again", archive, hexText.Bundle, keyA[SecretPublicKey]},
		{"replacement package with its own key", replacement, attackerSig.Bundle, keyA[SecretPublicKey]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := c.verifyDocumented(cmds, tc.archive, tc.bundle, tc.trusted)
			if err == nil || bytes.Contains(out, []byte("Verified OK")) {
				t.Fatalf("cosign accepted it:\n%s", out)
			}
			if !bytes.Contains(out, []byte("Error: ")) || bytes.Contains(out, []byte("no such file")) {
				t.Fatalf("cosign failed for another reason:\n%s", out)
			}
			t.Logf("cosign refused it: %s", bytes.TrimSpace(out))
		})
	}
	// The attacker's key would accept the replacement: trust comes only from
	// the key the verifier chooses, never from material in the package.
	if out, err := c.verifyDocumented(cmds, replacement, attackerSig.Bundle, keyB[SecretPublicKey]); err != nil {
		t.Fatalf("control: the attacker's own key should verify its signature: %v\n%s", err, out)
	}

	// Cosign's own sign-blob output for the same archive and key has the same
	// hint and message digest (its JSON spacing differs, and ECDSA
	// signatures are randomized).
	dir := t.TempDir()
	for name, b := range map[string][]byte{"cosign.key": keyA[SecretPrivateKey], "package.tar.gz": archive} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := c.run(dir, []string{"COSIGN_PASSWORD=" + string(keyA[SecretPassword])}, "cosign", "sign-blob", "--yes",
		"--key", "cosign.key", "--tlog-upload=false", "--use-signing-config=false", "--bundle", "cosign.sigstore.json", "package.tar.gz"); err != nil {
		t.Fatalf("cosign sign-blob: %v\n%s", err, out)
	}
	cosignBundle, err := os.ReadFile(filepath.Join(dir, "cosign.sigstore.json"))
	if err != nil {
		t.Fatal(err)
	}
	var theirs, ours wireBundle
	if err := json.Unmarshal(cosignBundle, &theirs); err != nil {
		t.Fatal(err)
	}
	ours = mustWire(t, sig.Bundle)
	if theirs.MediaType != ours.MediaType || theirs.VerificationMaterial != ours.VerificationMaterial ||
		theirs.MessageSignature.MessageDigest.Algorithm != ours.MessageSignature.MessageDigest.Algorithm ||
		!bytes.Equal(theirs.MessageSignature.MessageDigest.Digest, ours.MessageSignature.MessageDigest.Digest) {
		t.Fatalf("Cosign's bundle differs in content:\ncosign: %s\nours:   %s", cosignBundle, sig.Bundle)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(cosignBundle, &top); err != nil || len(top) != 3 {
		t.Fatalf("Cosign's key bundle has other top-level content: %s", cosignBundle)
	}

	// A key type Cosign can import but this contract does not support.
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(p384)
	if err != nil {
		t.Fatal(err)
	}
	plain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	imp := t.TempDir()
	if err := os.WriteFile(filepath.Join(imp, "p384.pem"), plain, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := c.run(imp, []string{"COSIGN_PASSWORD=pw-384"}, "cosign", "import-key-pair", "--key", "p384.pem", "--output-key-prefix", "cosign"); err != nil {
		t.Fatalf("cosign import-key-pair: %v\n%s", err, out)
	}
	if _, err := NewSecretSigner(c.secretFrom(imp, "pw-384")); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("a Cosign-encoded P-384 key: %v", err)
	}

	if n := c.connects.Load(); n != 0 {
		t.Fatalf("cosign attempted %d network connections", n)
	}
}

// The documented versions are the ones this test validates.
func TestDocumentedVersionsArePinned(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "docs/integration/evidence-signing.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	want := map[string]string{
		"Cosign CLI (Devbox)":                                 "v" + pinnedCosign(t),
		"`github.com/sigstore/sigstore-go`":                   goModVersion(t, "github.com/sigstore/sigstore-go"),
		"`github.com/sigstore/sigstore`":                      goModVersion(t, "github.com/sigstore/sigstore"),
		"`github.com/secure-systems-lab/go-securesystemslib`": goModVersion(t, "github.com/secure-systems-lab/go-securesystemslib"),
	}
	for name, version := range want {
		if !strings.Contains(doc, "| "+name+" | "+version+" |") {
			t.Errorf("docs/integration/evidence-signing.md does not list %s %s", name, version)
		}
	}
	if !strings.Contains(doc, "`"+BundleMediaType+"`") {
		t.Errorf("the documented bundle media type is not %s", BundleMediaType)
	}
	if !strings.Contains(doc, "`"+Algorithm+"`") {
		t.Errorf("the documented algorithm is not %s", Algorithm)
	}
}
