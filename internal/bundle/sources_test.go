package bundle

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func loadExample(t *testing.T, name string) Sources {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/bundles/sources/" + name)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseSources(raw)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return c
}

// loadOfficial loads the checked-in official source configuration, which the
// release workflow signs and verifies against.
func loadOfficial(t *testing.T) Sources {
	t.Helper()
	raw, err := os.ReadFile("../../bundles/official-sources.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseSources(raw)
	if err != nil {
		t.Fatalf("official-sources.yaml: %v", err)
	}
	return c
}

func TestExampleSourcesAreValid(t *testing.T) {
	off := loadOfficial(t)
	if len(off.Sources) != 1 || off.Sources[0].Publisher.Type != SignerKeyless || off.Sources[0].CredentialSecret != nil {
		t.Fatalf("official example: %+v", off)
	}
	org := loadExample(t, "organization.yaml")
	if len(org.Sources) != 2 || org.Sources[0].Name != "acme-baseline" {
		t.Fatalf("organization example is unsorted or wrong: %+v", org)
	}
	// Both signing methods, a private registry credential and CA are exercised.
	if org.Sources[0].Publisher.Type != SignerPublicKey || org.Sources[0].CredentialSecret == nil || org.Sources[0].CA == nil {
		t.Errorf("organization example misses a feature: %+v", org.Sources[0])
	}
	if org.Sources[1].Publisher.TrustRoot == nil {
		t.Errorf("custom trust root example missing")
	}
}

func baseDoc() string {
	return `version: 1
sources:
  - name: konstapel-privileged-containers
    repository: ghcr.io/backend-bunny/bundles/konstapel-privileged-containers
    publisher:
      type: keyless
      issuer: https://token.actions.githubusercontent.com
      identity: https://github.com/o/r/.github/workflows/w.yml@refs/heads/main
      provenance:
        sourceRepository: https://github.com/o/r
        builder: https://github.com/o/r/.github/workflows/w.yml@refs/heads/main
`
}

func TestSourcesRejections(t *testing.T) {
	cases := map[string]struct {
		doc  func(string) string
		want string
	}{
		"unsupported version": {func(s string) string { return strings.Replace(s, "version: 1", "version: 2", 1) }, "unsupported"},
		"missing version":     {func(s string) string { return strings.Replace(s, "version: 1\n", "", 1) }, "unsupported"},
		"unknown field":       {func(s string) string { return strings.Replace(s, "    publisher:", "    mirror: x\n    publisher:", 1) }, "unknown field"},
		"namespace on a ref": {func(s string) string {
			return strings.Replace(s, "    publisher:", "    ca:\n      kind: ConfigMap\n      name: ca\n      namespace: other\n    publisher:", 1)
		}, "unknown field"},
		"duplicate name": {func(s string) string {
			i := strings.Index(s, "  - name:")
			return s + s[i:]
		}, "duplicate source name"},
		"duplicate yaml key": {func(s string) string { return strings.Replace(s, "version: 1\n", "version: 1\nversion: 1\n", 1) }, "already set"},
		"uppercase name": {func(s string) string {
			return strings.Replace(s, "name: konstapel-privileged", "name: Konstapel-privileged", 1)
		}, "name must match"},
		"tag in repository": {func(s string) string {
			return strings.Replace(s, "containers\n    publisher", "containers:latest\n    publisher", 1)
		}, "embed a tag"},
		"digest in repository": {func(s string) string {
			return strings.Replace(s, "containers\n    publisher", "containers@sha256:"+strings.Repeat("a", 64)+"\n    publisher", 1)
		}, "embed a digest"},
		"scheme in repository": {func(s string) string { return strings.Replace(s, "repository: ghcr", "repository: https://ghcr", 1) }, "scheme"},
		"no path": {func(s string) string {
			return strings.Replace(s, "ghcr.io/backend-bunny/bundles/konstapel-privileged-containers", "ghcr.io", 1)
		}, "host[:port]/path"},
		"uppercase path": {func(s string) string { return strings.Replace(s, "/bundles/", "/Bundles/", 1) }, "invalid path"},
		"bad host":       {func(s string) string { return strings.Replace(s, "ghcr.io/", "-bad_host/", 1) }, "invalid registry host"},
		"missing repository": {func(s string) string {
			return strings.Replace(s, "    repository: ghcr.io/backend-bunny/bundles/konstapel-privileged-containers\n", "", 1)
		}, "repository"},
		"unknown publisher": {func(s string) string { return strings.Replace(s, "type: keyless", "type: trust-me", 1) }, "publisher.type"},
		"http issuer":       {func(s string) string { return strings.Replace(s, "issuer: https://token", "issuer: http://token", 1) }, "plain https URL"},
		"wildcard identity": {func(s string) string {
			return strings.Replace(s, "identity: https://github.com/o/r/.github/workflows/w.yml@refs/heads/main", "identity: https://github.com/o/*", 1)
		}, "exact value"},
		"regex identity": {func(s string) string {
			return strings.Replace(s, "identity: https://github.com/o/r/.github/workflows/w.yml@refs/heads/main", "identity: ^https://github.com/o/.+$", 1)
		}, "exact value"},
		"empty identity": {func(s string) string {
			return strings.Replace(s, "identity: https://github.com/o/r/.github/workflows/w.yml@refs/heads/main", `identity: ""`, 1)
		}, "exact value"},
		"missing identity": {func(s string) string {
			return strings.Replace(s, "      identity: https://github.com/o/r/.github/workflows/w.yml@refs/heads/main\n", "", 1)
		}, "exact value"},
		"match-anything identity": {func(s string) string {
			return strings.Replace(s, "identity: https://github.com/o/r/.github/workflows/w.yml@refs/heads/main", `identity: ".*"`, 1)
		}, "exact value"},
		"lone wildcard identity": {func(s string) string {
			return strings.Replace(s, "identity: https://github.com/o/r/.github/workflows/w.yml@refs/heads/main", `identity: "*"`, 1)
		}, "exact value"},
		"identity with surrounding space": {func(s string) string {
			return strings.Replace(s, "identity: https://github.com/o/r/.github/workflows/w.yml@refs/heads/main", `identity: " https://github.com/o/r/.github/workflows/w.yml@refs/heads/main"`, 1)
		}, "exact value"},
		"identity pattern field": {func(s string) string {
			return strings.Replace(s, "      identity: https://github.com/o/r/.github/workflows/w.yml@refs/heads/main\n", "      identityRegexp: https://github.com/o/.*\n", 1)
		}, "unknown field"},
		"missing issuer": {func(s string) string {
			return strings.Replace(s, "      issuer: https://token.actions.githubusercontent.com\n", "", 1)
		}, "plain https URL"},
		"wildcard issuer": {func(s string) string {
			return strings.Replace(s, "issuer: https://token.actions.githubusercontent.com", "issuer: https://*.githubusercontent.com", 1)
		}, "exact value"},
		"GitHub publisher with a non-workflow builder": {func(s string) string {
			return strings.Replace(s, "builder: https://github.com/o/r/.github/workflows/w.yml@refs/heads/main", "builder: https://ci.example.test/build@refs/heads/main", 1)
		}, "GitHub Actions workflow builder"},
		"GitHub publisher with a builder outside .github/workflows": {func(s string) string {
			return strings.Replace(s, "builder: https://github.com/o/r/.github/workflows/w.yml@refs/heads/main", "builder: https://github.com/o/r/ci/w.yml@refs/heads/main", 1)
		}, "GitHub Actions workflow builder"},
		"wildcard builder": {func(s string) string {
			return strings.Replace(s, "builder: https://github.com/o/r/.github/workflows/w.yml@refs/heads/main", "builder: https://github.com/o/*", 1)
		}, "exact value"},
		"missing provenance": {func(s string) string {
			return strings.Replace(s, "      provenance:\n        sourceRepository: https://github.com/o/r\n        builder: https://github.com/o/r/.github/workflows/w.yml@refs/heads/main\n", "", 1)
		}, "provenance"},
		"keyless with a key": {func(s string) string {
			return strings.Replace(s, "      provenance:", "      keyFingerprint: "+strings.Repeat("a", 64)+"\n      provenance:", 1)
		}, "must not set publicKey"},
		"public key needs fingerprint": {func(s string) string {
			return strings.Replace(strings.Replace(s, "type: keyless", "type: public-key\n      publicKey:\n        kind: Secret\n        name: k", 1), "      issuer: https://token.actions.githubusercontent.com\n      identity: https://github.com/o/r/.github/workflows/w.yml@refs/heads/main\n", "", 1)
		}, "keyFingerprint"},
		"public key with issuer": {func(s string) string {
			return strings.Replace(s, "type: keyless", "type: public-key\n      keyFingerprint: "+strings.Repeat("a", 64)+"\n      publicKey:\n        kind: Secret\n        name: k", 1)
		}, "must not set issuer"},
		"bad ca kind": {func(s string) string {
			return strings.Replace(s, "    publisher:", "    ca:\n      kind: Pod\n      name: ca\n    publisher:", 1)
		}, "kind"},
		"bad secret name": {func(s string) string {
			return strings.Replace(s, "    publisher:", "    credentialSecret:\n      name: Bad_Name\n    publisher:", 1)
		}, "DNS-1123"},
		"credential as configmap": {func(s string) string {
			return strings.Replace(s, "    publisher:", "    credentialSecret:\n      kind: ConfigMap\n      name: creds\n    publisher:", 1)
		}, "must be a Secret"},
		"bad data key": {func(s string) string {
			return strings.Replace(s, "    publisher:", "    ca:\n      kind: Secret\n      name: ca\n      key: a/b\n    publisher:", 1)
		}, "data key"},
		"inline private key": {func(s string) string { return s + "# -----BEGIN PRIVATE KEY-----\n" }, "belong in referenced Secrets"},
		"inline credentials": {func(s string) string { return s + "# auths: {}\n" }, "belong in referenced Secrets"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseSources([]byte(tc.doc(baseDoc())))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
	if _, err := ParseSources([]byte(baseDoc())); err != nil {
		t.Fatalf("the base document must be valid: %v", err)
	}
}

func TestGitHubWorkflowBuilder(t *testing.T) {
	gh, ok := GitHubWorkflowBuilder("https://github.com/backend-bunny/Konstapel/.github/workflows/bundle-release.yml@refs/heads/main")
	if !ok || gh != (GitHubWorkflow{Repository: "https://github.com/backend-bunny/Konstapel", Path: ".github/workflows/bundle-release.yml", Ref: "refs/heads/main"}) {
		t.Fatalf("%+v %v", gh, ok)
	}
	if gh, ok := GitHubWorkflowBuilder("https://github.com/o/r/.github/workflows/w.yaml@refs/tags/v1.2.3"); !ok || gh.Ref != "refs/tags/v1.2.3" {
		t.Fatalf("%+v %v", gh, ok)
	}
	for _, id := range []string{
		"",
		"https://ci.example.test/konstapel/bundle-release@refs/heads/main",
		"https://github.com/o/r/.github/workflows/w.yml",                     // no ref
		"https://github.com/o/r/.github/workflows/w.yml@main",                // not a qualified ref
		"https://github.com/o/r/.github/workflows/sub/w.yml@refs/heads/main", // not a workflow file
		"https://github.com/o/r/ci/w.yml@refs/heads/main",
		"https://github.com/o/r/.github/workflows/w.sh@refs/heads/main",
		"http://github.com/o/r/.github/workflows/w.yml@refs/heads/main",
		"https://github.com.evil.example/o/r/.github/workflows/w.yml@refs/heads/main",
		"https://github.com/o/../.github/workflows/w.yml@refs/heads/main",
		"https://github.com/o/r/.github/workflows/w.yml@refs/heads/main ",
		"https://github.com/o/r/.github/workflows/w.yml@refs/heads/ma in",
		"https://github.com/o/r/.github/workflows/w.yml@refs/heads/main\n",
	} {
		if gh, ok := GitHubWorkflowBuilder(id); ok {
			t.Errorf("%q parsed as %+v", id, gh)
		}
	}
}

func TestSelectIsExactAndHasNoFallback(t *testing.T) {
	c := loadExample(t, "organization.yaml")
	if s, err := c.Select("acme-baseline"); err != nil || s.Repository != "registry.acme.internal:5000/security/bundles/acme-baseline" {
		t.Fatalf("select: %+v %v", s, err)
	}
	for _, name := range []string{"acme", "acme-", "acme-baseline-2", "ACME-BASELINE", "", "konstapel-privileged-containers"} {
		if _, err := c.Select(name); !errors.Is(err, ErrUnconfigured) {
			t.Errorf("%q: got %v, want ErrUnconfigured", name, err)
		}
	}
	if _, err := (Sources{Version: 1}).Select("x"); !errors.Is(err, ErrUnconfigured) {
		t.Error("an empty configuration must not resolve anything")
	}
}

func TestPayloadNameMustMatchTheSource(t *testing.T) {
	c := loadOfficial(t)
	s, _ := c.Select("konstapel-privileged-containers")
	if err := s.CheckPayload(&Descriptor{Name: "konstapel-privileged-containers"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckPayload(&Descriptor{Name: "other-bundle"}); err == nil || !strings.Contains(err.Error(), "must equal the requested name") {
		t.Fatalf("a source answered with a different bundle: %v", err)
	}
}

func TestProvenanceMustMatchThePublisherRule(t *testing.T) {
	c := loadOfficial(t)
	s := c.Sources[0]
	ok := Provenance{Repository: s.Publisher.Provenance.SourceRepository, Builder: s.Publisher.Provenance.Builder}
	if err := s.CheckPublisher(ok); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]Provenance{
		"other repository": {Repository: "https://github.com/evil/fork", Builder: ok.Builder},
		"other builder":    {Repository: ok.Repository, Builder: "https://github.com/evil/w.yml@refs/heads/main"},
		"empty":            {},
	} {
		if err := s.CheckPublisher(p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestParseConfigMapData(t *testing.T) {
	if _, err := ParseConfigMapData(map[string]string{SourcesConfigKey: baseDoc()}); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseConfigMapData(map[string]string{}); err == nil {
		t.Error("accepted a ConfigMap without the document")
	}
	if _, err := ParseConfigMapData(map[string]string{SourcesConfigKey: baseDoc(), "extra": "x"}); err == nil || !strings.Contains(err.Error(), "unexpected key") {
		t.Errorf("accepted an extra key: %v", err)
	}
	// An invalid update is rejected whole: nothing is partially returned.
	if c, err := ParseConfigMapData(map[string]string{SourcesConfigKey: baseDoc() + "  - name: x\n"}); err == nil || len(c.Sources) != 0 {
		t.Errorf("partial acceptance of an invalid revision: %v %v", c, err)
	}
}

// The profile keeps its existing name/digest reference: central sources add no
// field to ComplianceProfile.spec.bundle.
func TestProfileBundleSchemaIsUnchanged(t *testing.T) {
	typ := reflect.TypeOf(v1alpha1.BundleReference{})
	var got []string
	for i := 0; i < typ.NumField(); i++ {
		got = append(got, typ.Field(i).Tag.Get("json"))
	}
	if !reflect.DeepEqual(got, []string{"name", "digest"}) {
		t.Fatalf("BundleReference fields = %v; sources are central and must not add profile fields", got)
	}
	// Every name a profile can carry is a configurable (or reportable) name.
	if !sourceNamePattern.MatchString("linux-workload-hardening") || !sourceNamePattern.MatchString("acme.baseline") {
		t.Error("source names do not follow the profile name pattern")
	}
}
