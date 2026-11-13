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
	// One keyless rule per released bundle, all with the same identity and
	// builder (the release workflow on main).
	if len(off.Sources) != 2 || off.Sources[0].Name != "konstapel-linux-hardening" || off.Sources[1].Name != "konstapel-privileged-containers" {
		t.Fatalf("official sources must be one rule per released bundle: %+v", off)
	}
	for _, s := range off.Sources {
		if s.Publisher.Type != SignerKeyless || s.CredentialSecret != nil {
			t.Fatalf("official rule %s: %+v", s.Name, s)
		}
		if s.Repository != "ghcr.io/backend-bunny/bundles/"+s.Name {
			t.Errorf("official rule %s repository %s", s.Name, s.Repository)
		}
		if s.Publisher.Identity != off.Sources[0].Publisher.Identity {
			t.Errorf("official rule %s identity differs from the others", s.Name)
		}
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

// realms adds a tokenRealms list to the base document.
func realms(entries ...string) func(string) string {
	return func(s string) string {
		list := "    tokenRealms:\n"
		for _, e := range entries {
			list += "      - " + e + "\n"
		}
		return strings.Replace(s, "    publisher:", list+"    publisher:", 1)
	}
}

func TestTokenRealmsAccepted(t *testing.T) {
	c := loadExample(t, "token-realms.yaml")
	want := map[string]string{"acme-dockerhub": "https://auth.docker.io", "acme-gitlab": "https://gitlab.com"}
	for _, s := range c.Sources {
		if len(s.TokenRealms) != 1 || s.TokenRealms[0] != want[s.Name] {
			t.Errorf("%s: tokenRealms %v", s.Name, s.TokenRealms)
		}
	}
	for in, canon := range map[string]string{
		"https://auth.example":       "https://auth.example",
		"https://auth.example:443":   "https://auth.example",
		"https://auth.example:8443":  "https://auth.example:8443",
		"https://token-service":      "https://token-service",
		"https://a.b-c.example:1":    "https://a.b-c.example:1",
		"https://auth.example:65535": "https://auth.example:65535",
	} {
		got, err := ParseTokenRealm(in)
		if err != nil || got != canon {
			t.Errorf("%s: got %q, %v; want %q", in, got, err, canon)
		}
	}
	if _, err := ParseSources([]byte(realms("https://auth.example", "https://auth2.example:8443")(baseDoc()))); err != nil {
		t.Fatal(err)
	}
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
		"http token realm":                      {realms("http://auth.example"), "https origin"},
		"token realm with a path":               {realms("https://auth.example/token"), "without userinfo, path"},
		"token realm with a trailing slash":     {realms("https://auth.example/"), "without userinfo, path"},
		"token realm with a query":              {realms("https://auth.example?x=1"), "without userinfo, path"},
		"token realm with a fragment":           {realms("https://auth.example#x"), "without userinfo, path"},
		"token realm with userinfo":             {realms("https://user@auth.example"), "without userinfo, path"},
		"token realm wildcard":                  {realms("https://*.example"), "wildcards"},
		"token realm uppercase":                 {realms("https://Auth.example"), "lowercase DNS host"},
		"token realm IPv4":                      {realms("https://192.0.2.1"), "not an IP address"},
		"token realm IPv4 with port":            {realms("https://192.0.2.1:8443"), "not an IP address"},
		"token realm numeric host":              {realms("https://3221225985"), "not an IP address"},
		"token realm IPv6":                      {realms("https://[2001:db8::1]"), "wildcards"},
		"token realm localhost":                 {realms("https://localhost"), "localhost"},
		"token realm localhost subdomain":       {realms("https://auth.localhost"), "localhost"},
		"token realm port zero":                 {realms("https://auth.example:0"), "invalid port"},
		"token realm port too large":            {realms("https://auth.example:65536"), "invalid port"},
		"token realm port leading zero":         {realms("https://auth.example:0443"), "invalid port"},
		"token realm empty port":                {realms(`"https://auth.example:"`), "lowercase DNS host"},
		"token realm empty":                     {realms(""), "https origin"},
		"token realm space":                     {realms("' https://auth.example'"), "https origin"},
		"token realm trailing newline":          {realms("\"https://auth.example\\n\""), "without userinfo"},
		"token realm duplicate":                 {realms("https://auth.example", "https://auth.example:443"), "more than once"},
		"token realm is the registry":           {realms("https://ghcr.io"), "registry's own origin"},
		"token realm is the registry with port": {realms("https://ghcr.io:443"), "registry's own origin"},
		"too many token realms":                 {realms("https://a.example", "https://b.example", "https://c.example", "https://d.example", "https://e.example"), "more than 4"},
		"token realms not a list": {func(s string) string {
			return strings.Replace(s, "    publisher:", "    tokenRealms: https://auth.example\n    publisher:", 1)
		}, "cannot unmarshal"},
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

func TestDockerHubAliasesRejected(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	for _, repo := range []string{
		"docker.io/library/alpine",
		"docker.io/acme/bundles",
		"index.docker.io/acme/bundles",
		"registry.hub.docker.com/acme/bundles",
		"registry.docker.io/acme/bundles",
		"hub.docker.com/acme/bundles",
		"DOCKER.IO/acme/bundles",
		"Index.Docker.IO/acme/bundles",
		"docker.io:443/acme/bundles",
		"index.docker.io:5000/acme/bundles",
		"docker.io/acme/bundles:latest",
		"docker.io/acme/bundles@" + d,
	} {
		err := ValidateRepository(repo)
		if err == nil {
			t.Errorf("%s: accepted", repo)
			continue
		}
		if strings.Contains(repo, "@") {
			continue // the digest rule fires first; still rejected
		}
		for _, w := range []string{"registry-1.docker.io", "`auths`", "tokenRealms"} {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: error lacks %q: %v", repo, w, err)
			}
		}
		doc := strings.Replace(baseDoc(), "ghcr.io/backend-bunny/bundles/konstapel-privileged-containers", repo, 1)
		if _, err := ParseSources([]byte(doc)); err == nil || !strings.Contains(err.Error(), "registry-1.docker.io") {
			t.Errorf("%s: ParseSources: %v", repo, err)
		}
	}
	for _, repo := range []string{"registry-1.docker.io/acme/bundles", "registry-1.docker.io:443/acme/bundles", "notdocker.io/acme/bundles"} {
		if err := ValidateRepository(repo); err != nil {
			t.Errorf("%s: %v", repo, err)
		}
	}
}
