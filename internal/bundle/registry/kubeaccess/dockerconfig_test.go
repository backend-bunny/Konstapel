package kubeaccess

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

const (
	host     = "registry.example:5000"
	user     = "robot-account"
	password = "Sup3r-S3cret-Passw0rd"
	idToken  = "identity-token-0123456789"
	regToken = "registry-token-9876543210"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// secretValues are strings that must never appear in an error.
var secretValues = []string{password, idToken, regToken, b64(user + ":" + password), b64(":" + password)}

func assertNoSecrets(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, out := range []string{err.Error(), fmt.Sprintf("%v %+v %#v %s %q", err, err, err, err, err)} {
		for _, v := range secretValues {
			if strings.Contains(out, v) {
				t.Fatalf("error discloses a credential value: %s", out)
			}
		}
	}
}

func TestCredentialForHostAccepts(t *testing.T) {
	basic := registry.Credential{Username: user, Password: password}
	for _, tc := range []struct {
		name string
		doc  string
		want registry.Credential
	}{
		{"auth", `{"auths":{"registry.example:5000":{"auth":"` + b64(user+":"+password) + `"}}}`, basic},
		{"username and password", `{"auths":{"registry.example:5000":{"username":"` + user + `","password":"` + password + `"}}}`, basic},
		{"auth agreeing with username/password and legacy fields", `{"auths":{"registry.example:5000":{"auth":"` + b64(user+":"+password) + `","username":"` + user + `","password":"` + password + `","email":"x@example.com","serveraddress":"registry.example:5000"}}}`, basic},
		{"password containing a colon", `{"auths":{"registry.example:5000":{"auth":"` + b64(user+":a:b:"+password) + `"}}}`, registry.Credential{Username: user, Password: "a:b:" + password}},
		{"identity token", `{"auths":{"registry.example:5000":{"identitytoken":"` + idToken + `"}}}`, registry.Credential{IdentityToken: idToken}},
		{"identity token with Docker's name-only auth", `{"auths":{"registry.example:5000":{"auth":"` + b64(user+":") + `","identitytoken":"` + idToken + `"}}}`, registry.Credential{IdentityToken: idToken}},
		{"registry token", `{"auths":{"registry.example:5000":{"registrytoken":"` + regToken + `"}}}`, registry.Credential{RegistryToken: regToken}},
		{"https form", `{"auths":{"https://registry.example:5000":{"auth":"` + b64(user+":"+password) + `"}}}`, basic},
		{"https form with slash", `{"auths":{"https://registry.example:5000/":{"auth":"` + b64(user+":"+password) + `"}}}`, basic},
		{"https form with /v1/", `{"auths":{"https://registry.example:5000/v1/":{"auth":"` + b64(user+":"+password) + `"}}}`, basic},
		{"other hosts present", `{"auths":{"registry.example":{"auth":"` + b64("a:b") + `"},"registry.example:5000":{"auth":"` + b64(user+":"+password) + `"},"evil-registry.example:5000":{"auth":"` + b64("c:d") + `"}}}`, basic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CredentialForHost([]byte(tc.doc), host)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatal("unexpected credential")
			}
		})
	}
}

func TestCredentialForHostRejects(t *testing.T) {
	entry := `{"auth":"` + b64(user+":"+password) + `"}`
	big := `{"auths":{"registry.example:5000":{"auth":"` + b64(user+":"+password) + `","email":"` + strings.Repeat("a", MaxDockerConfigBytes) + `"}}}`
	for _, tc := range []struct {
		name string
		doc  string
		want error
	}{
		{"empty", ``, ErrMalformedCredentials},
		{"whitespace", "  \n", ErrMalformedCredentials},
		{"oversized", big, ErrMalformedCredentials},
		{"not JSON", `auths: {}`, ErrMalformedCredentials},
		{"truncated", `{"auths":{"registry.example:5000":` + entry, ErrMalformedCredentials},
		{"trailing data", `{"auths":{"registry.example:5000":` + entry + `}} {}`, ErrMalformedCredentials},
		{"not UTF-8", "{\"auths\":{\"registry.example:5000\":{\"auth\":\"\xff\xfe\"}}}", ErrMalformedCredentials},
		{"array", `[]`, ErrMalformedCredentials},
		{"null", `null`, ErrMalformedCredentials},
		{"no auths", `{}`, ErrMalformedCredentials},
		{"auths null", `{"auths":null}`, ErrMalformedCredentials},
		{"auths not an object", `{"auths":[]}`, ErrMalformedCredentials},
		{"credsStore", `{"auths":{},"credsStore":"desktop"}`, ErrMalformedCredentials},
		{"credsStore only", `{"credsStore":"desktop"}`, ErrMalformedCredentials},
		{"credHelpers", `{"auths":{"registry.example:5000":` + entry + `},"credHelpers":{"registry.example:5000":"ecr-login"}}`, ErrMalformedCredentials},
		{"credhelpers lowercase", `{"auths":{},"credhelpers":{"registry.example:5000":"evil"}}`, ErrMalformedCredentials},
		{"HttpHeaders", `{"auths":{"registry.example:5000":` + entry + `},"HttpHeaders":{"X-Evil":"1"}}`, ErrMalformedCredentials},
		{"proxies", `{"auths":{"registry.example:5000":` + entry + `},"proxies":{"default":{"httpsProxy":"http://evil"}}}`, ErrMalformedCredentials},
		{"unknown top-level field", `{"auths":{"registry.example:5000":` + entry + `},"psFormat":"x"}`, ErrMalformedCredentials},
		{"differently cased auths", `{"Auths":{"registry.example:5000":` + entry + `}}`, ErrMalformedCredentials},
		{"duplicate top-level key", `{"auths":{},"auths":{"registry.example:5000":` + entry + `}}`, ErrMalformedCredentials},
		{"duplicate auths key", `{"auths":{"registry.example:5000":{"auth":"` + b64("a:b") + `"},"registry.example:5000":` + entry + `}}`, ErrMalformedCredentials},
		{"duplicate entry field", `{"auths":{"registry.example:5000":{"password":"x","password":"` + password + `","username":"u"}}}`, ErrMalformedCredentials},
		{"two keys for the host", `{"auths":{"registry.example:5000":` + entry + `,"https://registry.example:5000":` + entry + `}}`, ErrMalformedCredentials},
		{"entry not an object", `{"auths":{"registry.example:5000":"` + password + `"}}`, ErrMalformedCredentials},
		{"unknown entry field", `{"auths":{"registry.example:5000":{"auth":"` + b64(user+":"+password) + `","helper":"x"}}}`, ErrMalformedCredentials},
		{"non-string field", `{"auths":{"registry.example:5000":{"auth":1}}}`, ErrMalformedCredentials},
		{"empty entry", `{"auths":{"registry.example:5000":{}}}`, ErrMalformedCredentials},
		{"bad base64", `{"auths":{"registry.example:5000":{"auth":"not base64!"}}}`, ErrMalformedCredentials},
		{"unpadded base64", `{"auths":{"registry.example:5000":{"auth":"` + strings.TrimRight(b64(user+":"+password+"xy"), "=") + `"}}}`, ErrMalformedCredentials},
		{"auth without colon", `{"auths":{"registry.example:5000":{"auth":"` + b64(user+password) + `"}}}`, ErrMalformedCredentials},
		{"auth with empty user", `{"auths":{"registry.example:5000":{"auth":"` + b64(":"+password) + `"}}}`, ErrMalformedCredentials},
		{"auth with empty password", `{"auths":{"registry.example:5000":{"auth":"` + b64(user+":") + `"}}}`, ErrMalformedCredentials},
		{"auth with control characters", `{"auths":{"registry.example:5000":{"auth":"` + b64(user+":"+password+"\n") + `"}}}`, ErrMalformedCredentials},
		{"escaped control character", `{"auths":{"registry.example:5000":{"username":"u","password":"` + password + `\u0000"}}}`, ErrMalformedCredentials},
		{"control character in a key", `{"auths":{"registry.example:5000\u0007":` + entry + `}}`, ErrMalformedCredentials},
		{"auth disagrees with password", `{"auths":{"registry.example:5000":{"auth":"` + b64(user+":"+password) + `","username":"` + user + `","password":"other"}}}`, ErrMalformedCredentials},
		{"username without password", `{"auths":{"registry.example:5000":{"username":"` + user + `"}}}`, ErrMalformedCredentials},
		{"password without username", `{"auths":{"registry.example:5000":{"password":"` + password + `"}}}`, ErrMalformedCredentials},
		{"identity token and password", `{"auths":{"registry.example:5000":{"username":"u","password":"` + password + `","identitytoken":"` + idToken + `"}}}`, ErrMalformedCredentials},
		{"registry token and identity token", `{"auths":{"registry.example:5000":{"registrytoken":"` + regToken + `","identitytoken":"` + idToken + `"}}}`, ErrMalformedCredentials},
		{"registry token and basic", `{"auths":{"registry.example:5000":{"registrytoken":"` + regToken + `","auth":"` + b64(user+":"+password) + `"}}}`, ErrMalformedCredentials},
		{"malformed entry for another host", `{"auths":{"registry.example:5000":` + entry + `,"other.example":{"auth":"%%%"}}}`, ErrMalformedCredentials},
		{"too deep", `{"auths":{"registry.example:5000":` + entry + `,"x":` + strings.Repeat(`{"a":`, 10) + `1` + strings.Repeat(`}`, 10) + `}}`, ErrMalformedCredentials},
		{"no entry", `{"auths":{}}`, ErrNoCredentialForHost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CredentialForHost([]byte(tc.doc), host)
			if !errors.Is(err, tc.want) || !errors.Is(err, registry.ErrCredentials) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			assertNoSecrets(t, err)
		})
	}
}

// TestHelpersAreNamedNotExecuted: the error says why the document is
// refused, so an operator knows helpers are unsupported.
func TestHelpersAreNamedNotExecuted(t *testing.T) {
	_, err := CredentialForHost([]byte(`{"auths":{},"credHelpers":{"registry.example:5000":"evil"}}`), host)
	if err == nil || !strings.Contains(err.Error(), "credHelpers") || !strings.Contains(err.Error(), "never executed") {
		t.Fatalf("got %v", err)
	}
}

func TestExactHostMatching(t *testing.T) {
	cred := b64(user + ":" + password)
	for _, tc := range []struct {
		key, host string
		match     bool
	}{
		{"ghcr.io", "ghcr.io", true},
		{"https://ghcr.io", "ghcr.io", true},
		{"https://ghcr.io/", "ghcr.io", true},
		{"https://ghcr.io/v1/", "ghcr.io", true},
		{"ghcr.io:443", "ghcr.io:443", true},
		{"https://ghcr.io:443/", "ghcr.io:443", true},
		// Near misses: none of these may match.
		{"evil-ghcr.io", "ghcr.io", false},
		{"ghcr.io.evil.example", "ghcr.io", false},
		{"sub.ghcr.io", "ghcr.io", false},
		{"ghcr.io", "sub.ghcr.io", false},
		{"ghcr.i", "ghcr.io", false},
		{"GHCR.IO", "ghcr.io", false},
		{"https://GHCR.io", "ghcr.io", false},
		{"ghcr.io:443", "ghcr.io", false},
		{"ghcr.io", "ghcr.io:443", false},
		{"ghcr.io", "ghcr.io:5000", false},
		{"ghcr.io:5000", "ghcr.io:5001", false},
		{"http://ghcr.io", "ghcr.io", false},
		{"https://ghcr.io/v2/", "ghcr.io", false},
		{"https://ghcr.io/v1", "ghcr.io", false},
		{"ghcr.io/", "ghcr.io", false},
		{"ghcr.io/org", "ghcr.io", false},
		{"https://ghcr.io/org/", "ghcr.io", false},
		{"*.ghcr.io", "x.ghcr.io", false},
		{"*", "ghcr.io", false},
		{"user@ghcr.io", "ghcr.io", false},
		{" ghcr.io", "ghcr.io", false},
	} {
		t.Run(tc.key+"->"+tc.host, func(t *testing.T) {
			doc, _ := json.Marshal(map[string]any{"auths": map[string]any{tc.key: map[string]string{"auth": cred}}})
			got, err := CredentialForHost(doc, tc.host)
			if tc.match {
				if err != nil || got.Password != password {
					t.Fatalf("want a match, got %v", err)
				}
				return
			}
			if !errors.Is(err, ErrNoCredentialForHost) || got != (registry.Credential{}) {
				t.Fatalf("want no match, got %v", err)
			}
			assertNoSecrets(t, err)
		})
	}
}
