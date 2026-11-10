package kubeaccess

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

// MaxDockerConfigBytes bounds a dockerconfigjson document.
const MaxDockerConfigBytes = 1 << 20

const maxJSONDepth = 8

// Errors from parsing a dockerconfigjson document. They wrap
// registry.ErrCredentials and never contain credential values.
var (
	// ErrMalformedCredentials: the document is not an acceptable
	// dockerconfigjson (syntax, duplicate keys, unknown or forbidden fields,
	// a bad entry).
	ErrMalformedCredentials = fmt.Errorf("%w: malformed dockerconfigjson", registry.ErrCredentials)
	// ErrNoCredentialForHost: no auths entry matches the registry host.
	ErrNoCredentialForHost = fmt.Errorf("%w: no dockerconfigjson auths entry for the registry host", registry.ErrCredentials)
)

// forbiddenTopLevel are Docker config fields that would run a program or
// change what is sent where. Matching is case-insensitive, as Docker's own
// decoding is.
var forbiddenTopLevel = map[string]string{
	"credsstore":  "names a credential helper program",
	"credhelpers": "names credential helper programs",
	"httpheaders": "injects HTTP headers",
	"proxies":     "configures proxies",
}

// entryFields are the fields accepted in an auths entry. email and
// serveraddress are legacy informational fields and are ignored.
var entryFields = map[string]bool{
	"auth": true, "username": true, "password": true,
	"identitytoken": true, "registrytoken": true,
	"email": true, "serveraddress": true,
}

// safeName is how a field name or auths key may appear in an error.
var safeName = regexp.MustCompile(`^[A-Za-z0-9._:/\[\]-]{1,255}$`)

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrMalformedCredentials}, a...)...)
}

func quoted(name string) string {
	if safeName.MatchString(name) {
		return fmt.Sprintf("%q", name)
	}
	return "(unprintable name)"
}

// CredentialForHost parses a dockerconfigjson document strictly and returns
// the credential of the auths entry for host (host[:port], as in the source
// repository). See NormalizeAuthKey for which keys match.
//
// Only the "auths" top-level field is accepted. Credential helpers
// (credsStore, credHelpers), HttpHeaders and proxies are rejected, never
// executed or applied; any other field is rejected as unknown. Every entry
// is validated, not only the matching one. An entry holds exactly one
// credential form: username+password (or the equivalent "auth"), an identity
// token, or a registry token.
func CredentialForHost(doc []byte, host string) (registry.Credential, error) {
	if err := checkDocument(doc); err != nil {
		return registry.Credential{}, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil || top == nil {
		return registry.Credential{}, malformed("the document must be a JSON object")
	}
	for name := range top {
		if why, bad := forbiddenTopLevel[strings.ToLower(name)]; bad {
			return registry.Credential{}, malformed("field %s %s; credential helpers are never executed and only static auths entries are supported", quoted(name), why)
		}
		if name != "auths" {
			return registry.Credential{}, malformed("unknown top-level field %s; only \"auths\" is supported", quoted(name))
		}
	}
	rawAuths, ok := top["auths"]
	if !ok {
		return registry.Credential{}, malformed("missing \"auths\"")
	}
	var auths map[string]json.RawMessage
	if err := json.Unmarshal(rawAuths, &auths); err != nil || auths == nil {
		return registry.Credential{}, malformed("\"auths\" must be an object")
	}

	var (
		found   registry.Credential
		matches int
	)
	for key, raw := range auths {
		if key == "" || hasControl(key) {
			return registry.Credential{}, malformed("an auths key is empty or contains control characters")
		}
		cred, err := parseEntry(raw)
		if err != nil {
			return registry.Credential{}, fmt.Errorf("%w (auths entry %s)", err, quoted(key))
		}
		if h, ok := NormalizeAuthKey(key); ok && h == host {
			found = cred
			matches++
		}
	}
	switch {
	case matches > 1:
		return registry.Credential{}, malformed("more than one auths entry matches registry host %s", quoted(host))
	case matches == 0:
		return registry.Credential{}, fmt.Errorf("%w %s", ErrNoCredentialForHost, quoted(host))
	}
	return found, nil
}

// NormalizeAuthKey maps an auths key to the registry host it names. The
// accepted forms are "host", "host:port", "https://host[:port]",
// "https://host[:port]/" and "https://host[:port]/v1/". Anything else (other
// schemes or paths, wildcards) names no host. The result is compared with the
// source's registry host exactly: no case folding (repository hosts are
// lowercase, so "GHCR.IO" does not match), no prefix or suffix matching, and
// a port is part of the host ("registry.example" does not match
// "registry.example:5000", nor "registry.example:443" "registry.example").
func NormalizeAuthKey(key string) (string, bool) {
	k := key
	if rest, ok := strings.CutPrefix(k, "https://"); ok {
		k = rest
		if h, ok := strings.CutSuffix(k, "/v1/"); ok {
			k = h
		} else if h, ok := strings.CutSuffix(k, "/"); ok {
			k = h
		}
	}
	if k == "" || strings.ContainsAny(k, "/@?#*\\ ") || strings.Contains(k, "://") {
		return "", false
	}
	return k, true
}

// checkDocument enforces size, encoding, a single JSON value, bounded nesting
// and no repeated object keys anywhere (encoding/json silently keeps the
// last, so a duplicate could hide a credential from review).
func checkDocument(doc []byte) error {
	switch {
	case len(bytes.TrimSpace(doc)) == 0:
		return malformed("the document is empty")
	case len(doc) > MaxDockerConfigBytes:
		return malformed("the document exceeds %d bytes", MaxDockerConfigBytes)
	case !utf8.Valid(doc):
		return malformed("the document is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := walkValue(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return malformed("unexpected data after the JSON document")
	}
	return nil
}

// walkValue consumes one JSON value. Syntax errors are reported by offset
// only: encoding/json's messages can quote input bytes.
func walkValue(dec *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return malformed("nesting exceeds %d levels", maxJSONDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return malformed("invalid JSON near byte %d", dec.InputOffset())
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return malformed("invalid JSON near byte %d", dec.InputOffset())
			}
			k, _ := kt.(string)
			if seen[k] {
				return malformed("repeated key %s", quoted(k))
			}
			seen[k] = true
			if err := walkValue(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := walkValue(dec, depth+1); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return malformed("invalid JSON near byte %d", dec.InputOffset())
	}
	return nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == utf8.RuneError {
			return true
		}
	}
	return false
}

func parseEntry(raw json.RawMessage) (registry.Credential, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return registry.Credential{}, malformed("an auths entry must be an object")
	}
	vals := map[string]string{}
	for name, v := range fields {
		if !entryFields[name] {
			return registry.Credential{}, malformed("unknown auths entry field %s", quoted(name))
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return registry.Credential{}, malformed("auths entry field %s must be a string", quoted(name))
		}
		if hasControl(s) {
			return registry.Credential{}, malformed("auths entry field %s contains control or invalid characters", quoted(name))
		}
		vals[name] = s
	}
	user, pass := vals["username"], vals["password"]
	identity, token := vals["identitytoken"], vals["registrytoken"]

	if a := vals["auth"]; a != "" {
		raw, err := base64.StdEncoding.Strict().DecodeString(a)
		if err != nil {
			return registry.Credential{}, malformed("\"auth\" is not valid base64")
		}
		decoded := string(raw)
		if !utf8.ValidString(decoded) || hasControl(decoded) {
			return registry.Credential{}, malformed("\"auth\" decodes to control or invalid characters")
		}
		au, ap, ok := strings.Cut(decoded, ":")
		if !ok || au == "" {
			return registry.Credential{}, malformed("\"auth\" must decode to username:password")
		}
		if (user != "" || pass != "") && (user != au || pass != ap) {
			return registry.Credential{}, malformed("\"auth\" disagrees with username/password")
		}
		user, pass = au, ap
	}

	switch {
	case token != "":
		if identity != "" || user != "" || pass != "" {
			return registry.Credential{}, malformed("an entry must hold exactly one credential form; registrytoken is combined with another")
		}
		return registry.Credential{RegistryToken: token}, nil
	case identity != "":
		// Docker stores the account name next to an identity token (its
		// "auth" then decodes to "name:"); a password as well is ambiguous.
		if pass != "" {
			return registry.Credential{}, malformed("an entry must hold exactly one credential form; identitytoken is combined with a password")
		}
		return registry.Credential{IdentityToken: identity}, nil
	case user != "" && pass != "":
		return registry.Credential{Username: user, Password: pass}, nil
	case user != "" || pass != "":
		return registry.Credential{}, malformed("username and password must both be set")
	}
	return registry.Credential{}, malformed("the entry has no credential")
}
