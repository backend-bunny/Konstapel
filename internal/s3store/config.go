// Package s3store is Konstapel's S3 evidence backend: central destination
// configuration, client construction, and the compatibility probe that gates
// backend readiness. The publisher implementing publication.Publisher builds
// on these.
package s3store

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"sigs.k8s.io/yaml"
)

// Addressing selects S3 request addressing.
type Addressing string

const (
	AddressingPath    Addressing = "path"
	AddressingVirtual Addressing = "virtual"
)

// SecretRef names the credential Secret in the controller's namespace. It
// carries no namespace: credentials can only come from the controller's own
// namespace, never from an application namespace.
type SecretRef struct {
	Name string `json:"name"`
	// AccessKeyIDKey and SecretAccessKeyKey name the Secret's data keys.
	AccessKeyIDKey     string `json:"accessKeyIDKey,omitempty"`
	SecretAccessKeyKey string `json:"secretAccessKeyKey,omitempty"`
}

// Destination is the platform-controlled evidence destination. It is loaded
// from deployment configuration; no request, run, or binding field can
// override it.
type Destination struct {
	// ID is a stable identifier recorded with every publication, so a later
	// default destination never relocates history.
	ID         string     `json:"id"`
	Endpoint   string     `json:"endpoint"`
	Bucket     string     `json:"bucket"`
	Region     string     `json:"region"`
	Prefix     string     `json:"prefix,omitempty"`
	Addressing Addressing `json:"addressing"`
	// Exactly one credential source: the standard workload-identity chain,
	// or a Secret in the controller namespace.
	WorkloadIdentity bool       `json:"workloadIdentity,omitempty"`
	CredentialSecret *SecretRef `json:"credentialSecret,omitempty"`
	// CABundle is a PEM file with additional trusted roots.
	CABundle string `json:"caBundle,omitempty"`
	// DevelopmentFixture permits a plain-HTTP endpoint for an explicitly
	// isolated local test service. TLS verification is never disabled.
	DevelopmentFixture bool `json:"developmentFixture,omitempty"`
}

var (
	idPattern     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	ipPattern     = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
	keyPattern    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`)
)

// Validate checks the destination without contacting it.
func (d Destination) Validate() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if !idPattern.MatchString(d.ID) {
		fail("id %q must be a DNS label", d.ID)
	}
	u, err := url.Parse(d.Endpoint)
	switch {
	case err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/"):
		fail("endpoint %q must be a bare scheme://host[:port] URL", d.Endpoint)
	case u.Scheme == "http" && !d.DevelopmentFixture:
		fail("endpoint %q must use https; plain http is only for an explicitly isolated developmentFixture", d.Endpoint)
	case u.Scheme != "https" && u.Scheme != "http":
		fail("endpoint %q must use https", d.Endpoint)
	}
	if !bucketPattern.MatchString(d.Bucket) || strings.Contains(d.Bucket, "..") || ipPattern.MatchString(d.Bucket) {
		fail("bucket %q is not a valid S3 bucket name", d.Bucket)
	}
	if d.Region == "" {
		fail("region is required")
	}
	if p := d.Prefix; p != "" {
		trimmed := strings.TrimSuffix(p, "/")
		if strings.HasPrefix(p, "/") || strings.Contains(p, "//") || path.Clean(trimmed) != trimmed || strings.Contains(p, "..") || len(p) > 512 {
			fail("prefix %q must be a clean relative key prefix", p)
		}
	}
	if d.Addressing != AddressingPath && d.Addressing != AddressingVirtual {
		fail("addressing must be %q or %q", AddressingPath, AddressingVirtual)
	}
	switch {
	case d.WorkloadIdentity == (d.CredentialSecret != nil):
		fail("set exactly one of workloadIdentity and credentialSecret")
	case d.CredentialSecret != nil:
		s := d.CredentialSecret
		if !idPattern.MatchString(s.Name) {
			fail("credentialSecret.name %q must be a DNS label", s.Name)
		}
		for _, k := range []string{s.AccessKeyIDKey, s.SecretAccessKeyKey} {
			if k != "" && !keyPattern.MatchString(k) {
				fail("credentialSecret key %q is not a valid Secret data key", k)
			}
		}
	}
	return errors.Join(errs...)
}

// KeyPrefix is the destination prefix with exactly one trailing slash, or "".
func (d Destination) KeyPrefix() string {
	if d.Prefix == "" {
		return ""
	}
	return strings.TrimSuffix(d.Prefix, "/") + "/"
}

// LoadDestination reads a destination from a YAML file, rejecting unknown
// fields so a misspelled setting can never be silently ignored.
func LoadDestination(file string) (Destination, error) {
	var d Destination
	raw, err := os.ReadFile(file)
	if err != nil {
		return d, err
	}
	j, err := yaml.YAMLToJSON(raw)
	if err != nil {
		return d, err
	}
	if err := yaml.UnmarshalStrict(j, &d); err != nil {
		return d, fmt.Errorf("evidence destination: %w", err)
	}
	if bytes.Contains(bytes.ToLower(raw), []byte("secretaccesskey:")) && d.CredentialSecret == nil {
		return d, errors.New("evidence destination: credentials belong in a Secret, not in the destination file")
	}
	return d, d.Validate()
}
