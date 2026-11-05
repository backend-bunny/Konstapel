package targeting

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// This file is the content seam. Delivery needs, for a pinned bundle
// reference, the bundle's policy metadata and each policy's source manifest.
// LocalContent serves the repository's vendored content/ tree.
// add-policy-bundle-distribution supplies the verified OCI implementation
// behind the same interface; it owns transport, trust and caching, and
// targeting keeps rendering, names and revisions.

// ErrContentUnavailable means no verified content matches the pinned
// reference. The resolver reports it as ReasonContentUnavailable.
var ErrContentUnavailable = errors.New("content unavailable")

// ContentSource returns verified content for a pinned bundle reference.
type ContentSource interface {
	Content(ctx context.Context, ref v1alpha1.BundleReference) (*Content, error)
}

// Content is verified, immutable bundle content.
type Content struct {
	Bundle   Bundle
	Policies map[string]PolicySource
}

// PolicySource is one logical policy's source manifest.
type PolicySource struct {
	// Manifest is the unmodified source policy document.
	Manifest map[string]any
	// SourceDigest is the sha256 of the source file bytes.
	SourceDigest string
}

// ScopeFunc reports whether a resource is namespaced. known is false when
// the resource is not recognised; unknown resources are never targeted.
type ScopeFunc func(group, resource string) (namespaced, known bool)

// StandardWorkloadScopes recognises the built-in namespaced workload resources.
// The controller can supply a discovery-backed ScopeFunc instead.
func StandardWorkloadScopes(group, resource string) (namespaced, known bool) {
	switch group + "/" + resource {
	case "/pods", "/pods/ephemeralcontainers", "/replicationcontrollers",
		"apps/deployments", "apps/daemonsets", "apps/statefulsets", "apps/replicasets",
		"batch/jobs", "batch/cronjobs":
		return true, true
	}
	return false, false
}

// LocalContent serves one bundle from a directory verified by its SHA256SUMS.
// The bundle digest is the sha256 of the SHA256SUMS file. Every listed file
// is checked on each call, so the digest covers all of them.
type LocalContent struct {
	// Root contains SHA256SUMS; paths in it are relative to Root's parent,
	// matching the repository's content/SHA256SUMS layout.
	Root string
	Name string
	// Policies maps logical policy names to manifest paths listed in SHA256SUMS.
	Policies map[string]string
	Scope    ScopeFunc
}

// Content implements ContentSource.
func (l LocalContent) Content(_ context.Context, ref v1alpha1.BundleReference) (*Content, error) {
	sums, err := os.ReadFile(filepath.Join(l.Root, "SHA256SUMS"))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrContentUnavailable, err)
	}
	digest := "sha256:" + hexSum(sums)
	if ref.Name != l.Name || ref.Digest != digest {
		return nil, fmt.Errorf("%w: %s@%s is not served here (have %s@%s)", ErrContentUnavailable, ref.Name, ref.Digest, l.Name, digest)
	}
	base := filepath.Dir(l.Root)
	listed := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		sum, path, ok := strings.Cut(sc.Text(), "  ")
		if !ok {
			return nil, fmt.Errorf("%w: malformed SHA256SUMS line %q", ErrContentUnavailable, sc.Text())
		}
		b, err := os.ReadFile(filepath.Join(base, path))
		if err != nil || hexSum(b) != sum {
			return nil, fmt.Errorf("%w: %s does not match SHA256SUMS", ErrContentUnavailable, path)
		}
		listed[path] = sum
	}
	scope := l.Scope
	if scope == nil {
		scope = StandardWorkloadScopes
	}
	c := &Content{Bundle: Bundle{Name: l.Name, Digest: digest}, Policies: map[string]PolicySource{}}
	for name, path := range l.Policies {
		sum, ok := listed[path]
		if !ok {
			return nil, fmt.Errorf("%w: policy %s at %s is not covered by SHA256SUMS", ErrContentUnavailable, name, path)
		}
		raw, _ := os.ReadFile(filepath.Join(base, path))
		var m map[string]any
		if err := yaml.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("%w: policy %s: %v", ErrContentUnavailable, name, err)
		}
		s, err := PolicyScopeOf(m, scope)
		if err != nil {
			return nil, fmt.Errorf("%w: policy %s: %v", ErrContentUnavailable, name, err)
		}
		c.Bundle.Policies = append(c.Bundle.Policies, BundlePolicy{Name: name, Scope: s})
		c.Policies[name] = PolicySource{Manifest: m, SourceDigest: "sha256:" + sum}
	}
	return c, nil
}

// PolicyScopeOf classifies a source policy: Namespaced only if it is a
// policies.kyverno.io/v1 ValidatingPolicy whose every matched resource is a
// known namespaced resource. Otherwise the policy cannot be namespace-targeted.
func PolicyScopeOf(m map[string]any, scope ScopeFunc) (PolicyScope, error) {
	if m["apiVersion"] != "policies.kyverno.io/v1" || m["kind"] != "ValidatingPolicy" {
		return "", fmt.Errorf("unsupported policy type %v/%v", m["apiVersion"], m["kind"])
	}
	mc, _ := nested(m, "spec", "matchConstraints").(map[string]any)
	rules, _ := mc["resourceRules"].([]any)
	if len(rules) == 0 {
		return ScopeCluster, nil
	}
	for _, r := range rules {
		rule, _ := r.(map[string]any)
		groups, _ := rule["apiGroups"].([]any)
		resources, _ := rule["resources"].([]any)
		if len(groups) == 0 || len(resources) == 0 {
			return ScopeCluster, nil
		}
		for _, g := range groups {
			for _, res := range resources {
				gs, _ := g.(string)
				rs, _ := res.(string)
				if namespaced, known := scope(gs, rs); !namespaced || !known {
					return ScopeCluster, nil
				}
			}
		}
	}
	return ScopeNamespaced, nil
}

func nested(m map[string]any, keys ...string) any {
	var v any = m
	for _, k := range keys {
		mm, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = mm[k]
	}
	return v
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
