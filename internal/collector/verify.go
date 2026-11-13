package collector

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/api/equality"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// SanitizeEnginePolicy keeps what identifies and enforces an engine policy:
// apiVersion, kind, name, labels, annotations, and spec. Status, managed
// fields, and other server state are dropped.
func SanitizeEnginePolicy(o assessment.Object) assessment.Object {
	meta := assessment.Map(o["metadata"])
	return assessment.Object{"apiVersion": o["apiVersion"], "kind": o["kind"], "spec": o["spec"],
		"metadata": assessment.Object{"name": meta["name"], "labels": meta["labels"], "annotations": meta["annotations"]}}
}

// VerifyEnginePolicy checks one engine policy against the policy targeting
// renders for contribution c from the source manifest src: same name (which
// binds binding, policy, and revision), identical spec, and the rendered
// labels and annotations present. This is the comparison delivery uses to
// decide a policy is current, so verified policies are exactly what
// Konstapel would deliver from the pinned content.
func VerifyEnginePolicy(policy assessment.Object, c targeting.Contribution, src targeting.PolicySource) error {
	want, err := targeting.Render(c, src)
	if err != nil {
		return err
	}
	name := assessment.Str(assessment.At(policy, "metadata", "name"))
	if name != want.GetName() {
		return fmt.Errorf("engine policy %s is not the policy rendered for revision %s (%s)", name, c.Revision, want.GetName())
	}
	if !equality.Semantic.DeepEqual(policy["spec"], want.Object["spec"]) {
		return fmt.Errorf("engine policy %s spec differs from the render of source %s", name, src.SourceDigest)
	}
	for field, wantMap := range map[string]map[string]string{"labels": want.GetLabels(), "annotations": want.GetAnnotations()} {
		have := assessment.Map(assessment.At(policy, "metadata", field))
		for k, v := range wantMap {
			if assessment.Str(have[k]) != v {
				return fmt.Errorf("engine policy %s %s[%s] is %q, want %q", name, field, k, assessment.Str(have[k]), v)
			}
		}
	}
	return nil
}

// VerifyEnginePolicies checks every subject's captured engine policy against
// its contribution and the source manifest named by the subject's source
// digest, and that the captured checks were enumerated from that policy. A
// capture whose policy expressions or digests changed cannot pass by
// recomputing its own hashes: the render is anchored to the source content.
func VerifyEnginePolicies(c CaptureV2, sources map[string]targeting.PolicySource) error {
	policies := map[string]assessment.Object{}
	for _, p := range c.EnginePolicies {
		policies[assessment.Str(assessment.At(p, "metadata", "name"))] = p
	}
	checks := map[string][]Check{}
	for _, k := range c.Checks {
		checks[k.EnginePolicy] = append(checks[k.EnginePolicy], k)
	}
	var errs []error
	done := map[string]bool{}
	for _, s := range c.Subjects {
		if done[s.EnginePolicy] {
			continue
		}
		done[s.EnginePolicy] = true
		p, ok := policies[s.EnginePolicy]
		if !ok {
			errs = append(errs, fmt.Errorf("engine policy %s was not captured", s.EnginePolicy))
			continue
		}
		i := slices.IndexFunc(c.Contributions, func(x targeting.Contribution) bool {
			return x.Binding.UID == s.BindingUID && x.Policy == s.LogicalPolicy && x.Revision == s.Revision
		})
		if i < 0 {
			errs = append(errs, fmt.Errorf("no contribution recorded for %s", s.EnginePolicy))
			continue
		}
		src, ok := sources[s.SourceDigest]
		if !ok {
			errs = append(errs, fmt.Errorf("source %s for %s is not in the verified content", s.SourceDigest, s.EnginePolicy))
			continue
		}
		if err := VerifyEnginePolicy(p, c.Contributions[i], src); err != nil {
			errs = append(errs, err)
			continue
		}
		want, err := PolicyChecks(p, s.Checks)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !slices.Equal(want, checks[s.EnginePolicy]) {
			errs = append(errs, fmt.Errorf("checks recorded for %s do not match its policy", s.EnginePolicy))
		}
	}
	return errors.Join(errs...)
}

// PackageSources verifies a package's content tree and returns its policy
// sources by digest. content/SHA256SUMS must hash to every contribution's
// bundle digest and every listed file must match its sum, so the content
// cannot be edited without changing the pinned bundle identity.
//
// A package of a run with a content set carries one directory per member
// under bundles/<hex of the manifest digest>/ instead: an OCI member's
// frozen bundle (bundle.ReadFrozen: the manifest must hash to the directory's
// digest, and the layer it names must unpack to exactly the packaged
// content/ files), or the vendored member's content/ tree, whose SHA256SUMS
// must hash to the directory's digest. Every subject and contribution must
// name a packaged member, and every member must be named by one (or be the
// only member of a capture that assesses nothing: the desired bundle its
// plan names).
func PackageSources(dir string, c CaptureV2) (map[string]targeting.PolicySource, error) {
	if _, err := os.Lstat(filepath.Join(dir, bundlesDir)); err == nil {
		return memberSources(dir, c)
	}
	wanted := map[string]bool{}
	for _, s := range c.Subjects {
		wanted[strings.TrimPrefix(s.SourceDigest, "sha256:")] = true
	}
	digest, sources, err := vendoredSources(dir, wanted)
	if err != nil {
		return nil, err
	}
	for _, x := range c.Contributions {
		if x.BundleDigest != digest {
			return nil, fmt.Errorf("packaged content %s is not bundle %s of %s", digest, x.BundleDigest, x.Policy)
		}
	}
	return sources, nil
}

// vendoredSources verifies the content/ tree under base by its
// SHA256SUMS, returns that file's digest, and the wanted sources (hex sums).
func vendoredSources(base string, wanted map[string]bool) (string, map[string]targeting.PolicySource, error) {
	sums, err := os.ReadFile(filepath.Join(base, "content", "SHA256SUMS"))
	if err != nil {
		return "", nil, err
	}
	h := sha256.Sum256(sums)
	digest := "sha256:" + hex.EncodeToString(h[:])
	sources := map[string]targeting.PolicySource{}
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		sum, path, ok := strings.Cut(sc.Text(), "  ")
		if !ok {
			return "", nil, fmt.Errorf("malformed SHA256SUMS line %q", sc.Text())
		}
		if filepath.IsAbs(path) || strings.Contains(path, "..") {
			return "", nil, fmt.Errorf("unsafe content path %q", path)
		}
		b, err := os.ReadFile(filepath.Join(base, filepath.FromSlash(path)))
		if err != nil {
			return "", nil, err
		}
		fh := sha256.Sum256(b)
		if hex.EncodeToString(fh[:]) != sum {
			return "", nil, fmt.Errorf("%s does not match SHA256SUMS", path)
		}
		if wanted[sum] {
			var m map[string]any
			if err := yaml.Unmarshal(b, &m); err != nil {
				return "", nil, fmt.Errorf("%s: %w", path, err)
			}
			sources["sha256:"+sum] = targeting.PolicySource{Manifest: m, SourceDigest: "sha256:" + sum}
		}
	}
	return digest, sources, nil
}

// packagedMember is one verified member directory of a package.
type packagedMember struct {
	digest string
	// frozen is nil for the vendored member.
	frozen *bundle.Frozen
}

// packagedMembers verifies every directory under bundles/ and returns them
// by manifest digest, with the policy sources wanted (by "sha256:" digest).
func packagedMembers(dir string, wanted map[string]bool) (map[string]packagedMember, map[string]targeting.PolicySource, error) {
	entries, err := os.ReadDir(filepath.Join(dir, bundlesDir))
	if err != nil {
		return nil, nil, err
	}
	members := map[string]packagedMember{}
	sources := map[string]targeting.PolicySource{}
	for _, e := range entries {
		digest := "sha256:" + e.Name()
		base := filepath.Join(dir, bundlesDir, e.Name())
		if !e.IsDir() || publication.ContentPath(digest) != bundlesDir+"/"+e.Name() || len(e.Name()) != 64 {
			return nil, nil, fmt.Errorf("unexpected package entry %s/%s", bundlesDir, e.Name())
		}
		if _, err := os.Lstat(filepath.Join(base, bundle.FrozenDir)); err != nil {
			hexWanted := map[string]bool{}
			for d := range wanted {
				hexWanted[strings.TrimPrefix(d, "sha256:")] = true
			}
			got, src, err := vendoredSources(base, hexWanted)
			if err != nil {
				return nil, nil, fmt.Errorf("%s/%s: %w", bundlesDir, e.Name(), err)
			}
			if got != digest {
				return nil, nil, fmt.Errorf("%s/%s: packaged content is %s", bundlesDir, e.Name(), got)
			}
			maps.Copy(sources, src)
			members[digest] = packagedMember{digest: digest}
			continue
		}
		f, err := bundle.ReadFrozen(base)
		if err != nil {
			return nil, nil, fmt.Errorf("%s/%s: %w", bundlesDir, e.Name(), err)
		}
		if f.Identity.Digests.OCI != digest {
			return nil, nil, fmt.Errorf("%s/%s holds bundle %s", bundlesDir, e.Name(), f.Identity.Digests.OCI)
		}
		for _, p := range f.Descriptor.Policies {
			file, ok := f.Payload[p.Path]
			if !ok {
				return nil, nil, fmt.Errorf("frozen bundle policy %s is missing", p.Path)
			}
			h := sha256.Sum256(file.Data)
			sd := "sha256:" + hex.EncodeToString(h[:])
			if !wanted[sd] {
				continue
			}
			m, err := targeting.ParsePolicyManifest(file.Data)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", p.Path, err)
			}
			sources[sd] = targeting.PolicySource{Manifest: m, SourceDigest: sd}
		}
		members[digest] = packagedMember{digest: digest, frozen: f}
	}
	return members, sources, nil
}

// memberSources is PackageSources for a package with a content set.
func memberSources(dir string, c CaptureV2) (map[string]targeting.PolicySource, error) {
	wanted := map[string]bool{}
	for _, s := range c.Subjects {
		wanted[s.SourceDigest] = true
	}
	members, sources, err := packagedMembers(dir, wanted)
	if err != nil {
		return nil, err
	}
	named := map[string]bool{}
	check := func(what, name, digest string) error {
		m, ok := members[digest]
		if !ok || (m.frozen != nil && m.frozen.Identity.Name != name) {
			return contentFailure(ReasonContentMismatch, "%s references %s@%s, which the package does not carry", what, name, digest)
		}
		named[digest] = true
		return nil
	}
	for _, s := range c.Subjects {
		if err := check("subject "+s.EnginePolicy, s.BundleName, s.BundleDigest); err != nil {
			return nil, err
		}
	}
	for _, x := range c.Contributions {
		if err := check("contribution "+x.Policy, x.BundleName, x.BundleDigest); err != nil {
			return nil, err
		}
	}
	for d := range members {
		if !named[d] && (len(named) > 0 || len(members) > 1) {
			return nil, contentFailure(ReasonContentMismatch, "the package carries %s, which the capture does not assess", d)
		}
	}
	return sources, nil
}

// VerifyContent checks a package's members against its descriptor's
// content record: exactly the packaged (Frozen) entries are present under
// their paths, and each OCI member's frozen identity is the one recorded.
// A package without a content record carries no members.
func VerifyContent(dir string, rc *publication.RunContent) error {
	members, _, err := func() (map[string]packagedMember, map[string]targeting.PolicySource, error) {
		if _, err := os.Lstat(filepath.Join(dir, bundlesDir)); err != nil {
			return map[string]packagedMember{}, nil, nil
		}
		return packagedMembers(dir, nil)
	}()
	if err != nil {
		return err
	}
	if rc == nil {
		if len(members) > 0 {
			return errors.New("the package carries bundle content its descriptor does not record")
		}
		return nil
	}
	recorded := slices.Clone(rc.Applied)
	if rc.Desired != nil && rc.Desired.Frozen {
		recorded = append(recorded, *rc.Desired)
	}
	seen := map[string]bool{}
	for _, r := range recorded {
		if !r.Frozen {
			continue
		}
		seen[r.ManifestDigest] = true
		m, ok := members[r.ManifestDigest]
		switch {
		case !ok:
			return fmt.Errorf("recorded content %s@%s is not packaged at %s", r.Bundle, r.ManifestDigest, r.Path)
		case r.Vendored != (m.frozen == nil):
			return fmt.Errorf("recorded content %s@%s is packaged as the wrong kind", r.Bundle, r.ManifestDigest)
		case m.frozen != nil:
			id := m.frozen.Identity
			if id.Name != r.Bundle || id.Version != r.Version || id.Digests.Content != r.ContentDigest || id.Digests.Archive != r.ArchiveDigest ||
				id.Digests.Revision != r.SourceRevision || id.Receipt.SourceRule != r.SourceRule || id.Receipt.TrustRevision != r.TrustRevision {
				return fmt.Errorf("the packaged identity of %s@%s differs from the descriptor's", r.Bundle, r.ManifestDigest)
			}
		}
	}
	for d := range members {
		if !seen[d] {
			return fmt.Errorf("the package carries %s, which its descriptor does not record", d)
		}
	}
	return nil
}

// VerifyPackage re-verifies an assessment package's engine policies from its
// own content: the capture's policies and checks must re-render from the
// packaged, digest-pinned sources.
func VerifyPackage(dir string) error {
	var c CaptureV2
	if err := assessment.Read(filepath.Join(dir, "capture.json"), &c); err != nil {
		return err
	}
	sources, err := PackageSources(dir, c)
	if err != nil {
		return err
	}
	return VerifyEnginePolicies(c, sources)
}

// SourcesOf indexes verified content by source digest for VerifyEnginePolicies.
func SourcesOf(contents ...*targeting.Content) map[string]targeting.PolicySource {
	out := map[string]targeting.PolicySource{}
	for _, c := range contents {
		if c == nil {
			continue
		}
		for _, s := range c.Policies {
			out[s.SourceDigest] = s
		}
	}
	return out
}
