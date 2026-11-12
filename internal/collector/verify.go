package collector

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/api/equality"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
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
// A package of an OCI bundle run carries its frozen bundle instead
// (bundle/): the manifest must hash to every subject's and contribution's
// bundle digest, and the layer it names must unpack to exactly the packaged
// content/ files (bundle.ReadFrozen).
func PackageSources(dir string, c CaptureV2) (map[string]targeting.PolicySource, error) {
	if _, err := os.Lstat(filepath.Join(dir, bundle.FrozenDir)); err == nil {
		return frozenSources(dir, c)
	}
	sums, err := os.ReadFile(filepath.Join(dir, "content", "SHA256SUMS"))
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(sums)
	digest := "sha256:" + hex.EncodeToString(h[:])
	for _, x := range c.Contributions {
		if x.BundleDigest != digest {
			return nil, fmt.Errorf("packaged content %s is not bundle %s of %s", digest, x.BundleDigest, x.Policy)
		}
	}
	wanted := map[string]bool{}
	for _, s := range c.Subjects {
		wanted[strings.TrimPrefix(s.SourceDigest, "sha256:")] = true
	}
	sources := map[string]targeting.PolicySource{}
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		sum, path, ok := strings.Cut(sc.Text(), "  ")
		if !ok {
			return nil, fmt.Errorf("malformed SHA256SUMS line %q", sc.Text())
		}
		if filepath.IsAbs(path) || strings.Contains(path, "..") {
			return nil, fmt.Errorf("unsafe content path %q", path)
		}
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path)))
		if err != nil {
			return nil, err
		}
		fh := sha256.Sum256(b)
		if hex.EncodeToString(fh[:]) != sum {
			return nil, fmt.Errorf("%s does not match SHA256SUMS", path)
		}
		if wanted[sum] {
			var m map[string]any
			if err := yaml.Unmarshal(b, &m); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			sources["sha256:"+sum] = targeting.PolicySource{Manifest: m, SourceDigest: "sha256:" + sum}
		}
	}
	return sources, nil
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

// frozenSources is PackageSources for a package with a frozen bundle.
func frozenSources(dir string, c CaptureV2) (map[string]targeting.PolicySource, error) {
	f, err := bundle.ReadFrozen(dir)
	if err != nil {
		return nil, err
	}
	id := f.Identity
	if err := captureUses(c, id.Name, id.Digests.OCI); err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, s := range c.Subjects {
		wanted[s.SourceDigest] = true
	}
	sources := map[string]targeting.PolicySource{}
	for _, p := range f.Descriptor.Policies {
		file, ok := f.Payload[p.Path]
		if !ok {
			return nil, fmt.Errorf("frozen bundle policy %s is missing", p.Path)
		}
		h := sha256.Sum256(file.Data)
		digest := "sha256:" + hex.EncodeToString(h[:])
		if !wanted[digest] {
			continue
		}
		m, err := targeting.ParsePolicyManifest(file.Data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p.Path, err)
		}
		sources[digest] = targeting.PolicySource{Manifest: m, SourceDigest: digest}
	}
	return sources, nil
}
