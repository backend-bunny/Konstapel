package content

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/internal/provfixture"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/resolve"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// localContent serves the repository's vendored copy of the same policy.
func localContent(t *testing.T) (targeting.LocalContent, *targeting.Content) {
	t.Helper()
	lc := targeting.LocalContent{Root: filepath.Join(repoRoot, "content"), Name: "konstapel-vendored",
		Policies: map[string]string{assessment.PolicyName: assessment.SourcePolicy}}
	sums, err := os.ReadFile(filepath.Join(repoRoot, "content", "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := lc.Content(context.Background(), v1alpha1.BundleReference{Name: lc.Name, Digest: "sha256:" + hexSum(sums)})
	if err != nil {
		t.Fatal(err)
	}
	return lc, c
}

// TestOfficialMatchesLocalContent: the signed official bundle, served from
// the registry through the cache, yields exactly what LocalContent yields
// for the vendored copy of the same policy file.
func TestOfficialMatchesLocalContent(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	oc := w.mustContent()
	_, lc := localContent(t)

	if oc.Bundle.Name != provfixture.Name || oc.Bundle.Digest != w.f.Subject {
		t.Fatalf("bundle %s@%s, want the pinned name and OCI manifest digest %s", oc.Bundle.Name, oc.Bundle.Digest, w.f.Subject)
	}
	if !reflect.DeepEqual(oc.Bundle.Policies, lc.Bundle.Policies) {
		t.Fatalf("policies %+v, LocalContent %+v", oc.Bundle.Policies, lc.Bundle.Policies)
	}
	if got := slices.Sorted(maps.Keys(oc.Policies)); !slices.Equal(got, []string{assessment.PolicyName}) {
		t.Fatalf("policy sources %v", got)
	}
	o, l := oc.Policies[assessment.PolicyName], lc.Policies[assessment.PolicyName]
	if !reflect.DeepEqual(o.Manifest, l.Manifest) {
		t.Fatal("parsed manifests differ")
	}
	if o.SourceDigest != l.SourceDigest || !strings.HasPrefix(o.SourceDigest, "sha256:") {
		t.Fatalf("source digest %s, LocalContent %s", o.SourceDigest, l.SourceDigest)
	}
	if oc.Bundle.Policies[0].Scope != targeting.ScopeNamespaced {
		t.Fatalf("scope %s", oc.Bundle.Policies[0].Scope)
	}
	// Only OCI content declares a parameter contract; the official policy
	// has no schema, and neither source makes parameters renderable.
	if !o.ParametersValidated || o.ParameterSchema != nil || l.ParametersValidated || l.ParameterSchema != nil {
		t.Fatalf("parameter contract: oci %v/%v, local %v/%v", o.ParametersValidated, o.ParameterSchema, l.ParametersValidated, l.ParameterSchema)
	}
	if oc.Bundle.Policies[0].Parameters {
		t.Fatal("OCI content claims to render parameters")
	}
}

// The result is a deep copy: mutating it changes nothing that a later call
// returns, and no cache path appears in it.
func TestContentIsACopy(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c := w.mustContent()
	c.Policies[assessment.PolicyName].Manifest["kind"] = "Mutated"
	c.Bundle.Policies[0].Name = "mutated"
	again := w.mustContent()
	if again.Policies[assessment.PolicyName].Manifest["kind"] != "ValidatingPolicy" || again.Bundle.Policies[0].Name != assessment.PolicyName {
		t.Fatal("a returned Content aliases another call's result")
	}
	raw, _ := json.Marshal(again)
	if strings.Contains(string(raw), w.dir) {
		t.Fatal("content references the cache directory")
	}
}

// --- targeting integration --------------------------------------------------

const cluster = "kube-system:cluster-uid"

func profile(name string, ref v1alpha1.BundleReference, pols ...v1alpha1.ProfilePolicy) v1alpha1.ComplianceProfile {
	return v1alpha1.ComplianceProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name + "-uid"), Generation: 3},
		Spec:       v1alpha1.ComplianceProfileSpec{Bundle: ref, Policies: pols},
	}
}

func binding(name, prof string) v1alpha1.ComplianceBinding {
	return v1alpha1.ComplianceBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name + "-uid"), Generation: 2},
		Spec: v1alpha1.ComplianceBindingSpec{ProfileRef: v1alpha1.ProfileReference{Name: prof}, Mode: v1alpha1.ModeDeny,
			NamespaceSelector: &v1alpha1.NamespaceSelector{MatchLabels: map[string]v1alpha1.LabelValue{"team": "a"}}, EnforcementEpoch: 4},
	}
}

var selfService = v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: 72 * time.Hour}}

// run resolves one binding over one profile against content, rendering
// every contribution from content.
func run(t *testing.T, c *targeting.Content, pols ...v1alpha1.ProfilePolicy) (targeting.BindingResult, []map[string]any) {
	t.Helper()
	ref := v1alpha1.BundleReference{Name: c.Bundle.Name, Digest: c.Bundle.Digest}
	res := targeting.Resolve(targeting.Input{
		Cluster:    cluster,
		Bundles:    []targeting.Bundle{c.Bundle},
		Profiles:   []v1alpha1.ComplianceProfile{profile("p", ref, pols...)},
		Bindings:   []v1alpha1.ComplianceBinding{binding("b", "p")},
		Namespaces: []targeting.Namespace{{Name: "ns1", UID: "ns1-uid", Labels: map[string]string{"team": "a"}}},
	})
	if len(res.Bindings) != 1 {
		t.Fatalf("%d binding results", len(res.Bindings))
	}
	br := res.Bindings[0]
	var rendered []map[string]any
	for _, ctr := range br.Contributions {
		obj, err := targeting.Render(ctr, c.Policies[ctr.Policy])
		if err != nil {
			t.Fatal(err)
		}
		rendered = append(rendered, obj.Object)
	}
	return br, rendered
}

// TestTargetingPath feeds OCI content through the existing resolver and
// renderer: governance (names derived from the revision, owner labels and
// references, exception settings, mode, selector, untouched rules) is the
// same as for LocalContent; only the bundle identity differs, and the
// revision input is the OCI manifest digest.
func TestTargetingPath(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	oc := w.mustContent()
	_, lc := localContent(t)
	pol := v1alpha1.ProfilePolicy{Name: assessment.PolicyName, Exceptions: selfService}

	ob, orend := run(t, oc, pol)
	lb, lrend := run(t, lc, pol)
	if len(ob.Errors) != 0 || len(lb.Errors) != 0 || len(ob.Contributions) != 1 || len(lb.Contributions) != 1 {
		t.Fatalf("oci %+v, local %+v", ob, lb)
	}
	octr, lctr := ob.Contributions[0], lb.Contributions[0]
	if octr.BundleDigest != w.f.Subject || octr.BundleName != provfixture.Name {
		t.Fatalf("contribution bundle %s@%s", octr.BundleName, octr.BundleDigest)
	}
	want := targeting.EnforcementRevision(targeting.EnforcementInput{Cluster: cluster, BindingUID: "b-uid", BindingEpoch: 4,
		ProfileUID: "p-uid", ProfileGeneration: 3, Policy: assessment.PolicyName, BundleDigest: w.f.Subject,
		ConfigurationDigest: octr.ConfigurationDigest, Mode: v1alpha1.ModeDeny, NamespaceSelector: octr.NamespaceSelector})
	if octr.Revision != want {
		t.Fatalf("revision %s, want %s from the manifest digest", octr.Revision, want)
	}
	// Governance is identical apart from the bundle identity.
	strip := func(c targeting.Contribution) targeting.Contribution {
		c.BundleName, c.BundleDigest, c.Revision = "", "", ""
		return c
	}
	if !reflect.DeepEqual(strip(octr), strip(lctr)) {
		t.Fatalf("contributions differ beyond bundle identity:\n%+v\n%+v", octr, lctr)
	}
	if octr.Exceptions.Eligibility != v1alpha1.ExceptionsSelfService || octr.Exceptions.MaxLifetime.Duration != 72*time.Hour {
		t.Fatalf("exceptions %+v", octr.Exceptions)
	}
	o, l := orend[0], lrend[0]
	om, lm := o["metadata"].(map[string]any), l["metadata"].(map[string]any)
	if om["name"] != targeting.PolicyName(octr) || lm["name"] != targeting.PolicyName(lctr) {
		t.Fatal("rendered names are not derived from the revision")
	}
	if !reflect.DeepEqual(om["labels"], lm["labels"]) || !reflect.DeepEqual(om["ownerReferences"], lm["ownerReferences"]) || !reflect.DeepEqual(o["spec"], l["spec"]) {
		t.Fatal("rendered labels, owner or spec differ from LocalContent")
	}
	oa, la := om["annotations"].(map[string]any), lm["annotations"].(map[string]any)
	for k := range la {
		switch k {
		case targeting.AnnotationRevision, targeting.AnnotationBundle, targeting.AnnotationBundleDigest:
			continue
		}
		if !reflect.DeepEqual(oa[k], la[k]) {
			t.Fatalf("annotation %s: %v vs %v", k, oa[k], la[k])
		}
	}
	if oa[targeting.AnnotationBundleDigest] != w.f.Subject || oa[targeting.AnnotationSourceDigest] != la[targeting.AnnotationSourceDigest] {
		t.Fatal("rendered digests")
	}

	t.Run("mirror and credentials do not change the revision", func(t *testing.T) {
		// Point the source at a mirror, drop every acceptance and the
		// cache (so the content is fetched again from the mirror).
		w.revs.edit(func(r *revs) {
			s := r.src[provfixture.Name]
			s.Repository = "mirror.example.test/konstapel/konstapel-privileged-containers"
			s.CredentialSecret = &bundle.ObjectRef{Kind: bundle.KindSecret, Name: "pull-rotated"}
			r.src[provfixture.Name] = s
		})
		w.acc.InvalidateAll()
		w.cache.Close()
		if err := os.RemoveAll(w.dir); err != nil {
			t.Fatal(err)
		}
		w.open()
		mirrored := w.mustContent()
		w.fetch.mu.Lock()
		last := w.fetch.repos[len(w.fetch.repos)-1]
		w.fetch.mu.Unlock()
		if !strings.HasPrefix(last, "mirror.") {
			t.Fatalf("fetched from %s", last)
		}
		mb, _ := run(t, mirrored, pol)
		if mb.Contributions[0].Revision != octr.Revision || mirrored.Bundle.Digest != oc.Bundle.Digest {
			t.Fatal("a mirror or credential change changed the revision")
		}
	})

	t.Run("a new manifest digest advances the revision", func(t *testing.T) {
		a1, a2 := build(t, crafted{version: "0.1.1"}), build(t, crafted{version: "0.1.2"})
		cw := newCraftedWorld(t, nil, a1, a2)
		c1, err := cw.oci.Content(context.Background(), refOf(a1))
		if err != nil {
			t.Fatal(err)
		}
		c2, err := cw.oci.Content(context.Background(), refOf(a2))
		if err != nil {
			t.Fatal(err)
		}
		b1, _ := run(t, c1, pol)
		b2, _ := run(t, c2, pol)
		r1, r2 := b1.Contributions[0], b2.Contributions[0]
		if c1.Policies[pol.Name].SourceDigest != c2.Policies[pol.Name].SourceDigest {
			t.Fatal("same policy file, different source digest")
		}
		if r1.Revision == r2.Revision || targeting.PolicyName(r1) == targeting.PolicyName(r2) || r1.Revision == octr.Revision {
			t.Fatal("a different manifest digest did not advance the revision and name")
		}
		noLeases(t, cw.cache)
	})
}

// --- per-policy scope, unknown policies, fixtures ---------------------------

const policyTemplate = `apiVersion: %s
kind: %s
metadata:
  name: %s
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: [%q]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: [%q]
  validations:
    - expression: "true"
`

func policyYAML(apiVersion, kind, name, group, resource string) string {
	return fmt.Sprintf(policyTemplate, apiVersion, kind, name, group, resource)
}

func pol(name, path string) bundle.Policy {
	return bundle.Policy{Name: name, Path: path, Checks: []bundle.Check{{RuleID: name, CheckID: name}}}
}

// scopeBundle has the official policy plus one policy per unsupported
// shape, test fixtures that look like policies, and a policy-role file no
// policy entry names.
func scopeBundle(t *testing.T) *bundle.Archive {
	return build(t, crafted{
		version: "0.2.0",
		policies: []bundle.Policy{
			pol("cluster-scoped", "content/policies/cluster-scoped.yaml"),
			pol("unknown-resource", "content/policies/unknown-resource.yaml"),
			pol("not-validating", "content/policies/not-validating.yaml"),
			pol("another-namespaced", "content/policies/another-namespaced.yaml"),
		},
		files: map[string]string{
			"content/policies/cluster-scoped.yaml":     policyYAML("policies.kyverno.io/v1", "ValidatingPolicy", "cluster-scoped", "", "namespaces"),
			"content/policies/unknown-resource.yaml":   policyYAML("policies.kyverno.io/v1", "ValidatingPolicy", "unknown-resource", "example.com", "widgets"),
			"content/policies/not-validating.yaml":     policyYAML("kyverno.io/v1", "ClusterPolicy", "not-validating", "", "pods"),
			"content/policies/another-namespaced.yaml": policyYAML("policies.kyverno.io/v1", "ValidatingPolicy", "another-namespaced", "apps", "deployments"),
			"content/policies/dangling.yaml":           policyYAML("policies.kyverno.io/v1", "ValidatingPolicy", "dangling", "", "pods"),
			"tests/fixture-policy.yaml":                policyYAML("policies.kyverno.io/v1", "ValidatingPolicy", "fixture-policy", "", "pods"),
			"tests/fixture-pod.yaml":                   "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\n",
		},
		roles: map[string]string{
			"content/policies/cluster-scoped.yaml": bundle.RolePolicy, "content/policies/unknown-resource.yaml": bundle.RolePolicy,
			"content/policies/not-validating.yaml": bundle.RolePolicy, "content/policies/another-namespaced.yaml": bundle.RolePolicy,
			"content/policies/dangling.yaml": bundle.RolePolicy,
			"tests/fixture-policy.yaml":      bundle.RoleTest, "tests/fixture-pod.yaml": bundle.RoleTest,
		},
	})
}

func TestPolicyScopes(t *testing.T) {
	t.Parallel()
	a := scopeBundle(t)
	cw := newCraftedWorld(t, nil, a)
	c, err := cw.oci.Content(context.Background(), refOf(a))
	if err != nil {
		t.Fatal(err)
	}
	noLeases(t, cw.cache)
	scopes := map[string]targeting.PolicyScope{}
	for _, bp := range c.Bundle.Policies {
		scopes[bp.Name] = bp.Scope
	}
	want := map[string]targeting.PolicyScope{
		assessment.PolicyName: targeting.ScopeNamespaced,
		"another-namespaced":  targeting.ScopeNamespaced,
		"cluster-scoped":      targeting.ScopeCluster,
		"unknown-resource":    targeting.ScopeCluster,
		"not-validating":      targeting.ScopeUnsupported,
	}
	if !reflect.DeepEqual(scopes, want) {
		t.Fatalf("scopes %v, want %v", scopes, want)
	}
	// The same classification as targeting.PolicyScopeOf with the default
	// scope function, policy by policy.
	for name, src := range c.Policies {
		s, err := targeting.PolicyScopeOf(src.Manifest, targeting.StandardWorkloadScopes)
		if err != nil {
			s = targeting.ScopeUnsupported
		}
		if s != scopes[name] {
			t.Fatalf("%s: %s, PolicyScopeOf says %s", name, scopes[name], s)
		}
	}

	t.Run("fixtures and unnamed files are never policies", func(t *testing.T) {
		if got := slices.Sorted(maps.Keys(c.Policies)); !slices.Equal(got, slices.Sorted(maps.Keys(want))) {
			t.Fatalf("policy sources %v", got)
		}
		for name, src := range c.Policies {
			if n, _ := src.Manifest["metadata"].(map[string]any)["name"].(string); n == "dangling" || n == "fixture-policy" || n == "bad" {
				t.Fatalf("%s is served from %s", name, n)
			}
		}
	})

	t.Run("resolver reports per policy, renders only supported policies", func(t *testing.T) {
		pols := []v1alpha1.ProfilePolicy{{Name: assessment.PolicyName}, {Name: "another-namespaced"}, {Name: "cluster-scoped"},
			{Name: "unknown-resource"}, {Name: "not-validating"}, {Name: "no-such-policy"}, {Name: "dangling"}, {Name: "fixture-policy"}}
		br, rendered := run(t, c, pols...)
		got := map[string]string{}
		for _, e := range br.Errors {
			got[e.Policy] = string(e.Reason)
		}
		wantErrs := map[string]string{
			"cluster-scoped": v1alpha1.ReasonUnsupportedScope, "unknown-resource": v1alpha1.ReasonUnsupportedScope,
			"not-validating": v1alpha1.ReasonUnsupportedScope, "no-such-policy": v1alpha1.ReasonUnknownPolicy,
			"dangling": v1alpha1.ReasonUnknownPolicy, "fixture-policy": v1alpha1.ReasonUnknownPolicy,
		}
		if !reflect.DeepEqual(got, wantErrs) {
			t.Fatalf("errors %v, want %v", got, wantErrs)
		}
		if len(rendered) != 2 {
			t.Fatalf("%d rendered policies, want the 2 supported ones", len(rendered))
		}
		for _, obj := range rendered {
			if obj["kind"] != "ValidatingPolicy" {
				t.Fatalf("rendered %v", obj["kind"])
			}
		}
	})
}

// The official signed bundle carries upstream Kyverno and Chainsaw test
// fixtures (Pods, a PolicyException, RBAC); none is served as a policy.
func TestOfficialFixturesAreData(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	c := w.mustContent()
	entry, err := w.cache.Get(context.Background(), w.f.Subject)
	if err != nil {
		t.Fatal(err)
	}
	tests := 0
	for _, f := range entry.Descriptor.Files {
		if f.Role == bundle.RoleTest {
			tests++
		}
	}
	if tests == 0 {
		t.Fatal("the official bundle has no test fixtures; this test proves nothing")
	}
	if len(c.Policies) != len(entry.Descriptor.Policies) || len(c.Bundle.Policies) != len(entry.Descriptor.Policies) {
		t.Fatalf("%d sources for %d declared policies", len(c.Policies), len(entry.Descriptor.Policies))
	}
	for _, src := range c.Policies {
		if src.Manifest["kind"] != "ValidatingPolicy" {
			t.Fatalf("served a %v", src.Manifest["kind"])
		}
	}
}

// A policy path whose inventory role is not "policy" is refused, even when
// the descriptor names it (defense in depth: descriptor validation already
// rejects it).
func TestPolicyMustHavePolicyRole(t *testing.T) {
	t.Parallel()
	a := build(t, crafted{version: "0.2.1"})
	cw := newCraftedWorld(t, nil, a)
	e, err := cw.cache.Get(context.Background(), a.ManifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	for i := range e.Descriptor.Files {
		if e.Descriptor.Files[i].Path == assessment.SourcePolicy {
			e.Descriptor.Files[i].Role = bundle.RoleTest
		}
	}
	_, err = cw.oci.read(refOf(a), e)
	wantClass(t, err, targeting.ContentErrorMalformed)
}

// --- compatibility ----------------------------------------------------------

func officialDescriptor(t *testing.T) *bundle.Descriptor {
	t.Helper()
	d, _, err := bundle.Unpack(fixtures(t).Layer)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestCompatibilityCheck(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		compat Compatibility
		edit   func(d *bundle.Descriptor)
		reason string // substring of the single reason; "" means compatible
	}{
		"official":                 {Compatibility{Controller: "0.1.0"}, nil, ""},
		"newer controller":         {Compatibility{Controller: "1.4.2"}, nil, ""},
		"build metadata ignored":   {Compatibility{Controller: "0.1.0+abc"}, nil, ""},
		"controller too old":       {Compatibility{Controller: "0.0.9"}, nil, "requires Konstapel 0.1.0 or later"},
		"pre-release is older":     {Compatibility{Controller: "0.1.0-rc.1"}, nil, "requires Konstapel 0.1.0 or later"},
		"pre-release satisfies":    {Compatibility{Controller: "0.2.0-rc.1"}, nil, ""},
		"pre-release ordering":     {Compatibility{Controller: "0.2.0-rc.2"}, func(d *bundle.Descriptor) { d.Compatibility.Konstapel = "0.2.0-rc.10" }, "requires Konstapel 0.2.0-rc.10"},
		"provider not allowlisted": {Compatibility{Controller: "0.1.0"}, func(d *bundle.Descriptor) { d.Compatibility.Provider = "evil-exec/v1" }, `provider contract "evil-exec/v1" is not installed`},
		"provider version":         {Compatibility{Controller: "0.1.0"}, func(d *bundle.Descriptor) { d.Compatibility.Provider = "konstapel-kyverno/v2" }, "is not installed"},
		"allowlist excludes":       {Compatibility{Controller: "0.1.0", Providers: []string{"other/v1"}}, nil, "is not installed"},
		"unknown OSCAL":            {Compatibility{Controller: "0.1.0"}, func(d *bundle.Descriptor) { d.OSCAL[0].Version = "1.0.0" }, "OSCAL version 1.0.0 is not supported"},
		"windows only":             {Compatibility{Controller: "0.1.0"}, func(d *bundle.Descriptor) { d.Scope.OS = []string{"windows"} }, "only linux"},
		"linux and windows":        {Compatibility{Controller: "0.1.0"}, func(d *bundle.Descriptor) { d.Scope.OS = []string{"linux", "windows"} }, "only linux"},
		"invalid controller":       {Compatibility{Controller: "dev"}, nil, "not SemVer"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d := officialDescriptor(t)
			if c.edit != nil {
				c.edit(d)
			}
			v := c.compat.Check(d)
			if c.reason == "" {
				if !v.Compatible || len(v.Reasons) != 0 {
					t.Fatalf("%+v", v)
				}
				if v.Provider != d.Compatibility.Provider || v.Konstapel != d.Compatibility.Konstapel || !slices.Equal(v.OSCAL, []string{"1.1.3", "1.2.3"}) {
					t.Fatalf("%+v", v)
				}
				return
			}
			if v.Compatible || len(v.Reasons) != 1 || !strings.Contains(v.Reasons[0], c.reason) {
				t.Fatalf("%+v, want one reason containing %q", v, c.reason)
			}
		})
	}
}

func TestCompatibilityRevision(t *testing.T) {
	t.Parallel()
	rev := func(c Compatibility) string {
		t.Helper()
		r, err := c.Revision()
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	base := rev(Compatibility{Controller: "0.1.0"})
	if base != rev(Compatibility{Controller: "0.1.0", Providers: []string{DefaultProvider}}) ||
		base != rev(Compatibility{Controller: "0.1.0", Providers: []string{DefaultProvider, DefaultProvider}}) {
		t.Fatal("the default allowlist spelled out changed the revision")
	}
	two := rev(Compatibility{Controller: "0.1.0", Providers: []string{DefaultProvider, "other/v1"}})
	if two != rev(Compatibility{Controller: "0.1.0", Providers: []string{"other/v1", DefaultProvider}}) {
		t.Fatal("allowlist order changed the revision")
	}
	for _, other := range []string{two, rev(Compatibility{Controller: "0.1.1"}), rev(Compatibility{Controller: "0.1.0", Providers: []string{"other/v1"}})} {
		if other == base {
			t.Fatal("an allowlist or controller change kept the revision")
		}
	}
	if _, err := (Compatibility{Controller: "dev"}).Revision(); err == nil {
		t.Fatal("invalid controller version has a revision")
	}
	if _, err := (Compatibility{Controller: "0.1.0", Providers: []string{"/bin/sh"}}).Revision(); err == nil {
		t.Fatal("invalid provider has a revision")
	}
}

// Incompatibility through the real resolver: never adopted, classified, and
// the controller's compatibility change takes effect without a restart.
func TestIncompatibleEndToEnd(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]Compatibility{
		"controller too old":       {Controller: "0.0.9"},
		"provider not allowlisted": {Controller: "0.1.0", Providers: []string{"other-provider/v1"}},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			w.mustContent()
			w.revs.edit(func(r *revs) { r.compat = c })
			_, err := w.content()
			ce := wantClass(t, err, targeting.ContentErrorIncompatible)
			if !errors.Is(err, resolve.ErrIncompatible) || !strings.Contains(ce.Detail, provfixture.Name) {
				t.Fatalf("%v", err)
			}
			noLeases(t, w.cache)
			w.revs.edit(func(r *revs) { r.compat = Compatibility{Controller: "0.1.0"} })
			w.mustContent()
		})
	}
}

// --- parameters -------------------------------------------------------------

func TestParameters(t *testing.T) {
	t.Parallel()
	schema := `{"type":"object","properties":{"maxContainers":{"type":"integer","minimum":1}},"additionalProperties":false}`
	a := build(t, crafted{
		version:  "0.3.0",
		policies: []bundle.Policy{{Name: "with-params", Path: "content/policies/with-params.yaml", ParameterSchema: "content/schemas/with-params.json", Checks: []bundle.Check{{RuleID: "with-params", CheckID: "with-params"}}}},
		files: map[string]string{
			"content/policies/with-params.yaml": policyYAML("policies.kyverno.io/v1", "ValidatingPolicy", "with-params", "", "pods"),
			"content/schemas/with-params.json":  schema,
		},
		roles: map[string]string{"content/policies/with-params.yaml": bundle.RolePolicy, "content/schemas/with-params.json": bundle.RoleSchema},
	})
	cw := newCraftedWorld(t, nil, a)
	c, err := cw.oci.Content(context.Background(), refOf(a))
	if err != nil {
		t.Fatal(err)
	}
	withParams, schemaless := c.Policies["with-params"], c.Policies[assessment.PolicyName]
	if string(withParams.ParameterSchema) != schema || !withParams.ParametersValidated {
		t.Fatalf("schema %q", withParams.ParameterSchema)
	}
	cases := []struct {
		src    targeting.PolicySource
		policy string
		params string
		ok     bool
	}{
		{withParams, "with-params", `{"maxContainers":3}`, true},
		{withParams, "with-params", ``, true},
		{withParams, "with-params", `null`, true},
		{withParams, "with-params", `{"unknown":1}`, false},
		{withParams, "with-params", `{"maxContainers":"3"}`, false},
		{withParams, "with-params", `{"maxContainers":0}`, false},
		{withParams, "with-params", `[1]`, false},
		{withParams, "with-params", `{"maxContainers":1,"maxContainers":2}`, false},
		{schemaless, assessment.PolicyName, `{"x":1}`, false},
		{schemaless, assessment.PolicyName, `{}`, true},
		{schemaless, assessment.PolicyName, ``, true},
	}
	for _, tc := range cases {
		err := ValidateParameters(tc.src, tc.policy, []byte(tc.params))
		if (err == nil) != tc.ok {
			t.Errorf("%s %s: %v, want ok=%v", tc.policy, tc.params, err, tc.ok)
		}
	}
	// The same semantics as bundle.ValidateParameters over the payload.
	e, err := cw.cache.Get(context.Background(), a.ManifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		var m map[string]any
		if json.Unmarshal([]byte(tc.params), &m) != nil || strings.Count(tc.params, "maxContainers") > 1 {
			continue // not an object, or duplicate keys (rejected only by the raw-JSON helper)
		}
		if (bundle.ValidateParameters(e.Descriptor, e.FS(), tc.policy, m) == nil) != tc.ok {
			t.Errorf("bundle.ValidateParameters disagrees on %s %s", tc.policy, tc.params)
		}
	}

	// LocalContent declares no contract: the helper defers to targeting.
	_, lc := localContent(t)
	if err := ValidateParameters(lc.Policies[assessment.PolicyName], assessment.PolicyName, []byte(`{"x":1}`)); err != nil {
		t.Fatal(err)
	}

	// Neither source renders parameters, so the resolver keeps rejecting
	// them for both, valid or not; parameter-free profiles still resolve.
	for _, content := range []*targeting.Content{c, lc} {
		name := content.Bundle.Policies[0].Name
		br, _ := run(t, content, v1alpha1.ProfilePolicy{Name: name, Parameters: &apiextensionsv1.JSON{Raw: []byte(`{"maxContainers":3}`)}})
		if len(br.Errors) != 1 || br.Errors[0].Reason != v1alpha1.ReasonInvalidConfiguration || len(br.Contributions) != 0 {
			t.Fatalf("%s: %+v", content.Bundle.Name, br)
		}
	}
	br, _ := run(t, c, v1alpha1.ProfilePolicy{Name: "with-params"})
	if len(br.Errors) != 0 || len(br.Contributions) != 1 {
		t.Fatalf("%+v", br)
	}
}

// --- recovery ---------------------------------------------------------------

func TestRecovery(t *testing.T) {
	t.Parallel()
	t.Run("offline after restart", func(t *testing.T) {
		w := newWorld(t)
		want := w.mustContent()
		w.restart()
		w.fetch.down.Store(true)
		calls := w.fetch.calls.Load()
		if got := w.mustContent(); !reflect.DeepEqual(got, want) {
			t.Fatal("offline content differs")
		}
		if w.fetch.calls.Load() != calls {
			t.Fatal("offline resolution called the registry")
		}
	})
	t.Run("wiped cache, registry down, then back", func(t *testing.T) {
		w := newWorld(t)
		w.mustContent()
		w.fetch.down.Store(true)
		w.cache.Close()
		if err := os.RemoveAll(w.dir); err != nil {
			t.Fatal(err)
		}
		w.open()
		_, err := w.content()
		wantClass(t, err, targeting.ContentErrorContentUnavailable)
		if !errors.Is(err, resolve.ErrContentUnavailable) {
			t.Fatal(err)
		}
		noLeases(t, w.cache)
		w.fetch.down.Store(false)
		w.mustContent()
	})
	t.Run("key rotated out, then restored", func(t *testing.T) {
		w := newWorld(t)
		w.mustContent()
		w.fetch.down.Store(true)
		orig := w.f.Source()
		w.revs.edit(func(r *revs) {
			s := r.src[provfixture.Name]
			s.Publisher.PublicKey = &bundle.ObjectRef{Kind: bundle.KindSecret, Name: "other"}
			s.Publisher.KeyFingerprint = w.f.FPOther
			r.src[provfixture.Name] = s
		})
		w.acc.InvalidateSource(provfixture.Name)
		_, err := w.content()
		wantClass(t, err, targeting.ContentErrorUntrusted)
		noLeases(t, w.cache)
		w.revs.edit(func(r *revs) { r.src[provfixture.Name] = orig })
		w.acc.InvalidateSource(provfixture.Name)
		w.fetch.down.Store(false)
		w.mustContent()
	})
	t.Run("source removed", func(t *testing.T) {
		w := newWorld(t)
		w.revs.edit(func(r *revs) { delete(r.src, provfixture.Name) })
		_, err := w.content()
		wantClass(t, err, targeting.ContentErrorConfig)
	})
}

// --- errors -----------------------------------------------------------------

func TestClassify(t *testing.T) {
	t.Parallel()
	ref := v1alpha1.BundleReference{Name: "b", Digest: "sha256:" + strings.Repeat("a", 64)}
	cases := map[error]targeting.ContentErrorClass{
		resolve.ErrStale:              targeting.ContentErrorStale,
		resolve.ErrCapacity:           targeting.ContentErrorCapacity,
		resolve.ErrIncompatible:       targeting.ContentErrorIncompatible,
		resolve.ErrUntrusted:          targeting.ContentErrorUntrusted,
		resolve.ErrProofUnavailable:   targeting.ContentErrorProofUnavailable,
		resolve.ErrContentUnavailable: targeting.ContentErrorContentUnavailable,
		resolve.ErrConfig:             targeting.ContentErrorConfig,
		resolve.ErrRequest:            targeting.ContentErrorUnresolved,
		resolve.ErrUnresolved:         targeting.ContentErrorUnresolved,
		// A failed reuse followed by a failed retrieval keeps the reuse class.
		fmt.Errorf("%w; retrieval: %w", resolve.ErrUntrusted, registry.ErrUnavailable): targeting.ContentErrorUntrusted,
	}
	for in, want := range cases {
		ce := classify(ref, fmt.Errorf("wrapped: %w", in))
		if ce == nil || ce.Class != want || !errors.Is(ce, targeting.ErrContentUnavailable) {
			t.Errorf("%v: %+v, want %s", in, ce, want)
		}
	}
	if ce := classify(ref, errors.New("cache is closed")); ce != nil {
		t.Fatalf("a non-resolution error was classified: %v", ce)
	}
}

// Planted credentials in registry error text never reach the error.
func TestErrorsCarryNoSecrets(t *testing.T) {
	t.Parallel()
	const secret = "s3cr3t-token-VALUE"
	w := newEmptyWorld(t)
	w.fetch.mu.Lock()
	w.fetch.failWith = fmt.Errorf("%w: GET https://reader:%s@registry.example.test/v2/: Authorization: Bearer %s", registry.ErrUnauthorized, secret, secret)
	w.fetch.mu.Unlock()
	_, err := w.content()
	ce := wantClass(t, err, targeting.ContentErrorContentUnavailable)
	if strings.Contains(err.Error(), secret) || strings.Contains(fmt.Sprintf("%+v %#v", err, ce), secret) {
		t.Fatalf("secret in %v", err)
	}
	if !strings.Contains(ce.Detail, registry.ErrUnauthorized.Error()) {
		t.Fatalf("detail %q lost the cause class", ce.Detail)
	}
	for e := error(ce); e != nil; e = errors.Unwrap(e) {
		if strings.Contains(e.Error(), secret) {
			t.Fatal("an unwrapped error carries the secret")
		}
	}
	noLeases(t, w.cache)
}

func TestDigestMismatch(t *testing.T) {
	t.Parallel()
	a1, a2 := build(t, crafted{version: "0.4.0"}), build(t, crafted{version: "0.4.1"})
	cw := newCraftedWorld(t, nil, a1, a2)
	cw.r.substitute = a2.ManifestDigest
	_, err := cw.oci.Content(context.Background(), refOf(a1))
	wantClass(t, err, targeting.ContentErrorDigestMismatch)
	noLeases(t, cw.cache)
	cw.r.substitute = ""

	// Another name for the same digest is not served either.
	ref := refOf(a1)
	ref.Name = "other-bundle"
	_, err = cw.oci.Content(context.Background(), ref)
	wantClass(t, err, targeting.ContentErrorDigestMismatch)
	noLeases(t, cw.cache)

	// Through the real resolver: a digest that is not the subject is never
	// substituted.
	w := newWorld(t)
	_, err = w.oci.Content(context.Background(), v1alpha1.BundleReference{Name: provfixture.Name, Digest: a1.ManifestDigest})
	wantClass(t, err, targeting.ContentErrorContentUnavailable)
	_, err = w.oci.Content(context.Background(), v1alpha1.BundleReference{Name: provfixture.Name, Digest: "sha256:abc"})
	wantClass(t, err, targeting.ContentErrorUnresolved)
	noLeases(t, w.cache)
}

func TestTamperedAfterVerification(t *testing.T) {
	t.Parallel()
	a := build(t, crafted{version: "0.5.0"})
	cw := newCraftedWorld(t, nil, a)
	e, err := cw.cache.Get(context.Background(), a.ManifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	for i := range e.Descriptor.Files {
		if e.Descriptor.Files[i].Path == assessment.SourcePolicy {
			e.Descriptor.Files[i].SHA256 = strings.Repeat("0", 64)
		}
	}
	_, err = cw.oci.read(refOf(a), e)
	wantClass(t, err, targeting.ContentErrorContentUnavailable)
}

func TestContextErrorsPropagate(t *testing.T) {
	t.Parallel()
	w := newEmptyWorld(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := w.oci.Content(ctx, w.ref())
	if !errors.Is(err, context.Canceled) || errors.Is(err, targeting.ErrContentUnavailable) {
		t.Fatalf("%v", err)
	}

	// Cancelled while the registry is being contacted: the resolver wraps
	// the failure as unavailable content, but the caller's cancellation wins.
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	w.fetch.mu.Lock()
	w.fetch.failWith = fmt.Errorf("%w: %w", registry.ErrUnavailable, context.Canceled)
	w.fetch.onFetch = cancel
	w.fetch.mu.Unlock()
	_, err = w.oci.Content(ctx, w.ref())
	if !errors.Is(err, context.Canceled) || errors.Is(err, targeting.ErrContentUnavailable) {
		t.Fatalf("%v", err)
	}
	noLeases(t, w.cache)
	w.fetch.mu.Lock()
	w.fetch.failWith, w.fetch.onFetch = nil, nil
	w.fetch.mu.Unlock()

	// A deadline of the registry's own (not the caller's) is an outage.
	w.fetch.mu.Lock()
	w.fetch.failWith = fmt.Errorf("%w: %w", registry.ErrUnavailable, context.DeadlineExceeded)
	w.fetch.mu.Unlock()
	_, err = w.content()
	wantClass(t, err, targeting.ContentErrorContentUnavailable)
	noLeases(t, w.cache)
}

// Errors that are not resolution outcomes are returned unclassified.
func TestInternalErrorsAreNotContentUnavailable(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.mustContent()
	if err := w.cache.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := w.content()
	if err == nil || errors.Is(err, targeting.ErrContentUnavailable) {
		t.Fatalf("%v", err)
	}
}

// --- leases -----------------------------------------------------------------

func TestLeaseHygiene(t *testing.T) {
	t.Parallel()
	t.Run("panic", func(t *testing.T) {
		w := newWorld(t)
		w.scope = func(string, string) (bool, bool) { panic("scope function failed") }
		w.restart()
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("no panic")
				}
			}()
			_, _ = w.content()
		}()
		noLeases(t, w.cache)
	})
	t.Run("cancelled after resolution", func(t *testing.T) {
		w := newWorld(t)
		w.mustContent()
		ctx, cancel := context.WithCancel(context.Background())
		w.oci.hook = func(point string) {
			if point == "resolved" {
				if n := w.cache.Stats().Leases; n != 1 {
					t.Errorf("%d leases while reading", n)
				}
				cancel()
			}
		}
		_, err := w.oci.Content(ctx, w.ref())
		if !errors.Is(err, context.Canceled) || errors.Is(err, targeting.ErrContentUnavailable) {
			t.Fatalf("%v", err)
		}
		noLeases(t, w.cache)
	})
	t.Run("failures", func(t *testing.T) {
		w := newEmptyWorld(t)
		w.fetch.down.Store(true)
		_, err := w.content()
		wantClass(t, err, targeting.ContentErrorContentUnavailable)
		noLeases(t, w.cache)
	})
	t.Run("concurrent", func(t *testing.T) {
		w := newWorld(t)
		const n = 16
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make(chan error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				c, err := w.content()
				if err == nil && c.Bundle.Digest != w.f.Subject {
					err = errors.New("wrong digest")
				}
				errs <- err
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		noLeases(t, w.cache)
	})
}

func TestPins(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	ctx := context.Background()
	var pins []*Pin
	for _, h := range []string{bundle.HolderProfile, bundle.HolderApplied, bundle.HolderAssessment} {
		p, err := w.oci.Pin(ctx, w.ref(), h, "owner/"+h)
		if err != nil {
			t.Fatal(err)
		}
		if p.Handle.BundleDigest() != w.f.Subject || p.Handle.Lease.Holder != h {
			t.Fatalf("%+v", p.Handle.Lease)
		}
		pins = append(pins, p)
	}
	if n := w.cache.Stats().Leases; n != 3 {
		t.Fatalf("%d leases", n)
	}
	w.mustContentKeeping(3)
	for _, p := range pins {
		if err := p.Release(); err != nil {
			t.Fatal(err)
		}
		if err := p.Release(); err != nil {
			t.Fatalf("second release: %v", err)
		}
	}
	noLeases(t, w.cache)

	if _, err := w.oci.Pin(ctx, w.ref(), "nobody", "o"); err == nil || errors.Is(err, targeting.ErrContentUnavailable) && targeting.ContentErrorClassOf(err) != targeting.ContentErrorUnresolved {
		t.Fatalf("invalid holder: %v", err)
	}
	w.fetch.down.Store(true)
	w.revs.edit(func(r *revs) { r.compat = Compatibility{Controller: "0.0.1"} })
	if _, err := w.oci.Pin(ctx, w.ref(), bundle.HolderApplied, "o"); targeting.ContentErrorClassOf(err) != targeting.ContentErrorIncompatible {
		t.Fatalf("%v", err)
	}
	noLeases(t, w.cache)
}

func (w *world) mustContentKeeping(leases int) {
	w.t.Helper()
	if _, err := w.content(); err != nil {
		w.t.Fatal(err)
	}
	if n := w.cache.Stats().Leases; n != leases {
		w.t.Fatalf("%d leases, want %d", n, leases)
	}
}

// Freeze copies an assessment's content out of the cache under an
// assessment lease: from resolution until the copy is written the entry is
// pinned (a leased entry is never evicted), and the lease is released
// before Freeze returns, so the run depends on its copy alone.
func TestFreezeLeasesEntryUntilCopied(t *testing.T) {
	w := newWorld(t)
	w.mustContent()
	pinned := false
	w.oci.hook = func(point string) {
		if point != "resolved" {
			return
		}
		for _, e := range w.cache.Stats().Entries {
			if e.Digest == w.ref().Digest && e.Leases == 1 {
				pinned = true
			}
		}
	}
	dir := filepath.Join(t.TempDir(), "frozen")
	f, err := w.oci.Freeze(context.Background(), w.ref(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !pinned {
		t.Fatal("the entry was not leased while it was copied; eviction could remove it mid-freeze")
	}
	if f.Identity.Digests.OCI != w.ref().Digest {
		t.Fatalf("froze %s", f.Identity.Digests.OCI)
	}
	noLeases(t, w.cache)
}
