package installed_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/content"
	"github.com/backend-bunny/Konstapel/internal/capability"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const module = "github.com/backend-bunny/Konstapel"

// Test-only packages: the synthetic reporting provider and the conformance
// harness. Neither may reach a shipped binary or the production registry.
var testOnly = []string{module + "/internal/provider/reporttest", module + "/internal/provider/conformance"}

func TestProductionRegistryIsKyvernoOnly(t *testing.T) {
	r := installed.Registry()
	if got := r.Contracts(); !slices.Equal(got, []string{"konstapel-kyverno/v1"}) {
		t.Fatalf("installed contracts %v, want only konstapel-kyverno/v1", got)
	}
	if r.Default() != "konstapel-kyverno/v1" || installed.Default != kyverno.Contract {
		t.Fatalf("default %s / %s", r.Default(), installed.Default)
	}
	for _, d := range r.Descriptors() {
		if d.TestOnly {
			t.Errorf("%s is test-only", d.Contract())
		}
	}
}

// The registry describes the identity Konstapel already enforces; it does
// not introduce a second allowlist that could drift from the bundle one.
func TestRegistryAgreesWithExistingProviderIdentity(t *testing.T) {
	r := installed.Registry()
	if kyverno.Name != assessment.ProviderID || kyverno.Contract != content.DefaultProvider {
		t.Fatalf("kyverno identity %s / %s, existing %s / %s", kyverno.Name, kyverno.Contract, assessment.ProviderID, content.DefaultProvider)
	}
	compat := content.Compatibility{Controller: "0.3.0"}
	d := bundle.Descriptor{Compatibility: bundle.Compatibility{Konstapel: "0.1.0"}, Scope: bundle.Scope{Workloads: []string{"Pod"}, OS: []string{"linux"}}}
	for _, c := range r.Contracts() {
		d.Compatibility.Provider = c
		if v := compat.Check(&d); !v.Compatible {
			t.Errorf("installed %s is not accepted by the bundle compatibility check: %v", c, v.Reasons)
		}
	}
	for _, other := range []string{"konstapel-kyverno/v2", "trivy/v1", "konstapel-reporttest/v1"} {
		d.Compatibility.Provider = other
		if compat.Check(&d).Compatible {
			t.Errorf("bundle compatibility accepts %s, which is not installed", other)
		}
		if _, err := r.Lookup(other); err == nil {
			t.Errorf("registry selects %s", other)
		}
	}
}

func TestKyvernoReadsMatchAssessmentCapability(t *testing.T) {
	var want []provider.Read
	for _, res := range capability.Requirements[capability.Assessment] {
		if len(res.Access) > 0 {
			want = append(want, provider.Read{Group: res.Group, Version: res.Version, Resource: res.Resource, Verbs: res.Access})
		}
	}
	got := kyverno.Descriptor().Reads
	if len(got) != len(want) {
		t.Fatalf("reads %+v, capability access %+v", got, want)
	}
	for i := range got {
		if got[i].Group != want[i].Group || got[i].Version != want[i].Version || got[i].Resource != want[i].Resource || !slices.Equal(got[i].Verbs, want[i].Verbs) {
			t.Errorf("read %+v, capability access %+v", got[i], want[i])
		}
	}
}

func TestKyvernoCaptureVersionsMatchCollector(t *testing.T) {
	d := kyverno.Descriptor()
	var accepted []int
	for v := 0; v <= 10; v++ {
		if got, err := collector.CaptureVersion([]byte(`{"version":` + strconv.Itoa(v) + `}`)); err == nil && got == v {
			accepted = append(accepted, v)
		}
	}
	if !slices.Equal(accepted, d.Capture.Read) || d.Capture.Write != collector.CaptureV2Version {
		t.Fatalf("collector reads %v writes %d; descriptor %+v", accepted, collector.CaptureV2Version, d.Capture)
	}
	r := installed.Registry()
	for _, v := range accepted {
		if err := r.CheckCapture("", v); err != nil {
			t.Errorf("default provider cannot read capture %d: %v", v, err)
		}
	}
	if err := r.CheckCapture("", 3); err == nil {
		t.Error("capture 3 accepted")
	}
}

// Regression: with the Kyverno provider implied, the installed registry
// accepts and rejects exactly what the targeting resolver does today for
// the provider-owned dimensions (mode, policy type, parameters), over the
// resolver fixtures and an exhaustive matrix. Scope, unknown policies and
// exception settings remain targeting's and are not provider decisions.
func TestDefaultSelectionMatchesTheResolver(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot(t), "testdata/targeting/resolver/*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no resolver fixtures: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var fx struct {
			Input struct {
				Cluster    string                       `json:"cluster"`
				Bundles    []targeting.Bundle           `json:"bundles"`
				Profiles   []v1alpha1.ComplianceProfile `json:"profiles"`
				Bindings   []v1alpha1.ComplianceBinding `json:"bindings"`
				Namespaces []targeting.Namespace        `json:"namespaces"`
			} `json:"input"`
		}
		if err := yaml.Unmarshal(raw, &fx); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		in := targeting.Input{Cluster: fx.Input.Cluster, Bundles: fx.Input.Bundles, Profiles: fx.Input.Profiles, Bindings: fx.Input.Bindings, Namespaces: fx.Input.Namespaces}
		if n := agree(t, filepath.Base(f), in); n == 0 && !strings.Contains(f, "unresolved") {
			t.Errorf("%s: no binding compared", f)
		}
	}

	compared := 0
	for _, mode := range []v1alpha1.EnforcementMode{v1alpha1.ModeAudit, v1alpha1.ModeDeny, "Enforce"} {
		for _, scope := range []targeting.PolicyScope{targeting.ScopeNamespaced, targeting.ScopeCluster, targeting.ScopeUnsupported} {
			for _, rendered := range []bool{false, true} {
				for _, p := range []string{"", "{}", "null", `{"allowed":["NET_RAW"]}`} {
					compared += agree(t, string(mode)+"/"+string(scope)+"/"+p, matrixInput(mode, scope, rendered, p))
				}
			}
		}
	}
	if compared != 3*3*2*4 {
		t.Fatalf("compared %d matrix bindings", compared)
	}
}

func matrixInput(mode v1alpha1.EnforcementMode, scope targeting.PolicyScope, rendered bool, params string) targeting.Input {
	ref := v1alpha1.BundleReference{Name: "b", Digest: "sha256:" + strings.Repeat("1", 64)}
	pol := v1alpha1.ProfilePolicy{Name: "checked"}
	if params != "" {
		pol.Parameters = &apiextensionsv1.JSON{Raw: []byte(params)}
	}
	return targeting.Input{
		Cluster: "kube-system:c",
		Bundles: []targeting.Bundle{{Name: ref.Name, Digest: ref.Digest, Policies: []targeting.BundlePolicy{
			{Name: "checked", Scope: scope, Parameters: rendered}, {Name: "plain", Scope: targeting.ScopeNamespaced}}}},
		Profiles: []v1alpha1.ComplianceProfile{{ObjectMeta: metav1.ObjectMeta{Name: "p", UID: "p-uid", Generation: 1},
			Spec: v1alpha1.ComplianceProfileSpec{Bundle: ref, Policies: []v1alpha1.ProfilePolicy{pol, {Name: "plain"}}}}},
		Bindings: []v1alpha1.ComplianceBinding{{ObjectMeta: metav1.ObjectMeta{Name: "b", UID: "b-uid", Generation: 1},
			Spec: v1alpha1.ComplianceBindingSpec{ProfileRef: v1alpha1.ProfileReference{Name: "p"}, NamespaceSelector: &v1alpha1.NamespaceSelector{}, Mode: mode}}},
		Namespaces: []targeting.Namespace{{Name: "ns", UID: types.UID("ns-uid")}},
	}
}

// agree compares the resolver and the default selection for every binding
// whose profile and bundle resolve, and returns how many it compared.
func agree(t *testing.T, name string, in targeting.Input) int {
	t.Helper()
	r := installed.Registry()
	res := targeting.Resolve(in)
	compared := 0
	for _, b := range in.Bindings {
		var p *v1alpha1.ComplianceProfile
		for i := range in.Profiles {
			if in.Profiles[i].Name == b.Spec.ProfileRef.Name {
				p = &in.Profiles[i]
			}
		}
		var bundle *targeting.Bundle
		for i := range in.Bundles {
			if p != nil && in.Bundles[i].Ref() == p.Spec.Bundle {
				bundle = &in.Bundles[i]
			}
		}
		var br targeting.BindingResult
		for _, x := range res.Bindings {
			if x.Binding.UID == b.UID {
				br = x
			}
		}
		if p == nil || bundle == nil || slices.ContainsFunc(br.Errors, func(e targeting.ResolutionError) bool { return e.Reason == targeting.ReasonInvalidSelector }) {
			continue
		}

		// Build the selection exactly as content presents each policy.
		meta := map[string]targeting.BundlePolicy{}
		for _, bp := range bundle.Policies {
			meta[bp.Name] = bp
		}
		sel := provider.Selection{Mode: b.Spec.Mode}
		for _, pol := range p.Spec.Policies {
			bp, ok := meta[pol.Name]
			if !ok {
				continue // UnknownPolicy: not in content, nothing to select
			}
			kind := kyverno.CheckKind
			if bp.Scope == targeting.ScopeUnsupported {
				kind = provider.KindOf("kyverno.io/v1", "ClusterPolicy")
			}
			sel.Checks = append(sel.Checks, provider.CheckSelection{Name: pol.Name, Kind: kind, Parameters: pol.Parameters, Content: provider.ContentParameters{Rendered: bp.Parameters}})
		}
		if len(sel.Checks) == 0 {
			continue // every policy is unknown to the content: a targeting error
		}
		compared++
		plan, errs := r.Select(sel)

		resolverModeErr := slices.ContainsFunc(br.Errors, func(e targeting.ResolutionError) bool {
			return e.Policy == "" && e.Reason == targeting.ReasonInvalidConfiguration
		})
		selectionModeErr := slices.ContainsFunc(errs, func(e provider.SelectionError) bool { return e.Check == "" })
		if resolverModeErr != selectionModeErr {
			t.Errorf("%s/%s: resolver binding error %v, selection binding error %v (%v)", name, b.Name, br.Errors, selectionModeErr, errs)
			continue
		}
		if resolverModeErr {
			continue
		}
		for _, c := range sel.Checks {
			accepted := slices.ContainsFunc(br.Contributions, func(x targeting.Contribution) bool { return x.Policy == c.Name })
			var reason targeting.Reason
			targetingOwned := false
			for _, e := range br.Errors {
				if e.Policy != c.Name {
					continue
				}
				switch {
				case e.Reason == targeting.ReasonInvalidConfiguration && strings.Contains(e.Message, "does not accept parameters"),
					e.Reason == targeting.ReasonUnsupportedScope && meta[c.Name].Scope == targeting.ScopeUnsupported:
					reason = e.Reason
				default:
					targetingOwned = true // cluster scope, exception settings
				}
			}
			var got []string
			for _, e := range errs {
				if e.Check == c.Name {
					got = append(got, e.Reason.BindingReason())
				}
			}
			switch {
			case targetingOwned:
			case accepted && len(got) > 0:
				t.Errorf("%s/%s/%s: resolver accepts, selection rejects %v", name, b.Name, c.Name, errs)
			case !accepted && reason != "" && !slices.Equal(got, []string{string(reason)}):
				t.Errorf("%s/%s/%s: resolver rejects with %s, selection gives %v (%v)", name, b.Name, c.Name, reason, got, errs)
			}
		}
		if len(errs) == 0 && (plan == nil || plan.Provider != "konstapel-kyverno/v1" || !plan.Delivery || plan.Mode != b.Spec.Mode) {
			t.Errorf("%s/%s: default selection did not resolve to the delivering Kyverno provider: %+v", name, b.Name, plan)
		}
		// An explicit Kyverno contract (what every bundle descriptor names)
		// resolves exactly like the implied default.
		sel.Provider = content.DefaultProvider
		plan2, errs2 := r.Select(sel)
		if len(errs2) != len(errs) || (plan == nil) != (plan2 == nil) || (plan != nil && plan2.Provider != plan.Provider) {
			t.Errorf("%s/%s: explicit %s differs from the default: %v / %v", name, b.Name, sel.Provider, errs, errs2)
		}
	}
	return compared
}

// Compile-time boundary: no shipped binary links the test-only reporting
// provider or the conformance harness, so neither can be registered or
// selected in a production build. Shipped binaries are every main package
// under cmd/ (scripts/build.sh builds cmd/konstapel and cmd/konstapel-provider).
func TestTestOnlyProvidersAreNotLinkedIntoShippedBinaries(t *testing.T) {
	mains := goList(t, "-f", "{{if eq .Name \"main\"}}{{.ImportPath}}{{end}}", "./cmd/...")
	for _, want := range []string{module + "/cmd/konstapel", module + "/cmd/konstapel-provider"} {
		if !slices.Contains(mains, want) {
			t.Fatalf("main packages %v lack %s; the check is not working", mains, want)
		}
	}
	for _, pkg := range append(mains, module+"/internal/provider/installed", module+"/internal/provider/kyverno", module+"/internal/provider") {
		deps := goList(t, "-deps", pkg)
		if !slices.Contains(deps, pkg) {
			t.Fatalf("go list -deps %s did not list the package itself", pkg)
		}
		for _, bad := range testOnly {
			if slices.Contains(deps, bad) {
				t.Errorf("%s links test-only package %s", pkg, bad)
			}
		}
	}
	// The boundary is meaningful only if the test-only packages exist.
	for _, p := range testOnly {
		if got := goList(t, p); !slices.Equal(got, []string{p}) {
			t.Fatalf("test-only package %s not found: %v", p, got)
		}
	}
}

func goList(t *testing.T, args ...string) []string {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list", "-mod=readonly"}, args...)...)
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %v: %v", args, err)
	}
	return strings.Fields(string(out))
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatalf("repository root %s: %v", dir, err)
	}
	return dir
}
