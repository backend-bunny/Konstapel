package stack_test

// Reporting-only check content (add-assessment-provider-contract 6.2)
// through the real stack: signed by a disposable publisher key, verified,
// stored and served exactly as engine content, compatible only where its
// contract is selectable, and never a source of anything to execute.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/bundletest"
	"github.com/backend-bunny/Konstapel/internal/bundle/internal/provfixture"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/resolve"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const reportingRepo = "registry.example.test/org/reporting-checks"

type reportingWorld struct {
	*stack.World
	key   *bundletest.Signer
	fetch *multiFetcher
}

// newReportingWorld serves the given signed results from reportingRepo
// under a rule trusting key, with the given provider contracts installed
// (nil: the production allowlist).
func newReportingWorld(t *testing.T, key *bundletest.Signer, providers []string, res ...*registry.Result) *reportingWorld {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(stack.SchemeForTests()).WithObjects(pubKeySecret("publisher", key.PublicKey)).Build()
	f := &multiFetcher{}
	f.serve(reportingRepo, res...)
	w := &stack.World{T: t, Client: c, Opts: stack.Options{SourcesConfigMap: stack.TestConfigMap, Namespace: stack.TestNamespace,
		CacheDir: t.TempDir() + "/cache", ControllerVersion: "0.3.0"}}
	deps := stack.WithTestClock(stack.WithTestFetcher(stack.Deps{APIReader: c, Config: c}, f), func() time.Time { return stack.TestT0 })
	if providers != nil {
		deps = stack.WithTestProviders(deps, providers...)
	}
	w.Deps = deps
	w.SetSources(bundle.BundleSource{Name: "reporting-checks", Repository: reportingRepo,
		Publisher: bundle.Publisher{Type: bundle.SignerPublicKey, PublicKey: &bundle.ObjectRef{Kind: bundle.KindSecret, Name: "publisher"},
			KeyFingerprint: key.Fingerprint, Provenance: bundle.ProvenanceRule{SourceRepository: provfixture.SourceRepository, Builder: provfixture.Builder}}})
	w.Open()
	return &reportingWorld{World: w, key: key, fetch: f}
}

func reportingArchive(t *testing.T, checks ...bundletest.ReportingCheck) *bundle.Archive {
	t.Helper()
	i := strings.LastIndex(reporttest.CheckKind, "/")
	a, err := bundletest.Reporting(stack.RepoRoot, bundletest.ReportingOptions{Contract: reporttest.Contract,
		APIVersion: reporttest.CheckKind[:i], Kind: reporttest.CheckKind[i+1:], Checks: checks,
		Source: bundle.Source{Repository: provfixture.SourceRepository, Revision: strings.Repeat("f", 40)}})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func signed(t *testing.T, s *bundletest.Signer, a *bundle.Archive) *registry.Result {
	t.Helper()
	r, err := s.Result(a, reportingRepo, provfixture.Builder, builderRevision)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReportingContentThroughTheStack(t *testing.T) {
	key, err := bundletest.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	other, err := bundletest.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	a := reportingArchive(t)
	testProviders := []string{kyverno.Contract, reporttest.Contract}
	ctx := context.Background()

	t.Run("verified and served where the contract is selectable", func(t *testing.T) {
		w := newReportingWorld(t, key, testProviders, signed(t, key, a))
		c, err := w.Stack.Content.Content(ctx, ref(a))
		if err != nil {
			t.Fatal(err)
		}
		if c.Bundle.Ref() != ref(a) || len(c.Bundle.Policies) != 1 || c.Bundle.Policies[0].Name != "image-posture-current" {
			t.Fatalf("content %+v", c.Bundle)
		}
		// The definition is served as verified data. Until selection
		// connects reporting-only kinds (6.3), targeting reports it as an
		// unsupported policy, and nothing renders it as an engine policy.
		src := c.Policies["image-posture-current"]
		if c.Bundle.Policies[0].Scope != targeting.ScopeUnsupported || src.Manifest["kind"] != "ImagePosture" {
			t.Fatalf("policy %+v %+v", c.Bundle.Policies[0], src.Manifest)
		}
		if _, err := targeting.Render(targeting.Contribution{Policy: "image-posture-current"}, src); err == nil {
			t.Fatal("a check definition rendered as an engine policy")
		}
		if w.Stack.Acceptances.Len() != 1 {
			t.Fatalf("acceptances %d", w.Stack.Acceptances.Len())
		}
	})

	t.Run("incompatible under the production providers despite a valid signature", func(t *testing.T) {
		w := newReportingWorld(t, key, nil, signed(t, key, a))
		_, err := w.Stack.Content.Content(ctx, ref(a))
		if targeting.ContentErrorClassOf(err) != targeting.ContentErrorIncompatible || !errors.Is(err, resolve.ErrIncompatible) {
			t.Fatalf("error %v", err)
		}
		if !strings.Contains(err.Error(), reporttest.Contract) {
			t.Fatalf("the reason does not name the contract: %v", err)
		}
	})

	t.Run("signature and provenance are required", func(t *testing.T) {
		w := newReportingWorld(t, key, testProviders, signed(t, other, a))
		if _, err := w.Stack.Content.Content(ctx, ref(a)); targeting.ContentErrorClassOf(err) != targeting.ContentErrorUntrusted {
			t.Fatalf("content signed by an untrusted key: %v", err)
		}
	})

	t.Run("a tampered definition is not adopted", func(t *testing.T) {
		res := signed(t, key, a)
		tampered := *res
		tampered.Layer = append([]byte(nil), a.Layer...)
		tampered.Layer[len(tampered.Layer)/2] ^= 0xff
		w := newReportingWorld(t, key, testProviders, &tampered)
		if _, err := w.Stack.Content.Content(ctx, ref(a)); err == nil {
			t.Fatal("a tampered layer was adopted")
		}
	})

	t.Run("signed content naming an executable is refused", func(t *testing.T) {
		evil := reportingArchive(t, bundletest.ReportingCheck{Name: "image-posture-current",
			Definition: bundletest.ReportingDefinition("reporttest.konstapel.io/v1", "ImagePosture", "image-posture-current") +
				"  image: registry.example.test/scanner@sha256:" + strings.Repeat("a", 64) + "\n  command: [/scan]\n"})
		w := newReportingWorld(t, key, testProviders, signed(t, key, evil))
		_, err := w.Stack.Content.Content(ctx, v1alpha1.BundleReference{Name: evil.Descriptor.Name, Digest: evil.ManifestDigest})
		// The cache's content check refuses it before anything is stored
		// or accepted; the bounded reason does not repeat bundle data.
		if err == nil || !strings.Contains(err.Error(), "content check failed") {
			t.Fatalf("error %v", err)
		}
		if w.Stack.Acceptances.Len() != 0 {
			t.Fatal("refused content was accepted")
		}
	})
}
