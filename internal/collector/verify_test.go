package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

func repoSources(t *testing.T) map[string]targeting.PolicySource {
	t.Helper()
	root := repo(t)
	sums, err := os.ReadFile(filepath.Join(root, "content/SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(sums)
	content := targeting.LocalContent{Root: filepath.Join(root, "content"), Name: "konstapel-vendored", Policies: map[string]string{assessment.PolicyName: assessment.SourcePolicy}}
	c, err := content.Content(context.Background(), v1alpha1.BundleReference{Name: "konstapel-vendored", Digest: "sha256:" + hex.EncodeToString(h[:])})
	if err != nil {
		t.Fatal(err)
	}
	return SourcesOf(c)
}

// tamperExpression changes every captured validation expression and then
// recomputes the capture's own check digests and inventory, as an attacker
// re-hashing the capture would.
func tamperExpression(t *testing.T, c CaptureV2) CaptureV2 {
	t.Helper()
	c = clone(c)
	for _, p := range c.EnginePolicies {
		for _, v := range assessment.At(p, "spec", "validations").([]any) {
			assessment.Map(v)["expression"] = "true"
		}
	}
	c.Checks = nil
	for _, p := range c.EnginePolicies {
		k, err := PolicyChecks(p, nil)
		if err != nil {
			t.Fatal(err)
		}
		c.Checks = append(c.Checks, k...)
	}
	inv, err := BuildInventory(c.Subjects, c.Checks, c.Workloads, c.MappingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	c.Expected = inv
	if err := c.Validate(); err != nil {
		t.Fatal("tampered capture should be self-consistent:", err)
	}
	return c
}

func TestEnginePoliciesReRenderFromSource(t *testing.T) {
	c, sources := captureV2(t), repoSources(t)
	if err := VerifyEnginePolicies(c, sources); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*CaptureV2){
		"changed expression, recomputed hashes": func(c *CaptureV2) { *c = tamperExpression(t, *c) },
		"changed source digest":                 func(c *CaptureV2) { c.Subjects[0].SourceDigest = "sha256:" + strings.Repeat("0", 64) },
		"changed contribution mode": func(c *CaptureV2) {
			for i := range c.Contributions {
				c.Contributions[i].Mode = v1alpha1.ModeDeny
			}
		},
		"missing contribution":  func(c *CaptureV2) { c.Contributions = nil },
		"missing engine policy": func(c *CaptureV2) { c.EnginePolicies = c.EnginePolicies[:1] },
		"renamed engine policy": func(c *CaptureV2) { assessment.Map(c.EnginePolicies[0]["metadata"])["name"] = "konstapel-other" },
		"stripped revision label": func(c *CaptureV2) {
			delete(assessment.Map(assessment.At(c.EnginePolicies[0], "metadata", "annotations")), "compliance.erenius.io/revision")
		},
		"checks from another spec": func(c *CaptureV2) { c.Checks[0].SHA256 = strings.Repeat("a", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			x := clone(c)
			mutate(&x)
			if VerifyEnginePolicies(x, sources) == nil {
				t.Fatal("tampered engine policy verified")
			}
		})
	}
}

func exported(t *testing.T) (ExportRequest, publication.Descriptor) {
	t.Helper()
	c := freshCapture(t)
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), failProd)
	req := exportReq(t, c, evaluate(t, c, nil, maxAge), repo(t))
	d, err := Export(context.Background(), req)
	if err != nil || d.PackageKind != publication.KindAssessment {
		t.Fatalf("%v %+v", err, d.Diagnostic)
	}
	return req, d
}

// rehash rewrites the descriptor inventory after an edit, so only the
// content-anchored verification can notice.
func rehash(t *testing.T, dir string, d publication.Descriptor) {
	t.Helper()
	files, err := publication.Inventory(dir, exportRole)
	if err != nil {
		t.Fatal(err)
	}
	d.Files = files
	if err := assessment.Write(filepath.Join(dir, publication.DescriptorFile), d); err != nil {
		t.Fatal(err)
	}
	if err := publication.VerifyDir(dir, d); err != nil {
		t.Fatal("rehashed package should pass inventory checks:", err)
	}
}

func TestPackageVerificationIsAnchoredToContent(t *testing.T) {
	req, d := exported(t)
	if err := VerifyPackage(req.Out); err != nil {
		t.Fatal(err)
	}
	// Edit a captured policy expression, re-hash the capture and descriptor.
	var c CaptureV2
	_ = assessment.Read(filepath.Join(req.Out, "capture.json"), &c)
	_ = assessment.Write(filepath.Join(req.Out, "capture.json"), tamperExpression(t, c))
	rehash(t, req.Out, d)
	if err := VerifyPackage(req.Out); err == nil || !strings.Contains(err.Error(), "differs from the render") {
		t.Fatalf("re-hashed expression change verified: %v", err)
	}

	// Edit the packaged source and its SHA256SUMS line: the bundle digest no
	// longer matches the contribution's pinned bundle.
	req, d = exported(t)
	src := filepath.Join(req.Out, assessment.SourcePolicy)
	b, _ := os.ReadFile(src)
	edited := strings.Replace(string(b), "privileged", "privilegedX", 1)
	_ = os.WriteFile(src, []byte(edited), 0o644)
	sumsPath := filepath.Join(req.Out, "content/SHA256SUMS")
	sums, _ := os.ReadFile(sumsPath)
	oh, nh := sha256.Sum256(b), sha256.Sum256([]byte(edited))
	_ = os.WriteFile(sumsPath, []byte(strings.Replace(string(sums), hex.EncodeToString(oh[:]), hex.EncodeToString(nh[:]), 1)), 0o644)
	rehash(t, req.Out, d)
	if err := VerifyPackage(req.Out); err == nil || !strings.Contains(err.Error(), "is not bundle") {
		t.Fatalf("edited source verified: %v", err)
	}
}

func TestExportOfUnverifiablePoliciesIsDiagnostic(t *testing.T) {
	c := freshCapture(t)
	c = tamperExpression(t, c)
	req := exportReq(t, c, evaluate(t, c, nil, maxAge), repo(t))
	d, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if d.PackageKind != publication.KindDiagnostic || !strings.Contains(d.Diagnostic.Message, "engine policy verification") {
		t.Fatalf("unverifiable engine policies exported as an assessment: %+v", d.Diagnostic)
	}
}
