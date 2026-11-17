package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

const supportingUID = "0f1e2d3c-aaaa-4bbb-8ccc-000000000001"

// stagedCopy writes a document copy to a staging directory.
func stagedCopy(t *testing.T, body []byte) SupportingDocument {
	t.Helper()
	p := filepath.Join(t.TempDir(), supportingUID)
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(body)
	return SupportingDocument{ID: supportingUID, Source: p, SHA256: hex.EncodeToString(h[:]), Size: int64(len(body)),
		Title: "DC North physical access audit", MediaType: "application/pdf"}
}

func TestExportPlacesProtectedSupportingEvidence(t *testing.T) {
	c := freshCapture(t)
	c.Reports = reportsAt(c, c.Window.Started.Add(time.Minute), failProd)
	ev := evaluate(t, c, nil, maxAge)
	req := exportReq(t, c, ev, repo(t))
	doc := stagedCopy(t, []byte("%PDF-1.7 audit"))
	req.Supporting = &SupportingFiles{Context: []byte(`{"version":"x"}`), Documents: []SupportingDocument{doc}}
	plain := exportReq(t, c, ev, repo(t))
	dp, err := Export(context.Background(), plain)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Protected() || d.Evidence != dp.Evidence || d.Outcomes != dp.Outcomes || d.PackageKind != publication.KindAssessment {
		t.Fatalf("protection %+v, evidence %+v/%+v", d.Protection, d.Evidence, dp.Evidence)
	}
	if dp.Protected() {
		t.Fatal("a package without supporting files is protected")
	}
	roles := map[string]publication.FileRole{}
	for _, f := range d.Files {
		roles[f.Path] = f.Role
	}
	if roles[publication.SupportingContextFile] != publication.RoleSupportingContext || roles[publication.SupportingDocumentDir+supportingUID] != publication.RoleSupportingDocument {
		t.Fatalf("roles %v", roles)
	}
	if err := publication.VerifyDir(req.Out, d); err != nil {
		t.Fatal(err)
	}
	// The results reference the copy by relative path and digest only, and
	// gain no observation or finding from it.
	ar := results(t, req.Out)
	res, _ := assessment.At(ar, "back-matter", "resources").([]any)
	var found bool
	for _, r := range res {
		m := assessment.Map(r)
		links, _ := m["rlinks"].([]any)
		for _, l := range links {
			lm := assessment.Map(l)
			if lm["href"] == publication.SupportingDocumentDir+supportingUID {
				hs, _ := lm["hashes"].([]any)
				found = len(hs) == 1 && assessment.Map(hs[0])["value"] == doc.SHA256 && m["title"] == doc.Title
			}
		}
	}
	if !found {
		t.Fatalf("no back-matter resource for the copy: %v", res)
	}
	plainR, withR := firstResult(t, plain.Out), firstResult(t, req.Out)
	for _, k := range []string{"observations", "findings"} {
		a, _ := plainR[k].([]any)
		b, _ := withR[k].([]any)
		if len(a) != len(b) {
			t.Fatalf("%s changed: %d vs %d", k, len(a), len(b))
		}
	}
}

func TestExportRefusesUnverifiedOrNamespaceSupporting(t *testing.T) {
	c := freshCapture(t)
	ev := evaluate(t, c, nil, maxAge)
	req := exportReq(t, c, ev, repo(t))
	doc := stagedCopy(t, []byte("original"))
	if err := os.WriteFile(doc.Source, []byte("replaced"), 0o600); err != nil {
		t.Fatal(err)
	}
	req.Supporting = &SupportingFiles{Context: []byte("{}"), Documents: []SupportingDocument{doc}}
	if _, err := Export(context.Background(), req); !errors.Is(err, ErrSupportingCopy) {
		t.Fatalf("a changed staged copy: %v", err)
	}

	cm, _ := mixedCapture(t)
	p, err := Project(cm, "uid-shop-dev")
	if err != nil {
		t.Fatal(err)
	}
	run := publication.RunRef{ClusterID: p.Cluster, BindingUID: "uid-audit-all", RunUID: "run-ns"}
	ns := ExportRequest{Root: repo(t), Out: filepath.Join(t.TempDir(), "pkg"), Run: run, BindingConfiguration: "b",
		Scope: publication.Scope{Kind: publication.ScopeNamespace, ClusterID: run.ClusterID, BindingUID: run.BindingUID,
			Request:       &publication.RequestRef{Namespace: "shop-dev", Name: "r", UID: "req-1", NamespaceUID: "uid-shop-dev"},
			NamespaceUIDs: []string{"uid-shop-dev"}, Revision: "s"},
		Capture: p, Evaluation: evaluate(t, p, nil, maxAge),
		Supporting: &SupportingFiles{Context: []byte("{}"), Documents: []SupportingDocument{stagedCopy(t, []byte("doc"))}}}
	if _, err := Export(context.Background(), ns); err == nil || !strings.Contains(err.Error(), "cannot carry protected supporting evidence") {
		t.Fatalf("a namespace package accepted protected supporting evidence: %v", err)
	}
	// Refused before anything is written.
	if _, err := os.Stat(filepath.Join(ns.Out, "supporting-evidence")); !os.IsNotExist(err) {
		t.Fatal("supporting files were written into a namespace package")
	}
}

func TestDiagnosticPackageKeepsSupportingEvidence(t *testing.T) {
	root := t.TempDir()
	if err := os.CopyFS(filepath.Join(root, "content"), os.DirFS(filepath.Join(repo(t), "content"))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "content/component-definition.json"), []byte(`{"component-definition": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c := freshCapture(t)
	req := exportReq(t, c, evaluate(t, c, nil, maxAge), root)
	req.Supporting = &SupportingFiles{Context: []byte("{}"), Documents: []SupportingDocument{stagedCopy(t, []byte("doc"))}}
	d, err := Export(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if d.PackageKind != publication.KindDiagnostic || !d.Protected() {
		t.Fatalf("kind %s protection %+v", d.PackageKind, d.Protection)
	}
	if err := publication.VerifyDir(req.Out, d); err != nil {
		t.Fatal(err)
	}
}
