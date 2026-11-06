package s3store

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/publicationtest"
)

// extract unpacks a downloaded package archive into dir.
func extract(t *testing.T, archive []byte, dir string) {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg || strings.Contains(h.Name, "..") || filepath.IsAbs(h.Name) {
			if h.Typeflag == tar.TypeDir {
				continue
			}
			t.Fatalf("unexpected archive entry %q (type %c)", h.Name, h.Typeflag)
		}
		p := filepath.Join(dir, h.Name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// Complete, incomplete, and diagnostic packages keep their meaning through
// publication: the downloaded archive carries the same descriptor (kind,
// completeness, outcomes, diagnostic reason), every inventoried file verifies,
// and assessment packages keep their OSCAL reference closure.
func TestPublishedPackagesKeepTheirMeaningAfterDownload(t *testing.T) {
	root := repoRoot(t)
	build := map[string]func(dir string, run publication.RunRef) (publication.Descriptor, error){
		"complete": func(dir string, run publication.RunRef) (publication.Descriptor, error) {
			return publicationtest.FullAssessmentPackage(root, dir, run)
		},
		"incomplete": func(dir string, run publication.RunRef) (publication.Descriptor, error) {
			return publicationtest.IncompleteAssessmentPackage(root, dir, run)
		},
		"diagnostic": func(dir string, _ publication.RunRef) (publication.Descriptor, error) {
			src := filepath.Join(root, "testdata/publication/binding-diagnostic")
			if err := os.CopyFS(dir, os.DirFS(src)); err != nil {
				return publication.Descriptor{}, err
			}
			return publication.LoadDescriptor(dir)
		},
	}
	want := map[string]struct {
		kind         publication.PackageKind
		completeness publication.Completeness
	}{
		"complete":   {publication.KindAssessment, publication.Complete},
		"incomplete": {publication.KindAssessment, publication.Incomplete},
		"diagnostic": {publication.KindDiagnostic, ""},
	}
	f := newFake()
	p := newPublisher(t, f, time.Now)
	ctx := context.Background()
	for name, mk := range build {
		t.Run(name, func(t *testing.T) {
			run := testRun
			run.RunUID = "run-" + name
			dir := filepath.Join(t.TempDir(), "pkg")
			orig, err := mk(dir, run)
			if err != nil {
				t.Fatal(err)
			}
			run = orig.Run
			if orig.PackageKind != want[name].kind || (want[name].completeness != "" && orig.Evidence.Completeness != want[name].completeness) {
				t.Fatalf("fixture is not a %s package: %s %s", name, orig.PackageKind, orig.Evidence.Completeness)
			}
			s, err := p.Stage(ctx, publication.StageRequest{Run: run, Dir: dir})
			if err != nil {
				t.Fatal(err)
			}
			r, err := p.Publish(ctx, publication.PublishRequest{Staged: s, Retention: retention("2160h")})
			if err != nil {
				t.Fatal(err)
			}
			archive, err := p.read(ctx, r.Commit.ArchiveKey, r.Commit.ArchiveVersionID)
			if err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "downloaded")
			extract(t, archive, out)
			got, err := publication.LoadDescriptor(out)
			if err != nil {
				t.Fatal(err)
			}
			if got.Digest() != orig.Digest() || got.Digest() != r.DescriptorSHA256 || !reflect.DeepEqual(got.Evidence, orig.Evidence) ||
				!reflect.DeepEqual(got.Outcomes, orig.Outcomes) || !reflect.DeepEqual(got.Diagnostic, orig.Diagnostic) || got.PackageKind != orig.PackageKind {
				t.Fatalf("descriptor changed through publication:\nwant %+v\ngot  %+v", orig, got)
			}
			if err := publication.VerifyDir(out, got); err != nil {
				t.Fatalf("downloaded files do not match the inventory: %v", err)
			}
			if got.PackageKind == publication.KindAssessment {
				if err := assessment.ValidatePackage(root, out); err != nil {
					t.Fatalf("downloaded OSCAL references are not inspectable: %v", err)
				}
			}
		})
	}
}
