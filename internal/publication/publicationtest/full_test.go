package publicationtest_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
	"github.com/backend-bunny/Konstapel/internal/publication/publicationtest"
)

func TestFullAssessmentPackage(t *testing.T) {
	root, _ := filepath.Abs("../../..")
	dir := t.TempDir()
	run := publication.RunRef{ClusterID: "kube-system:synthetic-cluster", BindingUID: "binding-uid-1", RunUID: "run-uid-full"}
	d, err := publicationtest.FullAssessmentPackage(root, dir, run)
	if err != nil {
		t.Fatal(err)
	}
	// Full prototype validation, including OSCAL reference closure.
	if err = assessment.ValidatePackage(root, dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := publication.LoadDescriptor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Digest() != d.Digest() {
		t.Fatal("written descriptor does not round-trip")
	}
	if err = publication.VerifyDir(dir, loaded); err != nil {
		t.Fatal(err)
	}
	roles := map[publication.FileRole]bool{}
	for _, f := range loaded.Files {
		roles[f.Role] = true
	}
	for _, r := range []publication.FileRole{publication.RoleAssessmentResults, publication.RoleAssessmentPlan, publication.RoleSystemSecurityPlan, publication.RoleComponentDefinition, publication.RoleCapture, publication.RoleContent, publication.RoleProvenance} {
		if !roles[r] {
			t.Errorf("full package lacks %s", r)
		}
	}
	if loaded.Evidence.Completeness != publication.Complete || loaded.Outcomes.Fail == 0 {
		t.Fatalf("saved capture should be complete with failures: %+v %+v", loaded.Evidence, loaded.Outcomes)
	}

	// A publisher accepts the full package through the same contract.
	p := fake.New(func() time.Time { return time.Date(2026, 11, 5, 10, 5, 0, 0, time.UTC) })
	s, err := p.Stage(context.Background(), publication.StageRequest{Run: run, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Publish(context.Background(), publication.PublishRequest{Staged: s, Retention: publication.Retention{Duration: "2160h", BindingConfiguration: "prototype", SelectedAt: time.Date(2026, 11, 5, 10, 4, 0, 0, time.UTC)}}); err != nil {
		t.Fatal(err)
	}

	// Breaking reference closure is caught by package validation, and the
	// edit is caught by the descriptor checksums.
	if err = os.Remove(filepath.Join(dir, "content/component-definition.json")); err != nil {
		t.Fatal(err)
	}
	if assessment.ValidatePackage(root, dir) == nil || publication.VerifyDir(dir, loaded) == nil {
		t.Fatal("broken package accepted")
	}
}
