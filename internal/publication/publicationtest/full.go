// Package publicationtest builds complete evidence packages for tests that
// need real OSCAL reference closure, such as publisher validation.
//
// The static fixtures in testdata/publication are small contract fixtures.
// Their assessment results are schema-valid but reference no local plan, so
// they do not pass full package validation. A complete package must carry the
// pinned NIST catalog (about 10 MB), so it is generated on demand here rather
// than committed as a second copy of vendored content.
package publicationtest

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// SavedCapture is the offline capture the full package is built from.
const SavedCapture = "testdata/capture.json"

// FullAssessmentPackage exports the saved prototype capture from the
// repository at root into the empty directory dir, using the prototype's own
// export path (no plugin or cluster), and writes its descriptor for run.
// The result passes assessment.ValidatePackage (schemas, provenance,
// checksums, and reference closure) as well as publication.VerifyDir.
//
// The package is a Binding-scope platform package: the prototype capture is
// cluster-wide and is not projected to a namespace. Namespace UIDs are
// synthetic because the v1 capture format does not record them. OSCAL UUIDs
// differ on every call; compare packages by descriptor, not bytes.
func FullAssessmentPackage(root, dir string, run publication.RunRef) (publication.Descriptor, error) {
	return AssessmentPackage(root, dir, run, nil)
}

// IncompleteAssessmentPackage is FullAssessmentPackage with the saved
// capture's first PolicyReport dropped, so expected evidence is missing and
// the package is a valid, Incomplete assessment.
func IncompleteAssessmentPackage(root, dir string, run publication.RunRef) (publication.Descriptor, error) {
	return AssessmentPackage(root, dir, run, func(c *assessment.Capture) { c.Reports = c.Reports[1:] })
}

// AssessmentPackage builds a package from the saved capture after applying
// mutate (which may be nil).
func AssessmentPackage(root, dir string, run publication.RunRef, mutate func(*assessment.Capture)) (publication.Descriptor, error) {
	var c assessment.Capture
	if err := assessment.Read(filepath.Join(root, SavedCapture), &c); err != nil {
		return publication.Descriptor{}, err
	}
	if mutate != nil {
		mutate(&c)
	}
	input, plan, err := assessment.Input(root)
	if err != nil {
		return publication.Descriptor{}, err
	}
	ev, result, err := assessment.Reconcile(c)
	if err != nil {
		return publication.Descriptor{}, err
	}
	if err = assessment.Export(context.Background(), root, dir, input, plan, []policy.PVPResult{result}, c); err != nil {
		return publication.Descriptor{}, err
	}
	if err = assessment.ValidatePackage(root, dir); err != nil {
		return publication.Descriptor{}, fmt.Errorf("generated package is invalid: %w", err)
	}
	files, err := publication.Inventory(dir, role)
	if err != nil {
		return publication.Descriptor{}, err
	}

	namespaces := map[string]bool{}
	for _, r := range c.Expected {
		namespaces["ns-uid-"+r.Namespace] = true
	}
	var nsUIDs []string
	for ns := range namespaces {
		nsUIDs = append(nsUIDs, ns)
	}
	sort.Strings(nsUIDs)
	scope := publication.Scope{Kind: publication.ScopeBinding, ClusterID: run.ClusterID, BindingUID: run.BindingUID, NamespaceUIDs: nsUIDs, Revision: "prototype-capture-v1"}

	evidence := publication.EvidenceSummary{Expected: len(c.Expected), Missing: len(ev.Missing), Rejected: len(ev.Rejected)}
	evidence.Attributable = evidence.Expected - evidence.Missing - evidence.Rejected
	var outcomes publication.OutcomeCounts
	for _, e := range ev.Evaluations {
		switch e.Normalized {
		case policy.ResultPass.String():
			outcomes.Pass++
		case policy.ResultFail.String():
			outcomes.Fail++
		case policy.ResultError.String():
			outcomes.Error++
		default:
			outcomes.Unknown++
		}
	}
	switch {
	case evidence.Expected == 0:
		evidence.Completeness = publication.NoTargets
	case ev.Complete:
		evidence.Completeness = publication.Complete
	default:
		evidence.Completeness = publication.Incomplete
	}

	d := publication.Descriptor{
		APIVersion: publication.APIVersion, Kind: publication.DescriptorKind, Run: run,
		PackageKind: publication.KindAssessment, Scope: scope, ScopeSHA256: scope.Digest(),
		Revisions: publication.Revisions{BindingConfiguration: "prototype", Enforcement: []string{c.PolicyDigest}, MappingSHA256: c.MappingDigest},
		Window:    publication.Window{Started: c.Boundary, Closed: c.Collected},
		Evidence:  evidence, Outcomes: outcomes,
		Producer: publication.Producer{Name: "konstapel-prototype-export", Version: "capture-v1", ValidatedAt: time.Now().UTC().Truncate(time.Second),
			Checks: []string{"oscal-schema-1.1.3", "policy-provenance", "package-checksums", "reference-closure"}},
		Files: files,
	}
	if err = d.Validate(); err != nil {
		return d, err
	}
	return d, assessment.Write(filepath.Join(dir, publication.DescriptorFile), d)
}

func role(p string) publication.FileRole {
	switch {
	case p == "assessment-results.json":
		return publication.RoleAssessmentResults
	case p == "assessment-plan.json":
		return publication.RoleAssessmentPlan
	case p == "system-security-plan.json":
		return publication.RoleSystemSecurityPlan
	case p == "content/component-definition.json":
		return publication.RoleComponentDefinition
	case p == "capture.json":
		return publication.RoleCapture
	case p == "evidence.json":
		return publication.RoleEvidenceExtract
	case strings.HasPrefix(p, "content/"):
		return publication.RoleContent
	default: // run-manifest.json, content-manifest.json, rendered-policy.json
		return publication.RoleProvenance
	}
}
