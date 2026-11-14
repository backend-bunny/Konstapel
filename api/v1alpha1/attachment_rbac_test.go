package v1alpha1_test

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// add-supporting-evidence-attachments 1.3: registration, upload, metadata
// read and document download are distinct platform grants held by dedicated
// ClusterRoles; no namespace role (assessment requester, exception editor)
// or other shipped role receives any of them, and only the controller writes
// status. Checked statically against every shipped Role and ClusterRole;
// TestLiveEvidenceAttachmentAPI checks the same matrix against a real API
// server with SubjectAccessReview.

const (
	attachmentRegistrar  = "konstapel-evidence-attachment-registrar"
	attachmentUploader   = "konstapel-evidence-attachment-uploader"
	attachmentReader     = "konstapel-evidence-attachment-reader"
	attachmentDownloader = "konstapel-evidence-attachment-downloader"
	controllerRole       = "konstapel-controller"
)

type grant struct{ verb, resource string }

// attachmentMatrix is the documented authority matrix
// (docs/supporting-evidence.md): exactly these grants on attachment
// resources, per role. Any other role holds none.
var attachmentMatrix = map[string][]grant{
	attachmentRegistrar: {{"get", "evidenceattachments"}, {"list", "evidenceattachments"}, {"watch", "evidenceattachments"},
		{"create", "evidenceattachments"}, {"delete", "evidenceattachments"}, {"get", "evidenceattachments/status"}},
	attachmentUploader: {{"get", "evidenceattachments"}, {"create", "evidenceattachments/upload"}},
	attachmentReader: {{"get", "evidenceattachments"}, {"list", "evidenceattachments"}, {"watch", "evidenceattachments"},
		{"get", "evidenceattachments/status"}, {"list", "evidenceattachments/status"}, {"watch", "evidenceattachments/status"}},
	attachmentDownloader: {{"get", "evidenceattachments"}, {"get", "evidenceattachments/download"}},
	controllerRole: {{"get", "evidenceattachments"}, {"list", "evidenceattachments"}, {"watch", "evidenceattachments"},
		{"update", "evidenceattachments"}, {"patch", "evidenceattachments"},
		{"get", "evidenceattachments/status"}, {"update", "evidenceattachments/status"}, {"patch", "evidenceattachments/status"},
		{"update", "evidenceattachments/finalizers"}},
}

var (
	attachmentResources = []string{"evidenceattachments", "evidenceattachments/status", "evidenceattachments/finalizers", "evidenceattachments/upload", "evidenceattachments/download"}
	allVerbs            = []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "escalate", "bind", "impersonate"}
)

func TestAttachmentAuthorityMatrix(t *testing.T) {
	found := map[string]bool{}
	for _, r := range loadRoles(t) {
		want, listed := attachmentMatrix[r.name]
		if listed && r.kind != "ClusterRole" && r.name != controllerRole {
			t.Errorf("%s must be a ClusterRole (bound cluster-wide to platform subjects)", r.name)
		}
		if listed && r.kind == "ClusterRole" {
			found[r.name] = true
		}
		for _, res := range attachmentResources {
			for _, verb := range allVerbs {
				expected := listed && r.kind == "ClusterRole" && slices.Contains(want, grant{verb, res})
				if got := grants(r.rules, verb, res); got != expected {
					t.Errorf("%s %s (%s): %s %s = %v, want %v", r.kind, r.name, r.file, verb, res, got, expected)
				}
			}
		}
	}
	for name := range attachmentMatrix {
		if !found[name] {
			t.Errorf("ClusterRole %s not shipped", name)
		}
	}
}

// Platform attachment roles never carry namespace or other-resource rights,
// so binding one cannot widen assessment, exception or storage authority.
func TestAttachmentRolesGrantOnlyAttachments(t *testing.T) {
	for _, r := range loadRoles(t) {
		if r.name == controllerRole || attachmentMatrix[r.name] == nil {
			continue
		}
		for _, rule := range r.rules {
			for _, res := range rule.Resources {
				if !strings.HasPrefix(res, "evidenceattachments") {
					t.Errorf("%s grants %s", r.name, res)
				}
			}
			if slices.Contains(rule.Verbs, "*") || slices.Contains(rule.Resources, "*") || slices.Contains(rule.APIGroups, "*") {
				t.Errorf("%s uses a wildcard", r.name)
			}
		}
	}
}

// The documented authority matrix names exactly the shipped attachment roles.
func TestAttachmentAuthorityIsDocumented(t *testing.T) {
	raw, err := os.ReadFile("../../docs/supporting-evidence.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	documented := map[string]bool{}
	for _, m := range regexp.MustCompile(`konstapel-evidence-attachment-[a-z]+`).FindAllString(doc, -1) {
		documented[m] = true
	}
	delete(documented, "konstapel-evidence-attachment-registrant") // the admission policy
	for name := range attachmentMatrix {
		if name == controllerRole {
			continue
		}
		if !documented[name] {
			t.Errorf("%s is not documented", name)
		}
		delete(documented, name)
	}
	for name := range documented {
		t.Errorf("documented role %s is not shipped", name)
	}
	for _, g := range attachmentMatrix[attachmentUploader] {
		if g.resource == "evidenceattachments/upload" && !strings.Contains(doc, "`evidenceattachments/upload`: "+g.verb) {
			t.Errorf("upload grant %s not documented", g.verb)
		}
	}
	if !strings.Contains(doc, "`evidenceattachments/download`: get") {
		t.Error("download grant not documented")
	}
}
