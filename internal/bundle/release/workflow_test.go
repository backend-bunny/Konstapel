package release

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const workflowDir = "../../../.github/workflows"

type workflow struct {
	On          map[string]any               `yaml:"on"`
	Permissions map[string]string            `yaml:"permissions"`
	Defaults    map[string]map[string]string `yaml:"defaults"`
	Concurrency struct {
		Group            string `yaml:"group"`
		CancelInProgress any    `yaml:"cancel-in-progress"`
	} `yaml:"concurrency"`
	Jobs map[string]struct {
		If          string            `yaml:"if"`
		Uses        string            `yaml:"uses"`
		Needs       any               `yaml:"needs"`
		Permissions map[string]string `yaml:"permissions"`
		Steps       []struct {
			Uses string            `yaml:"uses"`
			Run  string            `yaml:"run"`
			With map[string]any    `yaml:"with"`
			Env  map[string]string `yaml:"env"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func loadWorkflow(t *testing.T, name string) (workflow, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(workflowDir, name))
	if err != nil {
		t.Fatal(err)
	}
	var w workflow
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(false)
	if err := dec.Decode(&w); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return w, string(raw)
}

// The bundle release workflow is dispatched alone, on main, with a name and
// commit; it is not coupled to the application, image, chart or
// release-please workflows in either direction.
func TestBundleReleaseWorkflowIsIndependent(t *testing.T) {
	w, raw := loadWorkflow(t, "bundle-release.yml")

	var triggers []string
	for k := range w.On {
		triggers = append(triggers, k)
	}
	if len(triggers) != 1 || triggers[0] != "workflow_dispatch" {
		t.Fatalf("triggers = %v, want only workflow_dispatch", triggers)
	}
	inputs, _ := w.On["workflow_dispatch"].(map[string]any)["inputs"].(map[string]any)
	var names []string
	for k, v := range inputs {
		names = append(names, k)
		in := v.(map[string]any)
		if in["required"] != true || in["type"] != "string" {
			t.Errorf("input %s = %v, want a required string", k, in)
		}
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "bundle,commit" {
		t.Fatalf("inputs = %v, want bundle and commit", names)
	}

	// No coupling to other workflows or to application release state.
	for _, banned := range []string{
		"workflow_call", "workflow_run", "release-please", "release_created", "tag_name",
		"publish.yml", "image.yml", "charts.yml", "test.yml", "gh workflow", "gh release",
		"check-version", "Chart.yaml", "charts/", "image:build", "image:test",
		"cosign", "oras", "docker", "helm", "attest", "ghcr.io",
	} {
		if strings.Contains(raw, banned) {
			t.Errorf("workflow references %q", banned)
		}
	}
	if regexp.MustCompile(`\bVERSION\b`).MatchString(raw) {
		t.Error("workflow references the application VERSION file")
	}

	// Least privilege: read-only by default; only the tag job may write, and
	// only repository contents (no packages, OIDC or attestations yet).
	if len(w.Permissions) != 1 || w.Permissions["contents"] != "read" {
		t.Errorf("workflow permissions = %v, want contents: read", w.Permissions)
	}
	if len(w.Jobs) != 2 {
		t.Fatalf("jobs = %d, want package and tag", len(w.Jobs))
	}
	for name, job := range w.Jobs {
		if job.Uses != "" {
			t.Errorf("job %s calls reusable workflow %s", name, job.Uses)
		}
		if job.If != "github.ref == 'refs/heads/main'" {
			t.Errorf("job %s if = %q, want dispatch on main only", name, job.If)
		}
		want := map[string]string{"contents": "read"}
		if name == "tag" {
			want = map[string]string{"contents": "write"}
		}
		if len(job.Permissions) != len(want) || job.Permissions["contents"] != want["contents"] {
			t.Errorf("job %s permissions = %v, want %v", name, job.Permissions, want)
		}
		for _, step := range job.Steps {
			// Dispatch inputs reach scripts only through env, never by
			// expression interpolation into shell.
			if strings.Contains(step.Run, "${{") {
				t.Errorf("job %s interpolates an expression into run: %q", name, step.Run)
			}
			if strings.HasPrefix(step.Uses, "actions/checkout@") {
				persist := step.With["persist-credentials"]
				if (name == "tag") != (persist == true) {
					t.Errorf("job %s persist-credentials = %v; only the tag job may keep a token", name, persist)
				}
				if step.With["fetch-depth"] != 0 {
					t.Errorf("job %s needs full history for ancestry and tags", name)
				}
			}
			if step.Uses != "" && !strings.HasPrefix(step.Uses, "./") && !regexp.MustCompile(`@[0-9a-f]{40}$`).MatchString(strings.Fields(step.Uses)[0]) {
				t.Errorf("job %s uses unpinned action %s", name, step.Uses)
			}
		}
	}
	if needs, _ := w.Jobs["tag"].Needs.(string); needs != "package" {
		t.Errorf("tag job needs = %v, want package (tag only after the source packages)", w.Jobs["tag"].Needs)
	}

	// Releases of one bundle are serialized and never cancelled midway.
	if w.Concurrency.Group != "bundle-release-${{ inputs.bundle }}" || w.Concurrency.CancelInProgress != false {
		t.Errorf("concurrency = %+v, want per-bundle group without cancel-in-progress", w.Concurrency)
	}
	// pipefail, so a failing tool piped into tee still fails the step.
	if w.Defaults["run"]["shell"] != "bash" {
		t.Errorf("defaults.run.shell = %q, want bash", w.Defaults["run"]["shell"])
	}
}

// The application release workflows do not trigger on or call the bundle
// release, and none of them runs on bundle tags.
func TestApplicationWorkflowsIgnoreBundleReleases(t *testing.T) {
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "bundle-release.yml" || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		w, raw := loadWorkflow(t, e.Name())
		if strings.Contains(raw, "bundle-release") {
			t.Errorf("%s references the bundle release workflow", e.Name())
		}
		if push, ok := w.On["push"].(map[string]any); ok {
			if _, ok := push["tags"]; ok {
				t.Errorf("%s runs on pushed tags; bundle tags must not start application releases", e.Name())
			}
		}
	}
}
