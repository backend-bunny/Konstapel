package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var (
	docFiles   = regexp.MustCompile(`<!-- preview-files: ([^>]*) -->`)
	docRun     = regexp.MustCompile("(?s)<!-- preview-run: exit=(\\d) -->\n```sh\n(.*?)```\n")
	docOutput  = regexp.MustCompile("(?s)<!-- preview-output -->\n```text\n(.*?)```\n")
	docFields  = regexp.MustCompile("(?s)<!-- report-fields -->\n(.*?)\n\n")
	docFlagRow = regexp.MustCompile("(?m)^\\| (`-[^|]*) \\|")
	backticked = regexp.MustCompile("`([^`]+)`")
)

// TestDocumentedPreviewCommands runs the local and CI examples of
// docs/policy-preview.md exactly as written (task 6.4), against the cluster
// the page describes: every documented command line, its exit status, the
// text excerpt, the jq expressions on the saved JSON, the report field table
// and the flag table.
func TestDocumentedPreviewCommands(t *testing.T) {
	raw, err := os.ReadFile("../../docs/policy-preview.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	content, err := filepath.Abs("../../content")
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeCluster(t)
	t.Setenv("KUBECONFIG", f.kubeconfig(t))
	work := t.TempDir()
	m := docFiles.FindStringSubmatch(doc)
	if m == nil {
		t.Fatal("no preview-files mapping")
	}
	for _, pair := range strings.Fields(m[1]) {
		name, src, _ := strings.Cut(pair, "=")
		data, err := os.ReadFile("../../" + src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(work, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(content, filepath.Join(work, "content")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	jq, _ := exec.LookPath("jq")

	blocks := docRun.FindAllStringSubmatch(doc, -1)
	if fences := strings.Count(doc, "```sh\n"); len(blocks) < 3 || fences != len(blocks) {
		t.Fatalf("%d sh fences, %d verified blocks", fences, len(blocks))
	}
	var firstText string
	for _, b := range blocks {
		want := int(b[1][0] - '0')
		for _, line := range strings.Split(strings.ReplaceAll(b[2], "\\\n", " "), "\n") {
			line = strings.TrimSpace(line)
			switch {
			case line == "":
			case strings.HasPrefix(line, "bin/konstapel preview "):
				if strings.ContainsAny(line, `"'$|;&<>`) {
					t.Fatalf("documented command needs a shell: %s", line)
				}
				res := runCLI(t, "", strings.Fields(line)[2:]...)
				if res.code != want {
					t.Fatalf("%s: exit %d, documented %d\n%s%s", line, res.code, want, res.stderr, res.stdout)
				}
				if firstText == "" && !strings.Contains(line, "--format json") {
					firstText = res.stdout
				}
			case strings.HasPrefix(line, "jq "):
				if jq == "" {
					t.Logf("jq not on PATH (it is in the Devbox environment); skipped: %s", line)
					continue
				}
				out, err := exec.Command("sh", "-c", line).CombinedOutput()
				if err != nil {
					t.Fatalf("%s: %v\n%s", line, err, out)
				}
			default:
				t.Fatalf("unverified documented command: %s", line)
			}
		}
	}

	// The text excerpt is an ordered subsequence of the local report.
	ex := docOutput.FindStringSubmatch(doc)
	if ex == nil || firstText == "" {
		t.Fatal("no documented output excerpt or no local text run")
	}
	got := strings.Split(firstText, "\n")
	i := 0
	for _, want := range strings.Split(strings.TrimSuffix(ex[1], "\n"), "\n") {
		if want == "..." {
			continue
		}
		for i < len(got) && got[i] != want {
			i++
		}
		if i == len(got) {
			t.Fatalf("documented excerpt line not in the report (in order): %q\n%s", want, firstText)
		}
		i++
	}

	// The saved JSON is a v1 report with exactly the documented fields.
	saved, err := os.ReadFile(filepath.Join(work, "preview.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := decodeReport(t, string(saved))
	if !r.Complete || r.ImpactCount == 0 {
		t.Fatalf("saved report: complete %t impacts %d", r.Complete, r.ImpactCount)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(saved, &top); err != nil {
		t.Fatal(err)
	}
	fm := docFields.FindStringSubmatch(doc)
	if fm == nil {
		t.Fatal("no report-fields table")
	}
	var documented []string
	for _, row := range strings.Split(fm[1], "\n")[2:] {
		cell, _, _ := strings.Cut(strings.TrimPrefix(row, "| "), " |")
		for _, n := range backticked.FindAllStringSubmatch(cell, -1) {
			documented = append(documented, n[1])
		}
	}
	var actual []string
	for k := range top {
		actual = append(actual, k)
	}
	slices.Sort(documented)
	slices.Sort(actual)
	if !slices.Equal(documented, actual) {
		t.Errorf("documented report fields %v, report has %v", documented, actual)
	}

	// The flag table lists exactly the command's flags.
	var help bytes.Buffer
	noOtherStartup(t)
	dispatch(context.Background(), []string{"preview", "-h"}, nil, &help, &help)
	var defined []string
	for _, l := range strings.Split(help.String(), "\n") {
		if strings.HasPrefix(l, "  -") {
			name, _, _ := strings.Cut(strings.TrimPrefix(l, "  -"), " ")
			defined = append(defined, name)
		}
	}
	var tabled []string
	for _, row := range docFlagRow.FindAllStringSubmatch(doc, -1) {
		for _, n := range backticked.FindAllStringSubmatch(row[1], -1) {
			tabled = append(tabled, strings.TrimLeft(n[1], "-"))
		}
	}
	slices.Sort(defined)
	slices.Sort(tabled)
	if !slices.Equal(defined, tabled) {
		t.Errorf("documented flags %v, command flags %v", tabled, defined)
	}
}
