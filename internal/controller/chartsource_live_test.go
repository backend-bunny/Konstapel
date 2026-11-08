//go:build live

package controller

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// Chart sources for the installed-chart tests. By default they use the
// source charts in this checkout. Release acceptance (scripts/charts/
// acceptance.sh) sets KONSTAPEL_LIVE_CHART_ARCHIVES to the directory of
// frozen archives, so the tests install exactly those bytes and their
// default image digest, never a re-rendered source chart.

var (
	extractOnce sync.Once
	extracted   string
	extractErr  error
)

// frozenCharts reports the frozen archive directory, if any.
func frozenCharts() string { return os.Getenv("KONSTAPEL_LIVE_CHART_ARCHIVES") }

// chartArchive is what Helm installs: the frozen .tgz in release
// acceptance, otherwise the source chart directory.
func chartArchive(t *testing.T, name string) string {
	t.Helper()
	dir := frozenCharts()
	if dir == "" {
		return filepath.Join("../../charts", name)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, name+"-[0-9]*.tgz"))
	if len(matches) != 1 {
		t.Fatalf("frozen chart %s: want one archive in %s, found %v", name, dir, matches)
	}
	return matches[0]
}

// chartDir is a directory with the chart's files, for inspecting templates
// or deriving test copies: the extracted frozen archive in release
// acceptance, otherwise the source chart.
func chartDir(t *testing.T, name string) string {
	t.Helper()
	if frozenCharts() == "" {
		return filepath.Join("../../charts", name)
	}
	extractOnce.Do(func() {
		extracted, extractErr = os.MkdirTemp("", "konstapel-frozen-charts-")
		if extractErr != nil {
			return
		}
		for _, c := range []string{"konstapel-crds", "konstapel"} {
			path := chartArchive(t, c)
			if out, err := exec.Command("tar", "-xzf", path, "-C", extracted).CombinedOutput(); err != nil {
				extractErr = &extractError{path: path, out: string(out), err: err}
				return
			}
		}
	})
	if extractErr != nil {
		t.Fatal(extractErr)
	}
	return filepath.Join(extracted, name)
}

type extractError struct {
	path, out string
	err       error
}

func (e *extractError) Error() string {
	return "extract " + e.path + ": " + e.err.Error() + ": " + e.out
}

// imageValues pins the runtime chart to the image under test. A frozen
// runtime archive already defaults to the verified release digest, so
// release acceptance sets nothing and installs that default.
func imageValues(repo, digest string) []string {
	if frozenCharts() != "" {
		return []string{"--set", "image.pullPolicy=Never"}
	}
	return []string{"--set", "image.repository=" + repo, "--set", "image.digest=" + digest, "--set", "image.pullPolicy=Never"}
}
