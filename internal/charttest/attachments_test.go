package charttest

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/controller"
	"github.com/backend-bunny/Konstapel/internal/download"
)

// argValue returns the value of --name=value in args.
func argValue(args []any, name string) (string, bool) {
	for _, a := range args {
		if v, ok := strings.CutPrefix(a.(string), "--"+name+"="); ok {
			return v, true
		}
	}
	return "", false
}

// renderedLimits reads the download server's attachment flags and its
// temporary storage budget from a render.
func renderedLimits(t *testing.T, docs []map[string]any) (download.AttachmentLimits, int64) {
	t.Helper()
	d := find(docs, "Deployment", "konstapel-download")
	if d == nil {
		t.Fatal("no download Deployment")
	}
	args := at(d, "spec", "template", "spec", "containers", 0, "args").([]any)
	get := func(name string) string {
		v, ok := argValue(args, name)
		if !ok {
			t.Fatalf("download args lack --%s: %v", name, args)
		}
		return v
	}
	var l download.AttachmentLimits
	var err error
	if l.MaxBytes, err = strconv.ParseInt(get("attachment-max-bytes"), 10, 64); err != nil {
		t.Fatal(err)
	}
	if l.Timeout, err = time.ParseDuration(get("attachment-timeout")); err != nil {
		t.Fatal(err)
	}
	if l.MaxConcurrent, err = strconv.Atoi(get("attachment-max-concurrent")); err != nil {
		t.Fatal(err)
	}
	if l.Retention, err = time.ParseDuration(get("attachment-retention")); err != nil {
		t.Fatal(err)
	}
	budget, err := strconv.ParseInt(get("max-temp-bytes"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return l, budget
}

// The download server's attachment limits are chart values whose defaults
// are the server's own, and any accepted value passes the server's startup
// validation (add-supporting-evidence-attachments 7.1).
func TestRuntimeChartAttachmentLimits(t *testing.T) {
	docs, _, err := render(t, "konstapel-system", "image.digest="+digest)
	if err != nil {
		t.Fatal(err)
	}
	l, budget := renderedLimits(t, docs)
	if l != download.DefaultAttachmentLimits() || l.Validate(budget) != nil {
		t.Fatalf("default limits %+v, server defaults %+v", l, download.DefaultAttachmentLimits())
	}
	docs, _, err = render(t, "konstapel-system", "image.digest="+digest, "download.attachments.maxBytes=1073741824", "download.maxTempBytes=2147483648",
		"download.attachments.timeout=60m", "download.attachments.maxConcurrent=64", "download.attachments.retention=26h")
	if err != nil {
		t.Fatal(err)
	}
	l, budget = renderedLimits(t, docs)
	want := download.AttachmentLimits{MaxBytes: 1 << 30, Timeout: time.Hour, MaxConcurrent: 64, Retention: 26 * time.Hour}
	if l != want || l.Validate(budget) != nil {
		t.Fatalf("overridden limits %+v (%v)", l, l.Validate(budget))
	}
	// Values the server would refuse at startup are refused at render.
	for name, set := range map[string][]string{
		"above the temporary budget": {"download.attachments.maxBytes=4096", "download.maxTempBytes=1024"},
		"above the API ceiling":      {"download.attachments.maxBytes=1073741825", "download.maxTempBytes=4294967296"},
		"zero bytes":                 {"download.attachments.maxBytes=0"},
		"timeout above 1h":           {"download.attachments.timeout=61m"},
		"timeout without unit":       {"download.attachments.timeout=300"},
		"fractional timeout":         {"download.attachments.timeout=1.5m"},
		"zero concurrency":           {"download.attachments.maxConcurrent=0"},
		"concurrency above 64":       {"download.attachments.maxConcurrent=65"},
		"zero retention":             {"download.attachments.retention=0h"},
		"retention in days":          {"download.attachments.retention=90d"},
		"unknown value":              {"download.attachments.maxFiles=3"},
	} {
		if _, out, err := render(t, "konstapel-system", append([]string{"image.digest=" + digest}, set...)...); err == nil {
			t.Errorf("%s accepted", name)
		} else if !strings.Contains(out, "download") {
			t.Errorf("%s: %s", name, out)
		}
	}
}

// The controller writes protected packages only while the chart's download
// Deployment runs its own image: the chart names that Deployment, gives the
// controller its pod name, and both containers carry the names and the image
// the check compares. Without a download service no reader exists.
func TestRuntimeChartProtectedPackageReaders(t *testing.T) {
	docs, _, err := render(t, "konstapel-system", "image.digest="+digest)
	if err != nil {
		t.Fatal(err)
	}
	ctl := find(docs, "Deployment", "konstapel-controller")
	dl := find(docs, "Deployment", "konstapel-download")
	cc := at(ctl, "spec", "template", "spec", "containers", 0)
	dc := at(dl, "spec", "template", "spec", "containers", 0)
	readers, _ := argValue(at(cc, "args").([]any), "protected-package-readers")
	env := at(cc, "env").([]any)
	podName := slices.ContainsFunc(env, func(e any) bool {
		return at(e, "name") == "POD_NAME" && at(e, "valueFrom", "fieldRef", "fieldPath") == "metadata.name"
	})
	if readers != "konstapel-download" || !podName || at(cc, "name") != controller.ControllerContainer || at(dc, "name") != controller.DownloadContainer ||
		at(cc, "image") != at(dc, "image") || len(at(dl, "spec", "template", "spec", "containers").([]any)) != 1 {
		t.Fatalf("readers %q, POD_NAME %v, containers %v/%v, images %v/%v", readers, podName, at(cc, "name"), at(dc, "name"), at(cc, "image"), at(dc, "image"))
	}
	docs, _, err = render(t, "konstapel-system", "image.digest="+digest, "download.enabled=false")
	if err != nil {
		t.Fatal(err)
	}
	ctl = find(docs, "Deployment", "konstapel-controller")
	if r, _ := argValue(at(ctl, "spec", "template", "spec", "containers", 0, "args").([]any), "protected-package-readers"); r != "none" || find(docs, "Deployment", "konstapel-download") != nil {
		t.Fatalf("without the download service: readers %q", r)
	}
}
