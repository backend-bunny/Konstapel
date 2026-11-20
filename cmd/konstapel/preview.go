package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle/content"
	"github.com/backend-bunny/Konstapel/internal/preview"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// `konstapel preview` (add-policy-change-preview group 6). It is dispatched
// before every other command and uses none of their startup: no manager,
// provider subprocess, delivery, metrics server or leader election. It reads
// the cluster with the caller's kubeconfig only and never writes to it.

// Preview exit statuses. Status selection is centralized here so that main
// never collapses the impact outcome into its generic error status.
const (
	exitPreviewOK     = 0
	exitPreviewFailed = 1
	exitPreviewImpact = 2
)

// DefaultControllerNamespace is the namespace the charts install the
// controller into.
const DefaultControllerNamespace = "konstapel-system"

// defaultContentRoot is where the image ships the vendored content, as the
// controller's --content-root default.
const defaultContentRoot = "/usr/share/konstapel/content"

const previewUsage = `Usage: konstapel preview -f FILE [-f FILE ...] [--before FILE ...] [flags]

Preview how rendered ComplianceProfile and ComplianceBinding manifests would
change the selected cluster's compliance configuration, without changing the
cluster. Only discovery, get and list requests are sent, with the caller's own
kubeconfig credentials; there is no in-cluster fallback.

Exit status:
  0  the preview is complete (with or without impacts, unless --fail-on-impact)
  2  the preview is complete, has policy impacts and --fail-on-impact is set
  1  invalid flags or inputs, a failed or incomplete preview, or a report that
     could not be written, regardless of impacts or --fail-on-impact

Flags:
`

// previewNow is the observation clock; tests fix it for golden reports.
var previewNow func() time.Time

type previewInvocation struct {
	opts         preview.RunOptions
	format       string
	output       string
	failOnImpact bool
	timeout      time.Duration
}

// parsePreview parses the preview flags. It returns flag.ErrHelp for -h and
// writes nothing itself: usage and errors are in the returned text.
func parsePreview(args []string) (*previewInvocation, string, error) {
	var msg bytes.Buffer
	fs := flag.NewFlagSet("preview", flag.ContinueOnError)
	fs.SetOutput(&msg)
	var files, before stringList
	fs.Var(&files, "f", "proposed rendered manifest file, repeatable; - reads standard input")
	fs.Var(&files, "file", "same as -f")
	fs.Var(&before, "before", "previous rendered set, repeatable: identities in it and absent from the proposed files are removed")
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig path (default: $KUBECONFIG, then ~/.kube/config)")
	kubeContext := fs.String("context", "", "kubeconfig context (default: the current context)")
	namespace := fs.String("controller-namespace", DefaultControllerNamespace, "namespace of the Konstapel controller (its POD_NAMESPACE)")
	sources := fs.String("bundle-sources-configmap", "", "the controller's --bundle-sources-configmap; pass it explicitly, empty when the controller serves only the vendored bundle")
	controllerVersion := fs.String("controller-version", version, "controller release (SemVer) that OCI bundle compatibility is checked against (defaults to this binary's release)")
	contentRoot := fs.String("content-root", defaultContentRoot, "directory with the vendored content and its SHA256SUMS")
	cacheDir := fs.String("bundle-cache-dir", "", "directory for the verified OCI bundle cache, used by one preview at a time (default: a temporary directory removed afterwards)")
	format := fs.String("format", "text", "report format: text or json")
	output := fs.String("output", "-", "write the report to this file instead of standard output")
	fs.StringVar(output, "o", "-", "same as --output")
	failOnImpact := fs.Bool("fail-on-impact", false, "exit 2 when a complete preview has policy impacts")
	timeout := fs.Duration("timeout", preview.DefaultObserveLimits().Timeout, "total time for the preview, observation recaptures included")
	fs.Usage = func() {
		msg.WriteString(previewUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return nil, msg.String(), err
	}
	fail := func(format string, a ...any) (*previewInvocation, string, error) {
		return nil, "", fmt.Errorf(format, a...)
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	switch {
	case fs.NArg() > 0:
		return fail("unexpected argument %q; name manifest files with -f", fs.Arg(0))
	case len(files) == 0:
		return fail("at least one proposed input (-f/--file) is required; use an empty file to propose removing the --before set")
	case *format != "text" && *format != "json":
		return fail("--format %q must be text or json", *format)
	case *timeout <= 0:
		return fail("--timeout %s must be positive", *timeout)
	case len(validation.IsDNS1123Label(*namespace)) > 0:
		return fail("--controller-namespace %q is not a namespace name", *namespace)
	case *sources != "" && len(validation.IsDNS1123Subdomain(*sources)) > 0:
		return fail("--bundle-sources-configmap %q is not a ConfigMap name", *sources)
	case *sources == "" && set["bundle-cache-dir"]:
		return fail("--bundle-cache-dir requires --bundle-sources-configmap")
	case *contentRoot == "":
		return fail("--content-root must not be empty")
	case *output == "":
		return fail("--output must not be empty; use - for standard output")
	}
	if *sources != "" {
		if err := (content.Compatibility{Controller: *controllerVersion}).Validate(); err != nil {
			return fail("--controller-version: %v; with --bundle-sources-configmap pass the controller's release, for example --controller-version 0.1.0", err)
		}
	}
	dir := *cacheDir
	if dir != "" {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return fail("--bundle-cache-dir: %v", err)
		}
		dir = abs
	}
	inv := &previewInvocation{format: *format, output: *output, failOnImpact: *failOnImpact, timeout: *timeout,
		opts: preview.RunOptions{
			Inputs:     preview.Inputs{Proposed: files, Before: before},
			Kubeconfig: *kubeconfig, Context: *kubeContext,
			ControllerNamespace: *namespace, SourcesConfigMap: *sources, SourcesExplicit: set["bundle-sources-configmap"],
			ObserveLimits: preview.ObserveLimits{Timeout: *timeout},
			Content: preview.ContentOptions{
				Vendored:          targeting.LocalContent{Root: *contentRoot, Name: VendoredBundle, Policies: assessment.ShippedPolicies},
				CacheDir:          dir,
				ControllerVersion: *controllerVersion,
			},
		}}
	return inv, "", nil
}

// previewExit selects the exit status of a written report.
func previewExit(r *preview.Report, failOnImpact bool) int {
	switch {
	case !r.Complete:
		return exitPreviewFailed
	case failOnImpact && r.ImpactCount > 0:
		return exitPreviewImpact
	}
	return exitPreviewOK
}

// encodeReport renders the report in the requested format.
func encodeReport(r *preview.Report, format string) ([]byte, error) {
	if format == "json" {
		return preview.MarshalReport(r)
	}
	return preview.RenderText(r), nil
}

// writeReport writes the whole report or fails; a short or failed write is
// an output error, never a silently truncated report.
func writeReport(data []byte, output string, stdout io.Writer) error {
	if output == "-" {
		_, err := stdout.Write(data)
		return err
	}
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// runPreview runs `konstapel preview` and returns its exit status. Flag
// errors go to stderr only. Once flags are valid, every failure produces an
// incomplete report in the requested format, if it can be written; stdout
// carries only the report and diagnostics go to stderr.
func runPreview(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	inv, usage, err := parsePreview(args)
	if errors.Is(err, flag.ErrHelp) {
		_, _ = io.WriteString(stdout, usage)
		return exitPreviewOK
	}
	if err != nil {
		if usage != "" {
			_, _ = io.WriteString(stderr, usage)
		} else {
			fmt.Fprintf(stderr, "konstapel preview: %v\n", err)
		}
		return exitPreviewFailed
	}
	inv.opts.Stdin, inv.opts.Now = stdin, previewNow
	ctx, cancel := context.WithTimeout(ctx, inv.timeout)
	defer cancel()
	report := preview.Run(ctx, inv.opts)
	data, err := encodeReport(report, inv.format)
	if err != nil {
		fmt.Fprintf(stderr, "konstapel preview: encoding the report: %v\n", err)
		return exitPreviewFailed
	}
	if err := writeReport(data, inv.output, stdout); err != nil {
		fmt.Fprintf(stderr, "konstapel preview: writing the report: %v\n", err)
		return exitPreviewFailed
	}
	code := previewExit(report, inv.failOnImpact)
	switch code {
	case exitPreviewFailed:
		fmt.Fprintf(stderr, "konstapel preview: incomplete: %d error(s); the report lists them\n", len(report.Errors))
	case exitPreviewImpact:
		fmt.Fprintf(stderr, "konstapel preview: %d policy impact(s) with --fail-on-impact\n", report.ImpactCount)
	}
	return code
}
