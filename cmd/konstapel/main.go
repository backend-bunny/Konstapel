package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/oscal-compass/compliance-to-policy-go/v2/framework/actions"
	"github.com/oscal-compass/compliance-to-policy-go/v2/plugin"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
)

func main() {
	ctx := context.Background()
	if len(os.Args) > 1 && os.Args[1] == "preview" {
		// A closed stdout must be a write error (exit 1), not a SIGPIPE
		// death; an interrupt ends the preview with an incomplete report.
		signal.Ignore(syscall.SIGPIPE)
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
	}
	code := dispatch(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	if code != 0 {
		os.Exit(code)
	}
}

// dispatch selects the command. preview is dispatched first with its own
// exit statuses (0, 1 and 2) and none of the startup below; every other
// command keeps its behavior: an error is printed and exits 1.
func dispatch(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "preview" {
		return runPreview(ctx, args[1:], stdin, stdout, stderr)
	}
	// replay has its own exit statuses too: re-evaluated, unavailable or
	// failed.
	if len(args) > 0 && args[0] == "replay" {
		return runReplay(args[1:], stdout, stderr)
	}
	if err := run(args); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

// Startup hooks of the other commands, replaced in tests to show that the
// preview never reaches them.
var (
	startController = runController
	startProvider   = assessment.StartProvider
)

func run(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: konstapel controller|download-server|evidence|preview|replay|generate|deliver|convert|acceptance|validate [flags]")
	}
	command := args[0]
	if command == "controller" {
		return startController(args[1:])
	}
	if command == "download-server" {
		return runDownload(args[1:])
	}
	// Supporting-evidence documents: Kubernetes API and download service
	// only; the C2P provider below is never started for them.
	if command == "evidence" {
		return runEvidence(args[1:], os.Stdout, os.Stderr)
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	root := fs.String("root", ".", "repository root")
	out := fs.String("output", "artifacts/run", "output package directory")
	manifest := fs.String("provider", "bin/c2p-konstapel-kyverno-manifest.json", "provider manifest")
	action := fs.String("action", "Deny", "Deny or Audit")
	ns := fs.String("namespace", "konstapel-acceptance", "test namespace")
	owner := fs.String("owner", "konstapel-assessment", "owned test run identity")
	capture := fs.String("capture", "", "saved capture path")
	kube := fs.String("kubeconfig", "", "explicit kubeconfig path")
	target := fs.String("context", "", "explicit Kubernetes context")
	timeout := fs.Duration("timeout", 180*time.Second, "bounded wait per phase")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	var err error
	*root, err = filepath.Abs(*root)
	if err != nil {
		return err
	}
	*out, err = filepath.Abs(*out)
	if err != nil {
		return err
	}
	if command == "validate" {
		return assessment.ValidatePackage(*root, *out)
	}
	input, plan, err := assessment.Input(*root)
	if err != nil {
		return err
	}
	cfg := map[string]string{"root": *root, "output": *out, "action": *action, "namespace": *ns, "owner": *owner, "capture": *capture}
	p, err := startProvider(*manifest, cfg)
	if err != nil {
		return err
	}
	defer plugin.Cleanup()
	providers := map[plugin.ID]policy.Provider{plugin.ID(assessment.ProviderID): p}
	ctx := context.Background()
	switch command {
	case "generate":
		return actions.GeneratePolicy(ctx, input, providers)
	case "deliver", "acceptance":
		client, err := assessment.NewTarget(*kube, *target, *timeout)
		if err != nil {
			return err
		}
		if err = actions.GeneratePolicy(ctx, input, providers); err != nil {
			return err
		}
		if command == "deliver" {
			var rendered assessment.Object
			if err = assessment.Read(filepath.Join(*out, "generated/policy.json"), &rendered); err != nil {
				return err
			}
			_, err = client.Deliver(ctx, rendered, *owner)
			return err
		}
		return assessment.Acceptance(ctx, client, *root, *out, *ns, *owner, *timeout, input, plan, p, providers)
	case "convert":
		var c assessment.Capture
		if err = assessment.Read(*capture, &c); err != nil {
			return err
		}
		// The prototype package is derived from a prototype capture only;
		// a continuous package's capture is never re-exported as one.
		if c.Version != 1 {
			return fmt.Errorf("convert re-exports prototype (version 1) captures only; a version %d capture is converted from its package", c.Version)
		}
		results, err := actions.AggregateResults(ctx, input, providers)
		if err != nil {
			return err
		}
		if err = assessment.Export(ctx, *root, *out, input, plan, results, c); err != nil {
			return err
		}
		ev, _, err := assessment.Reconcile(c)
		if err != nil {
			return err
		}
		if !ev.Complete {
			return fmt.Errorf("incomplete evidence; diagnostic package retained in %s", *out)
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}
