package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/oscal-compass/compliance-to-policy-go/v2/framework/actions"
	"github.com/oscal-compass/compliance-to-policy-go/v2/plugin"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: konstapel controller|download-server|generate|deliver|convert|acceptance|validate [flags]")
	}
	command := os.Args[1]
	if command == "controller" {
		return runController(os.Args[2:])
	}
	if command == "download-server" {
		return runDownload(os.Args[2:])
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
	if err := fs.Parse(os.Args[2:]); err != nil {
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
	p, err := assessment.StartProvider(*manifest, cfg)
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
