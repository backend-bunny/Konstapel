package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/controller"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// VendoredBundle is the bundle name LocalContent serves the image's
// vendored content under. Profiles pin it with the sha256 of content/SHA256SUMS.
const VendoredBundle = "konstapel-vendored"

// runController runs the targeting manager: `konstapel controller [flags]`.
// It uses in-cluster configuration, or KUBECONFIG/--kubeconfig outside a cluster.
func runController(args []string) error {
	fs := flag.NewFlagSet("controller", flag.ContinueOnError)
	root := fs.String("content-root", "/usr/share/konstapel/content", "directory with the vendored content and its SHA256SUMS")
	metrics := fs.String("metrics-bind-address", "0", "metrics address; \"0\" disables the metrics server")
	probes := fs.String("health-probe-bind-address", ":8081", "address for /healthz and /readyz")
	leader := fs.Bool("leader-elect", true, "use a Lease so only one replica reconciles")
	leaseDuration := fs.Duration("leader-election-lease-duration", controller.DefaultLeaseDuration, "how long a non-leader waits before taking over an unrenewed Lease")
	renewDeadline := fs.Duration("leader-election-renew-deadline", controller.DefaultRenewDeadline, "how long the leader retries renewing before giving up leadership")
	retryPeriod := fs.Duration("leader-election-retry-period", controller.DefaultRetryPeriod, "how often candidates try to acquire or renew the Lease")
	shutdown := fs.Duration("shutdown-timeout", controller.DefaultShutdownTimeout, "overall shutdown budget after a termination signal or leadership loss; keep it below the pod's termination grace")
	staging := fs.String("evidence-staging-dir", "/var/lib/konstapel/staging", "writable directory for captures and packages awaiting publication")
	webhookCerts := fs.String("webhook-cert-dir", "", "directory with tls.crt and tls.key for the ComplianceException admission webhooks; empty serves none")
	webhookPort := fs.Int("webhook-port", 9443, "admission webhook HTTPS port")
	leaderNS := fs.String("leader-election-namespace", os.Getenv("POD_NAMESPACE"), "namespace of the leader-election Lease (defaults to the pod namespace)")
	zopts := zap.Options{}
	zopts.BindFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zopts)))
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("kubernetes configuration: %w", err)
	}
	rt, err := controller.EvidenceRuntime(context.Background(), cfg, controller.EvidenceConfig{
		StagingDir: *staging, ContentDir: *root, Namespace: os.Getenv("POD_NAMESPACE")})
	if err != nil {
		return fmt.Errorf("evidence destination: %w", err)
	}
	controller.ConfigureAssessments(rt)
	// Readiness fails from the termination signal on, while shutdown drains.
	ctx := ctrl.SetupSignalHandler()
	mgr, err := controller.NewManager(cfg, controller.Options{
		Content: targeting.LocalContent{Root: *root, Name: VendoredBundle,
			Policies: assessment.ShippedPolicies},
		MetricsAddr:             *metrics,
		ProbeAddr:               *probes,
		LeaderElection:          *leader,
		LeaderElectionNamespace: *leaderNS,
		Election:                controller.Election{LeaseDuration: *leaseDuration, RenewDeadline: *renewDeadline, RetryPeriod: *retryPeriod},
		ShutdownTimeout:         *shutdown,
		Stopping:                func() bool { return ctx.Err() != nil },
		WebhookCertDir:          *webhookCerts,
		WebhookPort:             *webhookPort,
		SnapshotNamespace:       os.Getenv("POD_NAMESPACE"),
	})
	if err != nil {
		return err
	}
	return mgr.Start(ctx)
}
