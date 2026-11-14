package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/controller"
	"github.com/backend-bunny/Konstapel/internal/observability"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// VendoredBundle is the bundle name LocalContent serves the image's
// vendored content under. Profiles pin it with the sha256 of content/SHA256SUMS.
const VendoredBundle = "konstapel-vendored"

// version is the controller release, set at build time by scripts/build.sh
// (-ldflags "-X main.version=<VERSION>"). A development build keeps "dev",
// which is not SemVer: with bundle sources enabled every OCI bundle is then
// unavailable as a configuration error, and startup still succeeds.
var version = "dev"

// bundleFlags are the OCI bundle source flags.
type bundleFlags struct {
	sources, cacheDir, capacity *string
	refresh                     *time.Duration
}

func addBundleFlags(fs *flag.FlagSet) bundleFlags {
	return bundleFlags{
		sources:  fs.String("bundle-sources-configmap", "", "name of the central bundle sources ConfigMap in the controller namespace (POD_NAMESPACE); setting it enables verified OCI bundle content, empty (the default) serves only the vendored bundle"),
		cacheDir: fs.String("bundle-cache-dir", "", "writable directory for the OCI bundle content cache, used by this process only; required with --bundle-sources-configmap"),
		capacity: fs.String("bundle-cache-capacity", "", "OCI bundle cache capacity as a Kubernetes quantity (for example 1Gi); empty means 1Gi"),
		refresh:  fs.Duration("bundle-refresh-interval", stack.DefaultRefreshInterval, "how often Secrets and ConfigMaps referenced by the bundle sources are re-read (at most 5m)"),
	}
}

// options validates the bundle flags. Without --bundle-sources-configmap
// none of the other bundle flags may be given explicitly.
func (b bundleFlags) options(fs *flag.FlagSet, namespace string) (stack.Options, error) {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if *b.sources == "" {
		for _, name := range []string{"bundle-cache-dir", "bundle-cache-capacity", "bundle-refresh-interval"} {
			if set[name] {
				return stack.Options{}, fmt.Errorf("--%s requires --bundle-sources-configmap", name)
			}
		}
		return stack.Options{}, nil
	}
	o := stack.Options{SourcesConfigMap: *b.sources, Namespace: namespace, CacheDir: *b.cacheDir,
		RefreshInterval: *b.refresh, ControllerVersion: version}
	if *b.capacity != "" {
		q, err := resource.ParseQuantity(*b.capacity)
		if err != nil {
			return stack.Options{}, fmt.Errorf("--bundle-cache-capacity %q: %w", *b.capacity, err)
		}
		v, ok := q.AsInt64()
		if !ok || v <= 0 {
			return stack.Options{}, fmt.Errorf("--bundle-cache-capacity %q must be a positive whole number of bytes", *b.capacity)
		}
		o.CacheCapacity = v
	}
	if *b.refresh <= 0 {
		return stack.Options{}, fmt.Errorf("--bundle-refresh-interval %s must be positive", *b.refresh)
	}
	if err := o.Validate(); err != nil {
		return stack.Options{}, err
	}
	return o, nil
}

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
	bundleOpts := addBundleFlags(fs)
	zopts := zap.Options{}
	zopts.BindFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zopts)))
	bundles, err := bundleOpts.options(fs, os.Getenv("POD_NAMESPACE"))
	if err != nil {
		return err
	}
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
	// The metric contract is served next to controller-runtime's collectors.
	// Targeting, assessment and evidence storage always publish
	// projections; bundle resolution only with bundle sources.
	domains := []observability.Domain{observability.DomainTargeting, observability.DomainAssessment, observability.DomainEvidenceStorage}
	if bundles.Enabled() {
		domains = append(domains, observability.DomainBundleResolution)
	}
	hub, err := observability.NewHub(observability.Options{Enabled: domains})
	if err != nil {
		return err
	}
	if err := ctrlmetrics.Registry.Register(hub); err != nil {
		return fmt.Errorf("register metrics: %w", err)
	}
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
		LocalBundle:             VendoredBundle,
		Bundles:                 bundles,
		Observability:           hub,
	})
	if err != nil {
		return err
	}
	return mgr.Start(ctx)
}
