package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/controller"
	"github.com/backend-bunny/Konstapel/internal/observability"
	"github.com/backend-bunny/Konstapel/internal/provider"
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

// collectionFlags are the host's evidence collection limits
// (docs/assessment-providers.md, "Collection limits"). Their defaults are
// provider.DefaultLimits. The deadline is not a flag: it is each binding's
// spec.assessment.collectionTimeout.
type collectionFlags struct {
	pageSize, maxBytes  *int64
	maxRequests, maxObj *int
}

func addCollectionFlags(fs *flag.FlagSet) collectionFlags {
	return collectionFlags{
		pageSize:    fs.Int64("collection-page-size", provider.DefaultPageSize, fmt.Sprintf("objects per list request of one evidence collection (1 to %d, at most --collection-max-objects)", provider.MaxPageSize)),
		maxRequests: fs.Int("collection-max-requests", provider.DefaultMaxPages, fmt.Sprintf("list requests of one evidence collection (at most %d, at least the pages --collection-max-objects takes)", provider.MaxConfiguredPages)),
		maxObj:      fs.Int("collection-max-objects", provider.DefaultMaxObjects, fmt.Sprintf("objects one evidence collection reads (1 to %d); a collection that needs more is incomplete", provider.MaxConfiguredObjects)),
		maxBytes:    fs.Int64("collection-max-bytes", provider.DefaultMaxBytes, fmt.Sprintf("bytes of object JSON one evidence collection reads (%d to %d, and at least --collection-page-size x %d); decoded objects take about 2.4 times this, so size it with the controller's memory limit", provider.MinMaxBytes, provider.MaxConfiguredBytes, provider.MinObjectBytes)),
	}
}

// limits validates the collection flags. Out-of-range values fail startup.
func (c collectionFlags) limits() (provider.Limits, error) {
	l := provider.Limits{PageSize: *c.pageSize, MaxPages: *c.maxRequests, MaxObjects: *c.maxObj, MaxBytes: *c.maxBytes}
	if err := l.ValidateConfiguration(); err != nil {
		return provider.Limits{}, fmt.Errorf("collection limits: %w", err)
	}
	return l, nil
}

// noReaders is the --protected-package-readers value for an installation
// without a Konstapel download service.
const noReaders = "none"

// readerCheck builds the protected-package reader check from
// --protected-package-readers (add-supporting-evidence-attachments 7.1):
// empty leaves it unconfigured (platform packages then carry no supporting
// evidence), "none" declares that no Konstapel download service is
// deployed, and a name is the download Deployment in the controller's
// namespace, verified to run this controller's image (POD_NAME).
func readerCheck(value, namespace, pod string, reader client.Reader) (func(context.Context) error, error) {
	switch {
	case value == "":
		return nil, nil
	case value == noReaders:
		return controller.NoProtectedReaders, nil
	case len(validation.IsDNS1123Subdomain(value)) > 0:
		return nil, fmt.Errorf("--protected-package-readers %q must be %q or the name of the download Deployment", value, noReaders)
	case namespace == "" || pod == "":
		return nil, fmt.Errorf("--protected-package-readers=%s needs POD_NAMESPACE and POD_NAME to find this controller's image", value)
	}
	return controller.DeployedReaders{Reader: reader, Namespace: namespace, Deployment: value, Pod: pod}.Verify, nil
}

// runController runs the targeting manager: `konstapel controller [flags]`.
// It uses in-cluster configuration, or KUBECONFIG/--kubeconfig outside a cluster.
func runController(args []string) error {
	fs := flag.NewFlagSet("controller", flag.ContinueOnError)
	root := fs.String("content-root", "/usr/share/konstapel/content", "directory with the vendored content and its SHA256SUMS")
	metrics := fs.String("metrics-bind-address", "0", "HTTPS metrics address, authenticated with TokenReview and authorized with SubjectAccessReview; \"0\" disables the metrics server")
	metricsCertDir := fs.String("metrics-cert-dir", "", "directory with tls.crt, tls.key and ca.crt for the metrics server; required when it serves")
	metricsServerName := fs.String("metrics-server-name", "", "name the metrics certificate must cover, such as konstapel-controller-metrics.<namespace>.svc")
	probes := fs.String("health-probe-bind-address", ":8081", "address for /healthz and /readyz")
	leader := fs.Bool("leader-elect", true, "use a Lease so only one replica reconciles")
	leaseDuration := fs.Duration("leader-election-lease-duration", controller.DefaultLeaseDuration, "how long a non-leader waits before taking over an unrenewed Lease")
	renewDeadline := fs.Duration("leader-election-renew-deadline", controller.DefaultRenewDeadline, "how long the leader retries renewing before giving up leadership")
	retryPeriod := fs.Duration("leader-election-retry-period", controller.DefaultRetryPeriod, "how often candidates try to acquire or renew the Lease")
	shutdown := fs.Duration("shutdown-timeout", controller.DefaultShutdownTimeout, "overall shutdown budget after a termination signal or leadership loss; keep it below the pod's termination grace")
	staging := fs.String("evidence-staging-dir", "/var/lib/konstapel/staging", "writable directory for captures and packages awaiting publication")
	webhookCerts := fs.String("webhook-cert-dir", "", "directory with tls.crt and tls.key for the ComplianceException admission webhooks; empty serves none")
	webhookPort := fs.Int("webhook-port", 9443, "admission webhook HTTPS port")
	revocation := fs.Bool("exception-revocation-processing", false, "persist ComplianceException revocation records and release their finalizer; needs --webhook-cert-dir, the exception admission webhooks registered with failurePolicy Fail, and the gated config/rbac/controller/exception-revocation.yaml grant. Off by default")
	leaderNS := fs.String("leader-election-namespace", os.Getenv("POD_NAMESPACE"), "namespace of the leader-election Lease (defaults to the pod namespace)")
	externalCerts := fs.String("external-provider-client-cert-dir", "", "directory with tls.crt and tls.key: the controller's client certificate for registered external assessment providers (AssessmentProvider). Setting it probes registrations over mutual TLS and lets new work select them; empty (the default) watches, contacts and selects no external provider")
	readers := fs.String("protected-package-readers", "", "the download Deployment (in the pod namespace) that must run this controller's image before platform packages carry supporting evidence, or \"none\" without a download service; empty carries none")
	bundleOpts := addBundleFlags(fs)
	collection := addCollectionFlags(fs)
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
	collectionLimits, err := collection.limits()
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
	// Uncached: a stale cache could miss a reader rollout.
	uncached, err := client.New(cfg, client.Options{Scheme: controller.Scheme()})
	if err != nil {
		return err
	}
	rt.ProtectedReaders, err = readerCheck(*readers, os.Getenv("POD_NAMESPACE"), os.Getenv("POD_NAME"), uncached)
	if err != nil {
		return err
	}
	if rt.ProtectedReaders == nil {
		ctrl.Log.Info("--protected-package-readers is not set: platform packages carry no supporting evidence (ProtectedReadersUnverified)")
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
		MetricsTLS:              &controller.MetricsTLS{CertDir: *metricsCertDir, ServerName: *metricsServerName},
		ProbeAddr:               *probes,
		LeaderElection:          *leader,
		LeaderElectionNamespace: *leaderNS,
		Election:                controller.Election{LeaseDuration: *leaseDuration, RenewDeadline: *renewDeadline, RetryPeriod: *retryPeriod},
		ShutdownTimeout:         *shutdown,
		Stopping:                func() bool { return ctx.Err() != nil },
		WebhookCertDir:          *webhookCerts,
		WebhookPort:             *webhookPort,
		ExceptionRevocation:     *revocation,
		SnapshotNamespace:       os.Getenv("POD_NAMESPACE"),
		LocalBundle:             VendoredBundle,
		Bundles:                 bundles,
		CollectionLimits:        collectionLimits,
		ExternalProviders:       controller.ExternalProviders{ClientCertDir: *externalCerts},
		Observability:           hub,
	})
	if err != nil {
		return err
	}
	return mgr.Start(ctx)
}
