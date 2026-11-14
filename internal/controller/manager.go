package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	bundlecontent "github.com/backend-bunny/Konstapel/internal/bundle/content"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/capability"
	"github.com/backend-bunny/Konstapel/internal/exception"
	"github.com/backend-bunny/Konstapel/internal/observability"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Leader election and its events live in the controller's namespace. The
// pinned client-go LeaseLock only gets, creates and updates the one Lease
// LeaderElectionID: acquisition, renewal, takeover after expiry and release
// on cancel (disabled here) are get+update, and the first candidate creates
// it. Nothing lists, watches, patches or deletes Leases. Create cannot be
// restricted by name (the authorizer sees no name), so it is a separate
// rule; get and update are limited to the one Lease. The election's event
// recorder writes core Events about the Lease (create, patch for repeats).
// +kubebuilder:rbac:groups=coordination.k8s.io,namespace=konstapel-system,resources=leases,verbs=create
// +kubebuilder:rbac:groups=coordination.k8s.io,namespace=konstapel-system,resources=leases,resourceNames=konstapel-controller-leader-election,verbs=get;update
// +kubebuilder:rbac:groups="",namespace=konstapel-system,resources=events,verbs=create;patch

// ProfileRefIndex indexes ComplianceBindings by spec.profileRef.name.
const ProfileRefIndex = "spec.profileRef.name"

// LeaderElectionID is the Lease every controller pod of the installation
// shares in the controller namespace, across replicas and supported
// runtime revisions. It never includes a pod name, image, or chart version;
// each candidate process has its own holder identity.
const LeaderElectionID = "konstapel-controller-leader-election"

// Default election timings (controller-runtime's conventional values).
const (
	DefaultLeaseDuration = 15 * time.Second
	DefaultRenewDeadline = 10 * time.Second
	DefaultRetryPeriod   = 2 * time.Second
)

// DefaultShutdownTimeout is the controller's overall shutdown budget: after
// a termination signal or leadership loss, runnables have this long to stop
// before the process exits, within the pod's 60s termination grace.
const DefaultShutdownTimeout = 45 * time.Second

// electionJitter is client-go's leader election jitter factor: the renew
// deadline must exceed it times the retry period.
const electionJitter = 1.2

// Election holds the leader-election timings.
type Election struct {
	LeaseDuration, RenewDeadline, RetryPeriod time.Duration
}

// Validate checks the timings before startup, with client-go's ordering:
// positive, lease duration > renew deadline > 1.2 x retry period.
func (e Election) Validate() error {
	switch {
	case e.LeaseDuration <= 0 || e.RenewDeadline <= 0 || e.RetryPeriod <= 0:
		return fmt.Errorf("leader election timings must be positive (lease %s, renew %s, retry %s)", e.LeaseDuration, e.RenewDeadline, e.RetryPeriod)
	case e.LeaseDuration <= e.RenewDeadline:
		return fmt.Errorf("leader election lease duration %s must exceed the renew deadline %s", e.LeaseDuration, e.RenewDeadline)
	case float64(e.RenewDeadline) <= electionJitter*float64(e.RetryPeriod):
		return fmt.Errorf("leader election renew deadline %s must exceed %.1f x the retry period %s", e.RenewDeadline, electionJitter, e.RetryPeriod)
	}
	return nil
}

func (e Election) withDefaults() Election {
	if e.LeaseDuration == 0 {
		e.LeaseDuration = DefaultLeaseDuration
	}
	if e.RenewDeadline == 0 {
		e.RenewDeadline = DefaultRenewDeadline
	}
	if e.RetryPeriod == 0 {
		e.RetryPeriod = DefaultRetryPeriod
	}
	return e
}

// Options configure the targeting manager.
type Options struct {
	Content                 targeting.ContentSource
	MetricsAddr             string
	ProbeAddr               string
	LeaderElection          bool
	LeaderElectionNamespace string
	// Election overrides the default timings; zero fields keep defaults.
	Election Election
	// ShutdownTimeout bounds shutdown; zero means DefaultShutdownTimeout.
	ShutdownTimeout time.Duration
	// Stopping reports that termination has begun; readiness then fails so
	// the replica leaves service endpoints while it drains. Nil never stops.
	Stopping func() bool
	// SkipControllerNameValidation allows a second manager in the same
	// process. Only tests that restart the manager in-process set it.
	SkipControllerNameValidation bool
	// EnginePoll is how often discovery is retried until the engine API is
	// served, and how long an availability answer is cached.
	EnginePoll time.Duration
	// WebhookCertDir holds tls.crt and tls.key for the exception admission
	// webhooks. Empty serves no webhooks and starts no webhook server.
	WebhookCertDir string
	// WebhookPort is the webhook server's port; 0 means 9443.
	WebhookPort int
	// SnapshotNamespace holds acceptance snapshots; empty means
	// DefaultSnapshotNamespace.
	SnapshotNamespace string
	// LocalBundle is the bundle name Content serves (the image's vendored
	// bundle). When set, Content is wrapped in a stack.Router that serves
	// that name from Content exactly as before and every other name from
	// verified OCI content (Bundles enabled) or as a Config ContentError
	// (disabled). Empty uses Content as is.
	LocalBundle string
	// Bundles configures OCI bundle sources; the zero value is disabled and
	// constructs nothing.
	Bundles stack.Options
	// Observability holds the owner projections served as Prometheus
	// metrics. Its leadership term follows this manager's election. The
	// caller registers it once per process in the metrics registry. Nil
	// adds nothing.
	Observability *observability.Hub
}

// Scheme returns the scheme the manager uses.
func Scheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilMust(clientgoscheme.AddToScheme(s))
	utilMust(v1alpha1.AddToScheme(s))
	return s
}

// NewManager builds the targeting manager. It does not need the engine to
// be installed: the engine API is discovered while running, and the
// owned-policy watch starts once it is served.
func NewManager(cfg *rest.Config, opts Options) (manager.Manager, error) {
	if opts.EnginePoll == 0 {
		opts.EnginePoll = 15 * time.Second
	}
	election := opts.Election.withDefaults()
	if err := election.Validate(); err != nil {
		return nil, err
	}
	shutdown := opts.ShutdownTimeout
	if shutdown == 0 {
		shutdown = DefaultShutdownTimeout
	}
	if shutdown < 0 {
		return nil, fmt.Errorf("shutdown timeout %s must be positive", shutdown)
	}
	mopts := ctrl.Options{
		Scheme:                  Scheme(),
		Metrics:                 metricsserver.Options{BindAddress: opts.MetricsAddr},
		HealthProbeBindAddress:  opts.ProbeAddr,
		LeaderElection:          opts.LeaderElection,
		LeaderElectionID:        LeaderElectionID,
		LeaderElectionNamespace: opts.LeaderElectionNamespace,
		LeaseDuration:           &election.LeaseDuration,
		RenewDeadline:           &election.RenewDeadline,
		RetryPeriod:             &election.RetryPeriod,
		// The Lease is not released early: expiry bounds the wait while
		// shutdown may still be draining mutating work.
		LeaderElectionReleaseOnCancel: false,
		GracefulShutdownTimeout:       &shutdown,
		Controller:                    config.Controller{SkipNameValidation: &opts.SkipControllerNameValidation},
	}
	if opts.WebhookCertDir != "" {
		mopts.WebhookServer = webhook.NewServer(webhook.Options{Port: opts.WebhookPort, CertDir: opts.WebhookCertDir, CertName: "tls.crt", KeyName: "tls.key"})
	}
	mgr, err := ctrl.NewManager(cfg, mopts)
	if err != nil {
		return nil, err
	}
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return nil, err
	}
	if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
		return nil, err
	}
	if opts.Stopping != nil {
		if err := mgr.AddReadyzCheck("shutdown", func(*http.Request) error {
			if opts.Stopping() {
				return errors.New("shutting down")
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	if opts.Observability != nil {
		if err := mgr.Add(observability.Leadership{Hub: opts.Observability}); err != nil {
			return nil, err
		}
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.ComplianceBinding{}, ProfileRefIndex, func(o client.Object) []string {
		return []string{o.(*v1alpha1.ComplianceBinding).Spec.ProfileRef.Name}
	}); err != nil {
		return nil, err
	}

	// One content source for every consumer: reconcilers, assessments and
	// admission webhooks all receive this same instance.
	content, bundles, err := setupBundles(mgr, opts, func(o crcache.Options) (crcache.Cache, error) {
		o.Scheme, o.Mapper, o.HTTPClient = mgr.GetScheme(), mgr.GetRESTMapper(), mgr.GetHTTPClient()
		return crcache.New(mgr.GetConfig(), o)
	})
	if err != nil {
		return nil, err
	}
	opts.Content = content
	if bundles != nil {
		if err := bundles.stack.CompatibilityProblem(); err != nil {
			log.Log.WithName("bundle-sources").Info("controller version cannot satisfy bundle compatibility; every OCI bundle is unavailable as a configuration error", "version", opts.Bundles.ControllerVersion, "reason", err.Error())
		}
	}

	// The cluster identity is the assessment loop's: kube-system's UID.
	ks := &corev1.Namespace{}
	if err := mgr.GetAPIReader().Get(context.Background(), client.ObjectKey{Name: "kube-system"}, ks); err != nil {
		return nil, fmt.Errorf("read cluster identity: %w", err)
	}
	// Discovery calls are bounded; capability results are reused for one
	// poll interval, so a returning engine is noticed within it.
	dcfg := rest.CopyConfig(cfg)
	dcfg.Timeout = capabilityTimeout
	dc, err := discovery.NewDiscoveryClientForConfig(dcfg)
	if err != nil {
		return nil, err
	}
	reviewer, err := client.New(dcfg, client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		return nil, err
	}
	capabilities := &capability.Monitor{Discovery: dc, Review: capability.SelfReview(reviewer), Timeout: capabilityTimeout, TTL: opts.EnginePoll}
	engine := capabilities.Engine(capability.Delivery)
	reports := capabilities.Engine(capability.Assessment)
	// A capability change (an engine installed, removed, or its permissions
	// changed) re-reconciles every binding, so Conditions stay truthful
	// although a Ready binding is otherwise not requeued.
	deliveryEvents := make(chan event.GenericEvent)
	assessmentEvents := make(chan event.GenericEvent)
	if err := mgr.Add(&capabilityTrigger{name: "capability-trigger", client: mgr.GetClient(), poll: opts.EnginePoll,
		checks: []EngineAvailable{engine, reports}, out: []chan<- event.GenericEvent{deliveryEvents, assessmentEvents}}); err != nil {
		return nil, err
	}

	br, pr := targetingReconcilers(mgr.GetClient(), mgr.GetAPIReader(), opts.Content, engine, "kube-system:"+string(ks.UID))
	bb := builder.ControllerManagedBy(mgr).
		Named("compliancebinding").
		For(&v1alpha1.ComplianceBinding{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&v1alpha1.ComplianceProfile{}, handler.EnqueueRequestsFromMapFunc(bindingsForProfile(mgr.GetClient())), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.Namespace{}, namespaceHandler(mgr.GetClient())).
		WatchesRawSource(source.Channel(deliveryEvents, &handler.EnqueueRequestForObject{}))
	pb := builder.ControllerManagedBy(mgr).Named("complianceprofile").
		For(&v1alpha1.ComplianceProfile{}, builder.WithPredicates(predicate.GenerationChangedPredicate{}))
	if bundles != nil {
		// Source configuration, trust and referenced-object changes
		// re-reconcile the affected profiles and their bindings.
		bb = bb.WatchesRawSource(source.Channel(bundles.bindingEvents, handler.EnqueueRequestsFromMapFunc(bindingsForProfile(mgr.GetClient()))))
		pb = pb.WatchesRawSource(source.Channel(bundles.profileEvents, &handler.EnqueueRequestForObject{}))
	}
	bc, err := bb.Build(br)
	if err != nil {
		return nil, err
	}
	if err := pb.Complete(pr); err != nil {
		return nil, err
	}
	owned := &unstructured.Unstructured{}
	owned.SetGroupVersionKind(targeting.ValidatingPolicyGVK)
	if err := mgr.Add(&deferredWatch{name: "owned-policy-watch", available: engine, poll: opts.EnginePoll, register: func() error {
		// Only engine policies Konstapel manages are cached.
		managed := predicate.NewPredicateFuncs(func(o client.Object) bool {
			return o.GetLabels()[targeting.LabelManagedBy] == targeting.ManagedByValue
		})
		return bc.Watch(source.Kind(mgr.GetCache(), client.Object(owned),
			handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &v1alpha1.ComplianceBinding{}, handler.OnlyControllerOwner()), managed))
	}}); err != nil {
		return nil, err
	}
	var observeRun RunObserver
	if hub := opts.Observability; hub != nil {
		observeRun = RunObserver{Publication: observeOperation(hub, observability.OperationEvidencePublication),
			Cleanup: observeOperation(hub, observability.OperationEvidenceCleanup)}
		if err := setupObservability(mgr, hub, capabilities, bundles, opts.Bundles); err != nil {
			return nil, err
		}
	}
	if err := setupAssessments(mgr, opts.Content, engine, reports, assessmentEvents, br.Cluster, opts.EnginePoll, observeRun); err != nil {
		return nil, err
	}
	if err := setupExceptions(mgr, opts.SnapshotNamespace); err != nil {
		return nil, err
	}
	if err := setupAttachments(mgr, attachmentBaselines(opts.Content, currentRuntime())); err != nil {
		return nil, err
	}
	if opts.WebhookCertDir != "" {
		// Admission runs on every replica; the server needs no leader. It
		// reads through the API reader so acceptance sees current configuration.
		m, v := exception.NewHandlers(mgr.GetScheme(), mgr.GetAPIReader(), opts.Content, br.Cluster)
		exception.Register(mgr.GetWebhookServer(), m, v)
	}
	return mgr, nil
}

// targetingReconcilers builds the binding and profile reconcilers over one
// content source. Both give rejected parameters of content that declares a
// parameter contract (OCI bundles) a precise reason; content without one
// (LocalContent) is unaffected.
func targetingReconcilers(c client.Client, r client.Reader, content targeting.ContentSource, engine EngineAvailable, cluster string) (*BindingReconciler, *ProfileReconciler) {
	return &BindingReconciler{Client: c, Reader: r, Content: content, Engine: engine, Cluster: cluster, ValidateParameters: bundlecontent.ValidateParameters},
		&ProfileReconciler{Client: c, Content: content, ValidateParameters: bundlecontent.ValidateParameters}
}

// capabilityTimeout bounds each discovery and authorization request.
const capabilityTimeout = 10 * time.Second

// SelfSubjectAccessReviews check the controller's own permissions for each
// capability.
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=selfsubjectaccessreviews,verbs=create

// deferredWatch registers one watch once its capability is available, so the
// manager starts without the engine and reports why. It registers its source
// exactly once; afterwards the informer itself re-lists and re-watches when
// the API is removed and restored.
type deferredWatch struct {
	name      string
	available EngineAvailable
	register  func() error
	poll      time.Duration
}

func (w *deferredWatch) NeedLeaderElection() bool { return true }

func (w *deferredWatch) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName(w.name)
	t := time.NewTicker(w.poll)
	defer t.Stop()
	for {
		if ok, err := w.available(ctx); ok {
			if err := w.register(); err == nil {
				logger.Info("watch started")
				<-ctx.Done()
				return nil
			} else {
				logger.Info("could not start watch; retrying", "error", err.Error())
			}
		} else if err != nil {
			logger.Info("waiting for capability", "reason", capability.ReasonOf(err), "message", err.Error())
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// capabilityTrigger polls capabilities and, whenever any result changes,
// sends every ComplianceBinding to each output, so the dependent
// controllers re-evaluate.
type capabilityTrigger struct {
	name   string
	client client.Client
	checks []EngineAvailable
	out    []chan<- event.GenericEvent
	poll   time.Duration
}

func (t *capabilityTrigger) NeedLeaderElection() bool { return true }

func (t *capabilityTrigger) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName(t.name)
	ticker := time.NewTicker(t.poll)
	defer ticker.Stop()
	var last string
	for {
		var state []string
		for _, check := range t.checks {
			if _, err := check(ctx); err != nil {
				state = append(state, string(capability.ReasonOf(err))+":"+err.Error())
			} else {
				state = append(state, string(capability.Available))
			}
		}
		if s := strings.Join(state, "|"); s != last {
			if last != "" {
				logger.Info("capabilities changed; re-reconciling bindings", "capabilities", s)
			}
			last = s
			var list v1alpha1.ComplianceBindingList
			if err := t.client.List(ctx, &list); err != nil {
				last = "" // retry the notification next time
			} else {
				for i := range list.Items {
					for _, ch := range t.out {
						select {
						case ch <- event.GenericEvent{Object: &list.Items[i]}:
						case <-ctx.Done():
							return nil
						}
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// capabilityMessage is the message of a capability check result.
func capabilityMessage(err error) string {
	if err == nil {
		return "unavailable"
	}
	return err.Error()
}

func bindingsForProfile(c client.Client) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		var list v1alpha1.ComplianceBindingList
		if err := c.List(ctx, &list, client.MatchingFields{ProfileRefIndex: o.GetName()}); err != nil {
			return nil
		}
		return requests(list.Items)
	}
}

// namespaceHandler enqueues only bindings whose selector matches the
// namespace's old or new labels. Namespace events never change engine
// policies (the selector is rendered, not expanded), only status.
func namespaceHandler(c client.Client) handler.EventHandler {
	enqueue := func(ctx context.Context, q workqueue.TypedRateLimitingInterface[reconcile.Request], sets ...labels.Set) {
		var list v1alpha1.ComplianceBindingList
		if err := c.List(ctx, &list); err != nil {
			return
		}
		var hit []v1alpha1.ComplianceBinding
		for _, b := range list.Items {
			sel, err := b.Spec.NamespaceSelector.AsSelector()
			if err != nil {
				hit = append(hit, b) // let the reconciler report the invalid selector
				continue
			}
			for _, s := range sets {
				if sel.Matches(s) {
					hit = append(hit, b)
					break
				}
			}
		}
		for _, r := range requests(hit) {
			q.Add(r)
		}
	}
	return handler.Funcs{
		CreateFunc: func(ctx context.Context, e event.CreateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			enqueue(ctx, q, e.Object.GetLabels())
		},
		UpdateFunc: func(ctx context.Context, e event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			if labels.Equals(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels()) &&
				e.ObjectOld.GetDeletionTimestamp().IsZero() == e.ObjectNew.GetDeletionTimestamp().IsZero() {
				return
			}
			enqueue(ctx, q, e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels())
		},
		DeleteFunc: func(ctx context.Context, e event.DeleteEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			enqueue(ctx, q, e.Object.GetLabels())
		},
	}
}

func requests(bs []v1alpha1.ComplianceBinding) []reconcile.Request {
	out := make([]reconcile.Request, 0, len(bs))
	for _, b := range bs {
		out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: b.Name}})
	}
	return out
}

func utilMust(err error) {
	if err != nil {
		panic(err)
	}
}

func isNotFound(err error) bool {
	return apierrors.IsNotFound(err) || discovery.IsGroupDiscoveryFailedError(err)
}
