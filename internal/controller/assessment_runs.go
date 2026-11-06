package controller

// Assessment run scheduling and execution (add-continuous-assessments group
// 3). The AssessmentReconciler plans each binding's schedule and admits one
// run at a time; the AssessmentRunReconciler executes only the admitted run:
// it freezes scope into a staging capture, collects until collectionTimeout
// or complete evidence, evaluates, exports, publishes, and records the
// outcome, which releases the binding's slot.

// +kubebuilder:rbac:groups=compliance.erenius.io,resources=assessmentruns,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=assessmentruns/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=assessmentrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=assessmentrequests/status,verbs=get;update;patch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/schedule"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// LabelRunBinding labels AssessmentRuns with their binding's UID.
const LabelRunBinding = "compliance.erenius.io/binding-uid"

// AssessmentRuntime configures run execution. Scheduling is enabled only
// when a publisher, a staging directory, and a content root are configured;
// otherwise bindings report scheduled snapshots as disabled.
type AssessmentRuntime struct {
	Publisher publication.Publisher
	// StagingDir holds frozen captures and packages until publication.
	StagingDir string
	// ContentRoot contains the verified content/ tree used for export.
	ContentRoot string
	// Poll is how often a collecting run re-reads evidence.
	Poll time.Duration
	// PublishTimeout bounds publication retries after collection closes.
	PublishTimeout time.Duration
	// Workers bounds concurrently executing runs across all bindings.
	Workers int
	// Ready optionally checks that the publisher's backend supports the
	// required semantics (for example s3store.Publisher.Ready). While it
	// fails, scheduling is disabled with the reason shown on bindings.
	Ready func(context.Context) error
	// ReadyInterval caches a Ready answer (default 5m).
	ReadyInterval time.Duration
	// MaxQueue bounds pending AssessmentRequests per binding (default 100);
	// newer requests beyond it are rejected. Namespace ResourceQuotas on
	// count/assessmentrequests.compliance.erenius.io bound each team.
	MaxQueue int
}

var (
	runtimeMu        sync.Mutex
	assessmentRunCfg AssessmentRuntime
)

// ConfigureAssessments sets the run runtime used by managers built afterwards.
// add-s3-evidence-publishing supplies the production publisher; until then a
// manager has none and scheduling stays explicitly disabled.
func ConfigureAssessments(rt AssessmentRuntime) {
	runtimeMu.Lock()
	defer runtimeMu.Unlock()
	assessmentRunCfg = rt
}

func currentRuntime() AssessmentRuntime {
	runtimeMu.Lock()
	defer runtimeMu.Unlock()
	rt := assessmentRunCfg
	if rt.Poll <= 0 {
		rt.Poll = 15 * time.Second
	}
	if rt.PublishTimeout <= 0 {
		rt.PublishTimeout = 5 * time.Minute
	}
	if rt.Workers <= 0 {
		rt.Workers = 4
	}
	return rt
}

// ready reports whether runs can be executed and published.
func (rt AssessmentRuntime) ready() (bool, string) {
	switch {
	case rt.Publisher == nil:
		return false, "no evidence publisher is configured"
	case rt.StagingDir == "":
		return false, "no staging directory is configured"
	case rt.ContentRoot == "":
		return false, "no content root is configured for export"
	}
	return true, ""
}

func bindingDurations(b *v1alpha1.ComplianceBinding) (interval, timeout, retention time.Duration, err error) {
	a := v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "5m", Retention: "2160h"}
	if b.Spec.Assessment != nil {
		if b.Spec.Assessment.Interval != "" {
			a.Interval = b.Spec.Assessment.Interval
		}
		if b.Spec.Assessment.CollectionTimeout != "" {
			a.CollectionTimeout = b.Spec.Assessment.CollectionTimeout
		}
		if b.Spec.Assessment.Retention != "" {
			a.Retention = b.Spec.Assessment.Retention
		}
	}
	parse := func(d v1alpha1.Duration) time.Duration {
		v, e := time.ParseDuration(string(d))
		if e != nil || v <= 0 {
			err = fmt.Errorf("binding %s: invalid duration %q", b.Name, d)
		}
		return v
	}
	return parse(a.Interval), parse(a.CollectionTimeout), parse(a.Retention), err
}

func runDone(r *v1alpha1.AssessmentRun) bool {
	return r.Status.Phase == v1alpha1.RunCompleted || r.Status.Phase == v1alpha1.RunFailed
}

// plan runs the binding's schedule. It returns the schedule and latest run to
// persist, the next due time, and a limitation when scheduling is disabled.
func (r *AssessmentReconciler) plan(ctx context.Context, b *v1alpha1.ComplianceBinding, now time.Time) (*v1alpha1.AssessmentSchedule, *v1alpha1.RunReference, time.Time, string, error) {
	var prev *v1alpha1.AssessmentSchedule
	var latest *v1alpha1.RunReference
	if b.Status.Assessment != nil {
		prev, latest = b.Status.Assessment.Schedule, b.Status.Assessment.LatestRun
	}
	if ok, why := r.Runtime.ready(); !ok {
		return prev, latest, time.Time{}, "scheduled snapshots are disabled: " + why, nil
	}
	if err := r.backendReady(ctx); err != nil {
		return prev, latest, time.Time{}, truncateMsg("scheduled snapshots are disabled: evidence backend is not ready: " + err.Error()), nil
	}
	interval, _, _, err := bindingDurations(b)
	if err != nil {
		return prev, latest, time.Time{}, "", err
	}
	st, err := schedule.FromStatus(prev)
	if err != nil {
		return prev, latest, time.Time{}, "", err
	}
	activeDone, activeUID := false, ""
	if st.Active != "" {
		run := &v1alpha1.AssessmentRun{}
		switch err := r.reader().Get(ctx, client.ObjectKey{Name: st.Active}, run); {
		case apierrors.IsNotFound(err):
			activeDone = true
		case err != nil:
			return prev, latest, time.Time{}, "", err
		default:
			activeDone, activeUID = runDone(run), string(run.UID)
		}
	}
	var runs v1alpha1.AssessmentRunList
	if err := r.Client.List(ctx, &runs); err != nil {
		return prev, latest, time.Time{}, "", err
	}
	var pending []schedule.Pending
	for _, run := range runs.Items {
		manual := run.Spec.Trigger == nil || run.Spec.Trigger.Type == v1alpha1.TriggerManual
		if run.Spec.BindingRef.Name == b.Name && run.Spec.Scope == v1alpha1.RunScopeBinding && manual &&
			(run.Status.Phase == "" || run.Status.Phase == v1alpha1.RunPending) && run.Name != st.Active && run.DeletionTimestamp.IsZero() {
			pending = append(pending, schedule.Pending{Kind: schedule.Manual, Name: run.Name, UID: string(run.UID), Created: run.CreationTimestamp.Time})
		}
	}
	requests, err := r.pendingRequests(ctx, b, st.Active)
	if err != nil {
		return prev, latest, time.Time{}, "", err
	}
	pending = append(pending, requests...)
	d := schedule.Plan(schedule.Input{Now: now, BindingName: b.Name, BindingUID: string(b.UID), Interval: interval, State: st, ActiveDone: activeDone, Pending: pending, MaxQueue: r.Runtime.MaxQueue})
	for _, rej := range d.Rejected {
		if err := r.setRequest(ctx, rej.Namespace, rej.Name, rej.UID, func(s *v1alpha1.AssessmentRequestStatus) {
			s.Phase = v1alpha1.RequestRejected
			meta.SetStatusCondition(&s.Conditions, metav1.Condition{Type: v1alpha1.ConditionScoped, Status: metav1.ConditionFalse, Reason: "QueueFull", Message: "too many pending requests for this binding"})
		}); err != nil {
			return prev, latest, time.Time{}, "", err
		}
	}
	if d.Start != nil {
		var run *v1alpha1.AssessmentRun
		switch d.Start.Kind {
		case schedule.Scheduled:
			when := metav1.NewTime(d.Start.ScheduledTime)
			run = &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: d.Start.RunName, Labels: map[string]string{LabelRunBinding: string(b.UID)}},
				Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}, Scope: v1alpha1.RunScopeBinding,
					Trigger: &v1alpha1.RunTrigger{Type: v1alpha1.TriggerScheduled, ScheduledTime: &when}}}
			// The name is deterministic, so a retry or a lost race finds the
			// existing run instead of creating a duplicate snapshot.
			if err := r.Client.Create(ctx, run); err != nil && !apierrors.IsAlreadyExists(err) {
				return prev, latest, time.Time{}, "", err
			}
			if err := r.reader().Get(ctx, client.ObjectKey{Name: d.Start.RunName}, run); err != nil {
				return prev, latest, time.Time{}, "", err
			}
		case schedule.Request:
			p := d.Start.Pending
			run = &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: d.Start.RunName, Labels: map[string]string{LabelRunBinding: string(b.UID), LabelRunRequest: p.UID}},
				Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: b.Name}, Scope: v1alpha1.RunScopeNamespace,
					Request: &v1alpha1.RequestReference{Namespace: p.Namespace, Name: p.Name, UID: p.UID},
					Trigger: &v1alpha1.RunTrigger{Type: v1alpha1.TriggerRequest}}}
			if err := r.Client.Create(ctx, run); err != nil && !apierrors.IsAlreadyExists(err) {
				return prev, latest, time.Time{}, "", err
			}
			if err := r.reader().Get(ctx, client.ObjectKey{Name: d.Start.RunName}, run); err != nil {
				return prev, latest, time.Time{}, "", err
			}
			if err := r.setRequest(ctx, p.Namespace, p.Name, p.UID, func(s *v1alpha1.AssessmentRequestStatus) {
				s.Phase, s.Run = v1alpha1.RequestRunning, &v1alpha1.RunReference{Name: run.Name, UID: string(run.UID)}
			}); err != nil {
				return prev, latest, time.Time{}, "", err
			}
		default:
			// A platform-created manual run already exists under its own name.
			d.State.Active = d.Start.Pending.Name
			run = &v1alpha1.AssessmentRun{}
			if err := r.reader().Get(ctx, client.ObjectKey{Name: d.Start.Pending.Name}, run); err != nil {
				return prev, latest, time.Time{}, "", err
			}
		}
		activeUID = string(run.UID)
		latest = &v1alpha1.RunReference{Name: run.Name, UID: string(run.UID)}
	}
	if d.State.Active == "" {
		activeUID = ""
	}
	return schedule.ToStatus(d.State, d.NextDue, activeUID), latest, d.NextDue, "", nil
}

// readiness caches the backend readiness answer.
type readiness struct {
	mu  sync.Mutex
	at  time.Time
	err error
}

// backendReady runs the runtime's Ready check at most once per interval.
func (r *AssessmentReconciler) backendReady(ctx context.Context) error {
	if r.Runtime.Ready == nil {
		return nil
	}
	interval := r.Runtime.ReadyInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	r.ready.mu.Lock()
	defer r.ready.mu.Unlock()
	if !r.ready.at.IsZero() && time.Since(r.ready.at) < interval {
		return r.ready.err
	}
	r.ready.err, r.ready.at = r.Runtime.Ready(ctx), time.Now()
	return r.ready.err
}

// runsForBinding maps a binding to its runs, and a run to its binding.
func runsForBinding(c client.Client) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		var runs v1alpha1.AssessmentRunList
		if err := c.List(ctx, &runs); err != nil {
			return nil
		}
		var out []reconcile.Request
		for _, r := range runs.Items {
			if r.Spec.BindingRef.Name == o.GetName() && !runDone(&r) {
				out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Name: r.Name}})
			}
		}
		return out
	})
}

// LabelRunRequest labels namespace runs with their AssessmentRequest's UID.
const LabelRunRequest = "compliance.erenius.io/request-uid"

// pendingRequests resolves the binding's unstarted AssessmentRequests. A
// request whose namespace the binding does not select is rejected with an
// explicit scope reason; no broader assessment is substituted.
//
// A Running request whose run exists but is neither finished nor the active
// run stays a candidate: its admission was not persisted (for example the
// schedule write lost a compare-and-swap), and re-admitting it is idempotent
// because the run name is deterministic.
func (r *AssessmentReconciler) pendingRequests(ctx context.Context, b *v1alpha1.ComplianceBinding, active string) ([]schedule.Pending, error) {
	var reqs v1alpha1.AssessmentRequestList
	if err := r.Client.List(ctx, &reqs); err != nil {
		return nil, err
	}
	sel, selErr := b.Spec.NamespaceSelector.AsSelector()
	var out []schedule.Pending
	for i := range reqs.Items {
		req := &reqs.Items[i]
		if req.Spec.BindingRef.Name != b.Name || !req.DeletionTimestamp.IsZero() {
			continue
		}
		switch req.Status.Phase {
		case "", v1alpha1.RequestPending:
		case v1alpha1.RequestRunning:
			if req.Status.Run == nil || req.Status.Run.Name == active {
				continue
			}
			run := &v1alpha1.AssessmentRun{}
			if err := r.reader().Get(ctx, client.ObjectKey{Name: req.Status.Run.Name}, run); err != nil || runDone(run) {
				continue
			}
			out = append(out, schedule.Pending{Kind: schedule.Request, Namespace: req.Namespace, Name: req.Name, UID: string(req.UID), Created: req.CreationTimestamp.Time})
			continue
		default:
			continue
		}
		ns := &corev1.Namespace{}
		if err := r.Client.Get(ctx, client.ObjectKey{Name: req.Namespace}, ns); err != nil {
			return nil, client.IgnoreNotFound(err)
		}
		inScope := selErr == nil && ns.DeletionTimestamp.IsZero() && sel.Matches(labels.Set(ns.Labels))
		if err := r.setRequest(ctx, req.Namespace, req.Name, string(req.UID), func(s *v1alpha1.AssessmentRequestStatus) {
			s.Binding = &v1alpha1.ResolvedBinding{Name: b.Name, UID: string(b.UID)}
			s.NamespaceUID = string(ns.UID)
			if inScope {
				s.Phase = v1alpha1.RequestPending
				meta.SetStatusCondition(&s.Conditions, metav1.Condition{Type: v1alpha1.ConditionScoped, Status: metav1.ConditionTrue, Reason: "Selected", Message: "the binding selects this namespace"})
			} else {
				s.Phase = v1alpha1.RequestRejected
				meta.SetStatusCondition(&s.Conditions, metav1.Condition{Type: v1alpha1.ConditionScoped, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonNamespaceNotInScope, Message: "the binding does not select this namespace"})
			}
		}); err != nil {
			return nil, err
		}
		if inScope {
			out = append(out, schedule.Pending{Kind: schedule.Request, Namespace: req.Namespace, Name: req.Name, UID: string(req.UID), Created: req.CreationTimestamp.Time})
		}
	}
	return out, nil
}

// setRequest updates an AssessmentRequest's status if it still exists with
// the given UID. A deleted or recreated request is never updated or adopted.
func (r *AssessmentReconciler) setRequest(ctx context.Context, namespace, name, uid string, mutate func(*v1alpha1.AssessmentRequestStatus)) error {
	return setRequestStatus(ctx, r.Client, namespace, name, uid, mutate)
}

func setRequestStatus(ctx context.Context, c client.Client, namespace, name, uid string, mutate func(*v1alpha1.AssessmentRequestStatus)) error {
	req := &v1alpha1.AssessmentRequest{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, req); err != nil {
		return client.IgnoreNotFound(err)
	}
	if string(req.UID) != uid {
		return nil
	}
	before := req.Status.DeepCopy()
	mutate(&req.Status)
	if equalJSON(before, &req.Status) {
		return nil
	}
	return c.Status().Update(ctx, req)
}

// bindingForRequest maps a request to its binding.
func bindingForRequest() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		req, ok := o.(*v1alpha1.AssessmentRequest)
		if !ok {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: req.Spec.BindingRef.Name}}}
	})
}

func bindingForRun() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		run, ok := o.(*v1alpha1.AssessmentRun)
		if !ok {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: run.Spec.BindingRef.Name}}}
	})
}

// AssessmentRunReconciler executes admitted assessment runs.
type AssessmentRunReconciler struct {
	Client  client.Client
	Assess  *AssessmentReconciler
	Runtime AssessmentRuntime
	Now     func() time.Time
	// Instance identifies this controller process. A run resumed by another
	// instance (restart or leader change) records a watch discontinuity.
	Instance string
}

// closedRun is a run's frozen closure: the capture as closed and its
// evaluation. It is written before export, so a retry after a crash
// re-exports the same snapshot instead of collecting newer observations.
type closedRun struct {
	Capture    collector.CaptureV2  `json:"capture"`
	Evaluation collector.Evaluation `json:"evaluation"`
}

func (r *AssessmentRunReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC().Truncate(time.Second)
	}
	return time.Now().UTC().Truncate(time.Second)
}

func (r *AssessmentRunReconciler) staging(run *v1alpha1.AssessmentRun) string {
	return filepath.Join(r.Runtime.StagingDir, string(run.UID))
}

// Reconcile advances one run through Pending, Collecting, Publishing, and a
// terminal phase. Only the run admitted by its binding's schedule executes.
func (r *AssessmentRunReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	run := &v1alpha1.AssessmentRun{}
	if err := r.Client.Get(ctx, req.NamespacedName, run); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !run.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	if runDone(run) {
		return r.cleanupAttempts(ctx, run)
	}
	if run.UID == "" {
		return ctrl.Result{}, fmt.Errorf("run %s has no UID", run.Name)
	}
	b := &v1alpha1.ComplianceBinding{}
	err := r.Client.Get(ctx, client.ObjectKey{Name: run.Spec.BindingRef.Name}, b)
	if err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}
	gone := apierrors.IsNotFound(err) || (run.Status.Binding != nil && run.Status.Binding.UID != string(b.UID))
	if gone && run.Status.Phase == v1alpha1.RunPublishing {
		// Collection closed and the package is frozen: publish it with the
		// retention recorded at closure. A replacement binding with the same
		// name is never resolved or adopted.
		if ok, why := r.Runtime.ready(); !ok {
			return ctrl.Result{}, r.fail(ctx, run, v1alpha1.ConditionPublished, v1alpha1.ReasonPublicationFailed, why)
		}
		return r.publish(ctx, run, nil, r.now())
	}
	if apierrors.IsNotFound(err) {
		return ctrl.Result{}, r.fail(ctx, run, v1alpha1.ConditionScoped, v1alpha1.ReasonBindingNotFound, "binding "+run.Spec.BindingRef.Name+" does not exist")
	}
	if gone {
		return ctrl.Result{}, r.fail(ctx, run, v1alpha1.ConditionScoped, v1alpha1.ReasonBindingNotFound, "binding was replaced after the run started; the new binding is never adopted")
	}
	admitted := b.Status.Assessment != nil && b.Status.Assessment.Schedule != nil && b.Status.Assessment.Schedule.ActiveRun != nil &&
		b.Status.Assessment.Schedule.ActiveRun.Name == run.Name
	logger := log.FromContext(ctx).WithValues("run", run.Name, "phase", run.Status.Phase)
	if !admitted {
		active := ""
		if b.Status.Assessment != nil && b.Status.Assessment.Schedule != nil && b.Status.Assessment.Schedule.ActiveRun != nil {
			active = b.Status.Assessment.Schedule.ActiveRun.Name
		}
		logger.V(1).Info("run not admitted; waiting", "activeRun", active)
		if run.Status.Phase == "" {
			run.Status.Phase = v1alpha1.RunPending
			return ctrl.Result{}, r.Client.Status().Update(ctx, run)
		}
		return ctrl.Result{}, nil // queued; the binding's schedule admits it later
	}
	if ok, why := r.Runtime.ready(); !ok {
		return ctrl.Result{}, r.fail(ctx, run, v1alpha1.ConditionPublished, v1alpha1.ReasonPublicationFailed, why)
	}
	if run.Spec.Scope == v1alpha1.RunScopeNamespace && run.Status.Phase != v1alpha1.RunPublishing {
		if done, err := r.checkRequestScope(ctx, run); done || err != nil {
			return ctrl.Result{}, err
		}
	}
	now := r.now()
	switch run.Status.Phase {
	case "", v1alpha1.RunPending:
		return r.start(ctx, run, b, now)
	case v1alpha1.RunCollecting:
		return r.collect(ctx, run, b, now)
	case v1alpha1.RunPublishing:
		return r.publish(ctx, run, b, now)
	}
	return ctrl.Result{}, nil
}

func (r *AssessmentRunReconciler) start(ctx context.Context, run *v1alpha1.AssessmentRun, b *v1alpha1.ComplianceBinding, now time.Time) (ctrl.Result, error) {
	c, limits, _, err := r.Assess.snapshot(ctx, b, now)
	if err != nil {
		return ctrl.Result{}, err
	}
	c.Reports = []assessment.Object{}
	c.Observer = r.Instance
	if nsUID := runNamespaceUID(run); run.Spec.Scope == v1alpha1.RunScopeNamespace {
		// Recheck membership at execution and freeze only this namespace.
		if c, err = collector.Project(c, nsUID); errors.Is(err, collector.ErrNotInScope) {
			return ctrl.Result{}, r.fail(ctx, run, v1alpha1.ConditionScoped, v1alpha1.ReasonNamespaceNotInScope, "the binding does not select the request's namespace at execution; no broader assessment is substituted")
		} else if err != nil {
			return ctrl.Result{}, err
		}
		limits = nil // binding-wide limitations may name other namespaces
	}
	if err := os.MkdirAll(r.staging(run), 0o700); err != nil {
		return ctrl.Result{}, err
	}
	if err := assessment.Write(filepath.Join(r.staging(run), "capture.json"), c); err != nil {
		return ctrl.Result{}, err
	}
	var revisions []string
	nsUIDs := map[string]bool{}
	for _, s := range c.Subjects {
		if !slices.Contains(revisions, s.Revision) && len(revisions) < 64 {
			revisions = append(revisions, s.Revision)
		}
		nsUIDs[string(s.NamespaceUID)] = true
	}
	slices.Sort(revisions)
	scope := r.scope(run, b, c)
	run.Status.Phase = v1alpha1.RunCollecting
	run.Status.Binding = &v1alpha1.ResolvedBinding{Name: b.Name, UID: string(b.UID)}
	run.Status.BindingConfiguration = bindingConfiguration(b)
	run.Status.EnforcementRevisions = revisions
	nsUID := runNamespaceUID(run)
	run.Status.Scope = &v1alpha1.FrozenScope{ClusterID: c.Cluster, NamespaceUID: nsUID, NamespaceCount: int32(len(nsUIDs)), Revision: scope.Revision, SHA256: scope.Digest()}
	run.Status.Window = &v1alpha1.CaptureWindow{Started: metav1.NewTime(now)}
	msg := "collecting evidence"
	if len(limits) > 0 {
		msg = truncateMsg(limits[0])
	}
	meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{Type: v1alpha1.ConditionEvidenceComplete, Status: metav1.ConditionUnknown, Reason: "Collecting", Message: msg})
	if err := r.Client.Status().Update(ctx, run); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: r.Runtime.Poll}, nil
}

func bindingConfiguration(b *v1alpha1.ComplianceBinding) string {
	return fmt.Sprintf("generation-%d/epoch-%d", b.Generation, b.Spec.EnforcementEpoch)
}

func (r *AssessmentRunReconciler) scope(run *v1alpha1.AssessmentRun, b *v1alpha1.ComplianceBinding, c collector.CaptureV2) publication.Scope {
	if c.Projection != nil && run.Spec.Request != nil {
		q := run.Spec.Request
		return publication.Scope{Kind: publication.ScopeNamespace, ClusterID: c.Cluster, BindingUID: string(b.UID),
			Request:       &publication.RequestRef{Namespace: q.Namespace, Name: q.Name, UID: q.UID, NamespaceUID: c.Projection.NamespaceUID},
			NamespaceUIDs: []string{c.Projection.NamespaceUID}, Revision: "frozen-" + c.Window.Started.UTC().Format(time.RFC3339)}
	}
	set := map[string]bool{}
	for _, s := range c.Subjects {
		set[string(s.NamespaceUID)] = true
	}
	ns := sortedKeys(set)
	if ns == nil {
		ns = []string{}
	}
	return publication.Scope{Kind: publication.ScopeBinding, ClusterID: c.Cluster, BindingUID: string(b.UID), NamespaceUIDs: ns, Revision: "frozen-" + c.Window.Started.UTC().Format(time.RFC3339)}
}

// boundaries returns continuity boundaries for the frozen workload states
// without changing the shared tracker.
func (r *AssessmentRunReconciler) boundaries(c collector.CaptureV2) []collector.Boundary {
	var out []collector.Boundary
	for _, w := range c.Workloads {
		if b, ok := r.Assess.Boundaries.Lookup(w.UID, w.StateSHA256); ok {
			out = append(out, b)
		}
	}
	return out
}

func (r *AssessmentRunReconciler) collect(ctx context.Context, run *v1alpha1.AssessmentRun, b *v1alpha1.ComplianceBinding, now time.Time) (ctrl.Result, error) {
	var c collector.CaptureV2
	if err := assessment.Read(filepath.Join(r.staging(run), "capture.json"), &c); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ctrl.Result{}, r.fail(ctx, run, v1alpha1.ConditionPublished, v1alpha1.ReasonCaptureLost,
				"the staged capture was lost before closure; it is not reconstructed from the changed cluster, and a later run assesses current state")
		}
		return ctrl.Result{}, err
	}
	var frozen closedRun
	switch err := assessment.Read(filepath.Join(r.staging(run), "closed.json"), &frozen); {
	case err == nil:
		// Closed before a crash: finish the same frozen snapshot.
		return r.finish(ctx, run, b, frozen)
	case !errors.Is(err, os.ErrNotExist):
		return ctrl.Result{}, err
	}
	if c.Observer != r.Instance {
		// Another process collected until now; continuity across the gap
		// cannot be proven, so earlier evaluations no longer count.
		collector.NewTracker(&c).Discontinuity(now, "controller restart or leader change; earlier observations are not continuous")
		c.Observer = r.Instance
	}
	cur, _, maxAge, err := r.Assess.snapshot(ctx, b, now)
	if err != nil {
		return ctrl.Result{}, err
	}
	subjects, stale, workloads := cur.Subjects, cur.Stale, cur.Workloads
	if p := c.Projection; p != nil {
		// Only this namespace's observations feed a namespace run, and
		// binding-wide text is redacted, so nothing about siblings is recorded.
		subjects = slices.DeleteFunc(slices.Clone(subjects), func(s targeting.EvidenceSubject) bool { return string(s.NamespaceUID) != p.NamespaceUID })
		workloads = slices.DeleteFunc(slices.Clone(workloads), func(w collector.Workload) bool { return w.NamespaceUID != p.NamespaceUID })
		stale = slices.Clone(stale)
		for i := range stale {
			stale[i].Message = "redacted in namespace scope"
		}
		np := collector.Projection{Namespace: p.Namespace, NamespaceUID: p.NamespaceUID}
		cur.Reports = collector.ProjectReports(cur.Reports, &np)
		c.Projection = &np
	}
	// Record changes against the frozen scope; it never broadens or shrinks.
	t := collector.NewTracker(&c)
	present := map[string]bool{}
	for _, w := range workloads {
		present[w.UID] = true
		t.Workload(now, w, false)
	}
	for _, w := range c.Workloads {
		if !present[w.UID] {
			t.Workload(now, w, true)
		}
	}
	t.Configuration(now, subjects, stale)
	c.Reports = cur.Reports

	_, timeout, _, err := bindingDurations(b)
	if err != nil {
		return ctrl.Result{}, err
	}
	trial := c
	trial.Window.Closed = now
	ev, err := trial.Evaluate(r.boundaries(trial), maxAge)
	if err != nil {
		return ctrl.Result{}, err
	}
	log.FromContext(ctx).V(1).Info("collecting", "run", run.Name, "completeness", ev.Evidence.Completeness, "closesAt", c.Window.Started.Add(timeout))
	if now.Before(c.Window.Started.Add(timeout)) && ev.Evidence.Completeness != publication.Complete {
		if err := assessment.Write(filepath.Join(r.staging(run), "capture.json"), c); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: r.Runtime.Poll}, nil
	}
	// Close the bounded window: freeze the capture and its evaluation first.
	frozen = closedRun{Capture: trial, Evaluation: ev}
	if err := assessment.Write(filepath.Join(r.staging(run), "closed.json"), frozen); err != nil {
		return ctrl.Result{}, err
	}
	return r.finish(ctx, run, b, frozen)
}

// finish exports a frozen closure and records it. Export is repeated from
// the same frozen snapshot if a crash interrupted it; once the descriptor
// digest is recorded, publication only ever uses those package bytes.
func (r *AssessmentRunReconciler) finish(ctx context.Context, run *v1alpha1.AssessmentRun, b *v1alpha1.ComplianceBinding, frozen closedRun) (ctrl.Result, error) {
	c, ev := frozen.Capture, frozen.Evaluation
	now := c.Window.Closed
	pkg := filepath.Join(r.staging(run), "package")
	if err := os.RemoveAll(pkg); err != nil {
		return ctrl.Result{}, err
	}
	d, err := collector.Export(ctx, collector.ExportRequest{Root: r.Runtime.ContentRoot, Out: pkg,
		Run: publication.RunRef{ClusterID: c.Cluster, BindingUID: string(b.UID), RunUID: string(run.UID)}, Scope: r.scope(run, b, c),
		BindingConfiguration: run.Status.BindingConfiguration, Capture: c, Evaluation: ev})
	if err != nil {
		return ctrl.Result{}, r.fail(ctx, run, v1alpha1.ConditionPublished, "ExportFailed", err.Error())
	}
	sum := publication.SummaryToAPI(publication.Summarize(d, publication.Status{Phase: publication.PhasePending}))
	closed := metav1.NewTime(now)
	run.Status.Window.Closed = &closed
	run.Status.Summary = &sum
	if _, _, retention, err := bindingDurations(b); err == nil {
		run.Status.Retention = v1alpha1.Duration(retention.String())
	}
	run.Status.DescriptorSHA256 = d.Digest()
	run.Status.Phase = v1alpha1.RunPublishing
	evidence := metav1.ConditionFalse
	if d.Evidence.Completeness == publication.Complete {
		evidence = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{Type: v1alpha1.ConditionEvidenceComplete, Status: evidence, Reason: string(d.Evidence.Completeness),
		Message: fmt.Sprintf("%d of %d expected observations attributable; %d stale scopes", d.Evidence.Attributable, d.Evidence.Expected, d.Evidence.StaleScopes)})
	if err := r.Client.Status().Update(ctx, run); err != nil {
		return ctrl.Result{}, err
	}
	return r.publish(ctx, run, b, now)
}

func (r *AssessmentRunReconciler) publish(ctx context.Context, run *v1alpha1.AssessmentRun, b *v1alpha1.ComplianceBinding, now time.Time) (ctrl.Result, error) {
	ref := publication.RunRef{ClusterID: run.Status.Scope.ClusterID, BindingUID: run.Status.Binding.UID, RunUID: string(run.UID)}
	pkg := filepath.Join(r.staging(run), "package")
	d, err := publication.LoadDescriptor(pkg)
	if err != nil {
		// The frozen bytes are gone: never re-export a newer cluster state
		// under this run's identity.
		staged, rerr := r.Runtime.Publisher.Recover(ctx, ref)
		if rerr != nil {
			return ctrl.Result{}, r.fail(ctx, run, v1alpha1.ConditionPublished, v1alpha1.ReasonCaptureLost, "frozen package lost before publication: "+err.Error())
		}
		return r.commit(ctx, run, b, staged, now)
	}
	if d.Digest() != run.Status.DescriptorSHA256 {
		return ctrl.Result{}, r.fail(ctx, run, v1alpha1.ConditionPublished, v1alpha1.ReasonCaptureLost, "staged package does not match the frozen descriptor")
	}
	staged, err := r.Runtime.Publisher.Stage(ctx, publication.StageRequest{Run: ref, Dir: pkg})
	if err != nil {
		return r.retry(ctx, run, now, err)
	}
	return r.commit(ctx, run, b, staged, now)
}

func (r *AssessmentRunReconciler) commit(ctx context.Context, run *v1alpha1.AssessmentRun, b *v1alpha1.ComplianceBinding, staged publication.Staged, now time.Time) (ctrl.Result, error) {
	sel, err := selectRetention(run, b, now)
	if err != nil {
		return ctrl.Result{}, r.fail(ctx, run, v1alpha1.ConditionPublished, v1alpha1.ReasonPublicationFailed, err.Error())
	}
	receipt, err := r.Runtime.Publisher.Publish(ctx, publication.PublishRequest{Staged: staged, Retention: sel})
	if err != nil {
		return r.retry(ctx, run, now, err)
	}
	st := publication.Committed(receipt)
	pub := publication.ToAPI(st)
	run.Status.Publication = &pub
	if run.Status.Summary != nil {
		run.Status.Summary.Export = v1alpha1.ExportState(publication.ExportAssessment)
		if d, err := publication.LoadDescriptor(filepath.Join(r.staging(run), "package")); err == nil {
			sum := publication.SummaryToAPI(publication.Summarize(d, st))
			run.Status.Summary = &sum
		}
	}
	run.Status.Phase = v1alpha1.RunCompleted
	meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{Type: v1alpha1.ConditionPublished, Status: metav1.ConditionTrue, Reason: "Committed", Message: "published as " + receipt.PublicationID})
	if err := r.Client.Status().Update(ctx, run); err != nil {
		return ctrl.Result{}, err
	}
	_ = os.RemoveAll(r.staging(run))
	return ctrl.Result{}, r.finishRequest(ctx, run, "")
}

// AttemptCleanupRetry is how often cleanup of a terminal run's uncommitted
// storage attempts is retried after a failure.
const AttemptCleanupRetry = time.Minute

// cleanupAttempts removes a terminal run's uncommitted storage attempts. Runs
// that never froze a scope never staged anything. Failures are recorded on
// the run and retried; a restart re-lists terminal runs and resumes.
func (r *AssessmentRunReconciler) cleanupAttempts(ctx context.Context, run *v1alpha1.AssessmentRun) (ctrl.Result, error) {
	if r.Runtime.Publisher == nil || run.Status.Scope == nil || run.Status.Binding == nil || meta.IsStatusConditionTrue(run.Status.Conditions, v1alpha1.ConditionAttemptsCleaned) {
		return ctrl.Result{}, nil
	}
	ref := publication.RunRef{ClusterID: run.Status.Scope.ClusterID, BindingUID: run.Status.Binding.UID, RunUID: string(run.UID)}
	cond := metav1.Condition{Type: v1alpha1.ConditionAttemptsCleaned, Status: metav1.ConditionTrue, Reason: v1alpha1.ReasonCleaned, Message: "uncommitted storage attempts removed"}
	res := ctrl.Result{}
	if err := r.Runtime.Publisher.CleanupAttempts(ctx, ref); err != nil {
		cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, v1alpha1.ReasonCleanupPending, truncate(err.Error())
		res.RequeueAfter = AttemptCleanupRetry
	}
	if old := meta.FindStatusCondition(run.Status.Conditions, cond.Type); old != nil && old.Status == cond.Status && old.Reason == cond.Reason && old.Message == cond.Message {
		return res, nil
	}
	meta.SetStatusCondition(&run.Status.Conditions, cond)
	return res, r.Client.Status().Update(ctx, run)
}

// selectRetention chooses the retention for the first commit: a consistent
// read of the run's own binding while it exists, otherwise the retention
// recorded on the run at closure. The publisher keeps an existing commit's
// retention on retries, so this only affects the first commit.
func selectRetention(run *v1alpha1.AssessmentRun, b *v1alpha1.ComplianceBinding, now time.Time) (publication.Retention, error) {
	if b != nil && run.Status.Binding != nil && string(b.UID) == run.Status.Binding.UID {
		_, _, retention, err := bindingDurations(b)
		if err != nil {
			return publication.Retention{}, err
		}
		return publication.Retention{Duration: retention.String(), BindingConfiguration: bindingConfiguration(b), SelectedAt: now}, nil
	}
	if run.Status.Retention == "" {
		return publication.Retention{}, errors.New("the binding is gone and no retention was recorded at closure")
	}
	return publication.Retention{Duration: string(run.Status.Retention), BindingConfiguration: run.Status.BindingConfiguration + " (binding deleted or replaced; retention recorded at closure)", SelectedAt: now}, nil
}

// retry keeps a publishing run retrying within PublishTimeout after closure,
// then fails it so the binding's slot is released.
func (r *AssessmentRunReconciler) retry(ctx context.Context, run *v1alpha1.AssessmentRun, now time.Time, cause error) (ctrl.Result, error) {
	closed := now
	if run.Status.Window != nil && run.Status.Window.Closed != nil {
		closed = run.Status.Window.Closed.Time
	}
	if now.Before(closed.Add(r.Runtime.PublishTimeout)) {
		meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{Type: v1alpha1.ConditionPublished, Status: metav1.ConditionFalse, Reason: "Retrying", Message: truncateMsg(cause.Error())})
		if err := r.Client.Status().Update(ctx, run); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: r.Runtime.Poll}, nil
	}
	return ctrl.Result{}, r.fail(ctx, run, v1alpha1.ConditionPublished, v1alpha1.ReasonPublicationFailed, "publication did not succeed within "+r.Runtime.PublishTimeout.String()+": "+cause.Error())
}

// runNamespaceUID is the namespace a namespace run assesses.
func runNamespaceUID(run *v1alpha1.AssessmentRun) string {
	if run.Spec.Scope != v1alpha1.RunScopeNamespace || run.Status.Scope == nil {
		return ""
	}
	return run.Status.Scope.NamespaceUID
}

// checkRequestScope verifies a namespace run's request and namespace before
// it starts: the request must still exist with its original UID, and the
// namespace must still be the instance resolved for it. A recreated request
// or namespace is never adopted. A started run continues if its request is
// deleted, so its retained publication record is unaffected.
func (r *AssessmentRunReconciler) checkRequestScope(ctx context.Context, run *v1alpha1.AssessmentRun) (bool, error) {
	started := run.Status.Phase != "" && run.Status.Phase != v1alpha1.RunPending
	if started {
		return false, nil
	}
	q := run.Spec.Request
	req := &v1alpha1.AssessmentRequest{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: q.Namespace, Name: q.Name}, req)
	if apierrors.IsNotFound(err) || (err == nil && string(req.UID) != q.UID) {
		return true, r.fail(ctx, run, v1alpha1.ConditionScoped, "RequestNotFound", "the request was deleted or recreated before the run started")
	}
	if err != nil {
		return true, err
	}
	ns := &corev1.Namespace{}
	err = r.Client.Get(ctx, client.ObjectKey{Name: q.Namespace}, ns)
	if apierrors.IsNotFound(err) || (err == nil && (req.Status.NamespaceUID == "" || string(ns.UID) != req.Status.NamespaceUID)) {
		return true, r.fail(ctx, run, v1alpha1.ConditionScoped, v1alpha1.ReasonNamespaceNotInScope, "the request's namespace was deleted or recreated")
	}
	if err != nil {
		return true, err
	}
	if run.Status.Scope == nil {
		run.Status.Scope = &v1alpha1.FrozenScope{}
	}
	run.Status.Scope.NamespaceUID = string(ns.UID)
	return false, nil
}

// requestMessages are the only team-visible failure texts; operator detail
// stays on the platform-scoped run.
var requestMessages = map[string]string{
	v1alpha1.ReasonNamespaceNotInScope: "the binding does not select this namespace at execution",
	v1alpha1.ReasonPublicationFailed:   "the evidence package could not be published",
	v1alpha1.ReasonCaptureLost:         "the frozen evidence was lost before publication; a later request assesses current state",
	v1alpha1.ReasonBindingNotFound:     "the binding no longer exists",
	"RequestNotFound":                  "the request was deleted or recreated",
	"ExportFailed":                     "the evidence package could not be produced",
}

// finishRequest copies a namespace run's sanitized outcome to its request.
func (r *AssessmentRunReconciler) finishRequest(ctx context.Context, run *v1alpha1.AssessmentRun, reason string) error {
	q := run.Spec.Request
	if run.Spec.Scope != v1alpha1.RunScopeNamespace || q == nil {
		return nil
	}
	return setRequestStatus(ctx, r.Client, q.Namespace, q.Name, q.UID, func(s *v1alpha1.AssessmentRequestStatus) {
		s.Run = &v1alpha1.RunReference{Name: run.Name, UID: string(run.UID)}
		if run.Status.Summary != nil {
			sum := *run.Status.Summary
			s.Summary = &sum
		}
		switch {
		case run.Status.Phase == v1alpha1.RunCompleted:
			s.Phase = v1alpha1.RequestCompleted
			if run.Status.Publication != nil {
				s.ArtifactRef = run.Status.Publication.PublicationID
			}
			meta.SetStatusCondition(&s.Conditions, metav1.Condition{Type: v1alpha1.ConditionPublished, Status: metav1.ConditionTrue, Reason: "Committed", Message: "the evidence package was published"})
		case reason == v1alpha1.ReasonNamespaceNotInScope:
			s.Phase = v1alpha1.RequestRejected
			meta.SetStatusCondition(&s.Conditions, metav1.Condition{Type: v1alpha1.ConditionScoped, Status: metav1.ConditionFalse, Reason: reason, Message: requestMessages[reason]})
		default:
			s.Phase = v1alpha1.RequestFailed
			msg := requestMessages[reason]
			if msg == "" {
				msg = "the assessment failed"
			}
			meta.SetStatusCondition(&s.Conditions, metav1.Condition{Type: v1alpha1.ConditionPublished, Status: metav1.ConditionFalse, Reason: reason, Message: msg})
		}
	})
}

// fail ends a run with an explicit reason, which releases the binding's slot.
// Evidence already recorded in status is kept.
func (r *AssessmentRunReconciler) fail(ctx context.Context, run *v1alpha1.AssessmentRun, condition, reason, msg string) error {
	run.Status.Phase = v1alpha1.RunFailed
	meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{Type: condition, Status: metav1.ConditionFalse, Reason: reason, Message: truncateMsg(msg)})
	if reason == v1alpha1.ReasonCaptureLost {
		if run.Status.Summary == nil {
			run.Status.Summary = &v1alpha1.AssessmentSummary{Evidence: v1alpha1.EvidenceSummary{Completeness: "Incomplete"}}
		}
		run.Status.Summary.Export = v1alpha1.ExportState(publication.ExportCaptureLost)
	}
	if err := r.Client.Status().Update(ctx, run); err != nil {
		return err
	}
	_ = os.RemoveAll(r.staging(run))
	return r.finishRequest(ctx, run, reason)
}

func truncateMsg(s string) string {
	if len(s) > 1024 {
		return s[:1021] + "..."
	}
	return s
}
