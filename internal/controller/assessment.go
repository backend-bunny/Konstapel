package controller

// Continuous current-evidence status for ComplianceBindings
// (add-continuous-assessments task 3.4). The assessment reconciler resolves a
// binding's expected evidence through targeting, freezes the current scope
// with internal/collector, evaluates live PolicyReports against continuity
// boundaries, and server-side applies status.assessment.current. It never
// writes engine policies, conditions, or any other binding status field.

// +kubebuilder:rbac:groups=compliance.erenius.io,resources=compliancebindings;complianceprofiles,verbs=get;list;watch
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=compliancebindings/status,verbs=get;patch
// +kubebuilder:rbac:groups="",resources=namespaces;pods;replicationcontrollers,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments;daemonsets;statefulsets;replicasets,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=jobs;cronjobs,verbs=get;list;watch
// +kubebuilder:rbac:groups=wgpolicyk8s.io,resources=policyreports,verbs=get;list;watch
// +kubebuilder:rbac:groups=policies.kyverno.io,resources=validatingpolicies,verbs=get;list;watch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/uuid"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// AssessmentFieldManager owns status.assessment on ComplianceBindings.
const AssessmentFieldManager = "konstapel-assessments"

// PolicyReportGVK is the report layout the collector reads.
var PolicyReportGVK = schema.GroupVersionKind{Group: "wgpolicyk8s.io", Version: "v1alpha2", Kind: "PolicyReport"}

// workloadKinds maps the collected "group/version/resource" strings to the
// typed objects the assessment controller watches and lists. Subresources
// (pods/ephemeralcontainers) are evaluated on their parent pod.
var workloadKinds = map[string]func() (client.Object, client.ObjectList){
	"/v1/pods": func() (client.Object, client.ObjectList) { return &corev1.Pod{}, &corev1.PodList{} },
	"/v1/replicationcontrollers": func() (client.Object, client.ObjectList) {
		return &corev1.ReplicationController{}, &corev1.ReplicationControllerList{}
	},
	"apps/v1/deployments":  func() (client.Object, client.ObjectList) { return &appsv1.Deployment{}, &appsv1.DeploymentList{} },
	"apps/v1/daemonsets":   func() (client.Object, client.ObjectList) { return &appsv1.DaemonSet{}, &appsv1.DaemonSetList{} },
	"apps/v1/statefulsets": func() (client.Object, client.ObjectList) { return &appsv1.StatefulSet{}, &appsv1.StatefulSetList{} },
	"apps/v1/replicasets":  func() (client.Object, client.ObjectList) { return &appsv1.ReplicaSet{}, &appsv1.ReplicaSetList{} },
	"batch/v1/jobs":        func() (client.Object, client.ObjectList) { return &batchv1.Job{}, &batchv1.JobList{} },
	"batch/v1/cronjobs":    func() (client.Object, client.ObjectList) { return &batchv1.CronJob{}, &batchv1.CronJobList{} },
}

// BoundaryTracker remembers, per workload UID, the state this process has
// observed continuously and since when. It is process-local: a restart or a
// new leader starts with no history, so evidence must be re-established by
// evaluations after the new observation (relisting never creates history).
// It is shared by all bindings; entries not observed for PruneAfter are
// dropped, which bounds memory without one binding erasing another's history.
type BoundaryTracker struct {
	mu   sync.Mutex
	seen map[string]trackedState
}

type trackedState struct {
	boundary collector.Boundary
	lastSeen time.Time
}

// PruneAfter is how long an unobserved workload's boundary is kept.
const PruneAfter = 24 * time.Hour

// NewBoundaryTracker returns an empty tracker.
func NewBoundaryTracker() *BoundaryTracker {
	return &BoundaryTracker{seen: map[string]trackedState{}}
}

// Observe records the workloads' current states at time now and returns
// their boundaries. A changed state restarts its boundary at now.
func (t *BoundaryTracker) Observe(now time.Time, ws []collector.Workload) []collector.Boundary {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]collector.Boundary, 0, len(ws))
	for _, w := range ws {
		s, ok := t.seen[w.UID]
		if !ok || s.boundary.StateSHA256 != w.StateSHA256 {
			s.boundary = collector.Boundary{WorkloadUID: w.UID, StateSHA256: w.StateSHA256, Since: now}
		}
		s.lastSeen = now
		t.seen[w.UID] = s
		out = append(out, s.boundary)
	}
	for uid, s := range t.seen {
		if now.Sub(s.lastSeen) > PruneAfter {
			delete(t.seen, uid)
		}
	}
	return out
}

// Lookup returns the boundary for a workload only if its tracked state is
// state. It never changes the tracker.
func (t *BoundaryTracker) Lookup(uid, state string) (collector.Boundary, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.seen[uid]
	if !ok || s.boundary.StateSHA256 != state {
		return collector.Boundary{}, false
	}
	return s.boundary, true
}

// AssessmentReconciler maintains status.assessment.current and plans the
// binding's snapshot schedule.
type AssessmentReconciler struct {
	Client     client.Client
	Content    targeting.ContentSource
	Engine     EngineAvailable
	Cluster    string
	Boundaries *BoundaryTracker
	Now        func() time.Time
	// Runtime enables scheduled runs when ready; see AssessmentRuntime.
	Runtime AssessmentRuntime
	ready   readiness
	// Reader reads runs uncached. A run created moments ago may be missing
	// from the informer cache, and treating that as "finished" would free
	// the binding's slot while the run executes. Defaults to Client.
	Reader client.Reader
}

func (r *AssessmentReconciler) reader() client.Reader {
	if r.Reader != nil {
		return r.Reader
	}
	return r.Client
}

func (r *AssessmentReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC().Truncate(time.Second)
	}
	return time.Now().UTC().Truncate(time.Second)
}

// Reconcile computes and applies the binding's current evidence.
func (r *AssessmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	b := &v1alpha1.ComplianceBinding{}
	if err := r.Client.Get(ctx, req.NamespacedName, b); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !b.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	now := r.now()
	current, err := r.evaluate(ctx, b, now)
	if err != nil {
		return ctrl.Result{}, err
	}
	sched, latest, nextDue, limit, err := r.plan(ctx, b, now)
	if err != nil {
		return ctrl.Result{}, err
	}
	if limit != "" {
		current.Limitations = boundLimitations(append([]string{limit}, current.Limitations...))
	}
	// Destination selection is evidence readiness only; it never touches
	// enforcement status. It is not yet used to route publication (run pins
	// do that, add-s3-evidence-publishing 7.4).
	dest := selectDestination(ctx, r.reader(), r.Runtime.ControllerNamespace, b)
	if err := r.apply(ctx, b, &v1alpha1.BindingAssessmentStatus{Current: current, Schedule: sched, LatestRun: latest, Destination: dest}); err != nil {
		return ctrl.Result{}, err
	}
	// Re-evaluate when the oldest attributable evidence becomes stale (without
	// waiting for an event or a snapshot tick), or when the next run is due.
	var after time.Duration
	for _, t := range []time.Time{nextDue, ptrTime(current.NextExpiry)} {
		if !t.IsZero() {
			if d := t.Sub(now) + time.Second; after == 0 || d < after {
				after = d
			}
		}
	}
	return ctrl.Result{RequeueAfter: max(after, 0)}, nil
}

func ptrTime(t *metav1.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.Time
}

// snapshot resolves b's expected evidence at time now and freezes it into a
// capture with the current PolicyReports attached. It also returns the
// limitations found and the binding's maxEvidenceAge.
func (r *AssessmentReconciler) snapshot(ctx context.Context, b *v1alpha1.ComplianceBinding, now time.Time) (collector.CaptureV2, []string, time.Duration, error) {
	maxAge := 2 * time.Hour
	if b.Spec.Assessment != nil && b.Spec.Assessment.MaxEvidenceAge != "" {
		d, err := time.ParseDuration(string(b.Spec.Assessment.MaxEvidenceAge))
		if err != nil || d <= 0 {
			return collector.CaptureV2{}, nil, 0, fmt.Errorf("binding %s: maxEvidenceAge %q", b.Name, b.Spec.Assessment.MaxEvidenceAge)
		}
		maxAge = d
	}
	var limits []string
	if b.Spec.EnforcementEpoch == 0 {
		limits = append(limits, "binding has no enforcementEpoch: install the konstapel-binding-enforcement-epoch admission policy, or every edit rotates engine policies")
	}

	in, profile, err := (&BindingReconciler{Client: r.Client, Content: r.Content, Cluster: r.Cluster}).input(ctx, b)
	if err != nil {
		return collector.CaptureV2{}, nil, 0, err
	}
	res := targeting.Resolve(in)
	content := map[string]*targeting.Content{}
	if profile != nil && len(in.Bundles) > 0 {
		c, err := r.Content.Content(ctx, profile.Spec.Bundle)
		if err != nil {
			return collector.CaptureV2{}, nil, 0, err
		}
		content[c.Bundle.Digest] = c
	}
	subjects, stale, err := targeting.ExpectedEvidence(res, content)
	if err != nil {
		return collector.CaptureV2{}, nil, 0, err
	}

	engineUp := false
	if r.Engine != nil {
		engineUp, err = r.Engine(ctx)
		if err != nil {
			return collector.CaptureV2{}, nil, 0, err
		}
	}
	var rendered []assessment.Object
	var reports []assessment.Object
	if engineUp {
		if rendered, err = r.listUnstructured(ctx, targeting.ValidatingPolicyGVK, "", client.MatchingLabels{
			targeting.LabelManagedBy: targeting.ManagedByValue, targeting.LabelBindingUID: string(b.UID)}); err != nil {
			return collector.CaptureV2{}, nil, 0, err
		}
	} else {
		limits = append(limits, "policy engine API is not served; no engine policies or reports can be read")
	}

	// Subjects whose engine policy is not delivered cannot have evidence; they
	// count as stale scope rather than disappearing from the denominator.
	// Subjects whose engine policy is not delivered, or does not match what
	// targeting renders from the verified content (drift), cannot have
	// evidence; they count as stale scope instead of leaving the denominator.
	byName := map[string]assessment.Object{}
	for _, p := range rendered {
		byName[assessment.Str(assessment.At(p, "metadata", "name"))] = p
	}
	var contributions []targeting.Contribution
	for _, br := range res.Bindings {
		contributions = append(contributions, br.Contributions...)
	}
	sources := collector.SourcesOf(slices.Collect(maps.Values(content))...)
	kept := subjects[:0]
	unusable := map[string]string{}
	var used []targeting.Contribution
	for _, s := range subjects {
		p, delivered := byName[s.EnginePolicy]
		if !delivered {
			unusable[s.EnginePolicy] = "EngineNotDelivered"
			continue
		}
		i := slices.IndexFunc(contributions, func(x targeting.Contribution) bool {
			return x.Binding.UID == s.BindingUID && x.Policy == s.LogicalPolicy && x.Revision == s.Revision
		})
		if i < 0 {
			unusable[s.EnginePolicy] = "EnginePolicyDrift"
			continue
		}
		if err := collector.VerifyEnginePolicy(p, contributions[i], sources[s.SourceDigest]); err != nil {
			unusable[s.EnginePolicy] = "EnginePolicyDrift"
			continue
		}
		if !slices.ContainsFunc(used, func(x targeting.Contribution) bool {
			return x.Revision == contributions[i].Revision && x.Policy == contributions[i].Policy
		}) {
			used = append(used, contributions[i])
		}
		kept = append(kept, s)
	}
	subjects = kept
	for _, p := range sortedKeys(unusable) {
		msg := "engine policy " + p + " is not delivered"
		if unusable[p] == "EnginePolicyDrift" {
			msg = "engine policy " + p + " differs from the policy rendered from the pinned content"
		}
		stale = append(stale, targeting.StaleScope{Binding: targeting.ObjectRevision{Name: b.Name, UID: b.UID, Generation: b.Generation},
			Reason: targeting.Reason(unusable[p]), Message: msg})
	}

	// List the workloads the subjects can match, in their namespaces only.
	namespaces, resources := map[string]string{}, map[string]bool{}
	for _, s := range subjects {
		namespaces[s.Namespace] = string(s.NamespaceUID)
		for _, res := range s.Resources {
			resources[res] = true
		}
	}
	var listed []collector.ListedObject
	for _, res := range sortedKeys(resources) {
		mk, ok := workloadKinds[res]
		if !ok {
			if !strings.HasSuffix(res, "/ephemeralcontainers") {
				limits = append(limits, "resource "+res+" is not collected")
			}
			continue
		}
		for _, ns := range sortedKeys(namespaces) {
			_, list := mk()
			if err := r.Client.List(ctx, list, client.InNamespace(ns)); err != nil {
				return collector.CaptureV2{}, nil, 0, err
			}
			items, err := meta.ExtractList(list)
			if err != nil {
				return collector.CaptureV2{}, nil, 0, err
			}
			for _, it := range items {
				o, err := runtime.DefaultUnstructuredConverter.ToUnstructured(it)
				if err != nil {
					return collector.CaptureV2{}, nil, 0, err
				}
				if ts := assessment.Str(assessment.At(o, "metadata", "deletionTimestamp")); ts != "" {
					continue
				}
				listed = append(listed, collector.ListedObject{Resource: res, NamespaceUID: namespaces[ns], Object: o})
			}
		}
	}
	if engineUp {
		for _, ns := range sortedKeys(namespaces) {
			rs, err := r.listUnstructured(ctx, PolicyReportGVK, ns)
			if err != nil {
				limits = append(limits, "policy reports unavailable: "+err.Error())
				break
			}
			reports = append(reports, rs...)
		}
	}

	capture, err := collector.FreezeScope(r.Cluster, now, mappingDigest(subjects), subjects, stale, rendered, listed)
	if err != nil {
		return collector.CaptureV2{}, nil, 0, err
	}
	capture.Reports = reports
	capture.Contributions = used
	return capture, limits, maxAge, nil
}

// evaluate builds the current-evidence status for b at time now.
func (r *AssessmentReconciler) evaluate(ctx context.Context, b *v1alpha1.ComplianceBinding, now time.Time) (*v1alpha1.CurrentEvidence, error) {
	capture, limits, maxAge, err := r.snapshot(ctx, b, now)
	if err != nil {
		return nil, err
	}
	capture.Window.Closed = now
	boundaries := r.Boundaries.Observe(now, capture.Workloads)
	ev, err := capture.Evaluate(boundaries, maxAge)
	if err != nil {
		return nil, err
	}

	for _, s := range capture.Stale {
		limits = append(limits, fmt.Sprintf("stale scope %s: %s", s.Reason, s.Message))
	}
	if n := ev.Evidence.Expected - ev.Evidence.Attributable; n > 0 {
		limits = append(limits, fmt.Sprintf("%d of %d expected observations lack attributable evidence (missing %d, rejected %d, unresolved %d)",
			n, ev.Evidence.Expected, ev.Evidence.Missing, ev.Evidence.Rejected, ev.Evidence.Unresolved))
	}
	cur := &v1alpha1.CurrentEvidence{EvaluatedAt: metav1.NewTime(now), Limitations: boundLimitations(limits)}
	cur.Evidence = v1alpha1.EvidenceSummary{Completeness: v1alpha1.EvidenceCompleteness(ev.Evidence.Completeness), Expected: int32(ev.Evidence.Expected),
		Attributable: int32(ev.Evidence.Attributable), Missing: int32(ev.Evidence.Missing), Rejected: int32(ev.Evidence.Rejected),
		Unresolved: int32(ev.Evidence.Unresolved), StaleScopes: int32(ev.Evidence.StaleScopes)}
	o := ev.Outcomes
	cur.Outcomes = v1alpha1.OutcomeCounts{Pass: int32(o.Pass), Fail: int32(o.Fail), Error: int32(o.Error), Skip: int32(o.Skip),
		AcceptedRisk: int32(o.AcceptedRisk), NotApplicable: int32(o.NotApplicable), Unknown: int32(o.Unknown)}
	if ev.NextExpiry != nil {
		t := metav1.NewTime(*ev.NextExpiry)
		cur.NextExpiry = &t
	}
	return cur, nil
}

// apply server-side applies status.assessment when it changed. evaluatedAt
// alone never causes a write.
func (r *AssessmentReconciler) apply(ctx context.Context, b *v1alpha1.ComplianceBinding, a *v1alpha1.BindingAssessmentStatus) error {
	if b.Status.Assessment != nil {
		old, next := b.Status.Assessment.DeepCopy(), a.DeepCopy()
		if old.Current != nil && next.Current != nil {
			old.Current.EvaluatedAt, next.Current.EvaluatedAt = metav1.Time{}, metav1.Time{}
		}
		if equalJSON(old, next) {
			return nil
		}
	}
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(a)
	if err != nil {
		return err
	}
	u := &unstructured.Unstructured{Object: map[string]any{"status": map[string]any{"assessment": raw}}}
	u.SetGroupVersionKind(v1alpha1.GroupVersion.WithKind("ComplianceBinding"))
	u.SetName(b.Name)
	// Compare-and-swap: a plan computed from a stale binding (for example a
	// cache that has not yet seen the schedule this controller just wrote)
	// gets a Conflict and is recomputed, instead of overwriting the newer
	// schedule and releasing an executing run's slot.
	u.SetResourceVersion(b.ResourceVersion)
	return r.Client.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(u), client.FieldOwner(AssessmentFieldManager), client.ForceOwnership)
}

func (r *AssessmentReconciler) listUnstructured(ctx context.Context, gvk schema.GroupVersionKind, ns string, opts ...client.ListOption) ([]assessment.Object, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(gvk.GroupVersion().WithKind(gvk.Kind + "List"))
	if ns != "" {
		opts = append(opts, client.InNamespace(ns))
	}
	if err := r.Client.List(ctx, list, opts...); err != nil {
		return nil, err
	}
	out := make([]assessment.Object, 0, len(list.Items))
	for _, it := range list.Items {
		out = append(out, it.Object)
	}
	return out, nil
}

// mappingDigest identifies the content revisions the subjects were resolved
// against; the bundle carries the OSCAL mapping.
func mappingDigest(subjects []targeting.EvidenceSubject) string {
	seen := map[string]bool{}
	for _, s := range subjects {
		seen[s.BundleDigest] = true
	}
	h := sha256.Sum256([]byte(strings.Join(sortedKeys(seen), "\n")))
	return "sha256:" + hex.EncodeToString(h[:])
}

func boundLimitations(l []string) []string {
	out := make([]string, 0, min(len(l), 8))
	for _, s := range l {
		if len(out) == 8 {
			out[7] = fmt.Sprintf("%d further limitations not shown", len(l)-7)
			break
		}
		if len(s) > 256 {
			s = s[:253] + "..."
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// workloadStateChanged passes creates, deletes, and updates that change what
// policies or exception selectors can read; status-only churn is dropped.
func workloadStateChanged() predicate.Funcs {
	state := func(o client.Object) string {
		u, err := runtime.DefaultUnstructuredConverter.ToUnstructured(o)
		if err != nil {
			return ""
		}
		return collector.WorkloadState(u)
	}
	return predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
		return state(e.ObjectOld) != state(e.ObjectNew) || e.ObjectOld.GetDeletionTimestamp().IsZero() != e.ObjectNew.GetDeletionTimestamp().IsZero()
	}}
}

// allBindings enqueues every binding.
func allBindings(c client.Client) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
		var list v1alpha1.ComplianceBindingList
		if err := c.List(ctx, &list); err != nil {
			return nil
		}
		return requests(list.Items)
	})
}

// bindingForPolicy enqueues the binding named by an engine policy's labels.
func bindingForPolicy(c client.Client) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		uid := o.GetLabels()[targeting.LabelBindingUID]
		var list v1alpha1.ComplianceBindingList
		if uid == "" || c.List(ctx, &list) != nil {
			return nil
		}
		return requests(slices.DeleteFunc(list.Items, func(b v1alpha1.ComplianceBinding) bool { return string(b.UID) != uid }))
	})
}

// setupAssessments registers the assessment reconciler with the manager.
func setupAssessments(mgr manager.Manager, content targeting.ContentSource, engine EngineAvailable, cluster string, poll time.Duration) error {
	rt := currentRuntime()
	r := &AssessmentReconciler{Client: mgr.GetClient(), Reader: mgr.GetAPIReader(), Content: content, Engine: engine, Cluster: cluster, Boundaries: NewBoundaryTracker(), Runtime: rt}
	b := builder.ControllerManagedBy(mgr).Named("assessment").
		For(&v1alpha1.ComplianceBinding{}).
		Watches(&v1alpha1.ComplianceProfile{}, handler.EnqueueRequestsFromMapFunc(bindingsForProfile(mgr.GetClient())), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.Namespace{}, namespaceHandler(mgr.GetClient())).
		Watches(&v1alpha1.AssessmentRun{}, bindingForRun()).
		Watches(&v1alpha1.AssessmentRequest{}, bindingForRequest()).
		Watches(&v1alpha1.EvidenceDestination{}, allBindings(mgr.GetClient()))
	for _, res := range sortedKeys(workloadKinds) {
		obj, _ := workloadKinds[res]()
		b = b.Watches(obj, allBindings(mgr.GetClient()), builder.WithPredicates(workloadStateChanged()))
	}
	c, err := b.Build(r)
	if err != nil {
		return err
	}
	// Runs execute with bounded concurrency across all bindings; each binding
	// has at most one admitted run.
	if err := builder.ControllerManagedBy(mgr).Named("assessmentrun").
		For(&v1alpha1.AssessmentRun{}).
		Watches(&v1alpha1.ComplianceBinding{}, runsForBinding(mgr.GetClient())).
		WithOptions(controller.Options{MaxConcurrentReconciles: rt.Workers}).
		Complete(&AssessmentRunReconciler{Client: mgr.GetClient(), Assess: r, Runtime: rt, Instance: string(uuid.NewUUID())}); err != nil {
		return err
	}
	if err := builder.ControllerManagedBy(mgr).Named("evidencedestination").
		For(&v1alpha1.EvidenceDestination{}).
		Watches(&v1alpha1.AssessmentRun{}, destinationForRun(mgr.GetClient())).
		Complete(&DestinationReconciler{Client: mgr.GetClient(), Reader: mgr.GetAPIReader(), Namespace: rt.ControllerNamespace}); err != nil {
		return err
	}
	// Engine policies and reports are watched once the engine API is served.
	return mgr.Add(&engineWatches{mgr: mgr, ctrl: c, engine: engine, poll: poll})
}

// engineWatches starts the engine-policy and PolicyReport watches once the
// engine API is served, so the manager starts without Kyverno.
type engineWatches struct {
	mgr    manager.Manager
	ctrl   controller.Controller
	engine EngineAvailable
	poll   time.Duration
}

func (w *engineWatches) NeedLeaderElection() bool { return true }

func (w *engineWatches) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("assessment-engine-watches")
	t := time.NewTicker(w.poll)
	defer t.Stop()
	for {
		if ok, err := w.engine(ctx); err == nil && ok {
			policy := &unstructured.Unstructured{}
			policy.SetGroupVersionKind(targeting.ValidatingPolicyGVK)
			managed := predicate.NewPredicateFuncs(func(o client.Object) bool {
				return o.GetLabels()[targeting.LabelManagedBy] == targeting.ManagedByValue
			})
			report := &unstructured.Unstructured{}
			report.SetGroupVersionKind(PolicyReportGVK)
			errP := w.ctrl.Watch(source.Kind(w.mgr.GetCache(), client.Object(policy), bindingForPolicy(w.mgr.GetClient()), managed))
			errR := w.ctrl.Watch(source.Kind(w.mgr.GetCache(), client.Object(report), allBindings(w.mgr.GetClient())))
			if errP == nil && errR == nil {
				logger.Info("watching engine policies and policy reports")
				<-ctx.Done()
				return nil
			}
			logger.Info("could not start engine watches; retrying", "policies", errP, "reports", errR)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// destinationForRun requeues the destination a run is pinned to, so
// retirement accounting follows run progress.
func destinationForRun(c client.Client) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		uid := o.GetLabels()[LabelRunDestination]
		if uid == "" {
			return nil
		}
		var list v1alpha1.EvidenceDestinationList
		if err := c.List(ctx, &list); err != nil {
			return nil
		}
		for _, d := range list.Items {
			if string(d.UID) == uid {
				return []reconcile.Request{{NamespacedName: client.ObjectKeyFromObject(&d)}}
			}
		}
		return nil
	})
}
