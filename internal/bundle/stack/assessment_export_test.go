package stack_test

// Assessment runs of OCI bundles (add-policy-bundle-distribution 7.2): a
// run freezes the exact verified bundle when it starts, and exports,
// replays and packages only that copy. The real AssessmentReconciler,
// AssessmentRunReconciler and BindingReconciler run over a fake API server
// and the controller's Router, with content served by the real OCIContent
// over a real cache: a crafted bundle whose catalog and mapping differ from
// the vendored content (so a substituted vendored export is detectably
// wrong), and the Cosign-signed fixture through the complete stack. Every
// published package is opened and checked.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/bundletest"
	"github.com/backend-bunny/Konstapel/internal/bundle/cache"
	bundlecontent "github.com/backend-bunny/Konstapel/internal/bundle/content"
	"github.com/backend-bunny/Konstapel/internal/bundle/resolve"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/controller"
	"github.com/backend-bunny/Konstapel/internal/publication"
	pubfake "github.com/backend-bunny/Konstapel/internal/publication/fake"
	"github.com/backend-bunny/Konstapel/internal/s3store"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

var runT0 = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

// revocableResolver is craftedResolver with a trust switch and a
// compatibility switch, judged on every resolution exactly as the real
// resolver judges acceptance.
type revocableResolver struct {
	craftedResolver
	revoked, incompatible atomic.Bool
}

func (r *revocableResolver) judge(ctx context.Context, name, digest string) error {
	if r.revoked.Load() {
		return fmt.Errorf("%w: the publisher key was revoked", resolve.ErrUntrusted)
	}
	if r.incompatible.Load() {
		return fmt.Errorf("%w: requires a newer controller", resolve.ErrIncompatible)
	}
	return r.craftedResolver.judge(ctx, name, digest)
}

func (r *revocableResolver) Resolve(ctx context.Context, req resolve.Request) (bundle.ResolvedContent, error) {
	if err := r.judge(ctx, req.Name, req.Digest); err != nil {
		return bundle.ResolvedContent{}, err
	}
	h, err := r.craftedResolver.Resolve(ctx, req)
	if err != nil {
		return h, err
	}
	// A receipt as the real resolver records one.
	h.Receipt.Version, h.Receipt.SourceRule, h.Receipt.TrustRevision, h.Receipt.VerifiedAt = bundle.HandleVersion, "crafted-rule", "crafted-trust", runT0
	return h, nil
}

// runCluster runs the binding, assessment and run reconcilers.
type runCluster struct {
	t        *testing.T
	c        client.Client
	pub      *pubfake.Publisher
	binding  *controller.BindingReconciler
	assess   *controller.AssessmentReconciler
	runs     *controller.AssessmentRunReconciler
	staging  string
	now      time.Time
	ref      v1alpha1.BundleReference
	failNext atomic.Bool // fail the next run status update to Publishing
	// ready is the engine's readiness of a delivered policy; nil means
	// every policy is ready.
	ready atomic.Pointer[func(*unstructured.Unstructured) bool]
}

func newRunCluster(t *testing.T, router *stack.Router, ref v1alpha1.BundleReference) *runCluster {
	t.Helper()
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(targeting.ValidatingPolicyGVK, meta.RESTScopeRoot)
	mapper.Add(controller.PolicyReportGVK, meta.RESTScopeNamespace)
	for _, k := range []string{"ComplianceBinding", "ComplianceProfile", "AssessmentRun", "EvidenceDestination"} {
		mapper.Add(v1alpha1.GroupVersion.WithKind(k), meta.RESTScopeRoot)
	}
	mapper.Add(v1alpha1.GroupVersion.WithKind("AssessmentRequest"), meta.RESTScopeNamespace)
	for _, gvk := range []schema.GroupVersionKind{{Version: "v1", Kind: "Namespace"}} {
		mapper.Add(gvk, meta.RESTScopeRoot)
	}
	for _, gvk := range []schema.GroupVersionKind{{Version: "v1", Kind: "Pod"}, {Version: "v1", Kind: "ConfigMap"}, {Version: "v1", Kind: "Secret"},
		{Version: "v1", Kind: "ReplicationController"}, {Group: "apps", Version: "v1", Kind: "Deployment"}, {Group: "apps", Version: "v1", Kind: "DaemonSet"},
		{Group: "apps", Version: "v1", Kind: "StatefulSet"}, {Group: "apps", Version: "v1", Kind: "ReplicaSet"}, {Group: "batch", Version: "v1", Kind: "Job"},
		{Group: "batch", Version: "v1", Kind: "CronJob"}} {
		mapper.Add(gvk, meta.RESTScopeNamespace)
	}
	yes := true
	rc := &runCluster{t: t, now: runT0, ref: ref, pub: pubfake.New(nil), staging: t.TempDir()}
	rc.pub = pubfake.New(func() time.Time { return rc.now })
	c := fake.NewClientBuilder().WithScheme(controller.Scheme()).WithRESTMapper(mapper).
		WithObjects(
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app", UID: "uid-app", Labels: map[string]string{"team": "a"}}},
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "web", UID: "pod-1"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "x", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}},
			&v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "org", UID: "uid-org", Generation: 1},
				Spec: v1alpha1.ComplianceProfileSpec{Bundle: ref, Policies: []v1alpha1.ProfilePolicy{{Name: assessment.PolicyName}}}},
			&v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "org", UID: "uid-binding", Generation: 1},
				Spec: v1alpha1.ComplianceBindingSpec{ProfileRef: v1alpha1.ProfileReference{Name: "org"}, Mode: v1alpha1.ModeAudit, EnforcementEpoch: 1,
					NamespaceSelector: &v1alpha1.NamespaceSelector{MatchLabels: map[string]v1alpha1.LabelValue{"team": "a"}},
					Assessment:        &v1alpha1.BindingAssessment{CollectionTimeout: "5m"}}},
		).
		WithStatusSubresource(&v1alpha1.ComplianceBinding{}, &v1alpha1.ComplianceProfile{}, &v1alpha1.AssessmentRun{}, &v1alpha1.AssessmentRequest{}, &v1alpha1.EvidenceDestination{}).
		WithIndex(&v1alpha1.ComplianceBinding{}, controller.ProfileRefIndex, func(o client.Object) []string {
			return []string{o.(*v1alpha1.ComplianceBinding).Spec.ProfileRef.Name}
		}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if obj.GetUID() == "" {
					obj.SetUID(types.UID("uid-" + obj.GetName()))
				}
				return c.Create(ctx, obj, opts...)
			},
			SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				if r, ok := obj.(*v1alpha1.AssessmentRun); ok && r.Status.Phase == v1alpha1.RunPublishing && rc.failNext.CompareAndSwap(true, false) {
					return errors.New("injected: controller stopped before recording closure")
				}
				return c.SubResource(sub).Update(ctx, obj, opts...)
			},
		}).Build()
	rc.c = c
	engine := func(context.Context) (bool, error) { return true, nil }
	rc.binding = &controller.BindingReconciler{Client: c, Reader: c, Cluster: "kube-system:test", Engine: engine,
		Ready: func(o *unstructured.Unstructured) bool {
			if f := rc.ready.Load(); f != nil {
				return (*f)(o)
			}
			return true
		}, ValidateParameters: bundlecontent.ValidateParameters}
	root, err := filepath.Abs(stack.RepoRoot)
	if err != nil {
		t.Fatal(err)
	}
	rt := controller.AssessmentRuntime{Publisher: rc.pub, StagingDir: rc.staging, ContentRoot: root, Poll: 10 * time.Second, PublishTimeout: 5 * time.Minute, Workers: 1}
	rc.assess = &controller.AssessmentReconciler{Client: c, Reader: c, Cluster: "kube-system:test", Boundaries: controller.NewBoundaryTracker(),
		Engine: engine, Now: func() time.Time { return rc.now }, Runtime: rt}
	rc.runs = &controller.AssessmentRunReconciler{Client: c, Assess: rc.assess, Runtime: rt, Now: func() time.Time { return rc.now }}
	rc.setRouter(router)
	return rc
}

// setRouter points every reconciler at router (a restarted stack).
func (rc *runCluster) setRouter(router *stack.Router) {
	rc.binding.Content, rc.assess.Content = router, router
}

func (rc *runCluster) reconcile(r interface {
	Reconcile(context.Context, ctrl.Request) (ctrl.Result, error)
}, name string) error {
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}})
	return err
}

func (rc *runCluster) must(err error) {
	rc.t.Helper()
	if err != nil {
		rc.t.Fatal(err)
	}
}

// deliver applies the binding's engine policy from current content.
func (rc *runCluster) deliver() {
	rc.t.Helper()
	for range 2 {
		rc.must(rc.reconcile(rc.binding, "org"))
	}
}

// start plans the binding's first run and starts it; it returns the run.
func (rc *runCluster) start() *v1alpha1.AssessmentRun {
	rc.t.Helper()
	rc.must(rc.reconcile(rc.assess, "org"))
	b := &v1alpha1.ComplianceBinding{}
	rc.must(rc.c.Get(context.Background(), client.ObjectKey{Name: "org"}, b))
	if b.Status.Assessment == nil || b.Status.Assessment.Schedule == nil || b.Status.Assessment.Schedule.ActiveRun == nil {
		rc.t.Fatalf("no run admitted: %+v", b.Status.Assessment)
	}
	name := b.Status.Assessment.Schedule.ActiveRun.Name
	rc.must(rc.reconcile(rc.runs, name))
	run := rc.run(name)
	if run.Status.Phase != v1alpha1.RunCollecting {
		rc.t.Fatalf("run did not start: %+v", run.Status)
	}
	return run
}

func (rc *runCluster) run(name string) *v1alpha1.AssessmentRun {
	rc.t.Helper()
	r := &v1alpha1.AssessmentRun{}
	rc.must(rc.c.Get(context.Background(), client.ObjectKey{Name: name}, r))
	return r
}

// report records an attributable failure for the pod from the delivered
// engine policy, if one is delivered.
func (rc *runCluster) report(at time.Time) {
	rc.t.Helper()
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(targeting.ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
	rc.must(rc.c.List(context.Background(), list))
	if len(list.Items) != 1 {
		rc.t.Fatalf("want one engine policy, have %d", len(list.Items))
	}
	rc.reportFor(list.Items[0].GetName(), at)
}

// finish advances the run past its collection timeout until it is done.
func (rc *runCluster) finish(name string) *v1alpha1.AssessmentRun {
	rc.t.Helper()
	rc.now = runT0.Add(6 * time.Minute)
	for range 3 {
		if err := rc.reconcile(rc.runs, name); err != nil && !strings.Contains(err.Error(), "injected") {
			rc.t.Fatal(err)
		}
		if r := rc.run(name); r.Status.Phase == v1alpha1.RunCompleted || r.Status.Phase == v1alpha1.RunFailed {
			return r
		}
	}
	rc.t.Fatalf("run did not finish: %+v", rc.run(name).Status)
	return nil
}

// pkg opens the run's published package into a directory.
func (rc *runCluster) pkg(run *v1alpha1.AssessmentRun) (string, publication.Descriptor) {
	rc.t.Helper()
	if run.Status.Phase != v1alpha1.RunCompleted {
		rc.t.Fatalf("run not published: %+v", run.Status)
	}
	ref := publication.RunRef{ClusterID: run.Status.Scope.ClusterID, BindingUID: run.Status.Binding.UID, RunUID: string(run.UID)}
	r, _, err := rc.pub.Open(context.Background(), ref)
	rc.must(err)
	raw, err := io.ReadAll(r)
	rc.must(err)
	// The fake publisher's archive: name NUL size NUL bytes, repeated.
	dir := rc.t.TempDir()
	for len(raw) > 0 {
		parts := bytes.SplitN(raw, []byte{0}, 3)
		if len(parts) != 3 {
			rc.t.Fatal("malformed fake archive")
		}
		n, err := strconv.Atoi(string(parts[1]))
		rc.must(err)
		p := filepath.Join(dir, filepath.FromSlash(string(parts[0])))
		rc.must(os.MkdirAll(filepath.Dir(p), 0o755))
		rc.must(os.WriteFile(p, parts[2][:n], 0o644))
		raw = parts[2][n:]
	}
	d, err := publication.LoadDescriptor(dir)
	rc.must(err)
	rc.must(publication.VerifyDir(dir, d))
	return dir, d
}

// requireBundleExport fails unless the package is an assessment exported
// from exactly the frozen bundle ref, verifiable offline.
func requireBundleExport(t *testing.T, dir string, d publication.Descriptor, ref v1alpha1.BundleReference) *bundle.Frozen {
	t.Helper()
	if d.PackageKind != publication.KindAssessment {
		t.Fatalf("package %s: %+v", d.PackageKind, d.Diagnostic)
	}
	f, err := bundle.ReadFrozen(dir)
	if err != nil {
		t.Fatalf("package does not carry the frozen bundle: %v", err)
	}
	if f.Identity.Name != ref.Name || f.Identity.Digests.OCI != ref.Digest {
		t.Fatalf("packaged %s@%s, want %s@%s", f.Identity.Name, f.Identity.Digests.OCI, ref.Name, ref.Digest)
	}
	if c := d.Revisions.Content; c == nil || !c.Frozen || c.ManifestDigest != ref.Digest || c.SourceRule == "" || c.TrustRevision == "" || c.VerifiedAt == nil {
		t.Fatalf("content revision %+v", d.Revisions.Content)
	}
	if err := collector.VerifyPackage(dir); err != nil {
		t.Fatal(err)
	}
	// The storage backend's pre-archive validation accepts it as well.
	if _, err := s3store.ValidatePackage(dir); err != nil {
		t.Fatal(err)
	}
	ar, err := os.ReadFile(filepath.Join(dir, "assessment-results.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ar), ref.Digest) {
		t.Fatal("results do not name the bundle digest")
	}
	return f
}

// requireCrafted fails unless the package's OSCAL is the crafted bundle's.
func requireCrafted(t *testing.T, dir string) {
	t.Helper()
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join(dir, p))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	ssp, ar := read("system-security-plan.json"), read("assessment-results.json")
	if !strings.Contains(ssp, `"`+bundletest.Statement+`"`) || strings.Contains(ssp, `"`+bundletest.VendoredStatement+`"`) || !strings.Contains(ar, bundletest.Rationale) {
		t.Fatal("the exported mapping is not the bundle's (vendored content substituted)")
	}
	if !strings.Contains(read(assessment.NIST+"NIST_SP-800-53_rev5_catalog.json"), bundletest.CatalogTitle) {
		t.Fatal("the packaged catalog is not the bundle's")
	}
}

func requireDiagnostic(t *testing.T, rc *runCluster, run *v1alpha1.AssessmentRun, reason, detail string) {
	t.Helper()
	dir, d := rc.pkg(run)
	if d.PackageKind != publication.KindDiagnostic || d.Diagnostic == nil || d.Diagnostic.Reason != reason || !strings.Contains(d.Diagnostic.Message, detail) {
		t.Fatalf("want a %s diagnostic mentioning %q, got %s %+v", reason, detail, d.PackageKind, d.Diagnostic)
	}
	if run.Status.Summary == nil || run.Status.Summary.Export != v1alpha1.ExportState(publication.ExportDiagnostic) {
		t.Fatalf("run summary %+v", run.Status.Summary)
	}
	for _, p := range []string{"assessment-results.json", "content", bundle.FrozenDir} {
		if _, err := os.Stat(filepath.Join(dir, p)); !os.IsNotExist(err) {
			t.Fatalf("diagnostic package contains %s", p)
		}
	}
	if c := d.Revisions.Content; c == nil || c.Bundle != rc.ref.Name || c.ManifestDigest != rc.ref.Digest {
		t.Fatalf("diagnostic does not identify the bundle: %+v", c)
	}
}

// craftedWorld is a real cache holding the crafted bundle, served by the
// real OCIContent through the controller's Router.
type craftedWorld struct {
	t        *testing.T
	archive  *bundle.Archive
	resolver *revocableResolver
	cache    *cache.Cache
}

func newCraftedWorld(t *testing.T) *craftedWorld {
	t.Helper()
	a, err := bundletest.Differing(stack.RepoRoot, bundletest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	w := &craftedWorld{t: t, archive: a}
	w.open(true)
	return w
}

// open opens a fresh cache (the default content check validates the
// crafted bundle as production does), holding the bundle when filled.
func (w *craftedWorld) open(filled bool) {
	w.t.Helper()
	c, err := cache.Open(w.t.TempDir(), cache.Config{})
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { c.Close() })
	if filled {
		if _, err := c.Put(context.Background(), w.archive.Manifest, w.archive.Layer); err != nil {
			w.t.Fatal(err)
		}
	}
	old := w.resolver
	w.resolver = &revocableResolver{craftedResolver: craftedResolver{c: c, compat: bundlecontent.Compatibility{Controller: "0.1.0"}}}
	if old != nil {
		w.resolver.revoked.Store(old.revoked.Load())
	}
	w.cache = c
}

func (w *craftedWorld) router() *stack.Router {
	oci, err := bundlecontent.New(bundlecontent.Config{Resolver: w.resolver, Entries: w.cache})
	if err != nil {
		w.t.Fatal(err)
	}
	r := w.resolver
	return stack.NewTestRouter(stack.LocalContent(), stack.VendoredName, oci, func(name, digest string) error {
		if err := r.judge(context.Background(), name, digest); err != nil {
			return fmt.Errorf("%w: %w", resolve.ErrStale, err)
		}
		return nil
	})
}

func (w *craftedWorld) ref() v1alpha1.BundleReference {
	return v1alpha1.BundleReference{Name: w.archive.Descriptor.Name, Digest: w.archive.ManifestDigest}
}

// A run of a bundle whose catalog and mapping differ from the vendored
// content exports that bundle's OSCAL, from the copy frozen at start, even
// after the live content became unusable: the cache entry evicted (no
// registry can restore it), trust revoked, or both, and also when export
// is replayed after a crash under the changed state.
func TestOCIRunExportsFrozenBundle(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(w *craftedWorld, rc *runCluster){
		"unchanged": func(*craftedWorld, *runCluster) {},
		"evicted": func(w *craftedWorld, rc *runCluster) {
			w.open(false)
			rc.setRouter(w.router())
		},
		"trust revoked": func(w *craftedWorld, _ *runCluster) { w.resolver.revoked.Store(true) },
		"evicted and revoked": func(w *craftedWorld, rc *runCluster) {
			w.open(false)
			w.resolver.revoked.Store(true)
			rc.setRouter(w.router())
		},
	} {
		for _, replay := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/replay=%v", name, replay), func(t *testing.T) {
				t.Parallel()
				w := newCraftedWorld(t)
				rc := newRunCluster(t, w.router(), w.ref())
				rc.deliver()
				run := rc.start()
				if n := w.cache.Stats().Leases; n != 0 {
					t.Fatalf("%d cache leases held after freezing; the run must not depend on the cache", n)
				}
				rc.report(runT0.Add(time.Minute))
				if replay {
					// Export completes, then the closure is not recorded:
					// the next attempt re-exports from the same frozen copy.
					rc.failNext.Store(true)
					rc.now = runT0.Add(6 * time.Minute)
					if err := rc.reconcile(rc.runs, run.Name); err == nil || !strings.Contains(err.Error(), "injected") {
						t.Fatalf("closure was not interrupted: %v", err)
					}
				}
				change(w, rc)
				run = rc.finish(run.Name)
				dir, d := rc.pkg(run)
				requireBundleExport(t, dir, d, w.ref())
				requireCrafted(t, dir)
				// Evidence keeps its own meaning: a live content change
				// during collection leaves the observation unresolved (it
				// is never attributed across it); a change after closure
				// cannot affect it. The OSCAL is the frozen bundle's either way.
				if attributable := replay || name == "unchanged"; d.Evidence.Expected != 1 ||
					(attributable && (d.Evidence.Attributable != 1 || d.Outcomes.Fail != 1)) ||
					(!attributable && d.Evidence.Unresolved != 1) {
					t.Fatalf("evidence %+v outcomes %+v", d.Evidence, d.Outcomes)
				}
			})
		}
	}
}

// Content that cannot be frozen when the run starts makes the run's package
// an explicit Diagnostic; nothing is exported from the vendored content.
// Content that becomes available before closure is frozen then.
func TestOCIRunUnfrozenContentIsDiagnostic(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		break_ func(w *craftedWorld, rc *runCluster)
		detail string
	}{
		"untrusted":    {func(w *craftedWorld, _ *runCluster) { w.resolver.revoked.Store(true) }, string(targeting.ContentErrorUntrusted)},
		"incompatible": {func(w *craftedWorld, _ *runCluster) { w.resolver.incompatible.Store(true) }, string(targeting.ContentErrorIncompatible)},
		"missing": {func(w *craftedWorld, rc *runCluster) {
			w.open(false)
			rc.setRouter(w.router())
		}, string(targeting.ContentErrorContentUnavailable)},
		"sources disabled": {func(_ *craftedWorld, rc *runCluster) {
			rc.setRouter(stack.NewRouter(stack.LocalContent(), stack.VendoredName))
		}, string(targeting.ContentErrorConfig)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newCraftedWorld(t)
			rc := newRunCluster(t, w.router(), w.ref())
			rc.deliver()
			tc.break_(w, rc)
			run := rc.start()
			run = rc.finish(run.Name)
			requireDiagnostic(t, rc, run, collector.ReasonContentUnavailable, tc.detail)
		})
	}

	t.Run("restored before closure", func(t *testing.T) {
		t.Parallel()
		w := newCraftedWorld(t)
		rc := newRunCluster(t, w.router(), w.ref())
		rc.deliver()
		w.resolver.revoked.Store(true)
		run := rc.start()
		w.resolver.revoked.Store(false)
		run = rc.finish(run.Name)
		dir, d := rc.pkg(run)
		requireBundleExport(t, dir, d, w.ref())
		requireCrafted(t, dir)
	})
}

// A frozen copy lost or altered before export is never re-resolved under
// later state and never substituted: the package is a ContentLost
// diagnostic.
func TestOCIRunLostFrozenContentIsDiagnostic(t *testing.T) {
	t.Parallel()
	for name, damage := range map[string]func(dir string) error{
		"removed": os.RemoveAll,
		"mapping edited": func(dir string) error {
			p := filepath.Join(dir, "content/component-definition.json")
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(p, bytes.Replace(b, []byte(bundletest.Statement), []byte("cm-7_smt.a"), 1), 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newCraftedWorld(t)
			rc := newRunCluster(t, w.router(), w.ref())
			rc.deliver()
			run := rc.start()
			if err := damage(filepath.Join(rc.staging, string(run.UID), "frozen-bundle")); err != nil {
				t.Fatal(err)
			}
			run = rc.finish(run.Name)
			requireDiagnostic(t, rc, run, collector.ReasonContentLost, "never re-resolved")
		})
	}
}

// The Cosign-signed fixture through the complete stack (registry fetcher,
// verifier, acceptances, Watcher, resolver, cache): the frozen package
// records the real verification receipt and survives trust revocation and
// the loss of both the cache and the registry after the run started.
func TestOCIRunSignedBundleSurvivesRevocationAndLoss(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(w *stack.World, rc *runCluster){
		"trust revoked": func(w *stack.World, _ *runCluster) { w.SetSources(w.OtherSource()); w.Sync() },
		"cache and registry lost": func(w *stack.World, rc *runCluster) {
			w.Fetch.Down.Store(true)
			if err := w.Stack.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(w.Opts.CacheDir); err != nil {
				t.Fatal(err)
			}
			w.Open()
			rc.setRouter(w.Stack.Router(stack.LocalContent(), stack.VendoredName))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := stack.NewWorld(t)
			rc := newRunCluster(t, w.Stack.Router(stack.LocalContent(), stack.VendoredName), w.Ref())
			rc.deliver()
			run := rc.start()
			rc.report(runT0.Add(time.Minute))
			change(w, rc)
			if _, err := rc.assess.Content.Content(context.Background(), w.Ref()); err == nil {
				t.Fatal("the live content is still usable; the change did not take effect")
			}
			run = rc.finish(run.Name)
			dir, d := rc.pkg(run)
			f := requireBundleExport(t, dir, d, w.Ref())
			if f.Identity.Receipt.Signer.Kind != bundle.SignerPublicKey || f.Identity.Receipt.Signer.KeyFingerprint != w.Fix.FPOrg ||
				f.Identity.Receipt.Provenance.Repository == "" || d.Revisions.Content.TrustRevision != f.Identity.Receipt.TrustRevision {
				t.Fatalf("the frozen verification context is not the signed fixture's: %+v", f.Identity.Receipt)
			}
		})
	}
}
