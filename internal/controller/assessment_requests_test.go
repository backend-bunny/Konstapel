package controller

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
)

// newTeamEnv has two selected namespaces (prod, dev) with a privileged pod
// each, and a binding selecting both.
func newTeamEnv(t *testing.T) *runEnv {
	b := epochBinding("audit-all", map[string]v1alpha1.LabelValue{"assessed": "yes"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{CollectionTimeout: "5m"}
	e := newRunEnv(t, b)
	for _, o := range []client.Object{nsObj("dev", "assessed", "yes"), privilegedPod("dev", "web", "pod-dev")} {
		if err := e.c.Create(context.Background(), o); err != nil {
			t.Fatal(err)
		}
	}
	prod := &corev1.Namespace{}
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: "prod"}, prod)
	prod.Labels["assessed"] = "yes"
	if err := e.c.Update(context.Background(), prod); err != nil {
		t.Fatal(err)
	}
	e.deliver("audit-all")
	// Let the initial scheduled run finish so the slot is free for requests.
	e.assess("audit-all")
	first := e.schedule("audit-all").ActiveRun.Name
	e.step(first)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(first)
	if e.run(first).Status.Phase != v1alpha1.RunCompleted {
		t.Fatal("initial scheduled run did not complete")
	}
	return e
}

func (e *runEnv) request(ns, name string) *v1alpha1.AssessmentRequest {
	e.t.Helper()
	r := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, CreationTimestamp: metav1.NewTime(e.now)},
		Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: "audit-all"}}}
	if err := e.c.Create(context.Background(), r); err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *runEnv) requestStatus(ns, name string) v1alpha1.AssessmentRequestStatus {
	e.t.Helper()
	r := &v1alpha1.AssessmentRequest{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, r); err != nil {
		e.t.Fatal(err)
	}
	return r.Status
}

func noSibling(t *testing.T, what string, b []byte) {
	t.Helper()
	for _, leak := range []string{"uid-prod", "pod-prod", `"prod"`, "prod/"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("%s contains sibling data %q", what, leak)
		}
	}
}

func TestTeamRequestProducesNamespaceOnlyPackage(t *testing.T) {
	e := newTeamEnv(t)
	for range 3 { // keep the package in staging so its files can be inspected
		e.pub.Fail(fake.OpStage, publication.ErrUnavailable)
	}
	e.request("dev", "nightly")
	e.assess("audit-all")
	st := e.requestStatus("dev", "nightly")
	if st.Phase != v1alpha1.RequestRunning || st.Run == nil || st.NamespaceUID != "uid-dev" || st.Binding == nil {
		t.Fatalf("request not admitted: %+v", st)
	}
	run := e.run(st.Run.Name)
	if run.Spec.Scope != v1alpha1.RunScopeNamespace || run.Spec.Request.UID != "uid-nightly" || run.Spec.Trigger.Type != v1alpha1.TriggerRequest {
		t.Fatalf("run %+v", run.Spec)
	}
	e.step(run.Name)
	run = e.run(run.Name)
	if run.Status.Scope == nil || run.Status.Scope.NamespaceUID != "uid-dev" || run.Status.Scope.NamespaceCount != 1 {
		t.Fatalf("frozen scope %+v phase %s conds %+v", run.Status.Scope, run.Status.Phase, run.Status.Conditions)
	}
	b, _ := os.ReadFile(filepath.Join(e.rr.staging(run), "capture.json"))
	noSibling(t, "staged capture", b)

	// A cluster-wide report holds results for both teams.
	e.report("dev", "pod-dev", e.enginePolicy(), "fail", e.now.Add(time.Minute))
	e.report("prod", "pod-prod-x", e.enginePolicy(), "fail", e.now.Add(time.Minute))
	e.now = e.now.Add(2 * time.Minute)
	e.step(run.Name)
	run = e.run(run.Name)
	if run.Status.Phase != v1alpha1.RunPublishing || run.Status.Summary.Evidence.Expected != 1 || run.Status.Summary.Evidence.Completeness != "Complete" {
		t.Fatalf("namespace run %+v %+v", run.Status.Phase, run.Status.Summary)
	}
	pkg := filepath.Join(e.rr.staging(run), "package")
	d, err := publication.LoadDescriptor(pkg)
	if err != nil || d.Scope.Kind != publication.ScopeNamespace || d.Scope.Request.NamespaceUID != "uid-dev" {
		t.Fatalf("descriptor %+v %v", d.Scope, err)
	}
	_ = filepath.WalkDir(pkg, func(path string, ent fs.DirEntry, err error) error {
		if err != nil || ent.IsDir() || strings.Contains(path, "/content/") {
			return err
		}
		b, _ := os.ReadFile(path)
		noSibling(t, path, b)
		return nil
	})

	for i := 0; i < 3 && e.run(run.Name).Status.Phase != v1alpha1.RunCompleted; i++ {
		e.now = e.now.Add(30 * time.Second) // retries stay within PublishTimeout
		e.step(run.Name)
	}
	run = e.run(run.Name)
	if run.Status.Phase != v1alpha1.RunCompleted {
		t.Fatalf("not published: %+v", run.Status.Conditions)
	}
	st = e.requestStatus("dev", "nightly")
	if st.Phase != v1alpha1.RequestCompleted || st.ArtifactRef != run.Status.Publication.PublicationID || st.Summary == nil || st.Summary.Outcomes.Fail != 1 {
		t.Fatalf("request status %+v", st)
	}
	raw, _ := json.Marshal(st)
	noSibling(t, "request status", raw)
	if strings.Contains(string(raw), "bucket") || strings.Contains(string(raw), "memory://") {
		t.Fatal("request status exposes storage location")
	}
}

func TestRequestOutsideBindingScopeIsRejected(t *testing.T) {
	e := newTeamEnv(t)
	if err := e.c.Create(context.Background(), nsObj("other")); err != nil {
		t.Fatal(err)
	}
	e.request("other", "r")
	e.assess("audit-all")
	st := e.requestStatus("other", "r")
	c := meta.FindStatusCondition(st.Conditions, v1alpha1.ConditionScoped)
	if st.Phase != v1alpha1.RequestRejected || c == nil || c.Reason != v1alpha1.ReasonNamespaceNotInScope || st.Run != nil {
		t.Fatalf("%+v", st)
	}
	for _, r := range e.runs() {
		if r.Spec.Scope == v1alpha1.RunScopeNamespace {
			t.Fatal("an out-of-scope request produced a run")
		}
	}
}

func TestRequestQueueIsBounded(t *testing.T) {
	e := newTeamEnv(t)
	e.ar.Runtime.MaxQueue = 1
	e.request("dev", "first")
	e.now = e.now.Add(time.Second)
	e.request("dev", "second")
	e.assess("audit-all")
	if st := e.requestStatus("dev", "first"); st.Phase != v1alpha1.RequestRunning {
		t.Fatalf("oldest request not admitted: %+v", st.Phase)
	}
	st := e.requestStatus("dev", "second")
	c := meta.FindStatusCondition(st.Conditions, v1alpha1.ConditionScoped)
	if st.Phase != v1alpha1.RequestRejected || c == nil || c.Reason != "QueueFull" {
		t.Fatalf("newest request beyond the bound not rejected: %+v", st)
	}
}

func TestDeletedRequest(t *testing.T) {
	// Deleted before the run starts: the run fails explicitly.
	e := newTeamEnv(t)
	req := e.request("dev", "gone")
	e.assess("audit-all")
	name := e.requestStatus("dev", "gone").Run.Name
	if err := e.c.Delete(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	e.step(name)
	if r := e.run(name); r.Status.Phase != v1alpha1.RunFailed || meta.FindStatusCondition(r.Status.Conditions, v1alpha1.ConditionScoped).Reason != "RequestNotFound" {
		t.Fatalf("%+v", r.Status)
	}

	// Deleted after the run started: the run completes and its publication
	// record is retained.
	e = newTeamEnv(t)
	req = e.request("dev", "later")
	e.assess("audit-all")
	name = e.requestStatus("dev", "later").Run.Name
	e.step(name)
	if err := e.c.Delete(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(5*time.Minute + time.Second)
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted || r.Status.Publication == nil {
		t.Fatalf("started run abandoned after request deletion: %+v", r.Status.Phase)
	}
	if st, err := e.pub.Inspect(context.Background(), publication.RunRef{ClusterID: r.Status.Scope.ClusterID, BindingUID: "uid-audit-all", RunUID: string(r.UID)}); err != nil || st.Phase != publication.PhaseCommitted {
		t.Fatalf("publication not retained: %+v %v", st, err)
	}
}

func TestRecreatedNamespaceIsNotAdopted(t *testing.T) {
	e := newTeamEnv(t)
	e.request("dev", "r")
	e.assess("audit-all")
	name := e.requestStatus("dev", "r").Run.Name
	ns := &corev1.Namespace{}
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: "dev"}, ns)
	_ = e.c.Delete(context.Background(), ns)
	recreated := nsObj("dev", "assessed", "yes")
	recreated.UID = types.UID("uid-dev-2")
	if err := e.c.Create(context.Background(), recreated); err != nil {
		t.Fatal(err)
	}
	e.step(name)
	if r := e.run(name); r.Status.Phase != v1alpha1.RunFailed {
		t.Fatalf("run adopted a recreated namespace: %+v", r.Status.Phase)
	}
}
