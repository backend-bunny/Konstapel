//go:build live

package controller

// Integrated assessments (add-continuous-assessments task 6.1,
// add-s3-evidence-publishing task 6.1): two team namespaces under two
// overlapping bindings, publishing through EvidenceDestinations on the
// test-owned S3 service — one binding via the central default, the other via
// its own destinationRef — and served by the download service from each run's
// pinned destination. Scheduled and team-requested runs are checked together
// for current status, frozen scope, run-start pinning, publication,
// authorized package contents, and validated OSCAL; an engine reporting
// outage publishes an Incomplete package and an impossible OSCAL export a
// Diagnostic one, both downloadable. Run through scripts/targeting-live.sh.

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/download"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

func TestLiveIntegratedAssessments(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	ns := "konstapel-system"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "it-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	if err := l.c.Create(l.ctx, secret); err != nil {
		t.Fatal(err)
	}
	dests := map[string]*v1alpha1.EvidenceDestination{}
	for _, name := range []string{"it-default", "it-a-dest"} {
		ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{
			Endpoint: l.s3Endpoint, Bucket: pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/" + name, DevelopmentFixture: true,
			CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: secret.Name}}}}}
		if err := l.c.Create(l.ctx, ed); err != nil {
			t.Fatal(err)
		}
		dests[name] = ed
	}
	defaultCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: DefaultDestinationConfigMap},
		Data: map[string]string{DefaultDestinationNameKey: "it-default", DefaultDestinationUIDKey: string(dests["it-default"].UID)}}
	if err := l.c.Create(l.ctx, defaultCM); err != nil {
		t.Fatal(err)
	}
	dp := &DestinationPublishers{Reader: l.c, Namespace: ns}
	runtime := AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: time.Minute, Workers: 2,
		ControllerNamespace: ns, Destinations: dp}
	ConfigureAssessments(runtime)
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	l.applyFile("../../config/rbac/assessment-requester.yaml")
	l.applyFile("../../config/rbac/assessment-operator.yaml")

	teams := []string{"it-a", "it-b"}
	for _, ns := range teams {
		l.setNamespace(ns, "it-production")
	}
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "it-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	// Overlapping bindings: "wide" selects both team namespaces, "team-a"
	// selects it-a again by name label.
	wide := bindingObj("it-wide", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "it-production"})
	wide.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "40s"}
	onlyA := bindingObj("it-only-a", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{"kubernetes.io/metadata.name": "it-a"})
	onlyA.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "40s",
		DestinationRef: &v1alpha1.DestinationReference{Name: "it-a-dest", UID: string(dests["it-a-dest"].UID)}}
	yes := true
	objs := []client.Object{p, wide, onlyA}
	for _, ns := range teams {
		objs = append(objs,
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: ns},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}},
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "reader"}},
			&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "reader"},
				RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-assessment-requester"},
				Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: ns, Name: "reader"}}})
	}
	operator := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "it-operator"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-assessment-operator"},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "it-a", Name: "operator"}}}
	objs = append(objs, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "it-a", Name: "operator"}}, operator)
	t.Cleanup(func() {
		for _, o := range slices.Backward(objs) {
			_ = l.c.Delete(l.ctx, o)
		}
		l.eventually("integrated test policies removed", func() (bool, string) {
			got := l.policiesFor(wide.Name, onlyA.Name)
			return len(got) == 0, toJSON(got)
		})
		// Runs and destinations are released without waiting for package
		// expiry; the S3 service and its data are removed with the test.
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(l.ctx, &runs)
		for i := range runs.Items {
			if r := &runs.Items[i]; strings.HasPrefix(r.Spec.BindingRef.Name, "it-") {
				r.Finalizers = nil
				_ = l.c.Update(l.ctx, r)
				_ = l.c.Delete(l.ctx, r)
			}
		}
		for _, ed := range dests {
			got := &v1alpha1.EvidenceDestination{}
			if l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got) == nil {
				got.Finalizers = nil
				_ = l.c.Update(l.ctx, got)
				_ = l.c.Delete(l.ctx, got)
			}
		}
		_ = l.c.Delete(l.ctx, defaultCM)
		_ = l.c.Delete(l.ctx, secret)
	})
	for _, o := range objs {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	stop := l.startManager()
	defer func() { stop() }()
	for name := range dests {
		l.eventually(name+" ready", func() (bool, string) {
			ed := &v1alpha1.EvidenceDestination{}
			_ = l.c.Get(l.ctx, client.ObjectKey{Name: name}, ed)
			return meta.IsStatusConditionTrue(ed.Status.Conditions, v1alpha1.ConditionDestinationReady), toJSON(ed.Status)
		})
	}
	l.waitReady(wide.Name, 2)
	l.waitReady(onlyA.Name, 1)
	nsUID := map[string]string{}
	for _, ns := range teams {
		n := &corev1.Namespace{}
		_ = l.c.Get(l.ctx, client.ObjectKey{Name: ns}, n)
		nsUID[ns] = string(n.UID)
	}
	get := func(name string) *v1alpha1.AssessmentRun {
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, r); err != nil {
			return nil
		}
		return r
	}

	// 1. Current status and the first scheduled run of each binding.
	// Each binding's scheduled run is found by listing, since a run may
	// complete and leave the schedule's activeRun before it is observed.
	scheduled := map[string]*v1alpha1.AssessmentRun{}
	for _, b := range []*v1alpha1.ComplianceBinding{wide, onlyA} {
		l.eventually(b.Name+" scheduled run published", func() (bool, string) {
			var runs v1alpha1.AssessmentRunList
			_ = l.c.List(l.ctx, &runs)
			for i := range runs.Items {
				r := &runs.Items[i]
				if r.Spec.BindingRef.Name == b.Name && r.Spec.Trigger != nil && r.Spec.Trigger.Type == v1alpha1.TriggerScheduled && r.Status.Phase == v1alpha1.RunCompleted {
					scheduled[b.Name] = r
					return true, ""
				}
			}
			return false, toJSON(l.binding(b.Name).Status.Assessment)
		})
	}
	want := map[string]int32{wide.Name: 2, onlyA.Name: 1}
	for b, r := range scheduled {
		sum := r.Status.Summary
		if r.Status.Scope.NamespaceCount != want[b] || sum == nil || sum.Export != "Assessment" || sum.Evidence.Expected != want[b] ||
			r.Status.Publication == nil || r.Status.Publication.Phase != "Committed" {
			t.Fatalf("scheduled run of %s: %s", b, toJSON(r.Status))
		}
		l.eventually(b+" current evidence", func() (bool, string) {
			c := l.binding(b).Status.Assessment.Current
			return c != nil && c.Evidence.Expected == want[b] && c.Evidence.Completeness == "Complete" && c.Outcomes.Fail == want[b], toJSON(c)
		})
	}
	// Run-start pinning: the default for wide, the binding's own reference
	// for onlyA, each committed under its destination's prefix only.
	commitsUnder := func(dest, runUID string) int {
		out, err := pub.Client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{Bucket: aws.String(pub.Dest.Bucket), Prefix: aws.String("konstapel-test/" + dest + "/")})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, o := range out.Contents {
			if k := aws.ToString(o.Key); strings.Contains(k, runUID) && strings.HasSuffix(k, "/commit.json") {
				n++
			}
		}
		return n
	}
	pinnedTo := func(r *v1alpha1.AssessmentRun, dest string) {
		t.Helper()
		other := "it-default"
		if dest == other {
			other = "it-a-dest"
		}
		if r.Status.Destination == nil || r.Status.Destination.Name != dest || r.Status.Destination.UID != string(dests[dest].UID) ||
			commitsUnder(dest, string(r.UID)) != 1 || commitsUnder(other, string(r.UID)) != 0 {
			t.Fatalf("%s is not published at its pinned destination %s: %s", r.Name, dest, toJSON(r.Status.Destination))
		}
	}
	pinnedTo(scheduled[wide.Name], "it-default")
	pinnedTo(scheduled[onlyA.Name], "it-a-dest")
	l.record("scheduled", map[string]any{"wide": scheduled[wide.Name].Name, "onlyA": scheduled[onlyA.Name].Name,
		"wideDestination": "it-default (central default)", "onlyADestination": "it-a-dest (destinationRef)"})

	// 2. Team requests in both namespaces against the overlapping wide binding.
	reqs := map[string]*v1alpha1.AssessmentRequest{}
	for _, ns := range teams {
		r := &v1alpha1.AssessmentRequest{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "nightly"},
			Spec: v1alpha1.AssessmentRequestSpec{BindingRef: v1alpha1.BindingReference{Name: wide.Name}}}
		if err := l.c.Create(l.ctx, r); err != nil {
			t.Fatal(err)
		}
		reqs[ns] = r
		objs = append(objs, r)
	}
	teamRuns := map[string]*v1alpha1.AssessmentRun{}
	for _, ns := range teams {
		l.eventually(ns+" request published", func() (bool, string) {
			got := &v1alpha1.AssessmentRequest{}
			_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(reqs[ns]), got)
			reqs[ns] = got
			return got.Status.Phase == v1alpha1.RequestCompleted && got.Status.ArtifactRef != "", toJSON(got.Status)
		})
		r := get(reqs[ns].Status.Run.Name)
		if r.Spec.Scope != v1alpha1.RunScopeNamespace || r.Status.Scope.NamespaceUID != nsUID[ns] || r.Status.Scope.NamespaceCount != 1 ||
			reqs[ns].Status.NamespaceUID != nsUID[ns] || r.Status.Summary.Evidence.Expected != 1 || r.Status.Publication.PublicationID != reqs[ns].Status.ArtifactRef {
			t.Fatalf("%s team run: %s", ns, toJSON(r.Status))
		}
		pinnedTo(r, "it-default")
		teamRuns[ns] = r
	}
	l.record("team-requests", map[string]any{"it-a": teamRuns["it-a"].Name, "it-b": teamRuns["it-b"].Name})

	// 3. Scope is frozen: moving it-b out of the wide binding changes current
	// status, not published runs.
	frozen := toJSON(scheduled[wide.Name].Status.Scope)
	l.setNamespace("it-b", "it-elsewhere")
	l.waitReady(wide.Name, 1)
	if got := get(scheduled[wide.Name].Name); toJSON(got.Status.Scope) != frozen || got.Status.Publication.PackageSHA256 != scheduled[wide.Name].Status.Publication.PackageSHA256 {
		t.Fatalf("published run changed after relabel: %s", toJSON(got.Status))
	}
	l.eventually("current status follows the relabel", func() (bool, string) {
		c := l.binding(wide.Name).Status.Assessment.Current
		return c != nil && c.Evidence.Expected == 1, toJSON(c)
	})

	// 4. Authorized downloads: each team gets exactly its own validated package.
	srv := &download.Server{Reader: l.c, Reviews: download.KubeReviewer{Client: l.c, Audience: downloadAudience}, TempDir: t.TempDir(),
		PublisherFor: func(ctx context.Context, r *v1alpha1.AssessmentRun) (publication.Publisher, error) {
			return dp.For(ctx, r.Status.Destination)
		}}
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()
	hc := ts.Client()
	teamURL := func(ns string) string {
		return ts.URL + "/v1/namespaces/" + ns + "/assessmentrequests/nightly/download?uid=" + string(reqs[ns].UID)
	}
	// validate unpacks and fully validates a package, returning its
	// descriptor and the concatenated contents of its files.
	validate := func(what string, body []byte) (publication.Descriptor, string) {
		dir := t.TempDir()
		untar(t, body, dir)
		d, err := s3store.ValidatePackage(dir)
		if err != nil {
			t.Fatalf("%s package does not validate: %v", what, err)
		}
		var all strings.Builder
		_ = filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
			if err == nil && !e.IsDir() && !strings.Contains(p, "/content/") {
				b, _ := os.ReadFile(p)
				all.Write(b)
			}
			return nil
		})
		return d, all.String()
	}
	for _, ns := range teams {
		other := teams[0]
		if ns == other {
			other = teams[1]
		}
		tok := l.token(ns, "reader", downloadAudience)
		code, body := fetch(t, hc, teamURL(ns), tok)
		if code != http.StatusOK {
			t.Fatalf("%s download: %d %s", ns, code, body)
		}
		d, files := validate(ns, body)
		if d.Scope.Kind != publication.ScopeNamespace || d.Scope.Request == nil || d.Scope.Request.NamespaceUID != nsUID[ns] ||
			strings.Contains(files, `"`+other+`"`) || strings.Contains(files, nsUID[other]) {
			t.Fatalf("%s package scope %+v or mentions %s", ns, d.Scope, other)
		}
		if code, _ := fetch(t, hc, teamURL(other), tok); code != http.StatusForbidden {
			t.Fatalf("%s reached %s's package: %d", ns, other, code)
		}
		for _, r := range scheduled {
			if code, _ := fetch(t, hc, ts.URL+"/v1/assessmentruns/"+string(r.UID)+"/download", tok); code != http.StatusForbidden {
				t.Fatalf("%s reached full-binding run %s: %d", ns, r.Name, code)
			}
		}
	}
	opTok := l.token("it-a", "operator", downloadAudience)
	for b, r := range scheduled {
		code, body := fetch(t, hc, ts.URL+"/v1/assessmentruns/"+string(r.UID)+"/download", opTok)
		if code != http.StatusOK {
			t.Fatalf("operator download of %s: %d %s", b, code, body)
		}
		d, _ := validate(b, body)
		if d.Scope.Kind != publication.ScopeBinding || int32(len(d.Scope.NamespaceUIDs)) != want[b] || d.Evidence.Completeness != publication.Complete {
			t.Fatalf("%s binding package %+v %+v", b, d.Scope, d.Evidence)
		}
	}

	// 5. Incomplete and Diagnostic publications through onlyA's destination.
	manual := func(name string) *v1alpha1.AssessmentRun {
		t.Helper()
		r := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: onlyA.Name}, Scope: v1alpha1.RunScopeBinding}}
		if err := l.c.Create(l.ctx, r); err != nil {
			t.Fatal(err)
		}
		l.eventually(name+" published", func() (bool, string) {
			got := get(name)
			return got != nil && got.Status.Phase == v1alpha1.RunCompleted && got.Status.Publication != nil, toJSON(got)
		})
		got := get(name)
		pinnedTo(got, "it-a-dest")
		return got
	}
	operatorPackage := func(r *v1alpha1.AssessmentRun) publication.Descriptor {
		t.Helper()
		code, body := fetch(t, hc, ts.URL+"/v1/assessmentruns/"+string(r.UID)+"/download", opTok)
		if code != http.StatusOK {
			t.Fatalf("operator download of %s: %d %s", r.Name, code, body)
		}
		d, _ := validate(r.Name, body)
		return d
	}
	// An engine reporting outage while a workload is added: no evaluation
	// arrives for it, so the snapshot is published as Incomplete, never
	// Complete.
	l.scaleKyverno("kyverno-reports-controller", 0)
	l.scaleKyverno("kyverno-background-controller", 0)
	added := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged-added", Namespace: "it-a"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	if err := l.c.Create(l.ctx, added); err != nil {
		t.Fatal(err)
	}
	objs = append(objs, added)
	incomplete := manual("it-only-a-incomplete")
	l.scaleKyverno("kyverno-reports-controller", 1)
	l.scaleKyverno("kyverno-background-controller", 1)
	if ev := incomplete.Status.Summary.Evidence; ev.Completeness != "Incomplete" || incomplete.Status.Summary.Export != "Assessment" {
		t.Fatalf("outage run: %s", toJSON(incomplete.Status.Summary))
	}
	if d := operatorPackage(incomplete); d.PackageKind != publication.KindAssessment || d.Evidence.Completeness != publication.Incomplete {
		t.Fatalf("incomplete package %+v %+v", d.PackageKind, d.Evidence)
	}
	// An impossible OSCAL export (no shipped content to map to) publishes a
	// typed Diagnostic package instead of invalid OSCAL. The runtime is read
	// when the manager starts, so it restarts with the broken content root
	// and again with the real one.
	broken := runtime
	broken.ContentRoot = t.TempDir()
	stop()
	ConfigureAssessments(broken)
	stop = l.startManager()
	diagnostic := manual("it-only-a-diagnostic")
	stop()
	ConfigureAssessments(runtime)
	stop = l.startManager()
	if diagnostic.Status.Summary.Export != "Diagnostic" || diagnostic.Status.Publication.Phase != "Committed" {
		t.Fatalf("diagnostic run: %s", toJSON(diagnostic.Status))
	}
	if d := operatorPackage(diagnostic); d.PackageKind != publication.KindDiagnostic || d.Diagnostic == nil || d.Diagnostic.Reason != "ExportFailed" {
		t.Fatalf("diagnostic package %+v %+v", d.PackageKind, d.Diagnostic)
	}
	l.record("publication-kinds", map[string]any{"incomplete": incomplete.Name, "diagnostic": diagnostic.Name})
	l.record("integrated-passed", map[string]any{"bindings": 2, "teams": len(teams), "destinations": 2})
}
