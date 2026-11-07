//go:build live

package controller

// Live evidence recovery (add-s3-evidence-publishing task 6.2) on an
// object-lock bucket of the test-owned S3 service, through a pinned
// EvidenceDestination:
//   - a retention edit changes only later publications; the earlier receipt
//     and the engine policies are unchanged;
//   - a legal hold on a package makes expiry cleanup fail visibly
//     (RetentionBlocked/DeletionFailed, a destination cleanup blocker) with
//     bounded retries and the stored bytes intact; lifting it lets the retry
//     delete every version and leave a Deleted tombstone without its
//     retention finalizer;
//   - a binding deleted while its run is publishing against an outage: the
//     run publishes with its recorded retention once storage returns, and a
//     binding recreated under the same name never adopts it;
//   - revoking a platform operator's binding stops new downloads.
// Run through scripts/targeting-live.sh.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/download"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

func TestLiveEvidenceRecovery(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	pub := startS3(t, l)
	const bucket = "konstapel-lock"
	if _, err := pub.Client.CreateBucket(l.ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket), ObjectLockEnabledForBucket: aws.Bool(true)}); err != nil {
		t.Fatalf("object-lock bucket: %v", err)
	}
	ns := "konstapel-system"
	_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "er-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "er-dest"}, Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{
		Endpoint: l.s3Endpoint, Bucket: bucket, Region: "us-east-1", Prefix: "konstapel-test/er-dest", DevelopmentFixture: true,
		CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: secret.Name}}}}}
	for _, o := range []client.Object{secret, ed} {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	l.applyFile("../../config/rbac/assessment-operator.yaml")
	// The shipped epoch policy keeps enforcement identity stable across
	// edits that do not change enforcement (such as retention).
	l.epochPolicyInstalled(true)
	t.Cleanup(func() { l.epochPolicyInstalled(false) })
	l.setNamespace("er-prod", "er-production")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "er-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	newBinding := func() *v1alpha1.ComplianceBinding {
		b := bindingObj("er-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "er-production"})
		b.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "20s", Retention: "60s",
			DestinationRef: &v1alpha1.DestinationReference{Name: ed.Name, UID: string(ed.UID)}}
		return b
	}
	b := newBinding()
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "privileged", Namespace: "er-prod"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.invalid/x:1", SecurityContext: &corev1.SecurityContext{Privileged: &yes}}}}}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: "er-prod", Name: "operator"}}
	crb := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "er-operator"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-assessment-operator"},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: "er-prod", Name: sa.Name}}}
	for _, o := range []client.Object{p, b, pod, sa, crb} {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "unpause", l.s3Container).Run()
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(l.ctx, &runs)
		for i := range runs.Items {
			if r := &runs.Items[i]; r.Spec.BindingRef.Name == "er-audit" {
				r.Finalizers = nil
				_ = l.c.Update(l.ctx, r)
				_ = l.c.Delete(l.ctx, r)
			}
		}
		for _, o := range []client.Object{crb, sa, pod, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "er-audit"}}, p} {
			_ = l.c.Delete(l.ctx, o)
		}
		l.eventually("recovery test policies removed", func() (bool, string) { got := l.policiesFor("er-audit"); return len(got) == 0, toJSON(got) })
		got := &v1alpha1.EvidenceDestination{}
		if l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got) == nil {
			got.Finalizers = nil
			_ = l.c.Update(l.ctx, got)
			_ = l.c.Delete(l.ctx, got)
		}
		_ = l.c.Delete(l.ctx, secret)
	})
	dp := &DestinationPublishers{Reader: l.c, Namespace: ns}
	ConfigureAssessments(AssessmentRuntime{StagingDir: t.TempDir(), ContentRoot: root, Poll: 3 * time.Second, PublishTimeout: 5 * time.Minute, Workers: 2,
		ControllerNamespace: ns, Destinations: dp})
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	stop := l.startManager()
	defer stop()

	get := func(name string) *v1alpha1.AssessmentRun {
		r := &v1alpha1.AssessmentRun{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, r); err != nil {
			return nil
		}
		return r
	}
	versions := func(runUID string) []s3types.ObjectVersion {
		out, err := pub.Client.ListObjectVersions(context.Background(), &s3.ListObjectVersionsInput{Bucket: aws.String(bucket), Prefix: aws.String("konstapel-test/er-dest/")})
		if err != nil {
			t.Fatal(err)
		}
		var vs []s3types.ObjectVersion
		for _, v := range out.Versions {
			if strings.Contains(aws.ToString(v.Key), runUID) {
				vs = append(vs, v)
			}
		}
		return vs
	}
	manual := func(name string) {
		t.Helper()
		r := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: "er-audit"}, Scope: v1alpha1.RunScopeBinding}}
		if err := l.c.Create(l.ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	published := func(name string) *v1alpha1.AssessmentRun {
		t.Helper()
		l.eventually(name+" published", func() (bool, string) {
			r := get(name)
			return r != nil && r.Status.Phase == v1alpha1.RunCompleted && r.Status.Publication != nil, toJSON(r)
		})
		return get(name)
	}
	l.eventually("destination ready on the object-lock bucket", func() (bool, string) {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
		return meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionDestinationReady), toJSON(got.Status)
	})

	// 1. A scheduled run publishes with the 60s retention.
	var first string
	l.eventually("scheduled run started", func() (bool, string) {
		s := l.binding("er-audit").Status.Assessment
		if s != nil && s.Schedule != nil && s.Schedule.ActiveRun != nil {
			first = s.Schedule.ActiveRun.Name
		}
		return first != "", toJSON(s)
	})
	r1 := published(first)
	receipt := r1.Status.Publication.DeepCopy()
	if receipt.ExpiresAt.Sub(receipt.PublishedAt.Time) != 60*time.Second {
		t.Fatalf("first retention: %s", toJSON(receipt))
	}

	// 2. A retention edit changes only later publications.
	specs := func() map[string]string {
		out := map[string]string{}
		for name, v := range l.managedPolicies() {
			out[name] = v[strings.Index(v, "/")+1:] // spec only, not the resourceVersion
		}
		return out
	}
	policies := specs()
	bb := l.binding("er-audit")
	bb.Spec.Assessment.Retention = "600s"
	if err := l.c.Update(l.ctx, bb); err != nil {
		t.Fatal(err)
	}
	manual("er-audit-later")
	r2 := published("er-audit-later")
	if d := r2.Status.Publication.ExpiresAt.Sub(r2.Status.Publication.PublishedAt.Time); d != 600*time.Second {
		t.Fatalf("later retention %s", d)
	}
	if got := get(first).Status.Publication; !got.ExpiresAt.Equal(receipt.ExpiresAt) || got.PackageSHA256 != receipt.PackageSHA256 || got.Retention.Duration != receipt.Retention.Duration {
		t.Fatalf("retention edit rewrote the earlier receipt: %s", toJSON(got))
	}
	if after := specs(); toJSON(after) != toJSON(policies) {
		t.Fatalf("retention edit changed engine policies:\nbefore %v\nafter  %v", policies, after)
	}
	l.record("retention-edit", map[string]any{"first": "60s", "later": "600s"})

	// 3. A legal hold on the first package's archive blocks expiry cleanup.
	archive := receipt.Commit
	if _, err := pub.Client.PutObjectLegalHold(l.ctx, &s3.PutObjectLegalHoldInput{Bucket: aws.String(bucket), Key: aws.String(archive.ArchiveKey),
		VersionId: aws.String(archive.ArchiveVersionID), LegalHold: &s3types.ObjectLockLegalHold{Status: s3types.ObjectLockLegalHoldStatusOn}}); err != nil {
		t.Fatalf("legal hold: %v", err)
	}
	head := func() string {
		out, err := pub.Client.HeadObject(l.ctx, &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(archive.ArchiveKey), VersionId: aws.String(archive.ArchiveVersionID)})
		if err != nil {
			return "missing: " + err.Error()
		}
		return aws.ToString(out.ETag)
	}
	etag := head()
	l.eventually("expiry cleanup blocked by the legal hold", func() (bool, string) {
		c := get(first).Status.Publication.Cleanup
		return c.State == v1alpha1.CleanupState(publication.CleanupRetentionBlocked) || c.State == v1alpha1.CleanupState(publication.CleanupDeletionFailed), toJSON(c)
	})
	blocked := get(first).Status.Publication
	time.Sleep(20 * time.Second) // retries back off from one minute
	again := get(first).Status.Publication
	if again.Cleanup.Attempts > blocked.Cleanup.Attempts+1 || again.Availability != v1alpha1.Availability(publication.AvailabilityExpired) {
		t.Fatalf("cleanup retried without backoff: %d then %d attempts (%s)", blocked.Cleanup.Attempts, again.Cleanup.Attempts, toJSON(again.Cleanup))
	}
	if head() != etag || again.PackageSHA256 != receipt.PackageSHA256 || again.Commit.ArchiveVersionID != archive.ArchiveVersionID {
		t.Fatal("blocked cleanup changed the stored package or its receipt")
	}
	l.eventually("destination reports the cleanup blocker", func() (bool, string) {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
		return len(got.Status.CleanupBlockers) > 0 && strings.Contains(strings.Join(got.Status.CleanupBlockers, ";"), first), toJSON(got.Status)
	})
	l.record("cleanup-blocked", map[string]any{"state": blocked.Cleanup.State, "attempts": again.Cleanup.Attempts, "message": blocked.Cleanup.Message})

	// 4. Lifting the hold lets the next retry delete every version.
	if _, err := pub.Client.PutObjectLegalHold(l.ctx, &s3.PutObjectLegalHoldInput{Bucket: aws.String(bucket), Key: aws.String(archive.ArchiveKey),
		VersionId: aws.String(archive.ArchiveVersionID), LegalHold: &s3types.ObjectLockLegalHold{Status: s3types.ObjectLockLegalHoldStatusOff}}); err != nil {
		t.Fatal(err)
	}
	// The run was not deleted, so it stays as a Deleted tombstone without
	// its retention finalizer.
	l.eventually("cleanup resumes, deletes every version, and releases the record", func() (bool, string) {
		r := get(first)
		return r != nil && r.Status.Publication.Phase == v1alpha1.PublicationPhase(publication.PhaseDeleted) &&
			r.Status.Publication.Cleanup.State == v1alpha1.CleanupState(publication.CleanupDeleted) &&
			!controllerutil.ContainsFinalizer(r, RetentionFinalizer) && len(versions(string(r1.UID))) == 0, toJSON(r.Status.Publication)
	})
	l.record("cleanup-recovered", map[string]any{"run": first})

	// 5. The binding is deleted while a run publishes against an outage.
	manual("er-audit-orphaned-binding")
	l.eventually("run collecting", func() (bool, string) {
		r := get("er-audit-orphaned-binding")
		return r != nil && r.Status.Phase == v1alpha1.RunCollecting, toJSON(r)
	})
	if out, err := exec.Command("docker", "pause", l.s3Container).CombinedOutput(); err != nil {
		t.Fatalf("pause S3: %v %s", err, out)
	}
	l.eventually("run publishing during the outage", func() (bool, string) {
		r := get("er-audit-orphaned-binding")
		return r.Status.Phase == v1alpha1.RunPublishing, toJSON(r.Status)
	})
	oldBinding := get("er-audit-orphaned-binding").Status.Binding.UID
	if err := l.c.Delete(l.ctx, l.binding("er-audit")); err != nil {
		t.Fatal(err)
	}
	l.eventually("binding deleted", func() (bool, string) {
		err := l.c.Get(l.ctx, client.ObjectKey{Name: "er-audit"}, &v1alpha1.ComplianceBinding{})
		return apierrors.IsNotFound(err), fmt.Sprint(err)
	})
	if out, err := exec.Command("docker", "unpause", l.s3Container).CombinedOutput(); err != nil {
		t.Fatalf("unpause S3: %v %s", err, out)
	}
	r3 := published("er-audit-orphaned-binding")
	if d := r3.Status.Publication.ExpiresAt.Sub(r3.Status.Publication.PublishedAt.Time); d != 600*time.Second || r3.Status.Binding.UID != oldBinding {
		t.Fatalf("publication after binding deletion: %s", toJSON(r3.Status))
	}
	replacement := newBinding()
	replacement.Spec.Assessment.Retention = "60s"
	if err := l.c.Create(l.ctx, replacement); err != nil {
		t.Fatal(err)
	}
	l.waitReady("er-audit", 1)
	time.Sleep(10 * time.Second)
	if got := get("er-audit-orphaned-binding"); got.Status.Binding.UID != oldBinding || !got.Status.Publication.ExpiresAt.Equal(r3.Status.Publication.ExpiresAt) ||
		got.Status.Publication.PackageSHA256 != r3.Status.Publication.PackageSHA256 {
		t.Fatalf("recreated binding adopted the run: %s", toJSON(got.Status))
	}
	l.record("binding-deleted", map[string]any{"run": r3.Name, "retention": "600s (recorded)", "recreatedBinding": "not adopted"})

	// 6. Revoking the operator's binding stops new downloads.
	srv := &download.Server{Reader: l.c, Reviews: download.KubeReviewer{Client: l.c, Audience: downloadAudience}, TempDir: t.TempDir(),
		PublisherFor: func(ctx context.Context, r *v1alpha1.AssessmentRun) (publication.Publisher, error) {
			return dp.For(ctx, r.Status.Destination)
		}}
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()
	url := ts.URL + "/v1/assessmentruns/" + string(r2.UID) + "/download"
	tok := l.token("er-prod", sa.Name, downloadAudience)
	if code, body := fetch(t, ts.Client(), url, tok); code != http.StatusOK {
		t.Fatalf("operator download: %d %s", code, body)
	}
	if err := l.c.Delete(l.ctx, crb); err != nil {
		t.Fatal(err)
	}
	l.eventually("revoked operator refused", func() (bool, string) {
		code, _ := fetch(t, ts.Client(), url, tok)
		return code == http.StatusForbidden, fmt.Sprint(code)
	})
	l.record("rbac-revoked", map[string]any{"download": "403"})
}
