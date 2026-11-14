//go:build live

package controller

// Live EvidenceAttachment API (add-supporting-evidence-attachments 1.1-1.4),
// against the real API server with the generated CRD, the shipped
// attachment roles, the registrant admission policy, and the generated
// controller RBAC:
//   - CRD validation rejects malformed periods and digests, strict field
//     validation rejects unsupported fields, and the spec is immutable even
//     for a cluster administrator;
//   - admission records the authenticated registrant and overwrites a forged
//     one; the declared source stays a separate claim;
//   - registration, upload, metadata read and download are distinct grants
//     (SubjectAccessReview for the service attributes); namespace assessment
//     and exception credentials, the compliance admin and the assessment
//     operator receive none of them;
//   - the controller, running as the generated controller role, validates
//     associations against each binding's resolved catalog and baseline:
//     shared facility evidence for two bindings is Valid, a foreign
//     statement or wrong catalog is Mismatched, a reporting-only binding edit
//     keeps the association, and binding recreation stops it;
//   - withdrawal (delete) by the registrar releases the record.
// Run through scripts/targeting-live.sh (acceptance group "admission").

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/attachments"
)

func TestLiveEvidenceAttachmentAPI(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	root, _ := filepath.Abs("../..")
	const (
		ns                                           = "konstapel-system"
		teamNS                                       = "ea-team"
		registrar, uploader, reader, downloader      = "ea-registrar", "ea-uploader", "ea-reader", "ea-downloader"
		team, admin, operator, controllerUser, other = "system:serviceaccount:ea-team:dev", "ea-compliance-admin", "ea-assessment-operator", "ea-live-controller", "ea-someone-else"
	)
	for _, n := range []string{ns, teamNS} {
		_ = l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
	}
	// Shipped roles under test-owned names, so roles other tests or a chart
	// installed are never adopted or removed. Their rules are unchanged.
	suffix := func(u *unstructured.Unstructured) { u.SetName(u.GetName() + "-ea-live") }
	for _, f := range []string{"evidence-attachments", "assessment-requester", "exception-editor", "compliance-admin", "assessment-operator"} {
		l.applyManifests("../../config/rbac/"+f+".yaml", suffix)
	}
	l.applyManifests("../../config/rbac/controller/role.yaml", suffix)
	cluster := func(name string) rbacv1.RoleRef {
		return rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name + "-ea-live"}
	}
	l.bind("ea-registrar", registrar, cluster("konstapel-evidence-attachment-registrar"), "")
	l.bind("ea-uploader", uploader, cluster("konstapel-evidence-attachment-uploader"), "")
	l.bind("ea-reader", reader, cluster("konstapel-evidence-attachment-reader"), "")
	l.bind("ea-downloader", downloader, cluster("konstapel-evidence-attachment-downloader"), "")
	l.bind("ea-admin", admin, cluster("konstapel-compliance-admin"), "")
	l.bind("ea-operator", operator, cluster("konstapel-assessment-operator"), "")
	l.bind("ea-team-requester", team, cluster("konstapel-assessment-requester"), teamNS)
	l.bind("ea-team-exceptions", team, cluster("konstapel-exception-editor"), teamNS)
	l.bind("ea-controller", controllerUser, cluster("konstapel-controller"), "")
	l.bind("ea-controller", controllerUser, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "konstapel-controller-ea-live"}, ns)
	l.applyManifests("../../config/admission/evidence-attachment-registrant.yaml", nil)

	regC := l.as(registrar, "system:authenticated")
	catalog, err := attachments.ReadBaseline(os.DirFS(root))
	if err != nil {
		t.Fatal(err)
	}
	newAttachment := func(name string, as ...v1alpha1.AttachmentAssociation) *v1alpha1.EvidenceAttachment {
		return &v1alpha1.EvidenceAttachment{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v1alpha1.EvidenceAttachmentSpec{
			Document:     v1alpha1.AttachmentDocument{Title: "DC North physical access audit", MediaType: "application/pdf", Size: 482113, SHA256: "sha256:" + strings.Repeat("ab", 32)},
			Source:       v1alpha1.AttachmentSource{Issuer: "Example Audit AB", URL: "https://audits.example.com/reports/dc-north"},
			Validity:     v1alpha1.AttachmentValidity{ValidFrom: metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)), ValidUntil: metav1.NewTime(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))},
			Associations: as,
			Scope:        v1alpha1.AttachmentScope{Description: "DC North halls A and B"},
		}}
	}
	assoc := func(binding, uid, digest string, controls ...v1alpha1.AttachmentControl) v1alpha1.AttachmentAssociation {
		return v1alpha1.AttachmentAssociation{Binding: v1alpha1.ExactBindingReference{Name: binding, UID: uid}, CatalogDigest: digest, Controls: controls}
	}
	pe3 := v1alpha1.AttachmentControl{ID: "pe-3", Statements: []string{"pe-3_smt.a"}}
	var created []string
	t.Cleanup(func() {
		for _, n := range created {
			a := &v1alpha1.EvidenceAttachment{}
			if l.c.Get(context.Background(), client.ObjectKey{Name: n}, a) == nil {
				a.Finalizers = nil
				_ = l.c.Update(context.Background(), a)
				_ = l.c.Delete(context.Background(), a)
			}
		}
	})
	create := func(c client.Client, a *v1alpha1.EvidenceAttachment, opts ...client.CreateOption) error {
		err := c.Create(l.ctx, a, opts...)
		if err == nil {
			created = append(created, a.Name)
		}
		return err
	}

	// Admission policies become effective asynchronously.
	l.eventually("registrant admission effective", func() (bool, string) {
		probe := newAttachment("ea-probe", assoc("x", "x", catalog.CatalogDigest, pe3))
		if err := regC.Create(l.ctx, probe, client.DryRunAll); err != nil {
			return false, err.Error()
		}
		return probe.Spec.RegisteredBy != nil && probe.Spec.RegisteredBy.Username == registrar, toJSON(probe.Spec.RegisteredBy)
	})

	// 1.1: validation, unsupported fields, immutability.
	bad := newAttachment("ea-bad", assoc("x", "x", catalog.CatalogDigest, pe3))
	bad.Spec.Validity.ValidFrom = bad.Spec.Validity.ValidUntil
	if err := regC.Create(l.ctx, bad, client.DryRunAll); !apierrors.IsInvalid(err) || !strings.Contains(err.Error(), "validFrom must be before validUntil") {
		t.Fatalf("empty validity period: %v", err)
	}
	bad = newAttachment("ea-bad", assoc("x", "x", catalog.CatalogDigest, pe3))
	bad.Spec.Document.SHA256 = "sha256:XYZ"
	if err := regC.Create(l.ctx, bad, client.DryRunAll); !apierrors.IsInvalid(err) {
		t.Fatalf("malformed digest: %v", err)
	}
	u := &unstructured.Unstructured{}
	raw, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(newAttachment("ea-unknown", assoc("x", "x", catalog.CatalogDigest, pe3)))
	u.Object = raw
	u.SetAPIVersion(v1alpha1.GroupVersion.String())
	u.SetKind("EvidenceAttachment")
	_ = unstructured.SetNestedField(u.Object, "JVBERi0=", "spec", "document", "content")
	if err := regC.Create(l.ctx, u, client.DryRunAll, client.FieldValidation("Strict")); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unsupported field accepted with strict field validation: %v", err)
	}
	// The published example (docs/supporting-evidence.md) is accepted for a
	// registrar and refused for a namespace team.
	exampleRaw, err := os.ReadFile("../../docs/examples/supporting-evidence/attachment-datacenter.yaml")
	if err != nil {
		t.Fatal(err)
	}
	example := &unstructured.Unstructured{}
	if err := yaml.Unmarshal(exampleRaw, &example.Object); err != nil {
		t.Fatal(err)
	}
	if err := regC.Create(l.ctx, example.DeepCopy(), client.DryRunAll, client.FieldValidation("Strict")); err != nil {
		t.Fatalf("published example rejected for a registrar: %v", err)
	}
	if err := l.as(team, "system:authenticated").Create(l.ctx, example.DeepCopy(), client.DryRunAll); !apierrors.IsForbidden(err) {
		t.Fatalf("published example accepted for a namespace team: %v", err)
	}
	l.record("validation", map[string]any{"publishedExample": "accepted (registrar), Forbidden (team)", "emptyPeriod": "Invalid", "malformedDigest": "Invalid", "unknownField": "rejected (Strict)"})

	// 1.2/1.3: authority. Namespace and unrelated platform roles cannot
	// register; the registrar can, and a forged registrant is overwritten.
	for _, who := range []string{team, admin, operator, uploader, reader, downloader} {
		if err := create(l.as(who, "system:authenticated"), newAttachment("ea-denied", assoc("x", "x", catalog.CatalogDigest, pe3)), client.DryRunAll); !apierrors.IsForbidden(err) {
			t.Fatalf("%s registered an attachment: %v", who, err)
		}
	}
	forged := newAttachment("ea-forged", assoc("x", "x", catalog.CatalogDigest, pe3))
	forged.Spec.RegisteredBy = &v1alpha1.Requester{Username: other, UID: "uid-" + other}
	if err := create(regC, forged); err != nil {
		t.Fatal(err)
	}
	if got := forged.Spec.RegisteredBy; got == nil || got.Username != registrar || got.UID != "uid-"+registrar {
		t.Fatalf("forged registrant stored as %+v", got)
	}
	if forged.Spec.Source.Issuer != "Example Audit AB" {
		t.Fatal("declared source was changed by admission")
	}
	rewrite := forged.DeepCopy()
	rewrite.Spec.RegisteredBy = &v1alpha1.Requester{Username: other}
	if err := l.c.Update(l.ctx, rewrite); !apierrors.IsInvalid(err) {
		t.Fatalf("an administrator rewrote the registrant: %v", err)
	}
	extend := forged.DeepCopy()
	extend.Spec.Validity.ValidUntil = metav1.NewTime(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	if err := l.c.Update(l.ctx, extend); !apierrors.IsInvalid(err) {
		t.Fatalf("an administrator extended validity in place: %v", err)
	}
	l.record("attribution", map[string]any{"registeredBy": forged.Spec.RegisteredBy, "forged": other, "registrantRewrite": "Invalid", "validityExtension": "Invalid"})

	can := func(user, verb, resource, subresource, name string) bool {
		sar := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{User: user,
			Groups:             []string{"system:authenticated"},
			ResourceAttributes: &authorizationv1.ResourceAttributes{Group: v1alpha1.GroupVersion.Group, Version: "v1alpha1", Resource: resource, Subresource: subresource, Verb: verb, Name: name}}}
		if err := l.c.Create(l.ctx, sar); err != nil {
			t.Fatal(err)
		}
		return sar.Status.Allowed
	}
	type probe struct{ verb, sub string }
	matrix := map[string]map[probe]bool{
		registrar:  {{"create", ""}: true, {"delete", ""}: true, {"get", ""}: true, {"update", ""}: false, {"create", "upload"}: false, {"get", "download"}: false, {"patch", "status"}: false},
		uploader:   {{"create", ""}: false, {"delete", ""}: false, {"get", ""}: true, {"list", ""}: false, {"create", "upload"}: true, {"get", "download"}: false},
		reader:     {{"create", ""}: false, {"delete", ""}: false, {"get", ""}: true, {"list", ""}: true, {"create", "upload"}: false, {"get", "download"}: false},
		downloader: {{"create", ""}: false, {"delete", ""}: false, {"get", ""}: true, {"list", ""}: false, {"create", "upload"}: false, {"get", "download"}: true},
		team:       {{"create", ""}: false, {"delete", ""}: false, {"get", ""}: false, {"list", ""}: false, {"create", "upload"}: false, {"get", "download"}: false},
		admin:      {{"create", ""}: false, {"delete", ""}: false, {"get", ""}: false, {"create", "upload"}: false, {"get", "download"}: false},
		operator:   {{"create", ""}: false, {"delete", ""}: false, {"get", ""}: false, {"create", "upload"}: false, {"get", "download"}: false},
	}
	results := map[string]map[string]bool{}
	for user, probes := range matrix {
		results[user] = map[string]bool{}
		for p, want := range probes {
			got := can(user, p.verb, "evidenceattachments", p.sub, forged.Name)
			results[user][p.verb+" "+p.sub] = got
			if got != want {
				t.Errorf("%s %s evidenceattachments/%s = %v, want %v", user, p.verb, p.sub, got, want)
			}
		}
	}
	if err := l.as(team, "system:authenticated").Get(l.ctx, client.ObjectKeyFromObject(forged), &v1alpha1.EvidenceAttachment{}); !apierrors.IsForbidden(err) {
		t.Fatalf("team read private attachment metadata: %v", err)
	}
	if err := l.as(team, "system:authenticated").Delete(l.ctx, forged.DeepCopy()); !apierrors.IsForbidden(err) {
		t.Fatalf("team withdrew an attachment: %v", err)
	}
	st := forged.DeepCopy()
	st.Status.ObservedGeneration = 99
	if err := regC.Status().Update(l.ctx, st); !apierrors.IsForbidden(err) {
		t.Fatalf("registrar wrote status: %v", err)
	}
	l.record("authority", map[string]any{"subjectAccessReviews": results, "teamGet": "Forbidden", "teamDelete": "Forbidden", "registrarStatus": "Forbidden"})

	// 1.2: the controller validates associations against real bindings.
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "ea-baseline"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	bindings := []*v1alpha1.ComplianceBinding{
		bindingObj("ea-dc-a", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "ea-none"}),
		bindingObj("ea-dc-b", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "ea-none"}),
	}
	for _, o := range []client.Object{p, bindings[0], bindings[1]} {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, n := range []string{"ea-dc-a", "ea-dc-b"} {
			_ = l.c.Delete(context.Background(), &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: n}})
		}
		_ = l.c.Delete(context.Background(), p)
	})
	ConfigureAssessments(AssessmentRuntime{ContentRoot: root})
	t.Cleanup(func() { ConfigureAssessments(AssessmentRuntime{}) })
	stop := l.startManagerAs(controllerUser)
	defer func() { stop() }()
	resolved := func(name string) *v1alpha1.ComplianceBinding {
		var b *v1alpha1.ComplianceBinding
		l.eventually(name+" resolved", func() (bool, string) {
			b = l.binding(name)
			return b.Status.ObservedGeneration == b.Generation && meta.IsStatusConditionTrue(b.Status.Conditions, v1alpha1.ConditionResolved), toJSON(b.Status)
		})
		return b
	}
	a, b := resolved("ea-dc-a"), resolved("ea-dc-b")
	shared := newAttachment("ea-shared", assoc(a.Name, string(a.UID), catalog.CatalogDigest, pe3), assoc(b.Name, string(b.UID), catalog.CatalogDigest, v1alpha1.AttachmentControl{ID: "pe-6"}))
	foreign := newAttachment("ea-foreign", assoc(a.Name, string(a.UID), catalog.CatalogDigest, v1alpha1.AttachmentControl{ID: "pe-3", Statements: []string{"pe-2_smt.a"}}))
	wrongCatalog := newAttachment("ea-wrong-catalog", assoc(a.Name, string(a.UID), "sha256:"+strings.Repeat("0", 64), pe3))
	for _, x := range []*v1alpha1.EvidenceAttachment{shared, foreign, wrongCatalog} {
		if err := create(regC, x); err != nil {
			t.Fatal(err)
		}
	}
	states := func(name string, want metav1.ConditionStatus, reasons ...string) *v1alpha1.EvidenceAttachment {
		got := &v1alpha1.EvidenceAttachment{}
		l.eventually(name+" associations", func() (bool, string) {
			if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, got); err != nil {
				return false, err.Error()
			}
			c := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionAssociationsValid)
			if c == nil || c.Status != want || got.Status.ObservedGeneration != got.Generation || len(got.Status.Associations) != len(reasons) {
				return false, toJSON(got.Status)
			}
			for i, r := range reasons {
				if got.Status.Associations[i].Reason != r {
					return false, toJSON(got.Status)
				}
			}
			return true, ""
		})
		return got
	}
	got := states(shared.Name, metav1.ConditionTrue, v1alpha1.ReasonAssociationsValid, v1alpha1.ReasonAssociationsValid)
	if !containsString(got.Finalizers, v1alpha1.EvidenceAttachmentFinalizer) {
		t.Fatal("retention finalizer not added by the controller")
	}
	states(foreign.Name, metav1.ConditionFalse, v1alpha1.ReasonStatementNotInControl)
	states(wrongCatalog.Name, metav1.ConditionFalse, v1alpha1.ReasonCatalogMismatch)
	l.record("associations", map[string]any{"shared": "Valid/Valid", "foreignStatement": "StatementNotInControl", "wrongCatalog": "CatalogMismatch"})

	// A reporting-only edit keeps the association.
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cur := l.binding(a.Name)
		cur.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "12h"}
		return l.c.Update(l.ctx, cur)
	}); err != nil {
		t.Fatal(err)
	}
	edited := resolved(a.Name)
	if edited.Generation == a.Generation || edited.UID != a.UID {
		t.Fatal("setup: reporting-only edit not applied")
	}
	states(shared.Name, metav1.ConditionTrue, v1alpha1.ReasonAssociationsValid, v1alpha1.ReasonAssociationsValid)

	// Recreating the binding under the same name stops the association.
	if err := l.c.Delete(l.ctx, edited); err != nil {
		t.Fatal(err)
	}
	l.eventually("binding deleted", func() (bool, string) {
		err := l.c.Get(l.ctx, client.ObjectKey{Name: a.Name}, &v1alpha1.ComplianceBinding{})
		return apierrors.IsNotFound(err), "present"
	})
	again := bindingObj(a.Name, p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "ea-none"})
	again.SetUID("")
	if err := l.c.Create(l.ctx, again); err != nil {
		t.Fatal(err)
	}
	resolved(a.Name)
	got = states(shared.Name, metav1.ConditionFalse, v1alpha1.ReasonBindingReplaced, v1alpha1.ReasonAssociationsValid)
	l.record("recreation", map[string]any{"registeredUID": a.UID, "newUID": again.UID, "status": got.Status.Associations})

	// Withdrawal by the registrar releases the record (no stored bytes yet).
	if err := regC.Delete(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	l.eventually("withdrawn attachment released", func() (bool, string) {
		err := l.c.Get(l.ctx, client.ObjectKey{Name: shared.Name}, &v1alpha1.EvidenceAttachment{})
		return apierrors.IsNotFound(err), "present"
	})
	l.record("withdrawal", map[string]any{"deletedBy": registrar, "released": true})
}
