package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

func evidenceDestination(name string, ready bool) *v1alpha1.EvidenceDestination {
	ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID("uid-" + name), Generation: 1},
		Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{Endpoint: "https://s3.example.internal", Bucket: "evidence", Region: "eu-north-1",
			Prefix: name, CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: "s3"}}}}}
	status := metav1.ConditionFalse
	if ready {
		status = metav1.ConditionTrue
	}
	ed.Status.Conditions = []metav1.Condition{{Type: v1alpha1.ConditionDestinationReady, Status: status, Reason: "Probe", Message: "probe result", LastTransitionTime: metav1.Now()}}
	return ed
}

func defaultDestination(name, uid string) *corev1.ConfigMap {
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "konstapel-system", Name: DefaultDestinationConfigMap},
		Data: map[string]string{DefaultDestinationNameKey: name, DefaultDestinationUIDKey: uid}}
}

// Bindings select their own destination or the central default, by name and
// UID; every unusable selection is reported and never replaced by another.
func TestDestinationSelection(t *testing.T) {
	withRef := func(name, uid string) *v1alpha1.ComplianceBinding {
		b := epochBinding("override", map[string]v1alpha1.LabelValue{"environment": "production"})
		b.Spec.Assessment = &v1alpha1.BindingAssessment{DestinationRef: &v1alpha1.DestinationReference{Name: name, UID: uid}}
		return b
	}
	plain := epochBinding("plain", map[string]v1alpha1.LabelValue{"environment": "production"})
	retiring := evidenceDestination("retiring", true)
	retiring.DeletionTimestamp, retiring.Finalizers = &metav1.Time{Time: time.Now()}, []string{"compliance.erenius.io/destination"}
	ctx := context.Background()
	for name, c := range map[string]struct {
		objs    []client.Object
		binding *v1alpha1.ComplianceBinding
		source  v1alpha1.DestinationSource
		ref     string
		ready   bool
		reason  string
	}{
		"default":             {[]client.Object{evidenceDestination("primary", true), defaultDestination("primary", "uid-primary")}, plain, v1alpha1.DestinationFromDefault, "primary", true, v1alpha1.ReasonDestinationSelected},
		"override wins":       {[]client.Object{evidenceDestination("primary", true), evidenceDestination("team", true), defaultDestination("primary", "uid-primary")}, withRef("team", "uid-team"), v1alpha1.DestinationFromBinding, "team", true, v1alpha1.ReasonDestinationSelected},
		"no default":          {nil, plain, v1alpha1.DestinationNone, "", false, v1alpha1.ReasonNoDefaultDestination},
		"default without uid": {[]client.Object{defaultDestination("primary", "")}, plain, v1alpha1.DestinationFromDefault, "", false, v1alpha1.ReasonInvalidDefault},
		"override missing":    {[]client.Object{evidenceDestination("primary", true), defaultDestination("primary", "uid-primary")}, withRef("gone", "uid-gone"), v1alpha1.DestinationFromBinding, "gone", false, v1alpha1.ReasonDestinationNotFound},
		"override recreated":  {[]client.Object{evidenceDestination("primary", true), evidenceDestination("team", true), defaultDestination("primary", "uid-primary")}, withRef("team", "uid-old-team"), v1alpha1.DestinationFromBinding, "team", false, v1alpha1.ReasonDestinationUIDMismatch},
		"default recreated":   {[]client.Object{evidenceDestination("primary", true), defaultDestination("primary", "uid-old-primary")}, plain, v1alpha1.DestinationFromDefault, "primary", false, v1alpha1.ReasonDestinationUIDMismatch},
		"override retiring":   {[]client.Object{evidenceDestination("primary", true), retiring, defaultDestination("primary", "uid-primary")}, withRef("retiring", "uid-retiring"), v1alpha1.DestinationFromBinding, "retiring", false, v1alpha1.ReasonDestinationRetiring},
		"override not ready":  {[]client.Object{evidenceDestination("primary", true), evidenceDestination("team", false), defaultDestination("primary", "uid-primary")}, withRef("team", "uid-team"), v1alpha1.DestinationFromBinding, "team", false, v1alpha1.ReasonDestinationNotReady},
	} {
		e := newAssessEnv(t, c.objs...)
		sel := selectDestination(ctx, e.c, "", c.binding)
		ref := ""
		if sel.Ref != nil {
			ref = sel.Ref.Name
		}
		// An unusable override is never replaced by the (usable) default.
		if sel.Source != c.source || ref != c.ref || sel.Ready != c.ready || sel.Reason != c.reason {
			t.Errorf("%s: got %+v", name, sel)
		}
	}
}

// Selection is reported under status.assessment and never touches the
// binding's enforcement conditions.
func TestDestinationSelectionIsSeparateFromEnforcement(t *testing.T) {
	b := epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})
	b.Spec.Assessment = &v1alpha1.BindingAssessment{DestinationRef: &v1alpha1.DestinationReference{Name: "gone", UID: "uid-gone"}}
	e := newAssessEnv(t, nsObj("prod", "environment", "production"), profileObj(t, "baseline", pol), b)
	e.deliver("audit-prod")
	get := func() *v1alpha1.ComplianceBinding {
		b := &v1alpha1.ComplianceBinding{}
		if err := e.c.Get(context.Background(), client.ObjectKey{Name: "audit-prod"}, b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	before := l2s(get().Status.Conditions)
	e.assess("audit-prod")
	got := get()
	if got.Status.Assessment == nil || got.Status.Assessment.Destination == nil || got.Status.Assessment.Destination.Reason != v1alpha1.ReasonDestinationNotFound {
		t.Fatalf("selection not reported: %+v", got.Status.Assessment)
	}
	if l2s(got.Status.Conditions) != before || !meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionEngineReady) {
		t.Fatalf("destination selection changed enforcement status: %s", l2s(got.Status.Conditions))
	}
}

func l2s(cs []metav1.Condition) string {
	out := ""
	for _, c := range cs {
		out += c.Type + "=" + string(c.Status) + "/" + c.Reason + ";"
	}
	return out
}

// The destination reconciler probes with the destination's own credentials
// and trust and records readiness for the current generation.
func TestDestinationReconcilerRecordsReadiness(t *testing.T) {
	ed := evidenceDestination("primary", false)
	ed.Status = v1alpha1.EvidenceDestinationStatus{}
	ed.Spec.S3.CATrust = &v1alpha1.CATrust{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: "s3-ca"}}
	e := newAssessEnv(t, ed)
	probeErr := error(nil)
	var probed s3store.Destination
	r := &DestinationReconciler{Client: e.c, Reader: e.c, Probe: func(_ context.Context, d s3store.Destination, _ client.Reader, _ string) error {
		probed = d
		return probeErr
	}}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "primary"}}
	cond := func() *metav1.Condition {
		got := &v1alpha1.EvidenceDestination{}
		_ = e.c.Get(context.Background(), client.ObjectKey{Name: "primary"}, got)
		return meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionDestinationReady)
	}
	// The CA trust ConfigMap is missing: not ready, without probing.
	if res, err := r.Reconcile(context.Background(), req); err != nil || res.RequeueAfter != DestinationProbeInterval {
		t.Fatal(res, err)
	}
	if c := cond(); c == nil || c.Status != metav1.ConditionFalse || probed.ID != "" {
		t.Fatalf("missing CA trust: %+v probed %+v", c, probed)
	}
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	_ = e.c.Create(context.Background(), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "konstapel-system", Name: "s3-ca"}, Data: map[string]string{"ca.crt": pem}})
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if c := cond(); c == nil || c.Status != metav1.ConditionTrue || probed.ID != "uid-primary" || string(probed.CAPEM) != pem || probed.CredentialSecret.Name != "s3" {
		t.Fatalf("ready destination: %+v probed %+v", c, probed)
	}
	probeErr = errors.New("conditional create not enforced")
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if c := cond(); c == nil || c.Status != metav1.ConditionFalse || c.Message != "conditional create not enforced" {
		t.Fatalf("failed probe: %+v", c)
	}
}
