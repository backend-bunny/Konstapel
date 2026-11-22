//go:build live

package controller

// Live revocation history (add-self-service-policy-exceptions task 3.6).
// The manager runs as the controller service account with the shipped
// controller roles, so the webhooks learn that identity from a
// SelfSubjectReview exactly as a deployed replica does. It starts as the
// default installation does, with revocation processing off and without
// the gated grant: the controller can write no exception (RBAC), records
// nothing, keeps the finalizer and reports RevocationProcessingDisabled.
// Every later manager runs with --exception-revocation-processing and the
// gated config/rbac/controller/exception-revocation.yaml bound. A fault
// transport on the manager's own API connection injects the failures:
//   - enabled: the revocation held while processing was off is recorded
//     and released;
//   - revoke: the record is persisted, then the finalizer released, and a
//     deletion completes; tamper attempts on the record, the protected
//     annotation and the finalizer are denied, and the controller identity
//     can release the finalizer but cannot revoke or edit;
//   - the validating webhook removed: nothing is recorded or released
//     (RevocationProtectionUnverified) until it is registered again;
//   - a conflicting object at the record's name: the controller identity
//     cannot release the finalizer;
//   - persistence failure: the intent and finalizer stay through a renewal
//     attempt and a deletion until writes are restored;
//   - a lost record-create response: recovered without a second write;
//   - a controller stopped between persisting and releasing: while no
//     webhook serves, every write fails closed, the controller's release
//     included; the next manager cannot learn its identity at first, and
//     its webhook denies every write (ControllerIdentityUnknown) instead of
//     treating the controller as an application identity; once it can, it
//     is elected after the old Lease expires, verifies and releases;
//   - the controller unavailable (another holder owns the Lease) while a
//     never-activated acceptance is revoked and deleted with its namespace,
//     and while a rapid renewal waits for history: once elected, the
//     snapshot and record are written, the namespace goes, the history
//     stays, and the documented renewal of the revoked revision succeeds.
// Run through scripts/exception-admission-live.sh (assessments group).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/exception"
)

const historyWebhookPort = 19448

// controllerServiceAccount is the identity the shipped controller runs as.
const controllerServiceAccount = "system:serviceaccount:konstapel-system:konstapel-controller"

var controllerGroups = []string{"system:serviceaccounts", "system:serviceaccounts:konstapel-system", "system:authenticated"}

// waitHistory waits until Konstapel has recorded ex's revocation
// independently and released its finalizer (or ex is gone), and returns the
// record, verified against the revocation ex carries.
func (l *live) waitHistory(ex *v1alpha1.ComplianceException) *corev1.ConfigMap {
	l.t.Helper()
	want := revocation(l.t, ex)
	l.eventually("revocation history of "+ex.Name, func() (bool, string) {
		cur := &v1alpha1.ComplianceException{}
		err := l.c.Get(l.ctx, client.ObjectKeyFromObject(ex), cur)
		if apierrors.IsNotFound(err) {
			return true, ""
		}
		if err != nil {
			return false, err.Error()
		}
		cond := meta.FindStatusCondition(cur.Status.Conditions, v1alpha1.ConditionRevocationRecorded)
		return cond != nil && cond.Status == metav1.ConditionTrue && !slices.Contains(cur.Finalizers, exception.RevocationFinalizer),
			toJSON(map[string]any{"finalizers": cur.Finalizers, "conditions": cur.Status.Conditions})
	})
	cm := l.snapshotConfigMap(exception.RevocationRecordName(want.ExceptionUID, want.Revision))
	if cm == nil {
		l.t.Fatalf("finalizer of %s released without a revocation record", ex.Name)
	}
	rec, _, err := exception.RevocationRecordFrom(cm)
	if err == nil {
		err = rec.Matches(cm, want)
	}
	if err != nil {
		l.t.Fatalf("revocation record of %s: %v", ex.Name, err)
	}
	if len(cm.OwnerReferences) != 0 {
		l.t.Fatalf("revocation record %s has owners %v", cm.Name, cm.OwnerReferences)
	}
	return cm
}

// shippedRole creates the named Role from a shipped manifest, as
// shippedClusterRole does for ClusterRoles.
func (l *live) shippedRole(file, namespace, name string) {
	raw, err := os.ReadFile(file)
	if err != nil {
		l.t.Fatal(err)
	}
	dec := utilyaml.NewYAMLOrJSONDecoder(strings.NewReader(string(raw)), 4096)
	for {
		r := &rbacv1.Role{}
		if err := dec.Decode(r); err != nil {
			l.t.Fatalf("Role %s/%s not found in %s: %v", namespace, name, file, err)
		}
		if r.Kind != "Role" || r.Name != name || r.Namespace != namespace {
			continue
		}
		err := l.c.Create(l.ctx, r)
		switch {
		case err == nil:
			l.t.Cleanup(func() { _ = l.c.Delete(l.ctx, r) })
		case !apierrors.IsAlreadyExists(err):
			l.t.Fatal(err)
		}
		return
	}
}

// historyFaultState fails, or loses the response of, the manager's own API
// requests.
type historyFaultState struct {
	mu sync.Mutex
	// denyRecords fails every revocation record create before it is sent.
	denyRecords bool
	// loseRecord sends the next record create, then reports a failure.
	loseRecord bool
	// denyRelease fails exception patches (finalizer releases) by name.
	denyRelease map[string]bool
	// denyIdentity fails the manager's SelfSubjectReviews, its identity
	// lookup.
	denyIdentity bool
	// posts counts record creates sent, by record name.
	posts map[string]int
}

var recordName = regexp.MustCompile(`revocation-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-[0-9]+`)

type historyFaultTransport struct {
	state *historyFaultState
	next  http.RoundTripper
}

func (f *historyFaultTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s := f.state
	switch {
	case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/namespaces/"+DefaultSnapshotNamespace+"/configmaps") && req.Body != nil:
		body, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		req = req.Clone(req.Context())
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		name := recordName.Find(body)
		if name == nil {
			break
		}
		s.mu.Lock()
		deny, lose := s.denyRecords, s.loseRecord
		if !deny {
			s.posts[string(name)]++
			s.loseRecord = false
		}
		s.mu.Unlock()
		if deny {
			return nil, errors.New("injected: the protected namespace cannot be written")
		}
		if lose {
			resp, err := f.next.RoundTrip(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				return nil, errors.New("injected: connection reset after the record was sent")
			}
			return resp, err
		}
	case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/apis/authentication.k8s.io/v1/selfsubjectreviews"):
		s.mu.Lock()
		deny := s.denyIdentity
		s.mu.Unlock()
		if deny {
			return nil, errors.New("injected: the identity lookup cannot reach the API server")
		}
	case req.Method == http.MethodPatch && strings.Contains(req.URL.Path, "/complianceexceptions/") && !strings.HasSuffix(req.URL.Path, "/status"):
		name := req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:]
		s.mu.Lock()
		deny := s.denyRelease[name]
		s.mu.Unlock()
		if deny {
			return nil, errors.New("injected: the controller stopped before releasing the finalizer")
		}
	}
	return f.next.RoundTrip(req)
}

func TestLiveRevocationHistory(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	host := webhookHost(t)
	certs := t.TempDir()
	ca := servingCert(t, certs, host)
	if err := l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: DefaultSnapshotNamespace}}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: DefaultSnapshotNamespace, Name: LeaderElectionID}}
	_ = l.c.Delete(l.ctx, lease)
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, lease) })

	// The shipped controller RBAC, bound to its service account.
	sa := rbacv1.Subject{Kind: "ServiceAccount", Name: "konstapel-controller", Namespace: DefaultSnapshotNamespace}
	var objs []client.Object
	for _, cr := range []struct{ file, name string }{
		{"../../config/rbac/controller/role.yaml", "konstapel-controller"},
		{"../../config/rbac/controller-assessments.yaml", "konstapel-controller-assessments"},
	} {
		name := l.shippedClusterRole(cr.file, cr.name)
		objs = append(objs, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "exc-history-" + name},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name}, Subjects: []rbacv1.Subject{sa}})
	}
	l.shippedRole("../../config/rbac/controller/role.yaml", DefaultSnapshotNamespace, "konstapel-controller")
	objs = append(objs, &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "exc-history-controller", Namespace: DefaultSnapshotNamespace},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "konstapel-controller"}, Subjects: []rbacv1.Subject{sa}})

	const ns, gone = "exc-history", "exc-history-gone"
	l.setNamespace(ns, "exc-history")
	l.setNamespace(gone, "exc-history")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "exc-history-self-service"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)},
			Policies: []v1alpha1.ProfilePolicy{{Name: pol, Exceptions: v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: 720 * time.Hour}}}}}}
	b := bindingObj("exc-history-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "exc-history"})
	editor := l.shippedClusterRole("../../config/rbac/exception-editor.yaml", "konstapel-exception-editor")
	for _, n := range []string{ns, gone} {
		objs = append(objs, &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "exception-editors", Namespace: n},
			RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: editor},
			Subjects: []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: "Group", Name: "eh-team"}}})
	}
	objs = append(objs, p, b)
	for _, o := range objs {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = l.c.DeleteAllOf(l.ctx, &v1alpha1.ComplianceException{}, client.InNamespace(ns))
		for i := len(objs) - 1; i >= 0; i-- {
			_ = l.c.Delete(l.ctx, objs[i])
		}
		_ = l.c.Delete(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: gone}})
	})

	faults := &historyFaultState{denyRelease: map[string]bool{}, posts: map[string]int{}}
	setFault := func(edit func(s *historyFaultState)) {
		faults.mu.Lock()
		defer faults.mu.Unlock()
		edit(faults)
	}
	posts := func(name string) int {
		faults.mu.Lock()
		defer faults.mu.Unlock()
		return faults.posts[name]
	}
	// start runs a manager as the controller service account, through the
	// fault transport, electing it through the shared Lease, with or
	// without revocation processing.
	start := func(agent string, revocation bool) *candidate {
		t.Helper()
		cfg := rest.CopyConfig(l.cfg)
		cfg.UserAgent = agent
		cfg.Impersonate = rest.ImpersonationConfig{UserName: controllerServiceAccount, UID: "uid-" + controllerServiceAccount, Groups: controllerGroups}
		cfg.WrapTransport = func(rt http.RoundTripper) http.RoundTripper { return &historyFaultTransport{state: faults, next: rt} }
		mgr, err := NewManager(cfg, Options{Content: content, MetricsAddr: "0", ProbeAddr: "0", EnginePoll: 2 * time.Second,
			SkipControllerNameValidation: true, WebhookCertDir: certs, WebhookPort: historyWebhookPort, ExceptionRevocation: revocation,
			LeaderElection: true, LeaderElectionNamespace: DefaultSnapshotNamespace,
			Election: Election{LeaseDuration: 4 * time.Second, RenewDeadline: 3 * time.Second, RetryPeriod: time.Second}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(l.ctx)
		c := &candidate{mgr: mgr, cancel: cancel, done: make(chan error, 1)}
		go func() { c.done <- mgr.Start(ctx) }()
		return c
	}
	var running *candidate
	stop := func() {
		if running != nil {
			running.stop()
			running = nil
		}
	}
	t.Cleanup(stop)
	// Registered before the webhooks, so it runs after they are removed.
	t.Cleanup(func() { l.releaseRevocations(ns) })
	l.installExceptionWebhooksAt(host, historyWebhookPort, ca)

	alice := l.as("alice", "eh-team", "system:authenticated")
	dave := l.as("dave", "eh-team", "system:authenticated")
	controllerSA := l.as(controllerServiceAccount, controllerGroups...)
	expires := func(d time.Duration) metav1.Time { return metav1.NewTime(time.Now().Add(d).Truncate(time.Second)) }
	newEx := func(namespace, name string) *v1alpha1.ComplianceException {
		return &v1alpha1.ComplianceException{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: v1alpha1.ComplianceExceptionSpec{Policy: pol, WorkloadSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "debug"}},
				Reason: "live revocation history", ExpiresAt: expires(24 * time.Hour), AcceptanceRevision: 1}}
	}
	denied := func(what string, err error, reason string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "denied the request: "+reason+":") {
			t.Fatalf("%s: want a %s admission denial, got %v", what, reason, err)
		}
		l.record("denied", map[string]any{"attempt": what, "reason": reason})
	}
	forbidden := func(what string, err error) {
		t.Helper()
		if !apierrors.IsForbidden(err) || strings.Contains(err.Error(), "denied the request") {
			t.Fatalf("%s: want Forbidden by RBAC, got %v", what, err)
		}
		l.record("denied", map[string]any{"attempt": what, "reason": "RBAC"})
	}
	create := func(c client.Client, e *v1alpha1.ComplianceException) *v1alpha1.ComplianceException {
		t.Helper()
		if err := c.Create(l.ctx, e); err != nil {
			t.Fatalf("create %s: %v", e.Name, err)
		}
		return e
	}
	revoke := func(c client.Client, e *v1alpha1.ComplianceException) *v1alpha1.ComplianceException {
		t.Helper()
		got, err := l.jsonPatch(c, e.Namespace, e.Name, examplePatch(t, "revoke.json").withPreconditions(l.exception(e.Namespace, e.Name)))
		if err != nil {
			t.Fatalf("revoke %s: %v", e.Name, err)
		}
		if !slices.Contains(got.Finalizers, exception.RevocationFinalizer) {
			t.Fatalf("revocation of %s without the finalizer", e.Name)
		}
		return got
	}
	condition := func(e *v1alpha1.ComplianceException, reason string) {
		t.Helper()
		l.eventually(e.Name+" "+reason, func() (bool, string) {
			cur := l.exception(e.Namespace, e.Name)
			c := meta.FindStatusCondition(cur.Status.Conditions, v1alpha1.ConditionRevocationRecorded)
			return c != nil && c.Reason == reason, toJSON(cur.Status.Conditions)
		})
	}
	removed := func(what string, obj client.Object) {
		t.Helper()
		l.eventually(what+" removed", func() (bool, string) {
			err := l.c.Get(l.ctx, client.ObjectKeyFromObject(obj), obj.DeepCopyObject().(client.Object))
			return apierrors.IsNotFound(err), fmt.Sprint(err)
		})
	}
	renewalPatch := func(e *v1alpha1.ComplianceException) patchOps {
		return examplePatch(t, "renew-revoked.json").withPreconditions(e).
			set("/spec/acceptanceRevision", e.Spec.AcceptanceRevision+1).set("/spec/expiresAt", expires(48*time.Hour).UTC().Format(time.RFC3339))
	}
	held := func(what string, e *v1alpha1.ComplianceException) *v1alpha1.ComplianceException {
		t.Helper()
		cur := l.exception(e.Namespace, e.Name)
		if !slices.Contains(cur.Finalizers, exception.RevocationFinalizer) || cur.Annotations[exception.RevocationAnnotation] != e.Annotations[exception.RevocationAnnotation] {
			t.Fatalf("%s: the intent or its finalizer is gone: %s", what, lifecycle(cur))
		}
		return cur
	}

	serving := func(what string) {
		t.Helper()
		l.eventually(what, func() (bool, string) {
			err := alice.Create(l.ctx, newEx(ns, "probe"), client.DryRunAll)
			return err == nil, fmt.Sprint(err)
		})
	}
	unavailable := func(what string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "failed calling webhook") {
			t.Fatalf("%s: want the unavailable webhook to fail closed, got %v", what, err)
		}
		l.record("fail-closed", map[string]any{"attempt": what})
	}
	release := `{"metadata":{"finalizers":null}}`

	// 0. The default installation: processing off, no gated grant. The
	// controller can neither release nor edit (RBAC), records nothing, and
	// says why; a renewal of the revoked revision waits.
	running = start("eh-manager-0", false)
	l.eventually("manager elected", func() (bool, string) { return running.elected(), "" })
	serving("exception webhook serving")
	off := create(alice, newEx(ns, "disabled"))
	l.settled(ns, off.Name)
	off = revoke(dave, off)
	condition(off, v1alpha1.ReasonRevocationProcessingDisabled)
	cur := held("processing disabled", off)
	forbidden("release the finalizer as the controller without the gated grant", l.mergePatch(controllerSA, ns, off.Name, release))
	forbidden("label as the controller without the gated grant", l.mergePatch(controllerSA, ns, off.Name, `{"metadata":{"labels":{"by":"controller"}}}`))
	_, err := l.jsonPatch(alice, ns, off.Name, renewalPatch(cur))
	denied("renew while processing is disabled", err, exception.ReasonRevocationHistoryPending)
	time.Sleep(2 * historyRetry)
	if l.snapshotConfigMap(exception.RevocationRecordName(off.UID, 1)) != nil {
		t.Fatal("a revocation record was written with processing disabled")
	}
	held("processing disabled, later", off)
	l.record("processing-disabled", map[string]any{"reason": v1alpha1.ReasonRevocationProcessingDisabled, "finalizer": exception.RevocationFinalizer})

	// Enabling, in the documented order: the webhooks are registered and
	// fail closed (above), then the gated grant, then the flag. The held
	// revocation is recorded and released.
	stop()
	gated := l.shippedClusterRole("../../config/rbac/controller/exception-revocation.yaml", "konstapel-controller-exception-revocation")
	gatedBinding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "exc-history-" + gated},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: gated}, Subjects: []rbacv1.Subject{sa}}
	if err := l.c.Create(l.ctx, gatedBinding); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, gatedBinding) })
	running = start("eh-manager-1", true)
	l.eventually("manager elected", func() (bool, string) { return running.elected(), "" })
	serving("exception webhook serving with revocation processing")
	l.waitHistory(off)
	l.record("processing-enabled", map[string]any{"record": exception.RevocationRecordName(off.UID, 1)})

	// 1. Revoke: the record first, then the finalizer; deletion completes
	// and the history stays.
	basic := create(alice, newEx(ns, "basic"))
	l.settled(ns, basic.Name)
	revoked := revoke(dave, basic)
	rec := l.waitHistory(revoked)
	snapRef := l.exception(ns, basic.Name).Status.Acceptance
	parsed, _, _ := exception.RevocationRecordFrom(rec)
	if parsed.Revocation.Actor.Username != "dave" || parsed.Acceptance == nil || snapRef == nil || *parsed.Acceptance != *snapRef || parsed.Namespace.UID == "" {
		t.Fatalf("record %+v, snapshot %+v", parsed, snapRef)
	}
	cur = l.exception(ns, basic.Name)
	if err := alice.Delete(l.ctx, cur, client.Preconditions{UID: &cur.UID, ResourceVersion: &cur.ResourceVersion}); err != nil {
		t.Fatal(err)
	}
	removed("revoked exception", cur)
	if after := l.snapshotConfigMap(rec.Name); after == nil || after.ResourceVersion != rec.ResourceVersion {
		t.Fatal("deletion changed or removed the record")
	}
	l.record("revoke-record-release-delete", map[string]any{"record": rec.Name, "actor": "dave"})

	// 1b. The validating webhook is removed: the controller cannot verify
	// the protection its release depends on, so it records and releases
	// nothing until the webhook is registered again.
	val := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: exception.WebhookConfigurationName}, val); err != nil {
		t.Fatal(err)
	}
	if err := l.c.Delete(l.ctx, val); err != nil {
		t.Fatal(err)
	}
	unprotected := create(alice, newEx(ns, "unprotected"))
	l.settled(ns, unprotected.Name)
	unprotected = revoke(dave, unprotected)
	condition(unprotected, v1alpha1.ReasonRevocationProtectionUnverified)
	held("validating webhook removed", unprotected)
	if l.snapshotConfigMap(exception.RevocationRecordName(unprotected.UID, 1)) != nil {
		t.Fatal("a revocation record was written without verified admission protection")
	}
	restored := val.DeepCopy()
	restored.ObjectMeta = metav1.ObjectMeta{Name: val.Name, Labels: val.Labels, Annotations: val.Annotations}
	if err := l.c.Create(l.ctx, restored); err != nil {
		t.Fatal(err)
	}
	serving("validating webhook registered again")
	l.waitHistory(unprotected)
	l.record("protection-removed", map[string]any{"reason": v1alpha1.ReasonRevocationProtectionUnverified, "resumed": true})

	// 2. Tampering: application identities cannot touch the protected
	// namespace; the controller identity can neither rewrite records nor
	// revoke or edit exceptions; immutable records reject even an
	// administrator's rewrite.
	forged := rec.DeepCopy()
	forged.ObjectMeta = metav1.ObjectMeta{Name: exception.RevocationRecordName("00000000-0000-0000-0000-000000000001", 1), Namespace: DefaultSnapshotNamespace, Labels: rec.Labels, Annotations: rec.Annotations}
	forbidden("create a revocation record as a team member", alice.Create(l.ctx, forged))
	forbidden("delete a revocation record as a team member", alice.Delete(l.ctx, rec.DeepCopy()))
	edit := rec.DeepCopy()
	edit.Data[exception.RevocationRecordDataKey] = strings.Replace(edit.Data[exception.RevocationRecordDataKey], "dave", "platform-admin", 1)
	forbidden("rewrite a revocation record as a team member", alice.Update(l.ctx, edit.DeepCopy()))
	forbidden("rewrite a revocation record as the controller", controllerSA.Update(l.ctx, edit.DeepCopy()))
	forbidden("delete a revocation record as the controller", controllerSA.Delete(l.ctx, rec.DeepCopy()))
	if err := l.c.Update(l.ctx, edit.DeepCopy()); !apierrors.IsInvalid(err) {
		t.Fatalf("rewrite an immutable record as an administrator: want Invalid, got %v", err)
	}
	active := create(alice, newEx(ns, "active"))
	l.settled(ns, active.Name)
	denied("revoke as the controller", l.mergePatch(controllerSA, ns, active.Name, `{"spec":{"revoked":true}}`), exception.ReasonProtectedField)
	denied("label as the controller", l.mergePatch(controllerSA, ns, active.Name, `{"metadata":{"labels":{"by":"controller"}}}`), exception.ReasonProtectedField)
	l.record("tamper", map[string]any{"denied": true})

	// 3. Persistence fails: the intent and finalizer stay, renewal waits,
	// deletion is held, and only the controller may release, once the
	// record is durable.
	setFault(func(s *historyFaultState) { s.denyRecords = true })
	failing := create(alice, newEx(ns, "failing"))
	l.settled(ns, failing.Name)
	failing = revoke(alice, failing)
	condition(failing, v1alpha1.ReasonRevocationHistoryPending)
	cur = held("persistence failing", failing)
	_, err = l.jsonPatch(alice, ns, failing.Name, renewalPatch(cur))
	denied("renew while the record is not persisted", err, exception.ReasonRevocationHistoryPending)
	denied("release the finalizer as a team member", l.mergePatch(alice, ns, failing.Name, `{"metadata":{"finalizers":null}}`), exception.ReasonProtectedField)
	denied("release the finalizer as the controller before the record exists", l.mergePatch(controllerSA, ns, failing.Name, `{"metadata":{"finalizers":null}}`), exception.ReasonRevocationHistoryPending)
	cur = held("after release attempts", failing)
	if err := alice.Delete(l.ctx, cur, client.Preconditions{UID: &cur.UID, ResourceVersion: &cur.ResourceVersion}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * historyRetry) // retries keep failing; nothing is released
	if cur = held("deleted while persistence fails", failing); cur.DeletionTimestamp.IsZero() {
		t.Fatal("deletion not pending")
	}
	l.record("persistence-failure", map[string]any{"terminating": true, "finalizer": exception.RevocationFinalizer})
	setFault(func(s *historyFaultState) { s.denyRecords = false })
	rec = l.waitHistory(failing)
	removed("terminating revoked exception", failing)
	l.record("persistence-restored", map[string]any{"record": rec.Name, "removed": true})

	// 3b. Another object holds the record's name: it is not this
	// revocation's record, so the controller identity cannot release the
	// finalizer, and nothing overwrites it.
	squatted := create(alice, newEx(ns, "squatted"))
	l.settled(ns, squatted.Name)
	squatter := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: exception.RevocationRecordName(squatted.UID, 1), Namespace: DefaultSnapshotNamespace},
		Data: map[string]string{exception.RevocationRecordDataKey: `{"version":1}`}}
	if err := l.c.Create(l.ctx, squatter); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, squatter) })
	squatted = revoke(alice, squatted)
	condition(squatted, v1alpha1.ReasonRevocationRecordConflict)
	denied("release the finalizer as the controller with a conflicting record", l.mergePatch(controllerSA, ns, squatted.Name, release), exception.ReasonRevocationHistoryPending)
	held("conflicting record", squatted)
	if got := l.snapshotConfigMap(squatter.Name); got == nil || got.Data[exception.RevocationRecordDataKey] != squatter.Data[exception.RevocationRecordDataKey] {
		t.Fatal("the conflicting object was overwritten")
	}
	l.record("conflicting-record", map[string]any{"reason": v1alpha1.ReasonRevocationRecordConflict})

	// 4. The record create succeeds but its response is lost: recovered
	// from the stored record, without writing it again.
	setFault(func(s *historyFaultState) { s.loseRecord = true })
	lost := create(alice, newEx(ns, "lost"))
	l.settled(ns, lost.Name)
	lost = revoke(alice, lost)
	rec = l.waitHistory(lost)
	if n := posts(rec.Name); n != 1 {
		t.Fatalf("record %s sent %d times", rec.Name, n)
	}
	l.record("lost-response", map[string]any{"record": rec.Name, "creates": 1})

	// 5. The controller stops between persisting and releasing; a new
	// manager, elected once the old Lease expires, verifies and releases.
	setFault(func(s *historyFaultState) { s.denyRelease["crash"] = true })
	crash := create(alice, newEx(ns, "crash"))
	l.settled(ns, crash.Name)
	crash = revoke(alice, crash)
	crashRecord := exception.RevocationRecordName(crash.UID, 1)
	var persisted *corev1.ConfigMap
	l.eventually("record persisted before the release", func() (bool, string) {
		persisted = l.snapshotConfigMap(crashRecord)
		return persisted != nil, ""
	})
	condition(crash, v1alpha1.ReasonRevocationRecorded)
	held("record persisted, release failing", crash)
	stop()
	held("controller stopped", crash)
	// No webhook serves: every write fails closed, the controller's own
	// release included, although the record is durable.
	unavailable("release the finalizer as the controller while no webhook serves", l.mergePatch(controllerSA, ns, crash.Name, release))
	unavailable("revoke while no webhook serves", l.mergePatch(alice, ns, active.Name, `{"spec":{"revoked":true}}`))
	held("webhook unavailable", crash)
	// The replacement cannot learn its identity at first: its webhook
	// denies every write instead of letting the controller's pass as an
	// application identity's.
	setFault(func(s *historyFaultState) { delete(s.denyRelease, "crash"); s.denyIdentity = true })
	running = start("eh-manager-2", true)
	l.eventually("webhook serving without the controller identity", func() (bool, string) {
		err := alice.Create(l.ctx, newEx(ns, "probe"), client.DryRunAll)
		return err != nil && strings.Contains(err.Error(), "denied the request: "+exception.ReasonControllerIdentityUnknown+":"), fmt.Sprint(err)
	})
	denied("label as the controller, identity unknown", l.mergePatch(controllerSA, ns, active.Name, `{"metadata":{"labels":{"by":"controller"}}}`), exception.ReasonControllerIdentityUnknown)
	denied("release the finalizer as the controller, identity unknown", l.mergePatch(controllerSA, ns, crash.Name, release), exception.ReasonControllerIdentityUnknown)
	denied("revoke as a team member, identity unknown", l.mergePatch(alice, ns, active.Name, `{"spec":{"revoked":true}}`), exception.ReasonControllerIdentityUnknown)
	held("identity unknown", crash)
	if cur := l.exception(ns, active.Name); cur.Spec.Revoked || cur.Labels["by"] != "" {
		t.Fatalf("a write passed while the controller identity was unknown: %s", lifecycle(cur))
	}
	setFault(func(s *historyFaultState) { s.denyIdentity = false })
	serving("webhook serving once the identity is known")
	l.eventually("replacement elected", func() (bool, string) { return running.elected(), "" })
	rec = l.waitHistory(crash)
	if rec.ResourceVersion != persisted.ResourceVersion || posts(rec.Name) != 1 {
		t.Fatalf("record rewritten after restart: rv %s -> %s, creates %d", persisted.ResourceVersion, rec.ResourceVersion, posts(rec.Name))
	}
	l.record("restart-between-persist-and-release", map[string]any{"record": rec.Name, "rewritten": false})

	// 6. The controller is unavailable: another holder owns the Lease, so
	// the replica serves admission but does not reconcile.
	stop()
	l.eventually("Lease held by another holder", func() (bool, string) {
		cur := &coordinationv1.Lease{}
		if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(lease), cur); err != nil {
			return false, err.Error()
		}
		cur.Spec.HolderIdentity = ptr("exc-history-elsewhere")
		cur.Spec.LeaseDurationSeconds = ptr(int32(3600))
		cur.Spec.RenewTime = &metav1.MicroTime{Time: time.Now()}
		err := l.c.Update(l.ctx, cur)
		return err == nil, fmt.Sprint(err)
	})
	running = start("eh-manager-3", true)
	l.eventually("exception webhook serving without a leader", func() (bool, string) {
		err := alice.Create(l.ctx, newEx(ns, "probe"), client.DryRunAll)
		return err == nil, fmt.Sprint(err)
	})
	// A never-activated acceptance, revoked and deleted with its namespace.
	gnNS := &corev1.Namespace{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: gone}, gnNS); err != nil {
		t.Fatal(err)
	}
	never := create(alice, newEx(gone, "never"))
	never = revoke(alice, never)
	if err := alice.Delete(l.ctx, never); err != nil {
		t.Fatal(err)
	}
	if err := l.c.Delete(l.ctx, gnNS); err != nil {
		t.Fatal(err)
	}
	// A rapid renewal waits for the revoked revision's history.
	rapid := create(alice, newEx(ns, "rapid"))
	rapid = revoke(dave, rapid)
	_, err = l.jsonPatch(alice, ns, rapid.Name, renewalPatch(l.exception(ns, rapid.Name)))
	denied("rapid renewal before the history is durable", err, exception.ReasonRevocationHistoryPending)
	time.Sleep(3 * time.Second)
	if running.elected() {
		t.Fatal("a manager was elected while another holder owns the Lease")
	}
	held("never-activated, controller unavailable", never)
	if l.snapshotConfigMap(exception.SnapshotName(never.UID, 1)) != nil || l.snapshotConfigMap(exception.RevocationRecordName(never.UID, 1)) != nil {
		t.Fatal("history written without a leader")
	}
	nsState := &corev1.Namespace{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: gone}, nsState); err != nil || nsState.Status.Phase != corev1.NamespaceTerminating {
		t.Fatalf("namespace %s: %v %s", gone, err, nsState.Status.Phase)
	}
	l.record("controller-unavailable", map[string]any{"never": "terminating", "namespace": "terminating", "rapidRenewal": exception.ReasonRevocationHistoryPending})

	// The holder goes away; the replica is elected and catches up.
	if err := l.c.Delete(l.ctx, lease); err != nil {
		t.Fatal(err)
	}
	l.eventually("elected after the other holder left", func() (bool, string) { return running.elected(), "" })
	rec = l.waitHistory(never)
	removed("namespace "+gone, gnNS)
	snap := l.snapshotConfigMap(exception.SnapshotName(never.UID, 1))
	parsed, _, _ = exception.RevocationRecordFrom(rec)
	switch {
	case snap == nil:
		t.Fatal("the never-activated acceptance has no snapshot")
	case parsed.Acceptance == nil || parsed.Acceptance.Digest != snap.Annotations[exception.AnnotationSnapshotDigest]:
		t.Fatalf("record acceptance %+v, snapshot digest %s", parsed.Acceptance, snap.Annotations[exception.AnnotationSnapshotDigest])
	case rec.Labels[exception.LabelNamespaceUID] != string(gnNS.UID) || parsed.Namespace.UID != gnNS.UID:
		t.Fatalf("record namespace %+v, deleted namespace UID %s", parsed.Namespace, gnNS.UID)
	}
	l.record("never-activated-namespace-deleted", map[string]any{"record": rec.Name, "snapshot": snap.Name, "namespaceUID": gnNS.UID})

	// The rapid renewal goes through once the history is durable, with the
	// documented patch; revision 2 is revoked and deleted at once, and both
	// revisions keep their records.
	rec1 := l.waitHistory(rapid)
	renewed, err := l.jsonPatch(alice, ns, rapid.Name, renewalPatch(l.exception(ns, rapid.Name)))
	if err != nil {
		t.Fatalf("renew the revoked revision once its history is durable: %v", err)
	}
	if a := acceptance(t, renewed); a.Revision != 2 || a.Actor.Username != "alice" || renewed.Spec.Revoked || renewed.Annotations[exception.RevocationAnnotation] != "" {
		t.Fatalf("renewal = %+v %s", a, lifecycle(renewed))
	}
	l.settled(ns, rapid.Name)
	rapid2 := revoke(alice, renewed)
	if err := alice.Delete(l.ctx, rapid2); err != nil {
		t.Fatal(err)
	}
	rec2 := l.waitHistory(rapid2)
	removed("revision 2", rapid2)
	r1, _, _ := exception.RevocationRecordFrom(l.snapshotConfigMap(rec1.Name))
	r2, _, _ := exception.RevocationRecordFrom(rec2)
	if r1.Revocation.Actor.Username != "dave" || r2.Revocation.Actor.Username != "alice" || r1.AcceptanceRevision != 1 || r2.AcceptanceRevision != 2 ||
		l.snapshotConfigMap(rec1.Name).ResourceVersion != rec1.ResourceVersion {
		t.Fatalf("records %+v %+v", r1, r2)
	}
	l.record("rapid-renewal", map[string]any{"records": []string{rec1.Name, rec2.Name}})
}
