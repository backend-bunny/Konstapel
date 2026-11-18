//go:build live

package controller

// Live serving on every replica (add-controller-high-availability 3.1,
// 3.2). Two elected in-process managers serve the ComplianceException
// webhooks from config/webhook/exceptions.yaml; the API server reaches
// them through a test-owned TCP switch, so each step names the replica
// that answered:
//   - both replicas become ready while exactly one leads; the follower
//     serves admission without forwarding to the leader (3.1);
//   - central restrictions apply immediately on each replica, without
//     waiting for the leader to reconcile; acceptance, dry-run and
//     renewal attribution are the authenticated caller's (3.2);
//   - while the leader is gone and before the survivor is elected, the
//     survivor keeps serving with the same checks; failover renews,
//     broadens or rewrites no acceptance and no snapshot (3.2);
//   - a rejected certificate rotation takes one replica out of readiness
//     while it stays live and the other keeps serving; a missing external
//     capability (OCI bundle sources) fails only the affected namespace's
//     admission (3.1).
// Run through scripts/exception-admission-live.sh (assessments group).

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/exception"
)

const replicaSwitchPort = 19450

// tcpSwitch forwards every new connection to the current target and
// counts connections per target. Switching closes open connections, so
// the API server's next webhook call reaches only the new target.
type tcpSwitch struct {
	l      net.Listener
	mu     sync.Mutex
	target string
	open   map[net.Conn]bool
	counts map[string]int
}

func newTCPSwitch(t *testing.T, addr string) *tcpSwitch {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	s := &tcpSwitch{l: l, open: map[net.Conn]bool{}, counts: map[string]int{}}
	t.Cleanup(func() {
		_ = l.Close()
		s.route("")
	})
	go s.serve()
	return s
}

func (s *tcpSwitch) serve() {
	for {
		in, err := s.l.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		target := s.target
		if target == "" {
			s.mu.Unlock()
			_ = in.Close()
			continue
		}
		s.counts[target]++
		s.open[in] = true
		s.mu.Unlock()
		go func() {
			defer func() {
				s.mu.Lock()
				delete(s.open, in)
				s.mu.Unlock()
				_ = in.Close()
			}()
			out, err := net.DialTimeout("tcp", target, 5*time.Second)
			if err != nil {
				return
			}
			defer out.Close()
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(out, in); done <- struct{}{} }()
			go func() { _, _ = io.Copy(in, out); done <- struct{}{} }()
			<-done
		}()
	}
}

// route sends new connections to target ("" refuses them) and closes the
// open ones.
func (s *tcpSwitch) route(target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.target = target
	for c := range s.open {
		_ = c.Close()
	}
}

func (s *tcpSwitch) count(target string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[target]
}

// replica is one in-process controller pod: an elected manager serving
// probes and webhooks.
type replica struct {
	name, webhook, probes, certs string
	*candidate
}

func probeStatus(addr, path string) (int, string) {
	resp, err := http.Get("http://" + addr + path + "?verbose")
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestLiveReplicaAdmission(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	const sys = "konstapel-system"
	if err := l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: sys}}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = l.c.Delete(l.ctx, &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Namespace: sys, Name: LeaderElectionID}})
	})
	host := webhookHost(t)
	ca := newIssuer(t)
	now := time.Now()
	replicas := map[string]*replica{}
	for i, name := range []string{"a", "b"} {
		r := &replica{name: name, webhook: fmt.Sprintf("127.0.0.1:%d", exceptionWebhookPort+i), probes: freeAddr(t), certs: t.TempDir()}
		writeLeaf(t, r.certs, ca, int64(10+i), now.Add(-time.Hour), now.Add(time.Hour), host)
		replicas[name] = r
	}
	start := func(r *replica) {
		port := exceptionWebhookPort
		if r.name == "b" {
			port++
		}
		r.candidate = l.candidateWith("", "ra-replica-"+r.name, func(o *Options) {
			o.LocalBundle = content.Name
			o.ProbeAddr = r.probes
			o.WebhookCertDir, o.WebhookPort = r.certs, port
			o.Election = Election{LeaseDuration: 6 * time.Second, RenewDeadline: 4 * time.Second, RetryPeriod: time.Second}
		})
	}
	stopped := map[*candidate]bool{}
	t.Cleanup(func() {
		for _, r := range replicas {
			if r.candidate != nil && !stopped[r.candidate] {
				r.stop()
			}
		}
	})
	ready := func(r *replica) {
		t.Helper()
		l.eventually("replica "+r.name+" ready", func() (bool, string) {
			code, body := probeStatus(r.probes, "/readyz")
			return code == http.StatusOK, body
		})
	}
	sw := newTCPSwitch(t, fmt.Sprintf(":%d", replicaSwitchPort))
	l.installExceptionWebhooksAt(host, replicaSwitchPort, ca.pem)

	// Central configuration: SelfService in ra-team; ra-oci is also
	// targeted by a profile whose OCI bundle has no configured source.
	const team, oci = "ra-team", "ra-oci"
	l.setNamespace(team, "ra-team")
	l.setNamespace(oci, "ra-oci")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "ra-self-service"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: digest(t)},
			Policies: []v1alpha1.ProfilePolicy{{Name: pol, Exceptions: v1alpha1.ExceptionSettings{Eligibility: v1alpha1.ExceptionsSelfService, MaxLifetime: &metav1.Duration{Duration: 720 * time.Hour}}}}}}
	b := bindingObj("ra-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "ra-team"})
	bOCI := bindingObj("ra-audit-oci", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "ra-oci"})
	// A distinct digest: exception admission and targeting identify bundle
	// content by digest alone.
	orgDigest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("ra-org-bundle")))
	pOrg := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "ra-org"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: "ra-org-bundle", Digest: orgDigest}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	bOrg := bindingObj("ra-org", pOrg.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "ra-oci"})
	editor := l.shippedClusterRole("../../config/rbac/exception-editor.yaml", "konstapel-exception-editor")
	var objs []client.Object
	for _, ns := range []string{team, oci} {
		objs = append(objs, &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "exception-editors", Namespace: ns},
			RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: editor},
			Subjects: []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: "Group", Name: "ra-editors"}}})
	}
	objs = append(objs, p, b, bOCI, pOrg, bOrg)
	for _, o := range objs {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, ns := range []string{team, oci} {
			_ = l.c.DeleteAllOf(l.ctx, &v1alpha1.ComplianceException{}, client.InNamespace(ns))
		}
		for i := len(objs) - 1; i >= 0; i-- {
			_ = l.c.Delete(l.ctx, objs[i])
		}
	})
	alice := l.as("alice", "ra-editors", "system:authenticated")
	bob := l.as("bob", "ra-editors", "system:authenticated")
	newEx := func(ns, name string, annotations map[string]string) *v1alpha1.ComplianceException {
		return &v1alpha1.ComplianceException{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: annotations},
			Spec: v1alpha1.ComplianceExceptionSpec{Policy: pol, WorkloadSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "debug"}},
				Reason: "replica admission", ExpiresAt: metav1.NewTime(time.Now().Add(24 * time.Hour).Truncate(time.Second)), AcceptanceRevision: 1}}
	}
	// via routes the webhooks to r and waits until r answers a dry run.
	via := func(r *replica) {
		t.Helper()
		sw.route(r.webhook)
		before := sw.count(r.webhook)
		l.eventually("admission through replica "+r.name, func() (bool, string) {
			err := alice.Create(l.ctx, newEx(team, "ra-probe", nil), client.DryRunAll)
			return err == nil && sw.count(r.webhook) > before, fmt.Sprint(err)
		})
	}
	// served asserts that only r answered webhook calls since mark.
	served := func(r *replica, mark map[string]int) {
		t.Helper()
		for _, o := range replicas {
			if o != r && sw.count(o.webhook) != mark[o.webhook] {
				t.Fatalf("replica %s answered while admission was routed to %s", o.name, r.name)
			}
		}
	}
	marks := func() map[string]int {
		m := map[string]int{}
		for _, r := range replicas {
			m[r.webhook] = sw.count(r.webhook)
		}
		return m
	}
	setEligibility := func(e v1alpha1.ExceptionEligibility) {
		t.Helper()
		// The leader writes profile status concurrently.
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			cur := &v1alpha1.ComplianceProfile{}
			if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(p), cur); err != nil {
				return err
			}
			// The API requires a lifetime exactly for SelfService.
			cur.Spec.Policies[0].Exceptions = v1alpha1.ExceptionSettings{Eligibility: e}
			if e == v1alpha1.ExceptionsSelfService {
				cur.Spec.Policies[0].Exceptions.MaxLifetime = &metav1.Duration{Duration: 720 * time.Hour}
			}
			return l.c.Update(l.ctx, cur)
		}); err != nil {
			t.Fatal(err)
		}
	}
	// denied asserts that a webhook denied the request for reason.
	denied := func(what string, err error, reason string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "denied the request: "+reason) {
			t.Fatalf("%s: want %s, got %v", what, reason, err)
		}
	}
	stored := func(name string) bool {
		return l.c.Get(l.ctx, client.ObjectKey{Namespace: team, Name: name}, &v1alpha1.ComplianceException{}) == nil
	}

	// 1. Both replicas become ready while exactly one leads (3.1).
	start(replicas["a"])
	start(replicas["b"])
	var leader, follower *replica
	l.eventually("one replica elected", func() (bool, string) {
		a, bb := replicas["a"], replicas["b"]
		switch {
		case a.elected() && bb.elected():
			t.Fatal("both replicas elected")
		case a.elected():
			leader, follower = a, bb
		case bb.elected():
			leader, follower = bb, a
		}
		return leader != nil, ""
	})
	ready(leader)
	ready(follower)
	code, body := probeStatus(follower.probes, "/readyz")
	if follower.elected() || code != http.StatusOK || !strings.Contains(body, "informers") || !strings.Contains(body, "webhook") {
		t.Fatalf("follower readiness %d (elected %v): %s", code, follower.elected(), body)
	}
	l.record("both-ready", map[string]any{"leader": leader.name, "follower": follower.name, "followerReadyz": body})
	l.waitReady(b.Name, 1)

	// 2. The follower serves admission; attribution is the caller's.
	via(follower)
	mark := marks()
	forged := `{"revision":1,"actor":{"username":"platform-admin"}}`
	one := newEx(team, "ra-one", map[string]string{exception.AcceptanceAnnotation: forged})
	if err := alice.Create(l.ctx, one); err != nil {
		t.Fatal(err)
	}
	if a := acceptance(t, one); a.Actor.Username != "alice" || a.Revision != 1 || a.Eligibility == nil || a.Eligibility.Effective != v1alpha1.ExceptionsSelfService {
		t.Fatalf("acceptance through the follower = %+v", a)
	}
	dry := newEx(team, "ra-dry", nil)
	if err := bob.Create(l.ctx, dry, client.DryRunAll); err != nil {
		t.Fatal(err)
	}
	if acceptance(t, dry).Actor.Username != "bob" || stored(dry.Name) {
		t.Fatalf("dry run through the follower: %+v stored=%v", acceptance(t, dry), stored(dry.Name))
	}
	served(follower, mark)
	oneSnap1 := l.waitSnapshot(one, 1)
	l.record("follower-serves", map[string]any{"replica": follower.name, "actor": "alice", "dryRunStored": false})

	// 3. Central edits apply on each replica at once: no wait for the
	// leader to reconcile, no cached grant.
	for _, r := range []*replica{leader, follower} {
		via(r)
		mark := marks()
		setEligibility(v1alpha1.ExceptionsForbidden)
		denied("create under a central restriction via "+r.name, alice.Create(l.ctx, newEx(team, "ra-blocked-"+r.name, nil)), exception.ReasonForbidden)
		denied("dry run under a central restriction via "+r.name, bob.Create(l.ctx, newEx(team, "ra-blocked-dry-"+r.name, nil), client.DryRunAll), exception.ReasonForbidden)
		renew := &v1alpha1.ComplianceException{}
		if err := bob.Get(l.ctx, client.ObjectKeyFromObject(one), renew); err != nil {
			t.Fatal(err)
		}
		renew.Spec.AcceptanceRevision++
		renew.Spec.ExpiresAt = metav1.NewTime(time.Now().Add(48 * time.Hour).Truncate(time.Second))
		denied("renewal under a central restriction via "+r.name, l.patchException(bob, renew), exception.ReasonForbidden)
		setEligibility(v1alpha1.ExceptionsSelfService)
		allowed := newEx(team, "ra-after-"+r.name, nil)
		if err := alice.Create(l.ctx, allowed); err != nil {
			t.Fatalf("create after lifting the restriction via %s: %v", r.name, err)
		}
		// A missing external capability fails only the affected namespace.
		denied("namespace with unavailable OCI content via "+r.name, alice.Create(l.ctx, newEx(oci, "ra-oci-"+r.name, nil)), exception.ReasonUnresolved)
		served(r, mark)
		if code, body := probeStatus(r.probes, "/readyz"); code != http.StatusOK {
			t.Fatalf("replica %s unready with OCI content unavailable: %s", r.name, body)
		}
		l.record("central-edits", map[string]any{"replica": r.name, "restricted": "Forbidden at once", "lifted": "accepted at once", "ociNamespace": exception.ReasonUnresolved})
	}

	// 4. Renewal through the follower: a new revision by the renewing
	// caller; skipped revisions and rewritten records are rejected.
	via(follower)
	renewed := &v1alpha1.ComplianceException{}
	if err := bob.Get(l.ctx, client.ObjectKeyFromObject(one), renewed); err != nil {
		t.Fatal(err)
	}
	renewed.Spec.AcceptanceRevision = 2
	renewed.Spec.ExpiresAt = metav1.NewTime(time.Now().Add(48 * time.Hour).Truncate(time.Second))
	if err := l.patchException(bob, renewed); err != nil {
		t.Fatal(err)
	}
	if a := acceptance(t, renewed); a.Revision != 2 || a.Actor.Username != "bob" {
		t.Fatalf("renewal through the follower = %+v", a)
	}
	skip := renewed.DeepCopy()
	skip.Spec.AcceptanceRevision = 4
	if err := l.patchException(bob, skip); err == nil {
		t.Fatal("a renewal skipping a revision was accepted")
	}
	tampered := renewed.DeepCopy()
	tampered.Annotations[exception.AcceptanceAnnotation] = strings.Replace(tampered.Annotations[exception.AcceptanceAnnotation], `"username":"bob"`, `"username":"platform-admin"`, 1)
	denied("rewritten acceptance via the follower", l.patchException(bob, tampered), exception.AcceptanceAnnotation+" is protected")
	l.waitSnapshot(one, 2)

	// Everything accepted so far, as the API server stores it.
	type kept struct {
		annotation, expiresAt string
		revision              int64
		snapshot              string
		snapshotRV            string
	}
	before := map[string]kept{}
	var exceptions v1alpha1.ComplianceExceptionList
	if err := l.c.List(l.ctx, &exceptions, client.InNamespace(team)); err != nil {
		t.Fatal(err)
	}
	for i := range exceptions.Items {
		ex := &exceptions.Items[i]
		cm := l.waitSnapshot(ex, ex.Spec.AcceptanceRevision)
		before[ex.Name] = kept{ex.Annotations[exception.AcceptanceAnnotation], ex.Spec.ExpiresAt.UTC().Format(time.RFC3339), ex.Spec.AcceptanceRevision, cm.Name, cm.ResourceVersion}
	}
	l.record("before-failover", map[string]any{"exceptions": len(before)})

	// 5. The leader goes away. Until the survivor is elected, it serves
	// admission with the same checks; nothing waits for a leader.
	gone := leader
	gone.stop()
	stopped[gone.candidate] = true
	survivor := follower
	sw.route(survivor.webhook)
	gap := newEx(team, "ra-gap", nil)
	// The API server may first try a connection the switch just closed;
	// that call fails before admission and is retried. Denials are not.
	var err error
	for end := time.Now().Add(15 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		err = alice.Create(l.ctx, gap.DeepCopy())
		if err == nil || !strings.Contains(err.Error(), "failed calling webhook") || time.Now().After(end) {
			break
		}
	}
	if err == nil {
		err = l.c.Get(l.ctx, client.ObjectKeyFromObject(gap), gap)
	}
	if err != nil {
		t.Fatalf("admission without a leader: %v", err)
	}
	inGap := !survivor.elected()
	if a := acceptance(t, gap); a.Actor.Username != "alice" || a.Revision != 1 {
		t.Fatalf("acceptance without a leader = %+v", a)
	}
	setEligibility(v1alpha1.ExceptionsForbidden)
	denied("restriction without a leader", alice.Create(l.ctx, newEx(team, "ra-gap-blocked", nil)), exception.ReasonForbidden)
	setEligibility(v1alpha1.ExceptionsSelfService)
	if err := bob.Create(l.ctx, newEx(team, "ra-gap-dry", nil), client.DryRunAll); err != nil || stored("ra-gap-dry") {
		t.Fatalf("dry run without a leader: %v stored=%v", err, stored("ra-gap-dry"))
	}
	if code, body := probeStatus(survivor.probes, "/readyz"); code != http.StatusOK {
		t.Fatalf("survivor unready after the leader left: %s", body)
	}
	l.record("leaderless", map[string]any{"survivor": survivor.name, "servedBeforeElection": inGap})

	// The survivor takes over once the Lease expires; then the stopped pod
	// is replaced and follows, ready and serving.
	l.eventually("survivor elected", func() (bool, string) { return survivor.elected(), "" })
	start(gone)
	ready(gone)
	if gone.elected() {
		t.Fatal("both replicas elected")
	}
	// The new leader persists what was accepted without a leader exactly
	// as accepted.
	snapshotBy := func(rev int64, actor string) {
		t.Helper()
		snap, _, err := exception.SnapshotFrom(l.waitSnapshot(gap, rev))
		if err != nil {
			t.Fatal(err)
		}
		if snap.Actor.Username != actor || snap.AcceptanceRevision != rev || snap.Eligibility.Effective != v1alpha1.ExceptionsSelfService ||
			snap.ExpiresAt.UTC().Format(time.RFC3339) != gap.Spec.ExpiresAt.UTC().Format(time.RFC3339) {
			t.Fatalf("snapshot %d of the leaderless acceptance: %+v", rev, snap)
		}
	}
	snapshotBy(1, "alice")
	via(gone)
	mark = marks()
	gapRenew := &v1alpha1.ComplianceException{}
	if err := bob.Get(l.ctx, client.ObjectKeyFromObject(gap), gapRenew); err != nil {
		t.Fatal(err)
	}
	gapRenew.Spec.AcceptanceRevision = 2
	gapRenew.Spec.ExpiresAt = metav1.NewTime(time.Now().Add(48 * time.Hour).Truncate(time.Second))
	if err := l.patchException(bob, gapRenew); err != nil {
		t.Fatal(err)
	}
	if a := acceptance(t, gapRenew); a.Revision != 2 || a.Actor.Username != "bob" {
		t.Fatalf("renewal through the replacement = %+v", a)
	}
	served(gone, mark)

	gap = gapRenew
	snapshotBy(2, "bob")
	// Nothing accepted before failover changed.
	if cm := l.snapshotConfigMap(oneSnap1.Name); cm == nil || cm.ResourceVersion != oneSnap1.ResourceVersion {
		t.Errorf("the first snapshot of %s changed or vanished across failover", one.Name)
	}
	for name, k := range before {
		cur := &v1alpha1.ComplianceException{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: team, Name: name}, cur); err != nil {
			t.Fatal(err)
		}
		cm := l.snapshotConfigMap(k.snapshot)
		switch {
		case cur.Annotations[exception.AcceptanceAnnotation] != k.annotation:
			t.Errorf("%s: acceptance rewritten across failover", name)
		case cur.Spec.AcceptanceRevision != k.revision || cur.Spec.ExpiresAt.UTC().Format(time.RFC3339) != k.expiresAt:
			t.Errorf("%s: renewed across failover: revision %d expiresAt %s", name, cur.Spec.AcceptanceRevision, cur.Spec.ExpiresAt)
		case cur.Status.Acceptance == nil || cur.Status.Acceptance.Revision != k.revision:
			t.Errorf("%s: acceptance status %+v after failover", name, cur.Status.Acceptance)
		case cm == nil || cm.ResourceVersion != k.snapshotRV:
			t.Errorf("%s: snapshot %s changed or vanished across failover", name, k.snapshot)
		}
	}
	l.record("failover", map[string]any{"leader": survivor.name, "replacement": gone.name, "unchanged": len(before)})

	// 6. A rejected rotation on the follower takes it out of readiness
	// while it stays live; the leader keeps serving. A valid one restores it.
	writeLeaf(t, gone.certs, ca, 30, now.Add(-2*time.Hour), now.Add(-time.Hour), host)
	l.eventually("follower unready with expired TLS", func() (bool, string) {
		code, body := probeStatus(gone.probes, "/readyz")
		return code != http.StatusOK && strings.Contains(body, "webhook"), body
	})
	if code, body := probeStatus(gone.probes, "/healthz"); code != http.StatusOK {
		t.Fatalf("liveness failed with invalid TLS: %s", body)
	}
	if code, body := probeStatus(survivor.probes, "/readyz"); code != http.StatusOK {
		t.Fatalf("leader unready while the follower's TLS is invalid: %s", body)
	}
	via(survivor)
	l.record("invalid-tls", map[string]any{"unready": gone.name, "live": true, "serving": survivor.name})
	writeLeaf(t, gone.certs, ca, 31, now.Add(-time.Hour), now.Add(time.Hour), host)
	ready(gone)
	via(gone)
	l.record("tls-restored", map[string]any{"replica": gone.name})

	evidence, _ := json.Marshal(map[string]int{"leaderConnections": sw.count(survivor.webhook), "replacementConnections": sw.count(gone.webhook)})
	l.record("connections", map[string]any{"counts": string(evidence)})
}
