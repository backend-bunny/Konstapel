package preview

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/exception"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const (
	ctrlNS    = "konstapel-system"
	polName   = "disallow-privileged-containers"
	clusterID = "kube-system:ks-uid"
	// Free text and actor identity that must never reach an observation.
	secretReason = "REASON-TEXT-MUST-NOT-LEAK"
	actorName    = "alice@example.invalid"
)

var fixedNow = time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)

func clock() func() time.Time {
	t := fixedNow
	return func() time.Time { t = t.Add(time.Second); return t }
}

func selector(env string) *v1alpha1.NamespaceSelector {
	return &v1alpha1.NamespaceSelector{MatchLabels: map[string]v1alpha1.LabelValue{"env": v1alpha1.LabelValue(env)}}
}

func contribution(binding, bindingUID string, mode v1alpha1.EnforcementMode, env string) targeting.Contribution {
	return targeting.Contribution{Cluster: clusterID, Binding: targeting.ObjectRevision{Name: binding, UID: types.UID(bindingUID)},
		Profile: targeting.ObjectRevision{Name: "shared", UID: "uid-shared", Generation: 1}, Policy: polName,
		BundleName: "konstapel-vendored", BundleDigest: digestA, ConfigurationDigest: digestB, Mode: mode,
		NamespaceSelector: *selector(env), Revision: "sha256:" + strings.Repeat("c", 64)}
}

// enginePolicy renders the ownership and provenance metadata Konstapel
// delivers (targeting.Render). owner "" omits the controller reference.
func enginePolicy(c targeting.Contribution, owner string, annotate bool) map[string]any {
	ann := map[string]any{}
	if annotate {
		for k, v := range map[string]string{targeting.AnnotationRevision: c.Revision, targeting.AnnotationPolicy: c.Policy,
			targeting.AnnotationBinding: c.Binding.Name, targeting.AnnotationProfile: c.Profile.Name, targeting.AnnotationProfileUID: string(c.Profile.UID),
			targeting.AnnotationProfileGen: "1", targeting.AnnotationBundle: c.BundleName, targeting.AnnotationBundleDigest: c.BundleDigest,
			targeting.AnnotationConfiguration: c.ConfigurationDigest, targeting.AnnotationSourceDigest: digestA, targeting.AnnotationCluster: c.Cluster,
			targeting.AnnotationMode: string(c.Mode)} {
			ann[k] = v
		}
	}
	ann["kyverno.io/unrelated"] = "x"
	meta := map[string]any{"name": targeting.PolicyName(c), "uid": "uid-" + targeting.PolicyName(c), "annotations": ann,
		"labels": map[string]any{targeting.LabelManagedBy: targeting.ManagedByValue, targeting.LabelBindingUID: string(c.Binding.UID), targeting.LabelPolicyHash: targeting.PolicyHash(c.Policy)}}
	if owner != "" {
		meta["ownerReferences"] = []any{map[string]any{"apiVersion": "compliance.erenius.io/v1alpha1", "kind": "ComplianceBinding", "name": c.Binding.Name, "uid": owner, "controller": true}}
	}
	labels := map[string]any{}
	for k, v := range c.NamespaceSelector.MatchLabels {
		labels[k] = string(v)
	}
	return map[string]any{"metadata": meta,
		"spec": map[string]any{"validationActions": []any{"Deny"}, "matchConstraints": map[string]any{"namespaceSelector": map[string]any{"matchLabels": labels}}},
		"status": map[string]any{"conditionStatus": map[string]any{"conditions": []any{
			map[string]any{"type": "RBACPermissionsGranted", "status": "True", "lastTransitionTime": "2026-11-19T09:00:00Z"},
			map[string]any{"type": "WebhookConfigured", "status": "True", "lastTransitionTime": "2026-11-19T09:00:00Z"}}}}}
}

func namespace(name, uid string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uid), Labels: labels}}
}

// baseline is a cluster with one profile shared by two bindings, owned,
// orphaned, label-only and unreadable engine policies, and one accepted
// exception with its frozen snapshot.
func baseline(t *testing.T) *fakeAPI {
	t.Helper()
	f := newFakeAPI(t)
	f.put(pathNamespaces, namespace("kube-system", "ks-uid", nil))
	f.put(pathNamespaces, namespace(ctrlNS, "ctrl-uid", nil))
	f.put(pathNamespaces, namespace("prod", "prod-uid", map[string]string{"env": "production"}))
	f.put(pathNamespaces, namespace("dev", "dev-uid", map[string]string{"env": "development"}))
	f.put(pathNamespaces, namespace("staging", "staging-uid", map[string]string{"env": "staging"}))

	p := liveProfile(t, "shared", "uid-shared", 1)
	f.put(pathProfiles, &p)
	prod := liveBinding(t, "b-prod", "shared", "Deny", "uid-b-prod", 1)
	prod.Spec.NamespaceSelector = selector("production")
	f.put(pathBindings, &prod)
	dev := liveBinding(t, "b-dev", "shared", "Audit", "uid-b-dev", 1)
	dev.Spec.NamespaceSelector = selector("development")
	f.put(pathBindings, &dev)

	f.put(pathPolicies, enginePolicy(contribution("b-prod", "uid-b-prod", v1alpha1.ModeDeny, "production"), "uid-b-prod", true))
	f.put(pathPolicies, enginePolicy(contribution("b-gone", "uid-gone", v1alpha1.ModeDeny, "production"), "uid-gone", true))
	labelOnly := contribution("b-dev", "uid-b-dev", v1alpha1.ModeAudit, "development")
	labelOnly.Revision = "sha256:" + strings.Repeat("d", 64)
	f.put(pathPolicies, enginePolicy(labelOnly, "", true))
	unreadable := contribution("b-dev", "uid-b-dev", v1alpha1.ModeAudit, "development")
	f.put(pathPolicies, enginePolicy(unreadable, "uid-b-dev", false))

	f.putException(t, "allow-debug", "prod", "prod-uid", "uid-ex")
	return f
}

func (f *fakeAPI) putException(t *testing.T, name, ns, nsUID, uid string) {
	t.Helper()
	ref := targeting.NamespaceRef{Name: ns, UID: types.UID(nsUID)}
	acc := exception.Acceptance{Revision: 1, AcceptedAt: metav1.NewTime(fixedNow.Add(-time.Hour)), Actor: exception.Actor{Username: actorName, Groups: []string{"team-a"}},
		Cluster: clusterID, Namespace: ref, Policy: polName,
		Eligibility: &targeting.Eligibility{Namespace: ref, Policy: polName, Effective: v1alpha1.ExceptionsSelfService,
			Contributors: []targeting.ContributionRef{{Binding: targeting.ObjectRevision{Name: "b-prod", UID: "uid-b-prod", Generation: 1}, Mode: v1alpha1.ModeDeny, Revision: "sha256:" + strings.Repeat("c", 64)}}}}
	raw, _ := json.Marshal(acc)
	ex := &v1alpha1.ComplianceException{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: types.UID(uid), Generation: 1,
		Annotations: map[string]string{exception.AcceptanceAnnotation: string(raw)}},
		Spec: v1alpha1.ComplianceExceptionSpec{Policy: polName, WorkloadSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "debug"}},
			Reason: secretReason, ExpiresAt: metav1.NewTime(fixedNow.Add(24 * time.Hour)), AcceptanceRevision: 1}}
	snap, err := exception.NewSnapshot(ex, acc)
	if err != nil {
		t.Fatal(err)
	}
	cm, digest, err := snap.ConfigMap(ctrlNS)
	if err != nil {
		t.Fatal(err)
	}
	ex.Status.Acceptance = &v1alpha1.AcceptanceSnapshotReference{Revision: 1, Snapshot: cm.Name, Digest: digest}
	f.put(pathExceptions, ex)
	f.put(pathConfigMaps(ctrlNS), cm)
}

func observe(t *testing.T, f *fakeAPI, mod func(*ObserveOptions)) (*Snapshot, error) {
	t.Helper()
	opts := ObserveOptions{Config: f.config(), Context: "kind-test", Namespace: ctrlNS, Now: clock(), Limits: ObserveLimits{PageSize: 2}}
	if mod != nil {
		mod(&opts)
	}
	return Observe(context.Background(), opts)
}

func mustComplete(t *testing.T, s *Snapshot, err error) {
	t.Helper()
	if err != nil || s == nil || !s.Complete || len(s.Errors) != 0 {
		t.Fatalf("want a complete snapshot, got err=%v snapshot=%+v", err, s)
	}
}

// mustIncomplete asserts an incomplete snapshot that carries no object sets.
func mustIncomplete(t *testing.T, s *Snapshot, err error, code ObserveCode) {
	t.Helper()
	var inc *IncompleteError
	if !errors.As(err, &inc) || s == nil || s.Complete {
		t.Fatalf("want an incomplete snapshot (%s), got err=%v snapshot=%+v", code, err, s)
	}
	if len(s.Errors) == 0 || s.Errors[0].Code != code || len(inc.Errors) != len(s.Errors) {
		t.Fatalf("want error %s, got %+v", code, s.Errors)
	}
	if len(s.Live.Profiles)+len(s.Live.Bindings)+len(s.Namespaces)+len(s.Applied)+len(s.Unowned)+len(s.Exceptions)+len(s.AcceptanceSnapshots)+len(s.RevocationRecords)+len(s.Objects) != 0 ||
		s.Sources != nil || s.Cluster != "" {
		t.Fatalf("an incomplete snapshot must not carry partial object sets: %+v", s)
	}
}

func assertReadOnly(t *testing.T, reqs []recorded) {
	t.Helper()
	if len(reqs) == 0 {
		t.Fatal("no requests recorded")
	}
	for _, r := range reqs {
		if r.Method != http.MethodGet || strings.Contains(r.Query, "dryRun") || strings.Contains(r.Query, "watch=") || isSecretPath(r.Path) {
			t.Fatalf("non-read request sent: %+v", r)
		}
	}
}

// assertSecretReads asserts read-only requests in which every Secret request
// is a plain GET of one of the named Secrets in the controller namespace, and
// each named Secret was read.
func assertSecretReads(t *testing.T, reqs []recorded, names ...string) {
	t.Helper()
	read := map[string]bool{}
	var other []recorded
	for _, r := range reqs {
		if !isSecretPath(r.Path) {
			other = append(other, r)
			continue
		}
		name, ok := strings.CutPrefix(r.Path, pathSecrets(ctrlNS)+"/")
		if r.Method != http.MethodGet || r.Query != "" || !ok || !slices.Contains(names, name) {
			t.Fatalf("Secret request outside the referenced names: %+v", r)
		}
		read[name] = true
	}
	assertReadOnly(t, other)
	for _, n := range names {
		if !read[n] {
			t.Fatalf("referenced Secret %s was not read: %+v", n, reqs)
		}
	}
}

// assertNoSecretValues asserts that no Secret value appears in a
// snapshot's JSON or in any of its formatted forms.
func assertNoSecretValues(t *testing.T, s *Snapshot, values ...string) {
	t.Helper()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	forms := []string{string(raw), fmt.Sprintf("%v", s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s), fmt.Sprintf("%+v", *s),
		fmt.Sprintf("%v", s.inputs), fmt.Sprintf("%+v", s.inputs), fmt.Sprintf("%#v", s.inputs)}
	for _, v := range values {
		// Verbatim, base64, and as fmt renders a []byte with %v and %#v.
		decimal := strings.Trim(fmt.Sprint([]byte(v)), "[]")
		hexBytes := strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%#v", []byte(v)), "[]byte{"), "}")
		for _, enc := range []string{v, base64.StdEncoding.EncodeToString([]byte(v)), decimal, hexBytes} {
			for _, f := range forms {
				if strings.Contains(f, enc) {
					t.Fatalf("a Secret value reached the snapshot's output: %s", f)
				}
			}
		}
	}
}

func keys[T any](items []T, key func(T) string) []string {
	var out []string
	for _, i := range items {
		out = append(out, key(i))
	}
	return out
}

// 2.1: identity, profiles and bindings (including shared-profile consumers
// absent from any input), namespace UIDs, ownership and pagination.
func TestObserveReadsAttributableSnapshot(t *testing.T) {
	f := baseline(t)
	s, err := observe(t, f, nil)
	mustComplete(t, s, err)

	if s.Cluster != clusterID || s.Context != "kind-test" || !s.Start.Before(s.End) || s.Captures != 2 || len(s.Drift) != 0 {
		t.Fatalf("provenance: cluster=%s context=%s start=%v end=%v captures=%d drift=%v", s.Cluster, s.Context, s.Start, s.End, s.Captures, s.Drift)
	}
	if got := keys(s.Live.Bindings, func(b v1alpha1.ComplianceBinding) string { return b.Name + "@" + string(b.UID) }); !slices.Equal(got, []string{"b-dev@uid-b-dev", "b-prod@uid-b-prod"}) {
		t.Fatalf("bindings: %v", got)
	}
	if len(s.Live.Profiles) != 1 || s.Live.Profiles[0].UID != "uid-shared" || s.Live.Profiles[0].ResourceVersion == "" {
		t.Fatalf("profiles: %+v", s.Live.Profiles)
	}
	if got := keys(s.Namespaces, func(n ObservedNamespace) string { return n.Name + "@" + string(n.UID) }); !slices.Equal(got,
		[]string{"dev@dev-uid", ctrlNS + "@ctrl-uid", "kube-system@ks-uid", "prod@prod-uid", "staging@staging-uid"}) {
		t.Fatalf("namespaces: %v", got)
	}
	if tn := s.TargetingNamespaces(); len(tn) != 5 || tn[3].UID != "prod-uid" || tn[3].Labels["env"] != "production" {
		t.Fatalf("targeting namespaces: %+v", tn)
	}

	// Ownership follows targeting.OwnedBy; the label alone is not ownership.
	var unreadable *AppliedPolicy
	for i, a := range s.Applied {
		if a.ProvenanceError != "" {
			unreadable = &s.Applied[i]
		}
	}
	if len(s.Applied) != 3 || unreadable == nil || unreadable.Contribution != nil || unreadable.BindingUID != "uid-b-dev" || unreadable.Ownership != Owned {
		t.Fatalf("applied: %+v", s.Applied)
	}
	var owned, orphan int
	for _, a := range s.Applied {
		switch {
		case a.ProvenanceError != "":
		case a.Ownership == Owned && a.BindingUID == "uid-b-prod" && a.Ready && a.Contribution.Mode == v1alpha1.ModeDeny && a.UID != "" && a.ResourceVersion != "":
			owned++
		case a.Ownership == Orphaned && a.BindingUID == "uid-gone":
			orphan++
		}
	}
	if owned != 1 || orphan != 1 || len(s.Unowned) != 1 || !strings.HasPrefix(s.Unowned[0].Name, "konstapel-") {
		t.Fatalf("owned=%d orphan=%d unowned=%v", owned, orphan, s.Unowned)
	}

	// Acceptance projections come from the exception owner's records.
	if len(s.Exceptions) != 1 || s.Exceptions[0].Acceptance == nil || s.Exceptions[0].Acceptance.Namespace.UID != "prod-uid" ||
		s.Exceptions[0].Acceptance.Contributors != 1 || s.Exceptions[0].Snapshot == nil {
		t.Fatalf("exceptions: %+v", s.Exceptions)
	}
	if len(s.AcceptanceSnapshots) != 1 || s.AcceptanceSnapshots[0].VerifyError != "" || s.AcceptanceSnapshots[0].Digest != s.Exceptions[0].Snapshot.Digest ||
		s.AcceptanceSnapshots[0].ExceptionUID != "uid-ex" || s.AcceptanceSnapshots[0].Eligibility == nil {
		t.Fatalf("snapshots: %+v", s.AcceptanceSnapshots)
	}

	// Provenance: every object's identity and revision, list revisions, pages.
	if !slices.IsSortedFunc(s.Objects, compareRef) || len(s.Objects) != 5+1+2+4+1+1 {
		t.Fatalf("objects (%d): %+v", len(s.Objects), s.Objects)
	}
	for _, o := range s.Objects {
		if o.UID == "" || o.ResourceVersion == "" {
			t.Fatalf("object without identity: %+v", o)
		}
	}
	pages := map[string]int{}
	for _, c := range s.Collections {
		if c.Name == "" && c.ResourceVersion == "" {
			t.Fatalf("collection without resourceVersion: %+v", c)
		}
		pages[c.Resource] += c.Pages
	}
	if pages["/v1/namespaces"] != 1+3 || pages["policies.kyverno.io/v1/validatingpolicies"] != 2 {
		t.Fatalf("pagination: %v", pages)
	}
	var continued bool
	for _, r := range f.recorded() {
		continued = continued || strings.Contains(r.Query, "continue=")
		if strings.HasPrefix(r.Path, pathPolicies) && !strings.Contains(r.Query, "labelSelector=app.kubernetes.io%2Fmanaged-by%3Dkonstapel") {
			t.Fatalf("engine policies listed without the management label: %+v", r)
		}
	}
	if !continued {
		t.Fatal("no continuation request was sent")
	}
	assertReadOnly(t, f.recorded())

	// Limitations are explicit. Nothing is revoked, so there is no
	// revocation limitation and no revocation record.
	var codes []ObserveCode
	for _, l := range s.Limitations {
		codes = append(codes, l.Code)
	}
	if !slices.Equal(codes, []ObserveCode{LimitSourcesNotSelected, LimitNoAtomicSnapshot}) {
		t.Fatalf("limitations: %v", codes)
	}
	if s.Exceptions[0].Revoked || s.Exceptions[0].Revocation != nil || len(s.RevocationRecords) != 0 {
		t.Fatalf("revocation of an unrevoked exception: %+v %+v", s.Exceptions[0], s.RevocationRecords)
	}

	// No free text, actor or credential material is kept.
	raw, _ := json.Marshal(s)
	for _, leak := range []string{secretReason, actorName, "team-a"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("snapshot JSON carries %q", leak)
		}
	}

	// A proposal touching one binding keeps every other consumer of the
	// shared profile from the observed state.
	proposed := mustSet(t, strings.Replace(bindingYAML("b-prod", "shared", "Audit"), "namespaceSelector: {}", "namespaceSelector: {matchLabels: {env: production}}", 1))
	c, err := BuildCandidate(s.Live, proposed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := dispositions(c); got != "ComplianceBinding/b-dev=unchanged ComplianceBinding/b-prod=replaced ComplianceProfile/shared=unchanged" {
		t.Fatalf("candidate: %s", got)
	}
}

func TestObserveIsDeterministic(t *testing.T) {
	a, err := observe(t, baseline(t), nil)
	mustComplete(t, a, err)
	b, err := observe(t, baseline(t), nil)
	mustComplete(t, b, err)
	// Only the test servers' ports differ.
	a.Server, b.Server = "", ""
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	// Collection resourceVersions come from the store's write order, which
	// the fixture fixes; everything else is sorted.
	if string(ja) != string(jb) {
		t.Fatalf("observations differ:\n%s\n%s", ja, jb)
	}
}

// 2.2: a relevant change between capture and recheck forces a recapture; the
// final snapshot is the stable state.
func TestObserveRecapturesAfterRelevantChange(t *testing.T) {
	f := baseline(t)
	f.onCapture = func(n int) {
		if n == 2 {
			f.mutate(pathBindings, "b-dev", func(m map[string]any) {
				m["spec"].(map[string]any)["mode"] = "Deny"
				m["metadata"].(map[string]any)["generation"] = int64(2)
			})
		}
	}
	s, err := observe(t, f, nil)
	mustComplete(t, s, err)
	if s.Captures != 3 || len(s.Drift) != 1 || s.Drift[0].Reason != "drift" || !slices.Equal(s.Drift[0].Changed, []string{"compliance.erenius.io/v1alpha1/compliancebindings /b-dev"}) {
		t.Fatalf("captures=%d drift=%+v", s.Captures, s.Drift)
	}
	if s.Live.Bindings[0].Name != "b-dev" || s.Live.Bindings[0].Spec.Mode != v1alpha1.ModeDeny {
		t.Fatalf("the final snapshot is not the stable state: %+v", s.Live.Bindings[0].Spec)
	}
}

// Every relevant projection triggers a recapture: membership, applied
// policy, acceptance, cluster identity and source/trust configuration.
func TestObserveDetectsEachRelevantProjection(t *testing.T) {
	for name, change := range map[string]func(f *fakeAPI){
		"namespace labels": func(f *fakeAPI) {
			f.mutate(pathNamespaces, "staging", func(m map[string]any) { m["metadata"].(map[string]any)["labels"] = map[string]any{"env": "production"} })
		},
		"namespace recreated": func(f *fakeAPI) {
			f.mutate(pathNamespaces, "prod", func(m map[string]any) { m["metadata"].(map[string]any)["uid"] = "prod-uid-2" })
		},
		"new namespace": func(f *fakeAPI) { f.put(pathNamespaces, namespace("new", "new-uid", nil)) },
		"profile spec": func(f *fakeAPI) {
			f.mutate(pathProfiles, "shared", func(m map[string]any) {
				m["spec"].(map[string]any)["bundle"].(map[string]any)["digest"] = digestB
			})
		},
		"binding epoch": func(f *fakeAPI) {
			f.mutate(pathBindings, "b-prod", func(m map[string]any) { m["spec"].(map[string]any)["enforcementEpoch"] = int64(2) })
		},
		"binding removed": func(f *fakeAPI) { f.remove(pathBindings, "b-dev") },
		"policy readiness": func(f *fakeAPI) {
			name := targeting.PolicyName(contribution("b-prod", "uid-b-prod", v1alpha1.ModeDeny, "production"))
			f.mutate(pathPolicies, name, func(m map[string]any) {
				m["status"].(map[string]any)["conditionStatus"].(map[string]any)["conditions"].([]any)[1].(map[string]any)["status"] = "False"
			})
		},
		"policy delivered": func(f *fakeAPI) {
			f.put(pathPolicies, enginePolicy(contribution("b-dev", "uid-b-dev", v1alpha1.ModeAudit, "development"), "uid-b-dev", true))
		},
		"acceptance renewed": func(f *fakeAPI) {
			f.mutate(pathExceptions, "allow-debug", func(m map[string]any) { m["spec"].(map[string]any)["acceptanceRevision"] = int64(2) })
		},
		"snapshot written": func(f *fakeAPI) { f.putException(f.t, "allow-other", "dev", "dev-uid", "uid-ex-2") },
		"acceptance record": func(f *fakeAPI) {
			f.mutate(pathExceptions, "allow-debug", func(m map[string]any) {
				ann := m["metadata"].(map[string]any)["annotations"].(map[string]any)
				ann[exception.AcceptanceAnnotation] = strings.Replace(ann[exception.AcceptanceAnnotation].(string), "team-a", "team-b", 1)
			})
		},
		"snapshot reference": func(f *fakeAPI) {
			f.mutate(pathExceptions, "allow-debug", func(m map[string]any) {
				m["status"].(map[string]any)["acceptance"].(map[string]any)["digest"] = digestB
			})
		},
		"snapshot content": func(f *fakeAPI) {
			f.mu.Lock()
			name := f.colls[pathExceptions]["allow-debug"]["status"].(map[string]any)["acceptance"].(map[string]any)["snapshot"].(string)
			f.mu.Unlock()
			f.mutate(pathConfigMaps(ctrlNS), name, func(m map[string]any) {
				for k := range m["data"].(map[string]any) {
					m["data"].(map[string]any)[k] = "tampered"
				}
			})
		},
		"cluster identity": func(f *fakeAPI) {
			f.mutate(pathNamespaces, "kube-system", func(m map[string]any) { m["metadata"].(map[string]any)["uid"] = "other-cluster" })
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := baseline(t)
			f.onCapture = func(n int) {
				if n == 2 {
					change(f)
				}
			}
			s, err := observe(t, f, nil)
			mustComplete(t, s, err)
			if s.Captures != 3 || len(s.Drift) != 1 || len(s.Drift[0].Changed) == 0 {
				t.Fatalf("captures=%d drift=%+v", s.Captures, s.Drift)
			}
		})
	}
}

// Status churn that does not change a relevant projection (report
// timestamps, Kyverno condition times, annotations) never forces a retry.
func TestObserveIgnoresIrrelevantChurn(t *testing.T) {
	f := baseline(t)
	pol := targeting.PolicyName(contribution("b-prod", "uid-b-prod", v1alpha1.ModeDeny, "production"))
	f.onCapture = func(n int) {
		stamp := fixedNow.Add(time.Duration(n) * time.Minute).Format(time.RFC3339)
		f.mutate(pathBindings, "b-prod", func(m map[string]any) {
			m["status"] = map[string]any{"assessment": map[string]any{"lastEvaluatedAt": stamp}, "conditions": []any{map[string]any{"type": "EngineReady", "lastTransitionTime": stamp}}}
		})
		f.mutate(pathPolicies, pol, func(m map[string]any) {
			m["status"].(map[string]any)["conditionStatus"].(map[string]any)["conditions"].([]any)[0].(map[string]any)["lastTransitionTime"] = stamp
			m["metadata"].(map[string]any)["annotations"].(map[string]any)["kyverno.io/unrelated"] = stamp
			m["metadata"].(map[string]any)["annotations"].(map[string]any)[targeting.AnnotationReadinessRecheck] = fmt.Sprintf("%d@%s", n+1, stamp)
		})
		f.mutate(pathNamespaces, "prod", func(m map[string]any) {
			m["metadata"].(map[string]any)["annotations"] = map[string]any{"touched": stamp}
		})
		f.mutate(pathExceptions, "allow-debug", func(m map[string]any) {
			m["status"].(map[string]any)["conditions"] = []any{map[string]any{"type": "Active", "lastTransitionTime": stamp}}
		})
	}
	s, err := observe(t, f, nil)
	mustComplete(t, s, err)
	if s.Captures != 2 || len(s.Drift) != 0 {
		t.Fatalf("irrelevant churn forced recapture: captures=%d drift=%+v", s.Captures, s.Drift)
	}
	// The observed revisions are those of the final capture.
	f.mu.Lock()
	want := f.colls[pathBindings]["b-prod"]["metadata"].(map[string]any)["resourceVersion"]
	f.mu.Unlock()
	for _, o := range s.Objects {
		if o.Name == "b-prod" && o.ResourceVersion != want {
			t.Fatalf("resourceVersion %s, want the final capture's %s", o.ResourceVersion, want)
		}
	}
}

// 2.2/2.3: drift that persists through two recaptures is incomplete, never a
// result assembled from incompatible states.
func TestObserveIncompleteWhenDriftPersists(t *testing.T) {
	f := baseline(t)
	f.onCapture = func(n int) {
		if n >= 2 {
			f.mutate(pathNamespaces, "staging", func(m map[string]any) {
				m["metadata"].(map[string]any)["labels"] = map[string]any{"env": "staging", "n": string(rune('a' + n))}
			})
		}
	}
	s, err := observe(t, f, nil)
	mustIncomplete(t, s, err, ObserveUnstable)
	if s.Captures != 4 || len(s.Drift) != 3 || !strings.Contains(s.Errors[0].Message, "/v1/namespaces /staging") {
		t.Fatalf("captures=%d drift=%+v errors=%+v", s.Captures, s.Drift, s.Errors)
	}
}

// 2.3: an expired continuation restarts the whole capture as a recapture; if
// it keeps expiring the snapshot is incomplete, never truncated.
func TestObserveExpiredPagination(t *testing.T) {
	t.Run("recovered", func(t *testing.T) {
		f := baseline(t)
		f.expire = func(string) bool { return f.captures == 1 }
		s, err := observe(t, f, nil)
		mustComplete(t, s, err)
		if s.Captures != 3 || len(s.Drift) != 1 || s.Drift[0].Reason != "pagination-expired" || len(s.Namespaces) != 5 {
			t.Fatalf("captures=%d drift=%+v namespaces=%d", s.Captures, s.Drift, len(s.Namespaces))
		}
	})
	t.Run("persistent", func(t *testing.T) {
		f := baseline(t)
		f.expire = func(string) bool { return true }
		s, err := observe(t, f, nil)
		mustIncomplete(t, s, err, ObservePaginationExpired)
		if s.Captures != 3 {
			t.Fatalf("captures=%d, want the first plus two recaptures", s.Captures)
		}
	})
}

func status(code int, reason metav1.StatusReason) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) { writeStatus(w, code, reason, "injected") }
}

// 2.3: denied or missing required APIs, and invalid contracts, are
// incomplete. None of them is read as an empty set.
func TestObserveRequiredInputsFailClosed(t *testing.T) {
	forbidden := status(http.StatusForbidden, metav1.StatusReasonForbidden)
	cases := []struct {
		name  string
		path  string // exact request path to answer with respond
		resp  func(http.ResponseWriter)
		setup func(*fakeAPI)
		want  ObserveCode
	}{
		{name: "engine policies denied", path: pathPolicies, resp: forbidden, want: ObserveAccessDenied},
		{name: "exceptions denied", path: pathExceptions, resp: forbidden, want: ObserveAccessDenied},
		{name: "namespaces denied", path: pathNamespaces, resp: forbidden, want: ObserveAccessDenied},
		{name: "cluster identity denied", path: pathNamespaces + "/kube-system", resp: forbidden, want: ObserveAccessDenied},
		{name: "snapshots denied", path: pathConfigMaps(ctrlNS), resp: forbidden, want: ObserveAccessDenied},
		{name: "bindings unauthorized", path: pathBindings, resp: status(http.StatusUnauthorized, metav1.StatusReasonUnauthorized), want: ObserveUnauthorized},
		{name: "profiles list not found", path: pathProfiles, resp: status(http.StatusNotFound, metav1.StatusReasonNotFound), want: ObserveAPIUnavailable},
		{name: "server error", path: pathBindings, resp: status(http.StatusInternalServerError, metav1.StatusReasonInternalError), want: ObserveRequestFailed},
		{name: "discovery denied", path: "/apis/compliance.erenius.io/v1alpha1", resp: forbidden, want: ObserveAccessDenied},
		{name: "kyverno API not served", setup: func(f *fakeAPI) { delete(f.served, "/apis/policies.kyverno.io/v1") }, want: ObserveAPIUnavailable},
		{name: "exception API not served", setup: func(f *fakeAPI) {
			f.served["/apis/compliance.erenius.io/v1alpha1"] = slices.DeleteFunc(f.served["/apis/compliance.erenius.io/v1alpha1"], func(r metav1.APIResource) bool { return r.Name == "complianceexceptions" })
		}, want: ObserveAPIUnavailable},
		{name: "list verb not served", setup: func(f *fakeAPI) {
			f.served["/apis/policies.kyverno.io/v1"] = []metav1.APIResource{{Name: "validatingpolicies", Verbs: []string{"get"}}}
		}, want: ObserveAPIUnavailable},
		{name: "no cluster identity", setup: func(f *fakeAPI) { f.remove(pathNamespaces, "kube-system") }, want: ObserveNotFound},
		{name: "unknown binding field", setup: func(f *fakeAPI) {
			f.mutate(pathBindings, "b-dev", func(m map[string]any) { m["spec"].(map[string]any)["futureField"] = true })
		}, want: ObserveInvalidObject},
		{name: "duplicate list item", path: pathProfiles, resp: func(w http.ResponseWriter) {
			item := map[string]any{"apiVersion": "compliance.erenius.io/v1alpha1", "kind": "ComplianceProfile", "metadata": map[string]any{"name": "x", "uid": "u", "resourceVersion": "1"},
				"spec": map[string]any{"bundle": map[string]any{"name": "b", "digest": digestA}, "policies": []any{map[string]any{"name": "p"}}}}
			writeJSON(w, map[string]any{"apiVersion": "v1", "kind": "List", "metadata": map[string]any{"resourceVersion": "1"}, "items": []any{item, item}})
		}, want: ObserveInvalidObject},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := baseline(t)
			if tc.setup != nil {
				tc.setup(f)
			}
			if tc.resp != nil {
				f.hook = func(w http.ResponseWriter, r *http.Request) bool {
					if r.URL.Path == tc.path {
						tc.resp(w)
						return true
					}
					return false
				}
			}
			s, err := observe(t, f, nil)
			mustIncomplete(t, s, err, tc.want)
			assertReadOnly(t, f.recorded())
		})
	}
}

// 2.3: object, page and byte limits are errors, never truncation.
func TestObserveLimitsAreIncomplete(t *testing.T) {
	for name, tc := range map[string]struct {
		lim  ObserveLimits
		want ObserveCode
	}{
		"objects": {ObserveLimits{MaxObjects: 5, PageSize: 2}, ObserveObjectLimit},
		"pages":   {ObserveLimits{MaxPages: 3, PageSize: 2}, ObservePageLimit},
		"bytes":   {ObserveLimits{MaxResponseBytes: 2048, PageSize: 2}, ObserveByteLimit},
	} {
		t.Run(name, func(t *testing.T) {
			f := baseline(t)
			s, err := observe(t, f, func(o *ObserveOptions) { o.Limits = tc.lim })
			mustIncomplete(t, s, err, tc.want)
		})
	}
	// The design limits, and the recapture ceiling, are fixed.
	d := DefaultObserveLimits()
	if d.Timeout != 60*time.Second || d.MaxRecaptures != 2 || d.MaxObjects != 100_000 {
		t.Fatalf("default limits: %+v", d)
	}
	if s, err := Observe(context.Background(), ObserveOptions{Config: baseline(t).config(), Namespace: ctrlNS, Limits: ObserveLimits{MaxRecaptures: 3}}); err == nil || s != nil {
		t.Fatal("more than two recaptures accepted")
	}
	for _, o := range []ObserveOptions{{Namespace: ctrlNS}, {Config: newFakeAPI(t).config()}} {
		if s, err := Observe(context.Background(), o); err == nil || s != nil {
			t.Fatalf("invalid options accepted: %+v", o)
		}
	}
	// The manifest input bound remains the design's 16 MiB.
	if DefaultLimits().MaxInputBytes != 16<<20 {
		t.Fatal("input limit changed")
	}
}

// 2.3: the total timeout and caller cancellation stop the observation.
func TestObserveTimeoutAndCancellation(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		f := baseline(t)
		f.hook = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == pathExceptions {
				<-r.Context().Done()
				return true
			}
			return false
		}
		start := time.Now()
		s, err := observe(t, f, func(o *ObserveOptions) { o.Limits.Timeout = 300 * time.Millisecond })
		mustIncomplete(t, s, err, ObserveTimeout)
		if time.Since(start) > 10*time.Second {
			t.Fatalf("timeout not enforced: %v", time.Since(start))
		}
	})
	t.Run("canceled", func(t *testing.T) {
		f := baseline(t)
		ctx, cancel := context.WithCancel(context.Background())
		f.hook = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == pathBindings {
				cancel()
				<-r.Context().Done()
				return true
			}
			return false
		}
		s, err := Observe(ctx, ObserveOptions{Config: f.config(), Namespace: ctrlNS, Now: clock()})
		mustIncomplete(t, s, err, ObserveCanceled)
	})
	t.Run("timeout across recaptures", func(t *testing.T) {
		f := baseline(t)
		f.onCapture = func(n int) {
			time.Sleep(150 * time.Millisecond)
			f.mutate(pathNamespaces, "staging", func(m map[string]any) {
				m["metadata"].(map[string]any)["labels"] = map[string]any{"n": string(rune('a' + n))}
			})
		}
		s, err := observe(t, f, func(o *ObserveOptions) { o.Limits.Timeout = 400 * time.Millisecond })
		mustIncomplete(t, s, err, ObserveTimeout)
	})
}

// Source and trust projections: the named ConfigMap, the trust ConfigMaps it
// references and, by name and with the caller's identity, the Secrets it
// references (4.3, 2.5). Nothing else is requested, and no Secret value
// reaches the snapshot's serialized or formatted forms.
func TestObserveSourcesAndTrust(t *testing.T) {
	sourcesDoc := `version: 1
sources:
  - name: org-bundle
    repository: registry.example.com/org/bundle
    credentialSecret: {name: registry-pull}
    ca: {kind: ConfigMap, name: registry-ca}
    publisher:
      type: keyless
      issuer: https://issuer.example.com
      identity: https://example.com/ci
      trustRoot: {kind: Secret, name: sigstore-root}
      provenance:
        sourceRepository: https://example.com/org/bundle
        builder: https://example.com/builder
`
	const pullValue, rootValue = "PULL-SECRET-VALUE-MUST-NOT-LEAK", "ROOT-SECRET-VALUE-MUST-NOT-LEAK"
	setup := func(t *testing.T) *fakeAPI {
		f := baseline(t)
		f.put(pathConfigMaps(ctrlNS), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "konstapel-bundle-sources"}, Data: map[string]string{"sources.yaml": sourcesDoc}})
		f.put(pathConfigMaps(ctrlNS), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "registry-ca"}, Data: map[string]string{"ca.crt": "CA-1"}})
		f.put(pathSecrets(ctrlNS), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "registry-pull"}, Type: corev1.SecretTypeDockerConfigJson,
			Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte(pullValue)}})
		f.put(pathSecrets(ctrlNS), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "sigstore-root"},
			Data: map[string][]byte{"trusted_root.json": []byte(rootValue), "unreferenced": []byte("x")}})
		f.put(pathSecrets(ctrlNS), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "unrelated"}, Data: map[string][]byte{"k": []byte("v")}})
		return f
	}
	withSources := func(o *ObserveOptions) { o.SourcesConfigMap = "konstapel-bundle-sources" }
	referenced := []string{"registry-pull", "sigstore-root"}

	f := setup(t)
	s, err := observe(t, f, withSources)
	mustComplete(t, s, err)
	src := s.Sources
	if src == nil || src.Missing || src.ParseError != "" || len(src.Sources) != 1 || src.Sources[0].Repository != "registry.example.com/org/bundle" ||
		len(src.TrustConfigMaps) != 1 || src.TrustConfigMaps[0].Name != "registry-ca" || src.TrustConfigMaps[0].Digest == "" ||
		len(src.UnreadSecrets) != 0 || len(src.Secrets) != 2 {
		t.Fatalf("sources: %+v", src)
	}
	for i, want := range []struct{ name, key string }{{"registry-pull", corev1.DockerConfigJsonKey}, {"sigstore-root", "trusted_root.json"}} {
		got := src.Secrets[i]
		if got.Name != want.name || got.Access != SecretRead || got.UID != types.UID("uid-"+want.name) || got.ResourceVersion == "" || !slices.Equal(got.Keys, []string{want.key}) {
			t.Fatalf("secret %d: %+v", i, got)
		}
	}
	if slices.ContainsFunc(s.Limitations, func(d Diagnostic) bool { return d.Code == LimitSecretNotRead }) {
		t.Fatalf("limitations: %+v", s.Limitations)
	}
	assertSecretReads(t, f.recorded(), referenced...)
	assertNoSecretValues(t, s, pullValue, rootValue)
	// The values are held for the content adapter, referenced keys only.
	if o := s.inputs.objects["Secret/sigstore-root"]; o == nil || string(o.data["trusted_root.json"]) != rootValue || len(o.data) != 1 {
		t.Fatal("the referenced Secret value is not held for the content adapter")
	}

	t.Run("secret change is drift", func(t *testing.T) {
		f := setup(t)
		f.onCapture = func(n int) {
			if n == 2 {
				f.mutate(pathSecrets(ctrlNS), "sigstore-root", func(m map[string]any) {
					m["data"].(map[string]any)["trusted_root.json"] = base64.StdEncoding.EncodeToString([]byte("ROTATED"))
				})
			}
		}
		s, err := observe(t, f, withSources)
		mustComplete(t, s, err)
		if s.Captures != 3 || len(s.Drift) != 1 || !slices.Equal(s.Drift[0].Changed, []string{"/v1/secrets " + ctrlNS + "/sigstore-root"}) {
			t.Fatalf("drift: %+v", s.Drift)
		}
		if string(s.inputs.objects["Secret/sigstore-root"].data["trusted_root.json"]) != "ROTATED" {
			t.Fatal("the recaptured value is not the one held")
		}
		assertNoSecretValues(t, s, "ROTATED")
	})
	t.Run("secret changing on every capture is incomplete", func(t *testing.T) {
		f := setup(t)
		f.onCapture = func(n int) {
			f.mutate(pathSecrets(ctrlNS), "registry-pull", func(m map[string]any) {
				m["type"] = []string{string(corev1.SecretTypeDockerConfigJson), string(corev1.SecretTypeOpaque)}[n%2]
			})
		}
		s, err := observe(t, f, withSources)
		mustIncomplete(t, s, err, ObserveUnstable)
		if s.inputs != nil {
			t.Fatal("an incomplete snapshot holds Secret values")
		}
	})
	t.Run("unreferenced secret data and metadata are not drift", func(t *testing.T) {
		f := setup(t)
		f.onCapture = func(n int) {
			if n == 2 {
				f.mutate(pathSecrets(ctrlNS), "sigstore-root", func(m map[string]any) {
					m["data"].(map[string]any)["unreferenced"] = base64.StdEncoding.EncodeToString([]byte("y"))
					m["metadata"].(map[string]any)["labels"] = map[string]any{"rotated": "yes"}
				})
			}
		}
		s, err := observe(t, f, withSources)
		mustComplete(t, s, err)
		if s.Captures != 2 || len(s.Drift) != 0 {
			t.Fatalf("drift: %+v", s.Drift)
		}
	})
	t.Run("denied secret is recorded, not read and not incomplete", func(t *testing.T) {
		f := setup(t)
		f.hook = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == pathSecrets(ctrlNS)+"/registry-pull" {
				writeStatus(w, http.StatusForbidden, metav1.StatusReasonForbidden, `secrets "registry-pull" is forbidden: User "reader" cannot get resource "secrets"`)
				return true
			}
			return false
		}
		s, err := observe(t, f, withSources)
		mustComplete(t, s, err)
		if !slices.Equal(s.Sources.UnreadSecrets, []string{"registry-pull"}) || s.Sources.Secrets[0].Access != SecretDenied || s.Sources.Secrets[0].UID != "" ||
			s.Sources.Secrets[1].Access != SecretRead {
			t.Fatalf("sources: %+v", s.Sources)
		}
		i := slices.IndexFunc(s.Limitations, func(d Diagnostic) bool { return d.Code == LimitSecretNotRead })
		if i < 0 || s.Limitations[i].Name != "registry-pull" || strings.Contains(s.Limitations[i].Message, "forbidden: User") {
			t.Fatalf("limitations: %+v", s.Limitations)
		}
		assertSecretReads(t, f.recorded(), referenced...)
	})
	t.Run("missing secret", func(t *testing.T) {
		f := setup(t)
		f.remove(pathSecrets(ctrlNS), "sigstore-root")
		s, err := observe(t, f, withSources)
		mustComplete(t, s, err)
		if s.Sources.Secrets[1].Access != SecretMissing || len(s.Sources.UnreadSecrets) != 0 {
			t.Fatalf("sources: %+v", s.Sources)
		}
	})
	t.Run("a failed secret read is incomplete without echoing the response", func(t *testing.T) {
		f := setup(t)
		f.hook = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == pathSecrets(ctrlNS)+"/sigstore-root" {
				writeStatus(w, http.StatusInternalServerError, metav1.StatusReasonInternalError, "ECHOED-"+rootValue)
				return true
			}
			return false
		}
		s, err := observe(t, f, withSources)
		mustIncomplete(t, s, err, ObserveRequestFailed)
		if strings.Contains(err.Error(), rootValue) || strings.Contains(s.Errors[0].Message, "ECHOED") {
			t.Fatalf("error echoes the response: %v", err)
		}
	})
	t.Run("trust change is drift", func(t *testing.T) {
		f := setup(t)
		f.onCapture = func(n int) {
			if n == 2 {
				f.mutate(pathConfigMaps(ctrlNS), "registry-ca", func(m map[string]any) { m["data"] = map[string]any{"ca.crt": "CA-2"} })
			}
		}
		s, err := observe(t, f, withSources)
		mustComplete(t, s, err)
		if s.Captures != 3 || len(s.Drift) != 1 || !strings.Contains(s.Drift[0].Changed[0], "#trust/registry-ca") {
			t.Fatalf("drift: %+v", s.Drift)
		}
	})
	t.Run("source change is drift", func(t *testing.T) {
		f := setup(t)
		f.onCapture = func(n int) {
			if n == 2 {
				f.mutate(pathConfigMaps(ctrlNS), "konstapel-bundle-sources", func(m map[string]any) {
					m["data"] = map[string]any{"sources.yaml": strings.Replace(sourcesDoc, "org/bundle\n", "org/other\n", 1)}
				})
			}
		}
		s, err := observe(t, f, withSources)
		mustComplete(t, s, err)
		if s.Captures != 3 || len(s.Drift) != 1 || !slices.ContainsFunc(s.Drift[0].Changed, func(c string) bool { return strings.Contains(c, "konstapel-bundle-sources") }) {
			t.Fatalf("drift: %+v", s.Drift)
		}
	})
	t.Run("missing sources", func(t *testing.T) {
		f := baseline(t)
		s, err := observe(t, f, withSources)
		mustComplete(t, s, err)
		if s.Sources == nil || !s.Sources.Missing || !slices.ContainsFunc(s.Limitations, func(d Diagnostic) bool { return d.Code == LimitSourcesUnusable }) {
			t.Fatalf("missing sources: %+v %+v", s.Sources, s.Limitations)
		}
	})
	t.Run("sources denied", func(t *testing.T) {
		f := setup(t)
		f.hook = func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == pathConfigMaps(ctrlNS)+"/registry-ca" {
				writeStatus(w, http.StatusForbidden, metav1.StatusReasonForbidden, "denied")
				return true
			}
			return false
		}
		s, err := observe(t, f, withSources)
		mustIncomplete(t, s, err, ObserveAccessDenied)
	})
}

// 2.4: the transport refuses writes, dry-run, watches and Secrets before they
// are sent, and the observation itself sends none of them.
func TestReadOnlyTransportRefusesBeforeSending(t *testing.T) {
	var sent []string
	inner := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sent = append(sent, r.Method+" "+r.URL.String())
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})
	tr := readOnlyTransport{next: inner, namespace: "konstapel-system"}
	for _, c := range []struct{ method, url string }{
		{http.MethodPost, "https://api/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"},
		{http.MethodPut, "https://api/apis/compliance.erenius.io/v1alpha1/compliancebindings/b"},
		{http.MethodPatch, "https://api/apis/compliance.erenius.io/v1alpha1/compliancebindings/b"},
		{http.MethodDelete, "https://api/apis/policies.kyverno.io/v1/validatingpolicies/p"},
		{http.MethodPost, "https://api/apis/compliance.erenius.io/v1alpha1/compliancebindings?dryRun=All"},
		{http.MethodGet, "https://api/apis/compliance.erenius.io/v1alpha1/compliancebindings?dryRun=All"},
		{http.MethodGet, "https://api/apis/compliance.erenius.io/v1alpha1/compliancebindings?watch=true"},
		{http.MethodGet, "https://api/api/v1/secrets"},
		{http.MethodGet, "https://api/api/v1/namespaces/konstapel-system/secrets/registry-pull"},
		{http.MethodGet, "https://api/api/v1/namespaces/konstapel-system/secrets"},
	} {
		req, _ := http.NewRequest(c.method, c.url, nil)
		var refused *refusedError
		if _, err := tr.RoundTrip(req); !errors.As(err, &refused) {
			t.Fatalf("%s %s was not refused: %v", c.method, c.url, err)
		}
	}
	if len(sent) != 0 {
		t.Fatalf("refused requests were sent: %v", sent)
	}
	for _, u := range []string{"https://api/api/v1/namespaces/secrets", "https://api/api/v1/namespaces/secrets/configmaps", "https://api/apis/compliance.erenius.io/v1alpha1/compliancebindings?watch=false"} {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		if _, err := tr.RoundTrip(req); err != nil {
			t.Fatalf("%s refused: %v", u, err)
		}
	}
	if len(sent) != 3 {
		t.Fatalf("sent %v", sent)
	}
}

// 4.3: a Secret request leaves the process only as a plain GET of one Secret
// that the capture's grant names (the observed sources reference it) in the
// controller namespace. Unreferenced names, lists, watches, writes,
// subresources, queries and other namespaces are refused before sending.
func TestReadOnlyTransportAllowsOnlyReferencedSecretGets(t *testing.T) {
	var sent []string
	inner := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sent = append(sent, r.Method+" "+r.URL.String())
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	})
	tr := readOnlyTransport{next: inner, namespace: ctrlNS}
	granted := withSecretGrant(context.Background(), ctrlNS, []string{"registry-pull", "signing-key"})
	const base = "https://api/api/v1/namespaces/" + ctrlNS + "/secrets"
	for _, c := range []struct {
		ctx         context.Context
		method, url string
	}{
		{context.Background(), http.MethodGet, base + "/registry-pull"}, // no grant
		{granted, http.MethodGet, base + "/unreferenced"},
		{granted, http.MethodGet, base},
		{granted, http.MethodGet, base + "?labelSelector=a%3Db"},
		{granted, http.MethodGet, "https://api/api/v1/secrets"},
		{granted, http.MethodGet, "https://api/api/v1/secrets/registry-pull"},
		{granted, http.MethodGet, base + "?watch=true"},
		{granted, http.MethodGet, base + "/registry-pull?watch=1"},
		{granted, http.MethodGet, "https://api/api/v1/watch/namespaces/" + ctrlNS + "/secrets/registry-pull"},
		{granted, http.MethodGet, "https://api/api/v1/watch/secrets"},
		{granted, http.MethodGet, base + "/registry-pull?resourceVersion=0"},
		{granted, http.MethodGet, base + "/registry-pull/"},
		{granted, http.MethodGet, base + "/registry-pull/status"},
		{granted, http.MethodGet, "https://api/api/v1/namespaces/default/secrets/registry-pull"},
		{withSecretGrant(context.Background(), "default", []string{"registry-pull"}), http.MethodGet, "https://api/api/v1/namespaces/default/secrets/registry-pull"},
		{granted, http.MethodPut, base + "/registry-pull"},
		{granted, http.MethodPatch, base + "/registry-pull"},
		{granted, http.MethodDelete, base + "/registry-pull"},
		{granted, http.MethodPost, base},
		{granted, http.MethodGet, base + "/registry-pull?dryRun=All"},
	} {
		req, _ := http.NewRequestWithContext(c.ctx, c.method, c.url, nil)
		var refused *refusedError
		if _, err := tr.RoundTrip(req); !errors.As(err, &refused) {
			t.Fatalf("%s %s was not refused: %v", c.method, c.url, err)
		}
	}
	if len(sent) != 0 {
		t.Fatalf("refused requests were sent: %v", sent)
	}
	for _, name := range []string{"registry-pull", "signing-key"} {
		req, _ := http.NewRequestWithContext(granted, http.MethodGet, base+"/"+name, nil)
		if _, err := tr.RoundTrip(req); err != nil {
			t.Fatalf("referenced Secret %s refused: %v", name, err)
		}
	}
	// Without a controller namespace no Secret can be read at all.
	req, _ := http.NewRequestWithContext(granted, http.MethodGet, base+"/registry-pull", nil)
	if _, err := (readOnlyTransport{next: inner}).RoundTrip(req); err == nil {
		t.Fatal("a Secret was read without a controller namespace")
	}
	if len(sent) != 2 {
		t.Fatalf("sent %v", sent)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type access struct{ verb, group, resource, namespace string }

// requestAccess maps a recorded request to the RBAC access it needs; it
// returns false for discovery, which system:discovery grants.
func requestAccess(t *testing.T, r recorded) (access, bool) {
	segs := strings.Split(strings.Trim(r.Path, "/"), "/")
	var group string
	var rest []string
	switch {
	case segs[0] == "api" && len(segs) >= 2:
		rest = segs[2:]
	case segs[0] == "apis" && len(segs) >= 3:
		group, rest = segs[1], segs[3:]
	default:
		t.Fatalf("unexpected request %+v", r)
	}
	if len(rest) == 0 {
		return access{}, false
	}
	a := access{group: group}
	if rest[0] == "namespaces" && len(rest) >= 3 {
		a.namespace, rest = rest[1], rest[2:]
	}
	a.resource, a.verb = rest[0], "list"
	if len(rest) == 2 {
		a.verb = "get"
	}
	return a, true
}

func loadReaderRBAC(t *testing.T) (*rbacv1.ClusterRole, *rbacv1.Role, *rbacv1.Role) {
	t.Helper()
	raw, err := os.ReadFile("../../docs/examples/policy-preview/reader-rbac.yaml")
	if err != nil {
		t.Fatal(err)
	}
	docs := strings.Split(string(raw), "\n---\n")
	if len(docs) != 3 {
		t.Fatalf("want a ClusterRole and two Roles, got %d documents", len(docs))
	}
	cr, r, sr := &rbacv1.ClusterRole{}, &rbacv1.Role{}, &rbacv1.Role{}
	if err := yaml.UnmarshalStrict([]byte(docs[0]), cr); err != nil || cr.Kind != "ClusterRole" {
		t.Fatalf("cluster role: %v %s", err, cr.Kind)
	}
	for _, role := range []struct {
		doc string
		r   *rbacv1.Role
	}{{docs[1], r}, {docs[2], sr}} {
		if err := yaml.UnmarshalStrict([]byte(role.doc), role.r); err != nil || role.r.Kind != "Role" || role.r.Namespace != ctrlNS {
			t.Fatalf("role: %v %s %s", err, role.r.Kind, role.r.Namespace)
		}
	}
	return cr, r, sr
}

func allows(rules []rbacv1.PolicyRule, a access, name string) bool {
	for _, rule := range rules {
		if slices.Contains(rule.APIGroups, a.group) && slices.Contains(rule.Resources, a.resource) && slices.Contains(rule.Verbs, a.verb) &&
			(len(rule.ResourceNames) == 0 || slices.Contains(rule.ResourceNames, name)) {
			return true
		}
	}
	return false
}

// 2.4 and 4.3: the documented permission matrix is exactly what the
// observation uses: get and list only, Secrets only as a get of the named
// references, and every recorded request is allowed.
func TestDocumentedReaderRBACMatchesRecordedRequests(t *testing.T) {
	cr, role, secrets := loadReaderRBAC(t)
	for _, rule := range append(append(slices.Clone(cr.Rules), role.Rules...), secrets.Rules...) {
		for _, v := range rule.Verbs {
			if v != "get" && v != "list" {
				t.Fatalf("reader role grants %q: %+v", v, rule)
			}
		}
		if slices.Contains(rule.Resources, "*") || slices.Contains(rule.APIGroups, "*") {
			t.Fatalf("reader role is broader than documented: %+v", rule)
		}
	}
	for _, rule := range append(slices.Clone(cr.Rules), role.Rules...) {
		if slices.Contains(rule.Resources, "secrets") || len(rule.ResourceNames) > 0 {
			t.Fatalf("reader role is broader than documented: %+v", rule)
		}
	}
	if !slices.Equal(role.Rules[0].Resources, []string{"configmaps"}) || len(role.Rules) != 1 {
		t.Fatalf("namespace role: %+v", role.Rules)
	}
	if len(secrets.Rules) != 1 || !slices.Equal(secrets.Rules[0].Resources, []string{"secrets"}) || !slices.Equal(secrets.Rules[0].Verbs, []string{"get"}) ||
		!slices.Equal(secrets.Rules[0].ResourceNames, []string{"acme-registry", "acme-bundle-signing-key"}) {
		t.Fatalf("secret role must be get on named Secrets only: %+v", secrets.Rules)
	}

	// Run the widest observation (sources, trust ConfigMaps and the
	// documented private-source Secrets) and check each request.
	f := baseline(t)
	f.put(pathConfigMaps(ctrlNS), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "konstapel-bundle-sources"}, Data: map[string]string{"sources.yaml": "version: 1\nsources:\n  - name: org\n    repository: registry.example.com/org\n    credentialSecret: {name: acme-registry}\n    ca: {kind: ConfigMap, name: registry-ca}\n    publisher: {type: public-key, publicKey: {kind: Secret, name: acme-bundle-signing-key, key: cosign.pub}, keyFingerprint: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef, provenance: {sourceRepository: https://e.example.com/r, builder: https://e.example.com/b}}\n"}})
	f.put(pathConfigMaps(ctrlNS), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "registry-ca"}, Data: map[string]string{"ca.crt": "x"}})
	f.put(pathSecrets(ctrlNS), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "acme-registry"}, Type: corev1.SecretTypeDockerConfigJson, Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte("{}")}})
	f.put(pathSecrets(ctrlNS), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "acme-bundle-signing-key"}, Data: map[string][]byte{"cosign.pub": []byte("k")}})
	s, err := observe(t, f, func(o *ObserveOptions) { o.SourcesConfigMap = "konstapel-bundle-sources" })
	mustComplete(t, s, err)
	assertSecretReads(t, f.recorded(), "acme-registry", "acme-bundle-signing-key")
	used := map[access]bool{}
	for _, r := range f.recorded() {
		a, ok := requestAccess(t, r)
		if !ok {
			continue
		}
		used[a] = true
		rules := cr.Rules
		if a.namespace != "" {
			if a.namespace != ctrlNS {
				t.Fatalf("namespaced read outside the controller namespace: %+v", r)
			}
			rules = append(slices.Clone(role.Rules), secrets.Rules...)
		}
		segs := strings.Split(strings.Trim(r.Path, "/"), "/")
		if !allows(rules, a, segs[len(segs)-1]) {
			t.Fatalf("documented RBAC does not allow %+v (request %+v)", a, r)
		}
	}
	// And nothing in the roles is unused.
	for _, rule := range cr.Rules {
		for _, res := range rule.Resources {
			for _, v := range rule.Verbs {
				if !used[access{v, rule.APIGroups[0], res, ""}] {
					t.Errorf("ClusterRole grants unused %s %s", v, res)
				}
			}
		}
	}
	for _, v := range role.Rules[0].Verbs {
		if !used[access{v, "", "configmaps", ctrlNS}] {
			t.Errorf("Role grants unused %s configmaps", v)
		}
	}
	if !used[access{"get", "", "secrets", ctrlNS}] {
		t.Error("the Secret Role is unused")
	}

	// The guide documents the same matrix and links the example.
	doc, err := os.ReadFile("../../docs/policy-preview.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"docs/examples/policy-preview/reader-rbac.yaml", "complianceexceptions", "validatingpolicies", "60 seconds", "100,000", "two recaptures",
		"konstapel-policy-preview-bundle-secrets", "content-access-denied"} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("docs/policy-preview.md does not mention %q", want)
		}
	}
}

func TestRESTConfigUsesOnlyKubeconfig(t *testing.T) {
	dir := t.TempDir()
	kc := filepath.Join(dir, "config")
	if err := os.WriteFile(kc, []byte(`apiVersion: v1
kind: Config
current-context: a
clusters:
- {name: a, cluster: {server: "https://a.example:6443"}}
- {name: b, cluster: {server: "https://b.example:6443"}}
users:
- {name: u, user: {token: t}}
contexts:
- {name: a, context: {cluster: a, user: u}}
- {name: b, context: {cluster: b, user: u}}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, name, err := RESTConfig(kc, "b")
	if err != nil || name != "b" || cfg.Host != "https://b.example:6443" {
		t.Fatalf("named context: %v %s %+v", err, name, cfg)
	}
	if _, name, err := RESTConfig(kc, ""); err != nil || name != "a" {
		t.Fatalf("current context: %v %s", err, name)
	}
	if _, _, err := RESTConfig(kc, "missing"); err == nil {
		t.Fatal("unknown context accepted")
	}
	// No kubeconfig: no fallback to an in-cluster ServiceAccount, even where
	// one would be possible.
	t.Setenv("KUBECONFIG", filepath.Join(dir, "absent"))
	t.Setenv("HOME", dir)
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	if cfg, _, err := RESTConfig("", ""); err == nil {
		t.Fatalf("fell back to %+v", cfg)
	}
	if serverHost("https://user:pass@api.example:6443/path?token=x") != "api.example:6443" {
		t.Fatal("server host keeps credentials")
	}
}
