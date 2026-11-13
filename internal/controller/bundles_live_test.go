//go:build live

package controller

// Bundle acceptance (add-policy-bundle-distribution 8.1). The OpenSpec task
// calls this workflow `bundles:acceptance`; the repository runs it as the
// `bundles` acceptance group (`task acceptance GROUP=bundles`), because
// Taskfile.yml keeps one acceptance task with groups rather than a task per
// feature (AGENTS.md, "Taskfile scope").
//
// The controller runs in-process with OCI bundle sources enabled, against
// the disposable kind cluster and the pinned Kyverno that scripts/acceptance.sh
// creates. Admission is real: Kyverno enforces the delivered policy against a
// server-side dry-run privileged Pod. The packaged controller on the same
// content is TestLiveHelmBundles (charts group).
//
//   - TestLiveBundlesOfficial reads the released official bundle anonymously
//     from ghcr.io under bundles/official-sources.yaml (keyless, Sigstore
//     public-good root): a wrong signer identity is rejected and delivers
//     nothing; the checked-in rule delivers it in Audit (admits) and Deny
//     (rejects). Network to ghcr.io is required; its absence fails the test.
//   - TestLiveBundlesOrganization serves the organization-key fixture from a
//     disposable TLS + htpasswd registry: unsigned, wrong-key, tampered
//     signature and tampered content are rejected, deliver nothing and leave
//     nothing usable in the cache; valid content in Audit and Deny; a warm
//     cache keeps serving through a registry outage; a cold cache during an
//     outage reports ContentUnavailable, delivers nothing new and marks kept
//     policies stale; a revoked credential fails a cold fetch and the rotated
//     one recovers it without a restart; trust revocation and recovery.
// Both verify that every object and container they created is gone.

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const (
	// baOfficialDigest is the first official release of obBundle
	// (docs/policy-bundles.md, "First official release").
	baOfficialDigest  = "sha256:1a2ca25a4856868170fc0059e0e1c8721c6543d9c28c5f07520ba8cdd91f88f8"
	baOfficialSources = "../../bundles/official-sources.yaml"
)

// startBundleManager runs the in-process controller with OCI bundle sources
// read from obSourcesCM in ns and a content cache in cacheDir, as
// cmd/konstapel wires it. The returned stop is idempotent.
func (l *live) startBundleManager(ns, cacheDir string) (stop func()) {
	l.t.Helper()
	ver, err := os.ReadFile("../../VERSION")
	if err != nil {
		l.t.Fatal(err)
	}
	mgr, err := NewManager(l.cfg, Options{Content: content, LocalBundle: content.Name, MetricsAddr: "0", ProbeAddr: "0",
		EnginePoll: 2 * time.Second, SkipControllerNameValidation: true,
		Bundles: stack.Options{SourcesConfigMap: obSourcesCM, Namespace: ns, CacheDir: cacheDir,
			RefreshInterval: 5 * time.Second, ControllerVersion: strings.TrimSpace(string(ver))}})
	if err != nil {
		l.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(l.ctx)
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				l.t.Errorf("manager exited: %v", err)
			}
		})
	}
	l.t.Cleanup(stop)
	return stop
}

// baScenario tracks what one test creates, removes it in reverse, and then
// checks that nothing remains: no bindings, profiles, managed policies,
// namespaces or registry container.
type baScenario struct {
	l          *live
	namespaces []string
	profiles   []string
	bindings   []string
	containers []string
}

func newBAScenario(l *live) *baScenario {
	s := &baScenario{l: l}
	// Registered first, so it runs after every other cleanup.
	l.t.Cleanup(s.verifyClean)
	return s
}

func (s *baScenario) namespace(name string) {
	s.l.setNamespace(name, name)
	s.namespaces = append(s.namespaces, name)
}

func (s *baScenario) profile(name, digest string) *v1alpha1.ComplianceProfile {
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: obBundle, Digest: digest}, Policies: []v1alpha1.ProfilePolicy{{Name: obPolicy}}}}
	if err := s.l.c.Create(s.l.ctx, p); err != nil {
		s.l.t.Fatal(err)
	}
	s.profiles = append(s.profiles, name)
	return p
}

// binding binds profile to the namespace of the same name.
func (s *baScenario) binding(name, profile string, mode v1alpha1.EnforcementMode) *v1alpha1.ComplianceBinding {
	b := bindingObj(name, profile, mode, map[string]v1alpha1.LabelValue{envLabel: v1alpha1.LabelValue(name)})
	b.SetUID("")
	if err := s.l.c.Create(s.l.ctx, b); err != nil {
		s.l.t.Fatal(err)
	}
	s.bindings = append(s.bindings, name)
	return b
}

// remove deletes bindings and profiles and waits until their policies are
// withdrawn (the manager must still run).
func (s *baScenario) remove(bindings, profiles []string) {
	l := s.l
	for _, n := range bindings {
		_ = l.c.Delete(context.Background(), &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: n}})
	}
	for _, n := range profiles {
		_ = l.c.Delete(context.Background(), &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: n}})
	}
	l.eventually("bindings removed and their policies withdrawn", func() (bool, string) {
		var left []string
		for _, n := range bindings {
			if err := l.c.Get(context.Background(), client.ObjectKey{Name: n}, &v1alpha1.ComplianceBinding{}); !apierrors.IsNotFound(err) {
				left = append(left, "binding/"+n)
			}
		}
		for _, n := range profiles {
			if err := l.c.Get(context.Background(), client.ObjectKey{Name: n}, &v1alpha1.ComplianceProfile{}); !apierrors.IsNotFound(err) {
				left = append(left, "profile/"+n)
			}
		}
		left = append(left, l.policiesFor(bindings...)...)
		return len(left) == 0, fmt.Sprint(left)
	})
}

// teardown removes everything while the manager runs; call it from a
// cleanup registered after the manager's.
func (s *baScenario) teardown() {
	for _, n := range s.namespaces {
		_ = s.l.c.Delete(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
	}
	s.remove(s.bindings, s.profiles)
}

func (s *baScenario) verifyClean() {
	l := s.l
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var left []string
	for {
		left = nil
		for _, n := range s.namespaces {
			if err := l.c.Get(ctx, client.ObjectKey{Name: n}, &corev1.Namespace{}); !apierrors.IsNotFound(err) {
				left = append(left, "namespace/"+n)
			}
		}
		for _, n := range s.bindings {
			if err := l.c.Get(ctx, client.ObjectKey{Name: n}, &v1alpha1.ComplianceBinding{}); !apierrors.IsNotFound(err) {
				left = append(left, "binding/"+n)
			}
		}
		for _, n := range s.profiles {
			if err := l.c.Get(ctx, client.ObjectKey{Name: n}, &v1alpha1.ComplianceProfile{}); !apierrors.IsNotFound(err) {
				left = append(left, "profile/"+n)
			}
		}
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(targeting.ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
		_ = l.c.List(ctx, list, client.MatchingLabels{targeting.LabelManagedBy: targeting.ManagedByValue})
		for _, o := range list.Items {
			for _, b := range s.bindings {
				if o.GetAnnotations()[targeting.AnnotationBinding] == b {
					left = append(left, "policy/"+o.GetName())
				}
			}
		}
		for _, c := range s.containers {
			if out, _ := exec.Command("docker", "ps", "-aq", "--filter", "name=^"+c+"$").Output(); len(strings.TrimSpace(string(out))) > 0 {
				left = append(left, "container/"+c)
			}
		}
		if len(left) == 0 || ctx.Err() != nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if len(left) > 0 {
		l.t.Errorf("task-owned resources left after cleanup: %v", left)
		return
	}
	l.record("cleanup", map[string]any{"removed": map[string]any{"namespaces": s.namespaces, "bindings": s.bindings, "profiles": s.profiles, "containers": s.containers}})
}

// baResolvedFalse waits until a binding does not resolve with reason, has
// no managed policies and the privileged probe Pod is admitted in its
// namespace: nothing enforces there.
func (l *live) baNothingDelivered(binding, reason string) {
	l.t.Helper()
	l.eventually(binding+" unresolved", func() (bool, string) {
		b := l.binding(binding)
		c := meta.FindStatusCondition(b.Status.Conditions, v1alpha1.ConditionResolved)
		return c != nil && c.Status == metav1.ConditionFalse && c.Reason == reason && c.ObservedGeneration == b.Generation, toJSON(b.Status)
	})
	if got := l.policiesFor(binding); len(got) != 0 {
		l.t.Fatalf("rejected content delivered for %s: %v", binding, got)
	}
	if denied, msg := l.denied(binding); denied {
		l.t.Fatalf("a privileged Pod was denied in %s although nothing was delivered: %s", binding, msg)
	}
}

// baDelivered checks the binding's single policy is the mode's rendering of
// digest, and that admission in its namespace matches the mode.
func (l *live) baDelivered(binding, digest string, mode v1alpha1.EnforcementMode) string {
	l.t.Helper()
	l.waitReady(binding, 1)
	applied := l.policiesFor(binding)
	if len(applied) != 1 {
		l.t.Fatalf("%s policies %v", binding, applied)
	}
	pol := l.policy(applied[0])
	actions, _, _ := unstructured.NestedStringSlice(pol.Object, "spec", "validationActions")
	if pol.GetAnnotations()[targeting.AnnotationBundleDigest] != digest || pol.GetAnnotations()[targeting.AnnotationBundle] != obBundle ||
		len(actions) != 1 || actions[0] != string(mode) {
		l.t.Fatalf("%s: delivered policy is not the %s rendering of %s: %v %v", binding, mode, digest, pol.GetAnnotations(), actions)
	}
	var msg string
	switch mode {
	case v1alpha1.ModeDeny:
		l.eventually(binding+" denies a privileged Pod", func() (bool, string) {
			var ok bool
			ok, msg = l.denied(binding)
			return ok, "admitted"
		})
	default:
		// Kyverno loads a ready policy promptly; repeated admissions over
		// several seconds must all succeed in Audit.
		for i := 0; i < 5; i++ {
			if denied, m := l.denied(binding); denied {
				l.t.Fatalf("%s is Audit but denied a privileged Pod: %s", binding, m)
			}
			time.Sleep(2 * time.Second)
		}
		msg = "admitted"
	}
	return msg
}

// baProfileResolvedNow asserts the profile is Resolved right now.
func (l *live) baProfileResolvedNow(name string) {
	l.t.Helper()
	if c, p := l.profileResolved(name); c == nil || c.Reason != "Resolved" || c.ObservedGeneration != p.Generation {
		l.t.Fatalf("%s not Resolved: %s", name, toJSON(p.Status))
	}
}

func TestLiveBundlesOfficial(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	s := newBAScenario(l)
	// The official bundle lives on ghcr.io: this group fails, never skips,
	// without network access to it.
	hc := &http.Client{Timeout: 20 * time.Second}
	resp, err := hc.Get("https://ghcr.io/v2/")
	if err != nil {
		t.Fatalf("bundles acceptance needs anonymous HTTPS access to ghcr.io for the official bundle: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusOK {
		t.Fatalf("ghcr.io /v2/ answered %s; the official bundle cannot be read", resp.Status)
	}

	const ns = "konstapel-bundles-official"
	s.namespace(ns)
	raw, err := os.ReadFile(baOfficialSources)
	if err != nil {
		t.Fatal(err)
	}
	var official bundle.Sources
	if err := yaml.UnmarshalStrict(raw, &official); err != nil {
		t.Fatal(err)
	}
	wrong := official
	wrong.Sources = append([]bundle.BundleSource(nil), official.Sources...)
	// Alter the rule of the bundle this test consumes, not whichever is first.
	wi := -1
	for i, src := range wrong.Sources {
		if src.Name == "konstapel-privileged-containers" {
			wi = i
		}
	}
	if wi < 0 {
		t.Fatal("bundles/official-sources.yaml has no konstapel-privileged-containers rule")
	}
	wrong.Sources[wi].Publisher.Identity = strings.Replace(official.Sources[wi].Publisher.Identity, "@refs/heads/main", "@refs/heads/not-main", 1)
	wrongYAML, err := yaml.Marshal(wrong)
	if err != nil {
		t.Fatal(err)
	}
	cm := func(data string) *corev1.ConfigMap {
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: obSourcesCM}, Data: map[string]string{"sources.yaml": data}}
	}
	l.obApply(cm(string(wrongYAML)))
	stop := l.startBundleManager(ns, t.TempDir())
	t.Cleanup(func() { s.teardown(); stop() })

	// 1. Another signer identity than the release workflow's: the real
	// signature does not satisfy the rule; nothing is delivered.
	s.namespace("bo-deny")
	s.namespace("bo-audit")
	p := s.profile("bo-official", baOfficialDigest)
	s.binding("bo-deny", p.Name, v1alpha1.ModeDeny)
	untrusted := l.waitProfile(p.Name, v1alpha1.ReasonContentUnavailable, "(Untrusted)")
	l.baNothingDelivered("bo-deny", v1alpha1.ReasonContentUnavailable)
	l.record("official-wrong-identity", map[string]any{"identity": wrong.Sources[wi].Publisher.Identity, "profile": untrusted, "delivered": "nothing; privileged Pod admitted"})

	// 2. The checked-in official rule, verbatim: delivered in Deny and Audit.
	l.obApply(cm(string(raw)))
	l.waitProfile(p.Name, "Resolved", "")
	denied := l.baDelivered("bo-deny", baOfficialDigest, v1alpha1.ModeDeny)
	s.binding("bo-audit", p.Name, v1alpha1.ModeAudit)
	audit := l.baDelivered("bo-audit", baOfficialDigest, v1alpha1.ModeAudit)
	l.record("official-delivered", map[string]any{"digest": baOfficialDigest, "rule": baOfficialSources,
		"deny": denied, "audit": audit, "policies": l.policiesFor("bo-deny", "bo-audit")})
}

// baPush pushes a subject and proofs (manifest, Sigstore bundle pairs) to
// repoPath with the retrieval adapter's own session.
func baPush(t *testing.T, l *live, r obRegistry, f obFixture, repoPath string, subject, layer []byte, proofs [][2][]byte) {
	t.Helper()
	s := baSession(t, l, r, f, repoPath)
	push := func(mediaType string, b []byte, manifest bool) {
		d := ocispec.Descriptor{MediaType: mediaType, Digest: godigest.FromBytes(b), Size: int64(len(b))}
		var err error
		if manifest {
			err = s.Err("push manifest", s.Repository.Manifests().Push(l.ctx, d, strings.NewReader(string(b))))
		} else {
			err = s.Err("push blob", s.Repository.Blobs().Push(l.ctx, d, strings.NewReader(string(b))))
		}
		if err != nil {
			t.Fatalf("%s: %v", repoPath, err)
		}
	}
	push(bundle.EmptyConfigMediaType, []byte("{}"), false)
	push(bundle.LayerMediaType, layer, false)
	push(ocispec.MediaTypeImageManifest, subject, true)
	for _, p := range proofs {
		push(registry.SigstoreBundleArtifactType, p[1], false)
		push(ocispec.MediaTypeImageManifest, p[0], true)
	}
}

func baSession(t *testing.T, l *live, r obRegistry, f obFixture, repoPath string) *registry.Session {
	t.Helper()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: r.pool, MinVersion: tls.VersionTLS12}
	c, err := registry.NewClient(registry.Options{Transport: tr, Credentials: obCreds{Username: "reader-a", Password: r.users["reader-a"]}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.Open(l.ctx, obSource(f, r.host+"/"+repoPath, f.fpOrg))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// baProof rewrites a proof manifest to point at subject and to carry blob
// (the Sigstore bundle) as its layer.
func baProof(t *testing.T, manifest, blob, subject []byte) [2][]byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(manifest, &m); err != nil {
		t.Fatal(err)
	}
	m["subject"].(map[string]any)["digest"] = godigest.FromBytes(subject).String()
	m["subject"].(map[string]any)["size"] = len(subject)
	layer := m["layers"].([]any)[0].(map[string]any)
	layer["digest"], layer["size"] = godigest.FromBytes(blob).String(), len(blob)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return [2][]byte{out, blob}
}

// baTamperSignature flips one bit of the DSSE signature in a Sigstore bundle.
func baTamperSignature(t *testing.T, blob []byte) []byte {
	t.Helper()
	var b map[string]any
	if err := json.Unmarshal(blob, &b); err != nil {
		t.Fatal(err)
	}
	sig := b["dsseEnvelope"].(map[string]any)["signatures"].([]any)[0].(map[string]any)
	raw, err := base64.StdEncoding.DecodeString(sig["sig"].(string))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	sig["sig"] = base64.StdEncoding.EncodeToString(raw)
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLiveBundlesOrganization(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	s := newBAScenario(l)
	f := loadOBFixture(t)
	reg := startOBRegistry(t, l)
	s.containers = append(s.containers, reg.name)
	read := func(n string) []byte {
		b, err := os.ReadFile(obFixtures + "/" + n)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	otherSubject := read("other-subject-manifest.json")
	signOrg, provValid := read("sign-org.bundle.json"), read("prov-valid.bundle.json")
	// The valid subject and proofs (and a mirror the test does not use).
	publishFixture(t, l, reg, f, "org/valid/"+obBundle, "org/mirror/"+obBundle)
	// Unsigned: the subject alone.
	baPush(t, l, reg, f, "org/unsigned/"+obBundle, f.manifest, f.layer, nil)
	// Wrong key: signed and attested by the other key.
	baPush(t, l, reg, f, "org/wrong-key/"+obBundle, f.manifest, f.layer, [][2][]byte{
		{read("sign-other.manifest.json"), read("sign-other.bundle.json")}, {read("prov-valid-other.manifest.json"), read("prov-valid-other.bundle.json")}})
	// Tampered signature: the organization signature with one bit flipped.
	baPush(t, l, reg, f, "org/tampered-signature/"+obBundle, f.manifest, f.layer, [][2][]byte{
		baProof(t, read("sign-org.manifest.json"), baTamperSignature(t, signOrg), f.manifest), {read("prov-valid.manifest.json"), provValid}})
	// Tampered content: another subject (one manifest annotation added)
	// carrying the valid proofs re-attached to it.
	baPush(t, l, reg, f, "org/tampered-content/"+obBundle, otherSubject, f.layer, [][2][]byte{
		baProof(t, read("sign-org.manifest.json"), signOrg, otherSubject), baProof(t, read("prov-valid.manifest.json"), provValid, otherSubject)})
	otherDigest := godigest.FromBytes(otherSubject).String()

	const ns = "konstapel-bundles-org"
	s.namespace(ns)
	src := func(repo, fp string) bundle.BundleSource { return obSource(f, reg.host+"/org/"+repo+"/"+obBundle, fp) }
	sourcesCM := func(srcs ...bundle.BundleSource) *corev1.ConfigMap {
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: obSourcesCM}, Data: map[string]string{"sources.yaml": obSourcesYAML(t, srcs...)}}
	}
	cred := func(user, pass string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: obCredSecret}, Type: corev1.SecretTypeDockerConfigJson,
			Data: map[string][]byte{corev1.DockerConfigJsonKey: obDockerConfig(reg.host, user, pass)}}
	}
	key := func(pub []byte) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: obKeySecret}, Data: map[string][]byte{"cosign.pub": pub}}
	}
	for _, o := range []client.Object{
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: obCAConfig}, Data: map[string]string{"ca.crt": string(reg.caPEM)}},
		cred("reader-a", reg.users["reader-a"]), key(f.pubOrg), sourcesCM(src("unsigned", f.fpOrg)),
	} {
		l.obApply(o)
	}
	var stopMu sync.Mutex
	stop := l.startBundleManager(ns, t.TempDir())
	restart := func() {
		stopMu.Lock()
		defer stopMu.Unlock()
		stop()
		stop = l.startBundleManager(ns, t.TempDir())
	}
	t.Cleanup(func() {
		// The registry may or may not be paused when a step fails.
		_ = exec.Command("docker", "unpause", reg.name).Run()
		s.teardown()
		stopMu.Lock()
		defer stopMu.Unlock()
		stop()
	})

	// 1. Invalid signatures, with an empty cache: each variant is rejected
	// for a Deny binding, which gets no policy, and a privileged Pod is
	// admitted in its namespace.
	s.namespace("ba-reject")
	rejected := map[string]string{}
	for _, v := range []struct{ name, repo, digest, class string }{
		{"unsigned", "unsigned", f.subject, "(Untrusted)"},
		{"wrong-key", "wrong-key", f.subject, "(Untrusted)"},
		{"tampered-signature", "tampered-signature", f.subject, "(Untrusted)"},
		{"tampered-content", "tampered-content", otherDigest, "(Untrusted)"},
	} {
		l.obApply(sourcesCM(src(v.repo, f.fpOrg)))
		p := s.profile("ba-"+v.name, v.digest)
		b := bindingObj("ba-reject", p.Name, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{envLabel: "ba-reject"})
		b.SetUID("")
		if err := l.c.Create(l.ctx, b); err != nil {
			t.Fatal(err)
		}
		s.bindings = append(s.bindings, b.Name)
		rejected[v.name] = l.waitProfile(p.Name, v1alpha1.ReasonContentUnavailable, v.class)
		l.baNothingDelivered("ba-reject", v1alpha1.ReasonContentUnavailable)
		s.remove([]string{b.Name}, []string{p.Name})
	}
	// Nothing was kept: with the registry down, trusting the key that
	// signed the wrong-key variant must still find no content (a rejected
	// fetch that had been cached would now recheck and resolve offline).
	l.pause(reg.name, true)
	l.obApply(key(f.pubOther))
	l.obApply(sourcesCM(src("wrong-key", f.fpOther)))
	kept := s.profile("ba-kept", f.subject)
	keptMsg := l.waitProfile(kept.Name, v1alpha1.ReasonContentUnavailable, "(ContentUnavailable)")
	s.remove(nil, []string{kept.Name})
	l.obApply(key(f.pubOrg))
	l.obApply(sourcesCM(src("valid", f.fpOrg)))
	l.pause(reg.name, false)
	l.record("invalid-signatures", map[string]any{"rejected": rejected, "rejectedNotKept": keptMsg})

	// 2. Valid organization content in Deny and Audit.
	s.namespace("ba-deny")
	s.namespace("ba-audit")
	p := s.profile("ba-org", f.subject)
	s.binding("ba-deny", p.Name, v1alpha1.ModeDeny)
	s.binding("ba-audit", p.Name, v1alpha1.ModeAudit)
	l.waitProfile(p.Name, "Resolved", "")
	deny := l.baDelivered("ba-deny", f.subject, v1alpha1.ModeDeny)
	audit := l.baDelivered("ba-audit", f.subject, v1alpha1.ModeAudit)
	applied := map[string]string{"ba-deny": l.obApplied("ba-deny"), "ba-audit": l.obApplied("ba-audit")}
	l.record("organization-delivered", map[string]any{"digest": f.subject, "deny": deny, "audit": audit, "applied": applied})
	unchanged := func(step string) {
		t.Helper()
		for b, want := range applied {
			if got := l.obApplied(b); got != want {
				t.Fatalf("%s changed %s's applied policies:\n got %s\nwant %s", step, b, got, want)
			}
		}
	}
	recovered := func(step string) {
		t.Helper()
		l.waitProfile(p.Name, "Resolved", "")
		for b := range applied {
			l.waitReady(b, 1)
		}
		unchanged(step)
		if ok, msg := l.denied("ba-deny"); !ok {
			t.Fatalf("after %s the Deny binding no longer denies: %s", step, msg)
		}
	}

	// 3. Warm-cache outage: the registry is down; verified content keeps
	// serving, and a new Deny binding is delivered from the cache.
	l.pause(reg.name, true)
	s.namespace("ba-warm")
	s.binding("ba-warm", p.Name, v1alpha1.ModeDeny)
	warm := l.baDelivered("ba-warm", f.subject, v1alpha1.ModeDeny)
	l.baProfileResolvedNow(p.Name)
	for b := range applied {
		l.waitReady(b, 1)
	}
	unchanged("warm-cache outage")
	l.pause(reg.name, false)
	l.record("warm-cache-outage", map[string]any{"registry": "paused", "newDenyBinding": warm, "profile": "Resolved"})

	// 4. Cold-cache failure: a restarted controller with an empty cache and
	// the registry down reports ContentUnavailable, keeps applied policies
	// marked stale (not ready), and delivers nothing to a new binding.
	l.pause(reg.name, true)
	restart()
	cold := l.waitProfile(p.Name, v1alpha1.ReasonContentUnavailable, "(ContentUnavailable)")
	for _, b := range []string{"ba-deny", "ba-audit", "ba-warm"} {
		l.waitStale(b)
	}
	unchanged("cold-cache outage")
	s.namespace("ba-cold")
	s.binding("ba-cold", p.Name, v1alpha1.ModeDeny)
	l.baNothingDelivered("ba-cold", v1alpha1.ReasonContentUnavailable)
	l.pause(reg.name, false)
	recovered("cold-cache recovery")
	coldRecovered := l.baDelivered("ba-cold", f.subject, v1alpha1.ModeDeny)
	l.record("cold-cache-failure", map[string]any{"registry": "paused", "cache": "empty (restart)", "profile": cold,
		"kept": "stale, not ready", "newBinding": "unresolved, no policy, privileged Pod admitted", "afterRecovery": coldRecovered})

	// 5. Credential rotation: the old credential is revoked (its password
	// no longer matches), so a cold fetch fails while kept policies stay;
	// the rotated credential is picked up without a restart.
	l.obApply(cred("reader-a", "revoked-"+obRandHex(t, 8)))
	restart()
	unauthorized := l.waitProfile(p.Name, v1alpha1.ReasonContentUnavailable, "(ContentUnavailable)")
	l.waitStale("ba-deny")
	unchanged("revoked credential")
	since := time.Now().UTC().Format(time.RFC3339)
	l.obApply(cred("reader-b", reg.users["reader-b"]))
	recovered("credential rotation")
	logs, _ := exec.Command("docker", "logs", "--since", since, reg.name).CombinedOutput()
	if !strings.Contains(string(logs), "reader-b") {
		t.Fatal("no request authenticated with the rotated credential reached the registry")
	}
	l.record("credential-rotation", map[string]any{"revoked": unauthorized, "rotatedTo": "reader-b", "restart": "none after rotation"})

	// 6. Trust revocation and recovery: the rule and key now name another
	// key. Kept policies stay (stale) and new bindings get nothing; restoring
	// trust recovers both without a new revision.
	l.obApply(key(f.pubOther))
	l.obApply(sourcesCM(src("valid", f.fpOther)))
	revoked := l.waitProfile(p.Name, v1alpha1.ReasonContentUnavailable, "(Untrusted)")
	l.waitStale("ba-deny")
	l.waitStale("ba-audit")
	unchanged("trust revocation")
	s.namespace("ba-revoked")
	s.binding("ba-revoked", p.Name, v1alpha1.ModeDeny)
	l.baNothingDelivered("ba-revoked", v1alpha1.ReasonContentUnavailable)
	l.obApply(key(f.pubOrg))
	l.obApply(sourcesCM(src("valid", f.fpOrg)))
	recovered("trust recovery")
	afterTrust := l.baDelivered("ba-revoked", f.subject, v1alpha1.ModeDeny)
	l.record("trust-revocation", map[string]any{"revoked": revoked, "newBinding": "unresolved, no policy", "recovered": afterTrust})
}
