//go:build live

package controller

// Live OCI bundle acceptance on the Helm-installed controller
// (add-policy-bundle-distribution 5.1, 5.3, 5.4, stage 2b-ii). The runtime
// chart runs the image built from this checkout with the documented values
// (docs/examples/charts/oci-bundles.yaml) on two replicas. A disposable
// registry (KONSTAPEL_REGISTRY_IMAGE, the distribution registry: TLS from a
// throwaway CA, htpasswd authentication, no referrers API, so the tag schema
// fallback) on the kind network serves the checked-in Cosign-signed fixture
// bundle (internal/bundle/verify/testdata/provenance) under two
// repositories. Nothing runs in-process:
//   - the API server authorizes the controller's field-selected watch of the
//     sources ConfigMap through the chart's Role, and only that watch, and
//     the controller's effective Secret/ConfigMap access is exactly the
//     documented boundary;
//   - every replica's Watcher loads the configuration and sees changes;
//   - the leader's Trigger reconciles profiles on configuration, trust and
//     key changes: invalid configuration, deletion, trust revocation and
//     recovery keep the applied policy and never deliver rejected content;
//   - a follower pins (fetches and verifies) content itself, so after the
//     leader is lost it delivers with the registry down;
//   - a mirror, credential rotation, a controller upgrade and a rollback
//     (the latter during a registry outage) leave the applied revision
//     unchanged.
// Run through scripts/targeting-live.sh (charts acceptance group).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/crypto/bcrypt"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/mirror"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Names from docs/examples/charts/oci-bundles.yaml, which the test installs.
const (
	obSourcesCM  = "konstapel-bundle-sources"
	obCredSecret = "acme-registry"
	obKeySecret  = "acme-bundle-signing-key"
	obCAConfig   = "acme-registry-ca"
	obDecoy      = "bundle-live-unlisted"
	obBundle     = "konstapel-privileged-containers"
	obPolicy     = "disallow-privileged-containers"
	obFixtures   = "../../internal/bundle/verify/testdata/provenance"
)

// obFixture is the checked-in signed subject and its organization-key
// proofs (see that directory's README.md and facts.txt).
type obFixture struct {
	manifest, layer              []byte
	subject, layerDigest         string
	fpOrg, fpOther               string
	pubOrg, pubOther             []byte
	sourceRepo, builder          string
	proofManifests, proofBundles [][]byte
}

func loadOBFixture(t *testing.T) obFixture {
	t.Helper()
	read := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join(obFixtures, n))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	f := obFixture{manifest: read("subject-manifest.json"), layer: read("subject-layer.tar.gz"), pubOrg: read("org.pub"), pubOther: read("other.pub"),
		sourceRepo: "https://github.com/backend-bunny/Konstapel"}
	f.subject = godigest.FromBytes(f.manifest).String()
	var err error
	if f.layerDigest, _, err = bundle.ValidateManifest(f.manifest); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(read("facts.txt")), "\n") {
		k, v, _ := strings.Cut(line, " ")
		switch k {
		case "subject":
			if v != f.subject {
				t.Fatalf("facts.txt subject %s, manifest hashes to %s", v, f.subject)
			}
		case "org":
			f.fpOrg = v
		case "other":
			f.fpOther = v
		case "builder":
			f.builder = v
		}
	}
	for _, n := range []string{"sign-org", "prov-valid"} {
		f.proofManifests = append(f.proofManifests, read(n+".manifest.json"))
		f.proofBundles = append(f.proofBundles, read(n+".bundle.json"))
	}
	return f
}

// obRegistry is the disposable registry container.
type obRegistry struct {
	name, host string // container name; 127.0.0.1:port for this process
	caPEM      []byte
	pool       *x509.CertPool
	users      map[string]string
}

// inCluster is the registry's address from pods on the kind network.
func (r obRegistry) inCluster() string { return r.name + ":5000" }

func obRandHex(t *testing.T, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// startOBRegistry runs the pinned distribution registry over TLS with
// htpasswd users reader-a and reader-b, reachable from this process on a
// loopback port and from pods by its container name on the kind network.
// The container is always removed.
func startOBRegistry(t *testing.T, l *live) obRegistry {
	t.Helper()
	image := os.Getenv("KONSTAPEL_REGISTRY_IMAGE")
	if image == "" {
		t.Fatal("KONSTAPEL_REGISTRY_IMAGE is required (scripts/runtime.env)")
	}
	r := obRegistry{name: "konstapel-live-registry-" + obRandHex(t, 4), users: map[string]string{"reader-a": obRandHex(t, 12), "reader-b": obRandHex(t, 12)}}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "konstapel live bundle registry test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: r.name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{r.name}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(srvKey)
	r.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	r.pool = x509.NewCertPool()
	r.pool.AddCert(caCert)
	var htpasswd strings.Builder
	for u, p := range r.users {
		h, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&htpasswd, "%s:%s\n", u, h)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for n, b := range map[string][]byte{"server.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER}),
		"server.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), "htpasswd": []byte(htpasswd.String())} {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("docker", "run", "-d", "--name", r.name, "--label", liveContainerLabel(), "-p", "127.0.0.1::5000", "-v", dir+":/certs:ro",
		"-e", "REGISTRY_HTTP_TLS_CERTIFICATE=/certs/server.crt", "-e", "REGISTRY_HTTP_TLS_KEY=/certs/server.key",
		"-e", "REGISTRY_AUTH=htpasswd", "-e", "REGISTRY_AUTH_HTPASSWD_REALM=konstapel-live", "-e", "REGISTRY_AUTH_HTPASSWD_PATH=/certs/htpasswd",
		image).CombinedOutput(); err != nil {
		t.Fatalf("start registry: %v %s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", r.name).CombinedOutput()
			_ = os.WriteFile(filepath.Join(l.out, t.Name()+"-registry.log"), out, 0o644)
		}
		_ = exec.Command("docker", "unpause", r.name).Run()
		_ = exec.Command("docker", "rm", "-f", r.name).Run()
	})
	if out, err := exec.Command("docker", "network", "connect", "kind", r.name).CombinedOutput(); err != nil {
		t.Fatalf("attach the registry to the kind network: %v %s", err, out)
	}
	out, err := exec.Command("docker", "port", r.name, "5000/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	port := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	r.host = "127.0.0.1:" + port[strings.LastIndex(port, ":")+1:]
	hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: r.pool}}}
	l.eventually("registry serving", func() (bool, string) {
		resp, err := hc.Get("https://" + r.host + "/v2/")
		if err != nil {
			return false, err.Error()
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusUnauthorized, resp.Status
	})
	return r
}

// obCreds is a fixed registry credential for this process's pushes.
type obCreds registry.Credential

func (c obCreds) Credential(context.Context, bundle.BundleSource, string) (registry.Credential, error) {
	return registry.Credential(c), nil
}

// obSource is the publisher rule for the fixture at repository, with every
// reference named as in the documented chart values.
func obSource(f obFixture, repository, fingerprint string) bundle.BundleSource {
	return bundle.BundleSource{Name: obBundle, Repository: repository,
		CredentialSecret: &bundle.ObjectRef{Name: obCredSecret},
		CA:               &bundle.ObjectRef{Kind: bundle.KindConfigMap, Name: obCAConfig},
		Publisher: bundle.Publisher{Type: bundle.SignerPublicKey, PublicKey: &bundle.ObjectRef{Kind: bundle.KindSecret, Name: obKeySecret, Key: "cosign.pub"},
			KeyFingerprint: fingerprint, Provenance: bundle.ProvenanceRule{SourceRepository: f.sourceRepo, Builder: f.builder}}}
}

// publishFixture pushes the subject and its proofs to repoPath with the
// retrieval adapter's own session (so the referrers tag schema is written as
// the consumer reads it), then mirrors it to mirrorPath with the mirror tool,
// which reads both back and requires the proofs at the destination.
func publishFixture(t *testing.T, l *live, r obRegistry, f obFixture, repoPath, mirrorPath string) {
	t.Helper()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: r.pool, MinVersion: tls.VersionTLS12}
	c, err := registry.NewClient(registry.Options{Transport: tr, Credentials: obCreds{Username: "reader-a", Password: r.users["reader-a"]}})
	if err != nil {
		t.Fatal(err)
	}
	src := obSource(f, r.host+"/"+repoPath, f.fpOrg)
	s, err := c.Open(l.ctx, src)
	if err != nil {
		t.Fatal(err)
	}
	blob := func(mediaType string, b []byte) {
		d := ocispec.Descriptor{MediaType: mediaType, Digest: godigest.FromBytes(b), Size: int64(len(b))}
		if err := s.Err("push blob", s.Repository.Blobs().Push(l.ctx, d, bytes.NewReader(b))); err != nil {
			t.Fatal(err)
		}
	}
	manifest := func(b []byte) {
		d := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: godigest.FromBytes(b), Size: int64(len(b))}
		if err := s.Err("push manifest", s.Repository.Manifests().Push(l.ctx, d, bytes.NewReader(b))); err != nil {
			t.Fatal(err)
		}
	}
	blob(bundle.EmptyConfigMediaType, []byte("{}"))
	blob(bundle.LayerMediaType, f.layer)
	manifest(f.manifest)
	for i := range f.proofManifests {
		blob(registry.SigstoreBundleArtifactType, f.proofBundles[i])
		manifest(f.proofManifests[i])
	}
	res, err := mirror.Mirror(l.ctx, c, c, mirror.Request{Source: src, Destination: obSource(f, r.host+"/"+mirrorPath, f.fpOrg), Digest: f.subject})
	if err != nil {
		t.Fatalf("mirror the fixture: %v", err)
	}
	l.record("published", map[string]any{"subject": f.subject, "repositories": []string{repoPath, mirrorPath}, "proofs": res.Proofs})
}

func obSourcesYAML(t *testing.T, srcs ...bundle.BundleSource) string {
	b, err := yaml.Marshal(bundle.Sources{Version: 1, Sources: srcs})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func obDockerConfig(host, user, pass string) []byte {
	b, _ := json.Marshal(map[string]any{"auths": map[string]any{host: map[string]string{"username": user, "password": pass}}})
	return b
}

// obApply creates or replaces o's data.
func (l *live) obApply(o client.Object) {
	l.t.Helper()
	cur := o.DeepCopyObject().(client.Object)
	err := l.c.Get(l.ctx, client.ObjectKeyFromObject(o), cur)
	switch {
	case apierrors.IsNotFound(err):
		o.SetResourceVersion("")
		if err := l.c.Create(l.ctx, o); err != nil {
			l.t.Fatal(err)
		}
		return
	case err != nil:
		l.t.Fatal(err)
	}
	o.SetResourceVersion(cur.GetResourceVersion())
	if err := l.c.Update(l.ctx, o); err != nil {
		l.t.Fatal(err)
	}
}

// saClient is a clientset acting as the controller's ServiceAccount.
func (l *live) saClient(ns, sa string) *kubernetes.Clientset {
	cfg := rest.CopyConfig(l.cfg)
	cfg.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:" + ns + ":" + sa,
		Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + ns, "system:authenticated"}}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		l.t.Fatal(err)
	}
	return cs
}

// fieldWatch opens a watch of ConfigMaps (or Secrets) in ns, field-selected
// to name when name is set, and reports the first event's object name.
func fieldWatch(ctx context.Context, cs *kubernetes.Clientset, ns, kind, name string) (string, error) {
	opts := metav1.ListOptions{}
	if name != "" {
		opts.FieldSelector = "metadata.name=" + name
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	switch kind {
	case "ConfigMap":
		wi, err := cs.CoreV1().ConfigMaps(ns).Watch(ctx, opts)
		if err != nil {
			return "", err
		}
		defer wi.Stop()
		for ev := range wi.ResultChan() {
			if o, ok := ev.Object.(metav1.Object); ok {
				return o.GetName(), nil
			}
			return "", fmt.Errorf("watch event %s: %v", ev.Type, ev.Object)
		}
	case "Secret":
		wi, err := cs.CoreV1().Secrets(ns).Watch(ctx, opts)
		if err != nil {
			return "", err
		}
		defer wi.Stop()
		for ev := range wi.ResultChan() {
			if o, ok := ev.Object.(metav1.Object); ok {
				return o.GetName(), nil
			}
			return "", fmt.Errorf("watch event %s: %v", ev.Type, ev.Object)
		}
	}
	return "", fmt.Errorf("watch of %s %q ended without an event", kind, name)
}

var obRevisionRE = regexp.MustCompile(`"bundle sources changed".*?"revision":(\d+),"available":(true|false)`)

// sourceRevisions is the last configuration revision each controller pod's
// Watcher logged, and whether it was available. A pod only logs one after
// its single-object ConfigMap informer listed and watched.
func (l *live) sourceRevisions(ns string, pods []corev1.Pod) map[string]string {
	cs, err := kubernetes.NewForConfig(l.cfg)
	if err != nil {
		l.t.Fatal(err)
	}
	out := map[string]string{}
	for _, p := range pods {
		raw, err := cs.CoreV1().Pods(ns).GetLogs(p.Name, &corev1.PodLogOptions{Container: "controller"}).DoRaw(l.ctx)
		if err != nil {
			out[p.Name] = "logs: " + err.Error()
			continue
		}
		for _, m := range obRevisionRE.FindAllStringSubmatch(string(raw), -1) {
			out[p.Name] = m[1] + "/" + m[2]
		}
	}
	return out
}

// obApplied is the binding's applied engine policies: name, UID and bundle
// digest. A failed update, revocation or outage must never change them.
func (l *live) obApplied(binding string) string {
	l.t.Helper()
	var parts []string
	for _, n := range l.policiesFor(binding) {
		p := l.policy(n)
		parts = append(parts, n+"@"+string(p.GetUID())+"/"+p.GetAnnotations()[targeting.AnnotationBundleDigest])
	}
	return fmt.Sprint(parts)
}

// obState is what must not change across a mirror, a credential rotation,
// recovery, an upgrade and a rollback: the applied policies and the
// binding's resolved revision (which is cleared while it does not resolve).
func (l *live) obState(binding string) string {
	l.t.Helper()
	return l.obApplied(binding) + " rev=" + l.binding(binding).Status.ConfigurationRevision
}

func (l *live) profileResolved(name string) (*metav1.Condition, *v1alpha1.ComplianceProfile) {
	p := &v1alpha1.ComplianceProfile{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, p); err != nil {
		l.t.Fatal(err)
	}
	return meta.FindStatusCondition(p.Status.Conditions, v1alpha1.ConditionResolved), p
}

// waitProfile waits until the profile's Resolved condition is current with
// the given reason (and, if set, a message containing class).
func (l *live) waitProfile(name, reason, class string) string {
	l.t.Helper()
	var msg string
	l.eventually(name+" "+reason+" "+class, func() (bool, string) {
		c, p := l.profileResolved(name)
		if c == nil || c.Reason != reason || c.ObservedGeneration != p.Generation || p.Status.ObservedGeneration != p.Generation || !strings.Contains(c.Message, class) {
			return false, toJSON(p.Status)
		}
		msg = c.Message
		return true, ""
	})
	return msg
}

// waitStale waits until the binding keeps its applied policies while its
// configuration does not resolve.
func (l *live) waitStale(binding string) {
	l.t.Helper()
	l.eventually(binding+" keeps its applied policies", func() (bool, string) {
		b := l.binding(binding)
		c := meta.FindStatusCondition(b.Status.Conditions, v1alpha1.ConditionEngineReady)
		return c != nil && c.Status == metav1.ConditionFalse && c.Reason == v1alpha1.ReasonStaleRevision, toJSON(b.Status)
	})
}

func (l *live) pause(container string, on bool) {
	l.t.Helper()
	cmd := "unpause"
	if on {
		cmd = "pause"
	}
	if out, err := exec.Command("docker", cmd, container).CombinedOutput(); err != nil {
		l.t.Fatalf("docker %s %s: %v %s", cmd, container, err, out)
	}
}

func TestLiveHelmBundles(t *testing.T) {
	image, repo, imageDigest := liveImage(t)
	l := newLive(t)
	const ns = "konstapel-system"
	f := loadOBFixture(t)
	reg := startOBRegistry(t, l)
	publishFixture(t, l, reg, f, "fixtures/"+obBundle, "mirror/"+obBundle)
	primary := obSource(f, reg.inCluster()+"/fixtures/"+obBundle, f.fpOrg)
	mirrored := obSource(f, reg.inCluster()+"/mirror/"+obBundle, f.fpOrg)

	// The operator's objects, created before the chart as documented; the
	// chart creates none of them. The decoy is referenced by nothing.
	if err := l.c.Create(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	sourcesCM := func(srcs ...bundle.BundleSource) *corev1.ConfigMap {
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: obSourcesCM}, Data: map[string]string{"sources.yaml": obSourcesYAML(t, srcs...)}}
	}
	cred := func(user string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: obCredSecret}, Type: corev1.SecretTypeDockerConfigJson,
			Data: map[string][]byte{corev1.DockerConfigJsonKey: obDockerConfig(reg.inCluster(), user, reg.users[user])}}
	}
	key := func(pub []byte) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: obKeySecret}, Data: map[string][]byte{"cosign.pub": pub}}
	}
	operatorObjects := []client.Object{
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: obCAConfig}, Data: map[string]string{"ca.crt": string(reg.caPEM)}},
		cred("reader-a"), key(f.pubOrg), sourcesCM(primary),
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: obDecoy}, Data: map[string][]byte{"x": []byte("y")}},
	}
	for _, o := range operatorObjects {
		l.obApply(o)
	}
	t.Cleanup(func() {
		for _, o := range operatorObjects {
			_ = l.c.Delete(context.Background(), o)
		}
	})
	l.installCharts(ns, repo, imageDigest, "-f", "../../docs/examples/charts/oci-bundles.yaml", "--set", "bundles.refreshInterval=10s")
	pods := l.readyPods(ns, "controller", 2)
	for _, p := range pods {
		c := p.Spec.Containers[0]
		if c.Image != image || !strings.Contains(strings.Join(c.Args, " "), "--bundle-sources-configmap="+obSourcesCM) {
			t.Fatalf("pod %s does not run the bundle-enabled packaged controller: %v", p.Name, c.Args)
		}
	}

	// 1. RBAC against the real API server, as the controller's
	// ServiceAccount: the field-selected watch of the sources ConfigMap is
	// allowed, by the chart's bundle Role alone; nothing broader is. Then
	// the effective Secret/ConfigMap boundary of all the controller's roles.
	sa := l.saClient(ns, "konstapel-controller")
	allowed := func(what string, f func() error) {
		t.Helper()
		l.eventually(what+" allowed", func() (bool, string) {
			err := f()
			return err == nil, fmt.Sprint(err)
		})
	}
	forbidden := func(what string, f func() error) {
		t.Helper()
		l.eventually(what+" forbidden", func() (bool, string) {
			err := f()
			return apierrors.IsForbidden(err), fmt.Sprint(err)
		})
	}
	selectedWatch := func() error {
		name, err := fieldWatch(l.ctx, sa, ns, "ConfigMap", obSourcesCM)
		if err == nil && name != obSourcesCM {
			err = fmt.Errorf("watch delivered %s", name)
		}
		return err
	}
	allowed("field-selected watch of the sources ConfigMap", selectedWatch)
	forbidden("unselected ConfigMap watch", func() error { _, err := fieldWatch(l.ctx, sa, ns, "ConfigMap", ""); return err })
	forbidden("field-selected watch of a referenced ConfigMap", func() error { _, err := fieldWatch(l.ctx, sa, ns, "ConfigMap", obCAConfig); return err })
	forbidden("field-selected watch of the credential Secret", func() error { _, err := fieldWatch(l.ctx, sa, ns, "Secret", obCredSecret); return err })
	forbidden("Secret list", func() error { _, err := sa.CoreV1().Secrets(ns).List(l.ctx, metav1.ListOptions{}); return err })
	forbidden("ConfigMap update", func() error {
		cm, err := sa.CoreV1().ConfigMaps(ns).Get(l.ctx, obSourcesCM, metav1.GetOptions{})
		if err != nil {
			return err
		}
		_, err = sa.CoreV1().ConfigMaps(ns).Update(l.ctx, cm, metav1.UpdateOptions{})
		return err
	})
	forbidden("sources ConfigMap watch in another namespace", func() error { _, err := fieldWatch(l.ctx, sa, "default", "ConfigMap", obSourcesCM); return err })
	allowed("get of each referenced object", func() error {
		for _, n := range []string{obCredSecret, obKeySecret} {
			if _, err := sa.CoreV1().Secrets(ns).Get(l.ctx, n, metav1.GetOptions{}); err != nil {
				return err
			}
		}
		_, err := sa.CoreV1().ConfigMaps(ns).Get(l.ctx, obCAConfig, metav1.GetOptions{})
		return err
	})
	// The effective union of every Role and ClusterRole bound to the
	// controller ServiceAccount (docs/charts.md, "Controller ServiceAccount
	// boundary"). The S3 credentialSecret, CA trust, legacy configuration,
	// acceptance snapshot and orphan inventory names are chosen in CR specs
	// or derived at runtime, so Secret and ConfigMap get in this namespace
	// are not by name: a Secret the bundle values do not list is readable.
	// Asserted as allowed so a narrowing is a deliberate test change.
	allowed("get of a Secret no bundle value lists", func() error {
		_, err := sa.CoreV1().Secrets(ns).Get(l.ctx, obDecoy, metav1.GetOptions{})
		return err
	})
	forbidden("unselected ConfigMap list", func() error { _, err := sa.CoreV1().ConfigMaps(ns).List(l.ctx, metav1.ListOptions{}); return err })
	forbidden("field-selected list of a referenced ConfigMap", func() error {
		_, err := sa.CoreV1().ConfigMaps(ns).List(l.ctx, metav1.ListOptions{FieldSelector: "metadata.name=" + obCAConfig})
		return err
	})
	forbidden("unselected Secret watch", func() error { _, err := fieldWatch(l.ctx, sa, ns, "Secret", ""); return err })
	forbidden("Secret get in another namespace", func() error {
		_, err := sa.CoreV1().Secrets("default").Get(l.ctx, obDecoy, metav1.GetOptions{})
		return err
	})
	forbidden("ConfigMap get in another namespace", func() error {
		_, err := sa.CoreV1().ConfigMaps("kube-system").Get(l.ctx, "kube-root-ca.crt", metav1.GetOptions{})
		return err
	})
	forbidden("Secret update", func() error {
		s, err := sa.CoreV1().Secrets(ns).Get(l.ctx, obDecoy, metav1.GetOptions{})
		if err != nil {
			return err
		}
		_, err = sa.CoreV1().Secrets(ns).Update(l.ctx, s, metav1.UpdateOptions{})
		return err
	})
	forbidden("Secret delete", func() error {
		return sa.CoreV1().Secrets(ns).Delete(l.ctx, obDecoy, metav1.DeleteOptions{DryRun: []string{metav1.DryRunAll}})
	})
	forbidden("ConfigMap delete", func() error {
		return sa.CoreV1().ConfigMaps(ns).Delete(l.ctx, obCAConfig, metav1.DeleteOptions{DryRun: []string{metav1.DryRunAll}})
	})
	// Writes that would create objects are checked with SubjectAccessReview
	// (the same authorizer, without side effects).
	admin, err := kubernetes.NewForConfig(l.cfg)
	if err != nil {
		t.Fatal(err)
	}
	access := func(namespace, group, resource, verb, name string) bool {
		t.Helper()
		r, err := admin.AuthorizationV1().SubjectAccessReviews().Create(l.ctx, &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
			User:               "system:serviceaccount:" + ns + ":konstapel-controller",
			Groups:             []string{"system:serviceaccounts", "system:serviceaccounts:" + ns, "system:authenticated"},
			ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: namespace, Group: group, Resource: resource, Verb: verb, Name: name},
		}}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return r.Status.Allowed
	}
	reviews := map[string]bool{}
	for _, q := range []struct {
		namespace, group, resource, verb, name string
		want                                   bool
	}{
		{ns, "", "configmaps", "create", "", true},                              // acceptance snapshots, orphan inventory
		{ns, "", "configmaps", "get", DefaultDestinationConfigMap, true},        // central default destination
		{ns, "", "secrets", "get", "s3-credentials", true},                      // EvidenceDestination credentialSecret
		{ns, "", "events", "create", "", true},                                  // manager events
		{ns, "coordination.k8s.io", "leases", "update", LeaderElectionID, true}, // leader election
		{ns, "", "secrets", "create", "", false},
		{ns, "", "secrets", "list", "", false},
		{ns, "", "secrets", "patch", "s3-credentials", false},
		{ns, "", "secrets", "deletecollection", "", false},
		{ns, "", "configmaps", "list", "", false},
		{ns, "", "configmaps", "watch", "", false},
		{ns, "", "configmaps", "update", DefaultDestinationConfigMap, false},
		{ns, "", "configmaps", "patch", DefaultDestinationConfigMap, false},
		{ns, "", "configmaps", "deletecollection", "", false},
		{"default", "", "secrets", "get", "s3-credentials", false},
		{"default", "", "configmaps", "create", "", false},
		{"", "", "secrets", "get", "s3-credentials", false},
		{"", "", "configmaps", "list", "", false},
	} {
		got := access(q.namespace, q.group, q.resource, q.verb, q.name)
		what := fmt.Sprintf("%s %s/%s %s %q", q.namespace, q.group, q.resource, q.verb, q.name)
		reviews[what] = got
		if got != q.want {
			t.Errorf("SubjectAccessReview %s: allowed=%v, want %v", what, got, q.want)
		}
	}
	// Without the chart's bundle RoleBinding the selected watch is
	// forbidden: no other grant allows it.
	rb := &rbacv1.RoleBinding{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: "konstapel-controller-bundles"}, rb); err != nil {
		t.Fatal(err)
	}
	if err := l.c.Delete(l.ctx, rb); err != nil {
		t.Fatal(err)
	}
	forbidden("field-selected watch without the bundle RoleBinding", selectedWatch)
	rb.ResourceVersion, rb.UID = "", ""
	if err := l.c.Create(l.ctx, rb); err != nil {
		t.Fatal(err)
	}
	allowed("field-selected watch with the RoleBinding restored", selectedWatch)
	l.record("rbac", map[string]any{"selectedWatch": "allowed by konstapel-controller-bundles only",
		"forbidden": []string{"unselected ConfigMap watch and list", "selected watch and list of other ConfigMaps", "Secret watch and list",
			"ConfigMap and Secret update and delete", "other namespaces"},
		"unlistedSecretGet": "allowed (generated Role: Secret get in the controller namespace, not by name)",
		"accessReviews":     reviews})

	// 2. Every replica's Watcher loaded the configuration through that watch.
	l.eventually("both replicas loaded the sources configuration", func() (bool, string) {
		revs := l.sourceRevisions(ns, pods)
		ok := len(revs) == 2
		for _, r := range revs {
			ok = ok && strings.HasSuffix(r, "/true")
		}
		return ok, fmt.Sprint(revs)
	})

	// 3. An Audit binding over the OCI profile is delivered from the
	// verified bundle.
	l.setNamespace("ob-audit", "ob-audit")
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: "ob-oci"},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: obBundle, Digest: f.subject}, Policies: []v1alpha1.ProfilePolicy{{Name: obPolicy}}}}
	b := bindingObj("ob-audit", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "ob-audit"})
	b.SetUID("")
	for _, o := range []client.Object{p, b} {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	extra := map[string]*v1alpha1.ComplianceBinding{}
	t.Cleanup(func() {
		for _, o := range extra {
			_ = l.c.Delete(context.Background(), o)
		}
		_ = l.c.Delete(context.Background(), b)
		_ = l.c.Delete(context.Background(), p)
		l.eventually("bundle bindings' policies withdrawn", func() (bool, string) {
			names := []string{b.Name}
			for n := range extra {
				names = append(names, n)
			}
			left := l.policiesFor(names...)
			return len(left) == 0, fmt.Sprint(left)
		})
	})
	l.waitProfile(p.Name, "Resolved", "")
	l.waitReady(b.Name, 1)
	applied := l.policiesFor(b.Name)
	if len(applied) != 1 {
		t.Fatalf("Audit binding policies %v", applied)
	}
	pol := l.policy(applied[0])
	if pol.GetAnnotations()[targeting.AnnotationBundleDigest] != f.subject || pol.GetAnnotations()[targeting.AnnotationBundle] != obBundle ||
		!strings.Contains(toJSON(pol.Object["spec"]), `"Audit"`) {
		t.Fatalf("delivered policy is not the Audit rendering of the OCI bundle: %v %s", pol.GetAnnotations(), toJSON(pol.Object["spec"]))
	}
	state, applied0 := l.obState(b.Name), l.obApplied(b.Name)
	l.record("delivered", map[string]any{"profile": p.Name, "binding": b.Name, "state": state})
	unchanged := func(step string) {
		t.Helper()
		l.waitProfile(p.Name, "Resolved", "")
		l.waitReady(b.Name, 1)
		if got := l.obState(b.Name); got != state {
			t.Fatalf("%s changed the applied revision:\n got %s\nwant %s", step, got, state)
		}
	}

	// 4. A mirror is a location only: every replica sees the change through
	// the watch, and the revision does not advance.
	before := l.sourceRevisions(ns, pods)
	l.obApply(sourcesCM(mirrored))
	l.eventually("both replicas observed the mirror", func() (bool, string) {
		now := l.sourceRevisions(ns, pods)
		for name, r := range now {
			if r == before[name] || !strings.HasSuffix(r, "/true") {
				return false, fmt.Sprint(before, now)
			}
		}
		return len(now) == 2, fmt.Sprint(now)
	})
	unchanged("mirror")
	l.record("mirror", map[string]any{"revisions": l.sourceRevisions(ns, pods)})

	// 5. Invalid configuration, then deletion: the whole configuration is
	// unavailable, the profile says so, the binding keeps what it applied;
	// both recover without a new revision.
	l.obApply(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: obSourcesCM}, Data: map[string]string{"sources.yaml": "version: 2\nsources: []\n"}})
	invalid := l.waitProfile(p.Name, v1alpha1.ReasonContentUnavailable, "(Config)")
	l.waitStale(b.Name)
	if got := l.obApplied(b.Name); got != applied0 {
		t.Fatalf("invalid configuration changed applied policies: %s", got)
	}
	l.obApply(sourcesCM(mirrored))
	unchanged("recovery from invalid configuration")
	if err := l.c.Delete(l.ctx, sourcesCM()); err != nil {
		t.Fatal(err)
	}
	deleted := l.waitProfile(p.Name, v1alpha1.ReasonContentUnavailable, "(Config)")
	l.waitStale(b.Name)
	l.obApply(sourcesCM(mirrored))
	unchanged("recovery from deletion")
	l.record("configuration", map[string]any{"invalid": invalid, "deleted": deleted})

	// 6. Trust revocation through a referenced object (read by name every
	// refresh interval, never watched): the key Secret and the rule now name
	// another key, so the fixture's signature is no longer trusted. Applied
	// policies stay, and rejected content is not used for anything new.
	l.obApply(key(f.pubOther))
	l.obApply(sourcesCM(obSource(f, mirrored.Repository, f.fpOther)))
	revoked := l.waitProfile(p.Name, v1alpha1.ReasonContentUnavailable, "(Untrusted)")
	l.waitStale(b.Name)
	if got := l.obApplied(b.Name); got != applied0 {
		t.Fatalf("revocation changed applied policies: %s", got)
	}
	l.setNamespace("ob-late", "ob-late")
	late := bindingObj("ob-late", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "ob-late"})
	late.SetUID("")
	if err := l.c.Create(l.ctx, late); err != nil {
		t.Fatal(err)
	}
	extra[late.Name] = late
	l.eventually("a new binding of revoked content stays unresolved", func() (bool, string) {
		lb := l.binding(late.Name)
		c := meta.FindStatusCondition(lb.Status.Conditions, v1alpha1.ConditionResolved)
		return c != nil && c.Status == metav1.ConditionFalse && c.Reason == v1alpha1.ReasonContentUnavailable && c.ObservedGeneration == lb.Generation, toJSON(lb.Status)
	})
	if got := l.policiesFor(late.Name); len(got) != 0 {
		t.Fatalf("revoked content delivered for a new binding: %v", got)
	}
	l.obApply(key(f.pubOrg))
	l.obApply(sourcesCM(mirrored))
	unchanged("recovery from revocation")
	l.waitReady(late.Name, 1)
	l.record("revocation", map[string]any{"revoked": revoked, "newBindingDuringRevocation": "unresolved, no policies", "recovered": l.policiesFor(late.Name)})

	// 7. A follower pins content itself: with the registry down, the leader
	// is lost and the former follower delivers a new binding from its own
	// verified cache (it has no webhooks and reconciles nothing as a
	// follower, so only its Pinner can have fetched).
	leader := l.leaderPod(ns, "")
	follower := ""
	for _, p := range l.readyPods(ns, "controller", 2) {
		if p.Name != leader {
			follower = p.Name
		}
	}
	l.pause(reg.name, true)
	// Remove the leader without a replacement that could win the Lease
	// (leadership is not released on shutdown, so a fresh pod would race
	// the follower at expiry): scale to one replica with the leader as the
	// cheapest pod to delete.
	for name, cost := range map[string]string{leader: "-1000", follower: "1000"} {
		pod := &corev1.Pod{}
		if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: name}, pod); err != nil {
			t.Fatal(err)
		}
		patch := client.MergeFrom(pod.DeepCopy())
		metav1.SetMetaDataAnnotation(&pod.ObjectMeta, "controller.kubernetes.io/pod-deletion-cost", cost)
		if err := l.c.Patch(l.ctx, pod, patch); err != nil {
			t.Fatal(err)
		}
	}
	dep := &appsv1.Deployment{}
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: "konstapel-controller"}, dep); err != nil {
		t.Fatal(err)
	}
	patch := client.MergeFrom(dep.DeepCopy())
	one := int32(1)
	dep.Spec.Replicas = &one
	if err := l.c.Patch(l.ctx, dep, patch); err != nil {
		t.Fatal(err)
	}
	l.eventually("the leader pod is gone", func() (bool, string) {
		err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: leader}, &corev1.Pod{})
		return apierrors.IsNotFound(err), fmt.Sprint(err)
	})
	if next := l.leaderPod(ns, leader); next != follower {
		t.Fatalf("the Lease went to %s, not the running follower %s", next, follower)
	}
	l.setNamespace("ob-failover", "ob-failover")
	fo := bindingObj("ob-failover", p.Name, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{envLabel: "ob-failover"})
	fo.SetUID("")
	if err := l.c.Create(l.ctx, fo); err != nil {
		t.Fatal(err)
	}
	extra[fo.Name] = fo
	l.waitReady(fo.Name, 1)
	if got := l.obState(b.Name); got != state {
		t.Fatalf("failover changed applied policies: %s", got)
	}
	l.pause(reg.name, false)
	// Back to the chart's two replicas (the same value, so Helm's
	// server-side apply below does not conflict with this field manager).
	patch = client.MergeFrom(dep.DeepCopy())
	two := int32(2)
	dep.Spec.Replicas = &two
	if err := l.c.Patch(l.ctx, dep, patch); err != nil {
		t.Fatal(err)
	}
	l.readyPods(ns, "controller", 2)
	l.record("follower-pins", map[string]any{"lostLeader": leader, "newLeader": follower, "registry": "paused", "delivered": l.policiesFor(fo.Name)})

	// 8. Controller upgrade with a rotated credential: new pods start with
	// empty caches, fetch with the new credential and verify again; the
	// applied revision does not change.
	l.obApply(cred("reader-b"))
	upgrade := []string{"upgrade", "konstapel", chartArchive(t, "konstapel"), "--namespace", ns, "--wait", "--timeout", "5m",
		"-f", "../../docs/examples/charts/operator-tls.yaml", "-f", "../../docs/examples/charts/oci-bundles.yaml", "--set", "bundles.refreshInterval=15s"}
	if out, err := l.helm(append(upgrade, imageValues(repo, imageDigest)...)...); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, out)
	}
	pods = l.rolledOut(ns, "--bundle-refresh-interval=15s")
	unchanged("upgrade")
	if logs, _ := exec.Command("docker", "logs", reg.name).CombinedOutput(); !strings.Contains(string(logs), "reader-b") {
		t.Fatal("no request authenticated with the rotated credential reached the registry")
	}
	l.record("upgrade", map[string]any{"pods": len(pods), "credential": "rotated to reader-b before the upgrade", "state": l.obState(b.Name)})

	// 9. Rollback during a registry outage: the replaced pods cannot fetch,
	// so the profile reports ContentUnavailable while the binding keeps its
	// applied policies; when the registry returns it resolves again with the
	// same revision.
	l.pause(reg.name, true)
	if out, err := l.helm("rollback", "konstapel", "1", "--namespace", ns, "--wait", "--timeout", "5m"); err != nil {
		t.Fatalf("rollback: %v\n%s", err, out)
	}
	l.rolledOut(ns, "--bundle-refresh-interval=10s")
	outage := l.waitProfile(p.Name, v1alpha1.ReasonContentUnavailable, "")
	l.waitStale(b.Name)
	if got := l.obApplied(b.Name); got != applied0 {
		t.Fatalf("rollback during an outage changed applied policies: %s", got)
	}
	l.pause(reg.name, false)
	unchanged("rollback")
	l.record("rollback", map[string]any{"outage": outage, "state": l.obState(b.Name)})
}

// rolledOut waits until exactly two ready controller pods run with arg and
// no other controller pod remains.
func (l *live) rolledOut(ns, arg string) []corev1.Pod {
	l.t.Helper()
	var pods []corev1.Pod
	l.eventually("controller rolled out with "+arg, func() (bool, string) {
		var all corev1.PodList
		_ = l.c.List(l.ctx, &all, client.InNamespace(ns), client.MatchingLabels{"app.kubernetes.io/component": "controller"})
		pods = l.podsReady(ns, "controller")
		if len(all.Items) != 2 || len(pods) != 2 {
			return false, l.podDiagnostics(ns)
		}
		for _, p := range pods {
			if !strings.Contains(strings.Join(p.Spec.Containers[0].Args, " "), arg) {
				return false, p.Name + " " + strconv.Quote(strings.Join(p.Spec.Containers[0].Args, " "))
			}
		}
		return true, ""
	})
	return pods
}

// policy reads a managed engine policy.
func (l *live) policy(name string) *unstructured.Unstructured {
	l.t.Helper()
	p := &unstructured.Unstructured{}
	p.SetGroupVersionKind(targeting.ValidatingPolicyGVK)
	if err := l.c.Get(l.ctx, client.ObjectKey{Name: name}, p); err != nil {
		l.t.Fatal(err)
	}
	return p
}
