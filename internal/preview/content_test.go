package preview

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// Verified bundle resolution (tasks 4.1 to 4.3) through the real bundle
// stack: the source watcher, the exact-digest resolver, the public-key and
// provenance verifier, the content cache and the Secret-backed credential
// and CA provider, with the checked-in organization-key fixture of
// internal/bundle/verify/testdata/provenance served by an in-process TLS
// registry that behaves like distribution registry 3 (no referrers API, the
// referrers tag schema, htpasswd-style Basic authentication). Kubernetes is
// the recording API server; every credential is generated per test.

const (
	provFixtures  = "../bundle/verify/testdata/provenance"
	ociBundle     = "konstapel-privileged-containers"
	ociPolicy     = "disallow-privileged-containers"
	sourcesCMName = "konstapel-bundle-sources"
	credSecret    = "acme-registry"
	keySecret     = "acme-bundle-signing-key"
	caConfigMap   = "acme-registry-ca"
)

type provFixture struct {
	manifest, layer, otherManifest []byte
	subject                        string
	fpOrg, fpOther, builder        string
	pubOrg, pubOther               []byte
	// proofs are the organization signature and provenance: manifest, bundle.
	proofs, otherProofs [][2][]byte
}

func loadProvFixture(t *testing.T) provFixture {
	t.Helper()
	read := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join(provFixtures, n))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	f := provFixture{manifest: read("subject-manifest.json"), layer: read("subject-layer.tar.gz"), otherManifest: read("other-subject-manifest.json"),
		pubOrg: read("org.pub"), pubOther: read("other.pub")}
	f.subject = godigest.FromBytes(f.manifest).String()
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
		f.proofs = append(f.proofs, [2][]byte{read(n + ".manifest.json"), read(n + ".bundle.json")})
	}
	for _, n := range []string{"sign-other", "prov-valid-other"} {
		f.otherProofs = append(f.otherProofs, [2][]byte{read(n + ".manifest.json"), read(n + ".bundle.json")})
	}
	return f
}

// testRegistry is an in-process TLS OCI registry: manifests and blobs by
// digest, no referrers API (404, as distribution registry 3 answers) and the
// referrers tag schema index. Repositories under private/ require Basic
// credentials; public/ is anonymous.
type testRegistry struct {
	t          *testing.T
	srv        *httptest.Server
	user, pass string

	mu        sync.Mutex
	manifests map[string][]byte               // repo@digest
	blobs     map[string][]byte               // repo@digest
	referrers map[string][]ocispec.Descriptor // repo@subject
	requests  []string
	down      bool
	// override serves other bytes under a manifest digest (repo@digest).
	override map[string][]byte
}

func newTestRegistry(t *testing.T) *testRegistry {
	r := &testRegistry{t: t, user: "reader-" + randomHex(t, 3), pass: randomHex(t, 16),
		manifests: map[string][]byte{}, blobs: map[string][]byte{}, referrers: map[string][]ocispec.Descriptor{}, override: map[string][]byte{}}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

func randomHex(t *testing.T, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func (r *testRegistry) host() string { return strings.TrimPrefix(r.srv.URL, "https://") }

func (r *testRegistry) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.srv.Certificate().Raw})
}

func (r *testRegistry) repo(path string) string { return r.host() + "/" + path }

// publish stores a subject, its layer and its proofs in repo.
func (r *testRegistry) publish(repo string, manifest, layer []byte, proofs [][2][]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	subject := godigest.FromBytes(manifest).String()
	r.manifests[repo+"@"+subject] = manifest
	r.blobs[repo+"@"+godigest.FromBytes(layer).String()] = layer
	r.blobs[repo+"@"+godigest.FromBytes([]byte("{}")).String()] = []byte("{}")
	for _, p := range proofs {
		var m ocispec.Manifest
		if err := json.Unmarshal(p[0], &m); err != nil {
			r.t.Fatal(err)
		}
		d := godigest.FromBytes(p[0]).String()
		r.manifests[repo+"@"+d] = p[0]
		r.blobs[repo+"@"+godigest.FromBytes(p[1]).String()] = p[1]
		r.referrers[repo+"@"+m.Subject.Digest.String()] = append(r.referrers[repo+"@"+m.Subject.Digest.String()], ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageManifest, Digest: godigest.Digest(d), Size: int64(len(p[0])), ArtifactType: m.ArtifactType, Annotations: m.Annotations})
	}
}

func (r *testRegistry) setDown(down bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.down = down
}

func (r *testRegistry) log() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.requests)
}

func regError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []any{map[string]string{"code": code, "message": code}}})
}

func (r *testRegistry) serve(w http.ResponseWriter, req *http.Request) {
	u, p, hasAuth := req.BasicAuth()
	authed := hasAuth && u == r.user && p == r.pass
	r.mu.Lock()
	r.requests = append(r.requests, fmt.Sprintf("%s %s auth=%t", req.Method, req.URL.Path, hasAuth))
	down := r.down
	r.mu.Unlock()
	if req.URL.Path == "/v2/" {
		return
	}
	if down {
		regError(w, http.StatusServiceUnavailable, "UNAVAILABLE")
		return
	}
	rest := strings.TrimPrefix(req.URL.Path, "/v2/")
	var repo, kind, ref string
	for _, k := range []string{"/manifests/", "/blobs/", "/referrers/"} {
		if i := strings.LastIndex(rest, k); i > 0 {
			repo, kind, ref = rest[:i], strings.Trim(k, "/"), rest[i+len(k):]
			break
		}
	}
	if strings.HasPrefix(repo, "private/") && !authed {
		w.Header().Set("WWW-Authenticate", `Basic realm="preview-test"`)
		regError(w, http.StatusUnauthorized, "UNAUTHORIZED")
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch kind {
	case "manifests":
		if hexd, ok := strings.CutPrefix(ref, "sha256-"); ok {
			descs, ok := r.referrers[repo+"@sha256:"+hexd]
			if !ok {
				regError(w, http.StatusNotFound, "MANIFEST_UNKNOWN")
				return
			}
			body, _ := json.Marshal(ocispec.Index{Versioned: specsV2, MediaType: ocispec.MediaTypeImageIndex, Manifests: descs})
			writeManifest(w, req, ocispec.MediaTypeImageIndex, body)
			return
		}
		body, ok := r.manifests[repo+"@"+ref]
		if !ok {
			regError(w, http.StatusNotFound, "MANIFEST_UNKNOWN")
			return
		}
		if o, ok := r.override[repo+"@"+ref]; ok {
			body = o
		}
		writeManifest(w, req, ocispec.MediaTypeImageManifest, body)
	case "blobs":
		b, ok := r.blobs[repo+"@"+ref]
		if !ok {
			regError(w, http.StatusNotFound, "BLOB_UNKNOWN")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(b)))
		_, _ = w.Write(b)
	case "referrers":
		w.WriteHeader(http.StatusNotFound)
	default:
		regError(w, http.StatusNotFound, "NAME_UNKNOWN")
	}
}

func writeManifest(w http.ResponseWriter, req *http.Request, mediaType string, body []byte) {
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Docker-Content-Digest", godigest.FromBytes(body).String())
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	if req.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}

// bundleWorld is a cluster whose bundle-source ConfigMap maps the bundle
// name to a repository of the test registry under the organization key,
// with the documented Secret and ConfigMap names, plus one live profile and
// one Deny binding selecting prod.
type bundleWorld struct {
	t    *testing.T
	fx   provFixture
	reg  *testRegistry
	api  *fakeAPI
	repo string
	// secretValues are every credential value, which must never appear in
	// any output.
	secretValues []string
}

func newBundleWorld(t *testing.T, repoPath string) *bundleWorld {
	t.Helper()
	w := &bundleWorld{t: t, fx: loadProvFixture(t), reg: newTestRegistry(t), api: newFakeAPI(t)}
	w.reg.publish("private/valid", w.fx.manifest, w.fx.layer, w.fx.proofs)
	w.reg.publish("public/valid", w.fx.manifest, w.fx.layer, w.fx.proofs)
	w.reg.publish("private/unsigned", w.fx.manifest, w.fx.layer, nil)
	w.reg.publish("private/wrong-key", w.fx.manifest, w.fx.layer, w.fx.otherProofs)
	w.secretValues = []string{w.reg.pass, base64.StdEncoding.EncodeToString([]byte(w.reg.user + ":" + w.reg.pass))}
	f := w.api
	f.put(pathNamespaces, namespace("kube-system", "ks-uid", nil))
	f.put(pathNamespaces, namespace(ctrlNS, "ctrl-uid", nil))
	f.put(pathNamespaces, namespace("prod", "prod-uid", map[string]string{"env": "production"}))
	f.put(pathNamespaces, namespace("dev", "dev-uid", map[string]string{"env": "development"}))
	w.setSource(repoPath, true, w.fx.fpOrg)
	f.put(pathConfigMaps(ctrlNS), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: caConfigMap}, Data: map[string]string{"ca.crt": string(w.reg.caPEM())}})
	f.put(pathSecrets(ctrlNS), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: credSecret}, Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{corev1.DockerConfigJsonKey: w.dockerConfig(w.reg.user, w.reg.pass)}})
	w.setKey(w.fx.pubOrg)
	w.live(bundleProfile("org", ociBundle, w.fx.subject), "uid-org", 1)
	w.live(bundleBinding("deny-prod", "org", "Deny", "production"), "uid-deny-prod", 1)
	return w
}

func (w *bundleWorld) dockerConfig(user, pass string) []byte {
	b, _ := json.Marshal(map[string]any{"auths": map[string]any{w.reg.host(): map[string]string{"username": user, "password": pass}}})
	return b
}

// setSource writes the sources ConfigMap for one source at repoPath.
func (w *bundleWorld) setSource(repoPath string, withCredential bool, fingerprint string) {
	w.repo = w.reg.repo(repoPath)
	src := bundle.BundleSource{Name: ociBundle, Repository: w.repo,
		CA: &bundle.ObjectRef{Kind: bundle.KindConfigMap, Name: caConfigMap},
		Publisher: bundle.Publisher{Type: bundle.SignerPublicKey, PublicKey: &bundle.ObjectRef{Kind: bundle.KindSecret, Name: keySecret, Key: "cosign.pub"},
			KeyFingerprint: fingerprint, Provenance: bundle.ProvenanceRule{SourceRepository: "https://github.com/backend-bunny/Konstapel", Builder: w.fx.builder}}}
	if withCredential {
		src.CredentialSecret = &bundle.ObjectRef{Name: credSecret}
	}
	doc, err := yaml.Marshal(bundle.Sources{Version: 1, Sources: []bundle.BundleSource{src}})
	if err != nil {
		w.t.Fatal(err)
	}
	w.api.put(pathConfigMaps(ctrlNS), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: sourcesCMName}, Data: map[string]string{bundle.SourcesConfigKey: string(doc)}})
}

func (w *bundleWorld) setKey(pub []byte) {
	w.api.put(pathSecrets(ctrlNS), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: keySecret}, Data: map[string][]byte{"cosign.pub": pub}})
}

func (w *bundleWorld) live(doc, uid string, gen int64) {
	w.t.Helper()
	o := mustSet(w.t, doc).Objects[0]
	switch {
	case o.Profile != nil:
		p := o.Profile.DeepCopy()
		p.UID, p.Generation = types.UID(uid), gen
		w.api.put(pathProfiles, p)
	default:
		b := o.Binding.DeepCopy()
		b.UID, b.Generation, b.Spec.EnforcementEpoch = types.UID(uid), gen, gen
		w.api.put(pathBindings, b)
	}
}

func bundleProfile(name, bundleName, digest string) string {
	return "apiVersion: compliance.erenius.io/v1alpha1\nkind: ComplianceProfile\nmetadata:\n  name: " + name +
		"\nspec:\n  bundle: {name: " + bundleName + ", digest: " + digest + "}\n  policies:\n    - name: " + ociPolicy + "\n"
}

func bundleBinding(name, profile, mode, env string) string {
	return bindingWith(name, profile, mode, "{matchLabels: {env: "+env+"}}")
}

func (w *bundleWorld) observe() *Snapshot {
	w.t.Helper()
	s, err := observe(w.t, w.api, func(o *ObserveOptions) { o.SourcesConfigMap = sourcesCMName })
	mustComplete(w.t, s, err)
	return s
}

func controllerVersion(t *testing.T) string {
	t.Helper()
	v, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(v))
}

func vendoredContent() targeting.LocalContent {
	return targeting.LocalContent{Root: "../../content", Name: "konstapel-vendored", Policies: assessment.ShippedPolicies}
}

func (w *bundleWorld) open(s *Snapshot, cacheDir string) *BundleContent {
	w.t.Helper()
	bc, err := OpenContent(context.Background(), s, ContentOptions{Vendored: vendoredContent(), CacheDir: cacheDir, ControllerVersion: controllerVersion(w.t)})
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { _ = bc.Close() })
	return bc
}

func (w *bundleWorld) compare(s *Snapshot, bc *BundleContent, proposed *Set) *Comparison {
	w.t.Helper()
	c, err := Compare(context.Background(), CompareInput{Snapshot: s, Proposed: proposed, Content: bc})
	if err != nil {
		w.t.Fatal(err)
	}
	w.assertNoCredentials(c)
	return c
}

// assertNoCredentials checks that no credential value reaches a report.
func (w *bundleWorld) assertNoCredentials(v any) {
	w.t.Helper()
	raw, _ := json.Marshal(v)
	for _, form := range []string{string(raw), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v)} {
		for _, s := range w.secretValues {
			if strings.Contains(form, s) {
				w.t.Fatalf("a credential reached the output: %s", form)
			}
		}
	}
}

func contentRecord(t *testing.T, c *Comparison, name string) ContentRecord {
	t.Helper()
	for _, r := range c.Content {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no content record for %s: %+v", name, c.Content)
	return ContentRecord{}
}

func hasError(c *Comparison, code ObserveCode) bool {
	return slices.ContainsFunc(c.Errors, func(d Diagnostic) bool { return d.Code == code })
}

// 4.2/4.3: a private, organization-signed bundle resolves through the real
// stack with the registry credential and the public key the caller read by
// name; a public one anonymously. The digest is typed, no credential is in
// the report, and Kubernetes saw only reads of the referenced objects.
func TestBundleContentResolvesSignedPrivateAndPublicBundles(t *testing.T) {
	for _, tc := range []struct {
		name, repo string
		credential bool
	}{{"private", "private/valid", true}, {"public", "public/valid", false}} {
		t.Run(tc.name, func(t *testing.T) {
			w := newBundleWorld(t, tc.repo)
			if !tc.credential {
				w.setSource(tc.repo, false, w.fx.fpOrg)
			}
			s := w.observe()
			bc := w.open(s, t.TempDir())
			c := w.compare(s, bc, mustSet(t, bundleBinding("deny-prod", "org", "Audit", "production")))
			if !c.Complete || c.ImpactCount != 1 || !slices.Equal(categories(rowFor(t, c, "deny-prod", ociPolicy)), []string{"mode-changed", "revision-replaced"}) {
				t.Fatalf("%+v", c)
			}
			rec := contentRecord(t, c, ociBundle)
			if rec.DigestKind != DigestOCIManifest || !rec.Resolved || rec.Digest != w.fx.subject || rec.Repository != w.repo || rec.ErrorClass != "" {
				t.Fatalf("content record %+v", rec)
			}
			row := rowFor(t, c, "deny-prod", ociPolicy)
			if row.Before.BundleDigestKind != DigestOCIManifest || row.After.BundleDigestKind != DigestOCIManifest {
				t.Fatalf("digest kinds %+v %+v", row.Before, row.After)
			}
			if !slices.ContainsFunc(c.Limitations, func(d Diagnostic) bool { return d.Code == LimitControllerVersion }) {
				t.Fatalf("limitations %+v", c.Limitations)
			}
			var authed, anon int
			for _, r := range w.reg.log() {
				if strings.Contains(r, "/manifests/") || strings.Contains(r, "/blobs/") {
					if strings.HasSuffix(r, "auth=true") {
						authed++
					} else {
						anon++
					}
				}
			}
			if tc.credential && authed == 0 || !tc.credential && authed != 0 {
				t.Fatalf("registry requests %v", w.reg.log())
			}
			secrets := []string{keySecret}
			if tc.credential {
				secrets = append(secrets, credSecret)
			}
			assertSecretReads(t, w.api.recorded(), secrets...)
			assertNoSecretValues(t, s, w.secretValues...)
		})
	}
}

// 4.2: cached content is reused across previews only under current trust:
// a warm cache serves the pin with the registry down, and the same cache
// under a rotated publisher key is untrusted, never served.
func TestBundleContentCacheReuseRechecksCurrentTrust(t *testing.T) {
	w := newBundleWorld(t, "private/valid")
	cache := t.TempDir()
	s := w.observe()
	bc := w.open(s, cache)
	if c := w.compare(s, bc, &Set{}); !c.Complete || !contentRecord(t, c, ociBundle).Resolved {
		t.Fatalf("%+v", c)
	}
	if err := bc.Close(); err != nil {
		t.Fatal(err)
	}

	// A later preview with the registry down reuses the verified cache.
	w.reg.setDown(true)
	s = w.observe()
	bc = w.open(s, cache)
	c := w.compare(s, bc, mustSet(t, bundleBinding("deny-prod", "org", "Audit", "production")))
	if !c.Complete || !contentRecord(t, c, ociBundle).Resolved {
		t.Fatalf("warm cache: %+v", c)
	}
	_ = bc.Close()

	// The publisher rule now trusts the other key: the cached content was
	// accepted under trust that no longer holds and cannot support a
	// completed comparison of the binding that pins it. Untouched, that
	// binding is the baseline-unresolved limitation, as the controller
	// under the same trust also refuses the content.
	w.setKey(w.fx.pubOther)
	w.setSource("private/valid", true, w.fx.fpOther)
	s = w.observe()
	bc = w.open(s, cache)
	c = w.compare(s, bc, mustSet(t, bundleBinding("deny-prod", "org", "Audit", "production")))
	if rec := contentRecord(t, c, ociBundle); c.Complete || rec.Resolved || rec.ErrorClass != targeting.ContentErrorUntrusted || !hasError(c, CompareUnresolvedBaseline) {
		t.Fatalf("changed trust: %+v", c)
	}
	c = w.compare(s, bc, &Set{})
	if rec := contentRecord(t, c, ociBundle); rec.Resolved || rec.ErrorClass != targeting.ContentErrorUntrusted ||
		!slices.ContainsFunc(c.Limitations, func(d Diagnostic) bool { return d.Code == LimitBaselineUnresolved && d.Name == "deny-prod" }) {
		t.Fatalf("changed trust, untouched: %+v", c)
	}
	_ = bc.Close()
	// With the registry back, the same cache under the changed trust is
	// still not served: the fixture is not signed by the other key.
	w.reg.setDown(false)
	bc = w.open(s, cache)
	c = w.compare(s, bc, mustSet(t, bundleBinding("deny-prod", "org", "Audit", "production")))
	if c.Complete || contentRecord(t, c, ociBundle).ErrorClass != targeting.ContentErrorUntrusted {
		t.Fatalf("changed trust, registry up: %+v", c)
	}
}

// 4.2: no unsigned fallback, no other signer, no substituted bytes, no
// missing pin: each makes the comparison incomplete and nothing resolves.
func TestBundleContentRejectsUntrustedAndUnavailableContent(t *testing.T) {
	audit := func(t *testing.T) *Set { return mustSet(t, bundleBinding("deny-prod", "org", "Audit", "production")) }
	for _, tc := range []struct {
		name  string
		setup func(w *bundleWorld)
		class targeting.ContentErrorClass
	}{
		{"unsigned", func(w *bundleWorld) { w.setSource("private/unsigned", true, w.fx.fpOrg) }, targeting.ContentErrorUntrusted},
		{"wrong signer", func(w *bundleWorld) { w.setSource("private/wrong-key", true, w.fx.fpOrg) }, targeting.ContentErrorUntrusted},
		{"digest mismatch", func(w *bundleWorld) {
			w.reg.mu.Lock()
			w.reg.override["private/valid@"+w.fx.subject] = w.fx.otherManifest
			w.reg.mu.Unlock()
		}, targeting.ContentErrorContentUnavailable},
		{"unavailable pin", func(w *bundleWorld) {
			w.live(bundleProfile("org", ociBundle, godigest.FromBytes(w.fx.otherManifest).String()), "uid-org", 1)
		}, targeting.ContentErrorContentUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newBundleWorld(t, "private/valid")
			tc.setup(w)
			s := w.observe()
			bc := w.open(s, t.TempDir())
			c := w.compare(s, bc, audit(t))
			rec := contentRecord(t, c, ociBundle)
			if c.Complete || rec.Resolved || rec.ErrorClass != tc.class || !hasError(c, CompareUnresolvedCandidate) || !hasError(c, CompareUnresolvedBaseline) {
				t.Fatalf("%+v %+v", rec, c.Errors)
			}
			// Untouched by the proposal, the binding still cannot be
			// compared as resolved: a trust verdict is a baseline
			// limitation the controller shares; a retrieval failure is
			// the preview's own and makes the comparison incomplete.
			c = w.compare(s, bc, &Set{})
			switch tc.class {
			case targeting.ContentErrorUntrusted:
				if !c.Complete || !slices.ContainsFunc(c.Limitations, func(d Diagnostic) bool { return d.Code == LimitBaselineUnresolved && d.Name == "deny-prod" }) {
					t.Fatalf("%+v", c)
				}
			default:
				if c.Complete || !hasError(c, CompareContentUnavailable) {
					t.Fatalf("%+v", c)
				}
			}
		})
	}
}

// 4.3: a registry credential the caller may not read is never replaced by
// the controller's, an anonymous request or an earlier value: content from
// that source is unavailable and the comparison is incomplete, even when the
// proposal does not touch the bindings that pin it. Only Secret names, not
// values or server messages, appear in the report.
func TestBundleContentDeniedCredentialsAreIncomplete(t *testing.T) {
	for _, denied := range []string{credSecret, keySecret} {
		t.Run(denied, func(t *testing.T) {
			w := newBundleWorld(t, "private/valid")
			w.api.hook = func(rw http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path == pathSecrets(ctrlNS)+"/"+denied {
					writeStatus(rw, http.StatusForbidden, metav1.StatusReasonForbidden, `secrets "`+denied+`" is forbidden: User "reader" cannot get resource "secrets"`)
					return true
				}
				return false
			}
			s := w.observe()
			if !slices.Equal(s.Sources.UnreadSecrets, []string{denied}) {
				t.Fatalf("%+v", s.Sources)
			}
			bc := w.open(s, t.TempDir())
			for _, proposed := range []*Set{mustSet(t, bundleBinding("deny-prod", "org", "Audit", "production")), {}} {
				c := w.compare(s, bc, proposed)
				i := slices.IndexFunc(c.Errors, func(d Diagnostic) bool { return d.Code == CompareContentAccessDenied })
				if c.Complete || i < 0 || c.Errors[i].Name != ociBundle+"@"+w.fx.subject || !strings.Contains(c.Errors[i].Message, denied) ||
					strings.Contains(c.Errors[i].Message, "forbidden: User") || contentRecord(t, c, ociBundle).Resolved {
					t.Fatalf("%+v", c)
				}
			}
			for _, r := range w.reg.log() {
				if strings.HasSuffix(r, "auth=true") {
					t.Fatalf("a credential was sent although the caller could not read it: %v", w.reg.log())
				}
			}
			assertSecretReads(t, w.api.recorded(), credSecret, keySecret)
		})
	}
	// A credential the caller can read but the registry refuses: no
	// anonymous retry succeeds, and the value is never echoed.
	w := newBundleWorld(t, "private/valid")
	w.api.put(pathSecrets(ctrlNS), &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: credSecret}, Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{corev1.DockerConfigJsonKey: w.dockerConfig(w.reg.user, "wrong-"+w.reg.pass)}})
	w.secretValues = append(w.secretValues, "wrong-"+w.reg.pass)
	s := w.observe()
	bc := w.open(s, t.TempDir())
	if c := w.compare(s, bc, &Set{}); c.Complete || !hasError(c, CompareContentUnavailable) {
		t.Fatalf("%+v", c)
	}
}

// 4.1: the vendored bundle is served without the bundle stack, a cache, a
// provider or a manager; its digest is the checksum-manifest digest, typed
// apart from OCI manifest digests in the same report; and a corrupted local
// tree fails instead of serving.
func TestBundleContentVendoredChecksumTree(t *testing.T) {
	sums, err := os.ReadFile("../../content/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	vendoredDigest := "sha256:" + sha256Hex(sums)
	f := baseline(t)
	f.remove(pathBindings, "b-dev")
	f.remove(pathBindings, "b-prod")
	f.remove(pathProfiles, "shared")
	w := &bundleWorld{t: t, api: f}
	w.live(bundleProfile("vendored", "konstapel-vendored", vendoredDigest), "uid-vendored", 1)
	w.live(bundleBinding("deny-prod", "vendored", "Deny", "production"), "uid-deny-prod", 1)
	s, err := observe(t, f, nil)
	mustComplete(t, s, err)

	tmpBefore, _ := filepath.Glob(filepath.Join(os.TempDir(), "konstapel-preview-cache-*"))
	if _, err := OpenContent(context.Background(), s, ContentOptions{Vendored: vendoredContent(), CacheDir: t.TempDir()}); err == nil {
		t.Fatal("a cache was accepted without bundle sources")
	}
	bc, err := OpenContent(context.Background(), s, ContentOptions{Vendored: vendoredContent()})
	if err != nil {
		t.Fatal(err)
	}
	defer bc.Close()
	if bc.st != nil || bc.tmp != "" {
		t.Fatal("the vendored-only content source assembled the bundle stack")
	}
	if tmpAfter, _ := filepath.Glob(filepath.Join(os.TempDir(), "konstapel-preview-cache-*")); len(tmpAfter) != len(tmpBefore) {
		t.Fatal("the vendored-only content source created a cache directory")
	}
	c := w.compare(s, bc, mustSet(t, bundleBinding("deny-prod", "vendored", "Audit", "production")))
	if !c.Complete || c.ImpactCount != 1 {
		t.Fatalf("%+v", c)
	}
	rec := contentRecord(t, c, "konstapel-vendored")
	if rec.DigestKind != DigestVendoredChecksum || !rec.Resolved || rec.Digest != vendoredDigest || rec.Repository != "" {
		t.Fatalf("%+v", rec)
	}
	if row := rowFor(t, c, "deny-prod", ociPolicy); row.Before.BundleDigestKind != DigestVendoredChecksum {
		t.Fatalf("%+v", row.Before)
	}
	// An OCI pin without bundle sources is typed as an OCI manifest digest
	// and is unavailable, never served from the vendored tree.
	c = w.compare(s, bc, mustSet(t, bundleProfile("vendored", ociBundle, vendoredDigest)))
	if rec := contentRecord(t, c, ociBundle); c.Complete || rec.DigestKind != DigestOCIManifest || rec.Resolved || rec.ErrorClass != targeting.ContentErrorConfig {
		t.Fatalf("%+v", c.Content)
	}
	if rec := contentRecord(t, c, "konstapel-vendored"); rec.DigestKind != DigestVendoredChecksum || !rec.Resolved {
		t.Fatalf("%+v", c.Content)
	}

	// A live profile pinned to another release's vendored digest: this
	// installation cannot serve or verify it, so even untouched it is not a
	// known baseline condition.
	other := &bundleWorld{t: t, api: baseline(t)}
	other.api.remove(pathBindings, "b-dev")
	other.api.remove(pathBindings, "b-prod")
	other.api.remove(pathProfiles, "shared")
	other.live(bundleProfile("vendored", "konstapel-vendored", "sha256:"+strings.Repeat("9", 64)), "uid-vendored", 1)
	other.live(bundleBinding("deny-prod", "vendored", "Deny", "production"), "uid-deny-prod", 1)
	os2, err := observe(t, other.api, nil)
	mustComplete(t, os2, err)
	c = other.compare(os2, bc, &Set{})
	if rec := contentRecord(t, c, "konstapel-vendored"); c.Complete || !hasError(c, CompareContentUnavailable) || rec.Resolved || rec.DigestKind != DigestVendoredChecksum {
		t.Fatalf("another release's vendored digest: %+v", c)
	}

	// A corrupted copy of the tree: SHA256SUMS still hashes to the pin,
	// one listed file does not match it.
	root := corruptCopy(t, "../../content", assessment.SourcePolicy)
	corrupt := targeting.LocalContent{Root: root, Name: "konstapel-vendored", Policies: assessment.ShippedPolicies}
	bad, err := OpenContent(context.Background(), s, ContentOptions{Vendored: corrupt})
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	for _, proposed := range []*Set{mustSet(t, bundleBinding("deny-prod", "vendored", "Audit", "production")), {}} {
		c = w.compare(s, bad, proposed)
		rec := contentRecord(t, c, "konstapel-vendored")
		if c.Complete || rec.Resolved || rec.DigestKind != DigestVendoredChecksum || rec.Digest != vendoredDigest ||
			!strings.Contains(rec.Error, assessment.SourcePolicy+" does not match SHA256SUMS") ||
			!(hasError(c, CompareUnresolvedCandidate) || hasError(c, CompareContentUnavailable)) {
			t.Fatalf("corrupted tree: %+v", c)
		}
	}
}

// corruptCopy mirrors a content tree with symbolic links, except that the
// file at corrupted (a SHA256SUMS path) is a copy with one byte changed.
func corruptCopy(t *testing.T, root, corrupted string) string {
	t.Helper()
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "content")
	sums, err := os.ReadFile(filepath.Join(abs, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "SHA256SUMS"), sums, 0o644); err != nil {
		t.Fatal(err)
	}
	base, dstBase := filepath.Dir(abs), filepath.Dir(dst)
	found := false
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		_, p, _ := strings.Cut(line, "  ")
		to := filepath.Join(dstBase, p)
		if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
			t.Fatal(err)
		}
		if p != corrupted {
			if err := os.Symlink(filepath.Join(base, p), to); err != nil {
				t.Fatal(err)
			}
			continue
		}
		found = true
		b, err := os.ReadFile(filepath.Join(base, p))
		if err != nil {
			t.Fatal(err)
		}
		b = bytes.Replace(b, []byte("privileged"), []byte("Privileged"), 1)
		if err := os.WriteFile(to, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if !found {
		t.Fatalf("%s is not listed in SHA256SUMS", corrupted)
	}
	return dst
}

// The bundle stack reads nothing from the cluster itself: it is served the
// observed values, an unobserved object is an error rather than a live
// read, and nothing is listed.
func TestSnapshotReaderServesOnlyObservedObjects(t *testing.T) {
	w := newBundleWorld(t, "private/valid")
	s := w.observe()
	r := snapshotReader{in: s.inputs}
	ctx := context.Background()
	var sec corev1.Secret
	if err := r.Get(ctx, objectKey(ctrlNS, credSecret), &sec); err != nil || sec.Type != corev1.SecretTypeDockerConfigJson || len(sec.Data) != 1 {
		t.Fatalf("%v %v", err, sec.Type)
	}
	var cm corev1.ConfigMap
	if err := r.Get(ctx, objectKey(ctrlNS, sourcesCMName), &cm); err != nil || cm.Data[bundle.SourcesConfigKey] == "" {
		t.Fatal(err)
	}
	for _, k := range []struct{ ns, name string }{{ctrlNS, "unrelated"}, {"default", credSecret}} {
		if err := r.Get(ctx, objectKey(k.ns, k.name), &corev1.Secret{}); err == nil {
			t.Fatalf("served unobserved %s/%s", k.ns, k.name)
		}
	}
	// A denied or missing Secret is never served, not even empty.
	denied := snapshotReader{in: &sourceInputs{namespace: ctrlNS, objects: map[string]*sourceObject{
		"Secret/denied": {access: SecretDenied}, "Secret/missing": {access: SecretMissing}}}}
	if err := denied.Get(ctx, objectKey(ctrlNS, "denied"), &corev1.Secret{}); !apierrors.IsForbidden(err) {
		t.Fatalf("denied Secret: %v", err)
	}
	if err := denied.Get(ctx, objectKey(ctrlNS, "missing"), &corev1.Secret{}); !apierrors.IsNotFound(err) {
		t.Fatalf("missing Secret: %v", err)
	}
	if err := r.List(ctx, &corev1.SecretList{}); err == nil {
		t.Fatal("listed")
	}
	before := len(w.api.recorded())
	bc := w.open(s, t.TempDir())
	_ = w.compare(s, bc, &Set{})
	if after := len(w.api.recorded()); after != before {
		t.Fatalf("the bundle content sent %d Kubernetes requests", after-before)
	}
	if v := fmt.Sprintf("%v %+v %#v", s.inputs, s.inputs, s); strings.Contains(v, w.reg.pass) {
		t.Fatal("inputs are not redacted")
	}
	if raw, _ := json.Marshal(struct{ In *sourceInputs }{s.inputs}); strings.Contains(string(raw), w.reg.pass) {
		t.Fatal("inputs serialize")
	}
	if _, err := OpenContent(ctx, s, ContentOptions{Vendored: vendoredContent()}); err == nil {
		t.Fatal("OCI content without a controller release was accepted")
	}
	if _, err := OpenContent(ctx, &Snapshot{}, ContentOptions{Vendored: vendoredContent()}); err == nil {
		t.Fatal("an incomplete observation was accepted")
	}
}

var specsV2 = specs.Versioned{SchemaVersion: 2}

func objectKey(ns, name string) client.ObjectKey { return client.ObjectKey{Namespace: ns, Name: name} }
