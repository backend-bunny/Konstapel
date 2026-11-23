//go:build live

package controller

// Live acceptance of the `konstapel preview` command itself
// (add-policy-change-preview 7.1 and 7.2), in the bundles acceptance group:
// the shared-profile pin change and the trust change need the
// organization-key OCI fixture on the disposable TLS registry.
//
// The binary is built from this checkout as scripts/build.sh builds it and
// runs as its own process with a CI-style kubeconfig: a ServiceAccount token
// bound only to docs/examples/policy-preview/reader-rbac.yaml. An exec'd
// binary cannot use the in-process wire recorder of preview_live_test.go,
// and the kind cluster has no audit policy, so the kubeconfig's only server
// is a loopback TLS reverse proxy. It relays each request unchanged (the
// bearer token included, no credential of its own) to the API server and
// records method, URI and status, never headers. Around every invocation
// each ComplianceProfile, ComplianceBinding, ComplianceException,
// Konstapel-owned ValidatingPolicy, and ConfigMap and Secret of the
// controller namespace must keep its resourceVersion. The in-process
// controller delivers the state and is stopped for the invocations, so
// nothing else writes those objects meanwhile.
//
// Not covered here, because nothing in 0.3.0 provides it: exception
// acceptance consequences (renewal, newly forbidden, lifetime), which
// depend on add-self-service-policy-exceptions; an admission-recorded
// revocation (the exception admission webhooks run only in the assessments
// group); and stale owner evidence, which needs a real assessment to age
// past maxEvidenceAge.

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/preview"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const (
	pcliNS      = "preview-cli-system" // the controller namespace
	pcliCI      = "preview-cli-ci"     // the CI ServiceAccounts' namespace
	pcliEnv     = "preview-cli-test.konstapel.dev/environment"
	pcliDrift   = "preview-cli-test.konstapel.dev/drift"
	pcliProfile = "preview-cli-shared"
	pcliDeny    = "preview-cli-deny"
	pcliAudit   = "preview-cli-audit"
	pcliLate    = "preview-cli-late"
	pcliProd    = "preview-cli-prod"
	pcliStaging = "preview-cli-staging"
	pcliDev     = "preview-cli-dev"
)

// pcliRequest is one request the binary sent, as relayed to the API server.
// Headers, and so the bearer token, are never recorded.
type pcliRequest struct {
	Step   string `json:"step"`
	Method string `json:"method"`
	URI    string `json:"uri"`
	Status int    `json:"status"`
}

type pcliProxy struct {
	srv *httptest.Server
	// inflight counts relayed requests; end waits for them, so a request
	// whose response the binary read just before exiting is logged.
	inflight sync.WaitGroup
	mu       sync.Mutex
	step     string
	log      []pcliRequest
	hook     func(*http.Request)
}

type pcliStatus struct {
	http.ResponseWriter
	code int
}

func (s *pcliStatus) WriteHeader(code int)        { s.code = code; s.ResponseWriter.WriteHeader(code) }
func (s *pcliStatus) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// startPCLIProxy relays to the live API server over TLS with no credential
// of its own: what the API server authorizes is the caller's token.
func (l *live) startPCLIProxy() *pcliProxy {
	l.t.Helper()
	upstream, err := url.Parse(l.cfg.Host)
	if err != nil {
		l.t.Fatal(err)
	}
	tr, err := rest.TransportFor(&rest.Config{Host: l.cfg.Host, TLSClientConfig: rest.TLSClientConfig{
		CAData: l.cfg.CAData, CAFile: l.cfg.CAFile, ServerName: l.cfg.ServerName}})
	if err != nil {
		l.t.Fatal(err)
	}
	p := &pcliProxy{}
	rp := &httputil.ReverseProxy{Transport: tr, Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(upstream) }}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.inflight.Add(1)
		defer p.inflight.Done()
		p.mu.Lock()
		step, hook := p.step, p.hook
		p.mu.Unlock()
		if hook != nil {
			hook(r)
		}
		sw := &pcliStatus{ResponseWriter: w, code: http.StatusOK}
		rp.ServeHTTP(sw, r)
		p.mu.Lock()
		p.log = append(p.log, pcliRequest{Step: step, Method: r.Method, URI: r.URL.RequestURI(), Status: sw.code})
		p.mu.Unlock()
	}))
	l.t.Cleanup(p.srv.Close)
	return p
}

func (p *pcliProxy) begin(step string) { p.mu.Lock(); p.step = step; p.mu.Unlock() }

func (p *pcliProxy) end(step string) []pcliRequest {
	p.inflight.Wait()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.step = ""
	var out []pcliRequest
	for _, r := range p.log {
		if r.Step == step {
			out = append(out, r)
		}
	}
	return out
}

func (p *pcliProxy) setHook(h func(*http.Request)) { p.mu.Lock(); p.hook = h; p.mu.Unlock() }

// kubeconfig writes a CI-style kubeconfig for a ServiceAccount token whose
// only server is the proxy. It is test-private, never in the output.
func (p *pcliProxy) kubeconfig(t *testing.T, name, token string) string {
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["preview-live"] = &clientcmdapi.Cluster{Server: p.srv.URL,
		CertificateAuthorityData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.srv.Certificate().Raw})}
	cfg.AuthInfos[name] = &clientcmdapi.AuthInfo{Token: token}
	cfg.Contexts[name] = &clientcmdapi.Context{Cluster: "preview-live", AuthInfo: name}
	cfg.CurrentContext = name
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := clientcmd.WriteToFile(*cfg, path); err != nil {
		t.Fatal(err)
	}
	return path
}

// pcliAllowed is every path the documented access contract permits: the
// three discovery documents, the listed collections, the cluster identity,
// ConfigMaps of the controller namespace, and named gets of the two Secrets
// the bundle-source ConfigMap references.
var pcliAllowed = []*regexp.Regexp{
	regexp.MustCompile(`^/api/v1$`),
	regexp.MustCompile(`^/apis/compliance\.erenius\.io/v1alpha1$`),
	regexp.MustCompile(`^/apis/policies\.kyverno\.io/v1$`),
	regexp.MustCompile(`^/api/v1/namespaces(/kube-system)?$`),
	regexp.MustCompile(`^/apis/compliance\.erenius\.io/v1alpha1/(complianceprofiles|compliancebindings|complianceexceptions)$`),
	regexp.MustCompile(`^/apis/policies\.kyverno\.io/v1/validatingpolicies$`),
	regexp.MustCompile(`^/api/v1/namespaces/` + pcliNS + `/configmaps(/[a-z0-9.-]+)?$`),
	regexp.MustCompile(`^/api/v1/namespaces/` + pcliNS + `/secrets/(` + obCredSecret + `|` + obKeySecret + `)$`),
}

func pcliAssertWire(t *testing.T, step string, reqs []pcliRequest) {
	t.Helper()
	if len(reqs) == 0 {
		t.Fatalf("%s: the binary sent no request through the recording proxy", step)
	}
	for _, r := range reqs {
		u, err := url.ParseRequestURI(r.URI)
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		q := u.Query()
		allowed := slices.ContainsFunc(pcliAllowed, func(re *regexp.Regexp) bool { return re.MatchString(u.Path) })
		if r.Method != http.MethodGet || !allowed || q.Has("watch") || q.Has("dryRun") || strings.Contains(u.Path, "/watch/") ||
			(strings.Contains(u.Path, "/secrets/") && u.RawQuery != "") {
			t.Fatalf("%s: the preview sent a request outside its read-only contract: %s %s", step, r.Method, r.URI)
		}
	}
}

// pcliVersions is the resourceVersion of every object a preview must not
// change, read as metadata only (no Secret data is fetched).
func (l *live) pcliVersions() map[string]string {
	l.t.Helper()
	out := map[string]string{}
	for _, k := range []struct {
		gvk  schema.GroupVersionKind
		opts []client.ListOption
	}{
		{v1alpha1.GroupVersion.WithKind("ComplianceProfileList"), nil},
		{v1alpha1.GroupVersion.WithKind("ComplianceBindingList"), nil},
		{v1alpha1.GroupVersion.WithKind("ComplianceExceptionList"), nil},
		{targeting.ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"), []client.ListOption{client.MatchingLabels{targeting.LabelManagedBy: targeting.ManagedByValue}}},
		{corev1.SchemeGroupVersion.WithKind("ConfigMapList"), []client.ListOption{client.InNamespace(pcliNS)}},
		{corev1.SchemeGroupVersion.WithKind("SecretList"), []client.ListOption{client.InNamespace(pcliNS)}},
	} {
		list := &metav1.PartialObjectMetadataList{}
		list.SetGroupVersionKind(k.gvk)
		if err := l.c.List(l.ctx, list, k.opts...); err != nil {
			l.t.Fatal(err)
		}
		for _, o := range list.Items {
			out[strings.TrimSuffix(k.gvk.Kind, "List")+" "+o.Namespace+"/"+o.Name] = o.ResourceVersion
		}
	}
	return out
}

// pcliSettle waits until no tracked object changes for five seconds.
func (l *live) pcliSettle() {
	l.t.Helper()
	prev := l.pcliVersions()
	l.eventually("tracked objects settled", func() (bool, string) {
		time.Sleep(5 * time.Second)
		cur := l.pcliVersions()
		same := maps.Equal(prev, cur)
		prev = cur
		return same, "still changing"
	})
}

// startPCLIManager runs the in-process controller as cmd/konstapel wires it
// for this installation: bundle sources and acceptance snapshots in pcliNS.
func (l *live) startPCLIManager(cacheDir string) (stop func()) {
	l.t.Helper()
	ver, err := os.ReadFile("../../VERSION")
	if err != nil {
		l.t.Fatal(err)
	}
	mgr, err := NewManager(l.cfg, Options{Content: content, LocalBundle: content.Name, MetricsAddr: "0", ProbeAddr: "0",
		EnginePoll: 2 * time.Second, SkipControllerNameValidation: true, SnapshotNamespace: pcliNS,
		Bundles: stack.Options{SourcesConfigMap: obSourcesCM, Namespace: pcliNS, CacheDir: cacheDir,
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

func (l *live) pcliBindSA(name, sa string, role rbacv1.RoleRef, namespace string) {
	subjects := []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: sa, Namespace: pcliCI}}
	var o client.Object
	if namespace == "" {
		o = &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name}, Subjects: subjects, RoleRef: role}
	} else {
		o = &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Subjects: subjects, RoleRef: role}
	}
	if err := l.c.Create(l.ctx, o); err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { _ = l.c.Delete(l.ctx, o) })
}

type pcliRun struct {
	code   int
	report *preview.Report
	stdout []byte
	reqs   []pcliRequest
}

type pcliScenario struct {
	l       *live
	t       *testing.T
	bin     string
	content string
	proxy   *pcliProxy
	dir     string
	secrets []string
}

// run invokes the binary once and checks what holds for every invocation:
// only documented reads on the wire, no tracked object changed, nothing
// secret in the output, and, for JSON, exactly one report v1 on stdout
// whose completeness and impacts determine the documented exit status.
func (s *pcliScenario) run(step, kubeconfig string, args ...string) pcliRun {
	s.t.Helper()
	before := s.l.pcliVersions()
	s.proxy.begin(step)
	cmd := exec.CommandContext(s.l.ctx, s.bin, append([]string{"preview", "--kubeconfig", kubeconfig,
		"--controller-namespace", pcliNS, "--bundle-sources-configmap", obSourcesCM, "--content-root", s.content}, args...)...)
	// No ambient kubeconfig or Docker credentials can be picked up.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + s.t.TempDir()}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err := cmd.Run()
	took := time.Since(start)
	reqs := s.proxy.end(step)
	res := pcliRun{stdout: stdout.Bytes(), reqs: reqs}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		res.code = exit.ExitCode()
	case err != nil:
		s.t.Fatalf("%s: run the preview: %v", step, err)
	}
	pcliAssertWire(s.t, step, reqs)
	if after := s.l.pcliVersions(); !maps.Equal(before, after) {
		var changed []string
		for k := range maps.Keys(before) {
			if after[k] != before[k] {
				changed = append(changed, k)
			}
		}
		for k := range maps.Keys(after) {
			if _, ok := before[k]; !ok {
				changed = append(changed, k+" (new)")
			}
		}
		s.t.Fatalf("%s: objects changed around the preview: %v", step, changed)
	}
	for _, v := range s.secrets {
		if bytes.Contains(stdout.Bytes(), []byte(v)) || bytes.Contains(stderr.Bytes(), []byte(v)) {
			s.t.Fatalf("%s: a credential reached the preview's output", step)
		}
	}
	jsonOut := slices.Contains(args, "json")
	ext := ".txt"
	if jsonOut {
		ext = ".json"
	}
	for name, b := range map[string][]byte{step + ext: stdout.Bytes(), step + ".stderr.txt": stderr.Bytes()} {
		if err := os.WriteFile(filepath.Join(s.dir, name), b, 0o644); err != nil {
			s.t.Fatal(err)
		}
	}
	rec := map[string]any{"exit": res.code, "requests": len(reqs), "durationMs": took.Milliseconds(), "args": pcliArgs(args)}
	if jsonOut {
		dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
		r := &preview.Report{}
		if err := dec.Decode(r); err != nil {
			s.t.Fatalf("%s: stdout is not a JSON report: %v\n%s", step, err, stderr.String())
		}
		if _, err := dec.Token(); err != io.EOF {
			s.t.Fatalf("%s: stdout holds more than the report", step)
		}
		if r.Kind != preview.ReportKind || r.SchemaVersion != preview.ReportSchemaVersion {
			s.t.Fatalf("%s: report %s v%d", step, r.Kind, r.SchemaVersion)
		}
		want := 0
		switch {
		case !r.Complete:
			want = 1
		case slices.Contains(args, "--fail-on-impact") && r.ImpactCount > 0:
			want = 2
		}
		if res.code != want {
			s.t.Fatalf("%s: exit %d for complete=%v impactCount=%d (documented: %d)\n%s", step, res.code, r.Complete, r.ImpactCount, want, stderr.String())
		}
		res.report = r
		rec["complete"], rec["impactCount"], rec["categories"] = r.Complete, r.ImpactCount, r.Summary.Categories
		rec["errors"], rec["limitations"] = pcliCodes(r.Errors), pcliCodes(r.Limitations)
		if r.Observation != nil {
			rec["captures"], rec["drift"] = r.Observation.Captures, len(r.Observation.Drift)
		}
	}
	s.l.record("preview-cli-"+step, rec)
	return res
}

// pcliArgs keeps the flags of an invocation without its temporary paths.
func pcliArgs(args []string) []string {
	out := slices.Clone(args)
	for i, a := range out {
		if filepath.IsAbs(a) {
			out[i] = filepath.Base(a)
		}
	}
	return out
}

func pcliCodes(ds []preview.ReportDiagnostic) []string {
	var out []string
	for _, d := range ds {
		out = append(out, string(d.Code))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func pcliHasCode(ds []preview.ReportDiagnostic, code preview.ObserveCode) bool {
	return slices.ContainsFunc(ds, func(d preview.ReportDiagnostic) bool { return d.Code == code })
}

func pcliRow(r *preview.Report, binding string) *preview.ContributionChange {
	if r.Changes == nil {
		return nil
	}
	for i := range r.Changes.Contributions {
		if c := &r.Changes.Contributions[i]; c.Key.Binding == binding && c.Key.Policy == pol {
			return c
		}
	}
	return nil
}

func pcliNamespaceRow(r *preview.Report, ns string) *preview.NamespaceChange {
	if r.Changes == nil {
		return nil
	}
	for i := range r.Changes.Namespaces {
		if c := &r.Changes.Namespaces[i]; c.Namespace.Name == ns && c.Policy == pol {
			return c
		}
	}
	return nil
}

func pcliHas(is []preview.Impact, want ...preview.Category) bool {
	for _, w := range want {
		if !slices.ContainsFunc(is, func(i preview.Impact) bool { return i.Category == w }) {
			return false
		}
	}
	return true
}

func pcliContributor(cs []preview.ContributorRef, binding string) bool {
	return slices.ContainsFunc(cs, func(c preview.ContributorRef) bool { return c.Binding == binding })
}

func pcliContent(r *preview.Report, name string) *preview.ContentRecord {
	for i := range r.Content {
		if r.Content[i].Name == name {
			return &r.Content[i]
		}
	}
	return nil
}

func pcliBindingEvidence(r *preview.Report, binding string) *preview.BindingEvidence {
	for i := range r.Evidence.Bindings {
		if r.Evidence.Bindings[i].Binding == binding {
			return &r.Evidence.Bindings[i]
		}
	}
	return nil
}

func pcliBindingYAML(name, env, mode string) string {
	return fmt.Sprintf(`apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceBinding
metadata:
  name: %s
spec:
  profileRef:
    name: %s
  namespaceSelector:
    matchLabels:
      %s: %s
  mode: %s
`, name, pcliProfile, pcliEnv, env, mode)
}

func TestLivePolicyPreviewCLI(t *testing.T) {
	l := newLive(t)
	l.installCRDs()
	f := loadOBFixture(t)
	reg := startOBRegistry(t, l)
	publishFixture(t, l, reg, f, "org/valid/"+obBundle, "org/mirror/"+obBundle)
	vendored := digest(t)
	dir := filepath.Join(l.out, "preview-cli")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	// The installation: namespaces, the documented private source with the
	// controller's names, one shared profile and two bindings that use it.
	nsUID := map[string]types.UID{}
	for _, n := range []struct{ name, env string }{{pcliNS, ""}, {pcliCI, ""}, {pcliProd, "production"}, {pcliStaging, "staging"}, {pcliDev, "development"}} {
		o := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n.name}}
		if n.env != "" {
			o.Labels = map[string]string{pcliEnv: n.env}
		}
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(l.ctx, o) })
		nsUID[n.name] = o.UID
	}
	sourcesCM := func(fp string) *corev1.ConfigMap {
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: pcliNS, Name: obSourcesCM},
			Data: map[string]string{"sources.yaml": obSourcesYAML(t, obSource(f, reg.host+"/org/valid/"+obBundle, fp))}}
	}
	keySecret := func(pub []byte) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: pcliNS, Name: obKeySecret}, Data: map[string][]byte{"cosign.pub": pub}}
	}
	for _, o := range []client.Object{
		sourcesCM(f.fpOrg),
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: pcliNS, Name: obCAConfig}, Data: map[string]string{"ca.crt": string(reg.caPEM)}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: pcliNS, Name: obCredSecret}, Type: corev1.SecretTypeDockerConfigJson,
			Data: map[string][]byte{corev1.DockerConfigJsonKey: obDockerConfig(reg.host, "reader-a", reg.users["reader-a"])}},
		keySecret(f.pubOrg),
		// Not referenced: never requested.
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: pcliNS, Name: obDecoy}, Data: map[string][]byte{"k": []byte(reg.users["reader-b"])}},
	} {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(l.ctx, o) })
	}
	p := &v1alpha1.ComplianceProfile{ObjectMeta: metav1.ObjectMeta{Name: pcliProfile},
		Spec: v1alpha1.ComplianceProfileSpec{Bundle: v1alpha1.BundleReference{Name: content.Name, Digest: vendored}, Policies: []v1alpha1.ProfilePolicy{{Name: pol}}}}
	deny := bindingObj(pcliDeny, pcliProfile, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{pcliEnv: "production"})
	audit := bindingObj(pcliAudit, pcliProfile, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{pcliEnv: "development"})
	var created []client.Object
	for _, o := range []client.Object{p, deny, audit} {
		o.SetUID("")
		o.SetGeneration(0)
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
		created = append(created, o)
	}
	ownedBy := map[types.UID]bool{}
	t.Cleanup(func() {
		// Bindings before the profile; then no policy of them may remain.
		for _, o := range slices.Backward(created) {
			_ = l.c.Delete(l.ctx, o)
		}
		l.eventually("preview-cli policies removed", func() (bool, string) {
			list := &unstructured.UnstructuredList{}
			list.SetGroupVersionKind(targeting.ValidatingPolicyGVK.GroupVersion().WithKind("ValidatingPolicyList"))
			if err := l.c.List(l.ctx, list, client.MatchingLabels{targeting.LabelManagedBy: targeting.ManagedByValue}); err != nil {
				return false, err.Error()
			}
			for _, o := range list.Items {
				for _, ref := range o.GetOwnerReferences() {
					if ownedBy[ref.UID] {
						return false, o.GetName()
					}
				}
			}
			return true, ""
		})
	})

	// The controller delivers real engine policies and the owners record
	// their status; then it stops, so only a preview could write.
	stop := l.startPCLIManager(t.TempDir())
	denyB, auditB := l.waitReady(pcliDeny, 1), l.waitReady(pcliAudit, 1)
	ownedBy[denyB.UID], ownedBy[auditB.UID] = true, true
	l.eventually("current evidence recorded", func() (bool, string) {
		for _, n := range []string{pcliDeny, pcliAudit} {
			if b := l.binding(n); b.Status.Assessment == nil || b.Status.Assessment.Current == nil {
				return false, n + ": " + toJSON(b.Status.Assessment)
			}
		}
		return true, ""
	})
	l.pcliSettle()
	stop()
	l.record("delivered", map[string]any{"bindings": []string{pcliDeny + "@" + string(denyB.UID), pcliAudit + "@" + string(auditB.UID)}, "policies": len(l.managedPolicies())})

	// Three CI identities: the documented reader RBAC with the optional
	// Secret Role, without it, and the ClusterRole alone.
	l.applyManifests("../../docs/examples/policy-preview/reader-rbac.yaml", func(u *unstructured.Unstructured) {
		if u.GetKind() == "Role" {
			u.SetNamespace(pcliNS)
		}
	})
	const full, noSecrets, clusterOnly = "preview-ci", "preview-ci-no-secrets", "preview-ci-cluster-only"
	clusterRole := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-policy-preview-reader"}
	readerRole := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "konstapel-policy-preview-reader"}
	secretRole := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "konstapel-policy-preview-bundle-secrets"}
	tokens := map[string]string{}
	for sa, roles := range map[string][]rbacv1.RoleRef{full: {clusterRole, readerRole, secretRole}, noSecrets: {clusterRole, readerRole}, clusterOnly: {clusterRole}} {
		o := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: pcliCI, Name: sa}}
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(l.ctx, o) })
		for _, r := range roles {
			ns := ""
			if r.Kind == "Role" {
				ns = pcliNS
			}
			l.pcliBindSA(sa+"-"+r.Name, sa, r, ns)
		}
		tokens[sa] = l.apiToken(pcliCI, sa)
	}
	user := func(sa string) string { return "system:serviceaccount:" + pcliCI + ":" + sa }
	for _, a := range []authzv1.ResourceAttributes{
		{Verb: "create", Group: "compliance.erenius.io", Resource: "compliancebindings"},
		{Verb: "patch", Group: "compliance.erenius.io", Resource: "complianceprofiles"},
		{Verb: "update", Group: "compliance.erenius.io", Resource: "complianceexceptions", Namespace: pcliProd},
		{Verb: "delete", Group: "policies.kyverno.io", Resource: "validatingpolicies"},
		{Verb: "create", Resource: "configmaps", Namespace: pcliNS},
		{Verb: "watch", Group: "compliance.erenius.io", Resource: "compliancebindings"},
		{Verb: "list", Resource: "secrets", Namespace: pcliNS},
		{Verb: "get", Resource: "secrets", Namespace: pcliNS, Name: obDecoy},
	} {
		if l.can(user(full), a) {
			t.Fatalf("the preview identity may %s %s", a.Verb, a.Resource)
		}
	}
	l.eventually("reader RBAC effective", func() (bool, string) {
		ok := l.can(user(full), authzv1.ResourceAttributes{Verb: "list", Group: "policies.kyverno.io", Resource: "validatingpolicies"}) &&
			l.can(user(full), authzv1.ResourceAttributes{Verb: "get", Resource: "secrets", Namespace: pcliNS, Name: obCredSecret}) &&
			l.can(user(noSecrets), authzv1.ResourceAttributes{Verb: "list", Resource: "configmaps", Namespace: pcliNS}) &&
			l.can(user(clusterOnly), authzv1.ResourceAttributes{Verb: "list", Group: "compliance.erenius.io", Resource: "complianceexceptions"})
		return ok, "bindings not yet effective"
	})
	if l.can(user(noSecrets), authzv1.ResourceAttributes{Verb: "get", Resource: "secrets", Namespace: pcliNS, Name: obCredSecret}) ||
		l.can(user(clusterOnly), authzv1.ResourceAttributes{Verb: "list", Resource: "configmaps", Namespace: pcliNS}) {
		t.Fatal("a reduced identity has more than its roles")
	}

	// The binary, built as scripts/build.sh builds it.
	ver, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	bin := filepath.Join(work, "konstapel")
	buildStart := time.Now()
	if out, err := exec.CommandContext(l.ctx, "go", "build", "-mod=readonly", "-ldflags", "-X main.version="+strings.TrimSpace(string(ver)),
		"-o", bin, "../../cmd/konstapel").CombinedOutput(); err != nil {
		t.Fatalf("build konstapel: %v\n%s", err, out)
	}
	contentRoot, err := filepath.Abs("../../content")
	if err != nil {
		t.Fatal(err)
	}
	proxy := l.startPCLIProxy()
	kc := map[string]string{}
	for sa, tok := range tokens {
		kc[sa] = proxy.kubeconfig(t, sa, tok)
	}
	s := &pcliScenario{l: l, t: t, bin: bin, content: contentRoot, proxy: proxy, dir: dir,
		secrets: []string{tokens[full], tokens[noSecrets], tokens[clusterOnly], reg.users["reader-a"], reg.users["reader-b"]}}
	l.record("built", map[string]any{"version": strings.TrimSpace(string(ver)), "buildMs": time.Since(buildStart).Milliseconds()})
	input := func(name, body string) string {
		path := filepath.Join(work, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	restateDeny := input("restate-deny.yaml", pcliBindingYAML(pcliDeny, "production", "Deny"))
	moveDeny := input("move-deny.yaml", pcliBindingYAML(pcliDeny, "staging", "Deny"))
	auditToDeny := input("audit-to-deny.yaml", pcliBindingYAML(pcliAudit, "development", "Deny"))
	pinOCI := input("pin-oci.yaml", fmt.Sprintf(`apiVersion: compliance.erenius.io/v1alpha1
kind: ComplianceProfile
metadata:
  name: %s
spec:
  bundle:
    name: %s
    digest: %s
  policies:
    - name: %s
`, pcliProfile, obBundle, f.subject, pol))
	empty := input("empty.yaml", "")
	cache := t.TempDir()
	ref := func(ns string) targeting.NamespaceRef { return targeting.NamespaceRef{Name: ns, UID: nsUID[ns]} }

	// 7.1: complete previews. Exit 0 informational, 2 with --fail-on-impact
	// when there are impacts, 0 either way when there are none.
	noop := s.run("no-op", kc[full], "-f", restateDeny, "--format", "json")
	if r := noop.report; noop.code != 0 || !r.Complete || r.ImpactCount != 0 || len(r.Changes.Contributions) != 0 ||
		r.Observation.Captures != 2 || len(r.Observation.Drift) != 0 || r.Observation.Context != full ||
		r.Evidence.Analysis != preview.AnalysisAvailable || pcliBindingEvidence(r, pcliDeny) == nil {
		t.Fatalf("no-op: %s", noop.stdout)
	}
	if res := s.run("no-op-fail-on-impact", kc[full], "-f", restateDeny, "--format", "json", "--fail-on-impact"); res.code != 0 {
		t.Fatalf("no-op with --fail-on-impact: exit %d", res.code)
	}

	// Namespace expansion and removal: Deny moves from prod to staging.
	sel := s.run("selector", kc[full], "-f", moveDeny, "--format", "json")
	if r, row := sel.report, pcliRow(sel.report, pcliDeny); sel.code != 0 || !r.Complete || r.ImpactCount == 0 || row == nil ||
		row.Change != preview.ChangeChanged || row.RevisionEffect != preview.RevisionReplacement ||
		!pcliHas(row.Impacts, preview.CategorySelector, preview.CategoryNamespaceAdded, preview.CategoryNamespaceRemoved, preview.CategoryRevision) ||
		!slices.Equal(row.NamespacesAdded, []targeting.NamespaceRef{ref(pcliStaging)}) || !slices.Equal(row.NamespacesRemoved, []targeting.NamespaceRef{ref(pcliProd)}) ||
		pcliRow(r, pcliAudit) != nil || pcliNamespaceRow(r, pcliProd) == nil || !pcliContributor(pcliNamespaceRow(r, pcliProd).Removed, pcliDeny) ||
		pcliNamespaceRow(r, pcliStaging) == nil || !pcliContributor(pcliNamespaceRow(r, pcliStaging).Added, pcliDeny) {
		t.Fatalf("selector change: %s", sel.stdout)
	}
	if res := s.run("selector-fail-on-impact", kc[full], "-f", moveDeny, "--format", "json", "--fail-on-impact"); res.code != 2 {
		t.Fatalf("selector change with --fail-on-impact: exit %d", res.code)
	}
	if res := s.run("selector-text", kc[full], "-f", moveDeny); res.code != 0 || !bytes.HasPrefix(res.stdout, []byte("Konstapel policy change preview")) ||
		!bytes.Contains(res.stdout, []byte("\nResult: complete, ")) || !bytes.Contains(res.stdout, []byte("selector-changed")) {
		t.Fatalf("selector change as text: exit %d\n%s", res.code, res.stdout)
	}

	// Audit to Deny.
	mode := s.run("audit-to-deny", kc[full], "-f", auditToDeny, "--format", "json")
	if r, row := mode.report, pcliRow(mode.report, pcliAudit); mode.code != 0 || !r.Complete || row == nil || !pcliHas(row.Impacts, preview.CategoryMode, preview.CategoryRevision) ||
		row.Before == nil || row.Before.Mode != v1alpha1.ModeAudit || row.After == nil || row.After.Mode != v1alpha1.ModeDeny || pcliRow(r, pcliDeny) != nil {
		t.Fatalf("Audit to Deny: %s", mode.stdout)
	}
	if res := s.run("audit-to-deny-fail-on-impact", kc[full], "-f", auditToDeny, "--format", "json", "--fail-on-impact"); res.code != 2 {
		t.Fatalf("Audit to Deny with --fail-on-impact: exit %d", res.code)
	}

	// A shared-profile pin change from the vendored bundle to the verified
	// private OCI bundle: both bindings change, although only the profile
	// is in the input.
	pinCheck := func(step string, res pcliRun) {
		t.Helper()
		r := res.report
		oci, local := pcliContent(r, obBundle), pcliContent(r, content.Name)
		if !r.Complete || len(r.Inputs.Objects) != 1 || oci == nil || !oci.Resolved || oci.DigestKind != preview.DigestOCIManifest ||
			oci.Digest != f.subject || oci.Repository != reg.host+"/org/valid/"+obBundle || local == nil || local.DigestKind != preview.DigestVendoredChecksum {
			t.Fatalf("%s: %s", step, res.stdout)
		}
		for _, b := range []string{pcliDeny, pcliAudit} {
			row := pcliRow(r, b)
			if row == nil || !pcliHas(row.Impacts, preview.CategoryBundlePin, preview.CategoryRevision) || row.Before == nil || row.After == nil ||
				row.Before.BundleName != content.Name || row.Before.BundleDigest != vendored || row.Before.BundleDigestKind != preview.DigestVendoredChecksum ||
				row.After.BundleName != obBundle || row.After.BundleDigest != f.subject || row.After.BundleDigestKind != preview.DigestOCIManifest {
				t.Fatalf("%s: binding %s: %s", step, b, res.stdout)
			}
		}
		if !slices.ContainsFunc(res.reqs, func(q pcliRequest) bool { return strings.Contains(q.URI, "/secrets/") && q.Status == http.StatusOK }) {
			t.Fatalf("%s: the referenced Secrets were not read", step)
		}
	}
	pin := s.run("pin", kc[full], "-f", pinOCI, "--format", "json", "--bundle-cache-dir", cache)
	pinCheck("pin", pin)
	if res := s.run("pin-fail-on-impact", kc[full], "-f", pinOCI, "--format", "json", "--bundle-cache-dir", cache, "--fail-on-impact"); res.code != 2 {
		t.Fatalf("pin change with --fail-on-impact: exit %d", res.code)
	} else {
		pinCheck("pin-fail-on-impact", res)
	}

	// Removal through the documented CI form: the previous rendered set
	// names the binding, the proposed set no longer does.
	rm := s.run("removal", kc[full], "--before", restateDeny, "-f", empty, "--format", "json", "--fail-on-impact")
	if r, row := rm.report, pcliRow(rm.report, pcliDeny); rm.code != 2 || row == nil || row.Change != preview.ChangeRemoved ||
		!pcliHas(row.Impacts, preview.CategoryContributionRemoved) || r.AppliedState == nil ||
		!slices.ContainsFunc(r.AppliedState.Policies, func(e preview.AppliedEntry) bool {
			return e.BindingUID == denyB.UID && e.Condition == preview.AppliedCurrent && e.Proposed == preview.OutcomeWithdrawalRequested
		}) {
		t.Fatalf("removal: %s", rm.stdout)
	}

	// 7.2: incomplete previews exit 1, also with --fail-on-impact and
	// impacts (failure precedence).
	//
	// A required read denied: without the namespaced Role, the acceptance
	// snapshot ConfigMaps cannot be listed. Nothing is compared.
	denied := s.run("snapshots-denied", kc[clusterOnly], "-f", moveDeny, "--format", "json", "--fail-on-impact")
	if r := denied.report; denied.code != 1 || r.Complete || r.Changes != nil || r.Observation == nil || r.Observation.Complete ||
		len(r.Errors) != 1 || r.Errors[0].Code != preview.ObserveAccessDenied || !strings.HasSuffix(r.Errors[0].Resource, "/configmaps") || r.Errors[0].Namespace != pcliNS {
		t.Fatalf("denied snapshot read: %s", denied.stdout)
	}
	// Denied private-bundle access: the Secret Role is missing, so the
	// bundles of that source are never resolved, not even from the cache
	// this run shares with the earlier ones.
	noSec := s.run("bundle-secrets-denied", kc[noSecrets], "-f", pinOCI, "--format", "json", "--bundle-cache-dir", cache, "--fail-on-impact")
	if r, oci := noSec.report, pcliContent(noSec.report, obBundle); noSec.code != 1 || r.Complete || oci == nil || oci.Resolved ||
		!pcliHasCode(r.Errors, preview.CompareContentAccessDenied) || !pcliHasCode(r.Limitations, preview.LimitSecretNotRead) ||
		!slices.ContainsFunc(r.Errors, func(d preview.ReportDiagnostic) bool {
			return d.Code == preview.CompareContentAccessDenied && strings.Contains(d.Message, obCredSecret)
		}) {
		t.Fatalf("denied bundle Secrets: %s", noSec.stdout)
	}

	// Live drift that persists: a concurrent writer relabels a namespace
	// in the cluster just before each namespace list the binary sends, so
	// every capture differs from the one before.
	var relabels int
	proxy.setHook(func(r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces" {
			return
		}
		relabels++
		patch := fmt.Sprintf(`{"metadata":{"labels":{%q:%q}}}`, pcliDrift, strconv.Itoa(relabels))
		if err := l.c.Patch(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: pcliDev}}, client.RawPatch(types.MergePatchType, []byte(patch))); err != nil {
			t.Errorf("relabel %s: %v", pcliDev, err)
		}
	})
	drift := s.run("drift", kc[full], "-f", moveDeny, "--format", "json", "--fail-on-impact")
	proxy.setHook(nil)
	if err := l.c.Patch(l.ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: pcliDev}},
		client.RawPatch(types.MergePatchType, []byte(fmt.Sprintf(`{"metadata":{"labels":{%q:null}}}`, pcliDrift)))); err != nil {
		t.Fatal(err)
	}
	if r := drift.report; drift.code != 1 || r.Complete || r.Changes != nil || r.Observation == nil || r.Observation.Captures != 4 ||
		len(r.Observation.Drift) != 3 || relabels != 4 || len(r.Errors) != 1 || r.Errors[0].Code != preview.ObserveUnstable ||
		!strings.Contains(r.Errors[0].Message, "/"+pcliDev) {
		t.Fatalf("persistent drift (relabels %d): %s", relabels, drift.stdout)
	}

	// A trust change: the publisher rule and key move to another key. The
	// cached content was verified under the old trust and is refused now.
	l.obApply(keySecret(f.pubOther))
	l.obApply(sourcesCM(f.fpOther))
	untrusted := s.run("trust-changed", kc[full], "-f", pinOCI, "--format", "json", "--bundle-cache-dir", cache, "--fail-on-impact")
	if r, oci := untrusted.report, pcliContent(untrusted.report, obBundle); untrusted.code != 1 || r.Complete || oci == nil || oci.Resolved ||
		oci.ErrorClass != targeting.ContentErrorUntrusted || !pcliHasCode(r.Errors, preview.CompareUnresolvedCandidate) {
		t.Fatalf("changed trust: %s", untrusted.stdout)
	}
	l.obApply(keySecret(f.pubOrg))
	l.obApply(sourcesCM(f.fpOrg))
	restored := s.run("trust-restored", kc[full], "-f", pinOCI, "--format", "json", "--bundle-cache-dir", cache, "--fail-on-impact")
	if restored.code != 2 {
		t.Fatalf("restored trust: exit %d", restored.code)
	}
	pinCheck("trust-restored", restored)

	// 7.1/7.2 exceptions, as far as 0.3.0 goes: an observed exception in a
	// namespace and policy that the proposal changes makes the preview
	// incomplete (exception-impact-undetermined), because the acceptance
	// comparison is not integrated. This cluster has no exception
	// admission webhooks, so neither exception carries an admission record:
	// the first is not accepted, and the revoked one has no protected
	// revocation record. The controller still records its conditions.
	expires := metav1.NewTime(time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second))
	newException := func(ns, name string) *v1alpha1.ComplianceException {
		e := &v1alpha1.ComplianceException{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: v1alpha1.ComplianceExceptionSpec{
			Policy: pol, WorkloadSelector: &metav1.LabelSelector{}, Reason: "live preview acceptance", ExpiresAt: expires, AcceptanceRevision: 1}}
		if err := l.c.Create(l.ctx, e); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.c.Delete(l.ctx, e) })
		return e
	}
	inProd, revoked := newException(pcliProd, "preview-cli-in-prod"), newException(pcliDev, "preview-cli-revoked")
	revoked.Spec.Revoked = true
	if err := l.c.Update(l.ctx, revoked); err != nil {
		t.Fatal(err)
	}
	stop = l.startPCLIManager(t.TempDir())
	l.eventually("exception conditions", func() (bool, string) {
		for _, e := range []*v1alpha1.ComplianceException{inProd, revoked} {
			got := &v1alpha1.ComplianceException{}
			if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(e), got); err != nil {
				return false, err.Error()
			}
			if c := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionAcceptanceRecorded); c == nil || c.ObservedGeneration != got.Generation {
				return false, e.Name + ": " + toJSON(got.Status)
			}
			if c := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionRevocationRecorded); got.Spec.Revoked && (c == nil || c.ObservedGeneration != got.Generation) {
				return false, e.Name + ": " + toJSON(got.Status)
			}
		}
		return true, ""
	})
	l.pcliSettle()
	stop()
	revocationNoted := func(r *preview.Report) bool {
		return slices.ContainsFunc(r.Limitations, func(d preview.ReportDiagnostic) bool {
			return d.Code == preview.LimitRevocationInvalid && d.Namespace == pcliDev && d.Name == revoked.Name &&
				strings.Contains(d.Message, v1alpha1.ReasonRevocationProcessingDisabled)
		})
	}
	exc := s.run("exception-undetermined", kc[full], "-f", moveDeny, "--format", "json", "--fail-on-impact")
	if r := exc.report; exc.code != 1 || r.Complete || r.Changes == nil || r.ImpactCount == 0 || r.Exceptions.Analysis != preview.AnalysisNotAvailable ||
		r.Exceptions.Observed == nil || *r.Exceptions.Observed < 2 || len(r.Exceptions.Consequences) != 0 || len(r.Exceptions.PotentiallyAffected) != 1 ||
		r.Exceptions.PotentiallyAffected[0].Name != inProd.Name || r.Exceptions.PotentiallyAffected[0].Accepted ||
		len(r.Errors) != 1 || r.Errors[0].Code != preview.ReportExceptionImpactUndetermined || r.Errors[0].Namespace != pcliProd || !revocationNoted(r) {
		t.Fatalf("exception in a changed namespace: %s", exc.stdout)
	}
	// The revoked exception is observed, reported as found and left alone:
	// a preview that touches neither exception stays complete.
	untouched := s.run("exception-untouched", kc[full], "-f", restateDeny, "--format", "json", "--fail-on-impact")
	if r := untouched.report; untouched.code != 0 || !r.Complete || len(r.Exceptions.PotentiallyAffected) != 0 || r.Exceptions.Observed == nil ||
		*r.Exceptions.Observed < 2 || !revocationNoted(r) || !pcliHasCode(r.Limitations, preview.LimitExceptionAnalysisUnavailable) {
		t.Fatalf("untouched exceptions: %s", untouched.stdout)
	}

	// Stale applied policies: with the controller stopped, the live
	// configuration moves ahead of what it applied (Audit becomes Deny) and
	// a new binding has nothing applied yet. Restating both is no impact, so
	// the preview is complete and informational even with --fail-on-impact:
	// the applied state, the pending delivery and the evidence the owner has
	// not caught up on are context, not impacts.
	cur := l.binding(pcliAudit)
	cur.Spec.Mode = v1alpha1.ModeDeny
	if err := l.c.Update(l.ctx, cur); err != nil {
		t.Fatal(err)
	}
	late := bindingObj(pcliLate, pcliProfile, v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{pcliEnv: "staging"})
	late.SetUID("")
	late.SetGeneration(0)
	if err := l.c.Create(l.ctx, late); err != nil {
		t.Fatal(err)
	}
	created = append(created, late)
	ownedBy[late.UID] = true
	restateLate := input("restate-late.yaml", pcliBindingYAML(pcliLate, "staging", "Audit"))
	stale := s.run("stale-applied", kc[full], "-f", auditToDeny, "-f", restateLate, "--format", "json", "--fail-on-impact")
	r := stale.report
	pending := func(b string) bool {
		return r.AppliedState != nil && slices.ContainsFunc(r.AppliedState.Pending, func(p preview.PendingDelivery) bool { return p.Key.Binding == b && p.Key.Policy == pol })
	}
	auditEv, lateEv := pcliBindingEvidence(r, pcliAudit), pcliBindingEvidence(r, pcliLate)
	if stale.code != 0 || !r.Complete || r.ImpactCount != 0 || r.AppliedState == nil || !pending(pcliAudit) || !pending(pcliLate) ||
		!slices.ContainsFunc(r.AppliedState.Policies, func(e preview.AppliedEntry) bool {
			return e.BindingUID == auditB.UID && e.Mode == v1alpha1.ModeAudit && e.Condition == preview.AppliedSuperseded && e.Proposed == preview.OutcomeReplaced
		}) ||
		auditEv == nil || auditEv.State != preview.EvidenceUnattributable || lateEv == nil || lateEv.State != preview.EvidenceMissing ||
		!pcliHasCode(r.Limitations, preview.LimitEvidenceUnattributable) || !pcliHasCode(r.Limitations, preview.LimitEvidenceMissing) {
		t.Fatalf("stale applied policies: %s", stale.stdout)
	}

	// The whole request log, without credentials: every request has a step.
	proxy.mu.Lock()
	all := slices.Clone(proxy.log)
	proxy.mu.Unlock()
	if i := slices.IndexFunc(all, func(q pcliRequest) bool { return q.Step == "" }); i >= 0 {
		t.Fatalf("a request outside any preview invocation: %+v", all[i])
	}
	raw, _ := json.MarshalIndent(all, "", "  ")
	for _, v := range s.secrets {
		if bytes.Contains(raw, []byte(v)) {
			t.Fatal("a credential reached the request log")
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "requests.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	l.record("passed", map[string]any{"requests": len(all)})
}
