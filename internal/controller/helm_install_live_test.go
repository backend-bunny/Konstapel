//go:build live

package controller

// Live Helm installation (add-helm-oci-distribution 3.1): both charts are
// installed with the pinned Helm, the runtime chart running the controller
// image built from this checkout (KONSTAPEL_LIVE_IMAGE, loaded into the
// disposable node by scripts/acceptance.sh). Nothing runs in-process:
//   - both replicas become ready with the hardened pod spec (non-root,
//     read-only root, no capabilities, bounded staging) and one holds the
//     Lease;
//   - a Deny binding is delivered and enforced by the installed controller;
//   - a scheduled run is collected, exported to OSCAL with C2P, and
//     published to a test-owned S3 service the pods reach on the kind
//     network, using only the chart's writable volumes.
// Run through scripts/targeting-live.sh (charts acceptance group).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func TestLiveHelmInstall(t *testing.T) {
	image := os.Getenv("KONSTAPEL_LIVE_IMAGE")
	repo, digest, ok := strings.Cut(image, "@")
	if !ok {
		t.Fatalf("KONSTAPEL_LIVE_IMAGE=%q is not repository@digest (scripts/acceptance.sh builds and loads it for the charts group)", image)
	}
	l := newLive(t)
	const ns = "konstapel-system"
	if out, err := l.helm("install", "konstapel-crds", "../../charts/konstapel-crds", "--namespace", ns, "--create-namespace", "--wait"); err != nil {
		t.Fatalf("install CRD chart: %v\n%s", err, out)
	}
	// Helm does not wait for CRDs to be established, and the test client's
	// REST mapping predates them: wait, then use a fresh client.
	l.eventually("chart CRDs established", func() (bool, string) {
		var list apiextensionsv1.CustomResourceDefinitionList
		if err := l.c.List(l.ctx, &list); err != nil {
			return false, err.Error()
		}
		established := 0
		for _, c := range list.Items {
			if c.Spec.Group != v1alpha1.GroupVersion.Group {
				continue
			}
			for _, cond := range c.Status.Conditions {
				if cond.Type == apiextensionsv1.Established && cond.Status == apiextensionsv1.ConditionTrue {
					established++
				}
			}
		}
		want, _ := filepath.Glob("../../charts/konstapel-crds/templates/*.yaml")
		return established == len(want), fmt.Sprintf("%d of %d established", established, len(want))
	})
	fresh, err := client.New(l.cfg, client.Options{Scheme: l.c.Scheme()})
	if err != nil {
		t.Fatal(err)
	}
	l.c = fresh
	// Operator-managed TLS: a test CA issues the download server's
	// certificate for its service name, without cert-manager.
	tlsSecret, caPEM := downloadTLSSecret(t, ns)
	if err := l.c.Create(l.ctx, tlsSecret); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, tlsSecret) })
	if out, err := l.helm("install", "konstapel", "../../charts/konstapel", "--namespace", ns, "--wait", "--timeout", "5m",
		"--set", "image.repository="+repo, "--set", "image.digest="+digest, "--set", "image.pullPolicy=Never",
		"--set", "tls.mode=secret", "--set", "tls.secret.name="+tlsSecret.Name); err != nil {
		t.Fatalf("install runtime chart: %v\n%s\n%s", err, out, l.podDiagnostics(ns))
	}
	t.Cleanup(func() {
		_, _ = l.helm("uninstall", "konstapel", "--namespace", ns, "--wait")
		_, _ = l.helm("uninstall", "konstapel-crds", "--namespace", ns)
	})

	// 1. Two ready replicas from the packaged image, hardened as rendered.
	var pods corev1.PodList
	l.eventually("two ready controller pods", func() (bool, string) {
		_ = l.c.List(l.ctx, &pods, client.InNamespace(ns), client.MatchingLabels{"app.kubernetes.io/component": "controller"})
		ready := 0
		for _, p := range pods.Items {
			for _, c := range p.Status.Conditions {
				if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
					ready++
				}
			}
		}
		return ready == 2, l.podDiagnostics(ns)
	})
	for _, p := range pods.Items {
		c := p.Spec.Containers[0]
		sc := c.SecurityContext
		if c.Image != image || p.Spec.SecurityContext.RunAsNonRoot == nil || !*p.Spec.SecurityContext.RunAsNonRoot ||
			sc == nil || sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem || len(sc.Capabilities.Drop) != 1 {
			t.Fatalf("pod %s is not the hardened packaged runtime: %s", p.Name, toJSON(p.Spec))
		}
	}
	lease := &coordinationv1.Lease{}
	l.eventually("a replica holds the Lease", func() (bool, string) {
		if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: LeaderElectionID}, lease); err != nil || lease.Spec.HolderIdentity == nil {
			return false, fmt.Sprint(err)
		}
		for _, p := range pods.Items {
			if strings.HasPrefix(*lease.Spec.HolderIdentity, p.Name+"_") {
				return true, ""
			}
		}
		return false, *lease.Spec.HolderIdentity
	})
	l.record("installed", map[string]any{"image": image, "pods": len(pods.Items), "leader": *lease.Spec.HolderIdentity})

	// 2. The installed controller delivers and enforces a Deny binding.
	l.setNamespace("hi-prod", "hi-production")
	p := profileObj(t, "hi-baseline", pol)
	b := bindingObj("hi-deny", p.Name, v1alpha1.ModeDeny, map[string]v1alpha1.LabelValue{envLabel: "hi-production"})
	for _, o := range []client.Object{p, b} {
		o.SetUID("")
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = l.c.Delete(l.ctx, b)
		_ = l.c.Delete(l.ctx, p)
	})
	l.waitReady(b.Name, 1)
	l.eventually("installed controller enforces", func() (bool, string) { return l.denied("hi-prod") })
	l.record("delivered", map[string]any{"binding": b.Name, "policies": l.policiesFor(b.Name)})

	// 3. A scheduled run collects, exports with C2P, and publishes to S3
	// from inside the pod.
	pub := startS3(t, l)
	if out, err := exec.Command("docker", "network", "connect", "kind", l.s3Container).CombinedOutput(); err != nil {
		t.Fatalf("attach the S3 service to the kind network: %v %s", err, out)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "hi-s3"},
		Data: map[string][]byte{"accessKeyID": []byte(l.s3Access), "secretAccessKey": []byte(l.s3Secret)}}
	ed := &v1alpha1.EvidenceDestination{ObjectMeta: metav1.ObjectMeta{Name: "hi-dest"}, Spec: v1alpha1.EvidenceDestinationSpec{S3: v1alpha1.S3Location{
		Endpoint: "http://" + l.s3Container + ":9000", Bucket: pub.Dest.Bucket, Region: "us-east-1", Prefix: "konstapel-test/hi", DevelopmentFixture: true,
		CredentialSecret: &v1alpha1.S3CredentialSecret{ControllerNamespaceReference: v1alpha1.ControllerNamespaceReference{Name: secret.Name}}}}}
	for _, o := range []client.Object{secret, ed} {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(l.ctx, &runs)
		for i := range runs.Items {
			if r := &runs.Items[i]; r.Spec.BindingRef.Name == b.Name {
				r.Finalizers = nil
				_ = l.c.Update(l.ctx, r)
				_ = l.c.Delete(l.ctx, r)
			}
		}
		got := &v1alpha1.EvidenceDestination{}
		if l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got) == nil {
			got.Finalizers = nil
			_ = l.c.Update(l.ctx, got)
			_ = l.c.Delete(l.ctx, got)
		}
		_ = l.c.Delete(l.ctx, secret)
	})
	l.eventually("destination ready from inside the cluster", func() (bool, string) {
		got := &v1alpha1.EvidenceDestination{}
		_ = l.c.Get(l.ctx, client.ObjectKeyFromObject(ed), got)
		return meta.IsStatusConditionTrue(got.Status.Conditions, v1alpha1.ConditionDestinationReady), toJSON(got.Status)
	})
	got := l.binding(b.Name)
	got.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "24h", CollectionTimeout: "20s",
		DestinationRef: &v1alpha1.DestinationReference{Name: ed.Name, UID: string(ed.UID)}}
	if err := l.c.Update(l.ctx, got); err != nil {
		t.Fatal(err)
	}
	var run *v1alpha1.AssessmentRun
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		var runs v1alpha1.AssessmentRunList
		_ = l.c.List(l.ctx, &runs)
		for i := range runs.Items {
			if r := &runs.Items[i]; r.Spec.BindingRef.Name == b.Name && r.Status.Phase == v1alpha1.RunCompleted {
				run = r
			}
		}
		if run != nil {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if run == nil {
		t.Fatalf("no published run from the installed controller: %s\n%s", toJSON(l.binding(b.Name).Status.Assessment), l.podDiagnostics(ns))
	}
	if run.Status.Summary == nil || run.Status.Summary.Export != "Assessment" || run.Status.Publication == nil || run.Status.Publication.Phase != "Committed" ||
		run.Status.Destination == nil || run.Status.Destination.UID != string(ed.UID) {
		t.Fatalf("installed controller run: %s", toJSON(run.Status))
	}
	l.record("published", map[string]any{"run": run.Name, "export": run.Status.Summary.Export, "publication": run.Status.Publication.PublicationID})

	// 4. The installed download server serves the package over TLS trusted
	// only through the operator's CA, authorizing a platform operator.
	operator := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "hi-operator"}}
	crb := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "hi-operator"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "konstapel-assessment-operator"},
		Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Namespace: ns, Name: operator.Name}}}
	for _, o := range []client.Object{operator, crb} {
		if err := l.c.Create(l.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = l.c.Delete(l.ctx, crb); _ = l.c.Delete(l.ctx, operator) })
	local := l.portForward(ns, "svc/konstapel-download", 443)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	hc := &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "konstapel-download.konstapel-system.svc"}}}
	code, body := fetch(t, hc, "https://"+local+"/v1/assessmentruns/"+string(run.UID)+"/download", l.token(ns, operator.Name, downloadAudience))
	if code != http.StatusOK || len(body) == 0 {
		t.Fatalf("download through the installed server: %d %s", code, body)
	}
	if sum := fmt.Sprintf("%x", sha256.Sum256(body)); sum != run.Status.Publication.PackageSHA256 {
		t.Fatalf("downloaded %d bytes with sha256 %s, receipt %s", len(body), sum, run.Status.Publication.PackageSHA256)
	}
	l.record("downloaded", map[string]any{"bytes": len(body), "sha256": run.Status.Publication.PackageSHA256, "tls": "operator Secret"})

	// 5. Uninstalling keeps the operator's Secret: the chart never owned it.
	if out, err := l.helm("uninstall", "konstapel", "--namespace", ns, "--wait"); err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(tlsSecret), &corev1.Secret{}); err != nil {
		t.Fatalf("operator TLS Secret removed by uninstall: %v", err)
	}

	// 6. Default TLS mode: cert-manager (installed separately) issues the
	// download certificate from the chart's CA for the Service's names.
	if os.Getenv("KONSTAPEL_LIVE_CERT_MANAGER") != "true" {
		t.Log("cert-manager is not installed in this environment; the default TLS mode is covered by the charts acceptance group")
		return
	}
	if out, err := l.helm("install", "konstapel", "../../charts/konstapel", "--namespace", ns, "--wait", "--timeout", "5m",
		"--set", "image.repository="+repo, "--set", "image.digest="+digest, "--set", "image.pullPolicy=Never"); err != nil {
		t.Fatalf("install in cert-manager mode: %v\n%s\n%s", err, out, l.podDiagnostics(ns))
	}
	issued := &corev1.Secret{}
	l.eventually("download certificate issued", func() (bool, string) {
		err := l.c.Get(l.ctx, client.ObjectKey{Namespace: ns, Name: "konstapel-download-tls"}, issued)
		return err == nil && len(issued.Data["ca.crt"]) > 0 && len(issued.Data["tls.crt"]) > 0, fmt.Sprint(err)
	})
	block, _ := pem.Decode(issued.Data["tls.crt"])
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(leaf.DNSNames, "konstapel-download.konstapel-system.svc") {
		t.Fatalf("issued certificate names %v, not the Service", leaf.DNSNames)
	}
	issuedRoots := x509.NewCertPool()
	issuedRoots.AppendCertsFromPEM(issued.Data["ca.crt"])
	local = l.portForward(ns, "svc/konstapel-download", 443)
	hc = &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: issuedRoots, ServerName: "konstapel-download.konstapel-system.svc"}}}
	l.eventually("download through the cert-manager certificate", func() (bool, string) {
		code, body = fetch(t, hc, "https://"+local+"/v1/assessmentruns/"+string(run.UID)+"/download", l.token(ns, operator.Name, downloadAudience))
		return code == http.StatusOK && fmt.Sprintf("%x", sha256.Sum256(body)) == run.Status.Publication.PackageSHA256, fmt.Sprint(code)
	})
	l.record("cert-manager", map[string]any{"issuer": leaf.Issuer.CommonName, "dnsNames": leaf.DNSNames, "downloadSha256": run.Status.Publication.PackageSHA256})
}

// downloadTLSSecret issues a test CA and a serving certificate for the
// download Service, as an operator would provide them.
func downloadTLSSecret(t *testing.T, ns string) (*corev1.Secret, []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "konstapel live test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "konstapel-download"},
		DNSNames:    []string{"konstapel-download", "konstapel-download." + ns, "konstapel-download." + ns + ".svc"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "operator-download-tls"}, Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			"tls.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), "ca.crt": caPEM}}, caPEM
}

// portForward forwards a local port to target's port for the rest of the
// test and returns the local address.
func (l *live) portForward(ns, target string, port int) string {
	l.t.Helper()
	cmd := exec.CommandContext(l.ctx, "kubectl", "--kubeconfig", os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"), "--context", os.Getenv("KONSTAPEL_LIVE_CONTEXT"),
		"-n", ns, "port-forward", target, fmt.Sprintf("0:%d", port))
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	buf := make([]byte, 256)
	n, _ := stdout.Read(buf)
	// "Forwarding from 127.0.0.1:41235 -> 8443"
	line := string(buf[:n])
	i, j := strings.Index(line, "127.0.0.1:"), strings.Index(line, " ->")
	if i < 0 || j < i {
		l.t.Fatalf("port-forward: %q", line)
	}
	return line[i:j]
}

// podDiagnostics summarizes the namespace's pods for a failure message.
func (l *live) podDiagnostics(ns string) string {
	var pods corev1.PodList
	_ = l.c.List(l.ctx, &pods, client.InNamespace(ns))
	var b strings.Builder
	for _, p := range pods.Items {
		fmt.Fprintf(&b, "%s %s", p.Name, p.Status.Phase)
		for _, s := range p.Status.ContainerStatuses {
			if s.State.Waiting != nil {
				fmt.Fprintf(&b, " waiting:%s %s", s.State.Waiting.Reason, s.State.Waiting.Message)
			}
			if s.LastTerminationState.Terminated != nil {
				fmt.Fprintf(&b, " lastExit:%d %s", s.LastTerminationState.Terminated.ExitCode, s.LastTerminationState.Terminated.Message)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}
