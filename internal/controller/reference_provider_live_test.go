//go:build live

package controller

// Live reference provider chart (add-external-assessment-providers 5.1),
// on a disposable cluster with the example reporting provider's image built
// from this checkout (scripts/examples/reference-provider-image.sh, loaded
// by digest) and its reference chart Helm-installed:
//   - installing it registers nothing (no AssessmentProvider exists);
//   - the installed identities: the worker's ServiceAccount may get
//     Namespaces and nothing else, the evaluator's may do nothing
//     (SubjectAccessReview, and real API requests with tokens issued for
//     each ServiceAccount); the evaluator Pod has no API token, and from
//     its network namespace no connection reaches the API server, while
//     the same probe from the worker's does;
//   - the provider works through the worker alone: Describe reports the
//     image digest as the release, Collect reads the live Namespaces, and
//     Evaluate runs in the evaluator, which the host itself cannot call;
//   - TLS rotation without a restart: a new worker serving certificate,
//     host trust rotated to another CA (the old host identity is refused
//     and its established connection closed, the new one is accepted) and
//     a new evaluator serving certificate, still used by the worker.
// No private key is written to the evidence. Run through
// scripts/targeting-live.sh (acceptance group "providers").

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
	"github.com/backend-bunny/Konstapel/pkg/providerkit"
)

const (
	refNS        = "reference-provider"
	refRelease   = "ref"
	refWorker    = "ref-example-reporting-worker"
	refEvaluator = "ref-example-reporting-evaluator"
	refHost      = "host.konstapel.example.test"
	refCheckKind = "reporting.example.test/v1/RequiredLabel"
)

var refImagePattern = regexp.MustCompile(`^([a-z0-9][a-z0-9._/-]*[a-z0-9])@(sha256:[0-9a-f]{64})$`)

// refCA is a throwaway CA of the test. Its keys stay in memory and in the
// test's Secrets.
type refCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newRefCA(t *testing.T, name string) *refCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: refSerial(t), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(6 * time.Hour), KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &refCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func refSerial(t *testing.T) *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// refLeaf is one issued certificate and key.
type refLeaf struct {
	cert, key []byte
	serial    string
}

func (ca *refCA) issue(t *testing.T, dns string, usage x509.ExtKeyUsage) refLeaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial := refSerial(t)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(6 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage}}, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return refLeaf{cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), serial: serial.String()}
}

// refMaterial is one side's mutual TLS material held in memory.
type refMaterial struct{ cert, key, trust []byte }

func (m refMaterial) LoadTLS() (providerkit.TLSMaterial, error) {
	return providerkit.TLSMaterial{Certificate: m.cert, Key: m.key, Trust: m.trust}, nil
}

// refSecret writes a kubernetes.io/tls Secret with leaf and trust.
func (l *live) refSecret(name string, leaf refLeaf, trust []byte) {
	l.t.Helper()
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: refNS, Name: name}, Type: corev1.SecretTypeTLS}
	data := map[string][]byte{"tls.crt": leaf.cert, "tls.key": leaf.key, "ca.crt": trust}
	if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(s), s); apierrors.IsNotFound(err) {
		s.Data = data
		if err := l.c.Create(l.ctx, s); err != nil {
			l.t.Fatal(err)
		}
		return
	} else if err != nil {
		l.t.Fatal(err)
	}
	s.Data = data
	if err := l.c.Update(l.ctx, s); err != nil {
		l.t.Fatal(err)
	}
}

// refDial connects to a provider at addr whose certificate must name
// serverName, as the host whose material is m.
func refDial(addr, serverName string, m refMaterial) (*grpc.ClientConn, error) {
	mtls, err := providerkit.NewClientTLSFrom(m, serverName)
	if err != nil {
		return nil, err
	}
	opts, err := providerkit.DialOptions(mtls, providerkit.TransportLimits{})
	if err != nil {
		return nil, err
	}
	return grpc.NewClient("passthrough:///"+addr, opts...)
}

// refForward forwards a fresh local port to target's protocol port.
// kubectl port-forward ends as soon as the provider resets one forwarded
// connection, as it does for a refused TLS peer, so every probe uses its
// own forward and stops it afterwards.
func (l *live) refForward(target string) (string, func(), error) {
	cmd := exec.CommandContext(l.ctx, "kubectl", "--kubeconfig", os.Getenv("KONSTAPEL_LIVE_KUBECONFIG"), "--context", os.Getenv("KONSTAPEL_LIVE_CONTEXT"),
		"-n", refNS, "port-forward", target, "0:8443")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", nil, err
	}
	if err := cmd.Start(); err != nil {
		return "", nil, err
	}
	stop := func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }
	r := bufio.NewReader(stdout)
	// "Forwarding from 127.0.0.1:41235 -> 8443"
	line, err := r.ReadString('\n')
	i, j := strings.Index(line, "127.0.0.1:"), strings.Index(line, " ->")
	if err != nil || i < 0 || j < i {
		stop()
		return "", nil, fmt.Errorf("port-forward %s: %q %v", target, line, err)
	}
	go func() { _, _ = io.Copy(io.Discard, r) }()
	return line[i:j], stop, nil
}

// refCall runs f on a connection to target's provider, through its own
// forward, as m, requiring the server name serverName.
func (l *live) refCall(target, serverName string, m refMaterial, f func(*grpc.ClientConn) error) error {
	addr, stop, err := l.refForward(target)
	if err != nil {
		return err
	}
	defer stop()
	conn, err := refDial(addr, serverName, m)
	if err != nil {
		return err
	}
	defer conn.Close()
	return f(conn)
}

func refCompat(capabilities ...providerv1.Capability) providerkit.Compatibility {
	return providerkit.Compatibility{Provider: "example-reporting", ContractVersion: 1, PayloadVersion: 1, EvaluatorVersion: 1, Capabilities: capabilities}
}

// refDescribe describes the endpoint within a short deadline.
func refDescribe(conn grpc.ClientConnInterface, want providerkit.Compatibility) (*providerv1.DescribeResponse, error) {
	c, err := providerkit.NewClient(conn, want, nil)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return c.Describe(ctx)
}

// refServed returns the serial of the certificate target serves for
// serverName, presenting m's certificate, through its own forward.
func (l *live) refServed(target, serverName string, m refMaterial) (string, error) {
	addr, stop, err := l.refForward(target)
	if err != nil {
		return "", err
	}
	defer stop()
	pair, err := tls.X509KeyPair(m.cert, m.key)
	if err != nil {
		return "", err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(m.trust)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr,
		&tls.Config{Certificates: []tls.Certificate{pair}, RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS13})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.String(), nil
}

// refRefused reports whether err is the peer's refusal of this side's
// certificate in the TLS handshake, not a transport failure.
func refRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "remote error: tls:")
}

func TestLiveReferenceProviderChart(t *testing.T) {
	l := newLive(t)
	image := os.Getenv("KONSTAPEL_LIVE_REFERENCE_PROVIDER_IMAGE")
	m := refImagePattern.FindStringSubmatch(image)
	if m == nil {
		t.Fatalf("KONSTAPEL_LIVE_REFERENCE_PROVIDER_IMAGE=%q must be <repository>@sha256:<digest> (scripts/acceptance.sh loads it)", image)
	}
	repository, release := m[1], m[2]
	workload := os.Getenv("KONSTAPEL_WORKLOAD_IMAGE")
	if workload == "" {
		t.Fatal("KONSTAPEL_WORKLOAD_IMAGE is required for the egress probes")
	}
	l.installCRDs()
	kc, err := kubernetes.NewForConfig(l.cfg)
	if err != nil {
		t.Fatal(err)
	}

	// The live source: two namespaces the worker reads, one labeled.
	sources := map[string]map[string]string{"erl-team-a": {"owner": "alice"}, "erl-team-b": {}}
	uids := map[string]string{}
	for _, n := range []string{refNS, "erl-team-a", "erl-team-b"} {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n, Labels: sources[n]}}
		if err := l.c.Create(l.ctx, ns); err != nil {
			t.Fatal(err)
		}
		uids[n] = string(ns.UID)
		t.Cleanup(func() {
			_ = l.c.Delete(context.Background(), &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}})
		})
	}

	// PKI: one CA for the deployment, the host's identity under it.
	workerDNS, evaluatorDNS := refWorker+"."+refNS+".svc", refEvaluator+"."+refNS+".svc"
	ca := newRefCA(t, "reference provider live CA")
	workerServing := ca.issue(t, workerDNS, x509.ExtKeyUsageServerAuth)
	workerClient := ca.issue(t, workerDNS, x509.ExtKeyUsageClientAuth)
	evaluatorServing := ca.issue(t, evaluatorDNS, x509.ExtKeyUsageServerAuth)
	hostLeaf := ca.issue(t, refHost, x509.ExtKeyUsageClientAuth)
	host := refMaterial{cert: hostLeaf.cert, key: hostLeaf.key, trust: ca.pem}
	l.refSecret(refWorker+"-tls", workerServing, ca.pem)
	l.refSecret(refWorker+"-client-tls", workerClient, ca.pem)
	l.refSecret(refEvaluator+"-tls", evaluatorServing, ca.pem)

	out, err := l.helm("install", refRelease, "../../examples/external-provider/reporting/chart", "--namespace", refNS,
		"--set", "image.repository="+repository, "--set", "image.digest="+release, "--set", "image.pullPolicy=Never",
		"--set", "worker.authorizedHosts[0]="+refHost, "--wait", "--timeout", "5m")
	t.Cleanup(func() { _, _ = l.helm("uninstall", refRelease, "--namespace", refNS, "--wait", "--timeout", "2m") })
	if err != nil {
		t.Fatalf("helm install: %v\n%s\n%s", err, out, l.podDiagnostics(refNS))
	}
	l.record("installed", map[string]any{"image": image, "release": release})

	// Installing the provider registers nothing.
	var regs v1alpha1.AssessmentProviderList
	if err := l.c.List(l.ctx, &regs); err != nil {
		t.Fatal(err)
	}
	if len(regs.Items) != 0 {
		t.Fatalf("installing the reference chart left %d AssessmentProviders", len(regs.Items))
	}

	l.refIdentities(uids)
	l.refEgress(kc, workload)

	// Provider logs (no key material) for the evidence, before teardown.
	t.Cleanup(func() { l.refLogs(kc) })

	// The provider through the worker alone.
	both := refCompat(providerv1.Capability_CAPABILITY_COLLECT, providerv1.Capability_CAPABILITY_EVALUATE)
	evaluateOnly := refCompat(providerv1.Capability_CAPABILITY_EVALUATE)
	worker, evaluator := "svc/"+refWorker, "svc/"+refEvaluator
	if err := l.refCall(worker, workerDNS, host, func(conn *grpc.ClientConn) error {
		d, err := refDescribe(conn, both)
		if err != nil {
			return err
		}
		if d.GetImplementation() != release {
			return fmt.Errorf("the worker reports implementation %q, not the image digest %s", d.GetImplementation(), release)
		}
		l.refAssess(conn, uids, "initial")
		return nil
	}); err != nil {
		t.Fatalf("the worker: %v", err)
	}

	// The evaluator serves Evaluate only, the same release, and only to the
	// worker: the host's own identity is refused in the handshake.
	wc := refMaterial{cert: workerClient.cert, key: workerClient.key, trust: ca.pem}
	if err := l.refCall(evaluator, evaluatorDNS, wc, func(conn *grpc.ClientConn) error {
		ed, err := refDescribe(conn, evaluateOnly)
		if err == nil && (ed.GetImplementation() != release || !slices.Equal(ed.GetCapabilities(), []providerv1.Capability{providerv1.Capability_CAPABILITY_EVALUATE})) {
			err = fmt.Errorf("description %v", ed)
		}
		return err
	}); err != nil {
		t.Fatalf("the evaluator as the worker: %v", err)
	}
	var refused error
	l.eventually("the evaluator refuses the host", func() (bool, string) {
		err := l.refCall(evaluator, evaluatorDNS, host, func(conn *grpc.ClientConn) error { _, err := refDescribe(conn, evaluateOnly); return err })
		if err == nil {
			t.Fatal("the host reached the evaluator directly; only the worker is authorized")
		}
		refused = err
		return refRefused(err), err.Error()
	})
	l.record("host refused by the evaluator", map[string]any{"error": refused.Error()})

	pods := func(component string) []corev1.Pod {
		var list corev1.PodList
		if err := l.c.List(l.ctx, &list, client.InNamespace(refNS), client.MatchingLabels{"app.kubernetes.io/component": component}); err != nil {
			t.Fatal(err)
		}
		return list.Items
	}
	before := map[string]string{}
	for _, c := range []string{"worker", "evaluator"} {
		for _, p := range pods(c) {
			before[c] = string(p.UID)
		}
	}
	waitServed := func(what, target, serverName string, m refMaterial, serial string) {
		start := time.Now()
		l.eventually(what, func() (bool, string) {
			s, err := l.refServed(target, serverName, m)
			return err == nil && s == serial, fmt.Sprintf("serial %s %v, want %s", s, err, serial)
		})
		l.record(what, map[string]any{"serial": serial, "after": time.Since(start).Round(time.Second).String()})
	}

	// 1. A new worker serving certificate, same CA: served without a restart.
	if s, err := l.refServed(worker, workerDNS, host); err != nil || s != workerServing.serial {
		t.Fatalf("the worker serves %s %v, want %s", s, err, workerServing.serial)
	}
	rotated := ca.issue(t, workerDNS, x509.ExtKeyUsageServerAuth)
	l.refSecret(refWorker+"-tls", rotated, ca.pem)
	waitServed("the worker serves its rotated certificate", worker, workerDNS, host, rotated.serial)

	// 2. Host trust rotated to another CA: the old host identity is refused
	// and its established connection closed; the new one is accepted.
	ca2 := newRefCA(t, "reference provider live CA 2")
	host2Leaf := ca2.issue(t, refHost, x509.ExtKeyUsageClientAuth)
	host2 := refMaterial{cert: host2Leaf.cert, key: host2Leaf.key, trust: ca.pem}
	// One connection held open across the rotation, on a forward of its own.
	addr, stopEstablished, err := l.refForward(worker)
	if err != nil {
		t.Fatal(err)
	}
	defer stopEstablished()
	established, err := refDial(addr, workerDNS, host)
	if err != nil {
		t.Fatal(err)
	}
	defer established.Close()
	if _, err := refDescribe(established, both); err != nil {
		t.Fatalf("describe before the trust rotation: %v", err)
	}
	l.refSecret(refWorker+"-tls", rotated, ca2.pem)
	start := time.Now()
	l.eventually("the worker trusts only the rotated host CA", func() (bool, string) {
		oldErr := l.refCall(worker, workerDNS, host, func(conn *grpc.ClientConn) error { _, err := refDescribe(conn, both); return err })
		newErr := l.refCall(worker, workerDNS, host2, func(conn *grpc.ClientConn) error { _, err := refDescribe(conn, both); return err })
		return refRefused(oldErr) && newErr == nil, fmt.Sprintf("old host %v, new host %v", oldErr, newErr)
	})
	_, closed := refDescribe(established, both)
	if closed == nil {
		t.Error("a connection established under the old trust still works after the rotation")
	}
	l.record("host trust rotated", map[string]any{"after": time.Since(start).Round(time.Second).String(), "established": fmt.Sprint(closed)})
	if err := l.refCall(worker, workerDNS, host2, func(conn *grpc.ClientConn) error {
		l.refAssess(conn, uids, "after host trust rotation")
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// 3. A new evaluator serving certificate: served without a restart and
	// used by the worker's forwarding client.
	evaluatorRotated := ca.issue(t, evaluatorDNS, x509.ExtKeyUsageServerAuth)
	l.refSecret(refEvaluator+"-tls", evaluatorRotated, ca.pem)
	waitServed("the evaluator serves its rotated certificate", evaluator, evaluatorDNS, wc, evaluatorRotated.serial)
	if err := l.refCall(worker, workerDNS, host2, func(conn *grpc.ClientConn) error {
		l.refAssess(conn, uids, "after evaluator rotation")
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	for _, c := range []string{"worker", "evaluator"} {
		for _, p := range pods(c) {
			restarts := int32(0)
			for _, s := range p.Status.ContainerStatuses {
				restarts += s.RestartCount
			}
			if string(p.UID) != before[c] || restarts != 0 {
				t.Errorf("%s pod %s (was %s) restarted %d times: rotation must not need a restart", c, p.UID, before[c], restarts)
			}
		}
	}
	l.record("rotations without restart", map[string]any{"pods": before})
}

// refLogs saves the provider containers' logs to the test output. They
// hold events and peer names, never key material.
func (l *live) refLogs(kc kubernetes.Interface) {
	var list corev1.PodList
	if err := l.c.List(context.Background(), &list, client.InNamespace(refNS)); err != nil {
		return
	}
	for _, p := range list.Items {
		raw, err := kc.CoreV1().Pods(refNS).GetLogs(p.Name, &corev1.PodLogOptions{Container: "provider"}).DoRaw(context.Background())
		if err != nil {
			continue
		}
		_ = os.WriteFile(filepath.Join(l.out, l.t.Name()+"-"+p.Labels["app.kubernetes.io/component"]+"-"+p.Name+".log"), raw, 0o644)
	}
}

// refIdentities checks the installed identities with SubjectAccessReview
// and with real requests made with tokens issued for each ServiceAccount,
// and that the evaluator Pod has no API token.
func (l *live) refIdentities(uids map[string]string) {
	t := l.t
	t.Helper()
	can := func(sa, group, resource, namespace, verb, name string) bool {
		sar := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
			User:               "system:serviceaccount:" + refNS + ":" + sa,
			Groups:             []string{"system:serviceaccounts", "system:serviceaccounts:" + refNS, "system:authenticated"},
			ResourceAttributes: &authorizationv1.ResourceAttributes{Group: group, Resource: resource, Namespace: namespace, Verb: verb, Name: name}}}
		if err := l.c.Create(l.ctx, sar); err != nil {
			t.Fatal(err)
		}
		return sar.Status.Allowed
	}
	type access struct{ group, resource, namespace, verb, name string }
	probes := []access{
		{"", "namespaces", "", "get", "erl-team-a"}, {"", "namespaces", "", "list", ""}, {"", "namespaces", "", "watch", ""},
		{"", "namespaces", "", "update", "erl-team-a"}, {"", "namespaces", "", "create", ""}, {"", "namespaces", "", "delete", "erl-team-a"},
		{"", "secrets", refNS, "get", refWorker + "-tls"}, {"", "secrets", refNS, "list", ""}, {"", "secrets", "erl-team-a", "list", ""},
		{"", "configmaps", refNS, "list", ""}, {"", "pods", refNS, "list", ""}, {"", "serviceaccounts", refNS, "list", ""},
		{"compliance.erenius.io", "assessmentproviders", "", "list", ""}, {"rbac.authorization.k8s.io", "clusterroles", "", "list", ""},
		{"*", "*", "", "*", ""},
	}
	results := map[string]map[string]bool{}
	for _, sa := range []string{refWorker, refEvaluator} {
		results[sa] = map[string]bool{}
		for _, p := range probes {
			got := can(sa, p.group, p.resource, p.namespace, p.verb, p.name)
			key := strings.TrimSpace(p.verb + " " + p.group + "/" + p.resource + " " + p.namespace + " " + p.name)
			results[sa][key] = got
			want := sa == refWorker && p.resource == "namespaces" && p.verb == "get"
			if got != want {
				t.Errorf("%s may %s = %v, want %v", sa, key, got, want)
			}
		}
	}
	l.record("subject access reviews", map[string]any{"results": results})

	// Real requests as each identity.
	request := func(sa, path string) int {
		cfg := rest.AnonymousClientConfig(l.cfg)
		cfg.BearerToken = l.apiToken(refNS, sa)
		hc, err := rest.HTTPClientFor(cfg)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := hc.Get(strings.TrimSuffix(cfg.Host, "/") + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	codes := map[string]int{}
	for _, c := range []struct {
		sa, path string
		want     int
	}{
		{refWorker, "/api/v1/namespaces/erl-team-a", http.StatusOK},
		{refWorker, "/api/v1/namespaces", http.StatusForbidden},
		{refWorker, "/api/v1/namespaces/" + refNS + "/secrets", http.StatusForbidden},
		{refEvaluator, "/api/v1/namespaces/erl-team-a", http.StatusForbidden},
		{refEvaluator, "/api/v1/namespaces", http.StatusForbidden},
		{refEvaluator, "/api/v1/namespaces/" + refNS + "/secrets/" + refEvaluator + "-tls", http.StatusForbidden},
	} {
		got := request(c.sa, c.path)
		codes[c.sa+" GET "+c.path] = got
		if got != c.want {
			t.Errorf("%s GET %s: HTTP %d, want %d", c.sa, c.path, got, c.want)
		}
	}
	l.record("real requests", map[string]any{"status": codes, "uids": uids})

	// The evaluator Pod carries no API token at all; the worker's does.
	var list corev1.PodList
	if err := l.c.List(l.ctx, &list, client.InNamespace(refNS)); err != nil {
		t.Fatal(err)
	}
	for _, p := range list.Items {
		component := p.Labels["app.kubernetes.io/component"]
		token := false
		for _, v := range p.Spec.Volumes {
			if v.Projected != nil {
				for _, s := range v.Projected.Sources {
					token = token || s.ServiceAccountToken != nil
				}
			}
		}
		for _, c := range p.Spec.Containers {
			for _, m := range c.VolumeMounts {
				token = token || strings.HasPrefix(m.MountPath, "/var/run/secrets/kubernetes.io")
			}
		}
		if token != (component == "worker") {
			t.Errorf("%s pod %s has an API token: %v", component, p.Name, token)
		}
	}

	// The installed role is the rendered one: get on namespaces.
	var crb rbacv1.ClusterRoleBindingList
	if err := l.c.List(l.ctx, &crb, client.MatchingLabels{"app.kubernetes.io/instance": refRelease, "app.kubernetes.io/name": "example-reporting-provider"}); err != nil {
		t.Fatal(err)
	}
	if len(crb.Items) != 1 || len(crb.Items[0].Subjects) != 1 || crb.Items[0].Subjects[0].Name != refWorker {
		t.Errorf("installed ClusterRoleBindings %+v", crb.Items)
	}
}

// refEgress probes, from an ephemeral container in each Pod's network
// namespace, whether a TCP connection reaches the API server: the
// evaluator's NetworkPolicy must stop it, and the worker's must not.
func (l *live) refEgress(kc kubernetes.Interface, workload string) {
	t := l.t
	t.Helper()
	var api corev1.Service
	if err := l.c.Get(l.ctx, client.ObjectKey{Namespace: "default", Name: "kubernetes"}, &api); err != nil {
		t.Fatal(err)
	}
	target := net.JoinHostPort(api.Spec.ClusterIP, "443")
	// An HTTP request to the TLS port: any HTTP answer (400) proves a
	// connection; a timeout or refusal is no connection.
	script := `out=$(wget -T 5 -O /dev/null http://` + target + `/ 2>&1); case "$out" in *HTTP/*|*400*|*"Bad Request"*) echo CONNECTED;; *) echo "BLOCKED: $out";; esac`
	results := map[string]string{}
	for _, component := range []string{"worker", "evaluator"} {
		var list corev1.PodList
		if err := l.c.List(l.ctx, &list, client.InNamespace(refNS), client.MatchingLabels{"app.kubernetes.io/component": component}); err != nil || len(list.Items) == 0 {
			t.Fatalf("%s pods: %v", component, err)
		}
		p := &list.Items[0]
		name := "egress-probe"
		f := false
		yes := true
		uid := int64(65532)
		p.Spec.EphemeralContainers = append(p.Spec.EphemeralContainers, corev1.EphemeralContainer{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name: name, Image: workload, Command: []string{"sh", "-c", script},
			SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &yes, RunAsUser: &uid, AllowPrivilegeEscalation: &f, ReadOnlyRootFilesystem: &yes,
				Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}}})
		if err := l.c.SubResource("ephemeralcontainers").Update(l.ctx, p); err != nil {
			t.Fatalf("add the egress probe to %s: %v", p.Name, err)
		}
		l.eventually(component+" egress probe finished", func() (bool, string) {
			got := &corev1.Pod{}
			if err := l.c.Get(l.ctx, client.ObjectKeyFromObject(p), got); err != nil {
				return false, err.Error()
			}
			for _, s := range got.Status.EphemeralContainerStatuses {
				if s.Name == name && s.State.Terminated != nil {
					return true, ""
				}
				if s.Name == name {
					return false, fmt.Sprintf("%+v", s.State)
				}
			}
			return false, "not started"
		})
		raw, err := kc.CoreV1().Pods(refNS).GetLogs(p.Name, &corev1.PodLogOptions{Container: name}).DoRaw(l.ctx)
		if err != nil {
			t.Fatal(err)
		}
		results[component] = strings.TrimSpace(string(raw))
	}
	l.record("egress to the API server", map[string]any{"target": target, "results": results})
	if !strings.HasPrefix(results["worker"], "CONNECTED") {
		t.Errorf("the worker's probe did not connect, so the probe proves nothing: %q", results["worker"])
	}
	if !strings.HasPrefix(results["evaluator"], "BLOCKED") {
		t.Errorf("the evaluator reached the API server: %q", results["evaluator"])
	}
}

// refAssess runs one assessment through the worker: Collect over the live
// Namespaces and a missing one, ReadResult, Acknowledge and Evaluate.
func (l *live) refAssess(conn grpc.ClientConnInterface, uids map[string]string, step string) {
	t := l.t
	t.Helper()
	c, err := providerkit.NewClient(conn, refCompat(providerv1.Capability_CAPABILITY_COLLECT, providerv1.Capability_CAPABILITY_EVALUATE), nil)
	if err != nil {
		t.Fatal(err)
	}
	call := func() (context.Context, context.CancelFunc) { return context.WithTimeout(l.ctx, 30*time.Second) }
	scope := &providerv1.Scope{Cluster: "live", Namespaces: []*providerv1.Namespace{
		{Name: "erl-team-a", Uid: uids["erl-team-a"]}, {Name: "erl-team-b", Uid: uids["erl-team-b"]},
		{Name: "erl-missing", Uid: "00000000-0000-4000-8000-000000000000"}}}
	ctx, cancel := call()
	defer cancel()
	deadline, _ := ctx.Deadline()
	ref, err := c.Collect(ctx, scope, nil, deadline)
	if err != nil {
		t.Fatalf("%s: collect: %v", step, err)
	}
	if got := ref.GetLimitations(); len(got) != 1 || got[0] != "namespace erl-missing is not in the Kubernetes API" {
		t.Errorf("%s: limitations %q", step, got)
	}
	payload, err := c.ReadResult(ctx, ref)
	if err != nil {
		t.Fatalf("%s: read result: %v", step, err)
	}
	if err := c.Acknowledge(ctx, ref); err != nil {
		t.Fatalf("%s: acknowledge: %v", step, err)
	}
	def, _ := json.Marshal(map[string]string{"label": "owner"})
	ev, err := c.Evaluate(ctx, providerkit.EvaluateInput{PayloadVersion: 1, EvaluatorVersion: 1, Payload: payload, At: time.Now().UTC().Add(time.Second),
		Scope: scope, Content: []*providerv1.ContentReference{{Bundle: "live", ManifestDigest: providerkit.Digest([]byte("live"))}},
		Checks: []*providerv1.CheckDefinition{{Kind: refCheckKind, Name: "namespace-owner", Definition: def}}})
	if err != nil {
		t.Fatalf("%s: evaluate: %v", step, err)
	}
	got := map[string]string{}
	for _, o := range ev.Observations {
		got[o.GetSubject()] = o.GetState().String() + " " + o.GetOutcome().String()
	}
	want := map[string]string{
		"erl-team-a":  "EVIDENCE_STATE_ATTRIBUTABLE OUTCOME_PASS",
		"erl-team-b":  "EVIDENCE_STATE_ATTRIBUTABLE OUTCOME_FAIL",
		"erl-missing": "EVIDENCE_STATE_MISSING OUTCOME_UNSPECIFIED",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("%s: observations %v, want %v", step, got, want)
	}
	l.record("assessment "+step, map[string]any{"result": ref.GetResultId(), "bytes": ref.GetSizeBytes(), "sha256": ref.GetSha256(), "observations": got})
}
