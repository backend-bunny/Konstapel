package external_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/provider/external"
	"github.com/backend-bunny/Konstapel/internal/provider/external/externaltest"
	providerv1 "github.com/backend-bunny/Konstapel/pkg/providerapi/v1"
)

// trustStore is the serverTrust ConfigMaps the controller would read.
type trustStore struct {
	mu    sync.Mutex
	data  map[string][]byte
	reads int
}

func (s *trustStore) read(_ context.Context, name, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	b, ok := s.data[name+"/"+key]
	if !ok {
		return nil, fmt.Errorf("serverTrust ConfigMap %s has no key %s", name, key)
	}
	return b, nil
}

func (s *trustStore) set(name string, pem []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[name+"/ca.crt"] = pem
}

// world is a controller's view of one provider endpoint over real mutual
// TLS: its own credentials, the trust ConfigMaps, and where each Service
// actually listens.
type world struct {
	t      *testing.T
	ca     *externaltest.CA
	client string
	trust  *trustStore
	addrs  map[string]string // Service name -> loopback address
	dialer *external.Dialer
}

func newWorld(t *testing.T) *world {
	ca := externaltest.NewCA(t)
	w := &world{t: t, ca: ca, client: externaltest.ClientDir(t, ca), trust: &trustStore{data: map[string][]byte{}}, addrs: map[string]string{}}
	w.trust.set(externaltest.TrustConfig, ca.PEM)
	w.dialer = &external.Dialer{Credentials: external.CredentialsDir(w.client), Trust: w.trust.read,
		Address: func(e external.Endpoint) string { return w.addrs[e.Service] }}
	return w
}

func (w *world) serve(o externaltest.ServerOptions) *externaltest.Server {
	if o.CA == nil {
		o.CA = w.ca
	}
	s := externaltest.Serve(w.t, o)
	w.addrs[externaltest.ServiceName] = s.Addr
	return s
}

func (w *world) probe(ap *v1alpha1.AssessmentProvider, d time.Duration) external.Observation {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return w.dialer.Probe(ctx, ap, time.Now)
}

func wantProblem(t *testing.T, obs external.Observation, condition, reason string) {
	t.Helper()
	p := obs.Problem
	if p == nil || p.Condition != condition || p.Reason != reason {
		t.Fatalf("observation %+v, want %s %s", p, condition, reason)
	}
	if strings.Contains(p.Message, "PRIVATE KEY") || strings.Contains(p.Message, "BEGIN CERTIFICATE") {
		t.Fatalf("the problem carries PEM material: %s", p.Message)
	}
}

// A compatible endpoint is authenticated with the registration's server
// name and trust and described; the connection names the endpoint's
// identity.
func TestConnectAuthenticatesAndDescribes(t *testing.T) {
	w := newWorld(t)
	s := w.serve(externaltest.ServerOptions{})
	ap := externaltest.Registration("reporting")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := w.dialer.Connect(ctx, external.Expected(ap))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.Description.GetImplementation() != externaltest.Release || conn.Description.GetProvider().GetName() != externaltest.Provider {
		t.Fatalf("description %v", conn.Description)
	}
	if s.Describes.Load() != 1 || s.Calls.Load() != 1 {
		t.Fatalf("calls %d describes %d", s.Calls.Load(), s.Describes.Load())
	}
	if obs := w.probe(ap, 5*time.Second); obs.Problem != nil || obs.Generation != 1 {
		t.Fatalf("probe %+v", obs.Problem)
	}
	if _, err := w.dialer.Connect(context.Background(), external.Expected(ap)); err == nil {
		t.Fatal("connected without a deadline")
	}
}

// Nothing is sent to an endpoint the controller cannot authenticate, and
// each failure is attributed to its own bounded reason.
func TestConnectRefusesUnauthenticatedEndpoints(t *testing.T) {
	ap := externaltest.Registration("reporting")
	for _, tc := range []struct {
		name   string
		setup  func(w *world) *externaltest.Server
		reason string
	}{
		{name: "trust ConfigMap missing", reason: v1alpha1.ProviderReasonTrustUnavailable, setup: func(w *world) *externaltest.Server {
			w.trust.data = map[string][]byte{}
			return w.serve(externaltest.ServerOptions{})
		}},
		{name: "trust not PEM", reason: v1alpha1.ProviderReasonTrustUnavailable, setup: func(w *world) *externaltest.Server {
			w.trust.set(externaltest.TrustConfig, []byte("not a certificate"))
			return w.serve(externaltest.ServerOptions{})
		}},
		{name: "trust with a private key", reason: v1alpha1.ProviderReasonTrustUnavailable, setup: func(w *world) *externaltest.Server {
			l := w.ca.Issue(t, x509.ExtKeyUsageServerAuth, "x.svc")
			w.trust.set(externaltest.TrustConfig, append(append([]byte(nil), w.ca.PEM...), l.Key...))
			return w.serve(externaltest.ServerOptions{})
		}},
		{name: "client credentials missing", reason: v1alpha1.ProviderReasonClientCredentialsUnavailable, setup: func(w *world) *externaltest.Server {
			w.dialer.Credentials = external.CredentialsDir(t.TempDir())
			return w.serve(externaltest.ServerOptions{})
		}},
		{name: "client certificate for servers only", reason: v1alpha1.ProviderReasonClientCredentialsUnavailable, setup: func(w *world) *externaltest.Server {
			externaltest.WriteClient(t, w.client, w.ca.Issue(t, x509.ExtKeyUsageServerAuth, externaltest.ClientName))
			return w.serve(externaltest.ServerOptions{})
		}},
		{name: "untrusted server certificate", reason: v1alpha1.ProviderReasonAuthenticationFailed, setup: func(w *world) *externaltest.Server {
			return w.serve(externaltest.ServerOptions{CA: externaltest.NewCA(t), ClientTrust: w.ca.PEM})
		}},
		{name: "another server name", reason: v1alpha1.ProviderReasonAuthenticationFailed, setup: func(w *world) *externaltest.Server {
			return w.serve(externaltest.ServerOptions{ServerNames: []string{"impostor.providers.svc"}})
		}},
		{name: "provider rejects the controller", reason: v1alpha1.ProviderReasonAuthenticationFailed, setup: func(w *world) *externaltest.Server {
			return w.serve(externaltest.ServerOptions{AuthorizedClients: []string{"someone-else.svc"}})
		}},
		{name: "provider does not trust the controller", reason: v1alpha1.ProviderReasonAuthenticationFailed, setup: func(w *world) *externaltest.Server {
			return w.serve(externaltest.ServerOptions{ClientTrust: externaltest.NewCA(t).PEM})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			s := tc.setup(w)
			obs := w.probe(ap, 5*time.Second)
			wantProblem(t, obs, v1alpha1.ProviderConditionAvailable, tc.reason)
			if s.Calls.Load() != 0 {
				t.Fatalf("%d calls reached an endpoint that was not mutually authenticated", s.Calls.Load())
			}
		})
	}
}

// An endpoint that is not there, or never answers, is unavailable within
// the probe deadline.
func TestConnectBoundsUnreachableEndpoints(t *testing.T) {
	ap := externaltest.Registration("reporting")
	w := newWorld(t)
	w.addrs[externaltest.ServiceName] = externaltest.Closed(t)
	wantProblem(t, w.probe(ap, 5*time.Second), v1alpha1.ProviderConditionAvailable, v1alpha1.ProviderReasonEndpointUnavailable)

	w.addrs[externaltest.ServiceName] = externaltest.Hang(t)
	start := time.Now()
	wantProblem(t, w.probe(ap, 500*time.Millisecond), v1alpha1.ProviderConditionAvailable, v1alpha1.ProviderReasonEndpointUnavailable)
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("a hanging endpoint held the probe for %s", took)
	}
}

// An authenticated endpoint that does not serve what the registration
// expects is available but incompatible, one dimension at a time; the
// controller sends it nothing but Describe.
func TestConnectRejectsIncompatibleDescriptions(t *testing.T) {
	ap := externaltest.Registration("reporting")
	for _, tc := range []struct {
		name   string
		mutate func(d *providerv1.DescribeResponse)
		reason string
	}{
		{"another provider", func(d *providerv1.DescribeResponse) { d.Provider.Name = "other-reporting" }, v1alpha1.ProviderReasonProviderMismatch},
		{"another contract version", func(d *providerv1.DescribeResponse) { d.Provider.Version = 2 }, v1alpha1.ProviderReasonUnsupportedContractVersion},
		{"another protocol revision", func(d *providerv1.DescribeResponse) { d.ProtocolVersions = []uint32{1} }, v1alpha1.ProviderReasonUnsupportedProtocolVersion},
		{"another evaluator", func(d *providerv1.DescribeResponse) { d.EvaluatorVersion = 2 }, v1alpha1.ProviderReasonUnsupportedEvaluatorVersion},
		{"another payload", func(d *providerv1.DescribeResponse) {
			d.Payload = &providerv1.PayloadCompatibility{Write: 2, Read: []uint32{1, 2}}
		}, v1alpha1.ProviderReasonUnsupportedPayloadVersion},
		{"a missing capability", func(d *providerv1.DescribeResponse) {
			d.Capabilities = []providerv1.Capability{providerv1.Capability_CAPABILITY_COLLECT}
		}, v1alpha1.ProviderReasonUnsupportedCapability},
		{"another release", func(d *providerv1.DescribeResponse) { d.Implementation = externaltest.OtherRelease }, v1alpha1.ProviderReasonReleaseMismatch},
		{"no release", func(d *providerv1.DescribeResponse) { d.Implementation = "" }, v1alpha1.ProviderReasonReleaseMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "another protocol revision" {
				// The kit serves only its own revision; a server that lists
				// another is refused when it is built, so this dimension is
				// covered by the description check alone.
				d := externaltest.Description()
				tc.mutate(d)
				err := external.Expected(ap).CheckDescription(d)
				if err == nil || !strings.Contains(err.Error(), "UNSUPPORTED_PROTOCOL_VERSION") {
					t.Fatalf("check %v", err)
				}
				return
			}
			w := newWorld(t)
			d := externaltest.Description()
			tc.mutate(d)
			s := w.serve(externaltest.ServerOptions{Description: d})
			wantProblem(t, w.probe(ap, 5*time.Second), v1alpha1.ProviderConditionCompatible, tc.reason)
			if s.Calls.Load() != s.Describes.Load() {
				t.Fatalf("%d calls other than Describe reached an incompatible endpoint", s.Calls.Load()-s.Describes.Load())
			}
		})
	}
}

// The trust ConfigMap and the controller's credentials are read at each
// connection: after the provider rotates to a new CA it is unauthenticated
// until the ConfigMap holds the new roots, then authenticated again, with
// no restart; a rotated controller certificate is presented at once.
func TestConnectPicksUpRotatedTrustAndCredentials(t *testing.T) {
	w := newWorld(t)
	ca2 := externaltest.NewCA(t)
	s := w.serve(externaltest.ServerOptions{ClientTrust: append(append([]byte(nil), w.ca.PEM...), ca2.PEM...)})
	ap := externaltest.Registration("reporting")
	if obs := w.probe(ap, 5*time.Second); obs.Problem != nil {
		t.Fatal(obs.Problem)
	}
	s.Rotate(ca2)
	wantProblem(t, w.probe(ap, 5*time.Second), v1alpha1.ProviderConditionAvailable, v1alpha1.ProviderReasonAuthenticationFailed)
	w.trust.set(externaltest.TrustConfig, ca2.PEM)
	if obs := w.probe(ap, 5*time.Second); obs.Problem != nil {
		t.Fatalf("the rotated trust was not used: %v", obs.Problem)
	}
	// The controller's certificate rotates to the second CA as well.
	externaltest.WriteClient(t, w.client, ca2.Issue(t, x509.ExtKeyUsageClientAuth, externaltest.ClientName))
	if obs := w.probe(ap, 5*time.Second); obs.Problem != nil {
		t.Fatalf("the rotated client certificate was not used: %v", obs.Problem)
	}
	// A certificate the provider does not authorize is presented at once too.
	externaltest.WriteClient(t, w.client, ca2.Issue(t, x509.ExtKeyUsageClientAuth, "someone-else.svc"))
	wantProblem(t, w.probe(ap, 5*time.Second), v1alpha1.ProviderConditionAvailable, v1alpha1.ProviderReasonAuthenticationFailed)
}

func TestCredentialsCheck(t *testing.T) {
	ca := externaltest.NewCA(t)
	if err := external.CredentialsDir(externaltest.ClientDir(t, ca)).Check(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := external.CredentialsDir(dir).Check(); err == nil {
		t.Fatal("missing credentials passed")
	}
	externaltest.WriteClient(t, dir, ca.Issue(t, x509.ExtKeyUsageServerAuth, externaltest.ClientName))
	if err := external.CredentialsDir(dir).Check(); err == nil || !strings.Contains(err.Error(), "client authentication") {
		t.Fatalf("server-only credentials: %v", err)
	}
	other := ca.Issue(t, x509.ExtKeyUsageClientAuth, externaltest.ClientName)
	l := ca.Issue(t, x509.ExtKeyUsageClientAuth, externaltest.ClientName)
	externaltest.WriteClient(t, dir, externaltest.Leaf{Cert: l.Cert, Key: other.Key})
	err := external.CredentialsDir(dir).Check()
	if err == nil || strings.Contains(err.Error(), string(other.Key)) {
		t.Fatalf("mismatched credentials: %v", err)
	}
	if err := (external.Credentials{}).Check(); err == nil {
		t.Fatal("empty credentials passed")
	}
	var p *external.Problem
	if errors.As(err, &p) {
		t.Fatal("a credentials check is not a probe problem")
	}
}

// Frozen work that reconnects to an endpoint now serving another release
// fails with the frozen-work reason, not with the other release's answers.
func TestConnectRejectsAnotherImplementationForFrozenWork(t *testing.T) {
	w := newWorld(t)
	upgraded := externaltest.Description()
	upgraded.Implementation = externaltest.OtherRelease
	s := w.serve(externaltest.ServerOptions{Description: upgraded})
	frozen := external.Expected(externaltest.Registration("reporting"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := w.dialer.Connect(ctx, frozen)
	var fe *external.FrozenError
	var p *external.Problem
	if !errors.As(err, &fe) || fe.Reason != external.FrozenImplementationChanged || !errors.As(err, &p) || p.Reason != v1alpha1.ProviderReasonReleaseMismatch {
		t.Fatalf("connect: %v", err)
	}
	if s.Calls.Load() != s.Describes.Load() {
		t.Fatal("frozen work sent more than Describe to another release")
	}
}
