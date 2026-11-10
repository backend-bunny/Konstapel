package registry

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// blocker holds manifest GETs open until released, recording how many are in
// flight and whether the client abandoned any.
type blocker struct {
	release   chan struct{}
	started   chan struct{}
	inFlight  atomic.Int32
	peak      atomic.Int32
	abandoned atomic.Int32
}

func newBlocker() *blocker {
	return &blocker{release: make(chan struct{}), started: make(chan struct{}, 100)}
}

func (b *blocker) hook(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/manifests/") {
		return false
	}
	n := b.inFlight.Add(1)
	defer b.inFlight.Add(-1)
	for {
		p := b.peak.Load()
		if n <= p || b.peak.CompareAndSwap(p, n) {
			break
		}
	}
	b.started <- struct{}{}
	select {
	case <-b.release:
		return false // fall through to the normal handler
	case <-r.Context().Done():
		b.abandoned.Add(1)
		return true
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (c *Client) waiters(src bundle.BundleSource, d digest.Digest) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cl := c.inflight[sourceKey(src)+"\x00"+d.String()]; cl != nil {
		return cl.waiters
	}
	return 0
}

type outcome struct {
	res *Result
	err error
}

func TestConcurrentRequestsAreDeduplicated(t *testing.T) {
	f := newFakeRegistry(t)
	d := f.publishSigned(t)
	b := newBlocker()
	f.setHook(b.hook)
	c := newTestClient(t, f, Limits{}, nil)
	out := make(chan outcome, 5)
	for range 5 {
		go func() {
			res, err := c.Fetch(context.Background(), f.source(), d.String())
			out <- outcome{res, err}
		}()
	}
	waitFor(t, "five waiters", func() bool { return c.waiters(f.source(), d) == 5 })
	close(b.release)
	var first *Result
	for range 5 {
		o := <-out
		if o.err != nil {
			t.Fatal(o.err)
		}
		if first == nil {
			first = o.res
		} else if o.res != first {
			t.Fatal("waiters received different results")
		}
	}
	if n := f.count("GET /v2/" + repoPath + "/manifests/" + d.String()); n != 1 {
		t.Fatalf("subject fetched %d times", n)
	}
	if n := f.count("/blobs/" + official(t).LayerDigest); n != 1 {
		t.Fatalf("layer fetched %d times", n)
	}
	// A completed retrieval is not cached: the next call fetches again.
	if _, err := c.Fetch(context.Background(), f.source(), d.String()); err != nil {
		t.Fatal(err)
	}
	if n := f.count("GET /v2/" + repoPath + "/manifests/" + d.String()); n != 2 {
		t.Fatalf("subject fetched %d times", n)
	}
}

func TestDifferentDigestsAndSourcesAreNotDeduplicated(t *testing.T) {
	f := newFakeRegistry(t)
	d := f.publishSigned(t)
	other := digest.FromString("missing")
	b := newBlocker()
	f.setHook(b.hook)
	c := newTestClient(t, f, Limits{}, staticCreds{Credential{Username: "u", Password: "p"}})
	withSecret := f.source()
	withSecret.CredentialSecret = &bundle.ObjectRef{Name: "creds"}
	var wg sync.WaitGroup
	errs := make([]error, 3)
	for i, req := range []struct {
		src bundle.BundleSource
		d   digest.Digest
	}{{f.source(), d}, {f.source(), other}, {withSecret, d}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = c.Fetch(context.Background(), req.src, req.d.String())
		}()
	}
	waitFor(t, "three requests", func() bool { return b.inFlight.Load() == 3 })
	close(b.release)
	wg.Wait()
	if errs[0] != nil || !errors.Is(errs[1], ErrNotFound) || errs[2] != nil {
		t.Fatal(errs)
	}
}

func TestCancelingOneWaiterDoesNotFailOthers(t *testing.T) {
	f := newFakeRegistry(t)
	d := f.publishSigned(t)
	b := newBlocker()
	f.setHook(b.hook)
	c := newTestClient(t, f, Limits{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan outcome, 3)
	// The first caller, whose context started the shared work, cancels.
	go func() {
		res, err := c.Fetch(ctx, f.source(), d.String())
		out <- outcome{res, err}
	}()
	waitFor(t, "first waiter", func() bool { return c.waiters(f.source(), d) == 1 })
	for range 2 {
		go func() {
			res, err := c.Fetch(context.Background(), f.source(), d.String())
			out <- outcome{res, err}
		}()
	}
	waitFor(t, "three waiters", func() bool { return c.waiters(f.source(), d) == 3 })
	cancel()
	if o := <-out; !errors.Is(o.err, context.Canceled) || Classify(o.err) != ClassCanceled {
		t.Fatalf("canceled waiter got %v", o.err)
	}
	close(b.release)
	for range 2 {
		if o := <-out; o.err != nil || o.res == nil {
			t.Fatalf("remaining waiter failed: %v", o.err)
		}
	}
	if b.abandoned.Load() != 0 {
		t.Fatal("the shared request was canceled")
	}
	if n := f.count("GET /v2/" + repoPath + "/manifests/" + d.String()); n != 1 {
		t.Fatalf("subject fetched %d times", n)
	}
}

func TestLastWaiterCancelingCancelsTheWork(t *testing.T) {
	f := newFakeRegistry(t)
	d := f.publishSigned(t)
	b := newBlocker()
	f.setHook(b.hook)
	defer close(b.release)
	c := newTestClient(t, f, Limits{}, nil)
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	out := make(chan error, 2)
	for _, ctx := range []context.Context{ctx1, ctx2} {
		go func() {
			_, err := c.Fetch(ctx, f.source(), d.String())
			out <- err
		}()
	}
	waitFor(t, "two waiters", func() bool { return c.waiters(f.source(), d) == 2 })
	<-b.started
	cancel1()
	if err := <-out; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if b.abandoned.Load() != 0 {
		t.Fatal("work canceled while a waiter remained")
	}
	cancel2()
	if err := <-out; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	waitFor(t, "the registry request to be abandoned", func() bool { return b.abandoned.Load() == 1 })
	if c.waiters(f.source(), d) != 0 {
		t.Fatal("abandoned work is still shared")
	}
}

func TestConcurrencyCap(t *testing.T) {
	f := newFakeRegistry(t)
	b := newBlocker()
	f.setHook(b.hook)
	c := newTestClient(t, f, Limits{}, nil)
	const n = 10
	out := make(chan error, n)
	for i := range n {
		go func() {
			_, err := c.Fetch(context.Background(), f.source(), digest.FromString(fmt.Sprint(i)).String())
			out <- err
		}()
	}
	waitFor(t, "four retrievals", func() bool { return b.inFlight.Load() == 4 })
	time.Sleep(100 * time.Millisecond)
	if p := b.peak.Load(); p != 4 {
		t.Fatalf("peak concurrent retrievals %d, want 4", p)
	}
	close(b.release)
	for range n {
		if err := <-out; !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	}
	if p := b.peak.Load(); p > 4 {
		t.Fatalf("peak concurrent retrievals %d", p)
	}
}

func TestRequestTimeout(t *testing.T) {
	f := newFakeRegistry(t)
	d := f.publishSigned(t)
	b := newBlocker()
	f.setHook(b.hook)
	defer close(b.release)
	c := newTestClient(t, f, Limits{RequestTimeout: 100 * time.Millisecond}, nil)
	start := time.Now()
	_, err := c.Fetch(context.Background(), f.source(), d.String())
	if err == nil || Classify(err) != ClassRetryable || time.Since(start) > 5*time.Second {
		t.Fatalf("err %v after %s", err, time.Since(start))
	}
}

func TestResolutionTimeout(t *testing.T) {
	f := newFakeRegistry(t)
	d := f.publishSigned(t)
	b := newBlocker()
	f.setHook(b.hook)
	defer close(b.release)
	c := newTestClient(t, f, Limits{ResolutionTimeout: 150 * time.Millisecond}, nil)
	_, err := c.Fetch(context.Background(), f.source(), d.String())
	if !errors.Is(err, context.DeadlineExceeded) || Classify(err) != ClassRetryable {
		t.Fatalf("err %v", err)
	}
	waitFor(t, "the registry request to be abandoned", func() bool { return b.abandoned.Load() == 1 })
}

func TestCallerCancellation(t *testing.T) {
	f := newFakeRegistry(t)
	d := f.publishSigned(t)
	b := newBlocker()
	f.setHook(b.hook)
	defer close(b.release)
	c := newTestClient(t, f, Limits{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-b.started; cancel() }()
	start := time.Now()
	_, err := c.Fetch(ctx, f.source(), d.String())
	if !errors.Is(err, context.Canceled) || time.Since(start) > 5*time.Second {
		t.Fatalf("err %v", err)
	}
	waitFor(t, "the registry request to be abandoned", func() bool { return b.abandoned.Load() == 1 })
	if _, err := c.Fetch(ctx, f.source(), d.String()); !errors.Is(err, context.Canceled) {
		t.Fatal("an already canceled caller started work")
	}
}

func TestBackoff(t *testing.T) {
	p := DefaultLimits().Retry
	for _, tc := range []struct {
		attempt int
		lo, hi  time.Duration
	}{
		{0, 5 * time.Second, 10 * time.Second},
		{1, 10 * time.Second, 20 * time.Second},
		{2, 20 * time.Second, 40 * time.Second},
		{4, 80 * time.Second, 160 * time.Second},
		{5, 150 * time.Second, 5 * time.Minute},
		{1000, 150 * time.Second, 5 * time.Minute},
		{-3, 5 * time.Second, 10 * time.Second},
	} {
		if got := p.Delay(tc.attempt, func() float64 { return 0 }); got != tc.lo {
			t.Errorf("attempt %d low %s, want %s", tc.attempt, got, tc.lo)
		}
		if got := p.Delay(tc.attempt, func() float64 { return 0.999999999 }); got < tc.hi-time.Second || got > tc.hi {
			t.Errorf("attempt %d high %s, want ~%s", tc.attempt, got, tc.hi)
		}
		mid := p.Delay(tc.attempt, func() float64 { return 0.5 })
		if mid != tc.lo+(tc.hi-tc.lo)/2 {
			t.Errorf("attempt %d mid %s", tc.attempt, mid)
		}
	}
	for _, r := range []float64{-1, 1, 7} { // out-of-range randomness stays bounded
		if got := p.Delay(3, func() float64 { return r }); got < p.Min || got > p.Max {
			t.Errorf("rnd %v: %s", r, got)
		}
	}
	if got := (RetryPolicy{Min: time.Second, Max: time.Second}).Delay(9, func() float64 { return 0.5 }); got != time.Second {
		t.Errorf("min == max: %s", got)
	}
}

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want Class
	}{
		{nil, ClassNone},
		{context.Canceled, ClassCanceled},
		{fmt.Errorf("x: %w", context.DeadlineExceeded), ClassRetryable},
		{errors.New("connection refused"), ClassRetryable},
		{fmt.Errorf("x: %w", ErrNotFound), ClassRetryable},
		{fmt.Errorf("x: %w", ErrUnauthorized), ClassRetryable},
		{fmt.Errorf("x: %w", ErrCredentials), ClassRetryable},
		{fmt.Errorf("x: %w", ErrIntegrity), ClassPermanent},
		{fmt.Errorf("x: %w", ErrUnexpectedDescriptor), ClassPermanent},
		{fmt.Errorf("x: %w", ErrLimitExceeded), ClassPermanent},
		{fmt.Errorf("x: %w", ErrReferrersUnsupported), ClassPermanent},
		{&redactedError{msg: "x", cause: ErrIntegrity}, ClassPermanent},
	} {
		if got := Classify(tc.err); got != tc.want {
			t.Errorf("%v: %s, want %s", tc.err, got, tc.want)
		}
	}
}

type staticCreds struct{ c Credential }

func (s staticCreds) Credential(context.Context, bundle.BundleSource, string) (Credential, error) {
	return s.c, nil
}

type recordingCreds struct {
	mu    sync.Mutex
	hosts []string
	cred  Credential
	err   error
}

func (r *recordingCreds) Credential(_ context.Context, _ bundle.BundleSource, host string) (Credential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hosts = append(r.hosts, host)
	return r.cred, r.err
}

const secretPassword = "s3cr3t-registry-password"

func TestCredentials(t *testing.T) {
	cred := Credential{Username: "robot", Password: secretPassword}
	basic := base64.StdEncoding.EncodeToString([]byte("robot:" + secretPassword))

	t.Run("authenticated retrieval asks only for the registry host", func(t *testing.T) {
		f := newFakeRegistry(t)
		d := f.publishSigned(t)
		f.basicUser, f.basicPass = "robot", secretPassword
		creds := &recordingCreds{cred: cred}
		src := f.source()
		src.CredentialSecret = &bundle.ObjectRef{Name: "registry-creds"}
		c := newTestClient(t, f, Limits{}, creds)
		if _, err := c.Fetch(context.Background(), src, d.String()); err != nil {
			t.Fatal(err)
		}
		for _, h := range creds.hosts {
			if h != f.host() {
				t.Fatalf("credential requested for %q", h)
			}
		}
		fn := c.credentialFunc(src, f.host(), &secrets{})
		if got, _ := fn(context.Background(), "other.example:443"); got.Password != "" {
			t.Fatal("credential released for another origin")
		}
	})

	t.Run("wrong credentials are recoverable and redacted", func(t *testing.T) {
		f := newFakeRegistry(t)
		d := f.publishSigned(t)
		// A hostile registry echoes the Authorization header in its error.
		f.setHook(func(w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("WWW-Authenticate", `Basic realm="fake"`)
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED",
				fmt.Sprintf("rejected %q (password %s)", r.Header.Get("Authorization"), secretPassword))
			return true
		})
		src := f.source()
		src.CredentialSecret = &bundle.ObjectRef{Name: "registry-creds"}
		c := newTestClient(t, f, Limits{}, staticCreds{cred})
		_, err := c.Fetch(context.Background(), src, d.String())
		if !errors.Is(err, ErrUnauthorized) || Classify(err) != ClassRetryable {
			t.Fatalf("err %v", err)
		}
		for _, leak := range []string{secretPassword, basic} {
			if strings.Contains(err.Error(), leak) || strings.Contains(fmt.Sprintf("%+v %#v", err, err), leak) {
				t.Fatalf("credential leaked: %s", err)
			}
		}
		if !strings.Contains(err.Error(), "[REDACTED]") {
			t.Fatalf("expected a redaction marker: %s", err)
		}
	})

	t.Run("missing configured credential never falls back to anonymous", func(t *testing.T) {
		for name, creds := range map[string]CredentialProvider{
			"no provider":    nil,
			"provider error": &recordingCreds{err: errors.New("secret registry-creds not found")},
			"empty":          &recordingCreds{},
		} {
			f := newFakeRegistry(t)
			d := f.publishSigned(t) // anonymously readable
			src := f.source()
			src.CredentialSecret = &bundle.ObjectRef{Name: "registry-creds"}
			c := newTestClient(t, f, Limits{}, creds)
			_, err := c.Fetch(context.Background(), src, d.String())
			if !errors.Is(err, ErrCredentials) || Classify(err) != ClassRetryable {
				t.Fatalf("%s: err %v", name, err)
			}
			if len(f.log()) != 0 {
				t.Fatalf("%s: registry contacted: %v", name, f.log())
			}
		}
	})

	t.Run("credential values are not formatted", func(t *testing.T) {
		for _, s := range []string{fmt.Sprint(cred), fmt.Sprintf("%v %+v %#v %s", cred, cred, cred, cred)} {
			if strings.Contains(s, secretPassword) || strings.Contains(s, "robot") {
				t.Fatalf("formatted credential: %s", s)
			}
		}
	})

	t.Run("token reset", func(t *testing.T) {
		f := newFakeRegistry(t)
		c := newTestClient(t, f, Limits{}, nil)
		src := f.source()
		before := c.tokenCache(src)
		if c.tokenCache(src) != before {
			t.Fatal("cache not reused")
		}
		other := src
		other.CredentialSecret = &bundle.ObjectRef{Name: "x"}
		if c.tokenCache(other) == before {
			t.Fatal("sources with different credentials share a token cache")
		}
		c.ResetTokens(src)
		if c.tokenCache(src) == before {
			t.Fatal("ResetTokens kept the cache")
		}
	})
}

func TestTransportSecurity(t *testing.T) {
	insecure := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	if _, err := NewClient(Options{Transport: insecure}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("insecure transport accepted: %v", err)
	}
	// Without the test-only option the client speaks TLS, so a plain-HTTP
	// registry is unreachable.
	f := newFakeRegistry(t)
	d := f.publishSigned(t)
	c, err := NewClient(Options{Transport: f.srv.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Fetch(context.Background(), f.source(), d.String()); err == nil {
		t.Fatal("plain HTTP used without the test-only option")
	}
	if len(f.log()) != 0 {
		t.Fatalf("plain HTTP request served: %v", f.log())
	}
}

func TestRedirectPolicy(t *testing.T) {
	c, err := NewClient(Options{})
	if err != nil {
		t.Fatal(err)
	}
	req := func(u string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, u, nil)
		return r
	}
	if err := c.checkRedirect(req("https://storage.example/blob"), []*http.Request{req("https://reg.example/v2/")}); err != nil {
		t.Fatal(err)
	}
	if err := c.checkRedirect(req("http://reg.example/blob"), []*http.Request{req("https://reg.example/v2/")}); !errors.Is(err, ErrInsecureRedirect) {
		t.Fatalf("downgrade allowed: %v", err)
	}
	via := make([]*http.Request, maxRedirects)
	if err := c.checkRedirect(req("https://reg.example/blob"), via); err == nil {
		t.Fatal("unbounded redirects")
	}
}
