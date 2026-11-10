package registry

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

func TestCredentialScope(t *testing.T) {
	s := newCredentialScope("https", "registry.example", "bundles/x")
	redirect := &http.Response{}
	for _, tc := range []struct {
		name, method, url string
		authz, redirected bool
		wantErr, keepAuth bool
	}{
		{"registry API", "GET", "https://registry.example/v2/bundles/x/manifests/sha256:1", true, false, false, true},
		{"explicit default port", "GET", "https://registry.example:443/v2/bundles/x/blobs/sha256:1", true, false, false, true},
		{"same-origin token realm", "GET", "https://registry.example/token?scope=x", true, false, false, true},
		{"same-origin OAuth2 token POST", "POST", "https://registry.example/oauth2/token", false, false, false, false},
		{"realm on another host", "GET", "https://auth.example/token", true, false, true, false},
		{"realm on another port", "GET", "https://registry.example:8443/token", true, false, true, false},
		{"realm over another scheme", "GET", "http://registry.example/token", true, false, true, false},
		{"OAuth2 POST to another host", "POST", "https://auth.example/token", false, false, true, false},
		{"anonymous token from another host", "GET", "https://auth.example/token", false, false, false, false},
		{"redirect within the repository", "GET", "https://registry.example/v2/bundles/x/blobs/sha256:2", true, true, false, true},
		{"redirect to another host", "GET", "https://storage.example/blob", true, true, false, false},
		{"redirect to a subdomain", "GET", "https://cdn.registry.example/blob", true, true, false, false},
		{"redirect to another repository", "GET", "https://registry.example/v2/other/blobs/sha256:2", true, true, false, false},
		{"redirect to a repository prefix", "GET", "https://registry.example/v2/bundles/xy/blobs/sha256:2", true, true, false, false},
		{"redirect with dot segments", "GET", "https://registry.example/v2/bundles/x/../../other/blobs/sha256:2", true, true, false, false},
		{"redirect with escapes", "GET", "https://registry.example/v2/bundles/x/%2e%2e/y", true, true, false, false},
		{"redirect outside /v2", "GET", "https://registry.example/storage/blob", true, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, tc.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.authz {
				req.Header.Set("Authorization", "Basic c2VjcmV0")
			}
			if tc.redirected {
				req.Response = redirect
			}
			out, err := s.guard(req)
			if tc.wantErr {
				if !errors.Is(err, ErrCredentialScope) || out != nil {
					t.Fatalf("want ErrCredentialScope, got %v", err)
				}
				if strings.Contains(err.Error(), "c2VjcmV0") {
					t.Fatal("error contains the header")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := out.Header.Get("Authorization") != ""; got != (tc.authz && tc.keepAuth) {
				t.Fatalf("Authorization kept=%v", got)
			}
			if tc.authz && req.Header.Get("Authorization") == "" {
				t.Fatal("the caller's request was modified")
			}
		})
	}
}

type transportFunc func(context.Context, bundle.BundleSource) (http.RoundTripper, error)

func (f transportFunc) Transport(ctx context.Context, src bundle.BundleSource) (http.RoundTripper, error) {
	return f(ctx, src)
}

func TestPerSourceTransports(t *testing.T) {
	if _, err := NewClient(Options{Transport: http.DefaultTransport, Transports: transportFunc(nil)}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("both transports accepted: %v", err)
	}
	f := newFakeRegistry(t)
	d := f.publishSigned(t)
	for _, tc := range []struct {
		name string
		rt   http.RoundTripper
		err  error
		want error
	}{
		{"provider error", nil, errors.New("ca ConfigMap \"x\" not found"), ErrTrustConfig},
		{"no transport", nil, nil, ErrTrustConfig},
		{"insecure transport", &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, nil, ErrInvalidRequest},
	} {
		c, err := NewClient(Options{TestOnlyPlainHTTP: true, Transports: transportFunc(func(context.Context, bundle.BundleSource) (http.RoundTripper, error) {
			return tc.rt, tc.err
		})})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Fetch(context.Background(), f.source(), d.String()); !errors.Is(err, tc.want) {
			t.Fatalf("%s: want %v, got %v", tc.name, tc.want, err)
		}
		if len(f.log()) != 0 {
			t.Fatalf("%s: registry contacted", tc.name)
		}
	}
	var asked []string
	c, err := NewClient(Options{TestOnlyPlainHTTP: true, Transports: transportFunc(func(_ context.Context, src bundle.BundleSource) (http.RoundTripper, error) {
		asked = append(asked, src.Name)
		return f.srv.Client().Transport, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Fetch(context.Background(), f.source(), d.String()); err != nil || len(asked) != 1 {
		t.Fatalf("per-source transport: %v, asked %v", err, asked)
	}
}
