package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ServiceAccountDir is where the kubelet mounts a Pod's ServiceAccount
// token and the cluster CA.
const ServiceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// maxNamespaceBytes bounds one Namespace response.
const maxNamespaceBytes = 1 << 20

// Kubernetes reads Namespaces from the Kubernetes API with the Pod's own
// ServiceAccount: one get per scope namespace, nothing else. It is the
// source worker's only source access; the reference chart grants that
// ServiceAccount get on namespaces and nothing more.
//
// It talks to the API over plain HTTPS rather than through client-go, so
// the example module stays small. The token is re-read for every request,
// because the kubelet rotates projected tokens.
type Kubernetes struct {
	// Server is the API server's base URL.
	Server string
	// TokenFile holds the bearer token.
	TokenFile string
	client    *http.Client
}

// InCluster returns the source for the Pod's own API server and
// ServiceAccount, from the environment and files the kubelet provides.
func InCluster() (*Kubernetes, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are not set; not running in a Pod")
	}
	return NewKubernetes("https://"+net.JoinHostPort(host, port), filepath.Join(ServiceAccountDir, "token"), filepath.Join(ServiceAccountDir, "ca.crt"))
}

// NewKubernetes returns a source for server, authenticating with the token
// in tokenFile and trusting only the CA certificates in caFile.
func NewKubernetes(server, tokenFile, caFile string) (*Kubernetes, error) {
	if _, err := url.Parse(server); err != nil || !strings.HasPrefix(server, "https://") {
		return nil, fmt.Errorf("API server %q must be an https URL", server)
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read the API server CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s holds no CA certificate", caFile)
	}
	if _, err := os.Stat(tokenFile); err != nil {
		return nil, fmt.Errorf("ServiceAccount token: %w", err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, Proxy: nil,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxIdleConnsPerHost: 2}
	return &Kubernetes{Server: strings.TrimSuffix(server, "/"), TokenFile: tokenFile,
		client: &http.Client{Transport: transport, Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (*Kubernetes) String() string { return "the Kubernetes API" }

// Namespace gets one Namespace. 404 is an absent namespace; any other
// failure, a denied request included, is an error.
func (k *Kubernetes) Namespace(ctx context.Context, name string) (Namespace, bool, error) {
	token, err := os.ReadFile(k.TokenFile)
	if err != nil {
		return Namespace{}, false, fmt.Errorf("read the ServiceAccount token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.Server+"/api/v1/namespaces/"+url.PathEscape(name), nil)
	if err != nil {
		return Namespace{}, false, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	resp, err := k.client.Do(req)
	if err != nil {
		return Namespace{}, false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxNamespaceBytes+1))
	if err != nil {
		return Namespace{}, false, err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return Namespace{}, false, nil
	case resp.StatusCode != http.StatusOK:
		return Namespace{}, false, fmt.Errorf("get namespace %s: HTTP %d", name, resp.StatusCode)
	case len(body) > maxNamespaceBytes:
		return Namespace{}, false, fmt.Errorf("namespace %s is larger than %d bytes", name, maxNamespaceBytes)
	}
	var obj struct {
		Kind     string `json:"kind"`
		Metadata struct {
			Name   string            `json:"name"`
			UID    string            `json:"uid"`
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return Namespace{}, false, fmt.Errorf("namespace %s: %w", name, err)
	}
	if obj.Kind != "Namespace" || obj.Metadata.Name != name || obj.Metadata.UID == "" {
		return Namespace{}, false, fmt.Errorf("the API returned %s %q for namespace %s", obj.Kind, obj.Metadata.Name, name)
	}
	labels := obj.Metadata.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	return Namespace{UID: obj.Metadata.UID, Labels: labels}, true, nil
}
