package main

import (
	"context"
	"flag"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/provider"
)

func TestBundleFlags(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      []string
		namespace string
		want      stack.Options
		wantErr   string
	}{
		{name: "default off", args: nil, namespace: "konstapel-system", want: stack.Options{}},
		{name: "off without a namespace", args: nil, want: stack.Options{}},
		{name: "cache dir without sources", args: []string{"--bundle-cache-dir=/cache"}, wantErr: "--bundle-cache-dir requires --bundle-sources-configmap"},
		{name: "capacity without sources", args: []string{"--bundle-cache-capacity=2Gi"}, wantErr: "--bundle-cache-capacity requires"},
		{name: "refresh without sources", args: []string{"--bundle-refresh-interval=1m"}, wantErr: "--bundle-refresh-interval requires"},
		{name: "enabled with defaults", args: []string{"--bundle-sources-configmap=konstapel-bundle-sources", "--bundle-cache-dir=/var/cache/konstapel/bundles"},
			namespace: "konstapel-system",
			want: stack.Options{SourcesConfigMap: "konstapel-bundle-sources", Namespace: "konstapel-system", CacheDir: "/var/cache/konstapel/bundles",
				RefreshInterval: 30 * time.Second, ControllerVersion: version}},
		{name: "enabled with everything", args: []string{"--bundle-sources-configmap=src", "--bundle-cache-dir=/c", "--bundle-cache-capacity=2Gi", "--bundle-refresh-interval=5m"},
			namespace: "ns",
			want:      stack.Options{SourcesConfigMap: "src", Namespace: "ns", CacheDir: "/c", CacheCapacity: 2 << 30, RefreshInterval: 5 * time.Minute, ControllerVersion: version}},
		{name: "enabled without a namespace", args: []string{"--bundle-sources-configmap=src", "--bundle-cache-dir=/c"}, wantErr: "POD_NAMESPACE"},
		{name: "enabled without a cache dir", args: []string{"--bundle-sources-configmap=src"}, namespace: "ns", wantErr: "cache directory"},
		{name: "relative cache dir", args: []string{"--bundle-sources-configmap=src", "--bundle-cache-dir=cache"}, namespace: "ns", wantErr: "absolute"},
		{name: "bad capacity", args: []string{"--bundle-sources-configmap=src", "--bundle-cache-dir=/c", "--bundle-cache-capacity=lots"}, namespace: "ns", wantErr: "--bundle-cache-capacity"},
		{name: "fractional capacity", args: []string{"--bundle-sources-configmap=src", "--bundle-cache-dir=/c", "--bundle-cache-capacity=0.5"}, namespace: "ns", wantErr: "whole number"},
		{name: "capacity too small", args: []string{"--bundle-sources-configmap=src", "--bundle-cache-dir=/c", "--bundle-cache-capacity=1Mi"}, namespace: "ns", wantErr: "cannot hold one maximal entry"},
		{name: "refresh too long", args: []string{"--bundle-sources-configmap=src", "--bundle-cache-dir=/c", "--bundle-refresh-interval=10m"}, namespace: "ns", wantErr: "refresh interval"},
		{name: "refresh zero", args: []string{"--bundle-sources-configmap=src", "--bundle-cache-dir=/c", "--bundle-refresh-interval=0s"}, namespace: "ns", wantErr: "must be positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("controller", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			b := addBundleFlags(fs)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			got, err := b.options(fs, tc.namespace)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("options %+v, want %+v", got, tc.want)
			}
		})
	}
}

// --protected-package-readers: unset leaves the check unconfigured (the
// controller then withholds supporting evidence), "none" needs no reader,
// and a Deployment name needs the pod's own identity.
func TestReaderCheck(t *testing.T) {
	for _, tc := range []struct {
		name, value, namespace, pod string
		wantNil                     bool
		wantErr                     string
	}{
		{name: "unset", wantNil: true},
		{name: "no download service", value: "none"},
		{name: "deployment", value: "konstapel-download", namespace: "konstapel-system", pod: "konstapel-controller-0"},
		{name: "deployment without pod name", value: "konstapel-download", namespace: "konstapel-system", wantErr: "POD_NAME"},
		{name: "deployment without namespace", value: "konstapel-download", pod: "p", wantErr: "POD_NAMESPACE"},
		{name: "not a name", value: "deployment/konstapel-download", namespace: "ns", pod: "p", wantErr: "must be"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readerCheck(tc.value, tc.namespace, tc.pod, nil)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || (got == nil) != tc.wantNil {
				t.Fatalf("check %v, error %v", got != nil, err)
			}
		})
	}
	// "none" passes without contacting anything.
	if check, _ := readerCheck("none", "", "", nil); check(context.Background()) != nil {
		t.Fatal("none failed")
	}
}

// The --collection-* flags default to provider.DefaultLimits without a
// deadline (each binding's collection timeout stays the deadline), and
// startup refuses values out of range or combinations that could never
// complete, naming the flag; nothing is clamped.
func TestCollectionFlags(t *testing.T) {
	defaults := provider.DefaultLimits()
	defaults.Timeout = 0
	for _, tc := range []struct {
		name    string
		args    []string
		want    provider.Limits
		wantErr string
	}{
		{name: "unset", want: defaults},
		{name: "defaults spelled out", args: []string{"--collection-page-size=500", "--collection-max-requests=20000", "--collection-max-objects=100000", "--collection-max-bytes=536870912"}, want: defaults},
		{name: "raised", args: []string{"--collection-max-objects=250000", "--collection-max-bytes=2147483648", "--collection-max-requests=40000", "--collection-page-size=1000"},
			want: provider.Limits{PageSize: 1000, MaxPages: 40_000, MaxObjects: 250_000, MaxBytes: 2 << 30}},
		{name: "lowered", args: []string{"--collection-max-objects=10", "--collection-page-size=5", "--collection-max-requests=2", "--collection-max-bytes=1572864"},
			want: provider.Limits{PageSize: 5, MaxPages: 2, MaxObjects: 10, MaxBytes: 3 << 19}},
		{name: "zero objects", args: []string{"--collection-max-objects=0"}, wantErr: "--collection-max-objects 0 must be between 1 and 10000000"},
		{name: "negative bytes", args: []string{"--collection-max-bytes=-1"}, wantErr: "--collection-max-bytes -1 must be at least 1572864"},
		{name: "zero requests", args: []string{"--collection-max-requests=0"}, wantErr: "--collection-max-requests 0 must be between"},
		{name: "page size zero", args: []string{"--collection-page-size=0"}, wantErr: "--collection-page-size 0 must be between 1 and 10000"},
		{name: "page size above the ceiling", args: []string{"--collection-page-size=10001", "--collection-max-bytes=1073741824"}, wantErr: "--collection-page-size 10001"},
		{name: "page above objects", args: []string{"--collection-max-objects=100"}, wantErr: "--collection-page-size 500 must not exceed --collection-max-objects 100"},
		{name: "unreachable object limit", args: []string{"--collection-page-size=1"}, wantErr: "--collection-max-requests 20000 is fewer than the 100000 list requests"},
		{name: "bytes below one page", args: []string{"--collection-page-size=1000", "--collection-max-bytes=4000000"}, wantErr: "--collection-max-bytes 4000000 must be at least 4096000"},
		{name: "objects above the ceiling", args: []string{"--collection-max-objects=10000001"}, wantErr: "--collection-max-objects 10000001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("controller", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			c := addCollectionFlags(fs)
			if err := fs.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			got, err := c.limits()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.HasPrefix(err.Error(), "collection limits: ") {
					t.Fatalf("error %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("limits %+v (%v), want %+v", got, err, tc.want)
			}
		})
	}
	// A value that is not an integer is a parse error, not a default.
	fs := flag.NewFlagSet("controller", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addCollectionFlags(fs)
	if err := fs.Parse([]string{"--collection-max-bytes=1Gi"}); err == nil {
		t.Fatal("--collection-max-bytes=1Gi parsed")
	}
}
