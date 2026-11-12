package main

import (
	"flag"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
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
