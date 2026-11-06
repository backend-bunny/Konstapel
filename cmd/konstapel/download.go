package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"net"
	"os"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/backend-bunny/Konstapel/internal/controller"
	"github.com/backend-bunny/Konstapel/internal/download"
	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// runDownload serves verified evidence packages:
// `konstapel download-server [flags]`. Its service account needs
// config/rbac/evidence-download.yaml and, for a credentialSecret
// destination, get on that Secret in its namespace.
func runDownload(args []string) error {
	fs := flag.NewFlagSet("download-server", flag.ContinueOnError)
	addr := fs.String("listen", ":8443", "TLS listen address")
	cert := fs.String("tls-cert-file", "", "TLS certificate (required)")
	key := fs.String("tls-private-key-file", "", "TLS private key (required)")
	audience := fs.String("audience", "konstapel-download", "token audience callers must request (kubectl create token --audience)")
	dest := fs.String("evidence-destination", "", "legacy S3 evidence destination YAML file for runs without a pinned EvidenceDestination")
	tmp := fs.String("temp-dir", os.TempDir(), "directory for archives while they are verified")
	maxConcurrent := fs.Int("max-concurrent", 4, "concurrent downloads")
	maxDisk := fs.Int64("max-temp-bytes", 2<<30, "temporary disk bytes across concurrent downloads")
	zopts := zap.Options{}
	zopts.BindFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zopts)))
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("kubernetes configuration: %w", err)
	}
	c, err := client.New(cfg, client.Options{Scheme: controller.Scheme()})
	if err != nil {
		return err
	}
	ctx := ctrl.SetupSignalHandler()
	ns := os.Getenv("POD_NAMESPACE")
	// Pinned runs are served from their EvidenceDestination; the optional
	// legacy file destination serves unpinned runs.
	destinations := &controller.DestinationPublishers{Reader: c, Namespace: ns}
	var legacy publication.Publisher
	if *dest != "" {
		d, err := s3store.LoadDestination(*dest)
		if err != nil {
			return err
		}
		if legacy, err = s3store.NewPublisher(ctx, d, c, ns); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(*tmp, 0o700); err != nil {
		return err
	}
	srv := &download.Server{Reader: c, Reviews: download.KubeReviewer{Client: c, Audience: *audience}, Publisher: legacy,
		PublisherFor: func(ctx context.Context, run *v1alpha1.AssessmentRun) (publication.Publisher, error) {
			return destinations.For(ctx, run.Status.Destination)
		},
		TempDir: *tmp, MaxConcurrent: *maxConcurrent, MaxDiskBytes: *maxDisk}
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	return download.Serve(ctx, l, *cert, *key, srv.Handler())
}
