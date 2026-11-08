package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"net"
	"os"
	"strings"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/backend-bunny/Konstapel/internal/controller"
	"github.com/backend-bunny/Konstapel/internal/download"
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
	caFile := fs.String("tls-ca-file", "", "CA bundle clients use to trust this server; when set, the certificate must chain to it")
	var names stringList
	fs.Var(&names, "tls-server-name", "a service DNS name clients use; the certificate must cover it (repeatable)")
	audience := fs.String("audience", "konstapel-download", "token audience callers must request (kubectl create token --audience)")
	tmp := fs.String("temp-dir", os.TempDir(), "directory for archives while they are verified")
	maxConcurrent := fs.Int("max-concurrent", 4, "concurrent downloads")
	maxDisk := fs.Int64("max-temp-bytes", 2<<30, "temporary disk bytes across concurrent downloads")
	drain := fs.Duration("shutdown-drain", download.DefaultDrain, "how long accepted downloads may finish after a termination signal before connections are closed")
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
	if err := download.VerifyServingCertificate(*cert, *key, *caFile, names, time.Now()); err != nil {
		return err
	}
	ctx := ctrl.SetupSignalHandler()
	ns := os.Getenv("POD_NAMESPACE")
	// Runs are served from their pinned EvidenceDestination; a legacy run
	// is served once its migration attached it to one.
	destinations := &controller.DestinationPublishers{Reader: c, Namespace: ns}
	if err := os.MkdirAll(*tmp, 0o700); err != nil {
		return err
	}
	srv := &download.Server{Reader: c, Reviews: download.KubeReviewer{Client: c, Audience: *audience},
		PublisherFor: func(ctx context.Context, run *v1alpha1.AssessmentRun) (publication.Publisher, error) {
			return destinations.For(ctx, run.Status.Destination)
		},
		TempDir: *tmp, MaxConcurrent: *maxConcurrent, MaxDiskBytes: *maxDisk}
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	return download.Serve(ctx, l, *cert, *key, srv.Handler(), *drain)
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }
