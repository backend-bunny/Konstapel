package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/internal/s3store"
)

// A credentialSecret destination's Secret is read, uncached, from the
// controller's own namespace.
// +kubebuilder:rbac:groups="",namespace=konstapel-system,resources=secrets,verbs=get
// EvidenceDestinations are platform-managed; the controller reads them and
// owns their status.
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=evidencedestinations,verbs=get;list;watch
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=evidencedestinations/status,verbs=get;update;patch

// EvidenceConfig selects the production evidence destination.
type EvidenceConfig struct {
	// Destination is the S3 destination YAML file (s3store.LoadDestination).
	Destination string
	// StagingDir holds frozen captures and packages until publication.
	StagingDir string
	// ContentDir is the verified content directory (named "content") whose
	// parent the exporter reads.
	ContentDir string
	// Namespace is the controller's namespace, the only place a credential
	// Secret is read from.
	Namespace string
}

// EvidenceRuntime builds the assessment runtime for an S3 evidence
// destination. It validates configuration but does not contact the backend:
// readiness is probed while running, and scheduling stays disabled with the
// reason on bindings until the probe passes.
func EvidenceRuntime(ctx context.Context, cfg *rest.Config, ec EvidenceConfig) (AssessmentRuntime, error) {
	d, err := s3store.LoadDestination(ec.Destination)
	if err != nil {
		return AssessmentRuntime{}, err
	}
	if filepath.Base(filepath.Clean(ec.ContentDir)) != "content" {
		return AssessmentRuntime{}, fmt.Errorf("content root %s must be a directory named content", ec.ContentDir)
	}
	if d.CredentialSecret != nil && ec.Namespace == "" {
		return AssessmentRuntime{}, fmt.Errorf("evidence destination %s uses a credential Secret but the controller namespace is unknown (set POD_NAMESPACE)", d.ID)
	}
	if ec.StagingDir == "" {
		return AssessmentRuntime{}, fmt.Errorf("an evidence staging directory is required")
	}
	if err := os.MkdirAll(ec.StagingDir, 0o700); err != nil {
		return AssessmentRuntime{}, fmt.Errorf("evidence staging directory: %w", err)
	}
	reader, err := client.New(cfg, client.Options{Scheme: Scheme()})
	if err != nil {
		return AssessmentRuntime{}, err
	}
	pub, err := s3store.NewPublisher(ctx, d, reader, ec.Namespace)
	if err != nil {
		return AssessmentRuntime{}, err
	}
	return AssessmentRuntime{
		Publisher:           pub,
		StagingDir:          ec.StagingDir,
		ControllerNamespace: ec.Namespace,
		ContentRoot:         filepath.Dir(filepath.Clean(ec.ContentDir)),
		Ready: func(ctx context.Context) error {
			_, err := pub.Ready(ctx)
			return err
		},
	}, nil
}
