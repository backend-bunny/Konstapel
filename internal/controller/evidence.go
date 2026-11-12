package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// A credentialSecret destination's Secret is read, uncached, from the
// controller's own namespace. Its name is chosen in the EvidenceDestination
// spec, so the grant cannot carry static resourceNames; it is get only, never
// list or watch (docs/charts.md, "Controller ServiceAccount boundary").
// +kubebuilder:rbac:groups="",namespace=konstapel-system,resources=secrets,verbs=get
// EvidenceDestinations are platform-managed; the controller reads them and
// owns their status.
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=evidencedestinations,verbs=get;list;watch
// +kubebuilder:rbac:groups=compliance.erenius.io,resources=evidencedestinations/status,verbs=get;update;patch

// EvidenceConfig configures production evidence publication. Destinations
// are EvidenceDestination resources; the legacy destination file is gone.
type EvidenceConfig struct {
	// StagingDir holds frozen captures and packages until publication.
	StagingDir string
	// ContentDir is the verified content directory (named "content") whose
	// parent the exporter reads.
	ContentDir string
	// Namespace is the controller's namespace, the only place a credential
	// Secret is read from.
	Namespace string
}

// EvidenceRuntime builds the assessment runtime for EvidenceDestinations.
// It validates configuration but does not contact a backend: destinations
// are probed while running, and scheduling stays disabled with the reason
// on bindings until the selected destination is ready.
func EvidenceRuntime(_ context.Context, cfg *rest.Config, ec EvidenceConfig) (AssessmentRuntime, error) {
	if filepath.Base(filepath.Clean(ec.ContentDir)) != "content" {
		return AssessmentRuntime{}, fmt.Errorf("content root %s must be a directory named content", ec.ContentDir)
	}
	if ec.StagingDir == "" {
		return AssessmentRuntime{}, fmt.Errorf("an evidence staging directory is required")
	}
	staging := ec.StagingDir
	if err := os.MkdirAll(staging, 0o700); err != nil {
		// The controller still starts; evidence runs report "no staging
		// directory is configured" until it exists.
		staging = ""
	}
	reader, err := client.New(cfg, client.Options{Scheme: Scheme()})
	if err != nil {
		return AssessmentRuntime{}, err
	}
	return AssessmentRuntime{
		StagingDir:          staging,
		ContentRoot:         filepath.Dir(filepath.Clean(ec.ContentDir)),
		ControllerNamespace: ec.Namespace,
		// Runs pin an EvidenceDestination and publish there; legacy runs
		// are migrated to one.
		Destinations: &DestinationPublishers{Reader: reader, Namespace: ec.Namespace},
	}, nil
}
