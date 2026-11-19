package preview

import (
	"errors"
	"fmt"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// RESTConfig loads the caller's identity from kubeconfig: the explicit path, or
// the standard KUBECONFIG / ~/.kube/config rules when path is empty, and the
// named context or the current one. Unlike controller-runtime's loader it
// never falls back to an in-cluster ServiceAccount, so a preview always runs
// with credentials the caller chose. It returns the selected context name.
func RESTConfig(path, contextName string) (*rest.Config, string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if path != "" {
		rules.ExplicitPath = path
	}
	raw, err := rules.Load()
	if err != nil {
		return nil, "", fmt.Errorf("kubeconfig: %w", err)
	}
	if contextName == "" {
		contextName = raw.CurrentContext
	}
	if contextName == "" {
		return nil, "", errors.New("kubeconfig: no context selected and no current context")
	}
	if _, ok := raw.Contexts[contextName]; !ok {
		return nil, "", fmt.Errorf("kubeconfig: context %q not found", contextName)
	}
	cfg, err := clientcmd.NewNonInteractiveClientConfig(*raw, contextName, &clientcmd.ConfigOverrides{}, rules).ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("kubeconfig context %q: %w", contextName, err)
	}
	return cfg, contextName, nil
}
