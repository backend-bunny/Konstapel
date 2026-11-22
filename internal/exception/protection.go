package exception

import (
	"context"
	"errors"
	"fmt"
	"slices"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// The exception admission webhooks, as config/webhook/exceptions.yaml
// registers them. Revocation processing (task 3.6) depends on them: the
// validating webhook is what confines the controller identity's
// ComplianceException writes to releasing RevocationFinalizer.
const (
	// WebhookConfigurationName names both the mutating and the validating
	// webhook configuration.
	WebhookConfigurationName = "konstapel-exception-acceptance"
	// MutatingWebhookName records acceptances and revocations.
	MutatingWebhookName = "record.acceptance.compliance.erenius.io"
	// ValidatingWebhookName verifies them and restricts the controller.
	ValidatingWebhookName = "verify.acceptance.compliance.erenius.io"
)

// ErrUnprotected reports that the exception admission webhooks are not
// registered so that they fail closed for every ComplianceException write.
var ErrUnprotected = errors.New("the exception admission webhooks are not registered to fail closed")

// hook is what VerifyProtection checks of one registered webhook.
type hook struct {
	name       string
	policy     *admissionregistrationv1.FailurePolicyType
	rules      []admissionregistrationv1.RuleWithOperations
	selectors  []*metav1.LabelSelector
	conditions int
}

// VerifyProtection checks that both exception admission webhooks are
// registered so that no ComplianceException create or update can bypass
// them: each configuration exists and is not being deleted, and its webhook
// uses failurePolicy Fail, intercepts CREATE and UPDATE of v1alpha1
// complianceexceptions, and has no namespace or object selector and no
// match conditions that could exempt a request. It reads both
// configurations by name. A violation wraps ErrUnprotected; a read failure
// is returned as is. Either way the caller must not process revocations.
//
// It cannot tell whether the configured endpoint serves this controller's
// handlers; an endpoint that does not answer denies every write, because the
// failure policy is Fail.
func VerifyProtection(ctx context.Context, reader client.Reader) error {
	key := client.ObjectKey{Name: WebhookConfigurationName}
	mut := &admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := reader.Get(ctx, key, mut); err != nil {
		return fmt.Errorf("read MutatingWebhookConfiguration %s: %w", WebhookConfigurationName, err)
	}
	val := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	if err := reader.Get(ctx, key, val); err != nil {
		return fmt.Errorf("read ValidatingWebhookConfiguration %s: %w", WebhookConfigurationName, err)
	}
	var mh, vh []hook
	for _, w := range mut.Webhooks {
		mh = append(mh, hook{w.Name, w.FailurePolicy, w.Rules, []*metav1.LabelSelector{w.NamespaceSelector, w.ObjectSelector}, len(w.MatchConditions)})
	}
	for _, w := range val.Webhooks {
		vh = append(vh, hook{w.Name, w.FailurePolicy, w.Rules, []*metav1.LabelSelector{w.NamespaceSelector, w.ObjectSelector}, len(w.MatchConditions)})
	}
	if err := protects("MutatingWebhookConfiguration", mut.DeletionTimestamp, MutatingWebhookName, mh); err != nil {
		return err
	}
	return protects("ValidatingWebhookConfiguration", val.DeletionTimestamp, ValidatingWebhookName, vh)
}

// protects checks the named webhook of one configuration.
func protects(kind string, deleting *metav1.Time, name string, hooks []hook) error {
	unprotected := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s %s: %s", ErrUnprotected, kind, WebhookConfigurationName, fmt.Sprintf(format, args...))
	}
	if deleting != nil {
		return unprotected("it is being deleted")
	}
	i := slices.IndexFunc(hooks, func(h hook) bool { return h.name == name })
	if i < 0 {
		return unprotected("webhook %s is not registered", name)
	}
	h := hooks[i]
	switch {
	case h.policy == nil || *h.policy != admissionregistrationv1.Fail:
		return unprotected("webhook %s must use failurePolicy Fail", name)
	case slices.ContainsFunc(h.selectors, func(s *metav1.LabelSelector) bool {
		return s != nil && (len(s.MatchLabels) > 0 || len(s.MatchExpressions) > 0)
	}):
		return unprotected("webhook %s must not have a namespaceSelector or objectSelector", name)
	case h.conditions > 0:
		return unprotected("webhook %s must not have matchConditions", name)
	case !intercepts(h.rules, admissionregistrationv1.Create) || !intercepts(h.rules, admissionregistrationv1.Update):
		return unprotected("webhook %s must intercept CREATE and UPDATE of %s/%s complianceexceptions", name, v1alpha1.GroupVersion.Group, v1alpha1.GroupVersion.Version)
	}
	return nil
}

// intercepts reports whether a rule covers op on namespaced v1alpha1
// complianceexceptions.
func intercepts(rules []admissionregistrationv1.RuleWithOperations, op admissionregistrationv1.OperationType) bool {
	has := func(values []string, want string) bool {
		return slices.Contains(values, want) || slices.Contains(values, "*")
	}
	return slices.ContainsFunc(rules, func(r admissionregistrationv1.RuleWithOperations) bool {
		scope := r.Scope == nil || *r.Scope == admissionregistrationv1.AllScopes || *r.Scope == admissionregistrationv1.NamespacedScope
		ops := slices.Contains(r.Operations, op) || slices.Contains(r.Operations, admissionregistrationv1.OperationAll)
		return scope && ops && has(r.APIGroups, v1alpha1.GroupVersion.Group) && has(r.APIVersions, v1alpha1.GroupVersion.Version) &&
			has(r.Resources, "complianceexceptions")
	})
}
