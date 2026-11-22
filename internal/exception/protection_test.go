package exception

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// shippedWebhooks decodes config/webhook/exceptions.yaml.
func shippedWebhooks(t *testing.T) (*admissionregistrationv1.MutatingWebhookConfiguration, *admissionregistrationv1.ValidatingWebhookConfiguration) {
	t.Helper()
	raw, err := os.ReadFile("../../config/webhook/exceptions.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dec := utilyaml.NewYAMLOrJSONDecoder(strings.NewReader(string(raw)), 4096)
	mut, val := &admissionregistrationv1.MutatingWebhookConfiguration{}, &admissionregistrationv1.ValidatingWebhookConfiguration{}
	if err := dec.Decode(mut); err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(val); err != nil {
		t.Fatal(err)
	}
	if mut.Name != WebhookConfigurationName || val.Name != WebhookConfigurationName {
		t.Fatalf("shipped webhook configurations are %q and %q, want %q", mut.Name, val.Name, WebhookConfigurationName)
	}
	return mut, val
}

// Revocation processing needs both exception webhooks registered so that
// they fail closed for every create and update of an exception; any
// configuration that could let a write through without them is refused,
// and so is one that cannot be read.
func TestVerifyProtection(t *testing.T) {
	type mod func(m *admissionregistrationv1.MutatingWebhookConfiguration, v *admissionregistrationv1.ValidatingWebhookConfiguration) []client.Object
	both := func(m *admissionregistrationv1.MutatingWebhookConfiguration, v *admissionregistrationv1.ValidatingWebhookConfiguration) []client.Object {
		return []client.Object{m, v}
	}
	edit := func(f func(m *admissionregistrationv1.MutatingWebhook, v *admissionregistrationv1.ValidatingWebhook)) mod {
		return func(m *admissionregistrationv1.MutatingWebhookConfiguration, v *admissionregistrationv1.ValidatingWebhookConfiguration) []client.Object {
			f(&m.Webhooks[0], &v.Webhooks[0])
			return both(m, v)
		}
	}
	ignore := admissionregistrationv1.Ignore
	cluster := admissionregistrationv1.ClusterScope
	for name, c := range map[string]struct {
		mod         mod
		unprotected bool // false: allowed, unless missing
		missing     bool
	}{
		"shipped": {mod: both},
		"wildcard rules": {mod: edit(func(m *admissionregistrationv1.MutatingWebhook, v *admissionregistrationv1.ValidatingWebhook) {
			v.Rules = []admissionregistrationv1.RuleWithOperations{{Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.OperationAll},
				Rule: admissionregistrationv1.Rule{APIGroups: []string{"*"}, APIVersions: []string{"*"}, Resources: []string{"*"}}}}
		})},
		"empty selectors": {mod: edit(func(m *admissionregistrationv1.MutatingWebhook, v *admissionregistrationv1.ValidatingWebhook) {
			v.NamespaceSelector, v.ObjectSelector = &metav1.LabelSelector{}, &metav1.LabelSelector{}
		})},
		"no validating configuration": {missing: true, mod: func(m *admissionregistrationv1.MutatingWebhookConfiguration, _ *admissionregistrationv1.ValidatingWebhookConfiguration) []client.Object {
			return []client.Object{m}
		}},
		"no mutating configuration": {missing: true, mod: func(_ *admissionregistrationv1.MutatingWebhookConfiguration, v *admissionregistrationv1.ValidatingWebhookConfiguration) []client.Object {
			return []client.Object{v}
		}},
		"validating fails open": {unprotected: true, mod: edit(func(_ *admissionregistrationv1.MutatingWebhook, v *admissionregistrationv1.ValidatingWebhook) {
			v.FailurePolicy = &ignore
		})},
		"mutating fails open": {unprotected: true, mod: edit(func(m *admissionregistrationv1.MutatingWebhook, _ *admissionregistrationv1.ValidatingWebhook) {
			m.FailurePolicy = &ignore
		})},
		"no failure policy": {unprotected: true, mod: edit(func(_ *admissionregistrationv1.MutatingWebhook, v *admissionregistrationv1.ValidatingWebhook) {
			v.FailurePolicy = nil
		})},
		"namespace selector": {unprotected: true, mod: edit(func(_ *admissionregistrationv1.MutatingWebhook, v *admissionregistrationv1.ValidatingWebhook) {
			v.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}
		})},
		"object selector": {unprotected: true, mod: edit(func(m *admissionregistrationv1.MutatingWebhook, _ *admissionregistrationv1.ValidatingWebhook) {
			m.ObjectSelector = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "skip", Operator: metav1.LabelSelectorOpDoesNotExist}}}
		})},
		"match conditions": {unprotected: true, mod: edit(func(_ *admissionregistrationv1.MutatingWebhook, v *admissionregistrationv1.ValidatingWebhook) {
			v.MatchConditions = []admissionregistrationv1.MatchCondition{{Name: "not-controller", Expression: "request.userInfo.username != 'x'"}}
		})},
		"no UPDATE": {unprotected: true, mod: edit(func(_ *admissionregistrationv1.MutatingWebhook, v *admissionregistrationv1.ValidatingWebhook) {
			v.Rules[0].Operations = []admissionregistrationv1.OperationType{admissionregistrationv1.Create}
		})},
		"other resource": {unprotected: true, mod: edit(func(_ *admissionregistrationv1.MutatingWebhook, v *admissionregistrationv1.ValidatingWebhook) {
			v.Rules[0].Resources = []string{"compliancebindings"}
		})},
		"other version": {unprotected: true, mod: edit(func(_ *admissionregistrationv1.MutatingWebhook, v *admissionregistrationv1.ValidatingWebhook) {
			v.Rules[0].APIVersions = []string{"v1beta1"}
		})},
		"cluster scope only": {unprotected: true, mod: edit(func(_ *admissionregistrationv1.MutatingWebhook, v *admissionregistrationv1.ValidatingWebhook) {
			v.Rules[0].Scope = &cluster
		})},
		"validating webhook renamed": {unprotected: true, mod: edit(func(_ *admissionregistrationv1.MutatingWebhook, v *admissionregistrationv1.ValidatingWebhook) {
			v.Name = "other.example.com"
		})},
		"validating configuration deleting": {unprotected: true, mod: func(m *admissionregistrationv1.MutatingWebhookConfiguration, v *admissionregistrationv1.ValidatingWebhookConfiguration) []client.Object {
			v.Finalizers = []string{"example.com/hold"}
			v.DeletionTimestamp = ptr.To(metav1.Now())
			return both(m, v)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			m, v := shippedWebhooks(t)
			reader := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(c.mod(m, v)...).Build()
			err := VerifyProtection(context.Background(), reader)
			switch {
			case c.missing && (err == nil || errors.Is(err, ErrUnprotected) || !strings.Contains(err.Error(), "not found")):
				t.Errorf("want a not-found read error, got %v", err)
			case c.unprotected && !errors.Is(err, ErrUnprotected):
				t.Errorf("want ErrUnprotected, got %v", err)
			case !c.missing && !c.unprotected && err != nil:
				t.Errorf("want verified, got %v", err)
			}
		})
	}
	if err := VerifyProtection(context.Background(), unreadable{}); err == nil {
		t.Error("an unreadable configuration verified")
	}
}
