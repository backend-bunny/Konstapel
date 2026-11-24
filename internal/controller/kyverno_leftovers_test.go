package controller

import (
	"errors"
	"slices"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// kyvernoWebhook is one Kyverno-named webhook configuration as
// TestLiveHelmLateKyverno sees it after its own Kyverno uninstall.
type kyvernoWebhook struct {
	obj      client.Object
	uid      types.UID
	services []string
	// broken: every webhook in it calls a Service that does not exist.
	broken bool
}

// classifyKyvernoWebhook reports whether a webhook configuration is
// Kyverno's (kyverno- name) and, if so, the Services its webhooks call and
// whether every one of them is missing. A configuration with no webhook, or
// one calling a URL, is never broken; a Service lookup that fails other than
// NotFound is returned, so nothing is decided on it.
func classifyKyvernoWebhook(name string, configs []admissionregistrationv1.WebhookClientConfig, exists func(namespace, name string) (bool, error)) (kyverno bool, services []string, broken bool, err error) {
	if !strings.HasPrefix(name, "kyverno-") {
		return false, nil, false, nil
	}
	broken = len(configs) > 0
	for _, cc := range configs {
		if cc.Service == nil {
			broken = false
			continue
		}
		services = append(services, cc.Service.Namespace+"/"+cc.Service.Name)
		found, err := exists(cc.Service.Namespace, cc.Service.Name)
		if err != nil {
			return true, services, false, err
		}
		if found {
			broken = false
		}
	}
	return true, services, broken, nil
}

// leftoversToRemove returns the configurations the test owns as leftovers of
// its Kyverno uninstall: present before it with the same UID, and broken.
// A configuration created since (another UID) or still reaching a Service
// is kept.
func leftoversToRemove(before, now map[string]kyvernoWebhook) []string {
	var out []string
	for key, w := range now {
		if was, ok := before[key]; ok && was.uid == w.uid && w.broken {
			out = append(out, key)
		}
	}
	slices.Sort(out)
	return out
}

// The late-Kyverno test removes exactly the leftovers its own Kyverno
// uninstall left behind: Kyverno-named configurations, present before the
// uninstall, whose every webhook calls a removed Service. Others are kept,
// and a failed Service lookup decides nothing.
func TestKyvernoLeftoverSelection(t *testing.T) {
	svc := func(ns, name string) admissionregistrationv1.WebhookClientConfig {
		return admissionregistrationv1.WebhookClientConfig{Service: &admissionregistrationv1.ServiceReference{Namespace: ns, Name: name}}
	}
	url := "https://example.invalid/validate"
	present := map[string]bool{"kyverno/kyverno-svc-metrics": true, "other/webhook": true}
	exists := func(ns, name string) (bool, error) {
		if ns == "unreachable" {
			return false, errors.New("the API server timed out")
		}
		return present[ns+"/"+name], nil
	}
	for name, c := range map[string]struct {
		config  string
		configs []admissionregistrationv1.WebhookClientConfig
		kyverno bool
		broken  bool
		err     bool
	}{
		"cleanup leftover":     {"kyverno-cleanup-validating-webhook-configuration", []admissionregistrationv1.WebhookClientConfig{svc("kyverno", "kyverno-cleanup-controller")}, true, true, false},
		"ttl leftover":         {"kyverno-ttl-validating-webhook-configuration", []admissionregistrationv1.WebhookClientConfig{svc("kyverno", "kyverno-cleanup-controller"), svc("kyverno", "kyverno-cleanup-controller")}, true, true, false},
		"one Service present":  {"kyverno-mixed", []admissionregistrationv1.WebhookClientConfig{svc("kyverno", "gone"), svc("kyverno", "kyverno-svc-metrics")}, true, false, false},
		"URL webhook":          {"kyverno-url", []admissionregistrationv1.WebhookClientConfig{svc("kyverno", "gone"), {URL: &url}}, true, false, false},
		"no webhooks":          {"kyverno-empty", nil, true, false, false},
		"not Kyverno's":        {"konstapel-exception-acceptance", []admissionregistrationv1.WebhookClientConfig{svc("konstapel-system", "gone")}, false, false, false},
		"lookup fails":         {"kyverno-unknown", []admissionregistrationv1.WebhookClientConfig{svc("unreachable", "x")}, true, false, true},
		"other team's present": {"kyverno-like", []admissionregistrationv1.WebhookClientConfig{svc("other", "webhook")}, true, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			kyverno, _, broken, err := classifyKyvernoWebhook(c.config, c.configs, exists)
			if kyverno != c.kyverno || broken != c.broken || (err != nil) != c.err {
				t.Fatalf("kyverno=%v broken=%v err=%v, want %v %v err=%v", kyverno, broken, err, c.kyverno, c.broken, c.err)
			}
		})
	}

	before := map[string]kyvernoWebhook{
		"ValidatingWebhookConfiguration/kyverno-cleanup": {uid: "u1", broken: false},
		"ValidatingWebhookConfiguration/kyverno-ttl":     {uid: "u2"},
		"ValidatingWebhookConfiguration/kyverno-live":    {uid: "u3"},
		"MutatingWebhookConfiguration/kyverno-recreated": {uid: "u4"},
	}
	now := map[string]kyvernoWebhook{
		"ValidatingWebhookConfiguration/kyverno-cleanup":  {uid: "u1", broken: true},
		"ValidatingWebhookConfiguration/kyverno-ttl":      {uid: "u2", broken: true},
		"ValidatingWebhookConfiguration/kyverno-live":     {uid: "u3", broken: false},
		"MutatingWebhookConfiguration/kyverno-recreated":  {uid: "u9", broken: true},
		"MutatingWebhookConfiguration/kyverno-new-broken": {uid: "u5", broken: true},
	}
	want := []string{"ValidatingWebhookConfiguration/kyverno-cleanup", "ValidatingWebhookConfiguration/kyverno-ttl"}
	if got := leftoversToRemove(before, now); !slices.Equal(got, want) {
		t.Fatalf("leftovers to remove %v, want %v", got, want)
	}
}
