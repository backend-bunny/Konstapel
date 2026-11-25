package controller

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// kyvernoWebhook is one Kyverno-named webhook configuration as
// TestLiveHelmLateKyverno sees it after its own Kyverno uninstall.
type kyvernoWebhook struct {
	obj     client.Object
	uid     types.UID
	created time.Time
	// managed: labelled webhook.kyverno.io/managed-by=kyverno, the label
	// Kyverno puts on every webhook configuration it writes.
	managed  bool
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
// its Kyverno uninstall, all broken: present before it with the same UID, or
// recreated by Kyverno during it. The uninstall stops the admission
// controller, which on shutdown deletes every configuration labelled
// webhook.kyverno.io/managed-by=kyverno, the cleanup controller's ttl and
// cleanup ones included; a cleanup controller still running then recreates
// them, with new UIDs and the same name and label, calling its Service that
// the uninstall removes next. So a configuration also counts when it has the
// name of one present before, both carry Kyverno's label and it was created
// no earlier. Anything else (not there before, unlabelled, or still reaching
// a Service) is kept. Nothing is removed while a Kyverno pod (writers) is
// left, since it could still recreate what is deleted.
func leftoversToRemove(before, now map[string]kyvernoWebhook, writers []string) []string {
	if len(writers) > 0 {
		return nil
	}
	var out []string
	for key, w := range now {
		was, ok := before[key]
		if !ok || !w.broken {
			continue
		}
		if was.uid == w.uid || (was.managed && w.managed && !w.created.Before(was.created)) {
			out = append(out, key)
		}
	}
	slices.Sort(out)
	return out
}

// The late-Kyverno test removes exactly the leftovers its own Kyverno
// uninstall left behind: Kyverno-named configurations, present before the
// uninstall or recreated by Kyverno during it, whose every webhook calls a
// removed Service, once no Kyverno pod is left to recreate them. Others are kept, and a failed Service
// lookup decides nothing.
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

	installed := time.Date(2026, 11, 25, 2, 46, 0, 0, time.UTC)
	uninstalled := installed.Add(17 * time.Minute)
	before := map[string]kyvernoWebhook{
		"ValidatingWebhookConfiguration/kyverno-cleanup":           {uid: "u1", broken: false, managed: true, created: installed},
		"ValidatingWebhookConfiguration/kyverno-ttl":               {uid: "u2", managed: true, created: installed},
		"ValidatingWebhookConfiguration/kyverno-live":              {uid: "u3", managed: true, created: installed},
		"ValidatingWebhookConfiguration/kyverno-cleanup-recreated": {uid: "u6", managed: true, created: installed},
		"MutatingWebhookConfiguration/kyverno-recreated":           {uid: "u4", created: installed},
		"MutatingWebhookConfiguration/kyverno-relabelled":          {uid: "u7", managed: true, created: installed},
		"MutatingWebhookConfiguration/kyverno-older":               {uid: "u8", managed: true, created: uninstalled},
	}
	now := map[string]kyvernoWebhook{
		"ValidatingWebhookConfiguration/kyverno-cleanup": {uid: "u1", broken: true, managed: true, created: installed},
		"ValidatingWebhookConfiguration/kyverno-ttl":     {uid: "u2", broken: true, managed: true, created: installed},
		"ValidatingWebhookConfiguration/kyverno-live":    {uid: "u3", broken: false, managed: true, created: installed},
		// Deleted by the stopping admission controller and recreated by the
		// cleanup controller while it still ran.
		"ValidatingWebhookConfiguration/kyverno-cleanup-recreated": {uid: "u10", broken: true, managed: true, created: uninstalled},
		// Another UID is kept unless both carry Kyverno's label and it is
		// no older; one not there before is never the test's.
		"MutatingWebhookConfiguration/kyverno-recreated":  {uid: "u9", broken: true, created: uninstalled},
		"MutatingWebhookConfiguration/kyverno-relabelled": {uid: "u11", broken: true, created: uninstalled},
		"MutatingWebhookConfiguration/kyverno-older":      {uid: "u12", broken: true, managed: true, created: installed},
		"MutatingWebhookConfiguration/kyverno-new-broken": {uid: "u5", broken: true, managed: true, created: uninstalled},
	}
	if got := leftoversToRemove(before, now, []string{"kyverno/kyverno-cleanup-controller-588fc84c5d-wf2zj"}); got != nil {
		t.Fatalf("leftovers removed while a Kyverno pod still runs: %v", got)
	}
	want := []string{"ValidatingWebhookConfiguration/kyverno-cleanup", "ValidatingWebhookConfiguration/kyverno-cleanup-recreated", "ValidatingWebhookConfiguration/kyverno-ttl"}
	if got := leftoversToRemove(before, now, nil); !slices.Equal(got, want) {
		t.Fatalf("leftovers to remove %v, want %v", got, want)
	}
}
