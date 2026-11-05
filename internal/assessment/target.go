package assessment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Target is the sole cluster client passed to delivery and collection. Every
// invocation uses both explicit kubeconfig and context; ambient context is ignored.
type Target struct {
	Kubeconfig, Context, Cluster string
	Timeout                      time.Duration
}

func NewTarget(kubeconfig, contextName string, timeout time.Duration) (*Target, error) {
	if kubeconfig == "" || contextName == "" || timeout <= 0 {
		return nil, fmt.Errorf("explicit kubeconfig/context and positive timeout required")
	}
	t := &Target{Kubeconfig: kubeconfig, Context: contextName, Timeout: timeout}
	var ns Object
	if err := t.JSON(context.Background(), &ns, "get", "namespace", "kube-system", "-o", "json"); err != nil {
		return nil, err
	}
	uid := Str(At(ns, "metadata", "uid"))
	if uid == "" {
		return nil, fmt.Errorf("target kube-system UID missing")
	}
	t.Cluster = "kube-system:" + uid
	return t, nil
}
func (t *Target) Run(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	base := []string{"--kubeconfig", t.Kubeconfig, "--context", t.Context, "--request-timeout=30s"}
	cmd := exec.CommandContext(ctx, "kubectl", append(base, args...)...)
	cmd.Stdin = bytes.NewReader(input)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return b, fmt.Errorf("kubectl %v: %w: %s", args, err, b)
	}
	return b, nil
}
func (t *Target) JSON(ctx context.Context, v any, args ...string) error {
	b, e := t.Run(ctx, nil, args...)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func (t *Target) Apply(ctx context.Context, obj Object) (Object, error) {
	b, e := json.Marshal(obj)
	if e != nil {
		return nil, e
	}
	out, e := t.Run(ctx, b, "apply", "-f", "-", "-o", "json")
	if e != nil {
		return nil, e
	}
	var res Object
	e = json.Unmarshal(out, &res)
	return res, e
}
func (t *Target) Prerequisites(ctx context.Context) error {
	for _, path := range []string{"/apis/policies.kyverno.io/v1", "/apis/wgpolicyk8s.io/v1alpha2"} {
		var d Object
		if e := t.JSON(ctx, &d, "get", "--raw", path); e != nil {
			return fmt.Errorf("required API %s unavailable: %w", path, e)
		}
		required := []string{"validatingpolicies"}
		if path == "/apis/wgpolicyk8s.io/v1alpha2" {
			required = []string{"policyreports", "clusterpolicyreports"}
		}
		items, _ := d["resources"].([]any)
		for _, name := range required {
			found := false
			for _, r := range items {
				if Map(r)["name"] == name {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("required resource %s unavailable", name)
			}
		}
	}
	return nil
}
func (t *Target) Deliver(ctx context.Context, p Object, owner string) (Object, error) {
	if err := t.Prerequisites(ctx); err != nil {
		return nil, err
	}
	var existing Object
	if err := t.JSON(ctx, &existing, "get", "validatingpolicies.policies.kyverno.io", PolicyName, "--ignore-not-found", "-o", "json"); err != nil && !errors.Is(err, os.ErrNotExist) {
		// --ignore-not-found returns empty JSON; only that decoding error means absent.
		var syntax *json.SyntaxError
		if !errors.As(err, &syntax) && err.Error() != "unexpected end of JSON input" {
			return nil, err
		}
	}
	if len(existing) > 0 && Str(At(existing, "metadata", "labels", OwnerLabel)) != owner {
		return nil, fmt.Errorf("conflicting policy is not owned by %s", owner)
	}
	applied, err := t.Apply(ctx, p)
	if err != nil {
		return nil, err
	}
	desiredDigest := Digest(applied["spec"])
	deadline := time.Now().Add(t.Timeout)
	for time.Now().Before(deadline) {
		var current Object
		if err := t.JSON(ctx, &current, "get", "validatingpolicies.policies.kyverno.io", PolicyName, "-o", "json"); err != nil {
			return nil, err
		}
		conditions, _ := At(current, "status", "conditionStatus", "conditions").([]any)
		ready := map[string]bool{}
		for _, c := range conditions {
			m := Map(c)
			if m["status"] == "True" {
				ready[Str(m["type"])] = true
			}
			if ready["RBACPermissionsGranted"] && ready["WebhookConfigured"] {
				if Digest(current["spec"]) != desiredDigest {
					return nil, fmt.Errorf("policy spec changed during readiness")
				}
				return current, nil
			}
		}
		if err := pause(ctx, time.Second); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("policy applied but readiness timed out")
}
func pause(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
