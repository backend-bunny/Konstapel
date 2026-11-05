package assessment

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

func (t *Target) Deliver(ctx context.Context, p Object, owner string) (Object, error) {
	if err := t.Prerequisites(ctx); err != nil {
		return nil, err
	}
	existing, err := t.Get(ctx, policyGVK, "", PolicyName)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
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
		current, err := t.Get(ctx, policyGVK, "", PolicyName)
		if err != nil {
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
