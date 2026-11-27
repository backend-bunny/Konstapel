package targeting

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AnnotationReadinessRecheck records Konstapel's last readiness recheck of
// an owned engine policy as "<attempt>@<RFC3339 UTC time>". Writing it is a
// metadata-only update: the spec, the generation, the revision and every
// other label and annotation stay as they are.
//
// Kyverno 1.19 computes RBACPermissionsGranted when a policy is created or
// updated, but not when RBAC changes later, so a policy that reported a
// missing grant stays not ready after an administrator supplies it. Any
// update to the policy object makes Kyverno compute the condition again;
// this annotation is that update.
const AnnotationReadinessRecheck = annotationPrefix + "readiness-recheck"

// RecheckCondition is the readiness condition whose failure is rechecked.
const RecheckCondition = "RBACPermissionsGranted"

// RecheckBackoff bounds readiness rechecks of one policy. The first recheck
// is due Initial after the policy was created. Each later one waits twice as
// long as the one before it, but never longer than Max. A policy whose last
// recheck is more than twice Max ago (it was ready in between, or Konstapel
// was not running) starts again at Initial.
type RecheckBackoff struct {
	Initial time.Duration
	Max     time.Duration
}

// DefaultRecheckBackoff rechecks a policy 30 seconds after it was created,
// then after 1, 2, 4 and 8 minutes, then every 15 minutes while its
// permission failure lasts.
var DefaultRecheckBackoff = RecheckBackoff{Initial: 30 * time.Second, Max: 15 * time.Minute}

// maxRecheckAttempt bounds the recorded attempt counter.
const maxRecheckAttempt = 1 << 20

// recheckConflictRetries bounds how often one Recheck call re-reads a
// policy after an update conflict.
const recheckConflictRetries = 3

// delay is the wait after a policy's attempts-th recheck.
func (b RecheckBackoff) delay(attempts int) time.Duration {
	d := b.Initial
	for i := 0; i < attempts && d < b.Max; i++ {
		d *= 2
	}
	return min(d, b.Max)
}

func (b RecheckBackoff) valid() bool { return b.Initial > 0 && b.Max >= b.Initial }

// due reports whether a recheck of o is due at now, and the attempt number
// it records. An annotation that is missing, unreadable or in the future
// counts from the policy's creation.
func (b RecheckBackoff) due(o *unstructured.Unstructured, now time.Time) (int, bool) {
	attempts, last := 0, o.GetCreationTimestamp().Time
	if n, at, ok := parseRecheck(o.GetAnnotations()[AnnotationReadinessRecheck]); ok && !at.After(now) {
		attempts, last = n, at
		if now.Sub(at) > 2*b.Max {
			attempts = 0
		}
	}
	return min(attempts+1, maxRecheckAttempt), !now.Before(last.Add(b.delay(attempts)))
}

func formatRecheck(attempt int, at time.Time) string {
	return strconv.Itoa(attempt) + "@" + at.UTC().Format(time.RFC3339)
}

func parseRecheck(v string) (int, time.Time, bool) {
	count, stamp, ok := strings.Cut(v, "@")
	if !ok {
		return 0, time.Time{}, false
	}
	n, err := strconv.Atoi(count)
	if err != nil || n < 1 || n > maxRecheckAttempt {
		return 0, time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		return 0, time.Time{}, false
	}
	return n, at, true
}

// permissionPending reports whether a readiness detail is the failure a
// recheck addresses: Kyverno reported RBACPermissionsGranted False or
// Unknown. A missing or unreadable condition is not: Kyverno has not
// evaluated the policy, or its status cannot be read.
func permissionPending(d ReadinessDetail) bool {
	return d.Condition == RecheckCondition && (d.State == ReadinessFalse || d.State == ReadinessUnknown)
}

// RecheckCandidates lists the current policies of a Sync whose readiness
// details report a permission failure, sorted. Only these are rechecked.
func RecheckCandidates(res DeliveryResult) []string {
	var out []string
	for _, d := range res.Readiness {
		if permissionPending(d) && slices.Contains(res.Current, d.Policy) && !slices.Contains(out, d.Policy) {
			out = append(out, d.Policy)
		}
	}
	slices.Sort(out)
	return out
}

// RecheckAttempt is one readiness recheck written by Recheck.
type RecheckAttempt struct {
	Policy  string
	Attempt int
}

// RecheckResult is the outcome of one Recheck call.
type RecheckResult struct {
	// Rechecked lists the policies whose recheck annotation was written.
	Rechecked []RecheckAttempt
	// Conflicted lists policies that kept changing while being rechecked.
	// Nothing was written to them; a later call retries if still due.
	Conflicted []string
}

// Recheck asks the engine to evaluate the readiness of the binding's current
// policies again when the Sync that produced res found a permission failure
// (RecheckCandidates), by writing AnnotationReadinessRecheck once the
// backoff allows it. Each candidate is read again from the API server and
// written only while it is still owned by the binding at the desired
// revision, not being deleted, not ready, and still reports the failure.
// The write is a merge patch of that one annotation, conditional on the
// resourceVersion read, so it never replaces a newer object. After a
// conflict the policy is read and judged again, a bounded number of times.
// Ready policies, superseded revisions, held policies and anything not
// owned are never written. With Current set, it is confirmed before the
// first write; ErrStaleSnapshot then means nothing was written.
func (d *Delivery) Recheck(ctx context.Context, bindingUID types.UID, desired []*unstructured.Unstructured, res DeliveryResult, now time.Time, backoff RecheckBackoff) (RecheckResult, error) {
	var out RecheckResult
	if !backoff.valid() {
		return out, fmt.Errorf("invalid readiness recheck backoff %+v", backoff)
	}
	ready := d.Ready
	if ready == nil {
		ready = KyvernoReady
	}
	revisions := map[string]string{}
	for _, w := range desired {
		revisions[w.GetName()] = w.GetAnnotations()[AnnotationRevision]
	}
	confirmed := false
	for _, name := range RecheckCandidates(res) {
		revision, ok := revisions[name]
		if !ok || revision == "" {
			continue
		}
		conflicted := true
		for range recheckConflictRetries {
			cur := &unstructured.Unstructured{}
			cur.SetGroupVersionKind(ValidatingPolicyGVK)
			err := d.Client.Get(ctx, client.ObjectKey{Name: name}, cur)
			if apierrors.IsNotFound(err) {
				conflicted = false
				break
			}
			if err != nil {
				return out, err
			}
			attempt, due := backoff.due(cur, now)
			if !ownedBy(cur, bindingUID) || cur.GetAnnotations()[AnnotationRevision] != revision || cur.GetDeletionTimestamp() != nil ||
				ready(cur) || !slices.ContainsFunc(KyvernoReadiness(cur), permissionPending) || !due {
				conflicted = false
				break
			}
			if !confirmed {
				if err := d.current(ctx); err != nil {
					return out, err
				}
				confirmed = true
			}
			patched := cur.DeepCopy()
			annotations := patched.GetAnnotations()
			annotations[AnnotationReadinessRecheck] = formatRecheck(attempt, now)
			patched.SetAnnotations(annotations)
			err = d.Client.Patch(ctx, patched, client.MergeFromWithOptions(cur, client.MergeFromWithOptimisticLock{}), FieldOwner)
			if apierrors.IsConflict(err) {
				continue
			}
			conflicted = false
			if apierrors.IsNotFound(err) {
				break
			}
			if err != nil {
				return out, err
			}
			out.Rechecked = append(out.Rechecked, RecheckAttempt{Policy: name, Attempt: attempt})
			break
		}
		if conflicted {
			out.Conflicted = append(out.Conflicted, name)
		}
	}
	return out, nil
}
