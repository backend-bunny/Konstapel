package exception

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// NativeExceptionGVK is the only native exception version Konstapel emits.
var NativeExceptionGVK = schema.GroupVersionKind{Group: "policies.kyverno.io", Version: "v1", Kind: "PolicyException"}

// Labels, annotations and report properties on native exceptions.
const (
	ComponentNativeException = "native-exception"
	AnnotationSnapshot       = "compliance.erenius.io/acceptance-snapshot"
	// Report properties carry the acceptance identity into engine reports, so
	// evidence can resolve a skip to its acceptance (task 5.2).
	PropertySnapshot       = "compliance.erenius.io/acceptance-snapshot"
	PropertySnapshotDigest = "compliance.erenius.io/snapshot-digest"
)

// NativeName is the deterministic native exception name for one acceptance
// revision. A new revision always gets a new name.
func NativeName(exceptionUID types.UID, revision int64) string {
	sum := sha256.Sum256([]byte(string(exceptionUID) + "\x00" + strconv.FormatInt(revision, 10)))
	return "konstapel-acceptance-" + hex.EncodeToString(sum[:])[:16]
}

// RenderNative renders the managed native exception for an acceptance
// snapshot (design §4). It references exactly the engine policies rendered
// for the accepted contribution revisions, skips (never passes) their
// evaluation, ends no later than the acceptance, and matches only objects in
// the accepted namespace instance whose labels satisfy the accepted
// selector. snapshotRef ("<namespace>/<name>") and digest identify the
// persisted snapshot; exceptionNamespace is the engine's exception namespace.
func RenderNative(s *Snapshot, snapshotRef, digest, exceptionNamespace string) (*unstructured.Unstructured, error) {
	switch {
	case s.Namespace.Name == "" || s.Namespace.UID == "":
		return nil, fmt.Errorf("snapshot has no namespace identity; an exception cannot be granted without one")
	case len(s.Eligibility.Contributors) == 0:
		return nil, fmt.Errorf("snapshot accepts no contribution revisions")
	case s.ExpiresAt.IsZero():
		return nil, fmt.Errorf("snapshot has no expiry")
	case exceptionNamespace == "":
		return nil, fmt.Errorf("no exception namespace configured")
	}
	conditions, err := matchConditions(s.Namespace, s.WorkloadSelector)
	if err != nil {
		return nil, err
	}
	var refs []any
	seen := map[string]bool{}
	for _, c := range s.Eligibility.Contributors {
		name := targeting.PolicyName(targeting.Contribution{Binding: c.Binding, Policy: s.Policy, Revision: c.Revision})
		if !seen[name] {
			seen[name] = true
			refs = append(refs, map[string]any{"name": name, "kind": "ValidatingPolicy"})
		}
	}
	slices.SortFunc(refs, func(a, b any) int { return strings.Compare(a.(map[string]any)["name"].(string), b.(map[string]any)["name"].(string)) })

	obj := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{
			"policyRefs":      refs,
			"matchConditions": conditions,
			"reportResult":    "skip",
			"expiresAt":       s.ExpiresAt.UTC().Format(metav1.RFC3339Micro),
			"properties": map[string]any{
				PropertySnapshot:       snapshotRef,
				PropertySnapshotDigest: digest,
			},
		},
	}}
	obj.SetGroupVersionKind(NativeExceptionGVK)
	obj.SetName(NativeName(s.Exception.UID, s.AcceptanceRevision))
	obj.SetNamespace(exceptionNamespace)
	obj.SetLabels(map[string]string{
		targeting.LabelManagedBy:  targeting.ManagedByValue,
		LabelComponent:            ComponentNativeException,
		LabelExceptionUID:         string(s.Exception.UID),
		LabelNamespaceUID:         string(s.Namespace.UID),
		LabelAcceptanceRevision:   strconv.FormatInt(s.AcceptanceRevision, 10),
		targeting.LabelPolicyHash: targeting.PolicyHash(s.Policy),
	})
	obj.SetAnnotations(map[string]string{
		AnnotationSnapshot:       snapshotRef,
		AnnotationSnapshotDigest: digest,
	})
	return obj, nil
}

// matchConditions renders the CEL conditions (all must hold) that confine a
// grant to one namespace instance and the accepted workload selector.
// namespaceObject is null when the engine cannot supply the namespace, and
// then nothing matches.
func matchConditions(ns targeting.NamespaceRef, sel metav1.LabelSelector) ([]any, error) {
	out := []any{
		map[string]any{"name": "konstapel-namespace", "expression": fmt.Sprintf(
			"namespaceObject != null && namespaceObject.metadata.name == %s && namespaceObject.metadata.uid == %s",
			celString(ns.Name), celString(string(ns.UID)))},
	}
	const labels = "object.metadata.?labels.orValue({})"
	var reqs []string
	keys := make([]string, 0, len(sel.MatchLabels))
	for k := range sel.MatchLabels {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if err := checkLabel(k, []string{sel.MatchLabels[k]}); err != nil {
			return nil, err
		}
		reqs = append(reqs, fmt.Sprintf("%s in %s && %s[%s] == %s", celString(k), labels, labels, celString(k), celString(sel.MatchLabels[k])))
	}
	for _, r := range sel.MatchExpressions {
		if err := checkLabel(r.Key, r.Values); err != nil {
			return nil, err
		}
		k := celString(r.Key)
		switch r.Operator {
		case metav1.LabelSelectorOpIn, metav1.LabelSelectorOpNotIn:
			if len(r.Values) == 0 {
				return nil, fmt.Errorf("selector operator %s on %q needs values", r.Operator, r.Key)
			}
			vals := slices.Clone(r.Values)
			slices.Sort(vals)
			quoted := make([]string, len(vals))
			for i, v := range vals {
				quoted[i] = celString(v)
			}
			set := "[" + strings.Join(quoted, ", ") + "]"
			if r.Operator == metav1.LabelSelectorOpIn {
				reqs = append(reqs, fmt.Sprintf("%s in %s && %s[%s] in %s", k, labels, labels, k, set))
			} else {
				// Kubernetes semantics: NotIn also matches objects without the key.
				reqs = append(reqs, fmt.Sprintf("!(%s in %s) || !(%s[%s] in %s)", k, labels, labels, k, set))
			}
		case metav1.LabelSelectorOpExists, metav1.LabelSelectorOpDoesNotExist:
			if len(r.Values) > 0 {
				return nil, fmt.Errorf("selector operator %s on %q must not have values", r.Operator, r.Key)
			}
			if r.Operator == metav1.LabelSelectorOpExists {
				reqs = append(reqs, fmt.Sprintf("%s in %s", k, labels))
			} else {
				reqs = append(reqs, fmt.Sprintf("!(%s in %s)", k, labels))
			}
		default:
			return nil, fmt.Errorf("unsupported selector operator %q", r.Operator)
		}
	}
	for i, r := range reqs {
		out = append(out, map[string]any{"name": fmt.Sprintf("konstapel-selector-%d", i), "expression": r})
	}
	return out, nil
}

// checkLabel rejects keys and values that are not valid Kubernetes labels.
// The API server validates selectors already; this keeps the renderer safe
// on its own.
func checkLabel(key string, values []string) error {
	if errs := validation.IsQualifiedName(key); len(errs) > 0 {
		return fmt.Errorf("selector key %q: %s", key, strings.Join(errs, "; "))
	}
	for _, v := range values {
		if errs := validation.IsValidLabelValue(v); len(errs) > 0 {
			return fmt.Errorf("selector value %q: %s", v, strings.Join(errs, "; "))
		}
	}
	return nil
}

// celString renders s as a CEL string literal. Every byte outside printable
// ASCII and every quote or backslash is escaped, so no input can end the
// literal early.
func celString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range []byte(s) {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteByte(r)
		case r >= 0x20 && r < 0x7f:
			b.WriteByte(r)
		default:
			fmt.Fprintf(&b, "\\x%02x", r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
