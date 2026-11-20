package preview

import (
	"reflect"

	"k8s.io/apimachinery/pkg/runtime"
)

// StoredSpecChange says whether the API server would store a different
// specification than the live object has when a proposal is applied. It is
// separate from configuration equality (Fingerprint): two specifications with
// the same fingerprint can still be stored differently, for example with
// reordered selector expressions or a duration spelled 60m instead of 1h. The
// API server then advances metadata.generation, and for a binding whose
// enforcement fields are written differently the enforcement epoch, so the
// controller's EnforcementRevision rotates although the configuration is
// semantically the same.
type StoredSpecChange string

const (
	// StoredSpecNotProposed: no proposal restates this object.
	StoredSpecNotProposed StoredSpecChange = ""
	// StoredSpecEqual: the proposal is stored exactly as the live spec, after
	// the API server's null pruning and defaults. No generation change.
	StoredSpecEqual StoredSpecChange = "equal"
	// StoredSpecDifferent: the stored spec would differ; the generation
	// advances.
	StoredSpecDifferent StoredSpecChange = "different"
	// StoredSpecUnknown: the live stored spec was not observed, so equality
	// cannot be shown. Treated like StoredSpecDifferent.
	StoredSpecUnknown StoredSpecChange = "unknown"
)

// storedForm returns the spec as the API server stores it for comparison:
// nulls pruned outside preserved fields, CRD defaults applied, and the
// admission-maintained enforcementEpoch removed. List order, map contents and
// scalar spellings are kept exactly, because the API server compares stored
// objects with deep equality to decide whether the generation advances, and
// the epoch policy compares enforcement fields with CEL equality, which is
// order-sensitive for the atomic selector lists.
func storedForm(kind string, spec map[string]any) map[string]any {
	if spec == nil {
		return nil
	}
	s := runtime.DeepCopyJSON(spec)
	switch kind {
	case KindProfile:
		pruneNulls(s, "spec")
		pols, _ := s["policies"].([]any)
		for _, e := range pols {
			pol, ok := e.(map[string]any)
			if !ok {
				continue
			}
			ex, ok := pol["exceptions"].(map[string]any)
			if !ok {
				ex = map[string]any{}
				pol["exceptions"] = ex
			}
			if _, has := ex["eligibility"]; !has {
				ex["eligibility"] = "Forbidden"
			}
		}
	case KindBinding:
		pruneNulls(s, "spec")
		delete(s, "enforcementEpoch")
		a, ok := s["assessment"].(map[string]any)
		if !ok {
			a = map[string]any{}
			s["assessment"] = a
		}
		for k, v := range map[string]string{"interval": defaultInterval, "maxEvidenceAge": defaultMaxEvidenceAge,
			"collectionTimeout": defaultCollectionTimeout, "retention": defaultRetention} {
			if _, has := a[k]; !has {
				a[k] = v
			}
		}
	}
	return s
}

// pruneNulls removes null map values, except inside profile parameters,
// which preserve unknown fields as written.
func pruneNulls(v any, path string) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if e == nil {
				delete(x, k)
				continue
			}
			if k == "parameters" && path == "spec.policies[]" {
				continue
			}
			pruneNulls(e, path+"."+k)
		}
	case []any:
		for _, e := range x {
			pruneNulls(e, path+"[]")
		}
	}
}

// compareStored compares the stored forms of a live and a proposed spec.
func compareStored(kind string, live, proposed map[string]any) StoredSpecChange {
	if live == nil || proposed == nil {
		return StoredSpecUnknown
	}
	if reflect.DeepEqual(storedForm(kind, live), storedForm(kind, proposed)) {
		return StoredSpecEqual
	}
	return StoredSpecDifferent
}

// enforcementFieldsChanged mirrors the konstapel-binding-enforcement-epoch
// admission policy: the epoch advances when profileRef, namespaceSelector or
// mode differ under CEL equality (order-sensitive for the atomic
// matchExpressions and values lists). Unknown live input counts as changed.
func enforcementFieldsChanged(live, proposed map[string]any) bool {
	if live == nil || proposed == nil {
		return true
	}
	l, p := storedForm(KindBinding, live), storedForm(KindBinding, proposed)
	for _, k := range []string{"profileRef", "namespaceSelector", "mode"} {
		if !reflect.DeepEqual(l[k], p[k]) {
			return true
		}
	}
	return false
}
