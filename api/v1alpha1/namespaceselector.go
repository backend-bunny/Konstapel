package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// NamespaceSelector is a metav1.LabelSelector with the same JSON shape and
// semantics, plus bounds. The bounds let the API server validate operators,
// label keys and label values with CEL at admission. Without them, CRD
// creation is refused because the estimated rule cost is unbounded.
// Use LabelSelector or AsSelector for matching.
// +structType=atomic
type NamespaceSelector struct {
	// matchLabels requires each {key,value} pair; requirements are ANDed.
	// +optional
	// +kubebuilder:validation:MaxProperties=64
	// +kubebuilder:validation:XValidation:rule="self.all(k, !format.qualifiedName().validate(k).hasValue())",message="keys must be valid label keys (qualified names)"
	// +kubebuilder:validation:XValidation:rule="self.all(k, !format.labelValue().validate(self[k]).hasValue())",message="values must be valid label values"
	MatchLabels map[string]LabelValue `json:"matchLabels,omitempty"`

	// matchExpressions is a list of label selector requirements; requirements are ANDed.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=32
	MatchExpressions []NamespaceSelectorRequirement `json:"matchExpressions,omitempty"`
}

// LabelValue is a Kubernetes label value.
// +kubebuilder:validation:MaxLength=63
type LabelValue string

// NamespaceSelectorRequirement is a bounded metav1.LabelSelectorRequirement.
// +kubebuilder:validation:XValidation:rule="self.operator in ['In', 'NotIn'] ? (has(self.values) && size(self.values) > 0) : (!has(self.values) || size(self.values) == 0)",message="In and NotIn require values; Exists and DoesNotExist must not set values"
type NamespaceSelectorRequirement struct {
	// key is the label key the selector applies to.
	// +required
	// +kubebuilder:validation:MaxLength=317
	// +kubebuilder:validation:XValidation:rule="!format.qualifiedName().validate(self).hasValue()",message="must be a valid label key (qualified name)"
	Key string `json:"key"`

	// operator is In, NotIn, Exists, or DoesNotExist.
	// +required
	// +kubebuilder:validation:Enum=In;NotIn;Exists;DoesNotExist
	Operator metav1.LabelSelectorOperator `json:"operator"`

	// values for In and NotIn; must be empty for Exists and DoesNotExist.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:XValidation:rule="self.all(v, !format.labelValue().validate(v).hasValue())",message="values must be valid label values"
	Values []string `json:"values,omitempty"`
}

// LabelSelector returns the equivalent metav1.LabelSelector.
func (s *NamespaceSelector) LabelSelector() *metav1.LabelSelector {
	if s == nil {
		return nil
	}
	out := &metav1.LabelSelector{}
	if s.MatchLabels != nil {
		out.MatchLabels = make(map[string]string, len(s.MatchLabels))
		for k, v := range s.MatchLabels {
			out.MatchLabels[k] = string(v)
		}
	}
	for _, r := range s.MatchExpressions {
		out.MatchExpressions = append(out.MatchExpressions, metav1.LabelSelectorRequirement{
			Key: r.Key, Operator: r.Operator, Values: append([]string(nil), r.Values...),
		})
	}
	return out
}

// AsSelector converts with the standard Kubernetes selector validation. A nil
// selector is an error, never "match everything"; an empty selector matches all.
func (s *NamespaceSelector) AsSelector() (labels.Selector, error) {
	if s == nil {
		return nil, errNilSelector
	}
	return metav1.LabelSelectorAsSelector(s.LabelSelector())
}

type selectorError string

func (e selectorError) Error() string { return string(e) }

const errNilSelector = selectorError("namespaceSelector is required; use {} to select every namespace")
