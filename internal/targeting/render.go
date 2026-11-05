package targeting

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// ValidatingPolicyGVK is the engine resource Konstapel delivers.
var ValidatingPolicyGVK = schema.GroupVersionKind{Group: "policies.kyverno.io", Version: "v1", Kind: "ValidatingPolicy"}

// Labels and annotations on delivered engine policies. Labels support
// selection; annotations carry full provenance. There is deliberately no
// binding-generation annotation: reporting-only binding edits advance the
// generation, and must not write to engine policies. The revision identifies
// the enforcement configuration.
const (
	LabelManagedBy  = "app.kubernetes.io/managed-by"
	ManagedByValue  = "konstapel"
	LabelBindingUID = "compliance.erenius.io/binding-uid"
	// LabelPolicyHash is the first 40 hex characters of the sha256 of the
	// logical policy name, which may be longer than a label value allows.
	LabelPolicyHash = "compliance.erenius.io/policy-hash"

	annotationPrefix        = "compliance.erenius.io/"
	AnnotationRevision      = annotationPrefix + "revision"
	AnnotationPolicy        = annotationPrefix + "policy"
	AnnotationBinding       = annotationPrefix + "binding"
	AnnotationProfile       = annotationPrefix + "profile"
	AnnotationProfileUID    = annotationPrefix + "profile-uid"
	AnnotationProfileGen    = annotationPrefix + "profile-generation"
	AnnotationBundle        = annotationPrefix + "bundle"
	AnnotationBundleDigest  = annotationPrefix + "bundle-digest"
	AnnotationConfiguration = annotationPrefix + "configuration-digest"
	AnnotationSourceDigest  = annotationPrefix + "source-digest"
	AnnotationCluster       = annotationPrefix + "cluster"
	AnnotationMode          = annotationPrefix + "mode"
)

var nameUnsafe = regexp.MustCompile(`[^a-z0-9-]+`)

// PolicyName is the engine resource name for a contribution. It is derived
// from the revision, so changed semantics always get a new name. The readable
// part is truncated so names fit in 63 characters, the limit for names Kyverno
// derives other resources from; the 16-hex suffix keeps names unique. Exceptions bind to
// this name, so it must never be reused for another revision.
func PolicyName(c Contribution) string {
	readable := strings.Trim(nameUnsafe.ReplaceAllString(strings.ToLower(c.Policy), "-"), "-")
	if len(readable) > 36 {
		readable = strings.TrimRight(readable[:36], "-")
	}
	suffix := hexSum([]byte(string(c.Binding.UID) + "\x00" + c.Policy + "\x00" + c.Revision))[:16]
	return "konstapel-" + readable + "-" + suffix
}

// PolicyHash is the LabelPolicyHash value for a logical policy name.
func PolicyHash(policy string) string { return hexSum([]byte(policy))[:40] }

// Render produces the engine policy for one contribution from its unmodified
// source. It replaces only what Konstapel owns: name, labels, annotations,
// owner, validation action, background evaluation and namespace selector. The
// source's rules, variables and validations are untouched.
func Render(c Contribution, src PolicySource) (*unstructured.Unstructured, error) {
	if s, err := PolicyScopeOf(src.Manifest, StandardWorkloadScopes); err != nil {
		return nil, err
	} else if s != ScopeNamespaced {
		return nil, fmt.Errorf("policy %s: only namespaced workload policies can be namespace-targeted", c.Policy)
	}
	raw, err := json.Marshal(src.Manifest)
	if err != nil {
		return nil, err
	}
	obj := &unstructured.Unstructured{}
	if err := obj.UnmarshalJSON(raw); err != nil {
		return nil, err
	}
	if _, found, _ := unstructured.NestedFieldNoCopy(obj.Object, "spec", "matchConstraints", "namespaceSelector"); found {
		return nil, fmt.Errorf("policy %s: source sets its own namespaceSelector; Konstapel owns namespace scope", c.Policy)
	}
	if c.Mode != v1alpha1.ModeAudit && c.Mode != v1alpha1.ModeDeny {
		return nil, fmt.Errorf("policy %s: unsupported mode %q", c.Policy, c.Mode)
	}

	obj.SetName(PolicyName(c))
	obj.SetNamespace("")
	obj.SetLabels(map[string]string{
		LabelManagedBy:  ManagedByValue,
		LabelBindingUID: string(c.Binding.UID),
		LabelPolicyHash: PolicyHash(c.Policy),
	})
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	for k, v := range map[string]string{
		AnnotationRevision:      c.Revision,
		AnnotationPolicy:        c.Policy,
		AnnotationBinding:       c.Binding.Name,
		AnnotationProfile:       c.Profile.Name,
		AnnotationProfileUID:    string(c.Profile.UID),
		AnnotationProfileGen:    strconv.FormatInt(c.Profile.Generation, 10),
		AnnotationBundle:        c.BundleName,
		AnnotationBundleDigest:  c.BundleDigest,
		AnnotationConfiguration: c.ConfigurationDigest,
		AnnotationSourceDigest:  src.SourceDigest,
		AnnotationCluster:       c.Cluster,
		AnnotationMode:          string(c.Mode),
	} {
		annotations[k] = v
	}
	obj.SetAnnotations(annotations)
	controller := true
	obj.SetOwnerReferences([]metav1.OwnerReference{{
		APIVersion: v1alpha1.GroupVersion.String(),
		Kind:       "ComplianceBinding",
		Name:       c.Binding.Name,
		UID:        c.Binding.UID,
		Controller: &controller,
	}})

	sel, err := toUnstructured(c.NamespaceSelector.LabelSelector())
	if err != nil {
		return nil, err
	}
	for _, set := range []struct {
		value  any
		fields []string
	}{
		{[]any{string(c.Mode)}, []string{"spec", "validationActions"}},
		{true, []string{"spec", "evaluation", "background", "enabled"}},
		{sel, []string{"spec", "matchConstraints", "namespaceSelector"}},
	} {
		if err := unstructured.SetNestedField(obj.Object, set.value, set.fields...); err != nil {
			return nil, err
		}
	}
	return obj, nil
}

func toUnstructured(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	return out, json.Unmarshal(raw, &out)
}
