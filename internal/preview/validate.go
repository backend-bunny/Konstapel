package preview

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

// fieldProblem is one invalid field of a spec.
type fieldProblem struct {
	Field   string
	Message string
}

// Default values of the API server, mirrored from the CRD schema. The
// crd-conformance test checks them against the generated CRDs.
const (
	defaultInterval          = "24h"
	defaultMaxEvidenceAge    = "2h"
	defaultCollectionTimeout = "5m"
	defaultRetention         = "2160h"
)

// DefaultProfile applies the API server defaults to a profile in place:
// exception eligibility defaults to Forbidden.
func DefaultProfile(p *v1alpha1.ComplianceProfile) {
	for i := range p.Spec.Policies {
		pol := &p.Spec.Policies[i]
		if pol.Exceptions.Eligibility == "" {
			pol.Exceptions.Eligibility = v1alpha1.ExceptionsForbidden
		}
		// An explicit JSON null is pruned by the API server: same as omitted.
		if pol.Parameters != nil && isNullJSON(pol.Parameters.Raw) {
			pol.Parameters = nil
		}
	}
}

// DefaultBinding applies the API server defaults to a binding in place: the
// assessment settings. It leaves enforcementEpoch alone; whether an epoch is
// authoritative is the caller's decision (proposed input clears it).
func DefaultBinding(b *v1alpha1.ComplianceBinding) {
	if b.Spec.Assessment == nil {
		b.Spec.Assessment = &v1alpha1.BindingAssessment{}
	}
	a := b.Spec.Assessment
	def := func(d *v1alpha1.Duration, v string) {
		if *d == "" {
			*d = v1alpha1.Duration(v)
		}
	}
	def(&a.Interval, defaultInterval)
	def(&a.MaxEvidenceAge, defaultMaxEvidenceAge)
	def(&a.CollectionTimeout, defaultCollectionTimeout)
	def(&a.Retention, defaultRetention)
}

func isNullJSON(raw []byte) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || string(t) == "null"
}

var (
	namePattern     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)
	digestPattern   = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	durationPattern = regexp.MustCompile(`^([0-9]+(\.[0-9]+)?(ns|us|ms|s|m|h))+$`)
)

// ValidateProfileSpec reports every violation of the ComplianceProfile CRD
// schema and rules for a defaulted spec, in field order. It is stricter than
// the API server only in rejecting what the server would prune.
func ValidateProfileSpec(s *v1alpha1.ComplianceProfileSpec) []fieldProblem {
	var out []fieldProblem
	bad := func(field, format string, args ...any) {
		out = append(out, fieldProblem{field, fmt.Sprintf(format, args...)})
	}
	checkName := func(field, v string) {
		switch {
		case len(v) < 1 || len(v) > 253:
			bad(field, "must be 1 to 253 characters")
		case !namePattern.MatchString(v):
			bad(field, "must match %s", namePattern)
		}
	}
	checkName("spec.bundle.name", s.Bundle.Name)
	if !digestPattern.MatchString(s.Bundle.Digest) {
		bad("spec.bundle.digest", "must be a sha256 digest (sha256:<64 lowercase hex>)")
	}
	switch {
	case len(s.Policies) < 1:
		bad("spec.policies", "must list at least one policy")
	case len(s.Policies) > 256:
		bad("spec.policies", "must list at most 256 policies")
	}
	seen := map[string]bool{}
	for i, pol := range s.Policies {
		f := fmt.Sprintf("spec.policies[%d]", i)
		checkName(f+".name", pol.Name)
		if seen[pol.Name] {
			bad(f+".name", "duplicate policy %q", clip(pol.Name))
		}
		seen[pol.Name] = true
		if pol.Parameters != nil {
			if !isJSONObject(pol.Parameters.Raw) {
				bad(f+".parameters", "must be an object")
			}
		}
		ex := pol.Exceptions
		switch ex.Eligibility {
		case v1alpha1.ExceptionsForbidden:
			if ex.MaxLifetime != nil {
				bad(f+".exceptions", "SelfService requires a positive maxLifetime; Forbidden must not set maxLifetime")
			}
		case v1alpha1.ExceptionsSelfService:
			if ex.MaxLifetime == nil || ex.MaxLifetime.Duration <= 0 {
				bad(f+".exceptions", "SelfService requires a positive maxLifetime; Forbidden must not set maxLifetime")
			}
		default:
			bad(f+".exceptions.eligibility", "must be Forbidden or SelfService")
		}
	}
	return out
}

func isJSONObject(raw []byte) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == '{' && json.Valid(t)
}

// ValidateBindingSpec reports every violation of the ComplianceBinding CRD
// schema and rules for a defaulted spec. A missing namespaceSelector is an
// error: it is never read as the explicit empty selector that selects all.
func ValidateBindingSpec(s *v1alpha1.ComplianceBindingSpec) []fieldProblem {
	var out []fieldProblem
	bad := func(field, format string, args ...any) {
		out = append(out, fieldProblem{field, fmt.Sprintf(format, args...)})
	}
	if n := len(s.ProfileRef.Name); n < 1 || n > 253 {
		bad("spec.profileRef.name", "must be 1 to 253 characters")
	}
	if s.Mode != v1alpha1.ModeAudit && s.Mode != v1alpha1.ModeDeny {
		bad("spec.mode", "must be Audit or Deny; it has no default")
	}
	sel := s.NamespaceSelector
	if sel == nil {
		bad("spec.namespaceSelector", "is required; use {} to select every namespace")
	} else {
		bad2 := func(field, format string, args ...any) { bad("spec.namespaceSelector"+field, format, args...) }
		if len(sel.MatchLabels) > 64 {
			bad2(".matchLabels", "must have at most 64 entries")
		}
		for k, v := range sel.MatchLabels {
			if errs := validation.IsQualifiedName(k); len(errs) > 0 {
				bad2(".matchLabels", "key %q: %s", clip(k), strings.Join(errs, "; "))
			}
			if len(v) > 63 {
				bad2(".matchLabels", "value of %q must be at most 63 characters", clip(k))
			} else if errs := validation.IsValidLabelValue(string(v)); len(errs) > 0 {
				bad2(".matchLabels", "value of %q: %s", clip(k), strings.Join(errs, "; "))
			}
		}
		if len(sel.MatchExpressions) > 32 {
			bad2(".matchExpressions", "must have at most 32 entries")
		}
		for i, r := range sel.MatchExpressions {
			f := fmt.Sprintf(".matchExpressions[%d]", i)
			if len(r.Key) > 317 {
				bad2(f+".key", "must be at most 317 characters")
			} else if errs := validation.IsQualifiedName(r.Key); len(errs) > 0 {
				bad2(f+".key", "%s", strings.Join(errs, "; "))
			}
			switch r.Operator {
			case metav1.LabelSelectorOpIn, metav1.LabelSelectorOpNotIn:
				if len(r.Values) == 0 {
					bad2(f+".values", "In and NotIn require values")
				}
			case metav1.LabelSelectorOpExists, metav1.LabelSelectorOpDoesNotExist:
				if len(r.Values) > 0 {
					bad2(f+".values", "Exists and DoesNotExist must not set values")
				}
			default:
				bad2(f+".operator", "must be In, NotIn, Exists or DoesNotExist")
			}
			if len(r.Values) > 64 {
				bad2(f+".values", "must have at most 64 entries")
			}
			for _, v := range r.Values {
				if len(v) > 63 {
					bad2(f+".values", "values must be at most 63 characters")
				} else if errs := validation.IsValidLabelValue(v); len(errs) > 0 {
					bad2(f+".values", "%s", strings.Join(errs, "; "))
				}
			}
		}
		if !hasPrefixField(out, "spec.namespaceSelector") {
			// Final authority: the standard Kubernetes selector conversion
			// that the resolver itself uses.
			if _, err := sel.AsSelector(); err != nil {
				bad("spec.namespaceSelector", "%v", err)
			}
		}
	}
	if a := s.Assessment; a != nil {
		for _, d := range []struct {
			field string
			v     v1alpha1.Duration
		}{{"interval", a.Interval}, {"maxEvidenceAge", a.MaxEvidenceAge}, {"collectionTimeout", a.CollectionTimeout}, {"retention", a.Retention}} {
			if msg := checkDuration(string(d.v)); msg != "" {
				bad("spec.assessment."+d.field, "%s", msg)
			}
		}
		if r := a.DestinationRef; r != nil {
			switch {
			case len(r.Name) < 1 || len(r.Name) > 253 || !namePattern.MatchString(r.Name):
				bad("spec.assessment.destinationRef.name", "must be 1 to 253 characters matching %s", namePattern)
			}
			if len(r.UID) < 1 || len(r.UID) > 64 {
				bad("spec.assessment.destinationRef.uid", "must be 1 to 64 characters")
			}
		}
	}
	return out
}

func hasPrefixField(ps []fieldProblem, prefix string) bool {
	for _, p := range ps {
		if strings.HasPrefix(p.Field, prefix) {
			return true
		}
	}
	return false
}

func checkDuration(s string) string {
	switch {
	case len(s) < 2 || len(s) > 32:
		return "must be 2 to 32 characters, for example 24h"
	case !durationPattern.MatchString(s):
		return "must be a duration such as 24h, 90m or 2160h; days, cron expressions and signs are not supported"
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return "must be a positive duration"
	}
	return ""
}
