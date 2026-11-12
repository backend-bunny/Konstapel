package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// ProfileReconciler reports whether a profile's pinned content resolves.
// Bindings report their own resolution; this condition explains the profile
// side once, for every binding that references it.
//
// Unavailable content is always Resolved=False with reason
// ContentUnavailable, the boundary bindings and assessments depend on; a
// classified content error (targeting.ContentError) adds its class and
// bounded detail to the message and sets the retry interval
// (ContentRequeue). Source configuration and trust changes re-trigger the
// affected profiles through events, so they need no profile edit.
type ProfileReconciler struct {
	Client  client.Client
	Content targeting.ContentSource
	// ValidateParameters, when set, gives parameters of content that
	// declares a parameter contract a precise InvalidConfiguration
	// (content.ValidateParameters). Content without a contract
	// (LocalContent) is unaffected.
	ValidateParameters ParameterValidator
}

func (r *ProfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	p := &v1alpha1.ComplianceProfile{}
	if err := r.Client.Get(ctx, req.NamespacedName, p); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	cond := metav1.Condition{Type: v1alpha1.ConditionResolved, Status: metav1.ConditionTrue, Reason: v1alpha1.ReasonResolutionSucceeded, ObservedGeneration: p.Generation}
	var requeue time.Duration
	content, err := r.Content.Content(ctx, p.Spec.Bundle)
	switch {
	case errors.Is(err, targeting.ErrContentUnavailable):
		cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, v1alpha1.ReasonContentUnavailable, contentMessage(err)
		requeue = ContentRequeue(err)
	case err != nil:
		return ctrl.Result{}, err
	default:
		known := map[string]targeting.BundlePolicy{}
		for _, bp := range content.Bundle.Policies {
			known[bp.Name] = bp
		}
		var problems []string
		reason := ""
		for _, pol := range p.Spec.Policies {
			bp, ok := known[pol.Name]
			switch {
			case !ok:
				problems, reason = append(problems, fmt.Sprintf("unknown policy %q", pol.Name)), v1alpha1.ReasonUnknownPolicy
			case bp.Scope != targeting.ScopeNamespaced:
				problems = append(problems, fmt.Sprintf("policy %q has %s scope", pol.Name, bp.Scope))
				reason = cmpOr(reason, v1alpha1.ReasonUnsupportedScope)
			default:
				if msg := parameterProblem(r.ValidateParameters, content, bp, pol); msg != "" {
					problems = append(problems, msg)
					reason = cmpOr(reason, v1alpha1.ReasonInvalidConfiguration)
				}
			}
		}
		if len(problems) > 0 {
			cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, reason, truncate(strings.Join(problems, "; "))
		} else {
			cond.Message = fmt.Sprintf("%d policies resolve in %s@%s", len(p.Spec.Policies), p.Spec.Bundle.Name, p.Spec.Bundle.Digest)
		}
	}
	status := v1alpha1.ComplianceProfileStatus{ObservedGeneration: p.Generation, Conditions: slices.Clone(p.Status.Conditions)}
	meta.SetStatusCondition(&status.Conditions, cond)
	if equality.Semantic.DeepEqual(p.Status, status) {
		return ctrl.Result{RequeueAfter: requeue}, nil
	}
	p.Status = status
	if err := r.Client.Status().Update(ctx, p); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
