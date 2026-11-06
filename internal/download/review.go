// Package download serves published evidence packages to callers authorized
// by current Kubernetes RBAC (add-s3-evidence-publishing group 4). Callers
// authenticate with a bearer token checked by TokenReview against the
// service's audience; every request is authorized with SubjectAccessReview on
// dedicated download attributes and read access to the resolved object.
package download

import (
	"context"
	"errors"
	"fmt"
	"slices"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ErrUnauthenticated reports a token that TokenReview did not accept for the
// service's audience.
var ErrUnauthenticated = errors.New("unauthenticated")

// Reviewer authenticates tokens and authorizes resource attributes. Errors
// other than ErrUnauthenticated mean the review could not be performed; the
// server then fails closed.
type Reviewer interface {
	Authenticate(ctx context.Context, token string) (authnv1.UserInfo, error)
	Authorize(ctx context.Context, user authnv1.UserInfo, attrs authzv1.ResourceAttributes) (bool, error)
}

// KubeReviewer uses the TokenReview and SubjectAccessReview APIs. Only the
// download service account may create reviews
// (config/rbac/evidence-download.yaml); the controller role does not.
type KubeReviewer struct {
	Client client.Client
	// Audience is required in the token's audiences, so tokens minted for
	// other services are refused.
	Audience string
}

func (k KubeReviewer) Authenticate(ctx context.Context, token string) (authnv1.UserInfo, error) {
	if k.Audience == "" {
		return authnv1.UserInfo{}, errors.New("download audience is not configured")
	}
	tr := &authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: token, Audiences: []string{k.Audience}}}
	if err := k.Client.Create(ctx, tr); err != nil {
		return authnv1.UserInfo{}, fmt.Errorf("token review: %w", err)
	}
	if !tr.Status.Authenticated || !slices.Contains(tr.Status.Audiences, k.Audience) {
		return authnv1.UserInfo{}, ErrUnauthenticated
	}
	return tr.Status.User, nil
}

func (k KubeReviewer) Authorize(ctx context.Context, user authnv1.UserInfo, attrs authzv1.ResourceAttributes) (bool, error) {
	extra := map[string]authzv1.ExtraValue{}
	for key, v := range user.Extra {
		extra[key] = authzv1.ExtraValue(v)
	}
	sar := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
		User: user.Username, UID: user.UID, Groups: user.Groups, Extra: extra, ResourceAttributes: &attrs}}
	if err := k.Client.Create(ctx, sar); err != nil {
		return false, fmt.Errorf("subject access review: %w", err)
	}
	if sar.Status.EvaluationError != "" && !sar.Status.Allowed {
		return false, fmt.Errorf("subject access review: %s", sar.Status.EvaluationError)
	}
	return sar.Status.Allowed && !sar.Status.Denied, nil
}
