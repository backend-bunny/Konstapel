package capability

import (
	"context"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type metaResource = metav1.APIResource

// discoverWithContext asks discovery for one group/version, bounded by ctx.
func discoverWithContext(ctx context.Context, dc discovery.ServerResourcesInterfaceWithContext, gv string) (*metav1.APIResourceList, error) {
	return dc.ServerResourcesForGroupVersionWithContext(ctx, gv)
}

// SelfReview checks the client's own identity with SelfSubjectAccessReviews.
func SelfReview(c client.Client) Reviewer {
	return func(ctx context.Context, attrs authorizationv1.ResourceAttributes) (bool, string, error) {
		r := &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &attrs}}
		if err := c.Create(ctx, r); err != nil {
			return false, "", err
		}
		return r.Status.Allowed, r.Status.Reason, nil
	}
}
