package download

import (
	"context"
	"errors"
	"testing"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// apiserver answers reviews: the token "good" is valid for audiences, and
// SAR allows only user "alice".
func apiserver(audiences []string, fail bool) client.Client {
	return fake.NewClientBuilder().WithScheme(scheme()).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
			if fail {
				return errors.New("connection refused")
			}
			switch o := obj.(type) {
			case *authnv1.TokenReview:
				if o.Spec.Token == "good" {
					o.Status = authnv1.TokenReviewStatus{Authenticated: true, Audiences: audiences, User: authnv1.UserInfo{Username: "alice", Extra: map[string]authnv1.ExtraValue{"scopes": {"x"}}}}
				}
			case *authzv1.SubjectAccessReview:
				o.Status.Allowed = o.Spec.User == "alice" && o.Spec.Extra["scopes"][0] == "x"
			}
			return nil
		}}).Build()
}

func TestKubeReviewer(t *testing.T) {
	ctx := context.Background()
	k := KubeReviewer{Client: apiserver([]string{"konstapel-download"}, false), Audience: "konstapel-download"}
	u, err := k.Authenticate(ctx, "good")
	if err != nil || u.Username != "alice" {
		t.Fatal(u, err)
	}
	if ok, err := k.Authorize(ctx, u, authzv1.ResourceAttributes{Verb: "get"}); !ok || err != nil {
		t.Fatal("alice with her extras denied", err)
	}
	if _, err := k.Authenticate(ctx, "bad"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
	// A token valid only for another audience is refused.
	other := KubeReviewer{Client: apiserver([]string{"kubernetes"}, false), Audience: "konstapel-download"}
	if _, err := other.Authenticate(ctx, "good"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("other audience accepted: %v", err)
	}
	// Review failures are errors, not denials or grants.
	down := KubeReviewer{Client: apiserver(nil, true), Audience: "konstapel-download"}
	if _, err := down.Authenticate(ctx, "good"); err == nil || errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("review outage: %v", err)
	}
	if _, err := (KubeReviewer{Client: k.Client}).Authenticate(ctx, "good"); err == nil {
		t.Fatal("missing audience accepted")
	}
}
