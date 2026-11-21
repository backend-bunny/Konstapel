package exception

import (
	"context"
	"errors"
	"sync"

	authenticationv1 "k8s.io/api/authentication/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Identity is the authenticated username the Konstapel controller runs
// as. The validating webhook lets that identity release
// RevocationFinalizer once the revocation is recorded independently, and
// nothing else: it cannot revoke, renew, accept or edit an exception.
type Identity struct {
	// Lookup asks who the controller authenticates as.
	Lookup func(context.Context) (string, error)

	mu   sync.Mutex
	name string
}

// Cached returns the identity once a lookup has succeeded, and "" before.
// It never calls the API server.
func (i *Identity) Cached() string {
	if i == nil {
		return ""
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.name
}

// Get returns the identity, looking it up on first use. A failed lookup is
// not cached, so it is retried on the next call.
func (i *Identity) Get(ctx context.Context) (string, error) {
	if i == nil || i.Lookup == nil {
		return "", errors.New("no controller identity is configured")
	}
	if name := i.Cached(); name != "" {
		return name, nil
	}
	name, err := i.Lookup(ctx)
	if err != nil {
		return "", err
	}
	if name == "" {
		return "", errors.New("the controller identity lookup returned no username")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.name = name
	return name, nil
}

// SelfSubjectReview looks up the username c authenticates as with an
// authentication.k8s.io/v1 SelfSubjectReview, which every authenticated
// identity may create.
func SelfSubjectReview(c client.Client) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		r := &authenticationv1.SelfSubjectReview{}
		if err := c.Create(ctx, r); err != nil {
			return "", err
		}
		return r.Status.UserInfo.Username, nil
	}
}
