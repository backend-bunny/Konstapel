package s3store

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CredentialRefresh is how long credentials read from the controller-namespace
// Secret are reused before the Secret is read again, so a rotated Secret takes
// effect within this interval without a restart.
const CredentialRefresh = 5 * time.Minute

// SecretCredentials returns a credentials provider that reads ref from the
// controller's namespace through r, caching the values for refresh.
func SecretCredentials(r client.Reader, namespace string, ref *SecretRef, refresh time.Duration) aws.CredentialsProvider {
	return aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		c, err := LoadCredentials(ctx, r, namespace, ref)
		if err != nil {
			return aws.Credentials{}, err
		}
		return aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey,
			Source: "konstapel-secret", CanExpire: true, Expires: time.Now().Add(refresh)}, nil
	}), func(o *aws.CredentialsCacheOptions) { o.ExpiryWindow = 0 })
}

// NewPublisher builds the production publisher for d. A credentialSecret
// destination reads its Secret from namespace through r (an uncached reader
// with get access to that Secret only is sufficient); building the publisher
// does not contact the backend, so a missing Secret or an unreachable
// endpoint surfaces later as a not-ready backend, never as a local fallback.
func NewPublisher(ctx context.Context, d Destination, r client.Reader, namespace string) (*Publisher, error) {
	var provider aws.CredentialsProvider
	if d.CredentialSecret != nil {
		provider = SecretCredentials(r, namespace, d.CredentialSecret, CredentialRefresh)
	}
	c, err := NewClientWithCredentials(ctx, d, provider)
	if err != nil {
		return nil, err
	}
	return &Publisher{Client: c, Dest: d}, nil
}
