package s3store

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// StaticCredentials are values read from the controller-namespace Secret.
// They are never logged or included in errors or status.
type StaticCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

// String redacts the credentials.
func (StaticCredentials) String() string { return "StaticCredentials{redacted}" }

// ErrCredentials reports missing or unusable credentials without their values.
var ErrCredentials = errors.New("evidence destination credentials are missing or invalid")

// RequestTimeout bounds every individual S3 request.
const RequestTimeout = 30 * time.Second

// NewClient builds an S3 client for d. creds is used only for a
// credentialSecret destination; workload identity uses the SDK's standard
// chain (for example a projected web-identity token).
func NewClient(ctx context.Context, d Destination, creds *StaticCredentials) (*s3.Client, error) {
	var provider aws.CredentialsProvider
	if d.CredentialSecret != nil {
		if creds == nil || creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
			return nil, fmt.Errorf("%w: secret %s", ErrCredentials, d.CredentialSecret.Name)
		}
		provider = credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, "")
	}
	return NewClientWithCredentials(ctx, d, provider)
}

// NewClientWithCredentials builds an S3 client for d. A credentialSecret
// destination requires provider (see SecretCredentials); workload identity
// ignores it and uses the SDK's standard chain.
func NewClientWithCredentials(ctx context.Context, d Destination, provider aws.CredentialsProvider) (*s3.Client, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	httpClient, err := tlsClient(d.CABundle, d.CAPEM)
	if err != nil {
		return nil, err
	}
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(d.Region),
		awsconfig.WithHTTPClient(httpClient),
		awsconfig.WithRetryMaxAttempts(3),
	}
	if d.CredentialSecret != nil {
		if provider == nil {
			return nil, fmt.Errorf("%w: secret %s", ErrCredentials, d.CredentialSecret.Name)
		}
		opts = append(opts, awsconfig.WithCredentialsProvider(provider))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentials, err)
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(d.Endpoint)
		o.UsePathStyle = d.Addressing == AddressingPath
		// Integrity is checked explicitly with SHA-256 on every write.
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	}), nil
}

// tlsClient trusts the system roots plus an optional PEM bundle. Certificate
// verification is always on.
func tlsClient(caBundle string, caPEM []byte) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caBundle != "" {
		pem, err := os.ReadFile(caBundle)
		if err != nil {
			return nil, fmt.Errorf("caBundle: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("caBundle %s contains no PEM certificates", caBundle)
		}
	}
	if len(caPEM) > 0 && !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA trust contains no PEM certificates")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: transport, Timeout: RequestTimeout}, nil
}
