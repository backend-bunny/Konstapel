package s3store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// Versioning is a bucket's versioning mode.
type Versioning string

const (
	Unversioned Versioning = "Unversioned"
	Enabled     Versioning = "Enabled"
	Suspended   Versioning = "Suspended"
)

// ChecksumMode records how object content is verified.
type ChecksumMode string

const (
	// ChecksumServer: the service stores and returns SHA-256 checksums.
	ChecksumServer ChecksumMode = "server-sha256"
	// ChecksumReadback: content is verified by reading it back and hashing.
	ChecksumReadback ChecksumMode = "readback"
)

// MaxClockSkew bounds the difference between server and controller clocks.
const MaxClockSkew = 5 * time.Minute

// Compatibility is the result of probing a destination for the semantics the
// publisher relies on. Ready is false unless every required check passed.
type Compatibility struct {
	Ready             bool          `json:"ready"`
	Versioning        Versioning    `json:"versioning"`
	Checksum          ChecksumMode  `json:"checksum,omitempty"`
	ConditionalCreate bool          `json:"conditionalCreate"`
	ServerTime        bool          `json:"serverTime"`
	ClockSkew         time.Duration `json:"clockSkew"`
	VersionIDs        bool          `json:"versionIDs"`
	Problems          []string      `json:"problems,omitempty"`
}

// Probe checks, under a unique probe key prefix owned by this call, that the
// destination supports what publication requires:
//
//   - the bucket is reachable with the configured credentials;
//   - create-if-absent: a second PutObject with If-None-Match: * fails with
//     412, so a commit can never be overwritten;
//   - SHA-256 content verification, from server checksums or readback;
//   - server LastModified timestamps within MaxClockSkew of the controller;
//   - version IDs consistent with the bucket's versioning mode, and deletion
//     of a specific version, so owned bytes can be removed in every mode.
//
// It removes every object version it created. Probe never creates buckets or
// changes bucket configuration.
func Probe(ctx context.Context, c *s3.Client, d Destination) (Compatibility, error) {
	r := Compatibility{}
	if _, err := c.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(d.Bucket)}); err != nil {
		return r, fmt.Errorf("bucket %s is not reachable with the configured credentials: %w", d.Bucket, sanitize(err))
	}
	v, err := c.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(d.Bucket)})
	if err != nil {
		return r, fmt.Errorf("read bucket versioning: %w", sanitize(err))
	}
	switch v.Status {
	case types.BucketVersioningStatusEnabled:
		r.Versioning = Enabled
	case types.BucketVersioningStatusSuspended:
		r.Versioning = Suspended
	default:
		r.Versioning = Unversioned
	}

	id := make([]byte, 8)
	_, _ = rand.Read(id)
	prefix := d.KeyPrefix() + "konstapel-probe/" + hex.EncodeToString(id) + "/"
	defer func() { r.Problems = append(r.Problems, cleanup(context.WithoutCancel(ctx), c, d.Bucket, prefix)...) }()
	problem := func(format string, a ...any) { r.Problems = append(r.Problems, fmt.Sprintf(format, a...)) }

	// Checksummed write and verification.
	body := []byte("konstapel compatibility probe " + hex.EncodeToString(id))
	sum := sha256.Sum256(body)
	want := base64.StdEncoding.EncodeToString(sum[:])
	key := prefix + "archive"
	start := time.Now()
	put, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(d.Bucket), Key: aws.String(key), Body: bytes.NewReader(body),
		ChecksumSHA256: aws.String(want), ContentLength: aws.Int64(int64(len(body)))})
	if err != nil {
		return r, fmt.Errorf("put probe object: %w", sanitize(err))
	}
	head, err := c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(d.Bucket), Key: aws.String(key), ChecksumMode: types.ChecksumModeEnabled})
	if err != nil {
		return r, fmt.Errorf("head probe object: %w", sanitize(err))
	}
	switch {
	case aws.ToString(head.ChecksumSHA256) == want:
		r.Checksum = ChecksumServer
	case aws.ToString(head.ChecksumSHA256) != "":
		problem("server SHA-256 %s does not match the written content", aws.ToString(head.ChecksumSHA256))
	default:
		got, err := c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(d.Bucket), Key: aws.String(key)})
		if err != nil {
			return r, fmt.Errorf("read back probe object: %w", sanitize(err))
		}
		b, err := io.ReadAll(io.LimitReader(got.Body, 1<<20))
		_ = got.Body.Close()
		if h := sha256.Sum256(b); err == nil && h == sum {
			r.Checksum = ChecksumReadback
		} else {
			problem("read-back content does not match the written content")
		}
	}

	// Server timestamps.
	if head.LastModified == nil {
		problem("server returned no LastModified time")
	} else {
		r.ServerTime = true
		mid := start.Add(time.Since(start) / 2)
		r.ClockSkew = head.LastModified.Sub(mid).Round(time.Second)
		if r.ClockSkew > MaxClockSkew || r.ClockSkew < -MaxClockSkew {
			problem("server clock differs from the controller by %s", r.ClockSkew)
		}
	}

	// Create-if-absent.
	commit := prefix + "commit.json"
	if _, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(d.Bucket), Key: aws.String(commit), Body: bytes.NewReader([]byte("first")), IfNoneMatch: aws.String("*")}); err != nil {
		problem("conditional create of a new key failed: %v", sanitize(err))
	} else {
		_, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(d.Bucket), Key: aws.String(commit), Body: bytes.NewReader([]byte("second")), IfNoneMatch: aws.String("*")})
		var api smithy.APIError
		switch {
		case err == nil:
			problem("conditional create overwrote an existing key (If-None-Match: * not enforced)")
		case errors.As(err, &api) && (api.ErrorCode() == "PreconditionFailed" || httpStatus(err) == 412):
			r.ConditionalCreate = true
		default:
			problem("conditional create of an existing key failed unexpectedly: %v", sanitize(err))
		}
		if got, err := c.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(d.Bucket), Key: aws.String(commit)}); err == nil {
			b, _ := io.ReadAll(io.LimitReader(got.Body, 64))
			_ = got.Body.Close()
			if string(b) != "first" {
				r.ConditionalCreate = false
				problem("the first committed content was replaced")
			}
		}
	}

	// Version identity and specific-version deletion.
	vid := aws.ToString(put.VersionId)
	switch r.Versioning {
	case Enabled:
		if vid == "" || vid == "null" {
			problem("versioning is enabled but writes return no version ID")
		} else if _, err := c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(d.Bucket), Key: aws.String(key), VersionId: aws.String(vid)}); err != nil {
			problem("deleting a specific version failed: %v", sanitize(err))
		} else if _, err := c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(d.Bucket), Key: aws.String(key), VersionId: aws.String(vid)}); err == nil {
			problem("a deleted version is still readable")
		} else {
			r.VersionIDs = true
		}
	default:
		r.VersionIDs = vid == "" || vid == "null"
		if !r.VersionIDs {
			problem("bucket is %s but writes return version ID %q", r.Versioning, vid)
		}
	}
	r.Ready = len(r.Problems) == 0 && r.Checksum != "" && r.ConditionalCreate && r.ServerTime && r.VersionIDs
	return r, nil
}

// cleanup removes every object version and delete marker under prefix. It
// lists only that prefix, so unrelated objects are never touched.
func cleanup(ctx context.Context, c *s3.Client, bucket, prefix string) []string {
	var problems []string
	in := &s3.ListObjectVersionsInput{Bucket: aws.String(bucket), Prefix: aws.String(prefix)}
	versions, err := c.ListObjectVersions(ctx, in)
	if err != nil {
		// Unversioned services may not implement version listing.
		list, lerr := c.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String(prefix)})
		if lerr != nil {
			return []string{fmt.Sprintf("probe cleanup could not list %s: %v", prefix, sanitize(lerr))}
		}
		for _, o := range list.Contents {
			if _, err := c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: o.Key}); err != nil {
				problems = append(problems, fmt.Sprintf("probe cleanup of %s: %v", aws.ToString(o.Key), sanitize(err)))
			}
		}
		return problems
	}
	del := func(key, version *string) {
		if _, err := c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: key, VersionId: version}); err != nil {
			problems = append(problems, fmt.Sprintf("probe cleanup of %s: %v", aws.ToString(key), sanitize(err)))
		}
	}
	for _, v := range versions.Versions {
		del(v.Key, v.VersionId)
	}
	for _, m := range versions.DeleteMarkers {
		del(m.Key, m.VersionId)
	}
	return problems
}

func httpStatus(err error) int {
	var re interface{ HTTPStatusCode() int }
	if errors.As(err, &re) {
		return re.HTTPStatusCode()
	}
	return 0
}

// sanitize reduces an SDK error to its code and message, dropping request
// details that could carry signed headers.
func sanitize(err error) error {
	var api smithy.APIError
	if errors.As(err, &api) {
		return fmt.Errorf("%s: %s", api.ErrorCode(), api.ErrorMessage())
	}
	var op *smithy.OperationError
	if errors.As(err, &op) {
		return fmt.Errorf("%s %s: %v", op.ServiceID, op.OperationName, op.Err)
	}
	return err
}
