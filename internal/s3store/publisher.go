package s3store

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// MaxArchiveBytes bounds an uploaded package archive. Archives are uploaded
// in a single request, so their checksum is a true content hash, never a
// multipart ETag.
const MaxArchiveBytes = 512 << 20

// Publisher stores packages in an S3 destination. It implements
// publication.Publisher.
type Publisher struct {
	Client *s3.Client
	Dest   Destination
	// Now is the controller clock, used only for expiry comparisons;
	// publication times always come from the storage server.
	Now func() time.Time
}

var _ publication.Publisher = (*Publisher)(nil)

func (p *Publisher) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// runPrefix is the opaque, UID-based key prefix that owns a run's objects.
// It contains no names, reasons, or workload identities.
func (p *Publisher) runPrefix(run publication.RunRef) string {
	cluster := strings.TrimPrefix(run.ClusterID, "kube-system:")
	return p.Dest.KeyPrefix() + "evidence/" + safeSegment(cluster) + "/" + safeSegment(run.BindingUID) + "/" + safeSegment(run.RunUID) + "/"
}

func safeSegment(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			return r
		}
		return '_'
	}, s)
}

// Ready probes the destination's required semantics. Publication must not
// proceed, or fall back to local storage, while it reports an error.
func (p *Publisher) Ready(ctx context.Context) (Compatibility, error) {
	r, err := Probe(ctx, p.Client, p.Dest)
	if err != nil {
		return r, fmt.Errorf("%w: %v", publication.ErrUnavailable, err)
	}
	if !r.Ready {
		return r, fmt.Errorf("%w: destination %s lacks required semantics: %s", publication.ErrUnavailable, p.Dest.ID, strings.Join(r.Problems, "; "))
	}
	return r, nil
}

// attempt is the durable staging intent written beside an uploaded archive.
type attempt struct {
	Run              publication.RunRef `json:"run"`
	DescriptorSHA256 string             `json:"descriptorSha256"`
	ArchiveKey       string             `json:"archiveKey"`
	ArchiveVersionID string             `json:"archiveVersionID,omitempty"`
	PackageSHA256    string             `json:"packageSha256"`
	PackageSize      int64              `json:"packageSize"`
	Created          time.Time          `json:"created"`
}

// manifest is the commit object. Its successful conditional creation is the
// publication commit; its server LastModified time is publishedAt.
type manifest struct {
	APIVersion       string                `json:"apiVersion"`
	Kind             string                `json:"kind"`
	PublicationID    string                `json:"publicationID"`
	Run              publication.RunRef    `json:"run"`
	DescriptorSHA256 string                `json:"descriptorSha256"`
	ArchiveKey       string                `json:"archiveKey"`
	ArchiveVersionID string                `json:"archiveVersionID,omitempty"`
	PackageSHA256    string                `json:"packageSha256"`
	PackageSize      int64                 `json:"packageSize"`
	Retention        publication.Retention `json:"retention"`
}

// Stage validates the package directory, builds its deterministic archive,
// uploads it under a new attempt key with an explicit SHA-256, verifies the
// stored content, and records the attempt.
func (p *Publisher) Stage(ctx context.Context, req publication.StageRequest) (publication.Staged, error) {
	d, err := ValidatePackage(req.Dir)
	if err != nil {
		return publication.Staged{}, err
	}
	if d.Run != req.Run {
		return publication.Staged{}, fmt.Errorf("descriptor run does not match the request: %w", publication.ErrConflict)
	}
	archive, err := Archive(req.Dir)
	if err != nil {
		return publication.Staged{}, err
	}
	sum := sha256.Sum256(archive)
	staged := publication.Staged{Run: req.Run, PublicationID: req.Run.PublicationID(), DescriptorSHA256: d.Digest(),
		PackageSHA256: hex.EncodeToString(sum[:]), PackageSize: int64(len(archive))}
	// A committed publication for this run with other content is a conflict;
	// with the same content (a lost response or a failed receipt update) it
	// is already staged and nothing is uploaded again.
	if m, _, err := p.readManifest(ctx, req.Run); err == nil {
		if m.PackageSHA256 != staged.PackageSHA256 || m.DescriptorSHA256 != staged.DescriptorSHA256 {
			return publication.Staged{}, fmt.Errorf("run already committed different content: %w", publication.ErrConflict)
		}
		return staged, nil
	} else if !errors.Is(err, publication.ErrNotFound) {
		return publication.Staged{}, err
	}
	// An earlier attempt that uploaded the same bytes and still verifies is
	// reused, so a retry after an upload never uploads a second copy.
	if prior, err := p.Recover(ctx, req.Run); err == nil && prior.PackageSHA256 == staged.PackageSHA256 && prior.DescriptorSHA256 == staged.DescriptorSHA256 {
		return staged, nil
	} else if err != nil && !errors.Is(err, publication.ErrCaptureLost) {
		return publication.Staged{}, err
	}
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	at := p.runPrefix(req.Run) + "attempts/" + hex.EncodeToString(id) + "/"
	// Record the attempt's owner before any bytes, so an interrupted upload
	// can always be identified and cleaned up.
	intent, _ := json.Marshal(attemptIntent{Run: req.Run, Created: p.now().UTC()})
	if _, err := p.putVerified(ctx, at+intentFile, intent); err != nil {
		return publication.Staged{}, err
	}
	vid, err := p.putVerified(ctx, at+"package.tar.gz", archive)
	if err != nil {
		return publication.Staged{}, err
	}
	rec, _ := json.Marshal(attempt{Run: req.Run, DescriptorSHA256: staged.DescriptorSHA256, ArchiveKey: at + "package.tar.gz", ArchiveVersionID: vid,
		PackageSHA256: staged.PackageSHA256, PackageSize: staged.PackageSize, Created: p.now().UTC()})
	if _, err := p.putVerified(ctx, at+"attempt.json", rec); err != nil {
		return publication.Staged{}, err
	}
	return staged, nil
}

// putVerified uploads body with an explicit SHA-256 in a single request and
// verifies the stored content from the server checksum or by reading it
// back. ETags are never used as content hashes.
func (p *Publisher) putVerified(ctx context.Context, key string, body []byte) (string, error) {
	if len(body) > MaxArchiveBytes {
		return "", fmt.Errorf("object %s exceeds %d bytes", key, MaxArchiveBytes)
	}
	sum := sha256.Sum256(body)
	want := base64.StdEncoding.EncodeToString(sum[:])
	put, err := p.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(p.Dest.Bucket), Key: aws.String(key), Body: bytes.NewReader(body),
		ChecksumSHA256: aws.String(want), ContentLength: aws.Int64(int64(len(body)))})
	if err != nil {
		return "", fmt.Errorf("%w: upload %s: %v", publication.ErrUnavailable, key, sanitize(err))
	}
	vid := versionID(put.VersionId)
	if err := p.verify(ctx, key, vid, sum); err != nil {
		return "", err
	}
	return vid, nil
}

func (p *Publisher) verify(ctx context.Context, key, vid string, sum [32]byte) error {
	in := &s3.HeadObjectInput{Bucket: aws.String(p.Dest.Bucket), Key: aws.String(key), ChecksumMode: types.ChecksumModeEnabled}
	if vid != "" {
		in.VersionId = aws.String(vid)
	}
	head, err := p.Client.HeadObject(ctx, in)
	if err != nil {
		return fmt.Errorf("%w: verify %s: %v", publication.ErrUnavailable, key, sanitize(err))
	}
	if c := aws.ToString(head.ChecksumSHA256); c != "" {
		if c != base64.StdEncoding.EncodeToString(sum[:]) {
			return fmt.Errorf("stored %s has a different SHA-256", key)
		}
		return nil
	}
	b, err := p.read(ctx, key, vid)
	if err != nil {
		return err
	}
	if sha256.Sum256(b) != sum {
		return fmt.Errorf("read-back of %s does not match the uploaded content", key)
	}
	return nil
}

func (p *Publisher) read(ctx context.Context, key, vid string) ([]byte, error) {
	in := &s3.GetObjectInput{Bucket: aws.String(p.Dest.Bucket), Key: aws.String(key)}
	if vid != "" {
		in.VersionId = aws.String(vid)
	}
	got, err := p.Client.GetObject(ctx, in)
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("%s: %w", key, publication.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: read %s: %v", publication.ErrUnavailable, key, sanitize(err))
	}
	defer got.Body.Close()
	b, err := io.ReadAll(io.LimitReader(got.Body, MaxArchiveBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", publication.ErrUnavailable, key, err)
	}
	if len(b) > MaxArchiveBytes {
		return nil, fmt.Errorf("object %s exceeds %d bytes", key, MaxArchiveBytes)
	}
	return b, nil
}

// Recover returns the newest durably staged attempt whose archive still
// verifies, or ErrCaptureLost.
func (p *Publisher) Recover(ctx context.Context, run publication.RunRef) (publication.Staged, error) {
	prefix := p.runPrefix(run) + "attempts/"
	list, err := p.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(p.Dest.Bucket), Prefix: aws.String(prefix)})
	if err != nil {
		return publication.Staged{}, fmt.Errorf("%w: list attempts: %v", publication.ErrUnavailable, sanitize(err))
	}
	var attempts []attempt
	for _, o := range list.Contents {
		if !strings.HasSuffix(aws.ToString(o.Key), "/attempt.json") {
			continue
		}
		b, err := p.read(ctx, aws.ToString(o.Key), "")
		var a attempt
		if err != nil || json.Unmarshal(b, &a) != nil || a.Run != run {
			continue
		}
		attempts = append(attempts, a)
	}
	slices.SortFunc(attempts, func(a, b attempt) int { return b.Created.Compare(a.Created) })
	for _, a := range attempts {
		sum, err := hex.DecodeString(a.PackageSHA256)
		if err != nil || len(sum) != 32 {
			continue
		}
		if p.verify(ctx, a.ArchiveKey, a.ArchiveVersionID, [32]byte(sum)) == nil {
			return publication.Staged{Run: run, PublicationID: run.PublicationID(), DescriptorSHA256: a.DescriptorSHA256, PackageSHA256: a.PackageSHA256, PackageSize: a.PackageSize}, nil
		}
	}
	return publication.Staged{}, publication.ErrCaptureLost
}

// Publish commits staged content once. The run's single fixed commit key is
// created with If-None-Match: *, so concurrent or retried attempts reconcile
// one publication; an existing commit for the same content returns its
// original receipt, and different content is a conflict.
func (p *Publisher) Publish(ctx context.Context, req publication.PublishRequest) (publication.Receipt, error) {
	s := req.Staged
	if s.PublicationID != s.Run.PublicationID() {
		return publication.Receipt{}, publication.ErrConflict
	}
	if m, head, err := p.readManifest(ctx, s.Run); err == nil {
		return p.receipt(m, head, s)
	} else if !errors.Is(err, publication.ErrNotFound) {
		return publication.Receipt{}, err
	}
	if _, err := req.Retention.ParseDuration(); err != nil {
		return publication.Receipt{}, err
	}
	a, err := p.stagedAttempt(ctx, s)
	if err != nil {
		return publication.Receipt{}, err
	}
	m := manifest{APIVersion: publication.APIVersion, Kind: "PublicationCommit", PublicationID: s.PublicationID, Run: s.Run,
		DescriptorSHA256: s.DescriptorSHA256, ArchiveKey: a.ArchiveKey, ArchiveVersionID: a.ArchiveVersionID,
		PackageSHA256: s.PackageSHA256, PackageSize: s.PackageSize, Retention: req.Retention}
	body, _ := json.Marshal(m)
	sum := sha256.Sum256(body)
	_, err = p.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(p.Dest.Bucket), Key: aws.String(p.commitKey(s.Run)), Body: bytes.NewReader(body),
		ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sum[:])), ContentLength: aws.Int64(int64(len(body))), IfNoneMatch: aws.String("*")})
	if err != nil && !isPreconditionFailed(err) {
		return publication.Receipt{}, fmt.Errorf("%w: commit: %v", publication.ErrUnavailable, sanitize(err))
	}
	// Whether this attempt won or another did, the stored commit decides.
	m, head, err := p.readManifest(ctx, s.Run)
	if err != nil {
		return publication.Receipt{}, err
	}
	return p.receipt(m, head, s)
}

// stagedAttempt finds the verified attempt holding the staged content.
func (p *Publisher) stagedAttempt(ctx context.Context, s publication.Staged) (attempt, error) {
	got, err := p.Recover(ctx, s.Run)
	if err != nil {
		return attempt{}, err
	}
	if got.PackageSHA256 != s.PackageSHA256 || got.DescriptorSHA256 != s.DescriptorSHA256 {
		return attempt{}, fmt.Errorf("newest staged attempt differs from the content to publish: %w", publication.ErrConflict)
	}
	prefix := p.runPrefix(s.Run) + "attempts/"
	list, err := p.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(p.Dest.Bucket), Prefix: aws.String(prefix)})
	if err != nil {
		return attempt{}, fmt.Errorf("%w: list attempts: %v", publication.ErrUnavailable, sanitize(err))
	}
	var newest attempt
	for _, o := range list.Contents {
		if !strings.HasSuffix(aws.ToString(o.Key), "/attempt.json") {
			continue
		}
		b, err := p.read(ctx, aws.ToString(o.Key), "")
		var a attempt
		if err == nil && json.Unmarshal(b, &a) == nil && a.PackageSHA256 == s.PackageSHA256 && a.Created.After(newest.Created) {
			newest = a
		}
	}
	if newest.ArchiveKey == "" {
		return attempt{}, publication.ErrCaptureLost
	}
	return newest, nil
}

func (p *Publisher) commitKey(run publication.RunRef) string { return p.runPrefix(run) + "commit.json" }

func (p *Publisher) readManifest(ctx context.Context, run publication.RunRef) (manifest, *s3.HeadObjectOutput, error) {
	key := p.commitKey(run)
	b, err := p.read(ctx, key, "")
	if err != nil {
		return manifest{}, nil, err
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil || m.Run != run {
		return manifest{}, nil, fmt.Errorf("commit %s is not this run's publication: %w", key, publication.ErrConflict)
	}
	head, err := p.Client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(p.Dest.Bucket), Key: aws.String(key)})
	if err != nil {
		return manifest{}, nil, fmt.Errorf("%w: head commit: %v", publication.ErrUnavailable, sanitize(err))
	}
	return m, head, nil
}

// receipt derives the receipt from the stored commit: publishedAt is the
// commit object's immutable server time, and expiry uses the retention
// recorded at the first commit, never the retry's clock or retention.
func (p *Publisher) receipt(m manifest, head *s3.HeadObjectOutput, s publication.Staged) (publication.Receipt, error) {
	if m.PackageSHA256 != s.PackageSHA256 || m.DescriptorSHA256 != s.DescriptorSHA256 {
		return publication.Receipt{}, fmt.Errorf("run committed different content: %w", publication.ErrConflict)
	}
	if head.LastModified == nil {
		return publication.Receipt{}, fmt.Errorf("%w: commit has no server time", publication.ErrUnavailable)
	}
	d, err := m.Retention.ParseDuration()
	if err != nil {
		return publication.Receipt{}, err
	}
	at := head.LastModified.UTC()
	r := publication.Receipt{PublicationID: m.PublicationID,
		Destination:      publication.Destination{ID: p.Dest.ID, Endpoint: p.Dest.Endpoint, Bucket: p.Dest.Bucket, Prefix: p.Dest.Prefix},
		Commit:           publication.Commit{ManifestKey: p.commitKey(m.Run), ManifestVersionID: versionID(head.VersionId), ArchiveKey: m.ArchiveKey, ArchiveVersionID: m.ArchiveVersionID},
		DescriptorSHA256: m.DescriptorSHA256, PackageSHA256: m.PackageSHA256, PackageSize: m.PackageSize,
		PublishedAt: at, Retention: m.Retention, ExpiresAt: at.Add(d)}
	if p.Dest.CredentialSecret != nil {
		r.Destination.CredentialRef = &publication.SecretRef{Name: p.Dest.CredentialSecret.Name}
	}
	return r, r.Validate()
}

// Inspect reports publication state from storage.
func (p *Publisher) Inspect(ctx context.Context, run publication.RunRef) (publication.Status, error) {
	m, head, err := p.readManifest(ctx, run)
	if errors.Is(err, publication.ErrNotFound) {
		if _, rerr := p.Recover(ctx, run); rerr == nil {
			return publication.Status{Phase: publication.PhaseUploading, PublicationID: run.PublicationID(), Availability: publication.AvailabilityUnavailable,
				Cleanup: publication.Cleanup{State: publication.CleanupNotDue}}, nil
		}
		return publication.Status{}, publication.ErrNotFound
	}
	if err != nil {
		return publication.Status{}, err
	}
	r, err := p.receipt(m, head, publication.Staged{PackageSHA256: m.PackageSHA256, DescriptorSHA256: m.DescriptorSHA256})
	if err != nil {
		return publication.Status{}, err
	}
	st := publication.Committed(r)
	if !p.now().Before(r.ExpiresAt) {
		st.Phase, st.Availability, st.Cleanup.State = publication.PhaseExpired, publication.AvailabilityExpired, publication.CleanupPending
	}
	return st, nil
}

// Delete removes every owned object version under the run's prefix after
// expiry. Full retention reconciliation (finalizers, partial-failure states,
// locks) is add-s3-evidence-publishing group 5.
func (p *Publisher) Delete(ctx context.Context, run publication.RunRef) (publication.Cleanup, error) {
	st, err := p.Inspect(ctx, run)
	if err != nil && !errors.Is(err, publication.ErrNotFound) {
		return publication.Cleanup{}, err
	}
	if err == nil && st.Phase == publication.PhaseCommitted {
		return st.Cleanup, publication.ErrRetentionActive
	}
	now := p.now().UTC()
	problems := cleanup(ctx, p.Client, p.Dest.Bucket, p.runPrefix(run))
	// Deletion is confirmed only when no owned version or marker remains.
	if left, err := p.listVersions(ctx, p.runPrefix(run)); err != nil {
		problems = append(problems, fmt.Sprintf("verify deletion: %v", sanitize(err)))
	} else if len(left) > 0 {
		problems = append(problems, fmt.Sprintf("%d owned object versions remain", len(left)))
	}
	if len(problems) > 0 {
		msg := truncateMsg(strings.Join(problems, "; "))
		if blocked(msg) {
			return publication.Cleanup{State: publication.CleanupRetentionBlocked, LastAttempt: &now, Message: msg},
				fmt.Errorf("%w: %s", publication.ErrRetentionBlocked, problems[0])
		}
		return publication.Cleanup{State: publication.CleanupDeletionFailed, LastAttempt: &now, Message: msg},
			fmt.Errorf("%w: %s", publication.ErrUnavailable, problems[0])
	}
	return publication.Cleanup{State: publication.CleanupDeleted, LastAttempt: &now}, nil
}

// blocked recognizes refusals an administrator must resolve: object locks,
// legal holds, and missing delete permission.
func blocked(msg string) bool {
	for _, code := range []string{"AccessDenied", "ObjectLocked", "InvalidRetentionPeriod", "legal hold", "object lock", "Object is WORM protected"} {
		if strings.Contains(strings.ToLower(msg), strings.ToLower(code)) {
			return true
		}
	}
	return false
}

func truncateMsg(s string) string {
	if len(s) > publication.MaxMessageLength {
		return s[:publication.MaxMessageLength-3] + "..."
	}
	return s
}

func versionID(v *string) string {
	if s := aws.ToString(v); s != "null" {
		return s
	}
	return ""
}

func isNotFound(err error) bool {
	var api smithy.APIError
	return (errors.As(err, &api) && (api.ErrorCode() == "NoSuchKey" || api.ErrorCode() == "NotFound")) || httpStatus(err) == 404
}

func isPreconditionFailed(err error) bool {
	var api smithy.APIError
	return (errors.As(err, &api) && api.ErrorCode() == "PreconditionFailed") || httpStatus(err) == 412
}

// ValidatePackage checks a package directory before it is archived: the
// descriptor and exact file inventory (no traversal, symlinks, or extra
// files), OSCAL schemas and reference closure for assessment packages,
// engine-policy verification for controller (v2) captures, and namespace
// projection for namespace-scope packages.
func ValidatePackage(dir string) (publication.Descriptor, error) {
	d, err := publication.LoadDescriptor(dir)
	if err != nil {
		return d, err
	}
	if err := publication.VerifyDir(dir, d); err != nil {
		return d, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "capture.json"))
	hasCapture := err == nil
	v2 := false
	if hasCapture {
		ver, err := collector.CaptureVersion(raw)
		if err != nil {
			return d, err
		}
		v2 = ver == collector.CaptureV2Version
	}
	if d.PackageKind == publication.KindAssessment {
		schema := filepath.Join(dir, "content/schemas/oscal-1.1.3.json")
		for _, name := range []string{"assessment-plan", "assessment-results", "system-security-plan"} {
			if err := assessment.Schema(filepath.Join(dir, name+".json"), schema); err != nil {
				return d, fmt.Errorf("%s: %w", name, err)
			}
		}
		if err := assessment.ValidateReferences(dir); err != nil {
			return d, err
		}
		if v2 {
			if err := collector.VerifyPackage(dir); err != nil {
				return d, err
			}
		}
	}
	if d.Scope.Kind == publication.ScopeNamespace {
		if !v2 {
			return d, errors.New("a namespace package requires a projected controller capture")
		}
		var c collector.CaptureV2
		if err := json.Unmarshal(raw, &c); err != nil {
			return d, err
		}
		if err := collector.ValidateProjection(c); err != nil {
			return d, fmt.Errorf("namespace scope: %w", err)
		}
		if c.Projection.NamespaceUID != d.Scope.Request.NamespaceUID {
			return d, errors.New("namespace scope does not match the packaged projection")
		}
	}
	return d, nil
}

// Archive builds a deterministic gzip-compressed tar of a validated package
// directory: entries in path order with fixed modes, owners, and times, and
// no symlinks or special files. The same package yields the same bytes.
func Archive(dir string) ([]byte, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		if !e.Type().IsRegular() {
			return fmt.Errorf("non-regular file %s", path)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("path %s escapes the package", path)
		}
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(paths)
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zw.ModTime = time.Time{}
	tw := tar.NewWriter(zw)
	for _, rel := range paths {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return nil, err
		}
		if err := tw.WriteHeader(&tar.Header{Name: rel, Mode: 0o644, Size: int64(len(b)), ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if buf.Len() > MaxArchiveBytes {
		return nil, fmt.Errorf("package archive exceeds %d bytes", MaxArchiveBytes)
	}
	return buf.Bytes(), nil
}

// LoadCredentials reads static credentials from a Secret in the controller's
// own namespace. It is called for each client build, so rotated Secret data
// is picked up. Errors name the Secret and key but never contain values.
func LoadCredentials(ctx context.Context, r client.Reader, namespace string, ref *SecretRef) (*StaticCredentials, error) {
	if ref == nil {
		return nil, nil
	}
	sec := &corev1.Secret{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, sec); err != nil {
		return nil, fmt.Errorf("%w: secret %s/%s: %v", ErrCredentials, namespace, ref.Name, err)
	}
	idKey, secretKey := ref.AccessKeyIDKey, ref.SecretAccessKeyKey
	if idKey == "" {
		idKey = "accessKeyID"
	}
	if secretKey == "" {
		secretKey = "secretAccessKey"
	}
	id, secret := strings.TrimSpace(string(sec.Data[idKey])), strings.TrimSpace(string(sec.Data[secretKey]))
	var missing []string
	if id == "" {
		missing = append(missing, idKey)
	}
	if secret == "" {
		missing = append(missing, secretKey)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: secret %s/%s lacks %s", ErrCredentials, namespace, ref.Name, strings.Join(missing, ", "))
	}
	return &StaticCredentials{AccessKeyID: id, SecretAccessKey: secret}, nil
}
