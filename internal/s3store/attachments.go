package s3store

// S3 implementation of the supporting-evidence attachment storage contract
// (internal/attachments, add-supporting-evidence-attachments 2.1-2.4). It
// shares this package's client construction, verified writes, version
// listing and error handling with the assessment publisher, and keeps its
// own key space: <prefix>attachments/<cluster>/<attachment UID>/.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/backend-bunny/Konstapel/internal/attachments"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Attachment storage record kinds and version.
const (
	attachmentAPIVersion   = "storage.konstapel.dev/attachments/v1"
	attachmentIntentKind   = "AttachmentAttemptIntent"
	attachmentAttemptKind  = "AttachmentAttempt"
	attachmentCommitKind   = "AttachmentCommit"
	attachmentDocumentFile = "document"
	attachmentAttemptFile  = "attempt.json"
	attachmentCommitFile   = "commit.json"
	// maxAttachmentRecord bounds every JSON record read back.
	maxAttachmentRecord = 64 << 10
)

// MaxAttachmentBytes is the storage layer's absolute document ceiling, the
// API's (EvidenceAttachment spec.document.size). The transfer service
// applies its lower configured limit before staging.
const MaxAttachmentBytes = 1 << 30

// AttachmentStore stores supporting documents in one S3 destination.
type AttachmentStore struct {
	Client *s3.Client
	Dest   Destination
	// Now is the controller clock for expiry and attempt-age comparisons;
	// commitment times always come from the storage server.
	Now func() time.Time
}

var _ attachments.Store = (*AttachmentStore)(nil)

func (a *AttachmentStore) pub() *Publisher {
	return &Publisher{Client: a.Client, Dest: a.Dest, Now: a.Now}
}

func (a *AttachmentStore) now() time.Time { return a.pub().now() }

// AttachmentPrefix is the key prefix owning every object of one attachment.
func AttachmentPrefix(d Destination, ref attachments.Ref) string {
	cluster := strings.TrimPrefix(ref.ClusterID, "kube-system:")
	return d.KeyPrefix() + "attachments/" + safeSegment(cluster) + "/" + safeSegment(ref.UID) + "/"
}

func (a *AttachmentStore) prefix(ref attachments.Ref) string { return AttachmentPrefix(a.Dest, ref) }

func (a *AttachmentStore) commitKey(ref attachments.Ref) string {
	return a.prefix(ref) + attachmentCommitFile
}

// Destination identifies the store's destination.
func (a *AttachmentStore) Destination() attachments.Destination {
	return attachments.Destination{ID: a.Dest.ID, Endpoint: a.Dest.Endpoint, Bucket: a.Dest.Bucket, Prefix: a.Dest.Prefix}
}

type attachmentIntent struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Ref        attachments.Ref       `json:"ref"`
	Uploader   attachments.Principal `json:"uploader"`
	Created    time.Time             `json:"created"`
}

type attachmentAttempt struct {
	APIVersion        string                `json:"apiVersion"`
	Kind              string                `json:"kind"`
	Ref               attachments.Ref       `json:"ref"`
	DocumentKey       string                `json:"documentKey"`
	DocumentVersionID string                `json:"documentVersionID,omitempty"`
	Document          attachments.Document  `json:"document"`
	Uploader          attachments.Principal `json:"uploader"`
	Created           time.Time             `json:"created"`
}

// attachmentManifest is the commit. Its own key is not part of any
// document checksum; the document is identified by digest and version.
type attachmentManifest struct {
	APIVersion        string                `json:"apiVersion"`
	Kind              string                `json:"kind"`
	Ref               attachments.Ref       `json:"ref"`
	SpecDigest        string                `json:"specDigest"`
	DestinationID     string                `json:"destinationID"`
	DocumentKey       string                `json:"documentKey"`
	DocumentVersionID string                `json:"documentVersionID,omitempty"`
	Document          attachments.Document  `json:"document"`
	Uploader          attachments.Principal `json:"uploader"`
	ValidUntil        time.Time             `json:"validUntil"`
	Retention         string                `json:"retention"`
}

// decodeStrict decodes one record, rejecting unknown fields, trailing data,
// and another apiVersion or kind.
func decodeStrict(b []byte, kind string, into any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("%w: %v", attachments.ErrUnsupportedRecord, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing data", attachments.ErrUnsupportedRecord)
	}
	var head struct{ APIVersion, Kind string }
	_ = json.Unmarshal(b, &head)
	if head.APIVersion != attachmentAPIVersion || head.Kind != kind {
		return fmt.Errorf("%w: %s %s", attachments.ErrUnsupportedRecord, head.APIVersion, head.Kind)
	}
	return nil
}

func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, publication.ErrNotFound):
		return fmt.Errorf("%w: %v", attachments.ErrNotFound, err)
	case errors.Is(err, publication.ErrUnavailable):
		return fmt.Errorf("%w: %v", attachments.ErrUnavailable, err)
	}
	return err
}

// readRecord reads a small JSON record.
func (a *AttachmentStore) readRecord(ctx context.Context, key string) ([]byte, error) {
	in := &s3.GetObjectInput{Bucket: aws.String(a.Dest.Bucket), Key: aws.String(key)}
	got, err := a.Client.GetObject(ctx, in)
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("%s: %w", key, attachments.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: read %s: %v", attachments.ErrUnavailable, key, sanitize(err))
	}
	defer got.Body.Close()
	b, err := io.ReadAll(io.LimitReader(got.Body, maxAttachmentRecord+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", attachments.ErrUnavailable, key, err)
	}
	if len(b) > maxAttachmentRecord {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", attachments.ErrUnsupportedRecord, key, maxAttachmentRecord)
	}
	return b, nil
}

// putRecord writes a small JSON record with an explicit SHA-256 and verifies
// it, as every publisher write is verified.
func (a *AttachmentStore) putRecord(ctx context.Context, key string, v any) error {
	b, _ := json.Marshal(v)
	_, err := a.pub().putVerified(ctx, key, b)
	return mapErr(err)
}

// Stage hashes the body against the registered identity before anything is
// uploaded, records the attempt's owner, uploads the bytes with their
// SHA-256, verifies the stored version (server checksum or streamed
// read-back), and only then records the attempt. Mismatching bytes are
// never uploaded; an interrupted attempt is owned and cleanable.
func (a *AttachmentStore) Stage(ctx context.Context, req attachments.StageRequest) (attachments.Staged, error) {
	if err := req.Ref.Validate(); err != nil {
		return attachments.Staged{}, err
	}
	sum, err := req.Document.Sum()
	if err != nil {
		return attachments.Staged{}, err
	}
	if req.Document.Size > MaxAttachmentBytes {
		return attachments.Staged{}, fmt.Errorf("%w: %d bytes exceeds %d", attachments.ErrIntegrity, req.Document.Size, MaxAttachmentBytes)
	}
	if req.Uploader.Username == "" {
		return attachments.Staged{}, errors.New("an authenticated uploader is required")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(req.Body, req.Document.Size+1))
	if err != nil {
		return attachments.Staged{}, fmt.Errorf("read document: %w", err)
	}
	if n != req.Document.Size || !bytes.Equal(h.Sum(nil), sum[:]) {
		return attachments.Staged{}, fmt.Errorf("%w: received %d bytes with a different size or SHA-256", attachments.ErrIntegrity, n)
	}
	if _, err := req.Body.Seek(0, io.SeekStart); err != nil {
		return attachments.Staged{}, fmt.Errorf("rewind document: %w", err)
	}
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	attemptID := hex.EncodeToString(id)
	dir := a.prefix(req.Ref) + "attempts/" + attemptID + "/"
	if err := a.putRecord(ctx, dir+intentFile, attachmentIntent{APIVersion: attachmentAPIVersion, Kind: attachmentIntentKind,
		Ref: req.Ref, Uploader: req.Uploader, Created: a.now().UTC()}); err != nil {
		return attachments.Staged{}, err
	}
	key := dir + attachmentDocumentFile
	put, err := a.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(a.Dest.Bucket), Key: aws.String(key), Body: req.Body,
		ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sum[:])), ContentLength: aws.Int64(req.Document.Size),
		ContentType: aws.String("application/octet-stream")})
	if err != nil {
		return attachments.Staged{}, fmt.Errorf("%w: upload document: %v", attachments.ErrUnavailable, sanitize(err))
	}
	vid := versionID(put.VersionId)
	if p, err := a.check(ctx, key, vid, req.Document, true); err != nil {
		return attachments.Staged{}, err
	} else if p != nil {
		return attachments.Staged{}, fmt.Errorf("%w: stored document: %s", attachments.ErrIntegrity, p.Message)
	}
	if err := a.putRecord(ctx, dir+attachmentAttemptFile, attachmentAttempt{APIVersion: attachmentAPIVersion, Kind: attachmentAttemptKind,
		Ref: req.Ref, DocumentKey: key, DocumentVersionID: vid, Document: req.Document, Uploader: req.Uploader, Created: a.now().UTC()}); err != nil {
		return attachments.Staged{}, err
	}
	return attachments.Staged{Ref: req.Ref, AttemptID: attemptID, Document: req.Document, Uploader: req.Uploader}, nil
}

// check verifies one stored document version: present, of the registered
// size, and with the registered SHA-256 from the server checksum or, when
// the server returns none and readBack is set, a streamed read-back. A nil
// problem with a nil error means intact.
func (a *AttachmentStore) check(ctx context.Context, key, vid string, doc attachments.Document, readBack bool) (*attachments.Problem, error) {
	sum, err := doc.Sum()
	if err != nil {
		return nil, err
	}
	in := &s3.HeadObjectInput{Bucket: aws.String(a.Dest.Bucket), Key: aws.String(key), ChecksumMode: types.ChecksumModeEnabled}
	if vid != "" {
		in.VersionId = aws.String(vid)
	}
	head, err := a.Client.HeadObject(ctx, in)
	if err != nil {
		if isNotFound(err) {
			return &attachments.Problem{Reason: attachments.ProblemMissing, Message: "the document version is missing"}, nil
		}
		return nil, fmt.Errorf("%w: inspect document: %v", attachments.ErrUnavailable, sanitize(err))
	}
	if aws.ToInt64(head.ContentLength) != doc.Size {
		return &attachments.Problem{Reason: attachments.ProblemIntegrity, Message: "the stored document has a different size"}, nil
	}
	if c := aws.ToString(head.ChecksumSHA256); c != "" {
		if c != base64.StdEncoding.EncodeToString(sum[:]) {
			return &attachments.Problem{Reason: attachments.ProblemIntegrity, Message: "the stored document has a different SHA-256"}, nil
		}
		return nil, nil
	}
	if !readBack {
		return nil, nil
	}
	get := &s3.GetObjectInput{Bucket: aws.String(a.Dest.Bucket), Key: aws.String(key)}
	if vid != "" {
		get.VersionId = aws.String(vid)
	}
	out, err := a.Client.GetObject(ctx, get)
	if err != nil {
		if isNotFound(err) {
			return &attachments.Problem{Reason: attachments.ProblemMissing, Message: "the document version is missing"}, nil
		}
		return nil, fmt.Errorf("%w: read back document: %v", attachments.ErrUnavailable, sanitize(err))
	}
	defer out.Body.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(out.Body, doc.Size+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read back document: %v", attachments.ErrUnavailable, err)
	}
	if n != doc.Size || !bytes.Equal(h.Sum(nil), sum[:]) {
		return &attachments.Problem{Reason: attachments.ProblemIntegrity, Message: "the stored document reads back with different bytes"}, nil
	}
	return nil, nil
}

// attempts lists the attachment's recorded attempts (attempt.json present
// and naming this attachment), newest first.
func (a *AttachmentStore) attempts(ctx context.Context, ref attachments.Ref) ([]attachmentAttempt, error) {
	objs, err := a.pub().listCurrent(ctx, a.prefix(ref)+"attempts/")
	if err != nil {
		return nil, fmt.Errorf("%w: list attempts: %v", attachments.ErrUnavailable, sanitize(err))
	}
	var out []attachmentAttempt
	for _, o := range objs {
		if path.Base(o.key) != attachmentAttemptFile {
			continue
		}
		b, err := a.readRecord(ctx, o.key)
		if err != nil {
			if errors.Is(err, attachments.ErrNotFound) {
				continue
			}
			return nil, err
		}
		var at attachmentAttempt
		if decodeStrict(b, attachmentAttemptKind, &at) != nil || at.Ref != ref || path.Dir(at.DocumentKey)+"/" != path.Dir(o.key)+"/" {
			continue // not this attachment's record: never trusted
		}
		out = append(out, at)
	}
	slices.SortFunc(out, func(x, y attachmentAttempt) int { return y.Created.Compare(x.Created) })
	return out, nil
}

// Commit implements attachments.Store.
func (a *AttachmentStore) Commit(ctx context.Context, req attachments.CommitRequest) (attachments.Receipt, error) {
	if err := req.Ref.Validate(); err != nil {
		return attachments.Receipt{}, err
	}
	if r, err := a.Committed(ctx, req.Ref); err == nil {
		return r, sameCommitment(r, req)
	} else if !errors.Is(err, attachments.ErrNotFound) {
		return attachments.Receipt{}, err
	}
	if _, err := req.Document.Sum(); err != nil {
		return attachments.Receipt{}, err
	}
	if err := attachments.ValidateRetention(req.Retention); err != nil {
		return attachments.Receipt{}, err
	}
	if req.ValidUntil.IsZero() || !strings.HasPrefix(req.SpecDigest, "sha256:") || len(req.SpecDigest) != len("sha256:")+64 {
		return attachments.Receipt{}, errors.New("a spec digest and validUntil are required to commit")
	}
	list, err := a.attempts(ctx, req.Ref)
	if err != nil {
		return attachments.Receipt{}, err
	}
	var chosen *attachmentAttempt
	for i := range list {
		at := &list[i]
		if at.Document != req.Document {
			continue
		}
		p, err := a.check(ctx, at.DocumentKey, at.DocumentVersionID, at.Document, true)
		if err != nil {
			return attachments.Receipt{}, err
		}
		if p == nil {
			chosen = at
			break
		}
	}
	if chosen == nil {
		return attachments.Receipt{}, fmt.Errorf("%w: no verified upload holds %s", attachments.ErrNotFound, req.Document.SHA256)
	}
	m := attachmentManifest{APIVersion: attachmentAPIVersion, Kind: attachmentCommitKind, Ref: req.Ref, SpecDigest: req.SpecDigest,
		DestinationID: a.Dest.ID, DocumentKey: chosen.DocumentKey, DocumentVersionID: chosen.DocumentVersionID, Document: chosen.Document,
		Uploader: chosen.Uploader, ValidUntil: req.ValidUntil.UTC(), Retention: req.Retention.String()}
	body, _ := json.Marshal(m)
	sum := sha256.Sum256(body)
	_, err = a.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(a.Dest.Bucket), Key: aws.String(a.commitKey(req.Ref)), Body: bytes.NewReader(body),
		ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sum[:])), ContentLength: aws.Int64(int64(len(body))), IfNoneMatch: aws.String("*")})
	// Whether this writer won, lost a race, or lost the response, the
	// stored commitment decides.
	r, rerr := a.Committed(ctx, req.Ref)
	if rerr != nil {
		if err != nil && !isPreconditionFailed(err) {
			return attachments.Receipt{}, fmt.Errorf("%w: commit: %v", attachments.ErrUnavailable, sanitize(err))
		}
		return attachments.Receipt{}, rerr
	}
	return r, sameCommitment(r, req)
}

// sameCommitment rejects a request for other content than the commitment.
// Retention and validity of a retry are ignored: the first commitment's
// values are fixed.
func sameCommitment(r attachments.Receipt, req attachments.CommitRequest) error {
	if r.Document != req.Document || r.SpecDigest != req.SpecDigest {
		return fmt.Errorf("%w: the attachment committed %s (spec %s), not %s (spec %s)", attachments.ErrConflict,
			r.Document.SHA256, r.SpecDigest, req.Document.SHA256, req.SpecDigest)
	}
	return nil
}

// Committed implements attachments.Store.
func (a *AttachmentStore) Committed(ctx context.Context, ref attachments.Ref) (attachments.Receipt, error) {
	if err := ref.Validate(); err != nil {
		return attachments.Receipt{}, err
	}
	key := a.commitKey(ref)
	b, err := a.readRecord(ctx, key)
	if err != nil {
		return attachments.Receipt{}, err
	}
	var m attachmentManifest
	if err := decodeStrict(b, attachmentCommitKind, &m); err != nil {
		return attachments.Receipt{}, fmt.Errorf("commit %s: %w", key, err)
	}
	if m.Ref != ref {
		return attachments.Receipt{}, fmt.Errorf("%w: commit %s names another attachment", attachments.ErrConflict, key)
	}
	if m.DestinationID != a.Dest.ID {
		return attachments.Receipt{}, fmt.Errorf("%w: commit %s was made for destination %q, not %q", attachments.ErrConflict, key, m.DestinationID, a.Dest.ID)
	}
	if !strings.HasPrefix(m.DocumentKey, a.prefix(ref)+"attempts/") {
		return attachments.Receipt{}, fmt.Errorf("%w: commit %s points outside the attachment's prefix", attachments.ErrConflict, key)
	}
	retention, err := time.ParseDuration(m.Retention)
	if err != nil {
		return attachments.Receipt{}, fmt.Errorf("%w: retention %q", attachments.ErrUnsupportedRecord, m.Retention)
	}
	head, err := a.Client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(a.Dest.Bucket), Key: aws.String(key)})
	if err != nil {
		return attachments.Receipt{}, fmt.Errorf("%w: head commit: %v", attachments.ErrUnavailable, sanitize(err))
	}
	if head.LastModified == nil {
		return attachments.Receipt{}, fmt.Errorf("%w: commit has no server time", attachments.ErrUnavailable)
	}
	at := head.LastModified.UTC()
	r := attachments.Receipt{Ref: ref, Destination: a.Destination(), ManifestKey: key, ManifestVersionID: versionID(head.VersionId),
		DocumentKey: m.DocumentKey, DocumentVersionID: m.DocumentVersionID, Document: m.Document, SpecDigest: m.SpecDigest,
		Uploader: m.Uploader, CommittedAt: at, ValidUntil: m.ValidUntil.UTC(), Retention: retention,
		ExpiresAt: attachments.ExpiresAt(at, m.ValidUntil, retention)}
	if err := r.Validate(); err != nil {
		return attachments.Receipt{}, fmt.Errorf("%w: commit %s: %v", attachments.ErrUnsupportedRecord, key, err)
	}
	return r, nil
}

// Open implements attachments.Store.
func (a *AttachmentStore) Open(ctx context.Context, r attachments.Receipt) (io.ReadCloser, error) {
	if !a.now().Before(r.ExpiresAt) {
		return nil, fmt.Errorf("%w: the source document expired at %s", attachments.ErrNotFound, r.ExpiresAt.Format(time.RFC3339))
	}
	in := &s3.GetObjectInput{Bucket: aws.String(a.Dest.Bucket), Key: aws.String(r.DocumentKey)}
	if r.DocumentVersionID != "" {
		in.VersionId = aws.String(r.DocumentVersionID)
	}
	out, err := a.Client.GetObject(ctx, in)
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("%w: the committed document is missing before its expiry", attachments.ErrUnavailable)
		}
		return nil, fmt.Errorf("%w: read document: %v", attachments.ErrUnavailable, sanitize(err))
	}
	return out.Body, nil
}

// Health implements attachments.Store. It reads metadata only.
func (a *AttachmentStore) Health(ctx context.Context, r attachments.Receipt) (*attachments.Problem, error) {
	return a.check(ctx, r.DocumentKey, r.DocumentVersionID, r.Document, false)
}

// ownedAttempt reports whether an attempt directory's intent or attempt
// record names ref, and when the attempt was created.
func (a *AttachmentStore) ownedAttempt(ctx context.Context, dir string, ref attachments.Ref) (bool, time.Time, error) {
	for _, f := range []struct{ name, kind string }{{intentFile, attachmentIntentKind}, {attachmentAttemptFile, attachmentAttemptKind}} {
		b, err := a.readRecord(ctx, dir+f.name)
		if errors.Is(err, attachments.ErrNotFound) {
			continue
		}
		if err != nil {
			return false, time.Time{}, err
		}
		var rec struct {
			APIVersion string          `json:"apiVersion"`
			Kind       string          `json:"kind"`
			Ref        attachments.Ref `json:"ref"`
			Created    time.Time       `json:"created"`
		}
		if json.Unmarshal(b, &rec) == nil && rec.APIVersion == attachmentAPIVersion && rec.Kind == f.kind && rec.Ref == ref {
			return true, rec.Created, nil
		}
	}
	return false, time.Time{}, nil
}

// attemptDirs groups every object version under the attachment's attempts
// prefix by attempt directory. Objects not inside a directory are unowned.
func (a *AttachmentStore) attemptDirs(ctx context.Context, ref attachments.Ref) (map[string][]objectVersion, error) {
	prefix := a.prefix(ref) + "attempts/"
	objects, err := a.listRaw(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("%w: list attempts: %v", attachments.ErrUnavailable, sanitize(err))
	}
	dirs := map[string][]objectVersion{}
	for _, o := range objects {
		rest := strings.TrimPrefix(o.key, prefix)
		i := strings.Index(rest, "/")
		if i <= 0 {
			continue
		}
		dirs[prefix+rest[:i+1]] = append(dirs[prefix+rest[:i+1]], o)
	}
	return dirs, nil
}

// listRaw lists every object version and delete marker under prefix with
// its raw version ID ("null" kept, so a suspended bucket's null version is
// deleted permanently rather than hidden behind a new marker), or the
// current objects on services without version listing.
func (a *AttachmentStore) listRaw(ctx context.Context, prefix string) ([]objectVersion, error) {
	var out []objectVersion
	in := &s3.ListObjectVersionsInput{Bucket: aws.String(a.Dest.Bucket), Prefix: aws.String(prefix)}
	for {
		page, err := a.Client.ListObjectVersions(ctx, in)
		if err != nil {
			if len(out) > 0 {
				return nil, err
			}
			return a.pub().listCurrent(ctx, prefix)
		}
		for _, v := range page.Versions {
			out = append(out, objectVersion{aws.ToString(v.Key), aws.ToString(v.VersionId)})
		}
		for _, m := range page.DeleteMarkers {
			out = append(out, objectVersion{aws.ToString(m.Key), aws.ToString(m.VersionId)})
		}
		if !aws.ToBool(page.IsTruncated) {
			return out, nil
		}
		in.KeyMarker, in.VersionIdMarker = page.NextKeyMarker, page.NextVersionIdMarker
	}
}

func (a *AttachmentStore) deleteVersions(ctx context.Context, versions []objectVersion) []string {
	var problems []string
	for _, v := range versions {
		in := &s3.DeleteObjectInput{Bucket: aws.String(a.Dest.Bucket), Key: aws.String(v.key)}
		if v.version != "" {
			in.VersionId = aws.String(v.version)
		}
		if _, err := a.Client.DeleteObject(ctx, in); err != nil && !isNotFound(err) {
			problems = append(problems, fmt.Sprintf("delete %s: %v", v.key, sanitize(err)))
		}
	}
	return problems
}

// abortUploads aborts incomplete multipart uploads under the attachment's
// prefix initiated before olderThan (zero: all).
func (a *AttachmentStore) abortUploads(ctx context.Context, ref attachments.Ref, olderThan time.Time) []string {
	var problems []string
	in := &s3.ListMultipartUploadsInput{Bucket: aws.String(a.Dest.Bucket), Prefix: aws.String(a.prefix(ref))}
	for {
		page, err := a.Client.ListMultipartUploads(ctx, in)
		if err != nil {
			return append(problems, fmt.Sprintf("list multipart uploads: %v", sanitize(err)))
		}
		for _, u := range page.Uploads {
			if !olderThan.IsZero() && u.Initiated != nil && !u.Initiated.Before(olderThan) {
				continue
			}
			if _, err := a.Client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: aws.String(a.Dest.Bucket), Key: u.Key, UploadId: u.UploadId}); err != nil && !isNotFound(err) {
				problems = append(problems, fmt.Sprintf("abort upload of %s: %v", aws.ToString(u.Key), sanitize(err)))
			}
		}
		if !aws.ToBool(page.IsTruncated) {
			return problems
		}
		in.KeyMarker, in.UploadIdMarker = page.NextKeyMarker, page.NextUploadIdMarker
	}
}

// CleanupAttempts implements attachments.Store.
func (a *AttachmentStore) CleanupAttempts(ctx context.Context, ref attachments.Ref, olderThan time.Time) error {
	if err := ref.Validate(); err != nil {
		return err
	}
	keep := ""
	if r, err := a.Committed(ctx, ref); err == nil {
		keep = path.Dir(r.DocumentKey) + "/"
	} else if !errors.Is(err, attachments.ErrNotFound) {
		return err
	}
	dirs, err := a.attemptDirs(ctx, ref)
	if err != nil {
		return err
	}
	var problems []string
	for dir, versions := range dirs {
		if dir == keep {
			continue
		}
		owned, created, err := a.ownedAttempt(ctx, dir, ref)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if !owned || !created.Before(olderThan) {
			continue
		}
		problems = append(problems, a.deleteVersions(ctx, versions)...)
	}
	problems = append(problems, a.abortUploads(ctx, ref, olderThan)...)
	if len(problems) > 0 {
		return fmt.Errorf("%w: attempt cleanup: %s", attachments.ErrUnavailable, truncateMsg(strings.Join(problems, "; ")))
	}
	return nil
}

// DeleteUncommitted implements attachments.Store.
func (a *AttachmentStore) DeleteUncommitted(ctx context.Context, ref attachments.Ref) (attachments.Cleanup, error) {
	if err := ref.Validate(); err != nil {
		return attachments.Cleanup{}, err
	}
	if _, err := a.Committed(ctx, ref); err == nil {
		return attachments.Cleanup{}, fmt.Errorf("%w: the attachment has a commitment", attachments.ErrConflict)
	} else if !errors.Is(err, attachments.ErrNotFound) {
		return attachments.Cleanup{}, err
	}
	dirs, err := a.attemptDirs(ctx, ref)
	if err != nil {
		return attachments.Cleanup{}, err
	}
	var problems []string
	remaining := 0
	for dir, versions := range dirs {
		owned, _, err := a.ownedAttempt(ctx, dir, ref)
		switch {
		case err != nil:
			problems = append(problems, err.Error())
		case owned:
			problems = append(problems, a.deleteVersions(ctx, versions)...)
		}
	}
	problems = append(problems, a.abortUploads(ctx, ref, time.Time{})...)
	if left, err := a.attemptDirs(ctx, ref); err == nil {
		for dir := range left {
			if owned, _, _ := a.ownedAttempt(ctx, dir, ref); owned {
				remaining++
			}
		}
	}
	if remaining > 0 && len(problems) == 0 {
		problems = append(problems, fmt.Sprintf("%d owned attempts remain", remaining))
	}
	return a.cleanupResult(problems)
}

// Delete implements attachments.Store.
func (a *AttachmentStore) Delete(ctx context.Context, r attachments.Receipt, now time.Time) (attachments.Cleanup, error) {
	if now.Before(r.ExpiresAt) {
		return attachments.Cleanup{}, fmt.Errorf("%w until %s", attachments.ErrRetentionActive, r.ExpiresAt.Format(time.RFC3339))
	}
	if err := r.Ref.Validate(); err != nil {
		return attachments.Cleanup{}, err
	}
	// Only the attachment's own attempts and its commit are removed; any
	// other object that happens to share the prefix is left in place.
	dirs, err := a.attemptDirs(ctx, r.Ref)
	if err != nil {
		return attachments.Cleanup{}, err
	}
	var problems []string
	for dir, versions := range dirs {
		owned, _, err := a.ownedAttempt(ctx, dir, r.Ref)
		switch {
		case err != nil:
			problems = append(problems, err.Error())
		case owned || dir == path.Dir(r.DocumentKey)+"/":
			problems = append(problems, a.deleteVersions(ctx, versions)...)
		}
	}
	problems = append(problems, a.abortUploads(ctx, r.Ref, time.Time{})...)
	commits, err := a.listRaw(ctx, r.ManifestKey)
	if err != nil {
		problems = append(problems, fmt.Sprintf("list commit versions: %v", sanitize(err)))
	}
	var own []objectVersion
	for _, v := range commits {
		if v.key == r.ManifestKey {
			own = append(own, v)
		}
	}
	// The commit goes last, so an interrupted deletion still finds it.
	if len(problems) == 0 {
		problems = append(problems, a.deleteVersions(ctx, own)...)
	}
	if len(problems) == 0 {
		if left, err := a.listRaw(ctx, r.ManifestKey); err != nil {
			problems = append(problems, fmt.Sprintf("verify deletion: %v", sanitize(err)))
		} else {
			for _, v := range left {
				if v.key == r.ManifestKey {
					problems = append(problems, "the commit manifest remains")
					break
				}
			}
		}
		if dirs, err := a.attemptDirs(ctx, r.Ref); err != nil {
			problems = append(problems, err.Error())
		} else if _, ok := dirs[path.Dir(r.DocumentKey)+"/"]; ok {
			problems = append(problems, "the committed document versions remain")
		}
	}
	return a.cleanupResult(problems)
}

func (a *AttachmentStore) cleanupResult(problems []string) (attachments.Cleanup, error) {
	if len(problems) == 0 {
		return attachments.Cleanup{State: attachments.CleanupDeleted}, nil
	}
	msg := truncateMsg(strings.Join(problems, "; "))
	if blocked(msg) {
		return attachments.Cleanup{State: attachments.CleanupRetentionBlocked, Message: msg}, fmt.Errorf("%w: %s", attachments.ErrRetentionBlocked, problems[0])
	}
	return attachments.Cleanup{State: attachments.CleanupDeletionFailed, Message: msg}, fmt.Errorf("%w: %s", attachments.ErrUnavailable, problems[0])
}
