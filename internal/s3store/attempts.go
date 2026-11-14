package s3store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/backend-bunny/Konstapel/internal/publication"
)

// intentFile is written in an attempt directory before any upload. It records
// the owning run, so an interrupted attempt is always identifiable.
const intentFile = "intent.json"

type attemptIntent struct {
	Run     publication.RunRef `json:"run"`
	Created time.Time          `json:"created"`
}

type objectVersion struct{ key, version string }

// CleanupAttempts removes the run's uncommitted attempts once the run is
// terminal. Only attempt directories under the run's own prefix whose
// intent.json or attempt.json names this run are removed, every version and
// delete marker included; the committed archive's attempt and the commit are
// kept. Incomplete multipart uploads under the run prefix are aborted.
func (p *Publisher) CleanupAttempts(ctx context.Context, run publication.RunRef) error {
	keep := ""
	if m, _, err := p.readManifest(ctx, run); err == nil {
		keep = path.Dir(m.ArchiveKey) + "/"
	} else if !errors.Is(err, publication.ErrNotFound) {
		return err
	}
	prefix := p.runPrefix(run) + "attempts/"
	objects, err := p.listVersions(ctx, prefix)
	if err != nil {
		return fmt.Errorf("%w: list attempts: %v", publication.ErrUnavailable, sanitize(err))
	}
	dirs := map[string][]objectVersion{}
	for _, o := range objects {
		rest := strings.TrimPrefix(o.key, prefix)
		i := strings.Index(rest, "/")
		if i <= 0 {
			continue // not inside an attempt directory: ownership unknown
		}
		dir := prefix + rest[:i+1]
		dirs[dir] = append(dirs[dir], o)
	}
	var problems []string
	for dir, versions := range dirs {
		if dir == keep || !p.ownsAttempt(ctx, dir, run) {
			continue
		}
		for _, v := range versions {
			in := &s3.DeleteObjectInput{Bucket: aws.String(p.Dest.Bucket), Key: aws.String(v.key)}
			if v.version != "" {
				in.VersionId = aws.String(v.version)
			}
			if _, err := p.Client.DeleteObject(ctx, in); err != nil && !isNotFound(err) {
				problems = append(problems, fmt.Sprintf("delete %s: %v", v.key, sanitize(err)))
			}
		}
	}
	// Without a commit the run's signature object (and every version of
	// it) is an abandoned signing attempt owned by this run: remove it. A
	// committed signature is kept with its archive until retention.
	if keep == "" {
		sig := p.signatureKey(run)
		versions, err := p.listVersions(ctx, sig)
		if err != nil {
			problems = append(problems, fmt.Sprintf("list signature versions: %v", sanitize(err)))
		}
		for _, v := range versions {
			if v.key != sig {
				continue // another key that merely shares the prefix
			}
			in := &s3.DeleteObjectInput{Bucket: aws.String(p.Dest.Bucket), Key: aws.String(v.key)}
			if v.version != "" {
				in.VersionId = aws.String(v.version)
			}
			if _, err := p.Client.DeleteObject(ctx, in); err != nil && !isNotFound(err) {
				problems = append(problems, fmt.Sprintf("delete %s: %v", v.key, sanitize(err)))
			}
		}
	}
	uploads, err := p.Client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: aws.String(p.Dest.Bucket), Prefix: aws.String(p.runPrefix(run))})
	if err != nil {
		problems = append(problems, fmt.Sprintf("list multipart uploads: %v", sanitize(err)))
	} else {
		for _, u := range uploads.Uploads {
			if _, err := p.Client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: aws.String(p.Dest.Bucket), Key: u.Key, UploadId: u.UploadId}); err != nil && !isNotFound(err) {
				problems = append(problems, fmt.Sprintf("abort upload of %s: %v", aws.ToString(u.Key), sanitize(err)))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: attempt cleanup: %s", publication.ErrUnavailable, truncateMsg(strings.Join(problems, "; ")))
	}
	return nil
}

// ownsAttempt reports whether the attempt directory's intent or attempt
// record names run. Without either, ownership cannot be established.
func (p *Publisher) ownsAttempt(ctx context.Context, dir string, run publication.RunRef) bool {
	for _, name := range []string{intentFile, "attempt.json"} {
		b, err := p.read(ctx, dir+name, "")
		if err != nil {
			continue
		}
		var rec struct {
			Run publication.RunRef `json:"run"`
		}
		if json.Unmarshal(b, &rec) == nil && rec.Run == run {
			return true
		}
	}
	return false
}

// listVersions lists every object version and delete marker under prefix,
// or the current objects on services without version listing.
func (p *Publisher) listVersions(ctx context.Context, prefix string) ([]objectVersion, error) {
	var out []objectVersion
	in := &s3.ListObjectVersionsInput{Bucket: aws.String(p.Dest.Bucket), Prefix: aws.String(prefix)}
	for {
		page, err := p.Client.ListObjectVersions(ctx, in)
		if err != nil {
			if len(out) > 0 {
				return nil, err
			}
			return p.listCurrent(ctx, prefix)
		}
		for _, v := range page.Versions {
			out = append(out, objectVersion{aws.ToString(v.Key), versionID(v.VersionId)})
		}
		for _, m := range page.DeleteMarkers {
			out = append(out, objectVersion{aws.ToString(m.Key), versionID(m.VersionId)})
		}
		if !aws.ToBool(page.IsTruncated) {
			return out, nil
		}
		in.KeyMarker, in.VersionIdMarker = page.NextKeyMarker, page.NextVersionIdMarker
	}
}

func (p *Publisher) listCurrent(ctx context.Context, prefix string) ([]objectVersion, error) {
	var out []objectVersion
	in := &s3.ListObjectsV2Input{Bucket: aws.String(p.Dest.Bucket), Prefix: aws.String(prefix)}
	for {
		page, err := p.Client.ListObjectsV2(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, o := range page.Contents {
			out = append(out, objectVersion{key: aws.ToString(o.Key)})
		}
		if !aws.ToBool(page.IsTruncated) {
			return out, nil
		}
		in.ContinuationToken = page.NextContinuationToken
	}
}

// Open returns the committed archive for a verified download. The status is
// the committed receipt; the caller checks size and SHA-256 before serving.
func (p *Publisher) Open(ctx context.Context, run publication.RunRef) (io.ReadCloser, publication.Status, error) {
	st, err := p.Inspect(ctx, run)
	if err != nil {
		return nil, publication.Status{}, err
	}
	switch st.Phase {
	case publication.PhaseCommitted:
	case publication.PhaseExpired:
		return nil, st, publication.ErrExpired
	default:
		return nil, publication.Status{}, publication.ErrNotFound
	}
	in := &s3.GetObjectInput{Bucket: aws.String(p.Dest.Bucket), Key: aws.String(st.Commit.ArchiveKey)}
	if st.Commit.ArchiveVersionID != "" {
		in.VersionId = aws.String(st.Commit.ArchiveVersionID)
	}
	out, err := p.Client.GetObject(ctx, in)
	if err != nil {
		if isNotFound(err) {
			return nil, st, fmt.Errorf("%w: committed archive is missing before expiry", publication.ErrUnavailable)
		}
		return nil, st, fmt.Errorf("%w: read archive: %v", publication.ErrUnavailable, sanitize(err))
	}
	return out.Body, st, nil
}
