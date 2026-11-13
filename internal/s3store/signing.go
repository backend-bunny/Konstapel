package s3store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Durable record kinds (design section 4a). An unsigned commit keeps the
// original PublicationCommit document byte for byte. A signed commit is a
// SignedPublicationCommit whose run identity is under subject, so readers
// that predate signing (which require a top-level run) reject it as another
// run's record instead of reading it as unsigned.
const (
	kindCommit       = "PublicationCommit"
	kindSignedCommit = "SignedPublicationCommit"
	// signatureFormat names the only supported signature bundle format.
	signatureFormat = "sigstore-bundle-v0.3"
)

var sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// signatureKey is the run's single signature object, created once.
func (p *Publisher) signatureKey(run publication.RunRef) string {
	return p.runPrefix(run) + evidencesign.BundleFileName
}

// commitSubject is what a signed commit selects.
type commitSubject struct {
	Run              publication.RunRef `json:"run"`
	DescriptorSHA256 string             `json:"descriptorSha256"`
	ArchiveKey       string             `json:"archiveKey"`
	ArchiveVersionID string             `json:"archiveVersionID,omitempty"`
	PackageSHA256    string             `json:"packageSha256"`
	PackageSize      int64              `json:"packageSize"`
}

// commitSignature is the signature a signed commit references.
type commitSignature struct {
	Format         string `json:"format"`
	MediaType      string `json:"mediaType"`
	Key            string `json:"key"`
	VersionID      string `json:"versionID,omitempty"`
	SHA256         string `json:"sha256"`
	Size           int64  `json:"size"`
	Algorithm      string `json:"algorithm"`
	KeyFingerprint string `json:"keyFingerprint"`
	PublicKey      string `json:"publicKey"`
}

// signedManifest is the SignedPublicationCommit document.
type signedManifest struct {
	APIVersion    string                `json:"apiVersion"`
	Kind          string                `json:"kind"`
	PublicationID string                `json:"publicationID"`
	Subject       commitSubject         `json:"subject"`
	Retention     publication.Retention `json:"retention"`
	Signature     commitSignature       `json:"signature"`
}

func (s commitSignature) ref() *publication.Signature {
	return &publication.Signature{Key: s.Key, VersionID: s.VersionID, SHA256: s.SHA256, Size: s.Size, MediaType: s.MediaType, Algorithm: s.Algorithm, KeyFingerprint: s.KeyFingerprint}
}

// decodeCommit reads either commit kind strictly. Unknown kinds, versions,
// fields, and signature formats are ErrUnsupportedRecord, never unsigned.
func decodeCommit(b []byte) (manifest, *commitSignature, error) {
	var head struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return manifest{}, nil, fmt.Errorf("%w: commit is not JSON", publication.ErrUnsupportedRecord)
	}
	if head.APIVersion != publication.APIVersion {
		return manifest{}, nil, fmt.Errorf("%w: commit apiVersion %.64q", publication.ErrUnsupportedRecord, head.APIVersion)
	}
	strict := func(v any) error {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			return fmt.Errorf("%w: %s: %v", publication.ErrUnsupportedRecord, head.Kind, err)
		}
		if _, err := dec.Token(); err != io.EOF {
			return fmt.Errorf("%w: %s has trailing data", publication.ErrUnsupportedRecord, head.Kind)
		}
		return nil
	}
	switch head.Kind {
	case kindCommit:
		var m manifest
		if err := strict(&m); err != nil {
			return manifest{}, nil, err
		}
		return m, nil, nil
	case kindSignedCommit:
		var sm signedManifest
		if err := strict(&sm); err != nil {
			return manifest{}, nil, err
		}
		g := sm.Signature
		if g.Format != signatureFormat || g.MediaType != evidencesign.BundleMediaType || g.Algorithm != evidencesign.Algorithm {
			return manifest{}, nil, fmt.Errorf("%w: signature format %.64q, media type %.80q, algorithm %.64q", publication.ErrUnsupportedRecord, g.Format, g.MediaType, g.Algorithm)
		}
		if g.Key == "" || !sha256HexRe.MatchString(g.SHA256) || g.Size <= 0 || g.KeyFingerprint == "" || g.PublicKey == "" {
			return manifest{}, nil, fmt.Errorf("%w: signed commit has an incomplete signature reference", publication.ErrUnsupportedRecord)
		}
		pub, err := evidencesign.ParsePublicKey([]byte(g.PublicKey))
		if err != nil || pub.Fingerprint != g.KeyFingerprint {
			return manifest{}, nil, fmt.Errorf("%w: signed commit's public key does not match its fingerprint", publication.ErrUnsupportedRecord)
		}
		sub := sm.Subject
		return manifest{APIVersion: sm.APIVersion, Kind: sm.Kind, PublicationID: sm.PublicationID, Run: sub.Run, DescriptorSHA256: sub.DescriptorSHA256,
			ArchiveKey: sub.ArchiveKey, ArchiveVersionID: sub.ArchiveVersionID, PackageSHA256: sub.PackageSHA256, PackageSize: sub.PackageSize, Retention: sm.Retention}, &g, nil
	default:
		return manifest{}, nil, fmt.Errorf("%w: commit kind %.64q", publication.ErrUnsupportedRecord, head.Kind)
	}
}

// StoreSignature implements publication.Publisher. The bundle is created
// once with If-None-Match: *; an existing bundle wins and is returned.
func (p *Publisher) StoreSignature(ctx context.Context, run publication.RunRef, bundle []byte) ([]byte, publication.Signature, error) {
	if len(bundle) == 0 || len(bundle) > evidencesign.MaxBundleBytes {
		return nil, publication.Signature{}, fmt.Errorf("signature bundle is %d bytes; it must be 1 to %d", len(bundle), evidencesign.MaxBundleBytes)
	}
	key := p.signatureKey(run)
	sum := sha256.Sum256(bundle)
	_, err := p.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(p.Dest.Bucket), Key: aws.String(key), Body: bytes.NewReader(bundle),
		ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sum[:])), ContentLength: aws.Int64(int64(len(bundle))), IfNoneMatch: aws.String("*"),
		ContentType: aws.String("application/json")})
	if err != nil && !isPreconditionFailed(err) {
		return nil, publication.Signature{}, fmt.Errorf("%w: store signature: %v", publication.ErrUnavailable, sanitize(err))
	}
	// Whether this attempt won or another did, the stored bundle decides.
	return p.ReadSignature(ctx, run)
}

// ReadSignature implements publication.Publisher.
func (p *Publisher) ReadSignature(ctx context.Context, run publication.RunRef) ([]byte, publication.Signature, error) {
	key := p.signatureKey(run)
	head, err := p.Client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(p.Dest.Bucket), Key: aws.String(key)})
	if err != nil {
		if isNotFound(err) {
			return nil, publication.Signature{}, fmt.Errorf("%s: %w", key, publication.ErrNotFound)
		}
		return nil, publication.Signature{}, fmt.Errorf("%w: head signature: %v", publication.ErrUnavailable, sanitize(err))
	}
	if aws.ToInt64(head.ContentLength) > evidencesign.MaxBundleBytes {
		return nil, publication.Signature{}, fmt.Errorf("%w: stored signature exceeds %d bytes", publication.ErrUnsupportedRecord, evidencesign.MaxBundleBytes)
	}
	vid := versionID(head.VersionId)
	b, err := p.read(ctx, key, vid)
	if err != nil {
		return nil, publication.Signature{}, err
	}
	sum := sha256.Sum256(b)
	if err := p.verify(ctx, key, vid, sum); err != nil {
		return nil, publication.Signature{}, err
	}
	return b, publication.Signature{Key: key, VersionID: vid, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(b)), MediaType: evidencesign.BundleMediaType}, nil
}

// requireSignature is the commit gate for a Required intent: the stored
// signature must verify for the staged archive under the pinned key.
func (p *Publisher) requireSignature(ctx context.Context, s publication.Staged, sg *publication.Signing) (commitSignature, error) {
	pub, err := evidencesign.ParsePublicKey(sg.PublicKeyPEM)
	if err != nil || pub.Fingerprint != sg.KeyFingerprint {
		return commitSignature{}, fmt.Errorf("%w: the intent's public key does not match its fingerprint", publication.ErrSignatureRequired)
	}
	digest, err := evidencesign.ParseArchiveDigest(s.PackageSHA256)
	if err != nil {
		return commitSignature{}, err
	}
	bundle, ref, err := p.ReadSignature(ctx, s.Run)
	if errors.Is(err, publication.ErrNotFound) {
		return commitSignature{}, fmt.Errorf("%w: no stored signature", publication.ErrSignatureRequired)
	} else if err != nil {
		return commitSignature{}, err
	}
	if _, err := evidencesign.Verify(bundle, digest, pub); err != nil {
		return commitSignature{}, fmt.Errorf("%w: the stored signature does not verify: %v", publication.ErrSignatureRequired, err)
	}
	return commitSignature{Format: signatureFormat, MediaType: ref.MediaType, Key: ref.Key, VersionID: ref.VersionID, SHA256: ref.SHA256, Size: ref.Size,
		Algorithm: pub.Algorithm, KeyFingerprint: pub.Fingerprint, PublicKey: string(pub.PEM)}, nil
}

// checkCommitSigning refuses an existing commit that does not satisfy the
// request's frozen intent: never a downgrade, never another key.
func checkCommitSigning(existing *commitSignature, sg *publication.Signing) error {
	required := sg != nil && sg.Mode == publication.SigningRequired
	switch {
	case required && existing == nil:
		return fmt.Errorf("an unsigned commit exists for a run whose signing intent is Required: %w: %w", publication.ErrSignatureRequired, publication.ErrConflict)
	case !required && existing != nil:
		return fmt.Errorf("a signed commit exists for a run whose signing intent is Disabled: %w", publication.ErrConflict)
	case required && existing.KeyFingerprint != sg.KeyFingerprint:
		return fmt.Errorf("the commit is signed by %s, the intent requires %s: %w: %w", existing.KeyFingerprint, sg.KeyFingerprint, publication.ErrSignatureRequired, publication.ErrConflict)
	}
	return nil
}
