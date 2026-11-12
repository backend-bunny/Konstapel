// Package mirror copies one published policy bundle, with the signature and
// provenance referrers that make it verifiable, from one OCI repository to
// another by digest. Bytes are never rewritten: the subject manifest, layer
// and every proof keep their digests, so the original publisher's signature
// and provenance verify at the mirror under the same publisher rule; only the
// repository (a location) differs. A mirror is never a source of trust.
package mirror

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

// Required is the evidence a mirror copies and insists on: a bundle that
// cannot be verified at the destination is not a mirror of a release.
var Required = []registry.ProofKind{registry.ProofSignature, registry.ProofProvenance}

// ErrDestinationMismatch means the destination did not return exactly the
// copied content after the copy.
var ErrDestinationMismatch = errors.New("mirror destination does not hold the copied content")

// Request names the copy.
type Request struct {
	Source, Destination bundle.BundleSource
	// Digest is the subject manifest digest (sha256:HEX); mirroring is by
	// digest only.
	Digest string
}

// Result reports what was copied.
type Result struct {
	Digest string
	Proofs []string // referrer manifest digests, in copy order
}

// Mirror copies the subject and its required proofs. src reads the source
// (anonymously or with its credential), dst writes the destination. It fails
// before any write when the source lacks required proofs, and after the copy
// when the destination does not return identical content and proofs.
func Mirror(ctx context.Context, src, dst *registry.Client, req Request) (*Result, error) {
	got, err := src.Fetch(ctx, req.Source, req.Digest)
	if err != nil {
		return nil, fmt.Errorf("read source: %w", err)
	}
	if err := got.RequireProofs(Required...); err != nil {
		return nil, fmt.Errorf("source is not mirrorable: %w", err)
	}
	w, err := dst.Open(ctx, req.Destination)
	if err != nil {
		return nil, fmt.Errorf("open destination: %w", err)
	}
	empty := ocispec.Descriptor{MediaType: bundle.EmptyConfigMediaType, Digest: bundle.EmptyConfigDigest, Size: 2}
	blob := func(what string, d ocispec.Descriptor, b []byte) error {
		ok, err := w.Repository.Blobs().Exists(ctx, d)
		if err != nil {
			return w.Err("check "+what, err)
		}
		if ok {
			return nil
		}
		return w.Err("push "+what, w.Repository.Blobs().Push(ctx, d, bytes.NewReader(b)))
	}
	manifest := func(what string, b []byte) error {
		d := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(b), Size: int64(len(b))}
		ok, err := w.Repository.Manifests().Exists(ctx, d)
		if err != nil {
			return w.Err("check "+what, err)
		}
		if ok {
			return nil
		}
		return w.Err("push "+what, w.Repository.Manifests().Push(ctx, d, bytes.NewReader(b)))
	}
	if err := blob("config", empty, []byte("{}")); err != nil {
		return nil, err
	}
	layer := ocispec.Descriptor{MediaType: bundle.LayerMediaType, Digest: digest.Digest(got.LayerDigest), Size: int64(len(got.Layer))}
	if err := blob("layer", layer, got.Layer); err != nil {
		return nil, err
	}
	if err := manifest("manifest", got.Manifest); err != nil {
		return nil, err
	}
	res := &Result{Digest: got.Digest}
	for _, p := range got.Proofs {
		bd := ocispec.Descriptor{MediaType: p.BundleMediaType, Digest: digest.Digest(p.BundleDigest), Size: int64(len(p.Bundle))}
		if err := blob(string(p.Kind)+" bundle", bd, p.Bundle); err != nil {
			return nil, err
		}
		if err := manifest(string(p.Kind)+" referrer", p.Manifest); err != nil {
			return nil, err
		}
		res.Proofs = append(res.Proofs, p.ManifestDigest)
	}
	back, err := dst.Fetch(ctx, req.Destination, req.Digest)
	if err != nil {
		return nil, fmt.Errorf("read back destination: %w", err)
	}
	if err := back.RequireProofs(Required...); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDestinationMismatch, err)
	}
	if !bytes.Equal(back.Manifest, got.Manifest) || !bytes.Equal(back.Layer, got.Layer) {
		return nil, fmt.Errorf("%w: subject differs", ErrDestinationMismatch)
	}
	have := map[string]bool{}
	for _, p := range back.Proofs {
		have[p.ManifestDigest] = true
	}
	for _, d := range res.Proofs {
		if !have[d] {
			return nil, fmt.Errorf("%w: proof %s not listed", ErrDestinationMismatch, d)
		}
	}
	return res, nil
}
