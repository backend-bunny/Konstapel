package release

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/publish"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
)

// ErrNotAnonymous: the source needs a registry credential, so consumers
// could not retrieve the release anonymously; it is refused before any request.
var ErrNotAnonymous = errors.New("release verification reads anonymously")

// ErrReleaseRecord: the verified provenance does not attest the inputs the
// publication record says were frozen and tested.
var ErrReleaseRecord = errors.New("the provenance does not attest the recorded release inputs")

// ReleaseCheck is a verification of a published bundle through the
// consumer's trust contract.
type ReleaseCheck struct {
	// Source is the central rule, from configuration, never from the artifact.
	Source bundle.BundleSource
	// Digest is the published manifest digest to verify.
	Digest string
	// Verifier verifies proofs (its ObjectReader supplies any key or root the
	// rule references; the official keyless rule uses the embedded root).
	Verifier *verify.Verifier
	// Transport for registry requests (nil: system roots). Retrieval never
	// carries a credential: verification reads anonymously, as a consumer of
	// a public source does.
	Transport http.RoundTripper
	// Record, when set, is the publication record in effect; the provenance
	// must attest exactly its source, definition, content and tests.
	Record *publish.Record
}

// VerifyRelease fetches Digest anonymously through the consumer's adapter
// (registry.Client.Fetch by digest) and checks it with CheckRelease. A
// source that requires a registry credential is refused: the release is
// only complete when anyone can retrieve and verify it.
func VerifyRelease(ctx context.Context, c ReleaseCheck) (*verify.Accepted, *registry.Result, error) {
	if c.Source.CredentialSecret != nil {
		return nil, nil, fmt.Errorf("%w: source %s requires a registry credential", ErrNotAnonymous, c.Source.Name)
	}
	reader, err := registry.NewClient(registry.Options{Transport: c.Transport})
	if err != nil {
		return nil, nil, err
	}
	res, err := reader.Fetch(ctx, c.Source, c.Digest)
	if err != nil {
		return nil, nil, fmt.Errorf("retrieve %s@%s anonymously: %w", c.Source.Repository, c.Digest, err)
	}
	acc, err := CheckRelease(ctx, c, res)
	return acc, res, err
}

// CheckRelease applies the consumer's trust contract to a retrieved
// subject: Verifier.Accept (signature and SLSA provenance under the one
// publisher rule, layer and payload against the pinned manifest,
// CheckProvenance against the unpacked descriptor), the payload's own
// content rules (bundle.ValidateContent) and the source's name. With a
// Record it also requires the provenance to attest that record's inputs.
func CheckRelease(ctx context.Context, c ReleaseCheck, res *registry.Result) (*verify.Accepted, error) {
	if c.Verifier == nil || res == nil {
		return nil, errors.New("release check needs a verifier and a retrieval")
	}
	if err := c.Source.Validate(); err != nil {
		return nil, err
	}
	if res.Digest != c.Digest {
		return nil, fmt.Errorf("retrieved %s, asked to verify %s", res.Digest, c.Digest)
	}
	acc, err := c.Verifier.Accept(ctx, c.Source, res)
	if err != nil {
		return nil, err
	}
	d, payload, err := bundle.Unpack(res.Layer)
	if err != nil {
		return nil, err
	}
	if err := bundle.ValidateContent(d, payload); err != nil {
		return nil, fmt.Errorf("%w: %w", verify.ErrContent, err)
	}
	if err := c.Source.CheckPayload(acc.Descriptor); err != nil {
		return nil, err
	}
	if c.Record != nil {
		if err := checkRecord(res, acc.Provenance, *c.Record); err != nil {
			return nil, err
		}
	}
	return acc, nil
}

func checkRecord(res *registry.Result, vp *verify.VerifiedProvenance, rec publish.Record) error {
	if err := publish.CheckRecord(res.Manifest, res.Layer, rec); err != nil {
		return fmt.Errorf("%w: the record does not describe the published bytes: %w", ErrReleaseRecord, err)
	}
	var errs []error
	check := func(what, got, want string) {
		if got != want {
			errs = append(errs, fmt.Errorf("%s: attested %q, recorded %q", what, got, want))
		}
	}
	check("source repository", vp.SourceRepository, rec.Source.Repository)
	check("source commit", vp.SourceRevision, rec.Source.Commit)
	check("bundle", vp.BundleName+"@"+vp.BundleVersion, rec.Name+"@"+rec.Version)
	check("content", vp.ContentDigest, rec.ContentDigest)
	check("definition", vp.Definition.Digest, "sha256:"+rec.Definition.SHA256)
	var got, want []string
	for _, t := range vp.Tests {
		got = append(got, t.URI+" "+t.Digest)
	}
	for _, f := range rec.Tests.Files {
		want = append(want, "bundle-file:"+f.Path+" sha256:"+f.SHA256)
	}
	slices.Sort(got)
	slices.Sort(want)
	check("tests", strings.Join(got, ", "), strings.Join(want, ", "))
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: %w", ErrReleaseRecord, err)
	}
	return nil
}
