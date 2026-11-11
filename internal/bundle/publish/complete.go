package publish

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

// ErrProofSubject: the subject a Completer was asked to sign is not the
// recorded publication (another digest, other bytes or an unbound record).
// Nothing was signed.
var ErrProofSubject = errors.New("refusing to sign: the subject is not the recorded publication")

var subjectDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ProofSigner makes one proof over an exact subject reference
// <repository>@sha256:<hex>, never a tag, and attaches it to the subject as
// a referrer. The release tool implements it with the pinned Cosign CLI
// (internal/bundle/sign); this package never executes anything.
type ProofSigner interface {
	// Sign attaches a signature (cosign sign; statement predicate type
	// https://sigstore.dev/cosign/sign/v1).
	Sign(ctx context.Context, ref string) error
	// Attest attaches a signed SLSA provenance v1 attestation of predicate.
	Attest(ctx context.Context, ref string, predicate []byte) error
	// Tool names the signing tool and its version, recorded in provenance.
	Tool(ctx context.Context) (Tool, error)
}

// Completer is the release ProofCompleter: it signs and attests the
// published subject for exactly the missing proof kinds.
//
// Before anything is signed it reads the subject through the consumer's
// adapter (Reader.Fetch by digest, anonymous unless AuthenticatedRead) and
// requires its manifest and layer to be exactly the bytes the publication
// record is bound to; a different digest, other bytes or an unbound record
// is ErrProofSubject. It then signs only the requested kinds that the
// adapter still reports missing, so an existing proof is never duplicated.
// Provenance is built from the record (BuildProvenance) before any write.
type Completer struct {
	Signer ProofSigner
	Reader *registry.Client
	// AuthenticatedRead reads the subject with the publisher credential
	// reference (organization registries); the official release reads
	// anonymously, as consumers do.
	AuthenticatedRead bool
	// Provenance supplies the builder and the workflow revision. The
	// signer's tool is appended to SigningTools.
	Provenance ProvenanceInput
}

// Complete implements ProofCompleter.
func (c *Completer) Complete(ctx context.Context, s Subject, missing []registry.ProofKind) error {
	if c == nil || c.Signer == nil || c.Reader == nil {
		return errors.New("completer needs a signer and a reader")
	}
	want, err := checkKinds(missing)
	if err != nil || len(want) == 0 {
		return err
	}
	if err := bundle.ValidateRepository(s.Repository); err != nil {
		return fmt.Errorf("%w: %w", ErrProofSubject, err)
	}
	if !subjectDigest.MatchString(s.Digest) || s.Digest != s.Record.ManifestDigest {
		return fmt.Errorf("%w: asked to sign %q, but the publication record is for %s", ErrProofSubject, s.Digest, s.Record.ManifestDigest)
	}
	src := bundle.BundleSource{Name: s.Record.Name, Repository: s.Repository}
	if c.AuthenticatedRead {
		src.CredentialSecret = &PublisherCredential
	}
	r, err := c.Reader.Fetch(ctx, src, s.Digest)
	if err != nil {
		return fmt.Errorf("read the subject %s@%s through the consumer adapter before signing: %w", s.Repository, s.Digest, err)
	}
	if int64(len(r.Manifest)) != s.Size {
		return fmt.Errorf("%w: %s is %d bytes, the publication is %d", ErrProofSubject, s.Digest, len(r.Manifest), s.Size)
	}
	f, err := newFrozen(r.Manifest, r.Layer, s.Record)
	if err != nil || f.ManifestDigest != s.Digest {
		return fmt.Errorf("%w: %s@%s does not hold the bytes its publication record describes: %v", ErrProofSubject, s.Repository, s.Digest, err)
	}

	present := r.Found()
	var todo []registry.ProofKind
	for _, k := range want {
		if present[k] == 0 {
			todo = append(todo, k)
		}
	}
	if len(todo) == 0 {
		return nil
	}
	var predicate []byte
	if slices.Contains(todo, registry.ProofProvenance) {
		tool, err := c.Signer.Tool(ctx)
		if err != nil {
			return fmt.Errorf("signing tool version: %w", err)
		}
		in := c.Provenance
		in.SigningTools = append(append([]Tool(nil), in.SigningTools...), tool)
		if predicate, err = BuildProvenance(f.Record, in); err != nil {
			return fmt.Errorf("build provenance: %w", err)
		}
	}
	ref := s.Repository + "@" + s.Digest
	for _, k := range todo {
		switch k {
		case registry.ProofSignature:
			if err := c.Signer.Sign(ctx, ref); err != nil {
				return fmt.Errorf("sign %s: %w", ref, err)
			}
		case registry.ProofProvenance:
			if err := c.Signer.Attest(ctx, ref, predicate); err != nil {
				return fmt.Errorf("attest provenance for %s: %w", ref, err)
			}
		}
	}
	return nil
}

// checkKinds accepts only the required kinds, each at most once, in the
// order signature, provenance.
func checkKinds(missing []registry.ProofKind) ([]registry.ProofKind, error) {
	var out []registry.ProofKind
	for _, k := range missing {
		if !slices.Contains(registry.RequiredProofs, k) {
			return nil, fmt.Errorf("unknown proof kind %q", k)
		}
		if slices.Contains(out, k) {
			return nil, fmt.Errorf("proof kind %q requested twice", k)
		}
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b registry.ProofKind) int {
		return slices.Index(registry.RequiredProofs, a) - slices.Index(registry.RequiredProofs, b)
	})
	return out, nil
}
