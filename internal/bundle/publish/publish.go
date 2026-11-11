package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/errdef"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry"
)

// tagPattern is the OCI distribution tag grammar.
var tagPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

// PublisherCredential is the credential reference the writer's source
// carries, so registry.Client.Open demands a credential before any request
// and never writes anonymously. Its name is informational.
var PublisherCredential = bundle.ObjectRef{Kind: "Secret", Name: "bundle-publisher"}

// Subject is a published bundle whose proofs a ProofCompleter adds.
type Subject struct {
	Repository string
	Digest     string
	Size       int64
	// Record is the publication record in effect for the subject: the
	// facts provenance must attest (source, definition, content, tools,
	// tests).
	Record Record
}

// ProofCompleter attaches the missing required proofs (signature,
// provenance) to an already published subject. It is the seam for the
// release signer: it must only add referrers to exactly s.Digest and never
// push, tag or delete anything else. Publish calls it only with the kinds
// the consumer's adapter reports missing, after the subject read back as
// frozen, and then reads back again.
type ProofCompleter interface {
	Complete(ctx context.Context, s Subject, missing []registry.ProofKind) error
}

// Target is where and how to publish.
type Target struct {
	// Repository is host[:port]/path, for example
	// ghcr.io/backend-bunny/bundles/<name>. The version tag is the frozen
	// bundle's version.
	Repository string
	// Writer pushes. It must carry a CredentialProvider that answers for the
	// registry host: every write session demands a credential.
	Writer *registry.Client
	// Reader reads back through the consumer's adapter (Client.Fetch by
	// digest). For the official registry it is a client without credentials,
	// so read-back proves anonymous access.
	Reader *registry.Client
	// AuthenticatedReadBack makes the read-back source reference a
	// credential (for an organization's private registry). The official
	// release never sets it.
	AuthenticatedReadBack bool
	// Proofs adds missing proofs; nil reports them missing.
	Proofs ProofCompleter
	// ReadBackAttempts (default 6) and ReadBackDelay (default 5s, doubling
	// up to 30s) bound waiting for a registry to serve what it accepted.
	ReadBackAttempts int
	ReadBackDelay    time.Duration
}

// Outcome is what a successful Publish found and did.
type Outcome string

const (
	// Created: this run bound the version tag to the frozen subject.
	Created Outcome = "created"
	// AlreadyPublished: the version tag already named the frozen subject
	// and nothing was missing; nothing was written.
	AlreadyPublished Outcome = "already-published"
	// Completed: the version tag already named the frozen subject and this
	// run added only missing pieces (blobs, the record, a referrers listing
	// entry or proofs). The subject's bytes were not touched.
	Completed Outcome = "completed"
)

// Action states for one piece.
const (
	StateExisting = "existing"
	StatePushed   = "pushed"
	// StateRelisted: an identical manifest already existed but was missing
	// from the referrers tag schema listing; it was pushed again (same
	// bytes, same digest) so the client-maintained listing includes it.
	StateRelisted = "relisted"
)

// Action is what happened to one piece of the publication, in push order.
type Action struct {
	Piece  string `json:"piece"`
	Digest string `json:"digest"`
	State  string `json:"state"`
}

// ReadBack is the result of reading the publication back.
type ReadBack struct {
	// Anonymous is true when no credential was available to the reader.
	Anonymous bool `json:"anonymous"`
	// Verified: the tag, manifest and layer read back as the frozen bytes
	// and the record is listed for the subject.
	Verified        bool                     `json:"verified"`
	ReferrersSource registry.ReferrersSource `json:"referrersSource,omitempty"`
	Attempts        int                      `json:"attempts"`
}

// Result describes a publication. It contains no credentials.
type Result struct {
	Repository string  `json:"repository"`
	Tag        string  `json:"tag"`
	Digest     string  `json:"digest"`
	Outcome    Outcome `json:"outcome,omitempty"`
	// Recovered: the version was already published from the same source
	// and content, packaged into different bytes (for example by another
	// toolchain); the remote bytes and their record were adopted as the
	// frozen inputs and nothing local was pushed.
	Recovered      bool     `json:"recovered,omitempty"`
	Actions        []Action `json:"actions"`
	RecordDigest   string   `json:"recordDigest,omitempty"`
	IgnoredRecords int      `json:"ignoredRecords,omitempty"`
	ReadBack       ReadBack `json:"readBack"`
	// Missing lists required proofs the consumer's adapter did not find.
	Missing     []registry.ProofKind `json:"missingProofs"`
	ProofsAdded []registry.ProofKind `json:"proofsAdded,omitempty"`
	// Complete: read back verified and no required proof is missing.
	Complete bool `json:"complete"`
	// Frozen is the frozen bundle in effect (local or recovered).
	Frozen *Frozen `json:"-"`
}

// locks serializes publishers of the same repository and tag within a
// process. Across processes the release workflow's concurrency group does.
var locks sync.Map

func lockFor(key string) *sync.Mutex {
	m, _ := locks.LoadOrStore(key, &sync.Mutex{})
	return m.(*sync.Mutex)
}

type publisher struct {
	f   *Frozen
	t   Target
	w   *registry.Session
	res *Result
}

func (p *publisher) act(piece, d, state string) {
	p.res.Actions = append(p.res.Actions, Action{Piece: piece, Digest: d, State: state})
}

// incomplete marks a failure that may leave the remote short of the frozen
// state. Cancellation and timeouts stay detectable with errors.Is.
func incomplete(what string, err error) error {
	return fmt.Errorf("%w: %s: %w", ErrIncompleteRemote, what, err)
}

// Publish publishes f to t write-once and verifies it; see the package
// documentation for the order and the recovery rules. It returns a Result
// (also on error, describing what was done) and nil or an error wrapping
// ErrConflict, ErrIncompleteRemote, ErrReadBack or ErrFrozenInputs (or a
// registry configuration error such as registry.ErrCredentials).
func Publish(ctx context.Context, f *Frozen, t Target) (*Result, error) {
	if f == nil || f.Descriptor == nil || len(f.RecordJSON) == 0 {
		return nil, fmt.Errorf("%w: no frozen bundle", ErrFrozenInputs)
	}
	if err := f.verify(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFrozenInputs, err)
	}
	if t.Writer == nil || t.Reader == nil {
		return nil, fmt.Errorf("%w: target needs a writer and a reader", registry.ErrInvalidRequest)
	}
	if err := bundle.ValidateRepository(t.Repository); err != nil {
		return nil, fmt.Errorf("%w: %w", registry.ErrInvalidRequest, err)
	}
	tag := f.Record.Version
	if !tagPattern.MatchString(tag) {
		return nil, fmt.Errorf("%w: version %q is not a valid OCI tag", ErrFrozenInputs, tag)
	}
	mu := lockFor(t.Repository + ":" + tag)
	mu.Lock()
	defer mu.Unlock()

	res := &Result{Repository: t.Repository, Tag: tag, Digest: f.ManifestDigest, Actions: []Action{}, Missing: []registry.ProofKind{}, Frozen: f}
	src := bundle.BundleSource{Name: f.Record.Name, Repository: t.Repository, CredentialSecret: &PublisherCredential}
	w, err := t.Writer.Open(ctx, src)
	if err != nil {
		return res, err
	}
	p := &publisher{f: f, t: t, w: w, res: res}

	cur, curManifest, err := p.getTag(ctx)
	if err != nil {
		return res, incomplete("read tag "+tag, err)
	}
	existing := cur != ""
	if existing && cur != f.ManifestDigest {
		adopted, err := p.recover(ctx, cur, curManifest)
		if err != nil {
			return res, err
		}
		p.f, res.Frozen, res.Digest, res.Recovered = adopted, adopted, adopted.ManifestDigest, true
	}

	if err := p.ensureSubject(ctx); err != nil {
		return res, err
	}
	if err := p.ensureRecord(ctx); err != nil {
		return res, err
	}
	created := false
	if !existing {
		if created, err = p.pushTag(ctx); err != nil {
			return res, err
		}
	}
	// Whoever wrote it, the tag must now name the frozen subject.
	if now, _, err := p.getTag(ctx); err != nil {
		return res, incomplete("re-read tag "+tag, err)
	} else if now != p.f.ManifestDigest {
		return res, fmt.Errorf("%w: tag %s now names %s, not %s; another publisher wrote it concurrently. Nothing was changed back; resolve by hand", ErrConflict, tag, now, p.f.ManifestDigest)
	}

	if err := p.readBack(ctx); err != nil {
		return res, err
	}
	if len(res.Missing) > 0 && t.Proofs != nil {
		missing := append([]registry.ProofKind(nil), res.Missing...)
		s := Subject{Repository: t.Repository, Digest: p.f.ManifestDigest, Size: int64(len(p.f.Manifest)), Record: p.f.Record}
		if err := t.Proofs.Complete(ctx, s, missing); err != nil {
			return res, incomplete("complete proofs "+fmt.Sprint(missing), w.Redact(err))
		}
		if err := p.readBack(ctx); err != nil {
			return res, err
		}
		for _, k := range missing {
			if !contains(res.Missing, k) {
				res.ProofsAdded = append(res.ProofsAdded, k)
			}
		}
	}

	wrote := len(res.ProofsAdded) > 0
	for _, a := range res.Actions {
		wrote = wrote || (a.State != StateExisting && a.Piece != "tag")
	}
	switch {
	case created:
		res.Outcome = Created
	case wrote:
		res.Outcome = Completed
	default:
		res.Outcome = AlreadyPublished
	}
	res.Complete = res.ReadBack.Verified && len(res.Missing) == 0
	return res, nil
}

func contains(ks []registry.ProofKind, k registry.ProofKind) bool {
	for _, x := range ks {
		if x == k {
			return true
		}
	}
	return false
}

// verify re-checks a Frozen's bytes and record binding, so a Frozen built or
// modified outside Load/Freeze cannot publish unverified bytes.
func (f *Frozen) verify() error {
	g, err := newFrozen(f.Manifest, f.Layer, f.Record)
	if err != nil {
		return err
	}
	if g.ManifestDigest != f.ManifestDigest || g.LayerDigest != f.LayerDigest || !bytes.Equal(g.RecordJSON, f.RecordJSON) {
		return errors.New("frozen digests or record bytes do not match their content")
	}
	return nil
}

func manifestDesc(b []byte) ocispec.Descriptor {
	return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(b), Size: int64(len(b))}
}

// getTag reads the version tag's manifest and returns the SHA-256 of the
// bytes served (a Docker-Content-Digest header is not trusted), or "" when
// the tag does not exist.
func (p *publisher) getTag(ctx context.Context) (string, []byte, error) {
	return getTag(ctx, p.w, p.res.Tag, p.t.Writer.Limits().MaxManifestBytes)
}

func getTag(ctx context.Context, s *registry.Session, tag string, limit int64) (string, []byte, error) {
	desc, rc, err := s.Repository.Manifests().FetchReference(ctx, tag)
	if errors.Is(err, errdef.ErrNotFound) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, s.Err("fetch tag "+tag, err)
	}
	defer rc.Close()
	if desc.Size > limit {
		return "", nil, fmt.Errorf("%w: tag %s manifest is %d bytes", registry.ErrLimitExceeded, tag, desc.Size)
	}
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return "", nil, s.Err("read tag "+tag, err)
	}
	if int64(len(b)) > limit {
		return "", nil, fmt.Errorf("%w: tag %s manifest exceeds %d bytes", registry.ErrLimitExceeded, tag, limit)
	}
	return digestOf(b), b, nil
}

// fetchExact reads a blob and checks its size and digest.
func (p *publisher) fetchExact(ctx context.Context, desc ocispec.Descriptor, limit int64) ([]byte, error) {
	if desc.Size <= 0 || desc.Size > limit {
		return nil, fmt.Errorf("%w: %s is %d bytes, limit %d", registry.ErrLimitExceeded, desc.Digest, desc.Size, limit)
	}
	rc, err := p.w.Repository.Blobs().Fetch(ctx, desc)
	if err != nil {
		return nil, p.w.Err("fetch "+desc.Digest.String(), err)
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, desc.Size+1))
	if err != nil {
		return nil, p.w.Err("read "+desc.Digest.String(), err)
	}
	if int64(len(b)) != desc.Size || digest.FromBytes(b) != desc.Digest {
		return nil, fmt.Errorf("%w: %s does not match its digest or size", registry.ErrIntegrity, desc.Digest)
	}
	return b, nil
}

// recover handles a version tag that names other bytes than the frozen
// subject. Different content is a conflict. The same release (identical
// descriptor: name, version, source, policies and file inventory) packaged
// into different bytes is the original publication; its bytes are adopted
// only when a publication record bound to them and to the same definition
// is in the registry. Nothing is written either way.
func (p *publisher) recover(ctx context.Context, cur string, manifest []byte) (*Frozen, error) {
	conflict := func(format string, a ...any) error {
		return fmt.Errorf("%w: tag %s names %s, not the frozen %s: %s; a released version is never replaced",
			ErrConflict, p.res.Tag, cur, p.f.ManifestDigest, fmt.Sprintf(format, a...))
	}
	layerDigest, layerSize, err := bundle.ValidateManifest(manifest)
	if err != nil {
		return nil, conflict("it is not a bundle manifest (%v)", err)
	}
	layer, err := p.fetchExact(ctx, ocispec.Descriptor{MediaType: bundle.LayerMediaType, Digest: digest.Digest(layerDigest), Size: layerSize},
		p.t.Writer.Limits().MaxPayloadBytes)
	if err != nil {
		return nil, incomplete("fetch the published layer for comparison", err)
	}
	remote, err := verifyBundle(manifest, layer)
	if err != nil {
		return nil, conflict("its layer does not verify (%v)", err)
	}
	a, _ := json.Marshal(remote)
	b, _ := json.Marshal(p.f.Descriptor)
	if !bytes.Equal(a, b) {
		return nil, conflict("it holds %s@%s from %s with content %s, the frozen bundle %s@%s from %s with content %s",
			remote.Name, remote.Version, remote.Source.Revision, remote.ContentDigest(),
			p.f.Descriptor.Name, p.f.Descriptor.Version, p.f.Descriptor.Source.Revision, p.f.Descriptor.ContentDigest())
	}
	recs, _, err := p.records(ctx, manifestDesc(manifest))
	if err != nil {
		return nil, incomplete("list publication records of "+cur, err)
	}
	for _, r := range recs {
		if r.rec.Definition != p.f.Record.Definition {
			continue
		}
		if g, err := newFrozen(manifest, layer, r.rec); err == nil {
			p.res.RecordDigest = r.digest
			return g, nil
		}
	}
	return nil, fmt.Errorf("%w: tag %s names %s, which holds the same release content as the frozen %s packaged differently, but carries no publication record bound to it; the original build inputs cannot be established, and the release is not replaced",
		ErrFrozenInputs, p.res.Tag, cur, p.f.ManifestDigest)
}

// pushBlob uploads a blob unless the registry already has it.
func (p *publisher) pushBlob(ctx context.Context, piece string, desc ocispec.Descriptor, b []byte) error {
	ok, err := p.w.Repository.Blobs().Exists(ctx, desc)
	if err != nil {
		return incomplete("check "+piece, p.w.Err("check "+piece, err))
	}
	if ok {
		p.act(piece, desc.Digest.String(), StateExisting)
		return nil
	}
	if err := p.w.Repository.Blobs().Push(ctx, desc, bytes.NewReader(b)); err != nil {
		return incomplete("push "+piece, p.w.Err("push "+piece, err))
	}
	p.act(piece, desc.Digest.String(), StatePushed)
	return nil
}

// pushManifest pushes a manifest by digest unless it exists; relist pushes
// an existing one again (identical bytes) to repair a referrers listing.
func (p *publisher) pushManifest(ctx context.Context, piece string, b []byte, relist bool) error {
	desc := manifestDesc(b)
	ok, err := p.w.Repository.Manifests().Exists(ctx, desc)
	if err != nil {
		return incomplete("check "+piece, p.w.Err("check "+piece, err))
	}
	state := StatePushed
	if ok {
		if !relist {
			p.act(piece, desc.Digest.String(), StateExisting)
			return nil
		}
		state = StateRelisted
	}
	if err := p.w.Repository.Manifests().Push(ctx, desc, bytes.NewReader(b)); err != nil {
		return incomplete("push "+piece, p.w.Err("push "+piece, err))
	}
	p.act(piece, desc.Digest.String(), state)
	return nil
}

// ensureSubject pushes the missing blobs, then the manifest by digest.
func (p *publisher) ensureSubject(ctx context.Context) error {
	empty := []byte("{}")
	if err := p.pushBlob(ctx, "config", ocispec.Descriptor{MediaType: bundle.EmptyConfigMediaType, Digest: bundle.EmptyConfigDigest, Size: 2}, empty); err != nil {
		return err
	}
	if err := p.pushBlob(ctx, "layer", ocispec.Descriptor{MediaType: bundle.LayerMediaType, Digest: digest.Digest(p.f.LayerDigest), Size: int64(len(p.f.Layer))}, p.f.Layer); err != nil {
		return err
	}
	return p.pushManifest(ctx, "manifest", p.f.Manifest, false)
}

// recordManifest is the OCI referrer carrying the record: deterministic
// for a given record and subject.
func recordManifest(f *Frozen) []byte {
	m := map[string]any{
		"schemaVersion": 2,
		"mediaType":     ocispec.MediaTypeImageManifest,
		"artifactType":  RecordArtifactType,
		"config":        map[string]any{"mediaType": bundle.EmptyConfigMediaType, "digest": bundle.EmptyConfigDigest, "size": 2},
		"layers": []any{map[string]any{
			"mediaType": RecordArtifactType, "digest": digestOf(f.RecordJSON), "size": len(f.RecordJSON),
		}},
		"subject": map[string]any{"mediaType": ocispec.MediaTypeImageManifest, "digest": f.ManifestDigest, "size": len(f.Manifest)},
	}
	b, _ := json.Marshal(m)
	return b
}

type foundRecord struct {
	digest string
	rec    Record
}

// records lists the publication records referring to subject. Every listed
// entry is fetched by digest, bounded and parsed strictly; entries that are
// not valid records for subject are counted as ignored.
func (p *publisher) records(ctx context.Context, subject ocispec.Descriptor) ([]foundRecord, int, error) {
	limit := p.t.Writer.Limits().MaxReferrers
	var listed []ocispec.Descriptor
	err := p.w.Repository.Referrers(ctx, subject, RecordArtifactType, func(page []ocispec.Descriptor) error {
		if len(listed)+len(page) > limit {
			return fmt.Errorf("%w: more than %d records listed", registry.ErrLimitExceeded, limit)
		}
		listed = append(listed, page...)
		return nil
	})
	if err != nil {
		return nil, 0, p.w.Err("list records", err)
	}
	var found []foundRecord
	ignored := 0
	for _, desc := range listed {
		if desc.ArtifactType != RecordArtifactType || desc.MediaType != ocispec.MediaTypeImageManifest {
			continue
		}
		raw, err := p.fetchManifestExact(ctx, desc)
		if err != nil {
			if errors.Is(err, registry.ErrNotFound) || errors.Is(err, registry.ErrIntegrity) || errors.Is(err, registry.ErrLimitExceeded) {
				ignored++
				continue
			}
			return nil, 0, err
		}
		var m struct {
			ArtifactType string               `json:"artifactType"`
			Layers       []ocispec.Descriptor `json:"layers"`
			Subject      *ocispec.Descriptor  `json:"subject"`
		}
		if json.Unmarshal(raw, &m) != nil || m.ArtifactType != RecordArtifactType || m.Subject == nil ||
			m.Subject.Digest != subject.Digest || len(m.Layers) != 1 || m.Layers[0].MediaType != RecordArtifactType {
			ignored++
			continue
		}
		body, err := p.fetchExact(ctx, m.Layers[0], MaxRecordBytes)
		if err != nil {
			ignored++
			continue
		}
		rec, err := ParseRecord(body)
		if err != nil {
			ignored++
			continue
		}
		found = append(found, foundRecord{digest: desc.Digest.String(), rec: rec})
	}
	return found, ignored, nil
}

func (p *publisher) fetchManifestExact(ctx context.Context, desc ocispec.Descriptor) ([]byte, error) {
	if desc.Size <= 0 || desc.Size > MaxRecordBytes {
		return nil, fmt.Errorf("%w: record manifest %s is %d bytes", registry.ErrLimitExceeded, desc.Digest, desc.Size)
	}
	rc, err := p.w.Repository.Manifests().Fetch(ctx, desc)
	if err != nil {
		return nil, p.w.Err("fetch record "+desc.Digest.String(), err)
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, desc.Size+1))
	if err != nil {
		return nil, p.w.Err("read record "+desc.Digest.String(), err)
	}
	if int64(len(b)) != desc.Size || digest.FromBytes(b) != desc.Digest {
		return nil, fmt.Errorf("%w: record manifest %s does not match its digest", registry.ErrIntegrity, desc.Digest)
	}
	return b, nil
}

// ensureRecord makes a publication record bound to the subject listed as
// its referrer. A valid existing record (possibly written by an earlier run
// with other tool versions for the same bytes) is kept and becomes the
// record in effect; otherwise the frozen record is pushed.
func (p *publisher) ensureRecord(ctx context.Context) error {
	recs, ignored, err := p.records(ctx, manifestDesc(p.f.Manifest))
	if err != nil {
		return incomplete("list publication records", err)
	}
	p.res.IgnoredRecords = ignored
	ours := digestOf(recordManifest(p.f))
	for _, r := range recs {
		if r.digest == ours {
			p.res.RecordDigest = ours
			p.act("record", ours, StateExisting)
			return nil
		}
	}
	for _, r := range recs {
		if r.rec.Definition != p.f.Record.Definition {
			continue
		}
		if g, err := newFrozen(p.f.Manifest, p.f.Layer, r.rec); err == nil {
			p.f, p.res.Frozen, p.res.RecordDigest = g, g, r.digest
			p.act("record", r.digest, StateExisting)
			return nil
		}
		p.res.IgnoredRecords++
	}
	rd := ocispec.Descriptor{MediaType: RecordArtifactType, Digest: digest.Digest(digestOf(p.f.RecordJSON)), Size: int64(len(p.f.RecordJSON))}
	if err := p.pushBlob(ctx, "record-layer", rd, p.f.RecordJSON); err != nil {
		return err
	}
	// An existing but unlisted record manifest (a referrers tag schema
	// update that failed after the manifest was stored) is pushed again,
	// unchanged, so that the client-maintained listing includes it.
	if err := p.pushManifest(ctx, "record", recordManifest(p.f), true); err != nil {
		return err
	}
	p.res.RecordDigest = ours
	return nil
}

// pushTag binds the version tag to the frozen subject, last. It re-reads the
// tag first: one created meanwhile with the same subject is accepted, with
// other bytes is a conflict and nothing is written.
func (p *publisher) pushTag(ctx context.Context) (bool, error) {
	cur, _, err := p.getTag(ctx)
	if err != nil {
		return false, incomplete("re-check tag "+p.res.Tag, err)
	}
	switch {
	case cur == p.f.ManifestDigest:
		p.act("tag", cur, StateExisting)
		return false, nil
	case cur != "":
		return false, fmt.Errorf("%w: tag %s was created concurrently for %s, not the frozen %s; it is not replaced",
			ErrConflict, p.res.Tag, cur, p.f.ManifestDigest)
	}
	desc := manifestDesc(p.f.Manifest)
	if err := p.w.Repository.Manifests().PushReference(ctx, desc, bytes.NewReader(p.f.Manifest), p.res.Tag); err != nil {
		return false, incomplete("push tag "+p.res.Tag, p.w.Err("push tag "+p.res.Tag, err))
	}
	p.act("tag", desc.Digest.String(), StatePushed)
	return true, nil
}

// errMismatch marks a read-back that served other bytes: never retried.
var errMismatch = errors.New("mismatch")

// readBack reads the publication as a consumer would, retrying while the
// registry has not yet made it visible.
func (p *publisher) readBack(ctx context.Context) error {
	attempts, delay := p.t.ReadBackAttempts, p.t.ReadBackDelay
	if attempts <= 0 {
		attempts = 6
	}
	if delay <= 0 {
		delay = 5 * time.Second
	}
	src := bundle.BundleSource{Name: p.f.Record.Name, Repository: p.t.Repository}
	if p.t.AuthenticatedReadBack {
		src.CredentialSecret = &PublisherCredential
	}
	p.res.ReadBack = ReadBack{Anonymous: !p.t.AuthenticatedReadBack}
	var err error
	for i := 0; i < attempts; i++ {
		p.res.ReadBack.Attempts = i + 1
		if err = p.readBackOnce(ctx, src); err == nil {
			p.res.ReadBack.Verified = true
			return nil
		}
		if !retryableReadBack(err) || ctx.Err() != nil || i == attempts-1 {
			break
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
		}
		delay = min(2*delay, 30*time.Second)
	}
	hint := ""
	if errors.Is(err, registry.ErrUnauthorized) && !p.t.AuthenticatedReadBack {
		hint = "; anonymous read was refused: the package is probably private, and an owner must make it public (docs/policy-bundles.md#release-a-bundle) before rerunning"
	}
	return fmt.Errorf("%w: %s@%s after %d attempt(s): %w%s; the publication is not complete",
		ErrReadBack, p.t.Repository, p.f.ManifestDigest, p.res.ReadBack.Attempts, err, hint)
}

func retryableReadBack(err error) bool {
	switch {
	case errors.Is(err, errMismatch), errors.Is(err, registry.ErrUnauthorized), errors.Is(err, registry.ErrCredentials),
		errors.Is(err, registry.ErrTrustConfig), errors.Is(err, registry.ErrCredentialScope), errors.Is(err, registry.ErrInsecureRedirect):
		return false
	}
	return registry.Classify(err) == registry.ClassRetryable
}

func (p *publisher) readBackOnce(ctx context.Context, src bundle.BundleSource) error {
	s, err := p.t.Reader.Open(ctx, src)
	if err != nil {
		return err
	}
	cur, _, err := getTag(ctx, s, p.res.Tag, p.t.Reader.Limits().MaxManifestBytes)
	switch {
	case err != nil:
		return err
	case cur == "":
		return fmt.Errorf("%w: tag %s is not visible yet", registry.ErrNotFound, p.res.Tag)
	case cur != p.f.ManifestDigest:
		return fmt.Errorf("%w: tag %s reads back as %s", errMismatch, p.res.Tag, cur)
	}
	r, err := p.t.Reader.Fetch(ctx, src, p.f.ManifestDigest)
	if err != nil {
		if errors.Is(err, registry.ErrIntegrity) || errors.Is(err, registry.ErrUnexpectedDescriptor) {
			return fmt.Errorf("%w: %w", errMismatch, err)
		}
		return err
	}
	if !bytes.Equal(r.Manifest, p.f.Manifest) || !bytes.Equal(r.Layer, p.f.Layer) {
		return fmt.Errorf("%w: manifest or layer bytes differ from the frozen bundle", errMismatch)
	}
	listed := false
	for _, sk := range r.Skipped {
		listed = listed || (sk.Digest == p.res.RecordDigest && sk.ArtifactType == RecordArtifactType)
	}
	if !listed {
		return fmt.Errorf("%w: publication record %s is not listed for the subject yet", registry.ErrNotFound, p.res.RecordDigest)
	}
	p.res.ReadBack.ReferrersSource = r.ReferrersSource
	p.res.Missing = r.Missing(registry.RequiredProofs...)
	if p.res.Missing == nil {
		p.res.Missing = []registry.ProofKind{}
	}
	return nil
}
