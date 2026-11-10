package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/errcode"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// budget is the shared verification-metadata allowance of one retrieval.
type budget struct {
	mu        sync.Mutex
	limit     int64
	remaining int64
}

func (b *budget) take(n int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n > b.remaining {
		b.remaining = -1
		return fmt.Errorf("%w: verification metadata exceeds %d bytes", ErrLimitExceeded, b.limit)
	}
	b.remaining -= n
	return nil
}

func (b *budget) left() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return max(b.remaining, 0)
}

func (b *budget) used() int64 { return b.limit - b.left() }

// fetchTransport records the Authorization values it sends (for redaction),
// confines credentials to the source's registry and repository, and charges
// referrers listing bodies to the metadata budget.
type fetchTransport struct {
	base   http.RoundTripper
	rec    *secrets
	budget *budget
	scope  credentialScope
}

// credentialScope is where a retrieval may send credential material: the
// source's registry origin, and on a redirect only paths of its repository.
type credentialScope struct {
	origin   string // scheme://host[:port], default port omitted
	repoPath string // "/v2/<repository path>/"
}

func newCredentialScope(scheme, host, path string) credentialScope {
	return credentialScope{origin: canonicalOrigin(scheme, host), repoPath: "/v2/" + path + "/"}
}

func canonicalOrigin(scheme, host string) string {
	host = strings.ToLower(host)
	if h, port, err := net.SplitHostPort(host); err == nil &&
		((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
		host = h
		if strings.Contains(h, ":") {
			host = "[" + h + "]"
		}
	}
	return scheme + "://" + host
}

// inRepository reports whether p is the API root or a path of the source's
// repository. Paths with dot segments or escapes are never inside it: OCI
// repository names contain neither, and a server may resolve them elsewhere.
func (s credentialScope) inRepository(u *url.URL) bool {
	p := u.Path
	if strings.Contains(p, "/.") || strings.Contains(u.EscapedPath(), "%") || strings.Contains(p, "\\") {
		return false
	}
	return p == "/v2/" || strings.HasPrefix(p, s.repoPath)
}

// guard decides what may be sent. Credential material is an Authorization
// header or a request body (an OAuth2 token request carries the password or
// refresh token in its form). Another origin never receives it: a direct
// request (such as a token fetch from a realm on another host or port) fails
// before it is sent, and on a redirect the Authorization header is dropped.
// On the registry's own origin a redirect keeps the header only within the
// source's repository; direct requests there (the API and same-origin token
// realms) are unchanged.
func (s credentialScope) guard(req *http.Request) (*http.Request, error) {
	authz := req.Header.Get("Authorization") != ""
	sameOrigin := canonicalOrigin(req.URL.Scheme, req.URL.Host) == s.origin
	if req.Response != nil { // a redirect hop built by net/http
		if authz && !(sameOrigin && s.inRepository(req.URL)) {
			req = req.Clone(req.Context())
			req.Header.Del("Authorization")
		}
		return req, nil
	}
	bodied := req.Method != http.MethodGet && req.Method != http.MethodHead
	if !sameOrigin && (authz || bodied) {
		return nil, fmt.Errorf("%w: %s %s is not the source's registry %s", ErrCredentialScope, req.Method, req.URL.Host, s.origin)
	}
	return req, nil
}

func (t *fetchTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req, err := t.scope.guard(req)
	if err != nil {
		return nil, err
	}
	t.rec.addAuthorization(req.Header.Get("Authorization"))
	resp, err := t.base.RoundTrip(req)
	if err != nil || req.Method != http.MethodGet || !strings.Contains(req.URL.Path, "/referrers/") {
		return resp, err
	}
	resp.Body = &meteredBody{ReadCloser: resp.Body, budget: t.budget}
	return resp, nil
}

type meteredBody struct {
	io.ReadCloser
	budget *budget
}

func (m *meteredBody) Read(p []byte) (int, error) {
	n, err := m.ReadCloser.Read(p)
	if n > 0 {
		if berr := m.budget.take(int64(n)); berr != nil {
			return 0, berr
		}
	}
	return n, err
}

// readExact reads exactly size bytes whose digest must be want; a shorter or
// longer body is an integrity failure, and at most size+1 bytes are read.
func readExact(r io.Reader, size int64, want digest.Digest) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: %s is shorter than its %d-byte descriptor", ErrIntegrity, want, size)
		}
		return nil, err
	}
	var extra [1]byte
	switch _, err := io.ReadFull(r, extra[:]); {
	case err == nil:
		return nil, fmt.Errorf("%w: %s is longer than its %d-byte descriptor", ErrIntegrity, want, size)
	case !errors.Is(err, io.EOF):
		return nil, err
	}
	if got := digest.FromBytes(buf); got != want {
		return nil, fmt.Errorf("%w: received %s, want %s", ErrIntegrity, got, want)
	}
	return buf, nil
}

// readLimited reads at most limit bytes; more is ErrLimitExceeded.
func readLimited(r io.Reader, limit int64, what string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrLimitExceeded, what, limit)
	}
	return data, nil
}

const maxRedirects = 5

// checkRedirect bounds redirects (blob storage commonly redirects) and
// refuses any redirect to plain HTTP: net/http keeps the Authorization
// header on a same-host redirect regardless of scheme. Cross-host redirects
// drop it (net/http behaviour).
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if req.URL.Scheme != "https" && !c.plainHTTP {
		return fmt.Errorf("%w: %s", ErrInsecureRedirect, req.URL.Redacted())
	}
	return nil
}

func registryHost(repository string) string {
	host, _, _ := strings.Cut(repository, "/")
	return host
}

// retrieve performs one bounded attempt. Every error is redacted of the
// credential values this attempt used.
func (c *Client) retrieve(ctx context.Context, src bundle.BundleSource, d digest.Digest) (*Result, error) {
	rec := &secrets{}
	res, err := c.retrieveRaw(ctx, src, d, rec)
	return res, rec.redact(err)
}

func (c *Client) retrieveRaw(ctx context.Context, src bundle.BundleSource, d digest.Digest, rec *secrets) (*Result, error) {
	host := registryHost(src.Repository)
	if err := c.preflightCredential(ctx, src, host, rec); err != nil {
		return nil, err
	}
	base, err := c.transportFor(ctx, src)
	if err != nil {
		return nil, err
	}
	scheme := "https"
	if c.plainHTTP {
		scheme = "http"
	}
	_, path, _ := strings.Cut(src.Repository, "/")
	meta := &budget{limit: c.limits.MaxMetadataBytes, remaining: c.limits.MaxMetadataBytes}
	httpClient := &http.Client{
		Transport:     &fetchTransport{base: base, rec: rec, budget: meta, scope: newCredentialScope(scheme, host, path)},
		Timeout:       c.limits.RequestTimeout,
		CheckRedirect: c.checkRedirect,
	}
	authClient := &auth.Client{
		Client:     httpClient,
		Cache:      c.tokenCache(src),
		Credential: c.credentialFunc(src, host, rec),
	}
	if c.plainHTTP {
		authClient.BlockedRealmPrefixes = []netip.Prefix{}
	}
	repo, err := remote.NewRepository(src.Repository)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	repo.Client = authClient
	repo.PlainHTTP = c.plainHTTP
	// Accept an index only to reject it with a clear error.
	repo.ManifestMediaTypes = []string{ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex}
	repo.MaxMetadataBytes = c.limits.MaxManifestBytes
	repo.ReferrerListMaxPages = c.limits.MaxReferrers + 1
	// Make ORAS's Referrers call the referrers API only: when the registry
	// does not serve it, listReferrers reads the referrers tag schema itself,
	// so that the index is charged to the metadata budget and parsed strictly
	// (ORAS's built-in fallback does neither: it ignores the index's
	// schemaVersion and mediaType, treats a tag of the wrong media type as "no
	// referrers", and cannot report which listing was used).
	if err := repo.SetReferrersCapability(true); err != nil {
		return nil, err
	}

	manifest, err := fetchSubject(ctx, repo, d, c.limits.MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	layerDigest, layerSize, err := bundle.ValidateManifest(manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: manifest %s: %w", ErrUnexpectedDescriptor, d, err)
	}
	res := &Result{Repository: src.Repository, Digest: d.String(), Manifest: manifest, LayerDigest: layerDigest}

	subject := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: d, Size: int64(len(manifest))}
	if err := c.collectProofs(ctx, repo, subject, meta, res); err != nil {
		return nil, err
	}
	res.MetadataBytes = meta.used()

	if layerSize > c.limits.MaxPayloadBytes {
		return nil, fmt.Errorf("%w: bundle layer is %d bytes, limit %d", ErrLimitExceeded, layerSize, c.limits.MaxPayloadBytes)
	}
	ld := ocispec.Descriptor{MediaType: bundle.LayerMediaType, Digest: digest.Digest(layerDigest), Size: layerSize}
	res.Layer, err = fetchBlob(ctx, repo, ld, "bundle layer")
	if err != nil {
		return nil, err
	}
	return res, nil
}

// fetchSubject fetches the pinned manifest by digest and checks its bytes.
func fetchSubject(ctx context.Context, repo *remote.Repository, d digest.Digest, limit int64) ([]byte, error) {
	desc, rc, err := repo.Manifests().FetchReference(ctx, d.String())
	if err != nil {
		return nil, wrap("fetch manifest "+d.String(), err)
	}
	defer rc.Close()
	switch desc.MediaType {
	case ocispec.MediaTypeImageManifest:
	case ocispec.MediaTypeImageIndex:
		return nil, fmt.Errorf("%w: %s is an image index; indexes are not supported", ErrUnexpectedDescriptor, d)
	default:
		return nil, fmt.Errorf("%w: %s has media type %q, want %q", ErrUnexpectedDescriptor, d, desc.MediaType, ocispec.MediaTypeImageManifest)
	}
	if desc.Size > limit {
		return nil, fmt.Errorf("%w: manifest %s is %d bytes, limit %d", ErrLimitExceeded, d, desc.Size, limit)
	}
	raw, err := readLimited(rc, limit, "manifest "+d.String())
	if err != nil {
		return nil, wrap("read manifest "+d.String(), err)
	}
	if got := digest.FromBytes(raw); got != d {
		return nil, fmt.Errorf("%w: manifest bytes hash to %s, want %s", ErrIntegrity, got, d)
	}
	return raw, nil
}

func fetchBlob(ctx context.Context, repo *remote.Repository, desc ocispec.Descriptor, what string) ([]byte, error) {
	rc, err := repo.Blobs().Fetch(ctx, desc)
	if err != nil {
		return nil, wrap("fetch "+what+" "+desc.Digest.String(), err)
	}
	defer rc.Close()
	data, err := readExact(rc, desc.Size, desc.Digest)
	if err != nil {
		return nil, wrap("read "+what+" "+desc.Digest.String(), err)
	}
	return data, nil
}

// referrerManifest is the part of a referrer manifest that selection reads.
type referrerManifest struct {
	MediaType    string               `json:"mediaType"`
	ArtifactType string               `json:"artifactType"`
	Layers       []ocispec.Descriptor `json:"layers"`
	Subject      *ocispec.Descriptor  `json:"subject"`
	Annotations  map[string]string    `json:"annotations"`
}

// listReferrers lists the subject's referrers: through the OCI 1.1 referrers
// API when the registry serves it, otherwise from the OCI referrers tag schema
// (an image index tagged sha256-<hex>). Both listings are unauthenticated;
// callers check every entry. Cosign's legacy .sig/.att tags are never read.
func (c *Client) listReferrers(ctx context.Context, repo *remote.Repository, subject ocispec.Descriptor, meta *budget) ([]ocispec.Descriptor, ReferrersSource, error) {
	var listed []ocispec.Descriptor
	err := repo.Referrers(ctx, subject, "", func(page []ocispec.Descriptor) error {
		if len(listed)+len(page) > c.limits.MaxReferrers {
			return fmt.Errorf("%w: more than %d referrers listed for %s", ErrLimitExceeded, c.limits.MaxReferrers, subject.Digest)
		}
		listed = append(listed, page...)
		return nil
	})
	switch {
	case err == nil:
		return listed, ReferrersFromAPI, nil
	case referrersAPIUnavailable(err):
		return c.listReferrersByTagSchema(ctx, repo, subject, meta)
	default:
		return nil, "", wrap("list referrers of "+subject.Digest.String(), err)
	}
}

// referrersAPIUnavailable reports that the registry does not serve the
// referrers API: ORAS reports a 404 other than NAME_UNKNOWN, or a response
// that is not an image index, as errdef.ErrUnsupported; 405 and 501 mean the
// same. The OCI distribution spec then directs clients to the tag schema.
func referrersAPIUnavailable(err error) bool {
	var resp *errcode.ErrorResponse
	return errors.Is(err, errdef.ErrUnsupported) ||
		(errors.As(err, &resp) && (resp.StatusCode == http.StatusNotImplemented || resp.StatusCode == http.StatusMethodNotAllowed))
}

// referrersTag is the OCI referrers tag schema tag of a sha256 subject:
// "<alg>-<hex>" (the spec's truncation to 32/64 characters never applies to
// sha256).
func referrersTag(subject digest.Digest) string {
	return string(subject.Algorithm()) + "-" + subject.Encoded()
}

// referrersIndex is the strictly parsed referrers tag schema index.
type referrersIndex struct {
	SchemaVersion int                   `json:"schemaVersion"`
	MediaType     string                `json:"mediaType"`
	Manifests     *[]ocispec.Descriptor `json:"manifests"`
}

// listReferrersByTagSchema reads the referrers tag schema index. The tag is
// mutable and unauthenticated: its body is bounded by MaxManifestBytes and
// charged to the metadata budget, checked against the size and digest the
// registry declares for it, and parsed strictly; its entries get the same
// checks as an API listing. A missing tag means no referrers.
func (c *Client) listReferrersByTagSchema(ctx context.Context, repo *remote.Repository, subject ocispec.Descriptor, meta *budget) ([]ocispec.Descriptor, ReferrersSource, error) {
	tag := referrersTag(subject.Digest)
	desc, rc, err := repo.Manifests().FetchReference(ctx, tag)
	if err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return nil, ReferrersNone, nil
		}
		return nil, "", wrap("fetch referrers tag "+tag, err)
	}
	defer rc.Close()
	if desc.MediaType != ocispec.MediaTypeImageIndex {
		return nil, "", fmt.Errorf("%w: referrers tag %s has media type %q, want %q", ErrUnexpectedDescriptor, tag, desc.MediaType, ocispec.MediaTypeImageIndex)
	}
	if desc.Digest.Validate() != nil || desc.Digest.Algorithm() != digest.SHA256 || desc.Digest == subject.Digest {
		return nil, "", fmt.Errorf("%w: referrers tag %s resolves to %q, not a sha256 referrers index", ErrUnexpectedDescriptor, tag, desc.Digest)
	}
	if desc.Size > c.limits.MaxManifestBytes {
		return nil, "", fmt.Errorf("%w: referrers index %s is %d bytes, limit %d", ErrLimitExceeded, tag, desc.Size, c.limits.MaxManifestBytes)
	}
	if err := meta.take(desc.Size); err != nil {
		return nil, "", err
	}
	raw, err := readExact(rc, desc.Size, desc.Digest)
	if err != nil {
		return nil, "", wrap("read referrers index "+tag, err)
	}
	var index referrersIndex
	switch err := json.Unmarshal(raw, &index); {
	case err != nil:
		return nil, "", fmt.Errorf("%w: referrers index %s is not valid JSON: %w", ErrUnexpectedDescriptor, tag, err)
	case index.SchemaVersion != 2:
		return nil, "", fmt.Errorf("%w: referrers index %s has schemaVersion %d, want 2", ErrUnexpectedDescriptor, tag, index.SchemaVersion)
	case index.MediaType != ocispec.MediaTypeImageIndex:
		return nil, "", fmt.Errorf("%w: referrers index %s declares media type %q, want %q", ErrUnexpectedDescriptor, tag, index.MediaType, ocispec.MediaTypeImageIndex)
	case index.Manifests == nil:
		return nil, "", fmt.Errorf("%w: referrers index %s has no manifests list", ErrUnexpectedDescriptor, tag)
	case len(*index.Manifests) > c.limits.MaxReferrers:
		return nil, "", fmt.Errorf("%w: more than %d referrers listed for %s", ErrLimitExceeded, c.limits.MaxReferrers, subject.Digest)
	}
	return *index.Manifests, ReferrersFromTagSchema, nil
}

// collectProofs lists the subject's referrers and downloads the recognized
// proofs. Integrity and limit failures are errors; referrers that are merely
// unusable are recorded in res.Skipped.
func (c *Client) collectProofs(ctx context.Context, repo *remote.Repository, subject ocispec.Descriptor, meta *budget, res *Result) error {
	listed, source, err := c.listReferrers(ctx, repo, subject, meta)
	if err != nil {
		return err
	}
	res.ReferrersSource = source
	res.ReferrerCount = len(listed)

	seen := map[digest.Digest]bool{}
	for _, desc := range listed {
		skip := func(reason string) {
			res.Skipped = append(res.Skipped, Skipped{Digest: desc.Digest.String(), ArtifactType: desc.ArtifactType, Reason: reason})
		}
		if seen[desc.Digest] {
			skip("listed more than once")
			continue
		}
		seen[desc.Digest] = true
		if desc.ArtifactType != SigstoreBundleArtifactType {
			skip("unrelated artifact type")
			continue
		}
		if desc.MediaType != ocispec.MediaTypeImageManifest {
			skip(fmt.Sprintf("media type %q is not an OCI image manifest", desc.MediaType))
			continue
		}
		if err := desc.Digest.Validate(); err != nil || desc.Digest.Algorithm() != digest.SHA256 || desc.Size <= 0 {
			return fmt.Errorf("%w: referrer descriptor %q has an invalid digest or size", ErrUnexpectedDescriptor, desc.Digest)
		}
		if err := meta.take(desc.Size); err != nil {
			return err
		}
		rc, err := repo.Manifests().Fetch(ctx, desc)
		if err != nil {
			return wrap("fetch referrer "+desc.Digest.String(), err)
		}
		raw, err := readExact(rc, desc.Size, desc.Digest)
		rc.Close()
		if err != nil {
			return wrap("read referrer "+desc.Digest.String(), err)
		}
		proof, reason := selectProof(raw, desc, subject)
		if reason != "" {
			skip(reason)
			continue
		}
		layer := proof.layer
		if err := meta.take(layer.Size); err != nil {
			return err
		}
		bundleBytes, err := fetchBlob(ctx, repo, layer, "proof layer")
		if err != nil {
			return err
		}
		res.Proofs = append(res.Proofs, Proof{
			Kind: proof.kind, PredicateType: proof.predicateType,
			ManifestDigest: desc.Digest.String(), Manifest: raw,
			BundleMediaType: layer.MediaType, BundleDigest: layer.Digest.String(), Bundle: bundleBytes,
		})
	}
	return nil
}

type candidate struct {
	kind          ProofKind
	predicateType string
	layer         ocispec.Descriptor
}

// selectProof checks a digest-verified referrer manifest. It returns a reason
// when the referrer is not a usable proof for exactly this subject.
func selectProof(raw []byte, desc, subject ocispec.Descriptor) (candidate, string) {
	var m referrerManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return candidate{}, "manifest is not valid JSON"
	}
	switch {
	case m.MediaType != ocispec.MediaTypeImageManifest:
		return candidate{}, fmt.Sprintf("manifest media type %q", m.MediaType)
	case m.ArtifactType != desc.ArtifactType:
		return candidate{}, fmt.Sprintf("manifest artifact type %q differs from the listing", m.ArtifactType)
	case m.Subject == nil:
		return candidate{}, "manifest has no subject"
	case m.Subject.Digest != subject.Digest:
		return candidate{}, fmt.Sprintf("subject %s is not the pinned manifest", m.Subject.Digest)
	case m.Subject.Size != subject.Size:
		return candidate{}, fmt.Sprintf("subject size %d differs from the pinned manifest's %d", m.Subject.Size, subject.Size)
	}
	pt := m.Annotations[PredicateTypeAnnotation]
	kind, ok := predicateKinds[pt]
	if !ok {
		return candidate{}, fmt.Sprintf("unrelated predicate type %q", pt)
	}
	if len(m.Layers) != 1 {
		return candidate{}, fmt.Sprintf("want exactly one Sigstore bundle layer, found %d", len(m.Layers))
	}
	l := m.Layers[0]
	if l.MediaType != SigstoreBundleArtifactType {
		return candidate{}, fmt.Sprintf("layer media type %q", l.MediaType)
	}
	if l.Digest.Validate() != nil || l.Digest.Algorithm() != digest.SHA256 || l.Size <= 0 {
		return candidate{}, "layer has an invalid digest or size"
	}
	return candidate{kind: kind, predicateType: pt, layer: ocispec.Descriptor{MediaType: l.MediaType, Digest: l.Digest, Size: l.Size}}, ""
}
