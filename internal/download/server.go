package download

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/evidencesign"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// Routes. The namespace route is addressed by the request's namespace, name
// and UID; the platform route by run UID. Nothing else (keys, URLs, endpoints)
// is accepted as an address.
const (
	RequestRoute = "GET /v1/namespaces/{namespace}/assessmentrequests/{name}/download"
	RunRoute     = "GET /v1/assessmentruns/{uid}/download"
	// RequestSignatureRoute and RunSignatureRoute serve the companion
	// signature bundle of the same package, for the same identities and with
	// exactly the same authorization, expiry, destination and orphan checks.
	RequestSignatureRoute = "GET /v1/namespaces/{namespace}/assessmentrequests/{name}/signature"
	RunSignatureRoute     = "GET /v1/assessmentruns/{uid}/signature"
)

// artifact selects what a route serves. Both are served only after the same
// checks, and for a signed publication only after the archive/signature
// pair has been verified.
type artifact int

const (
	archiveArtifact artifact = iota
	signatureArtifact
)

// Server serves verified package archives.
type Server struct {
	// Reader reads requests, runs and namespaces. It should be uncached so
	// a recreated namespace or deleted request is seen immediately.
	Reader  client.Reader
	Reviews Reviewer
	// Publisher serves runs without a destination pin (legacy file
	// destination); it may be nil when every run is pinned.
	Publisher publication.Publisher
	// PublisherFor serves a run pinned to an EvidenceDestination, from that
	// destination; downloads never follow later selection edits.
	PublisherFor func(ctx context.Context, run *v1alpha1.AssessmentRun) (publication.Publisher, error)
	// TempDir holds archives while they are verified. Files are removed
	// after each response.
	TempDir string
	// MaxConcurrent bounds simultaneous downloads (default 4).
	MaxConcurrent int
	// MaxDiskBytes bounds TempDir usage across downloads (default 2 GiB).
	MaxDiskBytes int64

	once sync.Once
	sem  chan struct{}
	mu   sync.Mutex
	used int64
}

// Handler returns the download routes.
func (s *Server) Handler() http.Handler {
	s.once.Do(func() {
		if s.MaxConcurrent <= 0 {
			s.MaxConcurrent = 4
		}
		if s.MaxDiskBytes <= 0 {
			s.MaxDiskBytes = 2 << 30
		}
		s.sem = make(chan struct{}, s.MaxConcurrent)
	})
	mux := http.NewServeMux()
	mux.HandleFunc(RequestRoute, func(w http.ResponseWriter, r *http.Request) { s.serveRequest(w, r, archiveArtifact) })
	mux.HandleFunc(RunRoute, func(w http.ResponseWriter, r *http.Request) { s.serveRun(w, r, archiveArtifact) })
	mux.HandleFunc(RequestSignatureRoute, func(w http.ResponseWriter, r *http.Request) { s.serveRequest(w, r, signatureArtifact) })
	mux.HandleFunc(RunSignatureRoute, func(w http.ResponseWriter, r *http.Request) { s.serveRun(w, r, signatureArtifact) })
	return mux
}

// problem is an error response. Messages never contain storage locations,
// credentials, tokens, or another scope's data.
type problem struct {
	code int
	msg  string
}

func (p problem) Error() string { return p.msg }

var (
	errForbidden = problem{http.StatusForbidden, "forbidden: not found or not authorized"}
	errReview    = problem{http.StatusServiceUnavailable, "authorization is unavailable; try again later"}
)

func fail(w http.ResponseWriter, err error) {
	var p problem
	if !errors.As(err, &p) {
		p = problem{http.StatusInternalServerError, "internal error"}
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if p.code == http.StatusServiceUnavailable || p.code == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "30")
	}
	w.WriteHeader(p.code)
	fmt.Fprintln(w, p.msg)
}

// authenticate reads the bearer token. Forwarded identity headers are never
// consulted.
func (s *Server) authenticate(r *http.Request) (authnv1.UserInfo, error) {
	h := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || strings.TrimSpace(token) == "" {
		return authnv1.UserInfo{}, problem{http.StatusUnauthorized, "a bearer token is required"}
	}
	u, err := s.Reviews.Authenticate(r.Context(), strings.TrimSpace(token))
	switch {
	case errors.Is(err, ErrUnauthenticated):
		return u, problem{http.StatusUnauthorized, "the token was not accepted"}
	case err != nil:
		log.FromContext(r.Context()).Info("token review failed", "error", err.Error())
		return u, errReview
	}
	return u, nil
}

// authorize requires every attribute set; any review error fails closed.
func (s *Server) authorize(ctx context.Context, u authnv1.UserInfo, attrs ...authzv1.ResourceAttributes) error {
	for _, a := range attrs {
		ok, err := s.Reviews.Authorize(ctx, u, a)
		if err != nil {
			log.FromContext(ctx).Info("subject access review failed", "error", err.Error())
			return errReview
		}
		if !ok {
			return errForbidden
		}
	}
	return nil
}

func attrs(namespace, resource, name string) []authzv1.ResourceAttributes {
	base := authzv1.ResourceAttributes{Namespace: namespace, Verb: "get", Group: v1alpha1.GroupVersion.Group, Version: v1alpha1.GroupVersion.Version, Resource: resource, Name: name}
	download := base
	download.Subresource = "download"
	return []authzv1.ResourceAttributes{download, base}
}

// serveRequest serves a namespace request's own namespace-scoped package.
func (s *Server) serveRequest(w http.ResponseWriter, r *http.Request, art artifact) {
	ctx := r.Context()
	ns, name, uid := r.PathValue("namespace"), r.PathValue("name"), r.URL.Query().Get("uid")
	if uid == "" {
		fail(w, problem{http.StatusBadRequest, "the request UID is required (?uid=)"})
		return
	}
	u, err := s.authenticate(r)
	if err != nil {
		fail(w, err)
		return
	}
	// The address is known, so authorize before reading anything.
	if err := s.authorize(ctx, u, attrs(ns, "assessmentrequests", name)...); err != nil {
		fail(w, err)
		return
	}
	run, err := s.resolveRequest(ctx, ns, name, uid)
	if err != nil {
		fail(w, err)
		return
	}
	s.serve(w, r, run, art)
}

func (s *Server) resolveRequest(ctx context.Context, ns, name, uid string) (*v1alpha1.AssessmentRun, error) {
	req := &v1alpha1.AssessmentRequest{}
	if err := s.Reader.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, req); err != nil {
		return nil, errForbidden
	}
	namespace := &corev1.Namespace{}
	if err := s.Reader.Get(ctx, client.ObjectKey{Name: ns}, namespace); err != nil {
		return nil, errForbidden
	}
	// The request must be the one addressed, and its namespace the one it
	// was admitted in: a recreated request or namespace is a different
	// identity even with the same name.
	if string(req.UID) != uid || req.Status.NamespaceUID == "" || req.Status.NamespaceUID != string(namespace.UID) {
		return nil, errForbidden
	}
	if req.Status.Run == nil || req.Status.ArtifactRef == "" {
		return nil, problem{http.StatusConflict, "the request has no published package"}
	}
	run := &v1alpha1.AssessmentRun{}
	if err := s.Reader.Get(ctx, client.ObjectKey{Name: req.Status.Run.Name}, run); err != nil {
		return nil, errForbidden
	}
	// Only that request's namespace-scoped run, never a full-binding one.
	if run.Spec.Scope != v1alpha1.RunScopeNamespace || run.Spec.Request == nil || run.Spec.Request.UID != uid ||
		run.Status.Scope == nil || run.Status.Scope.NamespaceUID != req.Status.NamespaceUID ||
		run.Status.Publication == nil || run.Status.Publication.PublicationID != req.Status.ArtifactRef {
		return nil, errForbidden
	}
	return run, nil
}

// serveRun serves a platform run by UID.
func (s *Server) serveRun(w http.ResponseWriter, r *http.Request, art artifact) {
	ctx := r.Context()
	u, err := s.authenticate(r)
	if err != nil {
		fail(w, err)
		return
	}
	var runs v1alpha1.AssessmentRunList
	if err := s.Reader.List(ctx, &runs); err != nil {
		fail(w, errReview)
		return
	}
	var run *v1alpha1.AssessmentRun
	for i := range runs.Items {
		if string(runs.Items[i].UID) == r.PathValue("uid") {
			run = &runs.Items[i]
		}
	}
	if run == nil {
		// Same answer as a denial: run UIDs are not an existence oracle.
		fail(w, errForbidden)
		return
	}
	if err := s.authorize(ctx, u, attrs("", "assessmentruns", run.Name)...); err != nil {
		fail(w, err)
		return
	}
	s.serve(w, r, run, art)
}

// serve fetches the committed archive into bounded temporary storage and
// verifies its size and SHA-256 against the run's recorded receipt and the
// committed status. For a signed publication it then verifies the
// archive/signature pair (verifyPair). Only then does it stream the
// requested artifact; nothing is served from an unverified pair.
func (s *Server) serve(w http.ResponseWriter, r *http.Request, run *v1alpha1.AssessmentRun, art artifact) {
	ctx := r.Context()
	if run.Status.Phase != v1alpha1.RunCompleted || run.Status.Publication == nil || run.Status.Scope == nil || run.Status.Binding == nil {
		fail(w, problem{http.StatusConflict, "the run has no published package"})
		return
	}
	if run.Status.Publication.Phase == v1alpha1.PublicationPhase(publication.PhaseOrphaned) {
		// Recorded disposition: never served, whatever storage would answer.
		fail(w, problem{http.StatusGone, "the package's storage was handed off to an operator and is no longer served"})
		return
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		fail(w, problem{http.StatusTooManyRequests, "too many concurrent downloads; try again later"})
		return
	}
	ref := publication.RunRef{ClusterID: run.Status.Scope.ClusterID, BindingUID: run.Status.Binding.UID, RunUID: string(run.UID)}
	pub := s.Publisher
	if run.Status.Destination != nil {
		pub = nil
		if s.PublisherFor != nil {
			if p, err := s.PublisherFor(ctx, run); err == nil {
				pub = p
			} else if errors.Is(err, publication.ErrOrphaned) {
				fail(w, problem{http.StatusGone, "the package's storage was handed off to an operator and is no longer served"})
				return
			} else {
				log.FromContext(ctx).Info("pinned destination unavailable", "run", run.Name, "error", err.Error())
			}
		}
	}
	if pub == nil {
		fail(w, problem{http.StatusServiceUnavailable, "the package is unavailable"})
		return
	}
	body, st, err := pub.Open(ctx, ref)
	switch {
	case errors.Is(err, publication.ErrExpired):
		fail(w, problem{http.StatusGone, "the package expired and is no longer served"})
		return
	case errors.Is(err, publication.ErrNotFound):
		fail(w, problem{http.StatusConflict, "the package is not committed"})
		return
	case err != nil:
		log.FromContext(ctx).Info("package unavailable", "run", run.Name, "error", err.Error())
		fail(w, problem{http.StatusServiceUnavailable, "the package is unavailable"})
		return
	}
	defer body.Close()
	recorded := run.Status.Publication
	if st.PublicationID != recorded.PublicationID || st.PackageSHA256 == "" || st.PackageSHA256 != recorded.PackageSHA256 ||
		st.DescriptorSHA256 != run.Status.DescriptorSHA256 || st.PackageSize <= 0 {
		fail(w, problem{http.StatusBadGateway, "the stored package does not match the run's receipt"})
		return
	}
	if !s.reserve(st.PackageSize) {
		fail(w, problem{http.StatusServiceUnavailable, "download staging is full; try again later"})
		return
	}
	defer s.release(st.PackageSize)
	f, err := os.CreateTemp(s.TempDir, "download-*")
	if err != nil {
		fail(w, err)
		return
	}
	defer os.Remove(f.Name())
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, st.PackageSize+1))
	if err != nil {
		fail(w, problem{http.StatusServiceUnavailable, "the package is unavailable"})
		return
	}
	sum := h.Sum(nil)
	if n != st.PackageSize || hex.EncodeToString(sum) != st.PackageSHA256 {
		log.FromContext(ctx).Info("package failed integrity verification", "run", run.Name, "size", n)
		fail(w, problem{http.StatusBadGateway, "the stored package failed integrity verification"})
		return
	}
	recordedSigned, storedSigned := recorded.Signature != nil, st.Signature != nil
	if recordedSigned != storedSigned {
		log.FromContext(ctx).Info("signature record mismatch", "run", run.Name, "recorded", recordedSigned, "stored", storedSigned)
		fail(w, problem{http.StatusBadGateway, "the stored package does not match the run's receipt"})
		return
	}
	var bundle []byte
	if recordedSigned {
		var digest evidencesign.ArchiveDigest
		copy(digest[:], sum)
		if bundle, err = verifyPair(ctx, pub, ref, run, st, digest); err != nil {
			log.FromContext(ctx).Info("signed package failed verification", "run", run.Name, "error", err.Error())
			fail(w, err)
			return
		}
	} else if art == signatureArtifact {
		w.Header().Set("X-Konstapel-Signing", "unsigned")
		fail(w, problem{http.StatusNotFound, "the package was published unsigned; it has no signature"})
		return
	}
	hd := w.Header()
	if recordedSigned {
		hd.Set("X-Konstapel-Signing", "signed")
		hd.Set("X-Konstapel-Signing-Key", recorded.Signature.KeyFingerprint)
		hd.Set("X-Konstapel-Signature-SHA256", recorded.Signature.SHA256)
	} else {
		hd.Set("X-Konstapel-Signing", "unsigned")
	}
	if art == signatureArtifact {
		bsum := sha256.Sum256(bundle)
		hd.Set("Cache-Control", "private, no-store")
		hd.Set("Content-Type", "application/json")
		hd.Set("Content-Disposition", `attachment; filename="`+st.PublicationID+`.sigstore.json"`)
		hd.Set("Content-Length", strconv.Itoa(len(bundle)))
		hd.Set("Repr-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(bsum[:])+":")
		hd.Set("X-Konstapel-Publication", st.PublicationID)
		hd.Set("X-Konstapel-Package-SHA256", st.PackageSHA256)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle)
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		fail(w, err)
		return
	}
	hd.Set("Cache-Control", "private, no-store")
	hd.Set("Content-Type", "application/gzip")
	hd.Set("Content-Disposition", `attachment; filename="`+st.PublicationID+`.tar.gz"`)
	hd.Set("Content-Length", strconv.FormatInt(n, 10))
	hd.Set("Repr-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(sum)+":")
	hd.Set("X-Konstapel-Publication", st.PublicationID)
	hd.Set("X-Konstapel-Descriptor-SHA256", st.DescriptorSHA256)
	if st.PublishedAt != nil {
		hd.Set("X-Konstapel-Published-At", st.PublishedAt.UTC().Format(time.RFC3339))
	}
	if st.ExpiresAt != nil {
		hd.Set("X-Konstapel-Expires-At", st.ExpiresAt.UTC().Format(time.RFC3339))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

func (s *Server) reserve(n int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used+n > s.MaxDiskBytes {
		return false
	}
	s.used += n
	return true
}

func (s *Server) release(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.used -= n
}

// verifyPair checks a signed publication before either artifact is served:
// the run's protected receipt names the signature, the run's frozen signing
// intent pinned the same key, the stored commit references the same
// signature object, the stored bundle has the recorded digest and size, and
// it verifies for the verified archive digest under the retained public
// key. The current signing Secret or private key is never consulted.
func verifyPair(ctx context.Context, pub publication.Publisher, ref publication.RunRef, run *v1alpha1.AssessmentRun, st publication.Status, archive evidencesign.ArchiveDigest) ([]byte, error) {
	corrupt := problem{http.StatusBadGateway, "the stored signature does not match the run's receipt or fails verification"}
	rec := run.Status.Publication.Signature
	in := run.Status.SigningIntent
	if in == nil || in.Mode != v1alpha1.SigningRequired || in.Key == nil || in.Key.Fingerprint != rec.KeyFingerprint || in.ArchiveSHA256 != run.Status.Publication.PackageSHA256 {
		return nil, corrupt
	}
	g := st.Signature
	if g.Key != rec.Key || g.VersionID != rec.VersionID || g.SHA256 != rec.SHA256 || g.Size != rec.Size || g.KeyFingerprint != rec.KeyFingerprint {
		return nil, corrupt
	}
	key, err := evidencesign.ParsePublicKey([]byte(in.Key.PublicKey))
	if err != nil || key.Fingerprint != rec.KeyFingerprint {
		return nil, corrupt
	}
	bundle, _, err := pub.ReadSignature(ctx, ref)
	switch {
	case errors.Is(err, publication.ErrNotFound):
		return nil, problem{http.StatusServiceUnavailable, "the package's signature is missing before its expiry; the package is not served unsigned"}
	case err != nil:
		return nil, problem{http.StatusServiceUnavailable, "the package is unavailable"}
	}
	sum := sha256.Sum256(bundle)
	if int64(len(bundle)) != rec.Size || hex.EncodeToString(sum[:]) != rec.SHA256 {
		return nil, corrupt
	}
	if _, err := evidencesign.Verify(bundle, archive, key); err != nil {
		return nil, corrupt
	}
	return bundle, nil
}
