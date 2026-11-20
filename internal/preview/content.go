package preview

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// This file is the preview's verified bundle content (tasks 4.1 to 4.3). It
// is the controller's own content source, assembled without a manager, a
// provider or any watcher: the vendored bundle through targeting.LocalContent
// and every other name through the bundle owner's stack (its source mapping,
// exact-digest resolver, current-trust verifier and content cache), routed
// by stack.Router exactly as the controller routes them.
//
// The stack never reaches the cluster. Its source configuration, trust
// material and registry credentials are the values the observation read and
// rechecked with the caller's identity, served from the snapshot. So the
// preview resolves under the caller's authority only: a Secret the caller may
// not read is unavailable to it, and the controller's access is never used.

// DigestKind says what a pinned bundle digest identifies.
type DigestKind string

const (
	// DigestVendoredChecksum: the sha256 of the vendored content tree's
	// SHA256SUMS (the checksum manifest), served by targeting.LocalContent.
	DigestVendoredChecksum DigestKind = "vendored-checksum-manifest"
	// DigestOCIManifest: the digest of an OCI image manifest, resolved
	// through the configured bundle sources.
	DigestOCIManifest DigestKind = "oci-manifest"
	// DigestUnknown: the content source does not say how it interprets the
	// name. A digest is never labelled as the other kind.
	DigestUnknown DigestKind = "unknown"
)

// Content codes.
const (
	// CompareContentAccessDenied: content could not be resolved because the
	// caller may not read a Secret its bundle source references.
	CompareContentAccessDenied ObserveCode = "content-access-denied"
	// CompareContentUnavailable: content that a live binding the proposal
	// does not touch pins could not be read by the preview. The preview
	// cannot observe whether the controller resolves it, so the overlap in
	// that binding's namespaces is unknown.
	CompareContentUnavailable ObserveCode = "content-unavailable"
	// LimitControllerVersion: OCI bundle compatibility is checked against the
	// controller release given to the preview, not an observed one.
	LimitControllerVersion ObserveCode = "controller-version-assumed"
)

// ContentRecord is one pinned bundle the comparison read, with its typed
// digest. Resolved is true only for content that passed verification now.
type ContentRecord struct {
	Name       string     `json:"name"`
	Digest     string     `json:"digest"`
	DigestKind DigestKind `json:"digestKind"`
	// Repository is the configured OCI repository of the name's source.
	Repository string                      `json:"repository,omitempty"`
	Resolved   bool                        `json:"resolved"`
	ErrorClass targeting.ContentErrorClass `json:"errorClass,omitempty"`
	// Error is the content source's bounded explanation. Bundle-stack errors
	// are credential-free by construction (only fixed sentinel texts), and
	// vendored-tree errors name local paths and digests only.
	Error string `json:"error,omitempty"`
}

// maxContentError bounds ContentRecord.Error, as the bundle stack bounds
// its details.
const maxContentError = 512

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) > maxContentError {
		msg = msg[:maxContentError-3] + "..."
	}
	return msg
}

// ContentOptions configures the preview's bundle content.
type ContentOptions struct {
	// Vendored serves the vendored bundle from this installation's content
	// tree, verified against its SHA256SUMS on every read exactly as the
	// controller verifies its own. Name is the vendored bundle name.
	Vendored targeting.LocalContent
	// CacheDir is an absolute directory for the verified content cache,
	// owned exclusively by this process while it is open. Cached content is
	// verified again under the observed trust before it is used. Empty uses
	// a private temporary directory that Close removes.
	CacheDir string
	// CacheCapacity bounds the cache in bytes; zero is the cache default.
	CacheCapacity int64
	// ControllerVersion is the controller release (SemVer) that OCI bundle
	// compatibility is checked against. Required when the observation
	// selected bundle sources.
	ControllerVersion string
}

// BundleContent is the preview's verified content source. It implements
// targeting.ContentSource; Compare also reads its digest kinds,
// repositories and limitations.
type BundleContent struct {
	router      *stack.Router
	st          *stack.Stack
	vendored    string
	inputs      *sourceInputs
	tmp         string
	limitations []Diagnostic
}

var _ targeting.ContentSource = (*BundleContent)(nil)

// OpenContent assembles the content source for a complete observation.
// Without selected bundle sources it serves only the vendored bundle and
// creates nothing on disk. With them, it opens the bundle stack over the
// observed configuration and loads that configuration once.
func OpenContent(ctx context.Context, snap *Snapshot, opts ContentOptions) (*BundleContent, error) {
	switch {
	case snap == nil || !snap.Complete:
		return nil, errors.New("bundle content needs a complete cluster observation")
	case opts.Vendored.Name == "" || opts.Vendored.Root == "":
		return nil, errors.New("the vendored content tree and its bundle name are required")
	}
	b := &BundleContent{vendored: opts.Vendored.Name, inputs: snap.inputs}
	if snap.inputs == nil {
		if opts.CacheDir != "" || opts.CacheCapacity != 0 {
			return nil, errors.New("a bundle cache needs the bundle-source ConfigMap to be selected")
		}
		b.router = stack.NewRouter(opts.Vendored, opts.Vendored.Name)
		return b, nil
	}
	if opts.ControllerVersion == "" {
		return nil, errors.New("the controller release is required to check OCI bundle compatibility")
	}
	dir := opts.CacheDir
	if dir == "" {
		tmp, err := os.MkdirTemp("", "konstapel-preview-cache-")
		if err != nil {
			return nil, err
		}
		dir, b.tmp = tmp, tmp
	}
	r := snapshotReader{in: snap.inputs}
	st, err := stack.New(stack.Options{SourcesConfigMap: snap.inputs.configMap, Namespace: snap.inputs.namespace,
		CacheDir: dir, CacheCapacity: opts.CacheCapacity, ControllerVersion: opts.ControllerVersion},
		stack.Deps{APIReader: r, Config: r})
	if err != nil {
		b.removeTmp()
		return nil, err
	}
	b.st = st
	if _, err := st.Watcher.Sync(ctx); err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("loading the observed bundle-source configuration: %w", err)
	}
	b.router = st.Router(opts.Vendored, opts.Vendored.Name)
	msg := fmt.Sprintf("OCI bundle compatibility is checked against controller release %s as given to the preview; the running controller's release is not observed", opts.ControllerVersion)
	if err := st.CompatibilityProblem(); err != nil {
		msg += "; that release cannot satisfy any bundle's compatibility check, so every OCI bundle is unavailable"
	}
	b.limitations = append(b.limitations, Diagnostic{Code: LimitControllerVersion, Message: msg})
	return b, nil
}

// Content implements targeting.ContentSource: the vendored bundle from the
// local tree, every other name through the bundle stack, never substituted
// and never unverified.
func (b *BundleContent) Content(ctx context.Context, ref v1alpha1.BundleReference) (*targeting.Content, error) {
	c, err := b.router.Content(ctx, ref)
	if err != nil && ref.Name != b.vendored {
		if denied := b.deniedSecrets(ref.Name); len(denied) > 0 {
			return nil, &ContentAccessError{Ref: ref, Namespace: b.inputs.namespace, Secrets: denied, err: err}
		}
	}
	return c, err
}

// DigestKind is how the controller's router interprets a pinned name: the
// vendored name as a checksum-manifest digest, every other as an OCI
// manifest digest.
func (b *BundleContent) DigestKind(name string) DigestKind {
	if name == b.vendored {
		return DigestVendoredChecksum
	}
	return DigestOCIManifest
}

// Repository is the observed configured repository for a bundle name.
func (b *BundleContent) Repository(name string) string {
	if name == b.vendored || b.inputs == nil || b.inputs.parsed == nil {
		return ""
	}
	s, err := b.inputs.parsed.Select(name)
	if err != nil {
		return ""
	}
	return s.Repository
}

// Limitations are the informational bounds of this content source.
func (b *BundleContent) Limitations() []Diagnostic { return slices.Clone(b.limitations) }

// Close releases the cache lock and idle registry connections and removes a
// temporary cache directory.
func (b *BundleContent) Close() error {
	var err error
	if b.st != nil {
		err = b.st.Close()
		b.st = nil
	}
	b.removeTmp()
	return err
}

func (b *BundleContent) removeTmp() {
	if b.tmp != "" {
		_ = os.RemoveAll(b.tmp)
		b.tmp = ""
	}
}

// deniedSecrets names the Secrets that name's source references and the
// caller could not read.
func (b *BundleContent) deniedSecrets(name string) []string {
	if b.inputs == nil || b.inputs.parsed == nil {
		return nil
	}
	s, err := b.inputs.parsed.Select(name)
	if err != nil {
		return nil
	}
	var out []string
	for _, r := range sourceRefs(s) {
		if o := b.inputs.objects[r.kind+"/"+r.name]; r.kind == bundle.KindSecret && o != nil && o.access == SecretDenied {
			out = append(out, r.name)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// ContentAccessError is content that could not be resolved because the
// caller may not read a Secret its source references. It is an
// ErrContentUnavailable, and names the Secrets only.
type ContentAccessError struct {
	Ref       v1alpha1.BundleReference
	Namespace string
	Secrets   []string
	err       error
}

func (e *ContentAccessError) Error() string {
	return fmt.Sprintf("%s@%s: the caller may not read Secret %s in %s, which its bundle source references; the preview resolves content only with the caller's own access, never with the controller's (%s)",
		e.Ref.Name, e.Ref.Digest, strings.Join(e.Secrets, ", "), e.Namespace, classOf(e.err))
}

// Unwrap returns the content source's error.
func (e *ContentAccessError) Unwrap() error { return e.err }

func classOf(err error) string {
	if c := targeting.ContentErrorClassOf(err); c != "" {
		return string(c)
	}
	return "unavailable"
}

// contentKind is the digest kind a content source gives a name.
func contentKind(src targeting.ContentSource, name string) DigestKind {
	switch s := src.(type) {
	case *BundleContent:
		return s.DigestKind(name)
	case *stack.Router:
		if name == s.LocalName() {
			return DigestVendoredChecksum
		}
		return DigestOCIManifest
	case targeting.LocalContent:
		if name == s.Name {
			return DigestVendoredChecksum
		}
	}
	return DigestUnknown
}

// sourceInputs is the observed bundle-source configuration and the values of
// every object it references. It holds Secret data, so it never serializes
// or formats anything but a redaction.
type sourceInputs struct {
	namespace, configMap string
	missing              bool
	data                 map[string]string
	binaryData           bool
	parsed               *bundle.Sources
	// objects by "Kind/name", referenced keys only.
	objects map[string]*sourceObject
}

type sourceObject struct {
	access SecretAccess
	typ    string
	data   map[string][]byte
}

func (*sourceInputs) String() string   { return "sourceInputs{redacted}" }
func (*sourceInputs) GoString() string { return "preview.sourceInputs{redacted}" }

// Format redacts for every verb.
func (s *sourceInputs) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }

// MarshalJSON redacts.
func (*sourceInputs) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }

// LogValue redacts in structured logs.
func (s *sourceInputs) LogValue() slog.Value { return slog.StringValue(s.String()) }

// snapshotReader serves the bundle stack the observed objects by name. It is
// the stack's only Kubernetes reader, so the stack sends no request of its
// own: a Secret the caller could not read is Forbidden here too, and an
// object the observation did not read is an error, never a live read.
type snapshotReader struct{ in *sourceInputs }

var _ client.Reader = snapshotReader{}

func (r snapshotReader) Get(_ context.Context, key client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
	if key.Namespace != r.in.namespace {
		return fmt.Errorf("the preview observed only namespace %s, not %s", r.in.namespace, key.Namespace)
	}
	switch o := obj.(type) {
	case *corev1.ConfigMap:
		if key.Name == r.in.configMap {
			if r.in.missing {
				return apierrors.NewNotFound(schema.GroupResource{Resource: "configmaps"}, key.Name)
			}
			*o = corev1.ConfigMap{Data: maps.Clone(r.in.data)}
			o.Namespace, o.Name = key.Namespace, key.Name
			if r.in.binaryData {
				o.BinaryData = map[string][]byte{"": nil}
			}
			return nil
		}
		so, err := r.object(bundle.KindConfigMap, key.Name, "configmaps")
		if err != nil {
			return err
		}
		*o = corev1.ConfigMap{BinaryData: cloneValues(so.data)}
		o.Namespace, o.Name = key.Namespace, key.Name
		return nil
	case *corev1.Secret:
		so, err := r.object(bundle.KindSecret, key.Name, "secrets")
		if err != nil {
			return err
		}
		*o = corev1.Secret{Type: corev1.SecretType(so.typ), Data: cloneValues(so.data)}
		o.Namespace, o.Name = key.Namespace, key.Name
		return nil
	}
	return fmt.Errorf("the preview's bundle content reads only ConfigMaps and Secrets, not %T", obj)
}

func (r snapshotReader) object(kind, name, resource string) (*sourceObject, error) {
	so := r.in.objects[kind+"/"+name]
	switch {
	case so == nil:
		return nil, fmt.Errorf("%s %s/%s was not observed; the preview reads no object its observation did not", kind, r.in.namespace, name)
	case so.access == SecretMissing:
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: resource}, name)
	case so.access == SecretDenied:
		return nil, apierrors.NewForbidden(schema.GroupResource{Resource: resource}, name, errors.New("the caller may not read it"))
	}
	return so, nil
}

// List is refused: nothing in the bundle stack lists objects.
func (snapshotReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("the preview's bundle content lists nothing")
}

func cloneValues(m map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		out[k] = slices.Clone(v)
	}
	return out
}
