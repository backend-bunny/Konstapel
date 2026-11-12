// Package sources holds the central bundle source configuration of a running
// controller and keeps the bundle resolver's revisions current: it reads the
// sources ConfigMap as one atomic revision, derives the trust revision of
// every configured source from the objects its publisher rule references,
// notices changes to those objects and to the registry credentials and CAs,
// and, after the new state is in place, invalidates exactly the acceptances
// and transport state the change affects and reports the affected bundle
// names so that their profiles are reconciled again.
//
// A Watcher implements resolve.Revisions. It is built from small injected
// readers so that it is testable without a cluster; the manager wiring (the
// single-object ConfigMap informer, the uncached object reader, the
// kubeaccess provider, the acceptance store and the controllers' event
// channels) is done by the caller. Nothing here is linked into the shipped
// binaries yet.
//
// # Access and change notification
//
// The sources ConfigMap is read from a cache that holds only that object
// (ConfigMapCacheOptions: a field-selected list/watch, which RBAC
// resourceNames can restrict). Referenced Secrets and ConfigMaps
// (credentials, CAs, public keys, trusted roots) are never listed or
// watched: they are read by name with get, through an uncached reader, once
// per Sync. Sync runs on every change of the ConfigMap (ConfigMapHandler)
// and every Options.Interval, so a rotated or removed object is noticed
// within one interval (default kubeaccess.DefaultCacheFor, 30 s; at most
// kubeaccess.MaxCacheFor).
//
// # Invalidation
//
// Every Sync builds the complete new state first, publishes it (Source,
// Trust and Compatibility answer from it at once) and only then invalidates:
//
//   - the configuration becoming unavailable or available again (missing,
//     invalid, deleted, recovered): every acceptance (InvalidateAll);
//   - a source added or removed, its publisher rule changed, or its trust
//     revision changed or became unreadable: that source's acceptances
//     (InvalidateSource);
//   - a repository (mirror), credential or CA reference change, or a change
//     of a referenced credential or CA object: no acceptance; the transport
//     provider re-reads the changed objects (Invalidate(kind, name)), which
//     resets registry tokens when a credential changes.
//
// Every one of these changes reports the affected bundle names.
package sources

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/registry/kubeaccess"
	"github.com/backend-bunny/Konstapel/internal/bundle/resolve"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
)

// DefaultConfigMapName is the conventional name of the sources ConfigMap.
const DefaultConfigMapName = "konstapel-bundle-sources"

// DefaultReadTimeout bounds the reads of one Sync.
const DefaultReadTimeout = 10 * time.Second

// maxReason bounds State.Reason.
const maxReason = 512

// ErrUnavailable: there is no current source configuration (not loaded yet,
// missing, invalid or deleted). Resolution of every bundle is unavailable;
// the previous configuration is never served in its place.
var ErrUnavailable = errors.New("bundle source configuration is unavailable")

// ErrTrustUnavailable: the trust material a source's rule references cannot
// be read or is not acceptable now, or the caller's source is not the one
// configured now. Resolution of that source is unavailable; no earlier trust
// revision is served in its place.
var ErrTrustUnavailable = errors.New("trust revision of the bundle source is unavailable")

// Invalidator drops cached copies of referenced objects; *kubeaccess.Provider
// implements it.
type Invalidator interface {
	Invalidate(kind, name string)
}

var _ Invalidator = (*kubeaccess.Provider)(nil)

// Options configures a Watcher.
type Options struct {
	// Namespace is the controller namespace; Name the sources ConfigMap
	// (DefaultConfigMapName when empty). Both are fixed.
	Namespace string
	Name      string
	// Config reads the sources ConfigMap. In the manager it is the cache
	// built with ConfigMapCacheOptions, which holds only that object.
	Config client.Reader
	// Objects reads referenced Secrets and ConfigMaps by name in Namespace,
	// uncached (a kubeaccess.ClientReader over the manager's API reader).
	Objects kubeaccess.ObjectReader
	// Acceptances is the resolver's acceptance store.
	Acceptances *resolve.Acceptances
	// Transport, when set, is told about every changed credential or CA
	// object (and every other changed referenced object).
	Transport Invalidator
	// Compatibility is content.Compatibility.Revision.
	Compatibility func() (string, error)
	// Interval is how often referenced objects (and the ConfigMap) are
	// re-read without a ConfigMap event: zero means
	// kubeaccess.DefaultCacheFor; more than kubeaccess.MaxCacheFor is
	// rejected.
	Interval time.Duration
	// ReadTimeout bounds the reads of one Sync; zero means DefaultReadTimeout.
	ReadTimeout time.Duration
}

// State describes the configuration the Watcher serves now.
type State struct {
	// Revision increases by one whenever the served configuration changes:
	// availability, the parsed document, or the reason it is unavailable.
	// It is 0 before the first Sync.
	Revision uint64
	// Available is false before the first Sync and while the ConfigMap is
	// missing or invalid.
	Available bool
	// Reason explains an unavailable configuration: bounded and free of
	// object data (the ConfigMap holds no secrets, and documents with key
	// material or credentials are rejected with a fixed message).
	Reason string
	// Sources is the current document; empty when unavailable.
	Sources bundle.Sources
	// LastGoodRevision is the Revision of the most recent available
	// configuration. It is diagnostic only: nothing is resolved under it.
	LastGoodRevision uint64
}

// Change is what one Sync changed.
type Change struct {
	// Revision is the configuration revision after the Sync.
	Revision uint64
	// Affected are the bundle names whose profiles must be reconciled.
	Affected []string
	// Invalidated are the source names whose acceptances were invalidated;
	// InvalidatedAll is set when every acceptance was.
	Invalidated    []string
	InvalidatedAll bool
	// Objects are the referenced objects ("Kind/name") whose content
	// changed, appeared or disappeared; Transport was told about each.
	Objects []string
}

// Empty reports whether the Sync changed nothing.
func (c Change) Empty() bool {
	return len(c.Affected) == 0 && len(c.Invalidated) == 0 && !c.InvalidatedAll && len(c.Objects) == 0
}

type trustEntry struct {
	rule  string // verify.RuleRevision of the configured source
	token string
	err   string // non-empty when the trust revision is unavailable
}

type snapshot struct {
	state  State
	byName map[string]bundle.BundleSource
	trust  map[string]trustEntry
	// objects maps "Kind/name/key" of every referenced value to its state.
	objects map[string]string
}

// Watcher is the central configuration holder. It is safe for concurrent
// use; Syncs are serialized.
type Watcher struct {
	opts   Options
	compat func() (string, error)

	syncMu sync.Mutex // serializes Sync

	mu  sync.RWMutex // guards cur
	cur snapshot

	pendingMu sync.Mutex
	pending   map[string]bool
	notify    chan struct{} // pending is non-empty
	kick      chan struct{} // a ConfigMap event asks for a Sync

	// afterPublish is a test hook between publishing the new state and
	// invalidating.
	afterPublish func()
}

var _ resolve.Revisions = (*Watcher)(nil)

// New validates opts. The Watcher serves an unavailable configuration until
// its first Sync.
func New(opts Options) (*Watcher, error) {
	if opts.Name == "" {
		opts.Name = DefaultConfigMapName
	}
	switch {
	case opts.Namespace == "":
		return nil, errors.New("sources: the controller namespace is required")
	case opts.Config == nil || opts.Objects == nil || opts.Acceptances == nil || opts.Compatibility == nil:
		return nil, errors.New("sources: Config, Objects, Acceptances and Compatibility are required")
	case opts.Interval < 0 || opts.Interval > kubeaccess.MaxCacheFor:
		return nil, fmt.Errorf("sources: Interval %s must be between 0 and %s", opts.Interval, kubeaccess.MaxCacheFor)
	case opts.ReadTimeout < 0:
		return nil, errors.New("sources: ReadTimeout must not be negative")
	}
	if opts.Interval == 0 {
		opts.Interval = kubeaccess.DefaultCacheFor
	}
	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = DefaultReadTimeout
	}
	return &Watcher{
		opts: opts, compat: opts.Compatibility,
		cur:     snapshot{state: State{Reason: "not loaded yet"}},
		pending: map[string]bool{},
		notify:  make(chan struct{}, 1),
		kick:    make(chan struct{}, 1),
	}, nil
}

// State returns the configuration served now.
func (w *Watcher) State() State {
	w.mu.RLock()
	defer w.mu.RUnlock()
	s := w.cur.state
	s.Sources.Sources = slices.Clone(s.Sources.Sources)
	return s
}

// Source implements resolve.Revisions.
func (w *Watcher) Source(name string) (bundle.BundleSource, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if !w.cur.state.Available {
		return bundle.BundleSource{}, fmt.Errorf("%w (revision %d)", ErrUnavailable, w.cur.state.Revision)
	}
	src, ok := w.cur.byName[name]
	if !ok {
		return bundle.BundleSource{}, fmt.Errorf("%w: %q", bundle.ErrUnconfigured, name)
	}
	return src, nil
}

// Trust implements resolve.Revisions: the trust revision of src's publisher
// rule as observed by the last Sync. It is "<type>:" followed by
// verify.Verifier.TrustRevision, so it is derived from the content of the
// referenced public key or trusted root only. Credentials, CAs and the
// repository do not contribute. It fails when the configuration is
// unavailable, when src is not the source configured now under its name, and
// when the referenced material was missing, unreadable or unacceptable.
func (w *Watcher) Trust(src bundle.BundleSource) (string, error) {
	rule, err := verify.RuleRevision(src)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrTrustUnavailable, err)
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if !w.cur.state.Available {
		return "", fmt.Errorf("%w: %w", ErrTrustUnavailable, ErrUnavailable)
	}
	e, ok := w.cur.trust[src.Name]
	switch {
	case !ok:
		return "", fmt.Errorf("%w: %q is not configured", ErrTrustUnavailable, src.Name)
	case e.rule != rule:
		return "", fmt.Errorf("%w: %q is not the source configured now", ErrTrustUnavailable, src.Name)
	case e.err != "":
		return "", fmt.Errorf("%w: %q: %s", ErrTrustUnavailable, src.Name, e.err)
	}
	return e.token, nil
}

// Compatibility implements resolve.Revisions.
func (w *Watcher) Compatibility() (string, error) { return w.compat() }

// ReferencedBy returns the configured source names that reference the
// object kind/name (as credential, CA, public key or trusted root).
func (w *Watcher) ReferencedBy(kind, name string) []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var out []string
	for _, s := range w.cur.state.Sources.Sources {
		for _, r := range refs(s) {
			if r.kind == kind && r.name == name {
				out = append(out, s.Name)
				break
			}
		}
	}
	return out
}

// Sync reads the ConfigMap and every object the configuration references,
// publishes the result as the current state, then invalidates what changed
// and records the affected bundle names for the Trigger. A failure to read
// the ConfigMap other than its absence changes nothing and is returned: it
// says nothing about the configuration (the next Sync retries).
func (w *Watcher) Sync(ctx context.Context) (Change, error) {
	w.syncMu.Lock()
	defer w.syncMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, w.opts.ReadTimeout)
	defer cancel()

	next, err := w.load(ctx)
	if err != nil {
		return Change{}, err
	}

	w.mu.Lock()
	old := w.cur
	ch := diff(old, next)
	next.state.Revision = old.state.Revision
	next.state.LastGoodRevision = old.state.LastGoodRevision
	if configChanged(old.state, next.state) {
		next.state.Revision++
	}
	if next.state.Available {
		next.state.LastGoodRevision = next.state.Revision
	}
	w.cur = next
	w.mu.Unlock()
	ch.Revision = next.state.Revision

	// The new state is served; only now invalidate (the resolve package's
	// protocol: a verification that read the old revisions is refused at
	// Record or adoption).
	if w.afterPublish != nil {
		w.afterPublish()
	}
	if w.opts.Transport != nil {
		for _, o := range ch.Objects {
			kind, name := splitObject(o)
			w.opts.Transport.Invalidate(kind, name)
		}
	}
	if ch.InvalidatedAll {
		w.opts.Acceptances.InvalidateAll()
	} else {
		for _, name := range ch.Invalidated {
			w.opts.Acceptances.InvalidateSource(name)
		}
	}
	w.addPending(ch.Affected)
	return ch, nil
}

// load builds the complete next snapshot without touching the current one.
func (w *Watcher) load(ctx context.Context) (snapshot, error) {
	cm := &corev1.ConfigMap{}
	err := w.opts.Config.Get(ctx, client.ObjectKey{Namespace: w.opts.Namespace, Name: w.opts.Name}, cm)
	switch {
	case apierrors.IsNotFound(err):
		return unavailable(fmt.Sprintf("ConfigMap %s/%s not found", w.opts.Namespace, w.opts.Name)), nil
	case err != nil:
		return snapshot{}, fmt.Errorf("sources: reading ConfigMap %s/%s: %w", w.opts.Namespace, w.opts.Name, err)
	}
	if len(cm.BinaryData) > 0 {
		return unavailable(fmt.Sprintf("ConfigMap %s/%s: binaryData is not allowed; the document is data[%q]", w.opts.Namespace, w.opts.Name, bundle.SourcesConfigKey)), nil
	}
	parsed, err := bundle.ParseConfigMapData(cm.Data)
	if err != nil {
		return unavailable(fmt.Sprintf("ConfigMap %s/%s: %v", w.opts.Namespace, w.opts.Name, err)), nil
	}

	s := snapshot{
		state:   State{Available: true, Sources: parsed},
		byName:  make(map[string]bundle.BundleSource, len(parsed.Sources)),
		trust:   make(map[string]trustEntry, len(parsed.Sources)),
		objects: map[string]string{},
	}
	// One read per object per Sync, so the trust revision and the object
	// states describe the same observation.
	objs := &memoReader{r: w.opts.Objects, m: map[string]memoEntry{}}
	v, err := verify.New(objs)
	if err != nil {
		return snapshot{}, err
	}
	for _, src := range parsed.Sources {
		s.byName[src.Name] = src
		rule, err := verify.RuleRevision(src)
		if err != nil { // validated by ParseConfigMapData; kept for safety
			return unavailable(fmt.Sprintf("source %q: %v", src.Name, err)), nil
		}
		e := trustEntry{rule: rule}
		if rev, err := v.TrustRevision(ctx, src.Publisher); err != nil {
			e.err = bounded(err.Error())
		} else {
			e.token = src.Publisher.Type + ":" + rev
		}
		s.trust[src.Name] = e
		for _, r := range refs(src) {
			id := r.id()
			if _, done := s.objects[id]; !done {
				s.objects[id] = objectState(objs.Get(ctx, r.kind, r.name))(r.key)
			}
		}
	}
	return s, nil
}

func unavailable(reason string) snapshot {
	return snapshot{state: State{Reason: bounded(reason)}}
}

func configChanged(a, b State) bool {
	return a.Available != b.Available || a.Reason != b.Reason || !reflect.DeepEqual(a.Sources, b.Sources)
}

// diff computes what changed between two snapshots.
func diff(old, next snapshot) Change {
	var ch Change
	affected, invalid := map[string]bool{}, map[string]bool{}
	oa, na := old.state.Available, next.state.Available
	switch {
	case !oa && !na:
		// Nothing is served before or after.
	case oa != na:
		ch.InvalidatedAll = true
		for n := range old.byName {
			affected[n] = true
		}
		for n := range next.byName {
			affected[n] = true
		}
	default:
		for _, n := range union(old.byName, next.byName) {
			o, inOld := old.byName[n]
			x, inNew := next.byName[n]
			switch {
			case !inOld || !inNew:
				affected[n], invalid[n] = true, true
			case old.trust[n] != next.trust[n]:
				// The rule revision or the trust revision (or its
				// availability) changed.
				affected[n], invalid[n] = true, true
			case !reflect.DeepEqual(o, x):
				// Only the repository, credential or CA reference: no
				// cryptographic decision depends on them.
				affected[n] = true
			}
		}
	}
	// Objects whose observed state changed, appeared or disappeared.
	changedObj := map[string]bool{}
	for _, id := range union(old.objects, next.objects) {
		if old.objects[id] != next.objects[id] {
			changedObj[objectOf(id)] = true
		}
	}
	if na {
		for _, src := range next.state.Sources.Sources {
			for _, r := range refs(src) {
				if changedObj[r.kind+"/"+r.name] {
					affected[src.Name] = true
				}
			}
		}
	}
	ch.Affected = slices.Sorted(maps.Keys(affected))
	if !ch.InvalidatedAll {
		ch.Invalidated = slices.Sorted(maps.Keys(invalid))
	}
	ch.Objects = slices.Sorted(maps.Keys(changedObj))
	return ch
}

func union[V any](a, b map[string]V) []string {
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	return slices.Sorted(maps.Keys(keys))
}

// ref is one referenced value.
type ref struct{ kind, name, key string }

func (r ref) id() string { return r.kind + "/" + r.name + "/" + r.key }

// objectOf turns "Kind/name/key" into "Kind/name" (names and keys contain
// no '/').
func objectOf(id string) string {
	kind, rest, _ := strings.Cut(id, "/")
	name, _, _ := strings.Cut(rest, "/")
	return kind + "/" + name
}

func splitObject(o string) (string, string) {
	kind, name, _ := strings.Cut(o, "/")
	return kind, name
}

// refs lists every object value a source references, with default kinds
// and keys filled in.
func refs(s bundle.BundleSource) []ref {
	var out []ref
	add := func(r *bundle.ObjectRef, kind, key string) {
		if r == nil {
			return
		}
		if r.Kind != "" {
			kind = r.Kind
		}
		if r.Key != "" {
			key = r.Key
		}
		out = append(out, ref{kind: kind, name: r.Name, key: key})
	}
	add(s.CredentialSecret, bundle.KindSecret, bundle.DefaultCredentialKey)
	add(s.CA, "", bundle.DefaultCAKey)
	add(s.Publisher.PublicKey, "", bundle.DefaultPublicKey)
	add(s.Publisher.TrustRoot, "", bundle.DefaultTrustRootKey)
	return out
}

// objectState describes one referenced value without its data: a digest of
// the Secret type and the value, or why there is none.
func objectState(o kubeaccess.Object, err error) func(key string) string {
	return func(key string) string {
		switch {
		case errors.Is(err, kubeaccess.ErrObjectNotFound):
			return "absent"
		case err != nil:
			return "unreadable"
		}
		v, ok := o.Value(key)
		if !ok {
			return "no-key"
		}
		h := sha256.New()
		h.Write([]byte(o.Type()))
		h.Write([]byte{0})
		h.Write(v)
		return "sha256:" + hex.EncodeToString(h.Sum(nil))
	}
}

type memoEntry struct {
	o   kubeaccess.Object
	err error
}

// memoReader reads each object at most once.
type memoReader struct {
	r kubeaccess.ObjectReader
	m map[string]memoEntry
}

func (m *memoReader) Get(ctx context.Context, kind, name string) (kubeaccess.Object, error) {
	k := kind + "/" + name
	if e, ok := m.m[k]; ok {
		return e.o, e.err
	}
	o, err := m.r.Get(ctx, kind, name)
	m.m[k] = memoEntry{o: o, err: err}
	return o, err
}

func bounded(s string) string {
	if len(s) <= maxReason {
		return s
	}
	return s[:maxReason-3] + "..."
}
