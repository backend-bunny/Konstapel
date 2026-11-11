// Package cache materializes verified policy bundles into a bounded,
// content-addressed cache on local disk.
//
// Untrusted layer bytes are streamed through a strict archive policy into a
// private staging directory, checked against bundle.json's file inventory,
// and only then promoted atomically into an immutable entry addressed by the
// OCI manifest digest:
//
//	<root>/blobs/sha256/<hex>              raw manifest and layer bytes
//	<root>/content/sha256/<manifest-hex>/  record.json and tree/ (the payload)
//	<root>/staging/<random>/               in-flight work, removed on Open
//	<root>/.lock                           exclusive owner lock
//
// Entries are re-verified from the manifest digest down on every reuse; a
// corrupt entry is removed and never served. Capacity is reserved before
// anything is written. Leases, eviction and acceptance (trust, source and
// compatibility revisions) are separate concerns layered on top; a cache
// entry is never an authorization by itself.
package cache

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

const (
	lockName   = ".lock"
	blobsDir   = "blobs/sha256"
	contentDir = "content/sha256"
	stagingDir = "staging"
	recordName = "record.json"
	treeName   = "tree"
)

var hexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Cache is a content-addressed bundle cache rooted at one directory. It is
// safe for concurrent use. One Cache owns a root at a time (an exclusive
// lock enforces this across processes).
type Cache struct {
	dir   string
	lim   Limits
	check func(*bundle.Descriptor, string) error
	now   func() time.Time
	fs    fileSystem
	root  *os.Root
	lock  io.Closer

	// commit serializes every change to blobs/ and content/: promotion and
	// removal. Staging, extraction and verification run outside it.
	commit sync.Mutex

	mu       sync.Mutex // guards everything below
	closed   bool
	used     int64 // charged bytes of stored blobs and entries
	reserved int64 // bytes reserved by in-flight Puts
	entries  map[string]*entryState
	blobs    map[string]*blobState
	inflight map[string]*call
	gen      uint64
	recovery Recovery
}

type entryState struct {
	manifest, layer string // blob hex digests
	cost            int64  // the content directory only
	lastUsed        time.Time
	gen             uint64 // changes whenever the entry is (re)promoted
}

type blobState struct {
	cost int64
	refs int
}

type call struct {
	done chan struct{}
	err  error
}

// Recovery reports what Open removed: abandoned staging directories, entries
// whose record or blobs were missing or inconsistent, unreferenced blobs and
// unexpected names inside the cache's own directories.
type Recovery struct {
	Staging []string
	Entries []string
	Blobs   []string
	Other   []string
}

// Entry is a verified, immutable cache entry. Dir and FS are read-only views
// of the extracted payload (bundle.json included); they stay valid while the
// entry is stored. Verification happened when the Entry was returned; it does
// not authorize use: trust and compatibility are evaluated separately.
type Entry struct {
	// Digest is the OCI manifest digest, the entry's identity.
	Digest        string
	LayerDigest   string
	ContentDigest string
	Descriptor    *bundle.Descriptor
	// Dir is the absolute path of the extracted tree.
	Dir string
	// Bytes is what the entry is charged: its tree, record and both blobs.
	Bytes int64

	c               *Cache
	manifest, layer string
	manifestSize    int64
	layerSize       int64
}

// FS returns the extracted payload as a read-only filesystem.
func (e *Entry) FS() fs.FS { return os.DirFS(e.Dir) }

// Manifest re-reads the stored manifest and checks it against Digest.
func (e *Entry) Manifest() ([]byte, error) {
	return e.c.readBlob(e.manifest, e.manifestSize)
}

// Layer re-reads the stored layer and checks it against LayerDigest. These
// are the exact bytes verify.Verifier.Recheck takes.
func (e *Entry) Layer() ([]byte, error) {
	return e.c.readBlob(e.layer, e.layerSize)
}

func (c *Cache) readBlob(hexDigest string, size int64) ([]byte, error) {
	data, err := readBounded(c.fs, path.Join(blobsDir, hexDigest), size)
	if err != nil {
		return nil, fmt.Errorf("%w: blob %s: %v", ErrCorrupt, hexDigest, err)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != hexDigest || int64(len(data)) != size {
		return nil, fmt.Errorf("%w: blob %s does not match its digest", ErrCorrupt, hexDigest)
	}
	return data, nil
}

// Open opens or creates the cache at dir, takes its exclusive lock and
// recovers from any interrupted work: every staging directory is removed
// (the lock proves no one else is using it), entries whose record or blobs
// are missing or inconsistent are removed, and unreferenced blobs are
// removed. Payload trees are not re-hashed here; Get and Verify do that on
// reuse. Names in dir outside blobs/, content/, staging/ and .lock (such as
// a volume's lost+found) are never touched.
func Open(dir string, cfg Config) (*Cache, error) {
	lim := cfg.Limits
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	if err := lim.Validate(); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	if err := os.MkdirAll(abs, privateMode); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	lock, err := lockRoot(root)
	if err != nil {
		root.Close()
		return nil, err
	}
	c := &Cache{
		dir: abs, lim: lim, check: cfg.CheckContent, now: cfg.Now, root: root, lock: lock,
		fs: osFS{root}, entries: map[string]*entryState{}, blobs: map[string]*blobState{},
		inflight: map[string]*call{},
	}
	if c.check == nil {
		c.check = bundle.ValidateContentDir
	}
	if c.now == nil {
		c.now = time.Now
	}
	if cfg.wrapFS != nil {
		c.fs = cfg.wrapFS(c.fs)
	}
	if err := c.recover(); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// Close releases the lock. Operations after Close fail with ErrClosed.
func (c *Cache) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	c.commit.Lock()
	defer c.commit.Unlock()
	err := c.lock.Close()
	if rerr := c.root.Close(); err == nil {
		err = rerr
	}
	return err
}

// Recovery returns what Open cleaned up.
func (c *Cache) Recovery() Recovery { return c.recovery }

func (c *Cache) recover() error {
	for _, d := range []string{"blobs", blobsDir, "content", contentDir, stagingDir} {
		if err := c.fs.Mkdir(d, privateMode); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		info, err := c.fs.Lstat(d)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("%w: %s in the cache root is not a directory", ErrConfig, d)
		}
	}
	staged, err := c.fs.ReadDir(stagingDir)
	if err != nil {
		return err
	}
	for _, e := range staged {
		if err := c.fs.RemoveAll(path.Join(stagingDir, e.Name())); err != nil {
			return err
		}
		c.recovery.Staging = append(c.recovery.Staging, e.Name())
	}

	blobFiles := map[string]int64{}
	blobEntries, err := c.fs.ReadDir(blobsDir)
	if err != nil {
		return err
	}
	for _, e := range blobEntries {
		info, err := c.fs.Lstat(path.Join(blobsDir, e.Name()))
		if err != nil {
			return err
		}
		if !hexPattern.MatchString(e.Name()) || !info.Mode().IsRegular() {
			if err := c.fs.RemoveAll(path.Join(blobsDir, e.Name())); err != nil {
				return err
			}
			c.recovery.Other = append(c.recovery.Other, path.Join(blobsDir, e.Name()))
			continue
		}
		blobFiles[e.Name()] = info.Size()
	}

	contents, err := c.fs.ReadDir(contentDir)
	if err != nil {
		return err
	}
	for _, e := range contents {
		name := e.Name()
		st, err := c.loadEntry(name, blobFiles)
		if err != nil {
			if err := c.fs.RemoveAll(path.Join(contentDir, name)); err != nil {
				return err
			}
			if hexPattern.MatchString(name) {
				c.recovery.Entries = append(c.recovery.Entries, name)
			} else {
				c.recovery.Other = append(c.recovery.Other, path.Join(contentDir, name))
			}
			continue
		}
		c.gen++
		st.gen = c.gen
		c.entries[name] = st
		c.used += st.cost
		for _, b := range []string{st.manifest, st.layer} {
			bs := c.blobs[b]
			if bs == nil {
				bs = &blobState{cost: blocks(blobFiles[b])}
				c.blobs[b] = bs
				c.used += bs.cost
			}
			bs.refs++
		}
	}
	for b := range blobFiles {
		if c.blobs[b] == nil {
			if err := c.fs.RemoveAll(path.Join(blobsDir, b)); err != nil {
				return err
			}
			c.recovery.Blobs = append(c.recovery.Blobs, b)
		}
	}
	for _, s := range [][]string{c.recovery.Staging, c.recovery.Entries, c.recovery.Blobs, c.recovery.Other} {
		sort.Strings(s)
	}
	return nil
}

// loadEntry is Open's structural check of one stored entry: a well-formed
// record naming this digest, blobs of the recorded sizes, and a tree whose
// cost can be charged. Content is re-hashed on reuse, not here.
func (c *Cache) loadEntry(name string, blobFiles map[string]int64) (*entryState, error) {
	if !hexPattern.MatchString(name) {
		return nil, errors.New("not a digest")
	}
	dir := path.Join(contentDir, name)
	info, err := c.fs.Lstat(dir)
	if err != nil || !info.IsDir() {
		return nil, errors.New("not a directory")
	}
	raw, err := readBounded(c.fs, path.Join(dir, recordName), maxRecordBytes)
	if err != nil {
		return nil, err
	}
	var rec record
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return nil, err
	}
	m, err := hexOf(rec.Manifest.Digest)
	if err != nil || m != name || rec.Format != recordFormat {
		return nil, errors.New("record does not describe this entry")
	}
	l, err := hexOf(rec.Layer.Digest)
	if err != nil {
		return nil, err
	}
	if size, ok := blobFiles[m]; !ok || size != rec.Manifest.Size {
		return nil, errors.New("manifest blob missing or resized")
	}
	if size, ok := blobFiles[l]; !ok || size != rec.Layer.Size {
		return nil, errors.New("layer blob missing or resized")
	}
	cost, err := c.diskCost(path.Join(dir, treeName))
	if err != nil {
		return nil, err
	}
	cost += blockSize + blocks(int64(len(raw))) // the entry directory and the record
	return &entryState{manifest: m, layer: l, cost: cost, lastUsed: c.now()}, nil
}

// diskCost charges an on-disk tree as treeCost would, bounded so a damaged
// tree cannot make Open walk without end.
func (c *Cache) diskCost(dir string) (int64, error) {
	budget := 2*c.lim.MaxFiles + 2
	var cost int64 = blockSize // the tree directory itself
	var walk func(string) error
	walk = func(d string) error {
		entries, err := c.fs.ReadDir(d)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if budget--; budget < 0 {
				return errors.New("tree exceeds the configured limits")
			}
			info, err := c.fs.Lstat(path.Join(d, e.Name()))
			if err != nil {
				return err
			}
			switch {
			case info.IsDir():
				cost += blockSize
				if err := walk(path.Join(d, e.Name())); err != nil {
					return err
				}
			case info.Mode().IsRegular():
				cost += blocks(info.Size())
			default:
				return fmt.Errorf("%s: not a regular file", e.Name())
			}
		}
		return nil
	}
	if err := walk(dir); err != nil {
		return 0, err
	}
	return cost, nil
}

// Get returns the verified entry for a manifest digest. Every call re-hashes
// the stored manifest and layer, re-derives the inventory from the layer and
// checks the record and every extracted file against it. A mismatch removes
// the entry and returns ErrCorrupt; corrupt content is never returned.
func (c *Cache) Get(ctx context.Context, digest string) (*Entry, error) {
	h, err := hexOf(digest)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	st := c.entries[h]
	var gen uint64
	if st != nil {
		gen = st.gen
	}
	c.mu.Unlock()
	if st == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, digest)
	}
	e, err := c.verifyEntry(ctx, h)
	if err != nil {
		if errors.Is(err, ErrCorrupt) {
			if qerr := c.quarantine(h, gen); qerr != nil {
				return nil, errors.Join(err, qerr)
			}
		}
		return nil, err
	}
	c.mu.Lock()
	if st := c.entries[h]; st != nil {
		st.lastUsed = c.now()
	}
	c.mu.Unlock()
	return e, nil
}

// Verify is Get without returning the entry: it re-verifies and removes the
// entry if it is corrupt.
func (c *Cache) Verify(ctx context.Context, digest string) error {
	_, err := c.Get(ctx, digest)
	return err
}

// verifyEntry checks a stored entry from its path digest down: the manifest
// blob hashes to the digest and has the bundle shape, the layer blob hashes
// to the digest the manifest names, the inventory re-derived from that layer
// satisfies the archive policy and bundle.json, the record is exactly the
// one these bytes produce, and the tree on disk is exactly that inventory.
func (c *Cache) verifyEntry(ctx context.Context, h string) (*Entry, error) {
	corrupt := func(format string, a ...any) error {
		return fmt.Errorf("%w: sha256:%s: %s", ErrCorrupt, h, fmt.Sprintf(format, a...))
	}
	manifest, err := readBounded(c.fs, path.Join(blobsDir, h), c.lim.MaxManifestBytes)
	if err != nil {
		return nil, corrupt("manifest: %v", err)
	}
	if sum := sha256.Sum256(manifest); hex.EncodeToString(sum[:]) != h {
		return nil, corrupt("manifest does not match its digest")
	}
	layerDigest, layerSize, err := bundle.ValidateManifest(manifest)
	if err != nil {
		return nil, corrupt("manifest: %v", err)
	}
	lh, _ := hexOf(layerDigest)
	inv, err := c.scanStoredLayer(ctx, lh, layerSize)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, corrupt("layer: %v", err)
	}
	d, err := checkInventory(inv)
	if err != nil {
		return nil, corrupt("%v", err)
	}
	want, err := newRecord(blobRef{"sha256:" + h, int64(len(manifest))}, blobRef{layerDigest, layerSize}, d, inv)
	if err != nil {
		return nil, err
	}
	dir := path.Join(contentDir, h)
	got, err := readBounded(c.fs, path.Join(dir, recordName), maxRecordBytes)
	if err != nil || !bytes.Equal(got, want) {
		return nil, corrupt("integrity record is missing or does not match the stored bytes")
	}
	if err := verifyTree(c.fs, path.Join(dir, treeName), inv); err != nil {
		return nil, corrupt("payload: %v", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &Entry{
		Digest: "sha256:" + h, LayerDigest: layerDigest, ContentDigest: d.ContentDigest(), Descriptor: d,
		Dir: filepath.Join(c.dir, filepath.FromSlash(dir), treeName), Bytes: treeCost(inv, len(want)) + blocks(int64(len(manifest))) + blocks(layerSize),
		c: c, manifest: h, layer: lh, manifestSize: int64(len(manifest)), layerSize: layerSize,
	}, nil
}

// scanStoredLayer hashes the stored layer blob while re-deriving its
// inventory, so both come from the same read.
func (c *Cache) scanStoredLayer(ctx context.Context, lh string, size int64) (*inventory, error) {
	name := path.Join(blobsDir, lh)
	info, err := c.fs.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != size || size > c.lim.MaxCompressedBytes {
		return nil, fmt.Errorf("blob %s is not a regular file of %d bytes", lh, size)
	}
	f, err := c.fs.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, st) {
		return nil, errors.New("layer blob changed while being opened")
	}
	hasher := sha256.New()
	r := &ctxReader{ctx: ctx, r: io.TeeReader(io.LimitReader(f, size), hasher)}
	inv, err := scanLayer(r, c.lim, nil)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(hasher.Sum(nil)) != lh {
		return nil, fmt.Errorf("layer blob does not match its digest")
	}
	return inv, nil
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *ctxReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// quarantine removes a corrupt entry, unless it was re-promoted since it was
// found corrupt (gen changed). The content directory is first renamed into
// staging, so it disappears atomically, then deleted. The manifest blob is
// removed with it; the layer blob only when no other entry references it.
func (c *Cache) quarantine(h string, gen uint64) error {
	c.commit.Lock()
	defer c.commit.Unlock()
	c.mu.Lock()
	st := c.entries[h]
	if st == nil || st.gen != gen || c.closed {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()
	return c.removeEntryLocked(h)
}

// removeEntryLocked deletes a stored entry and releases its charge. The
// caller holds c.commit. It is the single removal path; eviction (task 4.4)
// is expected to call it for unpinned entries chosen by LRU.
func (c *Cache) removeEntryLocked(h string) error {
	c.mu.Lock()
	st := c.entries[h]
	c.mu.Unlock()
	if st == nil {
		return nil
	}
	trash := path.Join(stagingDir, "removed-"+randomName())
	if err := c.fs.Rename(path.Join(contentDir, h), trash); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	c.mu.Lock()
	delete(c.entries, h)
	c.used -= st.cost
	var drop []string
	for _, b := range []string{st.manifest, st.layer} {
		if bs := c.blobs[b]; bs != nil {
			if bs.refs--; bs.refs <= 0 {
				delete(c.blobs, b)
				c.used -= bs.cost
				drop = append(drop, b)
			}
		}
	}
	c.mu.Unlock()
	var errs []error
	errs = append(errs, c.fs.RemoveAll(trash))
	for _, b := range drop {
		errs = append(errs, c.fs.RemoveAll(path.Join(blobsDir, b)))
	}
	return errors.Join(errs...)
}

// Stats is the cache's accounting and the bookkeeping eviction needs.
type Stats struct {
	CapacityBytes int64
	UsedBytes     int64
	ReservedBytes int64
	Entries       []EntryInfo
}

// EntryInfo describes one stored entry.
type EntryInfo struct {
	Digest      string
	LayerDigest string
	// Bytes is the charge removing the entry would release: its content
	// directory and manifest blob, plus the layer blob unless another entry
	// shares it.
	Bytes    int64
	LastUsed time.Time
}

// Stats returns the current accounting, entries sorted by digest.
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Stats{CapacityBytes: c.lim.CapacityBytes, UsedBytes: c.used, ReservedBytes: c.reserved}
	for h, st := range c.entries {
		b := st.cost
		if bs := c.blobs[st.manifest]; bs != nil {
			b += bs.cost
		}
		if bs := c.blobs[st.layer]; bs != nil && bs.refs == 1 {
			b += bs.cost
		}
		s.Entries = append(s.Entries, EntryInfo{Digest: "sha256:" + h, LayerDigest: "sha256:" + st.layer, Bytes: b, LastUsed: st.lastUsed})
	}
	sort.Slice(s.Entries, func(i, j int) bool { return s.Entries[i].Digest < s.Entries[j].Digest })
	return s
}

// reserve charges n bytes against capacity before anything is written. It
// is the single admission point: task 4.4 adds eviction of unpinned entries
// here before giving up with ErrCapacity.
func (c *Cache) reserve(n int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	if c.used+c.reserved+n > c.lim.CapacityBytes {
		return fmt.Errorf("%w: need %d bytes, %d of %d used and %d reserved", ErrCapacity, n, c.used, c.lim.CapacityBytes, c.reserved)
	}
	c.reserved += n
	return nil
}

func (c *Cache) release(n int64) {
	c.mu.Lock()
	c.reserved -= n
	c.mu.Unlock()
}

func hexOf(digest string) (string, error) {
	const prefix = "sha256:"
	if len(digest) != len(prefix)+64 || digest[:len(prefix)] != prefix || !hexPattern.MatchString(digest[len(prefix):]) {
		return "", fmt.Errorf("%w: digest %q must be sha256:<64 hex>", ErrIntegrity, digest)
	}
	return digest[len(prefix):], nil
}

func randomName() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return hex.EncodeToString(b[:])
}

// classifyWrite maps a filesystem error while staging to ErrNoSpace when the
// disk or quota is exhausted.
func classifyWrite(err error) error {
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
		return fmt.Errorf("%w: %w", ErrNoSpace, err)
	}
	return err
}
