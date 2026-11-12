package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// Put verifies a bundle's manifest and layer against each other, extracts
// the layer into private staging under the archive policy, verifies the tree
// against bundle.json's inventory and the content check, and atomically
// promotes it as the entry for the manifest's digest. If an intact entry for
// the digest already exists it is returned and nothing is written.
//
// Every failure leaves existing entries and everything outside the cache's
// own staging untouched and removes the staging directory. Concurrent Puts
// of the same manifest coalesce: one stages, the others wait for it.
//
// The new entry is not leased and can be evicted to make room for another;
// use PutLeased to keep it.
func (c *Cache) Put(ctx context.Context, manifest, layer []byte) (*Entry, error) {
	e, _, err := c.put0(ctx, manifest, layer, nil)
	return e, err
}

// PutLeased is Put that also acquires a lease on the entry atomically with
// its promotion (or with finding it already stored), so that it cannot be
// evicted between being stored and being pinned.
func (c *Cache) PutLeased(ctx context.Context, manifest, layer []byte, holder, owner string) (*Entry, bundle.Lease, error) {
	if err := checkLeaseRequest(holder, owner); err != nil {
		return nil, bundle.Lease{}, err
	}
	e, l, err := c.put0(ctx, manifest, layer, &leaseRequest{holder: holder, owner: owner})
	if err != nil {
		return nil, bundle.Lease{}, err
	}
	return e, *l, nil
}

func (c *Cache) put0(ctx context.Context, manifest, layer []byte, req *leaseRequest) (*Entry, *bundle.Lease, error) {
	if int64(len(manifest)) > c.lim.MaxManifestBytes {
		return nil, nil, fmt.Errorf("%w: manifest of %d bytes exceeds %d", ErrLimit, len(manifest), c.lim.MaxManifestBytes)
	}
	msum := sha256.Sum256(manifest)
	h := hex.EncodeToString(msum[:])
	layerDigest, layerSize, err := bundle.ValidateManifest(manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if layerSize > c.lim.MaxCompressedBytes || int64(len(layer)) > c.lim.MaxCompressedBytes {
		return nil, nil, fmt.Errorf("%w: layer of %d bytes exceeds %d", ErrLimit, max(layerSize, int64(len(layer))), c.lim.MaxCompressedBytes)
	}
	lsum := sha256.Sum256(layer)
	if int64(len(layer)) != layerSize || "sha256:"+hex.EncodeToString(lsum[:]) != layerDigest {
		return nil, nil, fmt.Errorf("%w: the layer is not the %s (%d bytes) the manifest names", ErrIntegrity, layerDigest, layerSize)
	}
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, nil, ErrClosed
		}
		if other := c.inflight[h]; other != nil {
			c.mu.Unlock()
			select {
			case <-other.done:
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
			if other.err == nil {
				e, l, err := c.getLeased(ctx, h, req)
				if errors.Is(err, ErrNotFound) {
					continue // evicted before we could use it; store it ourselves
				}
				return e, l, err
			}
			if errors.Is(other.err, context.Canceled) || errors.Is(other.err, context.DeadlineExceeded) {
				continue // the other caller gave up; try ourselves
			}
			return nil, nil, other.err
		}
		me := &call{done: make(chan struct{})}
		c.inflight[h] = me
		c.mu.Unlock()
		return c.putLeader(ctx, me, h, manifest, layer, layerDigest, req)
	}
}

// getLeased returns the verified entry, leased first when req is set so that
// it cannot be evicted after verification. A failed verification releases
// the lease.
func (c *Cache) getLeased(ctx context.Context, h string, req *leaseRequest) (*Entry, *bundle.Lease, error) {
	if req == nil {
		e, err := c.Get(ctx, "sha256:"+h)
		return e, nil, err
	}
	l, err := c.Acquire("sha256:"+h, req.holder, req.owner)
	if err != nil {
		return nil, nil, err
	}
	e, err := c.Get(ctx, "sha256:"+h)
	if err != nil {
		return nil, nil, errors.Join(err, c.Release(l))
	}
	return e, &l, nil
}

func (c *Cache) putLeader(ctx context.Context, me *call, h string, manifest, layer []byte, layerDigest string, req *leaseRequest) (e *Entry, l *bundle.Lease, err error) {
	me.err = errors.New("put did not complete") // seen by waiters if put panics
	defer func() {
		if err != nil {
			me.err = err
		} else {
			me.err = nil
		}
		c.mu.Lock()
		delete(c.inflight, h)
		c.mu.Unlock()
		close(me.done)
	}()
	return c.put(ctx, h, manifest, layer, layerDigest, req)
}

func (c *Cache) put(ctx context.Context, h string, manifest, layer []byte, layerDigest string, req *leaseRequest) (*Entry, *bundle.Lease, error) {
	lh, _ := hexOf(layerDigest)
	// Reuse an intact entry; a corrupt one is removed by Get and replaced,
	// and one evicted meanwhile is stored again.
	c.mu.Lock()
	_, exists := c.entries[h]
	c.mu.Unlock()
	if exists {
		e, l, err := c.getLeased(ctx, h, req)
		if err == nil || !(errors.Is(err, ErrCorrupt) || errors.Is(err, ErrNotFound)) {
			return e, l, err
		}
	}

	// Pass 1 writes nothing: it applies the whole archive policy and the
	// inventory check to the in-memory layer, and sizes the reservation.
	inv, err := scanLayer(bytes.NewReader(layer), c.lim, nil)
	if err != nil {
		return nil, nil, err
	}
	d, err := checkInventory(inv)
	if err != nil {
		return nil, nil, err
	}
	rec, err := newRecord(blobRef{"sha256:" + h, int64(len(manifest))}, blobRef{layerDigest, int64(len(layer))}, d, inv)
	if err != nil {
		return nil, nil, err
	}
	need := blocks(int64(len(manifest))) + blocks(int64(len(layer))) + treeCost(inv, len(rec)) + stagingOverhead
	if err := c.reserve(need, ""); err != nil {
		return nil, nil, err
	}
	defer c.release(need)
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	stage := path.Join(stagingDir, randomName())
	if err := c.fs.Mkdir(stage, privateMode); err != nil {
		return nil, nil, classifyWrite(err)
	}
	defer c.fs.RemoveAll(stage) // after promotion only empty directories remain

	entryDir := path.Join(stage, "entry")
	tree := path.Join(entryDir, treeName)
	if err := c.stage(ctx, stage, h, lh, manifest, layer, inv); err != nil {
		return nil, nil, classifyWrite(err)
	}
	if err := verifyTree(c.fs, tree, inv); err != nil {
		return nil, nil, fmt.Errorf("%w: extracted tree: %v", ErrInventory, err)
	}
	if err := c.check(d, filepath.Join(c.dir, filepath.FromSlash(tree))); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrContent, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := writeFile(c.fs, path.Join(entryDir, recordName), rec); err != nil {
		return nil, nil, classifyWrite(err)
	}
	for _, dir := range []string{entryDir, path.Join(stage, "blobs"), stage} {
		if err := c.fs.SyncDir(dir); err != nil {
			return nil, nil, classifyWrite(err)
		}
	}
	existing, l, err := c.promote(ctx, stage, h, lh, manifest, layer, treeCost(inv, len(rec)), req)
	if existing != nil || err != nil {
		return existing, l, err
	}
	return &Entry{
		Digest: "sha256:" + h, LayerDigest: layerDigest, ContentDigest: d.ContentDigest(), Descriptor: d,
		Dir:   filepath.Join(c.dir, filepath.FromSlash(contentDir), h, treeName),
		Bytes: need - stagingOverhead,
		c:     c, manifest: h, layer: lh, manifestSize: int64(len(manifest)), layerSize: int64(len(layer)),
	}, l, nil
}

// stage writes the blobs and extracts the layer (pass 2, the same policy as
// pass 1) into the staging directory, fsyncing every file and directory.
func (c *Cache) stage(ctx context.Context, stage, h, lh string, manifest, layer []byte, inv *inventory) error {
	blobs := path.Join(stage, "blobs")
	if err := c.fs.Mkdir(blobs, privateMode); err != nil {
		return err
	}
	if err := writeFile(c.fs, path.Join(blobs, h), manifest); err != nil {
		return err
	}
	if err := writeFile(c.fs, path.Join(blobs, lh), layer); err != nil {
		return err
	}
	entryDir := path.Join(stage, "entry")
	tree := path.Join(entryDir, treeName)
	for _, d := range []string{entryDir, tree} {
		if err := c.fs.Mkdir(d, dirMode); err != nil {
			return err
		}
	}
	made := map[string]bool{}
	create := func(name string) (writer, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Parents were validated with the name; create each exactly once.
		for i := strings.IndexByte(name, '/'); i >= 0; i = nextSlash(name, i) {
			if dir := name[:i]; !made[dir] {
				if err := c.fs.Mkdir(path.Join(tree, dir), dirMode); err != nil {
					return nil, err
				}
				made[dir] = true
			}
		}
		return c.fs.Create(path.Join(tree, name), fileMode)
	}
	got, err := scanLayer(bytes.NewReader(layer), c.lim, create)
	if err != nil {
		return err
	}
	if !sameInventory(got, inv) {
		return fmt.Errorf("%w: the layer read differently twice", ErrIntegrity)
	}
	// Directories deepest first, then the tree itself.
	dirs := append([]string(nil), inv.dirs...)
	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
	for _, d := range dirs {
		if err := c.fs.SyncDir(path.Join(tree, d)); err != nil {
			return err
		}
	}
	return c.fs.SyncDir(tree)
}

func sameInventory(a, b *inventory) bool {
	if len(a.files) != len(b.files) || a.unpacked != b.unpacked || !bytes.Equal(a.descriptor, b.descriptor) {
		return false
	}
	for p, s := range a.files {
		if b.files[p] != s {
			return false
		}
	}
	return true
}

// promote makes the staged entry visible. Under the commit lock: if an
// intact entry for the digest appeared meanwhile, ours is discarded; blobs
// are renamed into blobs/ (an intact existing blob is kept, a corrupt one is
// atomically replaced by our verified copy) and that directory synced; then
// the entry directory is renamed into content/ — the commit point — and
// content/ synced. Nothing in content/ is ever written in place, and an
// existing entry is never replaced.
// It returns the existing entry when one was already promoted, or nil after
// promoting ours, and the lease req asked for, taken while the entry is
// indexed and the commit lock excludes eviction.
func (c *Cache) promote(ctx context.Context, stage, h, lh string, manifest, layer []byte, entryCost int64, req *leaseRequest) (*Entry, *bundle.Lease, error) {
	replaced := false
	defer func() { // after the commit lock is released
		if replaced {
			c.notifyRemoved(h)
		}
	}()
	c.commit.Lock()
	defer c.commit.Unlock()
	final := path.Join(contentDir, h)

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, nil, ErrClosed
	}
	st := c.entries[h]
	c.mu.Unlock()
	if st != nil {
		e, err := c.verifyEntry(ctx, h)
		if err == nil {
			// Someone promoted the same bytes first.
			c.mu.Lock()
			l, lerr := c.acquireLocked(h, req)
			c.mu.Unlock()
			if lerr != nil {
				return nil, nil, lerr
			}
			return e, l, nil
		}
		if !errors.Is(err, ErrCorrupt) {
			return nil, nil, err
		}
		if err := c.removeEntryLocked(h); err != nil {
			return nil, nil, err
		}
		replaced = true
	}
	if _, err := c.fs.Lstat(final); !errors.Is(err, fs.ErrNotExist) {
		// Only this Cache writes content/, so an untracked name there means
		// the root was modified behind its back.
		return nil, nil, fmt.Errorf("%w: %s exists but is not a tracked entry", ErrCorrupt, final)
	}

	type placed struct {
		hex  string
		cost int64
	}
	var added []placed // blobs new to the index
	blobs := []struct {
		hex  string
		data []byte
	}{{h, manifest}, {lh, layer}}
	committed := false
	defer func() {
		if committed {
			return
		}
		for _, b := range added {
			if err := c.fs.RemoveAll(path.Join(blobsDir, b.hex)); err != nil {
				// Keep the charge honest; Open removes the orphan later.
				c.mu.Lock()
				c.blobs[b.hex] = &blobState{cost: b.cost}
				c.used += b.cost
				c.mu.Unlock()
			}
		}
	}()
	for _, b := range blobs {
		dst := path.Join(blobsDir, b.hex)
		c.mu.Lock()
		known := c.blobs[b.hex] != nil
		c.mu.Unlock()
		if known {
			if data, err := c.readBlob(b.hex, int64(len(b.data))); err == nil && bytes.Equal(data, b.data) {
				continue // shared with another entry and intact
			}
		}
		if err := c.fs.Rename(path.Join(stage, "blobs", b.hex), dst); err != nil {
			return nil, nil, classifyWrite(err)
		}
		if !known {
			added = append(added, placed{b.hex, blocks(int64(len(b.data)))})
		}
	}
	if err := c.fs.SyncDir(blobsDir); err != nil {
		return nil, nil, classifyWrite(err)
	}
	if err := c.fs.Rename(path.Join(stage, "entry"), final); err != nil {
		return nil, nil, classifyWrite(err)
	}
	committed = true

	// Index the entry; from here on it is visible and accounted.
	c.mu.Lock()
	for _, b := range added {
		c.blobs[b.hex] = &blobState{cost: b.cost}
		c.used += b.cost
	}
	for _, b := range []string{h, lh} {
		c.blobs[b].refs++
	}
	c.gen++
	c.entries[h] = &entryState{manifest: h, layer: lh, cost: entryCost, lastUsed: c.now(), gen: c.gen}
	c.used += entryCost
	delete(c.lost, h)
	l, lerr := c.acquireLocked(h, req)
	c.mu.Unlock()
	if lerr != nil {
		return nil, nil, lerr
	}
	if err := c.fs.SyncDir(contentDir); err != nil {
		err = classifyWrite(err)
		if l != nil {
			err = errors.Join(err, c.Release(*l))
		}
		return nil, nil, err
	}
	return nil, l, nil
}
